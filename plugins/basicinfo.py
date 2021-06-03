'''
   Copyright (c) 2017 Yogesh Khatri

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the
   terms of the MIT License.

'''

import logging
import os
import sqlite3
from plugins.helpers.common import *
from plugins.helpers.disk_report import Disk_Info
from plugins.helpers.macinfo import *
from plugins.helpers.writer import *

__Plugin_Name = "BASICINFO"
__Plugin_Friendly_Name = "Basic system and OS configuration"
__Plugin_Version = "0.1"
__Plugin_Description = "Gets basic system and OS configuration like SN, timezone, device name, last logged in user, FS info, etc.."
__Plugin_Author = "Yogesh Khatri"
__Plugin_Author_Email = "yogesh@swiftforensics.com"
__Plugin_Modes = "MACOS,IOS"
__Plugin_ArtifactOnly_Usage = ''

log = logging.getLogger('MAIN.' + __Plugin_Name) # Do not rename or remove this ! This is the logger object

#---- Do not change the variable names in above section ----#

basic_data = []
basic_data_info = [ ('INFO_TYPE',DataType.TEXT),('Name',DataType.TEXT),('Data',DataType.TEXT),
                    ('Description',DataType.TEXT),('Source',DataType.TEXT) ]

def GetVolumeInfo(mac_info):
    '''Gets information for the volume where OSX/macOS is installed'''
    vol = mac_info.macos_FS
    if vol == None: # For MOUNTED option, this is None
        return
    if mac_info.is_apfs:
        used_space = Disk_Info.GetSizeStr(vol.container.block_size * vol.num_blocks_used)
        container_size = Disk_Info.GetSizeStr(vol.container.apfs_container_size)
        if mac_info.apfs_sys_volume:
            basic_data.append(['APFS', 'Information', '', 'Data below represents a combined SYSTEM & DATA volume', ''])
            basic_data.append(['APFS', 'Block Size (bytes)', vol.container.block_size, 'Container Block size', ''])
            basic_data.append(['APFS', 'Container Size', container_size, 'Container size (SYSTEM + DATA)', ''])
            basic_data.append(['APFS', 'Volume Name', mac_info.apfs_sys_volume.volume_name + "," + mac_info.apfs_data_volume.volume_name, 'Volume names (SYSTEM, DATA)', ''])
            basic_data.append(['APFS', 'Volume UUID', mac_info.apfs_sys_volume.uuid + "," + mac_info.apfs_data_volume.uuid, 'Volume Unique Identifiers (SYSTEM, DATA)', ''])
            basic_data.append(['APFS', 'Size Used', used_space, 'Space allocated  (SYSTEM + DATA)', ''])
            basic_data.append(['APFS', 'Total Files', vol.num_files, 'Total number of files (SYSTEM + DATA)', ''])
            basic_data.append(['APFS', 'Total Folders', vol.num_folders, 'Total number of directories/folders (SYSTEM + DATA)', ''])
            basic_data.append(['APFS', 'Total Symlinks', vol.num_symlinks, 'Total number of symbolic links (SYSTEM + DATA)', ''])
            basic_data.append(['APFS', 'Total Snapshots', vol.num_snapshots, 'Total number of snapshots (DATA)', ''])
            basic_data.append(['APFS', 'Created Time', CommonFunctions.ReadAPFSTime(vol.time_created), 'Created date and time (DATA)', ''])
            basic_data.append(['APFS', 'Updated Time', CommonFunctions.ReadAPFSTime(vol.time_updated), 'Last updated date and time (DATA)', ''])
        else:
            basic_data.append(['APFS', 'Information', '', 'Data below is only for volume with macOS installed', ''])
            basic_data.append(['APFS', 'Block Size (bytes)', vol.container.block_size, 'Container Block size', ''])
            basic_data.append(['APFS', 'Container Size (GB)', container_size, 'Container size', ''])
            basic_data.append(['APFS', 'Volume Name', vol.volume_name, 'Volume name', ''])
            basic_data.append(['APFS', 'Volume UUID', vol.uuid, 'Volume Unique Identifier', ''])
            basic_data.append(['APFS', 'Size Used', used_space, 'Space allocated', ''])
            basic_data.append(['APFS', 'Total Files', vol.num_files, 'Total number of files', ''])
            basic_data.append(['APFS', 'Total Folders', vol.num_folders, 'Total number of directories/folders', ''])
            basic_data.append(['APFS', 'Total Symlinks', vol.num_symlinks, 'Total number of symbolic links', ''])
            basic_data.append(['APFS', 'Total Snapshots', vol.num_snapshots, 'Total number of snapshots', ''])
            basic_data.append(['APFS', 'Created Time', CommonFunctions.ReadAPFSTime(vol.time_created), 'Created date and time', ''])
            basic_data.append(['APFS', 'Updated Time', CommonFunctions.ReadAPFSTime(vol.time_updated), 'Last updated date and time', ''])
    else:
        hfs_info = mac_info.hfs_native.GetVolumeInfo()
        used_space = '{:.2f} GB'.format(float(hfs_info.block_size * (hfs_info.total_blocks - hfs_info.free_blocks) / (1024*1024*1024.0)))
        volume_size = '{:.2f}'.format(float(hfs_info.block_size * hfs_info.total_blocks / (1024*1024*1024.0)))
        basic_data.append(['HFS', 'Block Size', hfs_info.block_size,'Volume Block size (internal)', ''])
        basic_data.append(['HFS', 'Volume Size (GB)', volume_size, 'Volume size', ''])
        basic_data.append(['HFS', 'Volume Used (GB)', used_space, 'Volume used size', ''])
        basic_data.append(['HFS', 'Created date', hfs_info.date_created_local_time,'Volume created date (in local time)', ''])
        basic_data.append(['HFS', 'Last Modified date', hfs_info.date_modified,'Volume last modified date', ''])
        basic_data.append(['HFS', 'Last Checked date', hfs_info.date_last_checked,'Volume last checked for errors', ''])
        basic_data.append(['HFS', 'Last Backup date', hfs_info.date_backup,'Volume last backup date', ''])
        basic_data.append(['HFS', 'Last Mounted Version', hfs_info.last_mounted_version,'', ''])
        basic_data.append(['HFS', 'HFSX status', hfs_info.is_HFSX,'Volume ' + ("is" if hfs_info.is_HFSX else "isn't") + ' HFSX', ''])
        basic_data.append(['HFS', 'HFS version', hfs_info.version,'Volume version', ''])
        basic_data.append(['HFS', 'Number of Files', hfs_info.num_files,"Volume's total files", ''])
        basic_data.append(['HFS', 'Number of Folders', hfs_info.num_folders,"Volume's total folders", ''])

def ReadSerialFromDb(mac_info, source):
    found_serial = False
    serial_number = ''
    if mac_info.IsValidFilePath(source):
        try:
            sqlite = SqliteWrapper(mac_info)
            conn = sqlite.connect(source)
            if conn:
                log.debug ("Opened DB {} successfully".format(os.path.basename(source)))
                try:
                    conn.row_factory = sqlite3.Row
                    cursor = conn.execute("SELECT SerialNumber FROM TableInfo")
                    try:
                        for row in cursor:
                            serial_number = row[0] # Was row['SerialNumber'] but sqlite has issues with unicode, so removed it.
                            if len(serial_number) > 1: found_serial = True
                            break
                    except sqlite3.Error as ex:
                        log.exception("Db cursor error while reading file " + source)

                except sqlite3.Error as ex:
                    log.error ("Sqlite error - \nError details: \n" + str(ex))
                conn.close()
        except sqlite3.Error as ex:
            log.error ("Failed to open {}, is it a valid DB? Error details: ".format(os.path.basename(source)) + str(ex))
    else:
        log.debug("File not found: {}".format(source))
    return (found_serial, serial_number)

def GetMacSerialNum(mac_info):
    sn_source1 = '/private/var/folders/zz/zyxvpxvq6csfxvn_n00000sm00006d/C/consolidated.db'
    sn_source2 = '/private/var/folders/zz/zyxvpxvq6csfxvn_n00000sm00006d/C/cache_encryptedA.db'
    sn_source3 = '/private/var/folders/zz/zyxvpxvq6csfxvn_n00000sm00006d/C/lockCache_encryptedA.db'

    found_SN = False
    serial_num = ''

    found_SN, serial_num = ReadSerialFromDb(mac_info, sn_source1)
    if found_SN:
        basic_data.append(['HARDWARE', 'Mac Serial Number', serial_num, 'Hardware Serial Number', sn_source1])
        mac_info.ExportFile(sn_source1, __Plugin_Name, '')
    else:
        found_SN, serial_num = ReadSerialFromDb(mac_info, sn_source2)
        if found_SN:
            basic_data.append(['HARDWARE', 'Mac Serial Number', serial_num,'Hardware Serial Number', sn_source2])
            mac_info.ExportFile(sn_source2, __Plugin_Name, '')
        else:
            found_SN, serial_num = ReadSerialFromDb(mac_info, sn_source3)
            if found_SN:
                basic_data.append(['HARDWARE', 'Mac Serial Number', serial_num,'Hardware Serial Number', sn_source3])
                mac_info.ExportFile(sn_source3, __Plugin_Name, '')

# Sources - /private/etc/localtime and /Library/Preferences/.GlobalPreferences.plist
def GetTimezone(mac_info):
    global_pref_plist_path = '/Library/Preferences/.GlobalPreferences.plist'
    mac_info.ExportFile(global_pref_plist_path, __Plugin_Name, '', False)
    success, plist, error_message = mac_info.ReadPlist(global_pref_plist_path)
    num_items_read = 0
    if success:
        for item in ['CountryCode','Latitude','Longitude','Name','RegionalCode','TimeZoneName','Version']:
            try:
                data = plist['com.apple.preferences.timezone.selected_city'][item]
                basic_data.append(['TIMEZONE', 'SelectedCity.' + item, data, '', global_pref_plist_path])
                num_items_read += 1
            except KeyError: pass
        mac_version_dict = mac_info.GetVersionDictionary()
        if num_items_read < 2 and (mac_version_dict['major'] == 10) and (mac_version_dict['minor'] < 12): # Not seen in later versions!
            log.info('Only read {} items from TimeZone.SelectedCity, this does not seem right!'.format(num_items_read))
    else:
        log.error('Failed to read plist ' + global_pref_plist_path + " Error was : " + error_message)

    # Read /private/etc/localtime --> /usr/share/zoneinfo/xxxxxxx
    try:
        tz_symlink_path = mac_info.ReadSymLinkTargetPath('/private/etc/localtime')
        if tz_symlink_path.startswith('/usr/share/zoneinfo'):
            tz_symlink_path = tz_symlink_path[20:]
        elif tz_symlink_path.startswith('/var/db/timezone/zoneinfo/'): # on HighSierra
            tz_symlink_path = tz_symlink_path[26:]
        basic_data.append(['TIMEZONE', 'TimeZone Set', tz_symlink_path, 'Timezone on machine', '/private/etc/localtime'])
    except (IndexError, ValueError) as ex:
        log.error('Error trying to read timezone information - ' + str(ex))

    # f = mac_info.Open('/private/etc/localtime')
    # if f:
    #     try:
    #         data = f.read(128).decode('utf8')
    #         if data.startswith('/usr/share/zoneinfo'):
    #             data = data[20:]
    #         elif data.startswith('/var/db/timezone/zoneinfo/'): # on HighSierra
    #             data = data[26:]
    #         data = data.rstrip('\x00')
    #         basic_data.append(['TIMEZONE', 'TimeZone Set', data, 'Timezone on machine', '/private/etc/localtime'])
    #     except:
    #         # if mounted on local system, this will resolve to the actual file and throw exception, we just wanted the symlink path!
    #         log.warning('Could not read file /private/etc/localtime. If this you are parsing local system using MOUNTED option this is normal!')
    # else:
    #     log.error('Could not open file /private/etc/localtime to read timezone information')

# Source - /Library/Preferences/com.apple.loginwindow.plist
# TODO: Perhaps move this to users plugin?
def GetLastLoggedInUser(mac_info):
    loginwindow_plist_path = '/Library/Preferences/com.apple.loginwindow.plist'
    mac_info.ExportFile(loginwindow_plist_path, __Plugin_Name, '', False)
    success, plist, error_message = mac_info.ReadPlist(loginwindow_plist_path)
    if success:
        try:
            for item, value in plist.items():
                if item in ['autoLoginUser','GuestEnabled','lastUserName']:
                    basic_data.append(['USER-LOGIN', item, value, '', loginwindow_plist_path])
                elif item == 'lastUser':
                    basic_data.append(['USER-LOGIN', item, value, 'Last user (Login) Action', loginwindow_plist_path])
                elif item == 'lastLoginPanic':
                    basic_data.append(['USER-LOGIN', item, CommonFunctions.ReadMacAbsoluteTime(value), '', loginwindow_plist_path])
                elif item.startswith('Optimizer') or item in ['SHOWFULLNAME']:
                    continue
                elif item == 'AccountInfo':
                    for k, v in value.items():
                        if k == 'FirstLogins':
                            for username in v.keys():
                                basic_data.append(['USER-LOGIN', item + '.' +  k, str(username), 'Logged in user once', loginwindow_plist_path])
                        elif k == 'MaximumUsers':
                            basic_data.append(['USER-LOGIN', item + '.' +  k, str(v), 'Maximum number of Fast User Switching (FUS) users at the same time', loginwindow_plist_path])
                        elif k == 'OnConsole':
                            for username in v.keys():
                                basic_data.append(['USER-LOGIN', item + '.' +  k, str(username), 'Logged in user once by Fast User Switching (FUS)', loginwindow_plist_path])
                        else:
                            basic_data.append(['USER-LOGIN', item + '.' +  k, str(v), '?', loginwindow_plist_path])
                else:
                    basic_data.append(['USER-LOGIN', item, str(value), 'unknown', loginwindow_plist_path])
        except ValueError as ex:
            log.error("Plist parsing error from GetLastLoggedInUser: " + str(ex))
    else:
        log.error('Failed to read plist ' + loginwindow_plist_path + " Error was : " + error_message)
    return

# Source - /Library/Preferences/SystemConfiguration/preferences.plist FOR ComputerName
def GetModelAndHostNameFromPreference(mac_info, preference_plist_path):
    #preference_plist_path = '/Library/Preferences/SystemConfiguration/preferences.plist'
    mac_info.ExportFile(preference_plist_path, __Plugin_Name, '', False)
    success, plist, error_message = mac_info.ReadPlist(preference_plist_path)
    if success:
        try:
            model = plist['Model']
            basic_data.append(['HARDWARE', 'Model', model, 'Mac Hardware Model', preference_plist_path])
        except KeyError: pass
        try:
            hostname = plist['System']['System']['HostName']
            basic_data.append(['SYSTEM', 'HostName', hostname, 'Host Name', preference_plist_path])
        except KeyError: log.info('/System/System/HostName not found in ' + preference_plist_path)
        try:
            computername = plist['System']['System']['ComputerName']
            basic_data.append(['SYSTEM', 'ComputerName', computername, '', preference_plist_path])
        except KeyError: log.info('/System/System/ComputerName not found in ' + preference_plist_path)
        try:
            other_host_names = plist['System']['Network']['HostNames']
            for k,v in list(other_host_names.items()):
                basic_data.append(['SYSTEM', k, v, '', preference_plist_path])
        except KeyError: log.info('/System/Network/HostNames not found in ' + preference_plist_path)
    else:
        log.error('Failed to read plist ' + preference_plist_path + " Error was : " + error_message)
    return

def GetMacOSVersion(mac_info):
    sys_ver_plist_path = '/System/Library/CoreServices/SystemVersion.plist'
    basic_data.append(['SYSTEM', 'macOS Version', mac_info.os_version, mac_info.os_friendly_name, sys_ver_plist_path])
    basic_data.append(['SYSTEM', 'macOS Build Version', mac_info.os_build, mac_info.os_friendly_name, sys_ver_plist_path])
    mac_info.ExportFile(sys_ver_plist_path, __Plugin_Name, "", False)

def Plugin_Start(mac_info):
    '''Main Entry point function for plugin'''
    GetMacOSVersion(mac_info)
    GetMacSerialNum(mac_info)
    GetModelAndHostNameFromPreference(mac_info, '/Library/Preferences/SystemConfiguration/preferences.plist')
    GetTimezone(mac_info)
    GetLastLoggedInUser(mac_info)
    GetVolumeInfo(mac_info)
    WriteList("basic machine info", "Basic_Info", basic_data, basic_data_info, mac_info.output_params)

def Plugin_Start_Standalone(input_files_list, output_params):
    log.info("This plugin cannot be run as standalone")

'''IOS
===========================================
'''
#Get IOS Version
def GetIOSVersion(ios_info):
    basic_data.append(['SYSTEM', 'iOS Version', ios_info.os_version, ios_info.os_friendly_name, '/System/Library/CoreServices/SystemVersion.plist'])
    basic_data.append(['SYSTEM', 'iOS Build Version', ios_info.os_build, ios_info.os_friendly_name, '/System/Library/CoreServices/SystemVersion.plist'])

def GetLastWipeDate(ios_info):
    pass #TODO

def GetDiskUsageAndSyncInfo(ios_info):
    plist_path = '/private/var/Mobile/Library/Preferences/com.apple.atc.plist'
    if ios_info.IsValidFilePath(plist_path):
        ios_info.ExportFile(plist_path, __Plugin_Name, '', False)
    success, plist, error = ios_info.ReadPlist(plist_path)
    if success:
        disk_usage = plist.get('DiskUsage', None)
        if disk_usage:
            disk_size = disk_usage.get('_PhysicalSize', '')
            free_size = disk_usage.get('_FreeSize', '')
            basic_data.append(['DISKUSAGE', 'Total Physical Size', f'{disk_size} bytes',
                '{:.2f} GB'.format(disk_size/ (1024 * 1024 * 1024)), plist_path])
            basic_data.append(['DISKUSAGE', 'Total Free Size', f'{free_size} bytes',
                '{:.2f} GB'.format(free_size/ (1024 * 1024 * 1024)), plist_path])
            for k, v in disk_usage.items():
                if not isinstance(v, dict):
                    continue
                category = k
                if '_Count' in v:
                    count = v.get('_Count', '')
                    phy_size = v.get('_PhysicalSize', '')
                    basic_data.append(['DISKUSAGE', category, f'{phy_size} bytes', f'Count={count}' if count else '', plist_path])
                else:
                    for sub_cat, values in v.items():
                        count = values.get('_Count', '')
                        phy_size = values.get('_PhysicalSize', 0)
                        basic_data.append(['DISKUSAGE', category + f'-{sub_cat}', f'{phy_size} bytes', f'Count={count}' if count else '', plist_path])
        hosts = plist.get('Hosts', None)
        if hosts:
            for k, v in hosts.items():
                host_id = k
                last_sync = v.get('LastSync', None)
                if last_sync:
                    last_sync = CommonFunctions.ReadMacAbsoluteTime(last_sync)
                os_type = v.get('OSType', '')
                os_ver = v.get('OSVersion', '')
                host_name = v.get('SyncHostName', '')
                basic_data.append([f'SYNC-HOST-{host_id}', 'Hostname',  host_name, '', plist_path])
                basic_data.append([f'SYNC-HOST-{host_id}', 'OS Name',  os_type, '', plist_path])
                basic_data.append([f'SYNC-HOST-{host_id}', 'OS Version',  os_ver, '', plist_path])
                basic_data.append([f'SYNC-HOST-{host_id}', 'Last Sync',  last_sync, '', plist_path])
    else:
        log.error(f'Error reading {plist_path} : {error}')


    #TODO
    # This plist also has last sync info

def GetLastFacetimeId(ios_info):
    tel_utilities_plist = '/private/var/Mobile/Library/Preferences/com.apple.TelephonyUtilities.plist'
    if ios_info.IsValidFilePath(tel_utilities_plist):
        ios_info.ExportFile(tel_utilities_plist, __Plugin_Name, '', False)
        success, plist, error = ios_info.ReadPlist(tel_utilities_plist)
        if success:
            facetime_id = plist.get('lastKnownFaceTimeCallerID', None)
            basic_data.append(['FACETIME', 'Last known Facetime Caller ID', facetime_id, '', tel_utilities_plist])
        else:
            log.error(f'Error reading {tel_utilities_plist} : {error}')

def GetPreviousRestoreDate(ios_info):
    prev_restore_date = None
    last_update_plist = '/private/var/MobileSoftwareUpdate/last_update_result.plist'
    if ios_info.IsValidFilePath(last_update_plist):
        ios_info.ExportFile(last_update_plist, __Plugin_Name, '', False)
        success, plist, error = ios_info.ReadPlist(last_update_plist)
        if success:
            prev_restore_date = plist.get('PreviousRestoreDate', None)
        else:
            log.error(f'Error reading {last_update_plist} : {error}')

    basic_data.append(['SYSTEM', 'iOS Previous Restore Date', prev_restore_date, '', last_update_plist])

def Plugin_Start_Ios(ios_info):
    '''Entry point for ios_apt plugin'''
    GetIOSVersion(ios_info)
    GetModelAndHostNameFromPreference(ios_info, '/private/var/Preferences/SystemConfiguration/preferences.plist')
    GetPreviousRestoreDate(ios_info)
    GetLastFacetimeId(ios_info)
    GetDiskUsageAndSyncInfo(ios_info)

    WriteList("basic device info", "Basic_Info", basic_data, basic_data_info, ios_info.output_params)

if __name__ == '__main__':
    print ("This plugin is a part of a framework and does not run independently on its own!")
