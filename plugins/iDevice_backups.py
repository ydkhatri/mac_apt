'''
   Copyright (c) 2018 Yogesh Khatri

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the
   terms of the MIT License.

   iDevice_backups.py
   ------------
   This plugin will scan for iPad/iPhone backups and export all files and databases found.
   It does not recreate the file and folder structure (for all exported files), there are 
   already many tools available to do this, just point them to the exported folder at 
   <YourOutputFolder>/Exports/IDEVICEBACKUPS/<USER>_<BACKUP_UUID>
'''

from __future__ import print_function
from __future__ import unicode_literals

from helpers.macinfo import *
from helpers.writer import *
from helpers.common import *
from biplist import *
import logging
import os

__Plugin_Name = "IDEVICEBACKUPS" # Cannot have spaces, and must be all caps!
__Plugin_Friendly_Name = "iDevice Backup Info"
__Plugin_Version = "1.0"
__Plugin_Description = "Reads and exports iPhone/iPad backup databases"
__Plugin_Author = "Jack Farley, Yogesh Khatri"
__Plugin_Author_Email = "jack.farley@mymail.champlain.edu, yogesh@swiftforensics.com"

__Plugin_Standalone = True
__Plugin_Standalone_Usage = 'Reads iDevice backup databases found at /Users/<USER>/Library/Application Support/MobileSync/Backup. '\
                            'Provide the path to this folder as input for this plugin'

log = logging.getLogger('MAIN.' + __Plugin_Name) # Do not rename or remove this ! This is the logger object

#---- Do not change the variable names in above section ----#

class iDeviceBackup:
    def __init__(self, Device_Name, Product_Name, Product_Model, Phone_Num, iOS_Vers, Backup_Start, Backup_End,
                 Last_Backup_Date, Passcode_Set, Encrypted, GUID, ICCID, IMEI, MEID, SN, Full_Backup, Version, iTunes_Vers, apps, user, source):

        self.Device_Name = Device_Name
        self.Product_Name = Product_Name
        self.Product_Model = Product_Model
        self.Phone_Num = Phone_Num
        self.iOS_Vers = iOS_Vers
        self.Backup_Start = Backup_Start
        self.Backup_End = Backup_End
        self.Last_Backup_Date = Last_Backup_Date
        self.Passcode_Set = Passcode_Set
        self.Encrypted = Encrypted
        self.GUID = GUID
        self.ICCID = ICCID
        self.IMEI = IMEI
        self.MEID = MEID
        self.SN = SN
        self.Full_Backup = Full_Backup
        self.Version = Version
        self.iTunes_Vers = iTunes_Vers
        self.apps = apps
        self.user = user
        self.source = source

def PrintAll(output_params, source_path, backups):
    backup_labels = [('Device_Name',DataType.TEXT),('Product_Name',DataType.TEXT),('Product_Model',DataType.TEXT),
                    ('Phone_Num',DataType.TEXT),('iOS_Vers',DataType.TEXT), ('Backup_Start',DataType.DATE),
                    ('Backup_End',DataType.DATE),('Last_Backup_Date',DataType.DATE),('Passcode_Set',DataType.TEXT),
                    ('Encrypted',DataType.TEXT),('GUID',DataType.TEXT),('ICCID',DataType.TEXT),
                    ('IMEI', DataType.TEXT), ('MEID', DataType.TEXT),('SN', DataType.TEXT),
                    ('Full_Backup', DataType.TEXT), ('Version', DataType.TEXT), ('iTunes_Vers', DataType.TEXT),
                    ('Apps_on_device',DataType.TEXT),('User', DataType.TEXT),('Source',DataType.TEXT)
                    ]

    backup_list = []
    for bkp in backups:
        bkps_item = [ bkp.Device_Name, bkp.Product_Name, bkp.Product_Model, bkp.Phone_Num,
                      bkp.iOS_Vers, bkp.Backup_Start, bkp.Backup_End, bkp.Last_Backup_Date, bkp.Passcode_Set, 
                      bkp.Encrypted, bkp.GUID, bkp.ICCID, bkp.IMEI, bkp.MEID,
                      bkp.SN, bkp.Full_Backup, bkp.Version, bkp.iTunes_Vers, 
                      bkp.apps, bkp.user, bkp.source  
                     ]
        backup_list.append(bkps_item)

    WriteList("iDevice Backups", "iDevice_Backups", backup_list, backup_labels, output_params, source_path)

def BackupFinder(mac_info, source, user):
    '''Finds backup folders and returns them in a list'''
    paths = []
    backup_folders = mac_info.ListItemsInFolder(source, EntryType.FOLDERS, True)
    if len(backup_folders) > 0:
        log.info(str(len(backup_folders)) + " iDevice Backups Found for user " + user)
        for folder in backup_folders:
            full_folder_path = source + '/' + folder['name']
            paths.append(full_folder_path)
    return paths

def ReadBackups(mac_info, export_folder_path, info_plist_path, status_plist_path, manifest_plist_path, user, backups, source):
    '''Captures relevant data in Info.plist, Status.plist, Manifest.plist'''
    success, info_plist, error = mac_info.ReadPlist(info_plist_path)
    if not success:
        info_plist = {}
        log.error('Error reading Info.plist - ' + error)

    success, status_plist, error = mac_info.ReadPlist(status_plist_path)
    if not success:
        status_plist = {}
        log.error('Error reading Status.plist - ' + error)

    success, manifest_plist, error = mac_info.ReadPlist(manifest_plist_path)
    if not success:
        manifest_plist = {}
        log.error('Error reading Manifest.plist - ' + error)
    
    ReadDataFromPlists(info_plist, status_plist, manifest_plist, user, backups, source)
    # Try exporting files
    base_folder = os.path.dirname(info_plist_path)
    log.debug('Lets try to export files now from {}'.format(base_folder))
    files_exported = 0
    import time
    time_processing_started = time.time()
    folders = mac_info.ListItemsInFolder(base_folder, EntryType.FOLDERS, False)
    for folder in folders:
        path = base_folder + '/' + folder['name']
        files = mac_info.ListItemsInFolder(path, EntryType.FILES, False)
        for item in files:
            mac_info.ExportFile(path + '/' + item['name'], export_folder_path, '', False)
            files_exported += 1

    time_processing_ended = time.time()
    run_time = time_processing_ended - time_processing_started
    log.debug("export time for {} files = {}".format(time.strftime('%H:%M:%S', time.gmtime(run_time)), files_exported))


def ReadDataFromPlists(info_plist, status_plist, manifest_plist, user, backups, source):

    lockdown = manifest_plist.get('Lockdown', {})
    deviceName = info_plist.get('Device Name', '')

    bkps = iDeviceBackup(
        deviceName,
        info_plist.get('Product Name', ''),
        info_plist.get('Product Type', ''),
        info_plist.get('Phone Number', ''),
        lockdown.get('ProductVersion', ''),
        manifest_plist.get('Date', ''),
        status_plist.get('Date', ''),
        info_plist.get('Last Backup Date', ''),
        manifest_plist.get('WasPasscodeSet', ''),
        manifest_plist.get('IsEncrypted', ''),
        info_plist.get('GUID', ''),
        info_plist.get('ICCID', ''),
        info_plist.get('IMEI', ''),
        info_plist.get('MEID', ''),
        info_plist.get('Serial Number', ''),
        status_plist.get('IsFullBackup', ''),
        status_plist.get('Version', ''),
        info_plist.get('iTunes Version', ''),
        ",".join(ReadApps(info_plist.get('Applications', {}))),
        user,
        source)
    backups.append(bkps)

def ReadApps(applications_dict):
    '''Get's application names only'''
    #TODO- Get all app details
    apps = []
    for k, v in applications_dict.items():
        plist_string = v.get('iTunesMetadata', None)
        if plist_string:
            try:
                plist = readPlistFromString(plist_string)
                app_name = plist.get('itemName')
                if app_name:
                    apps.append(app_name)
            except:
                log.debug('Failed to read embedded plist for {}'.format(k))
    return apps

def ReadBackupsStandalone(info_plist_path, status_plist_path, manifest_plist_path, backups, source):
    try:
        info_plist = readPlist(info_plist_path)
    except:
        log.exception("Failed to read Info.plist from path {}".format(info_plist_path))
        info_plist = {}
    try:
        status_plist = readPlist(status_plist_path)
    except:
        log.exception("Failed to read Status.plist from path {}".format(status_plist_path))
        status_plist = {}
    try:
        manifest_plist = readPlist(manifest_plist_path)
    except:
        log.exception("Failed to read Manifest.plist from path {}".format(manifest_plist_path))
        manifest_plist = {}

    ReadDataFromPlists(info_plist, status_plist, manifest_plist, '', backups, source)

def Plugin_Start(mac_info):
    '''Main Entry point function for plugin'''
    backupPath = '{}/Library/Application Support/MobileSync/Backup'
    processed_paths = []
    backups = []
    for user in mac_info.users:
        for user in mac_info.users:
            user_name = user.user_name
            if user.home_dir == '/private/var':
                continue  # Optimization, nothing should be here!
            elif user.home_dir == '/private/var/root':
                user_name = 'root'  # Some other users use the same root folder, we will list such all users as 'root', as there is no way to tell
            if user.home_dir in processed_paths: continue  # Avoid processing same folder twice (some users have same folder! (Eg: root & daemon))
            processed_paths.append(user.home_dir)
            userBackupPath = backupPath.format(user.home_dir)
            if mac_info.IsValidFolderPath(userBackupPath):
                deviceFolders = BackupFinder(mac_info, userBackupPath, user_name)
                for folder in deviceFolders:
                    info_plist_path = folder + '/Info.plist'
                    status_plist_path = folder + '/Status.plist'
                    manifest_plist_path = folder + '/Manifest.plist'
                    manifest_db_path1 = folder + '/Manifest.mbdb'
                    manifest_db_path2 = folder + '/Manifest.db'   # ios 9 and above
                    export_folder_path = os.path.join(__Plugin_Name, user_name + "_" + os.path.basename(folder)) # Should create folder EXPORT/IDEVICEBACKUPS/user_BackupUUID/
                    if mac_info.IsValidFilePath(info_plist_path):
                        mac_info.ExportFile(info_plist_path, export_folder_path, '', False)
                    else:
                        log.error("Failed to find Info.plist in {}".format(folder))
                    if mac_info.IsValidFilePath(status_plist_path):
                        mac_info.ExportFile(status_plist_path, export_folder_path, '', False)
                    else:
                        log.error("Failed to find Status.plist in {}".format(folder))
                    if mac_info.IsValidFilePath(manifest_plist_path):
                        mac_info.ExportFile(manifest_plist_path, export_folder_path, '', False)
                    else:
                        log.error("Failed to find Manifest.plist in {}".format(folder))
                    if mac_info.IsValidFilePath(manifest_db_path1):
                        mac_info.ExportFile(manifest_db_path1, export_folder_path, '', False)
                    elif mac_info.IsValidFilePath(manifest_db_path2):
                        mac_info.ExportFile(manifest_db_path2, export_folder_path, '', False)

                    ReadBackups(mac_info, export_folder_path, info_plist_path, status_plist_path, manifest_plist_path, user.user_name, backups, folder)
    if backups:
        PrintAll(mac_info.output_params, '', backups)
    else:
        log.info('No iDevice backups found')

def Plugin_Start_Standalone(input_files_list, output_params):
    log.info("Module Started as standalone")
    backups = []
    inputFolder = str(input_files_list[0])
    if os.path.isdir(inputFolder):
        log.debug("Input folder passed was: " + inputFolder)
        info_plist_path = os.path.join(inputFolder, 'Info.plist')
        status_plist_path = os.path.join(inputFolder, 'Status.plist')
        manifest_plist_path = os.path.join(inputFolder, 'Manifest.plist')
        ReadBackupsStandalone(info_plist_path, status_plist_path, manifest_plist_path, backups, inputFolder)
        if backups:
            PrintAll(output_params, '', backups)
        else:
            log.info('No iDevice backups found')
    else:
        log.error("Input must be a folder containing backup plists and data")

if __name__ == '__main__':
    print ("This plugin is a part of a framework and does not run independently on its own!")
