'''
   Copyright (c) 2017 Yogesh Khatri 

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the 
   terms of the MIT License.
   
'''

import logging
import os
import posixpath

from plistutils.alias import AliasParser

from plugins.helpers.bookmark import *
from plugins.helpers.macinfo import *
from plugins.helpers.writer import *

__Plugin_Name = "AUTOSTART" # Cannot have spaces, and must be all caps!
__Plugin_Friendly_Name = "Auto start"
__Plugin_Version = "2.0"
__Plugin_Description = "Retrieves persistent and auto-start programs, daemons, services"
__Plugin_Author = "Brandon Mignini, Yogesh Khatri, Minoru Kobayashi"
__Plugin_Author_Email = "brandon.mignini@mymail.champlain.edu, khatri@champlain.edu, unknownbit@gmail.com"
__Plugin_Modes = "MACOS,ARTIFACTONLY"
__Plugin_Standalone = False
__Plugin_ArtifactOnly_Usage = "Provide individual .btm file found at /private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v*.btm"

log = logging.getLogger('MAIN.' + __Plugin_Name) # Do not rename or remove this ! This is the logger object

#---- Do not change the variable names in above section ----#

# TODO: Old deprecated methods:
#     /private/var/at/jobs/  <--- CRONTAB
#  Login & Logout hooks- https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CustomLogin.html
# Good resource -> https://www.launchd.info/
# For explanation on StartupTypes, see https://keith.github.io/xcode-man-pages/launchd.plist.5.html

DispositionValues = {
    0x01: 'Enabled',
    0x02: 'Allowed',
    0x04: 'Hidden',
    0x08: 'Notified'
}

# Types as per sfltool dumpbtm output
TypeValues = {
    0x01: 'user item',
    0x02: 'app',
    0x04: 'login item',
    0x08: 'agent',
    0x10: 'daemon',
    0x20: 'developer',
    0x40: 'spotlight',
    0x800: 'quicklook',
    0x80000: 'curated',
    0x10000: 'legacy'
}

class PersistentProgram:
    def __init__(self, source, name, full_name, persistence_type, user, uid, disabled, app_path,
                 app_args='', btm_disp=0, btm_type=0, btm_flags=0, btm_developer='', btm_container='',
                 btm_exec_mod_date=0, btm_dev_identifier=''):
        self.source = source
        self.name = name
        self.full_name = full_name
        self.persistence_type = persistence_type
        self.user = user
        self.uid = uid
        self.disabled = disabled
        self.start_when = ''
        self.app_path = app_path
        self.app_args = app_args
        self.btm_disposition = btm_disp
        self.btm_type = btm_type
        self.btm_flags = btm_flags
        self.btm_developer = btm_developer
        self.btm_container = btm_container
        self.btm_exec_mod_date = btm_exec_mod_date
        self.btm_dev_identifier = btm_dev_identifier

def process_loginitems_plist(mac_info, plist_path, user, uid, persistent_programs):
    mac_info.ExportFile(plist_path, __Plugin_Name, user + "_", False)
    success, plist, error = mac_info.ReadPlist(plist_path)
    if success:
        try:
            items = plist['SessionItems']['CustomListItems']
            for item in items:
                try:
                    name = item.get('Name', '')
                    path = ''
                    alias_data = item.get('Alias', None)
                    if alias_data:
                        try:
                            alias_properties = next(AliasParser.parse(plist_path, 0, alias_data))
                            path = alias_properties.get('path', '')
                        except (IndexError, ValueError, KeyError, TypeError):
                            log.exception('')
                    program = PersistentProgram(plist_path, name, name, 'Login Item', user, uid, '', path)
                    program.start_when = 'Run at Login'
                    persistent_programs.append(program)
                except (ValueError, TypeError):
                    log.exception('')
        except KeyError:
            pass # SessionItems or CustomListItems not present
            log.warning('Possibly a newer version of com.apple.loginitems.plist Filepath was {}'.format(plist_path))
                    #Look for legacy LoginHook LogoutHook
        login_hook = plist.get('LoginHook', '')
        if login_hook:
            program = PersistentProgram(plist_path, os.path.basename(login_hook), name, 'Login Hook', user, uid, '', login_hook)
            program.start_when = 'Run at Login'
            persistent_programs.append(program)
        logout_hook = plist.get('LogoutHook', '')
        if logout_hook:
            program = PersistentProgram(plist_path, os.path.basename(logout_hook), name, 'Logout Hook', user, uid, '', logout_hook)
            program.start_when = 'Run at Logout'
            persistent_programs.append(program)
    else:
        log.error("Problem reading plist for {} - {}".format(plist_path, error))

def process_backgrounditems_btm(mac_info, btm_path, user, uid, persistent_programs):
    global DispositionValues
    global TypeValues
    if mac_info:
        mac_info.ExportFile(btm_path, __Plugin_Name, user + "_", False)
        success, plist, error = mac_info.ReadPlist(btm_path, deserialize=True)
    else:
        success, plist, error = CommonFunctions.ReadPlist(btm_path, deserialize=True)
    if success:
        # >= macOS 10.13 and <= macOS 12
        if isinstance(plist, dict) and plist['version'] == 2:
            all_containers = plist.get('backgroundItems', {}).get('allContainers', {})
            for container in all_containers:
                try:
                    bm = container['internalItems'][0]['bookmark']['data']
                except (KeyError, ValueError, TypeError) as ex:
                    log.error('Error fetching bookmark data ' + str(ex))
                    continue
                if isinstance(bm, bytes):
                    bm = Bookmark.from_bytes(bm)
                elif isinstance(bm, dict):
                    try:
                        bm = Bookmark.from_bytes(bm['NS.data'])
                    except (KeyError, ValueError, TypeError):
                        log.exception("Failed to read NS.data as bookmark")
                        continue
                try:
                    # record type 0xf017 means an item name
                    name = bm.tocs[0][1].get(0xf017, '')

                    # Get full file path
                    vol_path = bm.tocs[0][1].get(BookmarkKey.VolumePath, '')
                    file_path = bm.tocs[0][1].get(BookmarkKey.Path, [])
                    file_path = '/' + '/'.join(file_path)
                    if vol_path and (not file_path.startswith(vol_path)):
                        file_path = vol_path + file_path

                    # If file is on a mounted volume (dmg), get the dmg file details too
                    orig_vol_bm = bm.tocs[0][1].get(BookmarkKey.VolumeBookmark, None)
                    if orig_vol_bm:
                        filtered = list(filter(lambda x: x[0]==orig_vol_bm, bm.tocs))
                        if filtered:
                            orig_vol_toc = filtered[0][1]
                            orig_vol_path = orig_vol_toc.get(BookmarkKey.Path, '')
                            orig_vol_creation_date = orig_vol_toc.get(BookmarkKey.VolumeCreationDate, '')
                            if orig_vol_path:
                                orig_vol_path = '/' + '/'.join(orig_vol_path)
                                log.info
                        else:
                            print ("Error, tid {} not found ".format(orig_vol_bm))
                except (TypeError, KeyError, ValueError) as ex:
                    log.exception('Problem reading btm bookmark')
                    continue

                if not name:
                    name = os.path.basename(file_path)
                program = PersistentProgram(btm_path, name, file_path, 'Background Task Management Agent', user, uid, '', file_path)
                program.start_when = 'Run at Login'
                persistent_programs.append(program)

        # >= macOS 13
        elif isinstance(plist, list) and plist[0].get('version', 0) >= 3:
            log.info(f'BTM version is {plist[0]["version"]}')
            for uuid in plist[1]['store']['itemsByUserIdentifier'].keys():
                user_name = ''
                if mac_info:
                    for user_info in mac_info.users:
                        if uuid == user_info.UUID:
                            user_name = user_info.user_name
                            user_uid = user_info.UID
                            break

                if not user_name:
                    user_name = 'unknown (' + uuid + ')'
                    user_uid = ''

                for item_number in list(range(len(plist[1]['store']['itemsByUserIdentifier'][uuid]))):
                    entry = plist[1]['store']['itemsByUserIdentifier'][uuid][item_number]
                    if entry.get('url', ''):
                        url_relative = entry['url'].get('NS.relative', '')
                    else:
                        url_relative = ''
                    app_arguments = ' '.join(entry.get('programArguments', []))
                    btm_disp = entry.get('disposition', 0)
                    btm_type = entry.get('type', 0)
                    btm_flags = entry.get('flags', 0)
                    btm_dev = entry.get('developerName', '')
                    btm_container = entry.get('container', '')
                    btm_exec_mod_date = entry.get('executableModificationDate', '')
                    btm_team_identifier = entry.get('teamIdentifier', '')
                    name = entry.get('name', '')

                    if btm_type == 0x20:
                        continue # We don't care about 0x20:'developer', these aren't autostart entries
                    
                    executable_path = entry.get('executablePath', '')
                    items = entry.get('items', '')

                    start_when = ''
                    if url_relative.endswith('.plist'):
                        file_path = executable_path
                        if '/LaunchAgents/' in url_relative:
                            start_when = 'Run at Login'
                        elif '/LaunchDaemons/' in url_relative:
                            start_when = 'Run at Boot'
                    elif url_relative:
                        file_path = url_relative
                        start_when = 'Run at Login'
                    elif items:
                        file_path = items[0]
                    else:
                        file_path = 'unknown'

                    program = PersistentProgram(btm_path, name, file_path, 'Background Task Management Agent', user_name, user_uid, 
                                                '' if btm_disp & 0x1 == 1 else '1', file_path, app_arguments, 
                                                btm_disp, btm_type, btm_flags, btm_dev, btm_container, btm_exec_mod_date, btm_team_identifier)
                    program.start_when = start_when
                    persistent_programs.append(program)

        else:
            log.error('Unsupported btm file: {}'.format(btm_path))

    else:
        log.error('Failed to read btm file, Error was ' + error)

def process_kernel_extensions(mac_info, path, persistent_programs):
    folder_list = mac_info.ListItemsInFolder(path, EntryType.FOLDERS, False)
    if len(folder_list):
        for folder in folder_list:
            full_name = folder['name']
            full_path = path + '/' + full_name

            name = os.path.splitext(full_name)[0] # removes extension (.kext or .plugin or .bundle usually)
            valid_source = full_path
            info_plist_path = full_path + '/Contents/Info.plist'
            if mac_info.IsValidFilePath(info_plist_path):
                valid_source = info_plist_path
                success, plist, error = mac_info.ReadPlist(info_plist_path)
                if success:
                    name = plist.get('CFBundleName', name)
                    name = name.lstrip('"').rstrip('"')
                else:
                    log.error("Problem reading plist for {} - {}".format(info_plist_path, error))
                mac_info.ExportFile(info_plist_path, __Plugin_Name, "kext_" + name + "_", False)
            program = PersistentProgram(valid_source, name, full_name, 'Kernel Extension', 'root', 0, '', '')
            persistent_programs.append(program)
    else:
        log.info('No kernel extensions found under {}'.format(path))

def process_dir(mac_info, path, persistent_programs, method, user_name, uid):
    '''Description'''
    files_list = mac_info.ListItemsInFolder(path, EntryType.FILES, False)
    if len(files_list):
        for file in files_list:
            file_name = file['name']
            full_path = path + '/' + file_name
            if file_name.lower().endswith('.plist'):
                common_name = file_name.split('.')
                if len(common_name) >= 4:
                    del common_name[0]
                    del common_name[0]
                    del common_name[-1]
                    common_name = '.'.join(common_name)
                else:
                    common_name = common_name[len(common_name)-2]
            else:
                common_name = file_name
            full_name = os.path.splitext(file_name)[0]
            disabled = ''
            program = PersistentProgram(full_path, common_name, full_name, method, user_name, uid, disabled, '')

            if mac_info.IsSymbolicLink(full_path):
                target_path = mac_info.ReadSymLinkTargetPath(full_path)
                log.debug('SYMLINK {} <==> {}'.format(full_path, target_path))
                if target_path.startswith('../') or target_path.startswith('./'):
                    full_path = mac_info.GetAbsolutePath(posixpath.split(full_path)[0], target_path)
                else:
                    full_path = target_path
            if full_path.startswith('/System/Cryptexes/App/'):
                # This is a sym link to /../../System/Volumes/Preboot/Cryptexes/App   
                # Read from mac_info.apfs_preboot_volume.
                pass #TODO
                # TODO - change ExportFile and some other functions to accept a volume, or perhaps better to 
                #        add Preboot volume to the Combined_Volume after reading the 

            mac_info.ExportFile(full_path, __Plugin_Name, user_name + "_", False)

            if method == 'Daemon' or method == 'Agents':
                success, plist, error = mac_info.ReadPlist(full_path)
                if success:
                    disabled_param = plist.get('Disabled', '')
                    if isinstance(disabled_param, dict):
                        feature_flag_enabled = disabled_param.get('#IfFeatureFlagEnabled', '')
                        feature_flag_disabled = disabled_param.get('#IfFeatureFlagDisabled', '')
                        _disabled = disabled_param.get('#Then', '')
                        msg = ''
                        if feature_flag_enabled:
                            msg = 'IfFeatureFlagEnabled {} Then {}'.format(feature_flag_enabled, _disabled)
                        elif feature_flag_disabled:
                            msg = 'IfFeatureFlagDisabled {} Then {}'.format(feature_flag_disabled, _disabled)
                        else:
                            log.error('Unsupported plist Disabled parameter: {}'.format(disabled_param))
                            for k, v in disabled_param.items():
                                if msg:
                                    msg += ', {}:{}'.format(k, v)
                                else:
                                    msg = '{}:{}'.format(k, v)
                        program.disabled = msg
                    else:
                        program.disabled = disabled_param

                    program_path = plist.get('Program', '')
                    if not program_path:
                        program_args = plist.get('ProgramArguments', None)
                        if program_args:
                            program_path = program_args[0]
                    program.app_path = program_path
                    program.app_args = ' '.join(program_args)
                    persistent_programs.append(program)
                    program.start_when = get_run_when(plist, method)
                    program.user = plist.get('UserName', program.user) # plist can override this, so get that value
                else:
                    log.error("Problem reading plist for {} - {}".format(full_path, error))
            else:
                persistent_programs.append(program)

def get_run_when(plist, method):
    run_when = []
    run_at_load = plist.get('RunAtLoad', False)
    keep_alive = plist.get('KeepAlive', False)
    # This can be a dictionary. If AfterInitialDemand is True in this dict, then it is loaded but not started, ie, manual start.
    if isinstance(keep_alive, dict):
        after_initial_demand = keep_alive.get('AfterInitialDemand', False)
        if after_initial_demand == True:
            keep_alive = False
        else:
            keep_alive = True
    if run_at_load or keep_alive:
        #run_when.append('RunAtLoad') # if run_at_load else '') # 'DontRunAtLoad'
        #For daemons this means execution at boot time, for agents execution at login.
        if method == 'Daemon':
            run_when.append('Run at Boot')
        elif method == 'Agents':
            run_when.append('Run at Login')
    for item in ('StartInterval', 'StartCalendarInterval', 'StartOnMount', 'WatchPaths', 'QueueDirectories'):
        val = plist.get(item, '')
        if val:
            run_when.append(f'{item}={str(val)}')
    return ', '.join(run_when)

def process_file(mac_info, file_path, persistent_programs, file_name):
    full_path = file_path + '/' + file_name
    mac_info.ExportFile(full_path, __Plugin_Name, '', False)
    program = PersistentProgram(full_path, file_name, file_name, "Launch Script", 'root', 0, '', '')
    persistent_programs.append(program)

def process_overrides(mac_info, file_path, user, uid, persistent_programs):
    mac_info.ExportFile(file_path, __Plugin_Name, user + "_", False)
    success, plist, error = mac_info.ReadPlist(file_path)
    if success:
        for k, v in plist.items():
            disabled_value = v.get('Disabled', None)
            if disabled_value != None:
                for prog in persistent_programs:
                    if (prog.full_name == k) and (prog.uid == uid):
                        prog.disabled = disabled_value
                        log.debug("Override applied to {}".format(k))
                        break
            else:
                log.error('Did not find "Disabled" in override for {}'.format(k))
    else:
        log.error("Problem reading plist for {} - {}".format(file_path, error))

def ProcessLoginRestartApps(mac_info, persistent_programs):
    '''Gets apps/windows set to relaunch upon re-login (after logout)'''
    processed_paths = set()
    plist_folder_path = '{}/Library/Preferences/ByHost' # /com.apple.loginwindow.<UUID>.plist'

    for user in mac_info.users:
        user_name = user.user_name
        if user.home_dir == '/private/var/empty': continue # Optimization, nothing should be here!
        elif user.home_dir == '/private/var/root': user_name = 'root' # Some other users use the same root folder, we will list such all users as 'root', as there is no way to tell
        if user.home_dir in processed_paths: continue # Avoid processing same folder twice (some users have same folder! (Eg: root & daemon))
        processed_paths.add(user.home_dir)
        folder_path = plist_folder_path.format(user.home_dir)
        if mac_info.IsValidFolderPath(folder_path):
            files_list = mac_info.ListItemsInFolder(folder_path, EntryType.FILES, False)
            for file in files_list:
                file_name = file['name']
                full_path = folder_path + '/' + file_name
                if file_name.startswith('com.apple.loginwindow.') and len(file_name) == 64 and file_name.endswith('.plist') and file['size'] > 85:
                    mac_info.ExportFile(full_path, __Plugin_Name, user_name + "_", False)
                    success, plist, error = mac_info.ReadPlist(full_path)
                    if success:
                        items = plist.get('TALAppsToRelaunchAtLogin', [])
                        for item in items:
                            bundle_id = item.get('BundleID', '')
                            bundle_path = item.get('Path', '')
                            program = PersistentProgram(full_path, bundle_id, file_name, "Apps To Relaunch At Login", user_name, user.UID, '', bundle_path)
                            program.start_when = 'Run at Login'
                            persistent_programs.append(program)
                    else:
                        log.error("Problem reading plist {} - {}".format(full_path, error))

def GetEventFlagsString(flags, flag_values):
    '''Get string names of all flags set'''
    list_flags = []
    for k, v in list(flag_values.items()):
        if (k & flags) != 0:
            list_flags.append(v)
    return '|'.join(list_flags)

def print_all(programs, output_params, source_path):
    global DispositionValues
    global TypeValues
    program_info = [ ('Type',DataType.TEXT),('Name',DataType.TEXT),
                     ('User',DataType.TEXT),('StartupType',DataType.TEXT),('Disabled',DataType.TEXT),
                     ('AppPath',DataType.TEXT),('AppArguments',DataType.TEXT),
                     ('BTM_Disposition',DataType.TEXT),('BTM_Type',DataType.TEXT),
                     #('BTM_Flags',DataType.TEXT),
                     ('BTM_Developer',DataType.TEXT),('BTM_TeamIdentifier',DataType.TEXT),
                     ('BTM_Container',DataType.TEXT),('BTM_ExecutableModDate',DataType.DATE),
                     ('Source',DataType.TEXT) ]
    data_list = []
    log.info("Found {} autostart item(s)".format(len(programs)))
    for program in programs:
        disp_str = GetEventFlagsString(program.btm_disposition, DispositionValues)
        if disp_str.find('Allowed') < 0:
            disp_str = '|'.join(('NOT Allowed', disp_str))
        data_list.append([program.persistence_type, program.name, program.user, program.start_when, 
                          program.disabled, program.app_path, program.app_args,
                          disp_str, GetEventFlagsString(program.btm_type, TypeValues),
                          program.btm_developer, program.btm_dev_identifier, program.btm_container, 
                          CommonFunctions.ReadMacAbsoluteTime(program.btm_exec_mod_date), 
                          #program.flags,
                          program.source])
    WriteList("autostart information", "AutoStart", data_list, program_info, output_params, source_path)

def Plugin_Start(mac_info):
    '''Main Entry point function for plugin'''
    kext_paths = ('/System/Library/Extensions', '/Library/Extensions')
    persistent_system_paths = { 'Daemon': ['/System/Library/LaunchDaemons', '/Library/LaunchDaemons'], 
                                'Agents': ['/System/Library/LaunchAgents', '/Library/LaunchAgents'], 
                                'Startup Item': ['/System/Library/StartupItems', '/Library/StartupItems'], 
                                'Periodic': ['/private/etc/periodic/daily','/private/etc/periodic/monthly','/private/etc/periodic/weekly']
                              }
    persistent_file_paths = { '/private/etc' : ['rc.common', 'launchd.conf']}
    persistent_usr_paths = {'Agents' : ['/Library/LaunchAgents'] }
    processed_paths = set()
    persistent_programs = []

    ### process kernel extensions ###
    for path in kext_paths:
        process_kernel_extensions(mac_info, path, persistent_programs)

    ### process system directories  ###
    for method in persistent_system_paths:
        for path in persistent_system_paths[method]:
            if path in processed_paths: continue
            if mac_info.IsValidFolderPath(path):
                processed_paths.add(path)
                process_dir(mac_info, path, persistent_programs, method, 'root', 0)

    ### process system files ###
    for file_path in persistent_file_paths:
        for file_name in persistent_file_paths[file_path]:
            if file_name in processed_paths: continue
            if mac_info.IsValidFilePath(file_path + '/' + file_name):
                processed_paths.add(file_name)
                process_file(mac_info, file_path, persistent_programs, file_name)

    ### process user dirs ###
    for user in mac_info.users:
        user_name = user.user_name
        if user.home_dir == '/private/var/empty': continue # Optimization, nothing should be here!
        elif user.home_dir == '/private/var/root': user_name = 'root' # Some other users use the same root folder, we will list such all users as 'root', as there is no way to tell
        if user.home_dir in processed_paths: continue # Avoid processing same folder twice (some users have same folder! (Eg: root & daemon))
        processed_paths.add(user.home_dir)
        for method in persistent_usr_paths:
            for path in persistent_usr_paths[method]:
                full_path = "{0}{1}".format(user.home_dir, path)
                if mac_info.IsValidFolderPath(full_path):
                    process_dir(mac_info, full_path, persistent_programs, method, user_name, user.UID)
                else:
                    log.debug("Folder not found {}".format(full_path))

        # process loginitems plist
        loginitems_plist_path = '{}/Library/Preferences/com.apple.loginitems.plist'.format(user.home_dir)
        if mac_info.IsValidFilePath(loginitems_plist_path) and mac_info.GetFileSize(loginitems_plist_path) > 70:
            process_loginitems_plist(mac_info, loginitems_plist_path, user_name, user.UID, persistent_programs)

        # process backgrounditems.btm
        backgrounditems_btm_path = '{}/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm'.format(user.home_dir)
        if mac_info.IsValidFilePath(backgrounditems_btm_path):
            process_backgrounditems_btm(mac_info, backgrounditems_btm_path, user_name, user.UID, persistent_programs)

    # process BackgroundItems-v*.btm
    backgrounditems_btm_base_path = '/private/var/db/com.apple.backgroundtaskmanagement'
    if mac_info.IsValidFolderPath(backgrounditems_btm_base_path):
        files_list = mac_info.ListItemsInFolder(backgrounditems_btm_base_path, EntryType.FILES, include_dates=False)
        for file_entry in files_list:
                backgrounditems_btm_path = backgrounditems_btm_base_path + '/' + file_entry['name']
                process_backgrounditems_btm(mac_info, backgrounditems_btm_path, 'root', 0, persistent_programs)

    # system overrides
    override_plist_path = '/private/var/db/launchd.db/com.apple.launchd/overrides.plist'
    if mac_info.IsValidFilePath(override_plist_path) and mac_info.GetFileSize(override_plist_path):
        process_overrides(mac_info, override_plist_path, 'root', 0, persistent_programs)

    # user overrides
    user_override_folder = '/private/var/db/launchd.db'
    if mac_info.IsValidFilePath(user_override_folder):
        folder_list = mac_info.ListItemsInFolder(user_override_folder, EntryType.FOLDERS, False)
        if len(folder_list):
            for folder in folder_list:
                full_name = folder['name']
                if len(full_name) > 26 and full_name.startswith('com.apple.launchd.peruser.'):
                    uid_str = full_name[26:]
                    uid = CommonFunctions.IntFromStr(uid_str, error_val=None)
                    if uid != None:
                        uid = CommonFunctions.convert_32bit_num_to_signed(uid)
                        uid_str = str(uid)
                        user_name = ''
                        for user in mac_info.users:
                            if user.UID == uid_str:
                                user_name = user.user_name
                                break
                        if user_name != '':
                            override_plist_path = '/private/var/db/launchd.db/com.apple.launchd.peruser.{}/overrides.plist'.format(user.UID)
                            if mac_info.IsValidFilePath(override_plist_path) and mac_info.GetFileSize(override_plist_path):
                                process_overrides(mac_info, override_plist_path, user_name, uid, persistent_programs)
                        else:
                            log.error("Failed to get username for UID={}. This was found in filename {}".format(uid, full_name))
                    else:
                        log.error("Failed to get uid from filename {}".format(full_name))
    else:
        log.info('User overrides not present as folder {} not present'.format(user_override_folder))
    # user apps/windows to restart after logon/restart
    ### process user dirs ###
    ProcessLoginRestartApps(mac_info, persistent_programs)

    print_all(persistent_programs, mac_info.output_params, '')

def Plugin_Start_Standalone(input_files_list, output_params):
    '''Main entry point function when used on single artifacts (mac_apt_singleplugin), not on a full disk image'''
    log.info("Module Started as standalone")
    for input_path in input_files_list:
        log.debug("Input path passed was: " + input_path)
        persistent_programs = []
        if input_path.lower().endswith('.btm'):
            process_backgrounditems_btm(None, input_path, '', 0, persistent_programs)
        else:
            log.error('Did not process file as it does not end in ".btm"')

        if len(persistent_programs) > 0:
            print_all(persistent_programs, output_params, input_path)
        else:
            log.info('No autostart artifacts found in {}'.format(input_path))