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
from plugins.helpers.macinfo import *
from plugins.helpers.writer import *

__Plugin_Name = "AUTOSTART" # Cannot have spaces, and must be all caps!
__Plugin_Friendly_Name = "Auto start"
__Plugin_Version = "1.0"
__Plugin_Description = "Retrieves persistent and auto-start programs, daemons, services"
__Plugin_Author = "Brandon Mignini, Yogesh Khatri"
__Plugin_Author_Email = "brandon.mignini@mymail.champlain.edu, khatri@champlain.edu"
__Plugin_Modes = "MACOS"
__Plugin_Standalone = False
__Plugin_ArtifactOnly_Usage = ""

log = logging.getLogger('MAIN.' + __Plugin_Name) # Do not rename or remove this ! This is the logger object

#---- Do not change the variable names in above section ----#

# TODO: Old deprecated methods:
#     /private/var/at/jobs/  <--- CRONTAB
#  Login & Logout hooks- https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CustomLogin.html
# Good resource -> https://www.launchd.info/


class PersistentProgram:
    def __init__(self, source, name, full_name, persistence_type, user, uid, disabled, app_path):
        self.source = source
        self.name = name
        self.full_name = full_name
        self.persistence_type = persistence_type
        self.user = user
        self.uid = uid
        self.disabled = disabled
        self.start_when = ''
        self.app_path = app_path

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
        log.error("Problem reading plist for {} - ".format(plist_path, error))

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
                mac_info.ExportFile(info_plist_path, __Plugin_Name, "", False)
                success, plist, error = mac_info.ReadPlist(info_plist_path)
                if success:
                    name = plist.get('CFBundleName', name)
                    name = name.lstrip('"').rstrip('"')
                else:
                    log.error("Problem reading plist for {} - ".format(info_plist_path, error))
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

            mac_info.ExportFile(full_path, __Plugin_Name, user_name + "_", False)

            if method == 'Daemon' or method == 'Agents':
                success, plist, error = mac_info.ReadPlist(full_path)
                if success:
                    program.disabled = plist.get('Disabled', '')
                    program_path = plist.get('Program', '')
                    if not program_path:
                        program_args = plist.get('ProgramArguments', None)
                        if program_args:
                            program_path = program_args[0]
                    program.app_path = program_path
                    #keep_alive = isinstance(plist.get('KeepAlive', None), dict)
                    #if keep_alive or run_at_load:
                    persistent_programs.append(program)
                    program.start_when = get_run_when(plist, method)
                    program.user = plist.get('UserName', program.user) # plist can override this, so get that value
                else:
                    log.error("Problem reading plist - " + error)
            else:
                persistent_programs.append(program)

def get_run_when(plist, method):
    run_when = []
    run_at_load = plist.get('RunAtLoad', None)
    if run_at_load == True:
        #run_when.append('RunAtLoad') # if run_at_load else '') # 'DontRunAtLoad' 
        #For daemons this means execution at boot time, for agents execution at login.
        if method == 'Daemon':
            run_when.append('Run at Boot')
        elif method == 'Agents':
            run_when.append('Run at Login')
    for item in ('StartInterval', 'StartCalendarInterval', 'StartOnMount', 'WatchPaths', 'QueueDirectories'):
        if plist.get(item, ''):
            run_when.append(item)
    return ', '.join(run_when)
    
def process_file(mac_info, file_path, persistent_programs, file_name):
    full_path = file_path + '/' + file_name
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
        log.error("Problem reading plist - " + error)

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
                            persistent_programs.append(program)
                    else:
                        log.error("Problem reading plist {} - {}".format(full_path, error))

def print_all(programs, output_params, source_path):
    program_info = [ ('Type',DataType.TEXT),('Name',DataType.TEXT),
                     ('User',DataType.TEXT),('StartupType',DataType.TEXT),('Disabled',DataType.TEXT),
                     ('AppPath',DataType.TEXT),('Source',DataType.TEXT) ]
    data_list = []
    log.info("Found {} autostart item(s)".format(len(programs)))
    for program in programs:
        data_list.append([program.persistence_type, program.name, program.user, program.start_when, 
                          program.disabled, program.app_path, program.source])
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
                        if uid > 0x7fffffff: # convert to its signed version
                            uid = uid - 4294967296 # 4294967294 becomes -2
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