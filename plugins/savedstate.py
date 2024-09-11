'''
   Copyright (c) 2020 Yogesh Khatri

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the
   terms of the MIT License.

   savedstate.py
   ---------------
   This module gets window titles from saved application state
   files.
'''

import os

from plugins.helpers.macinfo import *
from plugins.helpers.writer import *

import logging

__Plugin_Name = "SAVEDSTATE"
__Plugin_Friendly_Name = "Saved State"
__Plugin_Version = "1.1"
__Plugin_Description = "Gets window titles from Saved Application State info"
__Plugin_Author = "Yogesh Khatri"
__Plugin_Author_Email = "yogesh@swiftforensics.com"

__Plugin_Modes = "MACOS"
__Plugin_ArtifactOnly_Usage = ''

log = logging.getLogger('MAIN.' + __Plugin_Name) # Do not rename or remove this ! This is the logger object

#---- Do not change the variable names in above section ----#

class SavedState:
    def __init__(self, window_title, dock_files, bundle, last_mod_date, user, source):
        self.window_title = window_title
        self.app = ''
        self.dock_files = dock_files
        self.bundle = bundle
        self.last_mod_date = last_mod_date
        self.user = user
        self.source = source
        app = bundle.replace(".savedState", "")
        try:
            self.app = app.split(".")[-1]
        except IndexError:
            pass

def PrintAll(saved_states, output_params, source_path):
    saved_info = [ ('App',DataType.TEXT),('Window Title',DataType.TEXT),
                    ('Dock Items',DataType.TEXT),('Source Last Modified Date',DataType.TEXT),
                    ('Bundle', DataType.TEXT),('User', DataType.TEXT),('Source',DataType.TEXT)
                   ]
    log.info("Found {} saved state(s)".format(len(saved_states)))
    data_list = []
    for item in saved_states:
        data_list.append( [ item.app, item.window_title, item.dock_files, item.last_mod_date, item.bundle, item.user, item.source ] )

    WriteList("Saved state information", "SavedState", data_list, saved_info, output_params, source_path)

def ProcessFolder(mac_info, saved_states, user, folder_path):
    files_list = mac_info.ListItemsInFolder(folder_path, EntryType.FILES, include_dates=True)
    bundle = os.path.basename(folder_path)

    for file_entry in files_list:
        if file_entry['size'] == 0: 
            continue
        if file_entry['name'] == 'windows.plist':
            dock_items = set()
            titles = set()

            file_path = folder_path + '/windows.plist'
            mac_info.ExportFile(file_path, __Plugin_Name, user + '_', False)
            found_at_least_one_title = False
            success, plist, error = mac_info.ReadPlist(file_path)
            if success:
                for item in plist:
                    title = item.get('NSTitle', '')
                    if title:
                        found_at_least_one_title = True
                        #saved_states.append(SavedState(title, bundle, file_entry['dates']['m_time'], user, file_path))
                        titles.add(title)
                    for dockitem in item.get('NSDockMenu', []):
                        name = dockitem.get('name', '')
                        if name and name not in titles and name not in ('New Window', 'New Window '):
                            if name == 'Open Recent' : # MS Office apps
                                for recent in dockitem.get('sub', []):
                                    recent_name = recent.get('name', '')
                                    if recent_name:
                                        dock_items.add(f'RECENT: {name}')
                            else:
                                dock_items.add(name)
                            #saved_states.append(SavedState('', bundle, file_entry['dates']['m_time'], user, file_path))
            else:
                log.error(f'Failed to read plist {file_path}, error was {error}')
            if found_at_least_one_title:
                for title in titles:
                    saved_states.append(SavedState(title, ', '.join(dock_items), bundle, file_entry['dates']['m_time'], user, file_path))
            else:
                saved_states.append(SavedState('', ', '.join(dock_items), bundle, file_entry['dates']['m_time'], user, file_path))
            
            break

def Plugin_Start(mac_info):
    '''Main Entry point function for plugin'''
    saved_states = []
    saved_state_path = '{}/Library/Saved Application State'
    saved_state_container_path = '{}/Library/Containers' #{}/Data/Library/Saved Application State'
    processed_paths = []
    processed_saved_state_paths = set()
    for user in mac_info.users:
        user_name = user.user_name
        if user.home_dir == '/private/var/empty': continue # Optimization, nothing should be here!
        elif user.home_dir == '/private/var/root': user_name = 'root' # Some other users use the same root folder, we will list all such users as 'root', as there is no way to tell
        if user.home_dir in processed_paths: continue # Avoid processing same folder twice (some users have same folder! (Eg: root & daemon))
        processed_paths.append(user.home_dir)
        source_path = saved_state_path.format(user.home_dir)
        if mac_info.IsValidFolderPath(source_path):
            files_list = mac_info.ListItemsInFolder(source_path, EntryType.FILES_AND_FOLDERS, include_dates=False)
            for file_entry in files_list:
                if file_entry['type'] == EntryType.FOLDERS:
                    processed_saved_state_paths.add(source_path + '/' + file_entry['name'])
                    ProcessFolder(mac_info, saved_states, user_name, source_path + '/' + file_entry['name'])
                else:
                    # Must be an alias (symlink)
                    file_path = source_path + '/' + file_entry['name']
                    if mac_info.IsSymbolicLink(file_path):
                        target_path = mac_info.ReadSymLinkTargetPath(file_path)
                        processed_saved_state_paths.add(target_path)
                        if  mac_info.IsValidFolderPath(target_path):
                            ProcessFolder(mac_info, saved_states, user_name, target_path)
                        else:
                            if mac_info.IsValidFilePath(target_path):
                                log.warning(f'Symlink target path was not a folder! Symlink file={file_path}, target={target_path}')
                            #else:
                            #    log.warning(f'Symlink target path does not exist! Symlink file={file_path}, target={target_path}')
        #
        source_path = saved_state_container_path.format(user.home_dir)
        if mac_info.IsValidFolderPath(source_path):
            folders_list = mac_info.ListItemsInFolder(source_path, EntryType.FOLDERS, include_dates=False)
            for item in folders_list:
                container_state_folder = f'{source_path}/{item["name"]}/Data/Library/Saved Application State'
                if mac_info.IsValidFolderPath(container_state_folder):
                    sub_folders_list = mac_info.ListItemsInFolder(container_state_folder, EntryType.FOLDERS, include_dates=False)
                    for sub_folder in sub_folders_list:
                        target_folder = f'{container_state_folder}/{sub_folder["name"]}'
                        if target_folder not in processed_saved_state_paths:
                            processed_saved_state_paths.add(target_folder)
                            log.debug(f'Processing saved state info for container {target_folder}')
                            ProcessFolder(mac_info, saved_states, user_name, target_folder)
                        #else:
                        #    log.debug(f'container already processed{target_folder}')

    if len(saved_states) > 0:
        PrintAll(saved_states, mac_info.output_params, '')
    else:
        log.info('No saved states were found!')

def Plugin_Start_Standalone(input_files_list, output_params):
    '''Main entry point function when used on single artifacts (mac_apt_singleplugin), not on a full disk image'''
    pass

def Plugin_Start_Ios(ios_info):
    '''Entry point for ios_apt plugin'''
    pass

if __name__ == '__main__':
    print ("This plugin is a part of a framework and does not run independently on its own!")