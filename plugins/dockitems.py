'''
   Copyright (c) 2018 Yogesh Khatri

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the
   terms of the MIT License.

   dockitems.py
   ---------------
   Reads the dock plist file for each user.

'''

import logging
from biplist import *
from helpers.macinfo import *
from helpers.writer import *

__Plugin_Name = "DOCKITEMS"
__Plugin_Friendly_Name = "Dock Items"
__Plugin_Version = "1.0"
__Plugin_Description = "Reads the Dock plist for every user"
__Plugin_Author = "Adam Ferrante"
__Plugin_Author_Email = "adam@ferrante.io"

__Plugin_Standalone = True
__Plugin_Standalone_Usage = 'Provide the plist file located at /Users/<USER>/Library/Preferences/com.apple.dock.plist'

log = logging.getLogger('MAIN.' + __Plugin_Name) # Do not rename or remove this ! This is the logger object

#---- Do not change the variable names in above section ----#

class DockItem:
    def __init__(self, file_label, parent_mod_date, file_mod_date, file_type, file_data, guid, user, source_path):
        self.file_label = file_label
        if parent_mod_date and (parent_mod_date > 0xFFFFFFFF): # On High Sierra and above..
            parent_mod_date = parent_mod_date & 0xFFFFFFFF # Killing upper 32 bits!
                                                           # Upper 32 bits maybe the finer resolution (microseconds?).

        if file_mod_date and (file_mod_date > 0xFFFFFFFF): # On High Sierra and above..
            file_mod_date = file_mod_date & 0xFFFFFFFF # Killing upper 32 bits!

        self.parent_mod_date = CommonFunctions.ReadMacHFSTime(parent_mod_date)
        self.file_mod_date = CommonFunctions.ReadMacHFSTime(file_mod_date)
        self.file_type = file_type
        self.file_path = file_data
        self.guid = guid
        self.user = user
        self.path = source_path

def PrintAll(docks, output_params, input_path=''):
    dock_info = [   ('File Label',DataType.TEXT),
                    ('Parent Modified',DataType.TEXT),('File Modified',DataType.DATE),
                    ('File Type',DataType.TEXT),('File Path',DataType.TEXT),
                    ('GUID',DataType.TEXT),
                    ('User',DataType.TEXT),('Source',DataType.TEXT)
                ]

    log.info (str(len(docks)) + " user dock item(s) found")

    dock_list_final = []
    for item in docks:
        single_dock_item = [item.file_label, item.parent_mod_date, item.file_mod_date, 
                            item.file_type, item.file_path,
                            item.guid,
                            item.user, item.path
                            ]
        dock_list_final.append(single_dock_item)

    WriteList("Dock Information", "Dock Items", dock_list_final, dock_info, output_params, input_path)

def GetPath(file_data):
    if file_data:
        return file_data.get("_CFURLString", "")
    return ""

def GetDockItemsPlistFromImage(mac_info, plist_path):
    success, plist, error = mac_info.ReadPlist(plist_path)
    if success:
        return plist
    else:
        log.error(error)
    return None

def ParseDockItemsPlist(plist, docks, user_name, plist_path):
    '''Parse plist and add items to docks list'''

    for key in ['persistent-others', 'persistent-apps', 'recent-apps']:
        if plist.get(key, None) != None:
            try:
                for item in plist[key]:
                    tile_data = item.get('tile-data', None)
                    if tile_data:
                        instance = DockItem(tile_data.get('file-label', ''),
                                            tile_data.get('parent-mod-date', None),
                                            tile_data.get('file-mod-date', None),
                                            tile_data.get('file-type', ''),
                                            GetPath(tile_data.get('file-data', None)),
                                            item.get('GUID', ''),
                                            user_name, plist_path)
                        docks.append(instance)
                    else:
                        log.warning('No tile-data found!! Perhaps a newer format?')
            except:
                log.exception("Exception while processing {}".format(key))
        else:
            log.debug('Key {} not found!'.format(key))

def Plugin_Start(mac_info):
    '''Main Entry point function for plugin'''
    dock_items_path = '{}/Library/Preferences/com.apple.dock.plist' # PList within each users directory.

    docks = []
    processed_paths = []
    for user in mac_info.users:
        user_name = user.user_name
        if user.home_dir == '/private/var/empty': continue # Optimization, nothing should be here!
        elif user.home_dir == '/private/var/root': user_name = 'root' # Some other users use the same root folder, we will list such all users as 'root', as there is no way to tell
        if user.home_dir in processed_paths: continue # Avoid processing same folder twice (some users have same folder! (Eg: root & daemon))
        processed_paths.append(user.home_dir)
        source_path = dock_items_path.format(user.home_dir) # Set a variable to the path of all user dock plist files.

        if mac_info.IsValidFilePath(source_path): # Determine if the above path is valid.
            mac_info.ExportFile(source_path, __Plugin_Name, user_name + "_", False)
            plist = GetDockItemsPlistFromImage(mac_info, source_path) 
            if plist:
                ParseDockItemsPlist(plist, docks, user_name, source_path)

    if len(docks) > 0:
        PrintAll(docks, mac_info.output_params, '')
    else:
        log.info('No dock items found')

def ReadDockPlistFile(input_file, docks):
    try:
        plist = readPlist(input_file)
        ParseDockItemsPlist(plist, docks, '', input_file)
    except (InvalidPlistException, NotBinaryPlistException) as e:
        log.error ("Could not open plist, error was : " + str(e) )

def Plugin_Start_Standalone(input_files_list, output_params):
    log.info("Module Started as standalone")
    for input_path in input_files_list:
        log.debug("Input file passed was: " + input_path)
        docks = []
        ReadDockPlistFile(input_path, docks)
        if len(docks) > 0:
            PrintAll(docks, output_params, input_path)
        else:
            log.info('No dock items found in {}'.format(input_path))

if __name__ == '__main__':
    print ("This plugin is a part of a framework and does not run independently on its own!")