'''
   Copyright (c) 2017 Yogesh Khatri 

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the 
   terms of the MIT License.
   
'''

import os
import sys
import logging
import struct

from plugins.helpers.common import CommonFunctions
from plugins.helpers.macinfo import *
from plugins.helpers.writer import *

__Plugin_Name = "SPOTLIGHTSHORTCUTS"
__Plugin_Friendly_Name = "Spotlight shortcuts"
__Plugin_Version = "1.0"
__Plugin_Description = "Gets user typed data in the spotlight bar, used to launch applications and documents"
__Plugin_Author = "Yogesh Khatri"
__Plugin_Author_Email = "yogesh@swiftforensics.com"

__Plugin_Modes = "MACOS,ARTIFACTONLY"
__Plugin_ArtifactOnly_Usage = 'This module parses user searched data using the spotlight bar. Data is retreived from the plist file(s) found at: /Users/<User>/Library/Preferences/com.apple.spotlight.plist and /Users/<User>/Library/Application Support/com.apple.spotlight.Shortcuts'

log = logging.getLogger('MAIN.' + __Plugin_Name) # Do not rename or remove this ! This is the logger object

#---- Do not change the variable names in above section ----#

def PrintAll(shortcut_items, output_params, source_path):
    shortcut_info = [ ('User',DataType.TEXT),('UserTyped',DataType.TEXT),('DisplayName',DataType.TEXT),
                      ('LastUsed',DataType.DATE),('URL',DataType.TEXT),('Source',DataType.TEXT)
                   ]
    log.debug('Writing {} spotlight shortcut item(s)'.format(len(shortcut_items)))
    WriteList("spotlight shortcut information", "SpotlightShortcuts", shortcut_items, shortcut_info, output_params, source_path)
    
def ParseShortcutFile(input_file, shortcuts):
    success, plist, error = CommonFunctions.ReadPlist(input_path)
    if success:
        ReadShortcutPlist(plist, shortcuts, input_file)
    else:
        log.error("Could not open plist, error was : " + error)

def ReadSingleShortcutEntry(entry, value, shortcuts, uses_path, source, user):
    sc = { 'User':user, 'Source':source, 'UserTyped':entry }
    for item, val in value.items():
        if item == 'DISPLAY_NAME': sc['DisplayName'] = val
        elif item == 'LAST_USED':  sc['LastUsed'] = val
        elif (uses_path and (item == 'PATH')) or (item == 'URL'):
            path = val
            if path.startswith('file://'):
                path = path[7:]
            sc['URL'] = path
        else:
            log.info("Found unknown item - {}, value={} in plist".format(item, value))
    shortcuts.append(sc)
    

def ReadShortcutPlist(plist, shortcuts, source='', user=''):
    try:
        user_shortcuts = plist.get('UserShortcuts', None)
        if len(plist) == 1 and user_shortcuts != None: # mavericks or older
            for item, value in user_shortcuts.items():
                ReadSingleShortcutEntry(item, value, shortcuts, True, source, user) 
        else :
            for item, value in plist.items():
                ReadSingleShortcutEntry(item, value, shortcuts, False, source, user)
    except ValueError as ex:
        log.exception('Error reading plist')
    
def Plugin_Start(mac_info):
    '''Main Entry point function for plugin'''
    shortcuts = []
    user_plist_rel_path = '{}/Library/Preferences/com.apple.spotlight.plist' # Mavericks (10.9) or older
    version = mac_info.GetVersionDictionary()
    if version['major'] == 10:
        if version['minor'] >= 10 and version['minor'] < 15:
            user_plist_rel_path = '{}/Library/Application Support/com.apple.spotlight.Shortcuts'
        elif version['minor'] >= 15:
            user_plist_rel_path = '{}/Library/Application Support/com.apple.spotlight/com.apple.spotlight.Shortcuts'
    elif version['major'] == 11:
        user_plist_rel_path = '{}/Library/Application Support/com.apple.spotlight/com.apple.spotlight.Shortcuts.v3'
    
    processed_paths = set()
    for user in mac_info.users:
        user_name = user.user_name
        if user.home_dir == '/private/var/empty': continue # Optimization, nothing should be here!
        elif user.home_dir == '/private/var/root': user_name = 'root' # Some other users use the same root folder, we will list such all users as 'root', as there is no way to tell
        if user.home_dir in processed_paths: continue # Avoid processing same folder twice (some users have same folder! (Eg: root & daemon))
        processed_paths.add(user.home_dir)
        source_path = user_plist_rel_path.format(user.home_dir)
        if mac_info.IsValidFilePath(source_path):
            mac_info.ExportFile(source_path, __Plugin_Name, user_name + "_", False)
            success, plist, error = mac_info.ReadPlist(source_path)
            if success:
                ReadShortcutPlist(plist, shortcuts, source_path, user_name)
            else:
                log.error('Could not open plist ' + source_path)
                log.error('Error was: ' + error)
        else:
            if not user_name.startswith('_'):
                log.debug('File not found: {}'.format(source_path))

    if len(shortcuts) > 0:
        PrintAll(shortcuts, mac_info.output_params, source_path)
    else:
        log.info('No shortcut items found')

def Plugin_Start_Standalone(input_files_list, output_params):
    log.info("Module Started as standalone")
    for input_path in input_files_list:
        log.debug("Input file passed was: " + input_path)
        shortcuts = []
        ParseShortcutFile(input_path, shortcuts)
        if len(shortcuts) > 0:
            PrintAll(shortcuts, output_params, input_path)
        else:
            log.info('No shortcut items found in {}'.format(input_path))

if __name__ == '__main__':
    print ("This plugin is a part of a framework and does not run independently on its own!")