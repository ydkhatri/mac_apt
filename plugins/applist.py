'''
   Copyright (c) 2018 Yogesh Khatri

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the
   terms of the MIT License.

   applist.py
   ---------------
   Reads the appList.dat plist file for each user.

'''

import logging
import nska_deserialize as nd
from plugins.helpers.macinfo import *
from plugins.helpers.writer import *

__Plugin_Name = "APPLIST"
__Plugin_Friendly_Name = "Application List"
__Plugin_Version = "1.0"
__Plugin_Description = "Reads apps & printers installed and/or available for each user from appList.dat"
__Plugin_Author = "Yogesh Khatri"
__Plugin_Author_Email = "yogesh@swiftforensics.com"

__Plugin_Modes = "MACOS,ARTIFACTONLY"
__Plugin_ArtifactOnly_Usage = 'Provide the plist file located at /Users/<USER>/Library/Application Support/com.apple.spotlight/appList.dat'

log = logging.getLogger('MAIN.' + __Plugin_Name) # Do not rename or remove this ! This is the logger object

#---- Do not change the variable names in above section ----#

class App:
    def __init__(self, display_name, bundle_id, url, user, source_path):
        self.display_name = display_name
        self.bundle_id = bundle_id
        self.url = url
        self.user = user
        self.path = source_path

def PrintAll(apps, output_params, input_path=''):
    apps_info = [   ('Display Name',DataType.TEXT),
                    ('Bundle ID',DataType.TEXT),
                    ('URL',DataType.TEXT),
                    ('User',DataType.TEXT),
                    ('Source',DataType.TEXT)
                ]

    log.info (str(len(apps)) + " app(s) found")

    apps_list_final = []
    for item in apps:
        single_app = [item.display_name, item.bundle_id, 
                      CommonFunctions.url_decode(item.url), 
                        item.user, item.path ]
        apps_list_final.append(single_app)

    WriteList("Apps List", "Apps", apps_list_final, apps_info, output_params, input_path)

def parse_appList_plist(plist, apps, user_name, plist_path):
    '''Parse plist and add items to app list'''
    for item in plist:
        display_name = item.get('displayName', '')
        bundle_id = item.get('bundleID', '')
        url = item['URL']['NS.relative']
        if item['URL']['NS.base']:
            log.debug('Got a value for URL_NS.base = {}, displayname = {}'.format(item['URL']['NS.base'], display_name))
        apps.append(App(display_name, bundle_id, url, user_name, plist_path))

def Plugin_Start(mac_info):
    '''Main Entry point function for plugin'''
    applist_path = '{}/Library/Application Support/com.apple.spotlight/appList.dat' # PList within each users directory.

    apps = []
    processed_paths = []
    for user in mac_info.users:
        user_name = user.user_name
        if user.home_dir == '/private/var/empty': continue # Optimization, nothing should be here!
        elif user.home_dir == '/private/var/root': user_name = 'root' # Some other users use the same root folder, we will list such all users as 'root', as there is no way to tell
        if user.home_dir in processed_paths: continue # Avoid processing same folder twice (some users have same folder! (Eg: root & daemon))
        processed_paths.append(user.home_dir)
        source_path = applist_path.format(user.home_dir)

        if mac_info.IsValidFilePath(source_path): # Determine if the above path is valid.
            mac_info.ExportFile(source_path, __Plugin_Name, user_name + "_", False)
            f = mac_info.Open(source_path)
            if f != None:
                deserialized_plist = nd.deserialize_plist(f)
                if deserialized_plist:
                    parse_appList_plist(deserialized_plist, apps, user_name, source_path)
            else:
                log.error('Could not open file {}'.format(source_path))

    if len(apps) > 0:
        PrintAll(apps, mac_info.output_params, '')
    else:
        log.info('No apps found')

def read_appList_plist_file(input_file, apps):
    try:
        with open(input_file, 'rb') as f:
            deserialized_plist = nd.deserialize_plist(f)
            parse_appList_plist(deserialized_plist, apps, '', input_file)
    except (nd.DeserializeError, nd.biplist.NotBinaryPlistException, 
            nd.biplist.InvalidPlistException,plistlib.InvalidFileException,
            nd.ccl_bplist.BplistError, TypeError, 
            OverflowError, ValueError, KeyError, IndexError, OSError):
        log.exception("Could not open/process plist")

def Plugin_Start_Standalone(input_files_list, output_params):
    log.info("Module Started as standalone")
    for input_path in input_files_list:
        log.debug("Input file passed was: " + input_path)
        apps = []
        read_appList_plist_file(input_path, apps)
        if len(apps) > 0:
            PrintAll(apps, output_params, input_path)
        else:
            log.info('No apps found in {}'.format(input_path))

if __name__ == '__main__':
    print ("This plugin is a part of a framework and does not run independently on its own!")