'''
   Copyright (c) 2024 Yogesh Khatri 

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the 
   terms of the MIT License.
   
'''
import datetime
import os
import logging

from plugins.helpers.common import CommonFunctions
from plugins.helpers.macinfo import *
from plugins.helpers.writer import *

__Plugin_Name = "CRASHREPORTER"
__Plugin_Friendly_Name = "Crash Reporter"
__Plugin_Version = "1.0"
__Plugin_Description = "Reads crash reporter plists at /Users/<user>/Library/Application Support/Crashreporter/*.plist"
__Plugin_Author = "Yogesh Khatri"
__Plugin_Author_Email = "yogesh@swiftforensics.com"

__Plugin_Modes = "MACOS,ARTIFACTONLY"
__Plugin_ArtifactOnly_Usage = 'Provide the path to ".../Library/Application Support/Crashreporter" as argument'

log = logging.getLogger('MAIN.' + __Plugin_Name) # Do not rename or remove this ! This is the logger object

#---- Do not change the variable names in above section ----#


class CrashReporterItem:
    def __init__(self, name, date, force_quit_date, file_created_date, path, user, source):
        self.name = name
        self.date = date
        self.force_quit_date = force_quit_date
        self.file_created_date = file_created_date
        self.path = path
        self.user = user
        self.source = source
        
def PrintAll(crashreporter_artifacts, output_params, source_path):
    crashreporter_info = [ ('App Name',DataType.TEXT),('Date',DataType.DATE),
                          ('ForceQuitDate',DataType.DATE),('FileCreatedDate',DataType.DATE),('Path',DataType.TEXT),
                          ('User', DataType.TEXT),('Source',DataType.TEXT)
                        ]
    data_list = []
    log.info (f"{len(crashreporter_artifacts)} crashreporter artifact(s) found")
    for item in crashreporter_artifacts:
        data_list.append( [ item.name, item.date, item.force_quit_date, item.file_created_date,
                             item.path, item.user, item.source ] )
    WriteList("crashreporter", "Crashreporter", data_list, crashreporter_info, output_params, source_path)

def ProcessPlist(plist, crashreporter_artifacts, app_name, cr_date, user_name, target_path):
    crashreporter_artifacts.append(
        CrashReporterItem(
            app_name,
            plist.get('Date', ''),
            plist.get('ForceQuitDate' , ''),
            cr_date,
            plist.get('Path', ''),
            user_name,
            target_path
        )
    )

def Plugin_Start(mac_info):
    '''Main Entry point function for plugin'''

    crashreporter_artifacts = []
    processed_paths = []
    crashreporter_path = '{}/Library/Application Support/CrashReporter'

    for user in mac_info.users:
        if user.home_dir == '/private/var/empty': continue # Optimization, nothing should be here!
        elif user.home_dir == '/private/var/root': user_name = 'root' # Some other users use the same root folder, we will list all such users as 'root', as there is no way to tell
        if user.home_dir in processed_paths: continue # Avoid processing same folder twice (some users have same folder! (Eg: root & daemon))
        processed_paths.append(user.home_dir)
        input_path = crashreporter_path.format(user.home_dir)
        user_name = user.user_name
        if mac_info.IsValidFolderPath(input_path):
            file_names = mac_info.ListItemsInFolder(input_path, EntryType.FILES, include_dates=True)
            for item in file_names:
                if item['name'].endswith('.plist'):
                    target_path = input_path + '/' + item['name']
                    mac_info.ExportFile(target_path, __Plugin_Name, user_name, False, False)
                    if item['name'].startswith('Intervals_'):
                        pass #TODO
                    else:
                        # normal plist
                        if len(item['name']) > 43:
                            app_name = item['name'][:-43]
                            success, plist, error = mac_info.ReadPlist(target_path)
                            if success:
                                ProcessPlist(plist, crashreporter_artifacts, app_name, item['dates']['cr_time'], user_name, target_path)
                            else:
                                log.error(f'Failed to read plist {target_path}')
                                log.error(error)
                        else:
                            log.error(f'Name length < 43 for name={item["name"]}')
                else:
                    log.warning(f'Found a non-plist file? Manually review.. {item["name"]}')

    if len(crashreporter_artifacts) > 0:
        PrintAll(crashreporter_artifacts, mac_info.output_params, '')
    else:
        log.info('No crashreporter artifacts were found!')

def Plugin_Start_Standalone(input_files_list, output_params):
    '''Main entry point function when used on single artifacts (mac_apt_singleplugin), not on a full disk image'''
    log.info("Module Started as standalone")
    for input_path in input_files_list:
        log.debug("Input path passed was: " + input_path)
        crashreporter_artifacts = []
        if os.path.isdir(input_path):
            file_names = os.listdir(input_path)
            for file_name in file_names:
                file_path = os.path.join(input_path, file_name)
                if file_name.endswith('.plist'):
                    if file_name.startswith('Intervals_'):
                        pass #TODO
                    else:
                        if len(file_name) > 43:
                            app_name = file_name[:-43]
                            success, plist, error = CommonFunctions.ReadPlist(file_path)
                            if success:
                                cr_time = datetime.datetime.fromtimestamp(os.path.getctime(file_path))
                                ProcessPlist(plist, crashreporter_artifacts, app_name, cr_time, '', file_path)
                            else:
                                log.error(f'Failed to read plist {file_path}')
                                log.error(error)
                else:
                    log.warning(f'Found a non-plist file? Manually review.. {file_name}')

        if len(crashreporter_artifacts) > 0:
            PrintAll(crashreporter_artifacts, output_params, input_path)
        else:
            log.info('No crashreporter artifacts found in {}'.format(input_path))

def Plugin_Start_Ios(ios_info):
    '''Entry point for ios_apt plugin'''
    pass

if __name__ == '__main__':
    print ("This plugin is a part of a framework and does not run independently on its own!")