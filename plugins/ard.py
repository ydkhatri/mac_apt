'''
   Copyright (c) 2020 Yogesh Khatri

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the
   terms of the MIT License.

   remotemanagement.py
   ---------------
   Reads files saved by Apple Remote Management.

'''

import logging
import plugins.helpers.common
import struct
from biplist import *
from datetime import timedelta
from plugins.helpers.macinfo import *
from plugins.helpers.writer import *
from time import gmtime, strftime

__Plugin_Name = "ARD"
__Plugin_Friendly_Name = "APPLE REMOTE DESKTOP"
__Plugin_Version = "1.0"
__Plugin_Description = "Reads ARD (Apple Remote Desktop) cached databases about app usage"
__Plugin_Author = "Yogesh Khatri"
__Plugin_Author_Email = "yogesh@swiftforensics.com"

__Plugin_Modes = "MACOS,ARTIFACTONLY"
__Plugin_ArtifactOnly_Usage = 'Provide the ...'

log = logging.getLogger('MAIN.' + __Plugin_Name) # Do not rename or remove this ! This is the logger object

#---- Do not change the variable names in above section ----#

class UserAcct:
    def __init__(self, app, time_start, time_end, uid, user, source_path):
        self.app = app
        self.time_start = time_start
        self.time_end = time_end
        self.uid = uid
        self.user = user
        self.source_path = source_path

def PrintUserAccounts(user_accounts, output_params, input_path=''):
    user_accounts_info = [   ('App',DataType.TEXT),
                    ('Start Time',DataType.DATE),
                    ('End Time',DataType.DATE),
                    ('UID',DataType.TEXT),
                    ('User',DataType.TEXT),
                    ('Source',DataType.TEXT)
                ]

    log.info (str(len(user_accounts)) + " user account entries found")

    user_accounts_list_final = []
    for item in user_accounts:
        single_item = [item.app, item.time_start, item.time_end, 
                            item.uid, item.user, item.source_path ]
        user_accounts_list_final.append(single_item)

    WriteList("ard user_accounts info", "ARD_UserAccounts", user_accounts_list_final, user_accounts_info, output_params, input_path)

def parse_user_acct_plist(plist, user_accounts, plist_path):
    '''Parse plist and add items to app list'''
    
    for user, items in plist.items():
        uid = items.get('uid', '')
        for k, v in items.items():
            if k == 'uid':
                continue
            elif isinstance (v, list): # tty or console
                session_name = k
                for session in v:
                    ua = UserAcct(session_name, 
                                CommonFunctions.ReadMacAbsoluteTime(session.get('inTime', None)),
                                CommonFunctions.ReadMacAbsoluteTime(session.get('outTime', None)),
                                uid, user, plist_path)
                    user_accounts.append(ua)

class AppUsage:
    def __init__(self, app_name, app_path, was_quit, frontmost, time_start, run_length, user, source_path):
        self.app_name = app_name
        self.app_path = app_path
        self.was_quit = was_quit
        self.frontmost = frontmost
        self.time_start = time_start
        self.run_length = run_length
        self.user = user
        self.source_path = source_path

def AppUsageInsertUnique(usage_list, app_usage):
    for item in usage_list:
        if item.user == app_usage.user:
            if item.app_path == app_usage.app_path:
                if item.time_start == app_usage.time_start:
                    if item.run_length == app_usage.run_length:
                        return
    # If reached here, then not found, add to list
    usage_list.append(app_usage)

def convert_to_dhms(seconds):
    '''Converts seconds to a string in "D Days, HH:MM:SS" format'''
    hms = strftime('%H:%M:%S', gmtime(seconds)) # gets HH:MM:SS
    td = timedelta(seconds=seconds)
    return f"{td.days} days {hms}"

def PrintAppUsage(app_usage_list, output_params, input_path=''):
    app_usage_info = [   ('App Name',DataType.TEXT),
                    ('App Path',DataType.TEXT),
                    ('Was Quit',DataType.INTEGER),
                    ('Frontmost',DataType.REAL),
                    ('Launched',DataType.DATE),
                    ('Run Length',DataType.TEXT),
                    ('User',DataType.TEXT),
                    ('Source',DataType.TEXT)
                ]

    log.info (str(len(app_usage_list)) + " app usage entries found")

    app_usage_list_final = []
    for item in app_usage_list:
        single_usage_item = [item.app_name, item.app_path, item.was_quit, 
                            item.frontmost, item.time_start,
                            convert_to_dhms(item.run_length), 
                            item.user, item.source_path ]
        app_usage_list_final.append(single_usage_item)

    WriteList("ARD App Usage", "ARD_AppUsage", app_usage_list_final, app_usage_info, output_params, input_path)

def parse_app_usage_plist(plist, app_usage_list, plist_path):
    '''Parse plist and add items to app list'''
    
    for app_path, items in plist.items():
        app_name = items.get('Name', '')
        run_data = items.get('runData', None)
        if run_data:
            for run in run_data:    
                was_quit = run.get('wasQuit', 0)
                frontmost = run.get('Frontmost', 0)
                start_time = CommonFunctions.ReadMacAbsoluteTime(run.get('Launched', ''))
                run_length = run.get('runLength', '')
                user = run.get('userName', '')
                au = AppUsage(app_name, app_path, was_quit, frontmost, start_time, run_length, user, plist_path)
                AppUsageInsertUnique(app_usage_list, au)

def read_plist_from_image(mac_info, plist_path):
    success, plist, error = mac_info.ReadPlist(plist_path)
    if success:
        return plist
    else:
        log.error(error)
    return None

def Plugin_Start(mac_info):
    '''Main Entry point function for plugin'''
    user_acct_path = '/private/var/db/RemoteManagement/caches/UserAcct.tmp'
    app_usage_path_1 = '/private/var/db/RemoteManagement/caches/AppUsage.plist'
    app_usage_path_2 = '/private/var/db/RemoteManagement/caches/AppUsage.tmp'

    user_accounts = []
    if mac_info.IsValidFilePath(user_acct_path):
        mac_info.ExportFile(user_acct_path, __Plugin_Name, "", False)
        plist = read_plist_from_image(mac_info, user_acct_path)
        if plist:
            parse_user_acct_plist(plist, user_accounts, user_acct_path)
    if len(user_accounts) > 0:
        PrintUserAccounts(user_accounts, mac_info.output_params, '')
    else:
        log.info('No user accounts found in RemoteManagement cache')
    
    app_usage_list = []
    if mac_info.IsValidFilePath(app_usage_path_1):
        mac_info.ExportFile(app_usage_path_1, __Plugin_Name, "", False)
        plist = read_plist_from_image(mac_info, app_usage_path_1)
        if plist:
            parse_app_usage_plist(plist, app_usage_list, app_usage_path_1)

    if mac_info.IsValidFilePath(app_usage_path_2):
        mac_info.ExportFile(app_usage_path_2, __Plugin_Name, "", False)
        plist = read_plist_from_image(mac_info, app_usage_path_2)
        if plist:
            parse_app_usage_plist(plist, app_usage_list, app_usage_path_2)

    if len(app_usage_list) > 0:
        PrintAppUsage(app_usage_list, mac_info.output_params, '')
    else:
        log.info('No app usage info found in RemoteManagement cache')

def read_plist_file(input_file):
    try:
        plist = readPlist(input_file)
        return plist
    except (InvalidPlistException, OSError):
        log.exception("Could not open/process plist")
    return None

def Plugin_Start_Standalone(input_files_list, output_params):
    log.info("Module Started as standalone")
    for input_path in input_files_list:
        log.debug("Input file passed was: " + input_path)
        #extension = os.path.splitext(input_path)[1].lower()
        if input_path.lower().endswith('useracct.tmp'):
            user_accounts = []
            plist = read_plist_file(input_path)
            if plist:
                parse_user_acct_plist(plist, user_accounts, input_path)
            if len(user_accounts) > 0:
                PrintUserAccounts(user_accounts, output_params, input_path)
            else:
                log.info('No user accounts found in {}'.format(input_path))
        elif input_path.lower().endswith('appusage.tmp') or input_path.lower().endswith('appusage.plist'):
            app_usage_list = []
            plist = read_plist_file(input_path)
            if plist:
                parse_app_usage_plist(plist, app_usage_list, input_path)
            if len(app_usage_list) > 0:
                PrintAppUsage(app_usage_list, output_params, input_path)
            else:
                log.info('No app usage info found in {}'.format(input_path))
if __name__ == '__main__':
    print ("This plugin is a part of a framework and does not run independently on its own!")