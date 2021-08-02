'''
   Copyright (c) 2020 Yogesh Khatri

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the
   terms of the MIT License.

   sudo_ts.py
   ---------------
   This gets the last time(s) sudo was used by each user.
'''

import os

from plugins.helpers.macinfo import *
from plugins.helpers.writer import *

import logging
import struct

__Plugin_Name = "SUDOLASTRUN" # Cannot have spaces, and must be all caps!
__Plugin_Friendly_Name = "sudo lastrun timestamps"
__Plugin_Version = "1.0"
__Plugin_Description = "Gets last time sudo was used and a few other times earlier (if available)"
__Plugin_Author = "Yogesh Khatri"
__Plugin_Author_Email = "yogesh@swiftforensics.com"

__Plugin_Modes = "MACOS,ARTIFACTONLY" # Valid values are 'MACOS', 'IOS, 'ARTIFACTONLY' 
__Plugin_ArtifactOnly_Usage = 'Provide files under /var/db/sudo/ts/ to read this info'

log = logging.getLogger('MAIN.' + __Plugin_Name) # Do not rename or remove this ! This is the logger object

#---- Do not change the variable names in above section ----#

def PrintAll(sudo_logs, output_params, source_path):
    sudo_info = [ ('Uid',DataType.TEXT),('Run Date',DataType.TEXT),
                    ('User', DataType.TEXT),('Source',DataType.TEXT)
                   ]
    log.info("Found {} sudo last run timestamp(s)".format(len(sudo_logs)))
    WriteList("sudo last run timestamp", "SudoLastRun", sudo_logs, sudo_info, output_params, source_path)

def ProcessTsFile(f, name, file_path, file_size, sudo_logs):
    while f.tell() < file_size:
        header = f.read(8)
        if len(header) == 8:
            version, size, typ, flags = struct.unpack('<HHHH', header)
            if typ == 2:                    
                data = f.read(size - 8)
                if len(data) == size - 8:
                    if size == 0x28:
                        uid, _, _, date_1, _ = struct.unpack('<HHIQQ', data[0:24])
                        date_1 = CommonFunctions.ReadUnixTime(date_1)
                        if date_1:
                            sudo_logs.append( [uid, date_1, name, file_path] )
                    elif size == 0x38:
                        uid, _, _, date_1, _, date_2, _ = struct.unpack('<HHIQQQQ', data[0:40])
                        date_1 = CommonFunctions.ReadUnixTime(date_1)
                        date_2 = CommonFunctions.ReadUnixTime(date_2)
                        if date_1:
                            sudo_logs.append( [uid, date_1, name, file_path] )
                        if date_2:
                            sudo_logs.append( [uid, date_2, name, file_path] )
                    else:
                        log.error(f'Got unknown size for sudo_timestamp struct , size={size}')
                        break
                else:
                    break
            else:
                f.seek(size - 8, 1)
        else:
            break

def Plugin_Start(mac_info):
    '''Main Entry point function for plugin'''
    sudo_logs = []
    source_path = '/private/var/db/sudo/ts'
    if mac_info.IsValidFolderPath(source_path):
        files_list = mac_info.ListItemsInFolder(source_path, EntryType.FILES, include_dates=False)
        for file_entry in files_list:
            if file_entry['size'] > 0:
                file_path = source_path + '/' + file_entry['name']
                mac_info.ExportFile(file_path, __Plugin_Name, '', False)
                f = mac_info.Open(file_path)
                if f:
                    ProcessTsFile(f, file_entry['name'], file_path, file_entry['size'], sudo_logs)
                    f.close()

        if len(sudo_logs) > 0:
            PrintAll(sudo_logs, mac_info.output_params, '')
        else:
            log.info('No sudo timestamp files were found!')
    else:
        log.info(f'{source_path} does not exist.')


def Plugin_Start_Standalone(input_files_list, output_params):
    '''Main entry point function when used on single artifacts (mac_apt_singleplugin), not on a full disk image'''
    log.info("Module Started as standalone")
    sudo_logs = []
    for input_path in input_files_list:
        log.debug("Input file passed was: " + input_path)
        ## Process the input file here ##
        f = open(input_path)
        if f:
            ProcessTsFile(f, os.path.basename(input_path), input_path, os.path.getsize(input_path), sudo_logs)
            f.close()

    if len(sudo_logs) > 0:
        PrintAll(sudo_logs, output_params, '')
    else:
        log.info('No sudo timestamp files were found!')

def Plugin_Start_Ios(ios_info):
    '''Entry point for ios_apt plugin'''
    pass

if __name__ == '__main__':
    print ("This plugin is a part of a framework and does not run independently on its own!")