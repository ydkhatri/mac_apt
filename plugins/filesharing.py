'''
   Copyright (c) 2021 Minoru Kobayashi

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the
   terms of the MIT License.

   filesharing.py
   ---------------
   This plugin reads file sharing plist files under /private/var/db/dslocal/nodes/Default/sharepoints/ .
   Although access permissions are stored as file system metadata (permission and extended permission), this plugin does not support them yet.
'''

import os

from plugins.helpers.common import CommonFunctions
from plugins.helpers.macinfo import *
from plugins.helpers.writer import *

import logging

__Plugin_Name = "FILESHARING" # Cannot have spaces, and must be all caps!
__Plugin_Friendly_Name = "file sharing"
__Plugin_Version = "1.0"
__Plugin_Description = "Reads plist files under /private/var/db/dslocal/nodes/Default/sharepoints/ and extract shared folder and its display name."
__Plugin_Author = "Minoru Kobayashi"
__Plugin_Author_Email = "unknownbit@gmail.com"

__Plugin_Modes = "MACOS,ARTIFACTONLY" # Valid values are 'MACOS', 'IOS, 'ARTIFACTONLY' 
__Plugin_ArtifactOnly_Usage = 'Provide plist files under /private/var/db/dslocal/nodes/Default/sharepoints/'

log = logging.getLogger('MAIN.' + __Plugin_Name) # Do not rename or remove this ! This is the logger object

#---- Do not change the variable names in above section ----#

class FileSharingItem:
    def __init__(self, name, directory_path, smb_guestaccess, afp_guestaccess, source):
        self.name = name
        self.directory_path = directory_path
        self.smb_guestaccess = smb_guestaccess
        self.afp_guestaccess = afp_guestaccess
        self.source = source


def ExtractAndReadSharePointsPlist(mac_info, filesharing_artifacts, plist_path):
    if mac_info.IsValidFilePath(plist_path):
        mac_info.ExportFile(plist_path, __Plugin_Name)
        success, plist, error = mac_info.ReadPlist(plist_path)
        if success:
            ProcessSharePointsPlist(plist, filesharing_artifacts, plist_path)
        else:
            log.error(error)

def ReadSharePointsPlist(filesharing_artifacts, plist_path):
    success, plist, error = CommonFunctions.ReadPlist(plist_path)
    if success:
        ProcessSharePointsPlist(plist, filesharing_artifacts, plist_path)
    else:
        log.error ("Could not open plist, error was : " + error)

def ProcessSharePointsPlist(plist, filesharing_artifacts, plist_path):
    try:
        if plist['name'][0] and plist['directory_path'][0]:
            item = FileSharingItem(plist['name'][0], plist['directory_path'][0], plist.get('smb_guestaccess', ('N/A',))[0], plist.get('afp_guestaccess', ('N/A',))[0], plist_path)
            filesharing_artifacts.append(item)
    except ValueError:
        log.exception("Exception while processing {}".format('name or directory_path'))


def PrintAll(filesharing_artifacts, output_params, source_path):
    filesharing_info = [('Name', DataType.TEXT), ('Directory_Path', DataType.TEXT), ('SMB_Guest_Access', DataType.TEXT), ('AFP_Guest_Access', DataType.TEXT), ('Source', DataType.TEXT)]

    data_list = []
    log.info(f"{len(filesharing_artifacts)} filesharing artifact(s) found")
    for item in filesharing_artifacts:
        data_list.append([item.name, item.directory_path, item.smb_guestaccess, item.afp_guestaccess, item.source])

    WriteList("File Sharing", "FileSharing", data_list, filesharing_info, output_params, source_path)

def Plugin_Start(mac_info):
    '''Main Entry point function for plugin'''
    filesharing_artifacts = []
    filesharing_base_path = '/private/var/db/dslocal/nodes/Default/sharepoints/'

    sharepoints_folder_list = mac_info.ListItemsInFolder(filesharing_base_path, EntryType.FILES, include_dates=False)
    sharepoints_files = [folder_item['name'] for folder_item in sharepoints_folder_list]
    for sharepoints_file in sharepoints_files:
        plist_path = os.path.join(filesharing_base_path, sharepoints_file)
        if mac_info.IsValidFilePath(plist_path) and mac_info.GetFileSize(plist_path) > 0:
            ExtractAndReadSharePointsPlist(mac_info, filesharing_artifacts, plist_path)

    if len(filesharing_artifacts) > 0:
        PrintAll(filesharing_artifacts, mac_info.output_params, '')
    else:
        log.info('No filesharing artifacts were found!')

def Plugin_Start_Standalone(input_files_list, output_params):
    '''Main entry point function when used on single artifacts (mac_apt_singleplugin), not on a full disk image'''
    log.info("Module Started as standalone")
    for input_path in input_files_list:
        log.debug("Input file passed was: " + input_path)
        filesharing_artifacts = []
        if os.path.isfile(input_path) and os.path.getsize(input_path) > 0:
            ReadSharePointsPlist(filesharing_artifacts, input_path)

        if len(filesharing_artifacts) > 0:
            PrintAll(filesharing_artifacts, output_params, input_path)
        else:
            log.info('No filesharing artifacts were found!')

def Plugin_Start_Ios(ios_info):
    '''Entry point for ios_apt plugin'''
    pass

if __name__ == '__main__':
    print ("This plugin is a part of a framework and does not run independently on its own!")
