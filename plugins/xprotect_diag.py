'''
    Copyright (c) 2022 Minoru Kobayashi

    This file is part of mac_apt (macOS Artifact Parsing Tool).
    Usage or distribution of this software/code is subject to the
    terms of the MIT License.

    xprotect_diag.py
    ---------------
    This plugin parses XProtect diagnostic files and extract timestamp, signature name, user action, and so on.
'''

import logging
import os
import re

from plugins.helpers.common import CommonFunctions
from plugins.helpers.macinfo import *
from plugins.helpers.writer import *

__Plugin_Name = "XPROTECTDIAG"  # Cannot have spaces, and must be all caps!
__Plugin_Friendly_Name = "XProtect diagnostic"
__Plugin_Version = "1.0"
__Plugin_Description = "Parses XProtect diagnostic files and extract timestamp, signature name, user action, and so on."
__Plugin_Author = "Minoru Kobayashi"
__Plugin_Author_Email = "unknownbit@gmail.com"

__Plugin_Modes = "MACOS,ARTIFACTONLY"  # Valid values are 'MACOS', 'IOS, 'ARTIFACTONLY'
__Plugin_ArtifactOnly_Usage = 'Provide folder path(s) that contains XProtect diagnostic files.'

log = logging.getLogger('MAIN.' + __Plugin_Name) # Do not rename or remove this ! This is the logger object

#---- Do not change the variable names in above section ----#

xp_diag_filename_regex = r'XProtect_(\d{4}-\d{2}-\d{2})-(\d{2})(\d{2})(\d{2})_[\w\-]+\.diag'


class XProtectDiagItem:
    def __init__(self, timestamp, signature_name, user_action, app_bundle_id, data_url, origin_url, download_timestamp, username, source):
        self.timestamp = timestamp
        self.signature_name = signature_name
        self.user_action = user_action
        self.app_bundle_id = app_bundle_id
        self.data_url = data_url
        self.origin_url = origin_url
        self.download_timestamp = download_timestamp
        self.username = username
        self.source = source


def ParseXProtectDiag(plist, xp_diag_artifacts, username, xp_diag_path):
    filename_match = re.match(xp_diag_filename_regex, os.path.basename(xp_diag_path))
    plist = plist[0]
    if filename_match:
        timestamp = filename_match.group(1) + ' ' + filename_match.group(2) + ':' + filename_match.group(3) + ':' + filename_match.group(4)

        try:
            app_bundle_id = plist['LSQuarantineAgentBundleIdentifier']
            data_url = plist['LSQuarantineDataURL']
            origin_url = plist['LSQuarantineOriginURL']
            download_timestamp = plist['LSQuarantineTimeStamp']
        except KeyError:
            app_bundle_id = ''
            data_url = ''
            origin_url = ''
            download_timestamp = ''

        try:
            user_action = plist['UserAction']
            signature_name = plist['XProtectSignatureName']
        except KeyError:
            log.error('{} does not have necessary key(s).'.format(xp_diag_path))
            return

        item = XProtectDiagItem(timestamp, signature_name, user_action, app_bundle_id, data_url, origin_url, download_timestamp, username, xp_diag_path)
        xp_diag_artifacts.append(item)


def ExtractAndReadXProtectDiag(mac_info, xp_diag_artifacts, username, xp_diag_path):
    success, plist, error = mac_info.ReadPlist(xp_diag_path)
    if success:
        ParseXProtectDiag(plist, xp_diag_artifacts, username, xp_diag_path)
        mac_info.ExportFile(xp_diag_path, __Plugin_Name, '', False)
    else:
        log.error('Could not open plist ' + xp_diag_path)
        log.error('Error was: ' + error)


def OpenAndReadXProtectDiag(xp_diag_artifacts, username, xp_diag_path):
    success, plist, error = CommonFunctions.ReadPlist(xp_diag_path)
    if success:
        ParseXProtectDiag(plist, xp_diag_artifacts, username, xp_diag_path)
    else:
        log.error('Could not open plist ' + xp_diag_path)
        log.error('Error was: ' + error)


def PrintAll(xp_diag_artifacts, output_params, source_path):
    xp_diag_info = [('Timestamp', DataType.TEXT), ('Signature_Name', DataType.TEXT), ('User_Action', DataType.TEXT), 
                    ('Application_Bundle_ID', DataType.TEXT), ('DataURL', DataType.TEXT), ('OriginURL', DataType.TEXT), ('Download_Timestamp', DataType.TEXT), 
                    ('User', DataType.TEXT), ('Source', DataType.TEXT)]

    data_list = []
    log.info(f"{len(xp_diag_artifacts)} XProtect diagnostics item(s) found")
    for item in xp_diag_artifacts:
        data_list.append([item.timestamp, item.signature_name, item.user_action, item.app_bundle_id, item.data_url, 
                            item.origin_url, item.download_timestamp, item.username, item.source])

    WriteList("XProtect Diag", "XProtect_Diag", data_list, xp_diag_info, output_params, source_path)


def Plugin_Start(mac_info):
    '''Main Entry point function for plugin'''
    xp_diag_artifacts = []
    xp_diag_base_path = '{}/Library/Logs/DiagnosticReports/'
    processed_paths = set()

    for user in mac_info.users:
        if user.home_dir in processed_paths:
            continue  # Avoid processing same folder twice (some users have same folder! (Eg: root & daemon))
        processed_paths.add(user.home_dir)
        base_path = xp_diag_base_path.format(user.home_dir)
        if not mac_info.IsValidFolderPath(base_path):
            continue

        if mac_info.IsValidFilePath(base_path):
            folder_items = mac_info.ListItemsInFolder(base_path, EntryType.FILES, include_dates=False)
            xp_diag_files = [folder_item['name'] for folder_item in folder_items if re.match(xp_diag_filename_regex, folder_item['name'])]
            for xp_diag_file in xp_diag_files:
                xp_diag_path = os.path.join(base_path, xp_diag_file)
                if xp_diag_file['size'] > 0:
                    log.debug('Processing {}'.format(xp_diag_path))
                    ExtractAndReadXProtectDiag(mac_info, xp_diag_artifacts, user.username, xp_diag_path)

    if len(xp_diag_artifacts) > 0:
        PrintAll(xp_diag_artifacts, mac_info.output_params, '')
    else:
        log.info('No XProtect diag artifacts were found!')


def Plugin_Start_Standalone(input_folders_list, output_params):
    '''Main entry point function when used on single artifacts (mac_apt_singleplugin), not on a full disk image'''
    log.info("Module Started as standalone")
    xp_diag_artifacts = []
    for input_path in input_folders_list:
        log.debug("Input folder passed was: " + input_path)
        if os.path.isdir(input_path):
            xp_diag_files = [f for f in os.listdir(input_path) if re.match(xp_diag_filename_regex, f)]
            for xp_diag_file in xp_diag_files:
                xp_diag_path = os.path.join(input_path, xp_diag_file)
                if os.path.getsize(xp_diag_path) > 0:
                    log.debug('Processing {}'.format(xp_diag_path))
                    OpenAndReadXProtectDiag(xp_diag_artifacts, 'N/A', xp_diag_path)
        else:
            log.info('{] is not a folder.'.format(input_path))

    if len(xp_diag_artifacts) > 0:
        PrintAll(xp_diag_artifacts, output_params, xp_diag_path)
    else:
        log.info('No XProtect diag artifacts were found!')


def Plugin_Start_Ios(ios_info):
    '''Entry point for ios_apt plugin'''
    pass


if __name__ == '__main__':
    print("This plugin is a part of a framework and does not run independently on its own!")
