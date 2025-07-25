'''
   Copyright (c) 2025 Yogesh Khatri 

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the 
   terms of the MIT License.

'''
import logging

from plugins.helpers.macinfo import *

__Plugin_Name = "UNIFIEDLOGEXPORT" # Cannot have spaces, and must be all caps!
__Plugin_Friendly_Name = "UnifiedLog Export"
__Plugin_Version = "1.0"
__Plugin_Description = "Export all UnifiedLog files along with DSC files required for extraction"
__Plugin_Author = "Yogesh Khatri"
__Plugin_Author_Email = "yogesh@swiftforensics.com"

__Plugin_Modes = "MACOS"
__Plugin_ArtifactOnly_Usage = ''

log = logging.getLogger('MAIN.' + __Plugin_Name) # Do not rename or remove this ! This is the logger object

#---- Do not change the variable names in above section ----#

def Plugin_Start(mac_info):
    '''Main Entry point function for plugin'''
    version_info = mac_info.GetVersionDictionary()
    if version_info['major'] == 10:
        if (version_info['minor'] < 12):
            log.info('Unified Logging is not present in this version of macOS ({})'.format(mac_info.os_version))
            return
    elif version_info['major'] > 10:
        pass
    else:
        log.info('Unified Logging is not present in this version of macOS ({})'.format(mac_info.os_version))
        return

    traceV3_path = '/private/var/db/diagnostics'
    uuidtext_folder_path = '/private/var/db/uuidtext'

    if mac_info.IsValidFolderPath(traceV3_path):
        for item in mac_info.ListItemsInFolder(traceV3_path, EntryType.FILES_AND_FOLDERS, True):
            if item['type'] == EntryType.FILES:
                mac_info.ExportFile(f'{traceV3_path}/{item['name']}', __Plugin_Name, '', False, True)
            elif item['type'] == EntryType.FOLDERS:
                mac_info.ExportFolder(f'{traceV3_path}/{item['name']}', __Plugin_Name, True)
            else:
                log.warning(f'{traceV3_path}/{item['name']} ignored, was neither a file or folder!')
        log.info('Logs exported.')
    else:
        log.info(f'Unified Logging folder {traceV3_path} not found!')
        return

    if mac_info.IsValidFolderPath(uuidtext_folder_path):
        for item in mac_info.ListItemsInFolder(uuidtext_folder_path, EntryType.FILES_AND_FOLDERS, True):
            if item['type'] == EntryType.FILES:
                mac_info.ExportFile(f'{uuidtext_folder_path}/{item['name']}', __Plugin_Name, '', False, True)
            elif item['type'] == EntryType.FOLDERS:
                mac_info.ExportFolder(f'{uuidtext_folder_path}/{item['name']}', __Plugin_Name, True)
            else:
                log.warning(f'{uuidtext_folder_path}/{item['name']} ignored, was neither a file or folder!')
    else:
        log.info(f'Unified Logging folder {uuidtext_folder_path} not found!')

    log.info(f'Unified logs exported to the Export/{__Plugin_Name} folder merging contents of both' + \
             f'{traceV3_path} and {traceV3_path}, use a tool like macos-UnifiedLogs to parse.')
    log.info('https://github.com/mandiant/macos-UnifiedLogs')

if __name__ == '__main__':
    print ("This plugin is a part of a framework and does not run independently on its own!")