'''
   Copyright (c) 2026 Yogesh Khatri

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the
   terms of the MIT License.

   trash.py
   --------
   This plugin analyses data in the .Trash folders, primarily by
   reading .DS_Store files to reveal original paths and other stored
   metadata of deleted files/folders as well as enumerating the 
   folder contents if available.

   Ref for .DS_Store format:
   https://metacpan.org/dist/Mac-Finder-DSStore/view/DSStoreFormat.pod

   Sometimes macOS misses adding some files into the .DS_Store that are
   in .Trash folder. This has been observed in macOS 26.5.1. 
'''
from collections import defaultdict
from ds_store import DSStore, buddy
from plugins.helpers.common import CommonFunctions
from plugins.helpers.macinfo import *
from plugins.helpers.writer import *

import logging
import os

__Plugin_Name = "TRASH"
__Plugin_Friendly_Name = ".Trash"
__Plugin_Version = "1.0"
__Plugin_Description = "Get deleted items metadata from .Trash folders and .DS_Store files"
__Plugin_Author = "Yogesh Khatri"
__Plugin_Author_Email = "yogesh@swiftforensics.com"

__Plugin_Modes = "MACOS,ARTIFACTONLY" # Valid values are 'MACOS', 'IOS, 'ARTIFACTONLY' 
__Plugin_ArtifactOnly_Usage = 'Provide the file path to /Users/<profile>/.DS_Store'

log = logging.getLogger('MAIN.' + __Plugin_Name) # Do not rename or remove this ! This is the logger object

#---- Do not change the variable names in above section ----#

class DeletedItem:
    def __init__(self, ds_current_name, ds_current_location, 
                 ds_original_name, ds_original_path,
                 ds_logical_size, ds_physical_size, ds_modified,
                 modified, accessed, changed, birth, user, source):
        self.ds_current_name = ds_current_name
        self.ds_current_location = ds_current_location
        self.ds_original_name = ds_original_name
        self.ds_original_path = ds_original_path
        self.ds_logical_size = ds_logical_size
        self.ds_physical_size = ds_physical_size
        self.ds_modified = ds_modified
        self.modified = modified
        self.accessed = accessed
        self.changed = changed
        self.birth = birth
        self.user = user
        self.source = source
        
def PrintAll(deleted_artifacts, output_params, source_path):
    deleted_info = [
                    ('Current Name',DataType.TEXT),('Current Location',DataType.TEXT),
                    ('Original Name',DataType.TEXT),('Original Location',DataType.TEXT),
                    ('Logical Size',DataType.INTEGER),('Physical Size',DataType.INTEGER),
                    ('DS_Store Modified Date',DataType.DATE),
                    ('Modified Date',DataType.DATE),('Accessed Date',DataType.DATE),
                    ('Changed Date',DataType.DATE),('Birth Date',DataType.DATE),
                    ('User', DataType.TEXT),('Source',DataType.TEXT)
                    ]
    data_list = []
    log.info (f"{len(deleted_artifacts)} Trash item(s) found")
    for item in deleted_artifacts:
        data_list.append( [ item.ds_current_name, item.ds_current_location, 
                            item.ds_original_name, item.ds_original_path,
                            item.ds_logical_size, item.ds_physical_size, item.ds_modified,
                            item.modified, item.accessed, item.changed, item.birth,
                            item.user, item.source ] )
    WriteList("trash", "Trash", data_list, deleted_info, output_params, source_path)

def ProcessDSStore(ds, deleted_artifacts, user_name, source_path):
    '''Processes a .DS_Store file and extracts deleted items information'''
    trash_location = os.path.dirname(source_path)

    ds_store_data = defaultdict(dict) # {name, {code: value, ...}, ...}

    for idx, entry in enumerate(ds):
        try:
            val_decoded = ''
            if entry.code in (b'modD', b'moDD'):
                raw_blob = struct.unpack('<d', entry.value)[0]
                val_decoded = CommonFunctions.ReadMacAbsoluteTime(raw_blob)

            # Assign the code and its value to the specific filename
            ds_store_data[entry.filename][entry.code] = val_decoded if val_decoded else entry.value
        except (buddy.BuddyError, struct.error, KeyError, TypeError, ValueError) as e:
            log.error(f"Error occurred while processing entry {idx} in .DS_Store file at path: {source_path}")
            log.error(f"Error was: {e}")

    for filename, codes in ds_store_data.items():
        ds_current_name = filename
        ds_current_location = trash_location
        ds_original_name = codes.get(b'ptbN', '')
        ds_original_path = codes.get(b'ptbL', '')
        ds_logical_size = codes.get(b'lg1S', None)
        ds_physical_size = codes.get(b'ph1S', None)
        ds_modified = codes.get(b'modD', None)
        if ds_modified is None:
            ds_modified = codes.get(b'moDD', None)

        # Create a DeletedItem object and add it to the list
        deleted_item = DeletedItem(ds_current_name, ds_current_location, ds_original_name, ds_original_path,
                                    ds_logical_size, ds_physical_size, ds_modified,
                                    None, None, None, None, user_name, source_path)
        deleted_artifacts.append(deleted_item)

def ProcessTrashFolder(mac_info, trash_artifacts, user_name, trash_folder_path):
    '''Processes a .Trash folder and enumerate existing items at root level only'''
    for item in mac_info.ListItemsInFolder(trash_folder_path, EntryType.FILES_AND_FOLDERS, include_dates=True):
        if item['name'] == '.DS_Store':
            continue
        # find existing entry in trash_artifacts
        existing_entry = next((artifact for artifact in trash_artifacts if artifact.ds_current_name == item['name']), None)
        if existing_entry:
            existing_entry.modified = item['dates']['m_time']
            existing_entry.accessed = item['dates']['a_time']
            existing_entry.changed = item['dates']['c_time']
            existing_entry.birth = item['dates']['cr_time']
        else:
            log.warning(f"Item '{item['name']}' not found in {trash_folder_path}/.DS_Store, adding it as a new entry.")
        
            ds_current_name = item['name']
            ds_current_location = trash_folder_path
            ds_original_name = ''
            ds_original_path = ''
            ds_logical_size = item['size']
            ds_physical_size = None
            ds_modified = None
            modified = item['dates']['m_time']
            accessed = item['dates']['a_time']
            changed = item['dates']['c_time']
            birth = item['dates']['cr_time']

            # Create a DeletedItem object and add it to the list
            deleted_item = DeletedItem(ds_current_name, ds_current_location, ds_original_name, ds_original_path,
                                        ds_logical_size, ds_physical_size, ds_modified,
                                        modified, accessed, changed, birth, user_name, trash_folder_path)
            trash_artifacts.append(deleted_item)

def Plugin_Start(mac_info):
    '''Main Entry point function for plugin'''

    all_trash_artifacts = []
    processed_paths = []
    trash_path = '{}/.Trash'
    ds_store_path = '{}/.Trash/.DS_Store'

    for user in mac_info.users:
        if user.home_dir == '/private/var/empty': continue # Optimization, nothing should be here!
        elif user.home_dir == '/private/var/root': user_name = 'root' # Some other users use the same root folder, we will list all such users as 'root', as there is no way to tell
        if user.home_dir in processed_paths: continue # Avoid processing same folder twice (some users have same folder! (Eg: root & daemon))
        processed_paths.append(user.home_dir)
        trash_folder_path = trash_path.format(user.home_dir)
        ds_source_path = ds_store_path.format(user.home_dir)
        user_name = user.user_name
        trash_artifacts = []
        if mac_info.IsValidFilePath(ds_source_path):
            mac_info.ExportFile(ds_source_path, __Plugin_Name)
            dss_file = mac_info.Open(ds_source_path)
            if dss_file:
                try:
                    with DSStore.open(dss_file, 'r') as ds:
                        ProcessDSStore(ds, trash_artifacts, user_name, ds_source_path)
                except buddy.BuddyError as e:
                    log.error("Error occurred while processing .DS_Store file at path: " + ds_source_path)
                    log.error("Error was: " + str(e))
            else:
                log.error("Unable to open .DS_Store file at path: " + ds_source_path)
                
        if mac_info.IsValidFolderPath(trash_folder_path):
            ProcessTrashFolder(mac_info, trash_artifacts, user_name, trash_folder_path)
        
        all_trash_artifacts.extend(trash_artifacts)
    if len(all_trash_artifacts) > 0:
        PrintAll(all_trash_artifacts, mac_info.output_params, '')
    else:
        log.info('No Trash artifacts were found!')

def Plugin_Start_Standalone(input_files_list, output_params):
    '''Main entry point function when used on single artifacts (mac_apt_singleplugin), not on a full disk image'''
    log.info("Module Started as standalone")
    for input_path in input_files_list:
        log.debug("Input path passed was: " + input_path)
        trash_artifacts = []
        if input_path.lower().endswith('.ds_store'):
            with open(input_path, 'rb') as dss_file:
                try:
                    with DSStore.open(dss_file, 'r') as ds:
                        ProcessDSStore(ds, trash_artifacts, '', input_path)
                except buddy.BuddyError as e:
                    log.error("Error occurred while processing .DS_Store file at path: " + input_path)
                    log.error("Error was: " + str(e))
        else:
            log.error("Input file name is not a .DS_Store : " + input_path)

        if len(trash_artifacts) > 0:
            PrintAll(trash_artifacts, output_params, input_path)
        else:
            log.info('No Trash artifacts found in {}'.format(input_path))

def Plugin_Start_Ios(ios_info):
    '''Entry point for ios_apt plugin'''
    pass

if __name__ == '__main__':
    print ("This plugin is a part of a framework and does not run independently on its own!")