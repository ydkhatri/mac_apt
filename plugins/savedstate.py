'''
   Copyright (c) 2020 Yogesh Khatri

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the
   terms of the MIT License.

   savedstate.py
   ---------------
   This module gets window titles and Dock items (seen when right-clicked) from saved application state
   files.
'''

import io
import nska_deserialize as nd
import os
import plistlib
import struct

from Crypto.Cipher import AES
from plugins.helpers.common import CommonFunctions
from plugins.helpers.macinfo import *
from plugins.helpers.writer import *

import logging

__Plugin_Name = "SAVEDSTATE"
__Plugin_Friendly_Name = "Saved State"
__Plugin_Version = "1.2"
__Plugin_Description = "Gets window titles from Saved Application State info"
__Plugin_Author = "Yogesh Khatri"
__Plugin_Author_Email = "yogesh@swiftforensics.com"

__Plugin_Modes = "MACOS"
__Plugin_ArtifactOnly_Usage = ''

log = logging.getLogger('MAIN.' + __Plugin_Name) # Do not rename or remove this ! This is the logger object

#---- Do not change the variable names in above section ----#

class SavedState:
    def __init__(self, window_title, dock_items, bundle, last_mod_date, user, source):
        self.window_title = window_title
        self.app = ''
        self.dock_items = dock_items
        self.bundle = bundle
        self.last_mod_date = last_mod_date
        self.user = user
        self.source = source
        app = bundle.replace(".savedState", "")
        try:
            self.app = app.split(".")[-1]
        except IndexError:
            pass

def PrintAll(saved_states, output_params, source_path):
    saved_info = [ ('App',DataType.TEXT),('Window Titles',DataType.TEXT),
                    ('Dock Items',DataType.TEXT),('Source Last Modified Date',DataType.TEXT),
                    ('Bundle', DataType.TEXT),('User', DataType.TEXT),('Source',DataType.TEXT)
                   ]
    log.info("Found {} saved state(s)".format(len(saved_states)))
    data_list = []
    for item in saved_states:
        data_list.append( [ item.app, item.window_title, item.dock_items, item.last_mod_date, item.bundle, item.user, item.source ] )

    WriteList("Saved state information", "SavedState", data_list, saved_info, output_params, source_path)

def ProcessFolder(mac_info, saved_states, user, folder_path):
    files_list = mac_info.ListItemsInFolder(folder_path, EntryType.FILES, include_dates=True)
    bundle = os.path.basename(folder_path)
    data_path = ''
    for file_entry in files_list:
        if file_entry['name'] == 'data.data' and file_entry['size'] > 0:
            data_path = folder_path + '/data.data'
            break

    for file_entry in files_list:
        if file_entry['size'] == 0: 
            continue
        if file_entry['name'] == 'windows.plist':
            dock_items = set()
            titles = set()

            file_path = folder_path + '/windows.plist'
            mac_info.ExportFile(file_path, __Plugin_Name, user + '_', False)
            success, plist, error = mac_info.ReadPlist(file_path)
            if success:
                for item in plist:
                    title = item.get('NSTitle', '').strip()
                    if title:
                        titles.add(title)
                    for dockitem in item.get('NSDockMenu', []):
                        name = dockitem.get('name', '').strip()
                        if name and name not in titles and name not in ('New Window', 'New Window '):
                            if name == 'Open Recent' : # MS Office apps
                                for recent in dockitem.get('sub', []):
                                    recent_name = recent.get('name', '').strip()
                                    if recent_name and recent_name != 'More...':
                                        dock_items.add(f'RECENT: {recent_name}')
                            else:
                                dock_items.add(name)

                if data_path:
                    all_data_file = mac_info.Open(data_path)
                    if all_data_file:
                        all_data = all_data_file.read()
                        find_additional_titles(plist, all_data, titles, data_path, bundle)
                    else:
                        log.error('Failed to open data.data file - {}'.format(data_path)) 
            else:
                log.error(f'Failed to read plist {file_path}, error was {error}')

            saved_states.append(SavedState('\n'.join(titles), '\n'.join(dock_items), bundle, file_entry['dates']['m_time'], user, file_path))
            
            break

def get_decoded_plist_data(data):
    data_size = len(data)
    name = ''
    if data_size > 8:
        name_len = struct.unpack('>I', data[4:8])[0]
        if name_len > 64:
            log.error('Name too long, likely garbage/enc data')
            return (data[8 : 8 + 64], None)
        name = data[8 : 8 + name_len]
        log.debug('NSName = {}'.format(name))
        rchv = data[8 + name_len : 12 + name_len] # "rchv"
        if rchv != b"rchv":
            log.warning('magic was not "rchv", it was {}'.format(str(rchv)))
            return (name, None)
        nsa_plist_len = struct.unpack('>I', data[12 + name_len : 16 + name_len])[0]
        nsa_plist = data[16 + name_len : 16 + name_len + nsa_plist_len]

        f = io.BytesIO(nsa_plist)
        try:
            deserialized_plist = nd.deserialize_plist(f, True, format=dict)
        except (nd.DeserializeError, nd.biplist.NotBinaryPlistException, 
                nd.biplist.InvalidPlistException,nd.plistlib.InvalidFileException,
                nd.ccl_bplist.BplistError, ValueError, TypeError, 
                OSError, OverflowError) as ex:
            log.exception("")
            f.close()
            return (name, None)
        f.close()
        return (name, deserialized_plist)
    else:
        log.warning('Plist seems empty!')
    return (name, None)

def get_key_and_title_for_window_id(plist, ns_window_id):
    key = None
    title = ''
    for item in plist:
        w_id = item.get('NSWindowID', None)
        if w_id == ns_window_id:
            key = item.get('NSDataKey', None)
            title = item.get('NSTitle', '')
            if key == None:
                log.error("Error fetching key, key was not found for windowID={}!".format(ns_window_id))
            break
    return key, title

def decrypt(enc_data, key, iv):
    '''Decrypts the data given encrypted data, key and IV'''
    try:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        dec_data = cipher.decrypt(enc_data)
        return dec_data
    except (KeyError, ValueError) as ex:
        log.exception('Decryption error:')
    return b''

def find_additional_titles(windows_plist, all_data, titles, input_path, bundle_name):
    iv = struct.pack("<IIII", 0, 0, 0, 0)

    pos = 0
    # Parsing data.data
    size_data = len(all_data)
    while (pos + 16) < size_data:
        magic = all_data[pos:pos+8]
        ns_window_id, rec_length = struct.unpack(">II", all_data[pos+8:pos+16])
        pos += 16
        rec_length -= 16
        if (pos + rec_length) <= size_data:
            enc_data = all_data[pos:pos + rec_length]
            if magic != b"NSCR1000":
                log.error("Unknown header:" + str(magic))
                return
                
            key, title = get_key_and_title_for_window_id(windows_plist, ns_window_id)

            if key:
                dec_data = decrypt(enc_data, key, iv)
                #f = open(f'{out_path}/{bundle_name}.{ns_window_id}.{pos}.dec', 'wb')
                #f.write(dec_data)
                #f.close()
                log.info(f"Processing {bundle_name}.{ns_window_id}.{pos}")
                data_name, data_plist = get_decoded_plist_data(dec_data)
                if data_name and data_plist:
                    #out_file = open(f'/tmp/{bundle_name}.{ns_window_id}.{pos}.{data_name}.plist', 'wb')
                    #plistlib.dump(data_plist, out_file, fmt=plistlib.FMT_BINARY)
                    #out_file.close()

                    if b'_NSWindow'== data_name:
                        embedded_ns_title = data_plist.get('NSTitle', '').strip()
                        if bundle_name == 'com.apple.finder.savedState':
                            url = data_plist.get('WindowState', {}).get('TargetURL', '')
                            if url:
                                embedded_ns_title += f" -> {url}"
                        elif bundle_name == 'com.apple.Preview.savedState':
                            url = data_plist.get('currentMediaContainerFileReferenceURL', {}).get('NS.relative', '')
                            if url:
                                embedded_ns_title += f" -> {url}"
                        elif bundle_name == 'com.vmware.fusion.savedState':
                            restorationID = data_plist.get('restorationID', '')
                            if restorationID:
                                embedded_ns_title += f" -> {restorationID}"
                        if embedded_ns_title:
                            titles.add(embedded_ns_title)
            else:
                log.debug(f'key not found for window_id={ns_window_id} for {bundle_name}.{ns_window_id}.{pos}, title={title}')
        pos += rec_length

def Plugin_Start(mac_info):
    '''Main Entry point function for plugin'''
    saved_states = []
    saved_state_path = '{}/Library/Saved Application State'
    saved_state_container_path = '{}/Library/Containers' #{}/Data/Library/Saved Application State'
    processed_paths = []
    processed_saved_state_paths = set()
    for user in mac_info.users:
        user_name = user.user_name
        if user.home_dir == '/private/var/empty': continue # Optimization, nothing should be here!
        elif user.home_dir == '/private/var/root': user_name = 'root' # Some other users use the same root folder, we will list all such users as 'root', as there is no way to tell
        if user.home_dir in processed_paths: continue # Avoid processing same folder twice (some users have same folder! (Eg: root & daemon))
        processed_paths.append(user.home_dir)
        source_path = saved_state_path.format(user.home_dir)
        if mac_info.IsValidFolderPath(source_path):
            files_list = mac_info.ListItemsInFolder(source_path, EntryType.FILES_AND_FOLDERS, include_dates=False)
            for file_entry in files_list:
                file_path = source_path + '/' + file_entry['name']
                if file_entry['type'] == EntryType.FOLDERS:
                    processed_saved_state_paths.add(file_path)
                    ProcessFolder(mac_info, saved_states, user_name, file_path)
                else:
                    # Must be an alias (symlink)
                    if mac_info.IsSymbolicLink(file_path):
                        target_path = mac_info.ReadSymLinkTargetPath(file_path)
                        processed_saved_state_paths.add(target_path)
                        if  mac_info.IsValidFolderPath(target_path):
                            ProcessFolder(mac_info, saved_states, user_name, target_path)
                        else:
                            if mac_info.IsValidFilePath(target_path):
                                log.warning(f'Symlink target path was not a folder! Symlink file={file_path}, target={target_path}')
                            #else:
                            #    log.warning(f'Symlink target path does not exist! Symlink file={file_path}, target={target_path}')
        #
        source_path = saved_state_container_path.format(user.home_dir)
        if mac_info.IsValidFolderPath(source_path):
            folders_list = mac_info.ListItemsInFolder(source_path, EntryType.FOLDERS, include_dates=False)
            for item in folders_list:
                container_state_folder = f'{source_path}/{item["name"]}/Data/Library/Saved Application State'
                if mac_info.IsValidFolderPath(container_state_folder):
                    sub_folders_list = mac_info.ListItemsInFolder(container_state_folder, EntryType.FOLDERS, include_dates=False)
                    for sub_folder in sub_folders_list:
                        target_folder = f'{container_state_folder}/{sub_folder["name"]}'
                        if target_folder not in processed_saved_state_paths:
                            processed_saved_state_paths.add(target_folder)
                            log.debug(f'Processing saved state info for container {target_folder}')
                            ProcessFolder(mac_info, saved_states, user_name, target_folder)
                        #else:
                        #    log.debug(f'container already processed{target_folder}')

    if len(saved_states) > 0:
        PrintAll(saved_states, mac_info.output_params, '')
    else:
        log.info('No saved states were found!')

def Plugin_Start_Standalone(input_files_list, output_params):
    '''Main entry point function when used on single artifacts (mac_apt_singleplugin), not on a full disk image'''
    pass

def Plugin_Start_Ios(ios_info):
    '''Entry point for ios_apt plugin'''
    pass

if __name__ == '__main__':
    print ("This plugin is a part of a framework and does not run independently on its own!")