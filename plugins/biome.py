'''
   Copyright (c) 2026 Yogesh Khatri

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the
   terms of the MIT License.

   biome.py
   ---------------
   This plugin reads Biome data.
   
'''

from plugins.helpers.ccl_segb.ccl_segb_common import EntryState
from plugins.helpers.ccl_segb.ccl_segb1 import Segb1Entry, read_segb1_stream, stream_matches_segbv1_signature
from plugins.helpers.ccl_segb.ccl_segb2 import Segb2Entry, read_segb2_stream, stream_matches_segbv2_signature
from plugins.helpers.macinfo import *
from plugins.helpers.writer import *
from pprint import pformat
import blackboxprotobuf as bbpb
import logging
import os
import typing

__Plugin_Name = "BIOME" # Cannot have spaces, and must be all caps!
__Plugin_Friendly_Name = "Biome"
__Plugin_Version = "1.0"
__Plugin_Description = "Reads Biome data"
__Plugin_Author = "Yogesh Khatri"
__Plugin_Author_Email = "yogesh@swiftforensics.com"

__Plugin_Modes = "MACOS,ARTIFACTONLY" # Valid values are 'MACOS', 'IOS, 'ARTIFACTONLY' 
__Plugin_ArtifactOnly_Usage = 'Provide path of biome/streams folder'

log = logging.getLogger('MAIN.' + __Plugin_Name) # Do not rename or remove this ! This is the logger object

#---- Do not change the variable names in above section ----#

class InvalidStreamException(Exception):
    pass

class BiomeItem:
    def __init__(self, filename_timestamp, offset, state, data, ts1, ts2, biome_type, user, source_path):
        self.filename_timestamp = filename_timestamp
        self.offset = offset
        self.state = state
        self.data = data
        self.ts1 = ts1
        self.ts2 = ts2
        self.biome_type = biome_type
        self.user = user
        self.source_path = source_path

def PrintAll(biome_items, output_params, input_path=''):
    biome_info = [  ('Biome Type',DataType.TEXT), 
                    ('Filename timestamp',DataType.TEXT),
                    ('Offset',DataType.INTEGER),('State',DataType.TEXT),
                    ('Data',DataType.DATE),
                    ('Timestamp1',DataType.DATE),('Timestamp2',DataType.DATE),
                    ('User',DataType.TEXT),('Source',DataType.TEXT)
                ]

    log.info (str(len(biome_items)) + " biome item(s) found")

    biome_list_final = []
    for item in biome_items:
        single_biome_item = [item.biome_type, item.filename_timestamp, 
                             item.offset, item.state, 
                             item.data, 
                             item.ts1, item.ts2,
                             item.user, item.source_path
                            ]
        biome_list_final.append(single_biome_item)

    WriteList("Biome Information", "Biome", biome_list_final, biome_info, output_params, input_path)

def read_segb_stream(stream: typing.BinaryIO):
    '''Reads a single stream from the Biome SEGB file stream'''
    if stream_matches_segbv1_signature(stream):
        return read_segb1_stream(stream)
    elif stream_matches_segbv2_signature(stream):
        return read_segb2_stream(stream)
    else:
        raise InvalidStreamException("Not a SEGB File or maybe encrypted", stream)
    return None

def get_enum_name_or_value(enum_class, value):
    try:
        # Returns the string name if the value is defined
        return enum_class(value).name
    except ValueError:
        # Returns the raw integer if undefined
        return value
    
def interpret_data(data: bytes, biome_type: str, record_offset: int) -> tuple:
    try:
        if biome_type == 'SystemSettings.SearchTerms':
            pb_def = {'1': {'type': 'string', 'name': 'search_term'}, 
                    '2': {'name': 'match', 'type': 'message', 'message_typedef': {
                        '1': {'type': 'string', 'name': 'bundle_identifier'},
                        '2': {'type': 'string', 'name': 'app_or_bundle'},
                        '3': {'type': 'int', 'name': 'unknown'}
                    }}}
            message, _ = bbpb.decode_message(data, pb_def)
        elif biome_type == 'Device.Wireless.Bluetooth':
            pb_def = {'1': {'type': 'string', 'name': 'address'},
                    '2': {'type': 'string', 'name': 'product_name'},
                    '3': {'type': 'int', 'name': 'product_id'},
                    '4': {'type': 'int', 'name': 'status'}
                    }
            message, _ = bbpb.decode_message(data, pb_def)
            if message['status'] == 0:
                message['status'] = 'Disconnect'
            elif message['status'] == 1:
                message['status'] = 'Connect'
            else:
                message['status'] = f'Unknown ({message["status"]})'
        elif biome_type == 'Device.Wireless.WiFi':
            pb_def = {'1': {'type': 'string', 'name': 'ssid'},
                    '2': {'type': 'int', 'name': 'status'}
                    }
            message, _ = bbpb.decode_message(data, pb_def)
            if message['status'] == 0:
                message['status'] = 'Disconnect'
            elif message['status'] == 1:
                message['status'] = 'Connect'
            else:
                message['status'] = f'Unknown ({message["status"]})'
        elif biome_type == 'App.InFocus':
            pb_def = {'3': {'type': 'int', 'name': 'status'},
                    '6': {'type': 'string', 'name': 'product_name'},
                    '9': {'type': 'string', 'name': 'CFBundleShortVersionString'},
                    '10': {'type': 'string', 'name': 'CFBundleVersion'}
                    }
            message, _ = bbpb.decode_message(data, pb_def)
            if message['status'] == 0:
                message['status'] = 'Out of focus'
            elif message['status'] == 1:
                message['status'] = 'In focus'
            else:
                message['status'] = f'Unknown ({message["status"]})'
        elif biome_type.startswith('Safari.'):
            pb_def = {'1': {'type': 'string', 'name': 'domain_visited'}}
            message, _ = bbpb.decode_message(data, pb_def)
        elif biome_type == 'App.WebUsage':
            pb_def = {
                    '3': {'type': 'int', 'name': 'status'},
                    '4': {'type': 'string', 'name': 'url'},
                    '5': {'type': 'string', 'name': 'domain_visited'},
                    '6': {'type': 'string', 'name': 'app_bundle_id'},
                    }
            message, _ = bbpb.decode_message(data, pb_def)
        elif biome_type == 'ScreenTime.AppUsage':
            pb_def = {'1': {'type': 'int', 'name': 'status'},
                    '3': {'type': 'string', 'name': 'app_bundle_id'}
                    }
            message, _ = bbpb.decode_message(data, pb_def)
            if message['status'] == 0:
                message['status'] = 'Out of focus'
            elif message['status'] == 1:
                message['status'] = 'In focus'
            else:
                message['status'] = f'Unknown ({message["status"]})'
        else:
            pb_def = None
            message, _ = bbpb.decode_message(data, pb_def)
            
    except (bbpb.DecoderException, ValueError, KeyError) as ex:
        log.error(f"Had an error interpreting protobuf for record at pos {record_offset} : {ex}")
        message = data
    return message

def process_biome(stream: typing.BinaryIO, biome_items: list, user: str, source_path: str, file_name: str, biome_type: str):
    log.debug(f'Reading biome file {source_path}')
    try:
        for record in read_segb_stream(stream):
            # record will be a SEGB1 or SEGB2 class depending on which type of file was passed
            if record.state == 3: 
                continue # DELETED
            
            ts_filename_int = CommonFunctions.IntFromStr(file_name, suppress_exception=True)
            ts_filename = CommonFunctions.ReadMacAbsoluteTime(ts_filename_int/1000000)
            message = interpret_data(record.data, biome_type, record.data_start_offset)

            b = BiomeItem(ts_filename, 
                          record.data_start_offset, 
                          get_enum_name_or_value(EntryState, record.state), 
                          pformat(message) if isinstance(message, dict) else message,
                          record.timestamp1, 
                          record.timestamp2 if isinstance(record, Segb1Entry) else None,
                          biome_type, user, source_path)
            biome_items.append(b)
    except InvalidStreamException as ex:
        log.warning(f'Not a valid SEGB1 or SEGB2 stream, invalid file data in file {source_path}')
    except ValueError as ex:
        log.error(f'Had error reading biome data from {source_path} : {ex}')

def process_biome_folder(mac_info, base_path, biome_items, user_name):
    for folder in ('restricted', 'public'):
        if not mac_info.IsValidFolderPath(base_path + folder):
            continue

        for biome_type in mac_info.ListItemsInFolder(base_path + folder, EntryType.FOLDERS):
            # List all files under /local/ , ignore the /tombstone/* entries in it
            biome_folder = base_path + folder + f'/{biome_type["name"]}/local'
            for biome_file in mac_info.ListItemsInFolder(biome_folder, EntryType.FILES):
                if biome_file['size'] == 0:
                    continue
                source_path = f'{biome_folder}/{biome_file["name"]}'
                mac_info.ExportFile(source_path, __Plugin_Name, f'{user_name}_{biome_type["name"]}_', False)
                f = mac_info.Open(source_path)
                if f:
                    process_biome(f, biome_items, user_name, source_path, biome_file["name"], biome_type["name"])
                else:
                    log.error(f'Failed to open file {source_path}')

def process_biome_folder_local(base_path, biome_items):
    for folder in ('restricted', 'public'):
        path1 = os.path.join(base_path, folder)
        if not os.path.isdir(path1):
            continue

        for biome_type in os.listdir(path1):
            # List all files under /local/ , ignore the /tombstone/* entries in it
            path2 = os.path.join(path1, biome_type)
            if not os.path.isdir(path2):
                continue
            biome_folder = os.path.join(path2, 'local')
            for biome_file in os.listdir(biome_folder):
                source_path = os.path.join(biome_folder, biome_file)
                if os.path.isdir(source_path) or \
                    os.path.getsize(source_path) == 0:
                    continue
                try:
                    with open(source_path, 'rb') as f:
                        process_biome(f, biome_items, '-', source_path, biome_file, biome_type)
                except OSError as ex:
                    log.error(f'Failed to open file {source_path} : {ex}')

def Plugin_Start(mac_info):
    '''Main Entry point function for plugin'''
    user_biome_path = '{}/Library/Biome/streams/'
    system_biome_path = '/private/var/db/biome/streams/'
    biome_items = []

    if mac_info.IsValidFolderPath(system_biome_path):
        process_biome_folder(mac_info, system_biome_path, biome_items, '-')

    processed_paths = []
    for user in mac_info.users:
        user_name = user.user_name
        if user.home_dir == '/private/var/empty': continue # Optimization, nothing should be here!
        elif user.home_dir == '/private/var/root': user_name = 'root' # Some other users use the same root folder, we will list such all users as 'root', as there is no way to tell
        if user.home_dir in processed_paths: continue # Avoid processing same folder twice (some users have same folder! (Eg: root & daemon))
        processed_paths.append(user.home_dir)
        base_path = user_biome_path.format(user.home_dir)
        if mac_info.IsValidFolderPath(base_path):
            process_biome_folder(mac_info, base_path, biome_items, user_name)

    if len(biome_items) > 0:
        PrintAll(biome_items, mac_info.output_params, '')
    else:
        log.info('No Biome artifacts found')

def Plugin_Start_Standalone(input_files_list, output_params):
    '''Main entry point function when used on single artifacts (mac_apt_singleplugin), not on a full disk image'''
    log.info("Module Started as standalone")
    biome_items = []
    for input_path in input_files_list:
        log.debug("Input file passed was: " + input_path)
        ## Process the input file here ##
        if os.path.isdir(input_path):
            process_biome_folder_local(input_path, biome_items)

    if len(biome_items) > 0:
        PrintAll(biome_items, output_params, '')
    else:
        log.info('No Biome artifacts found')

def Plugin_Start_Ios(ios_info):
    '''Entry point for ios_apt plugin'''
    pass

if __name__ == '__main__':
    print ("This plugin is a part of a framework and does not run independently on its own!")