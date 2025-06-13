'''
   Copyright (c) 2025 Yogesh Khatri 

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the 
   terms of the MIT License.
   
'''
import binascii
import json
import logging
import os
import re
import time
import zipfile_deflate64 as zipfile

from dateutil import parser
from plugins.helpers.common import CommonFunctions
from win32_setctime import setctime

log = logging.getLogger('MAIN.HELPERS.VR_EXTRACTOR')

windows_bad_chars = '[<>?\'":*|]'
is_windows = (os.name == 'nt')

def unsanitize(s):
    '''Mimics VR unsanitize function'''
    def replace(matchobj):
        try:
            return binascii.unhexlify(matchobj.group(1))
        except ValueError as ex:
            log.exception('Error')
        return b''
    # convert to binary
    bin_string = s.encode()
    ret = re.sub(b'%([0-9A-Fa-f]{2})', replace, bin_string).decode('utf8')
    #if ret.endswith('%'):
    #    ret = ret[:-1]
    return ret

def convert_str_to_epoch(s):
    try:
        return parser.parse(s)
    except (OSError, ValueError, OverflowError):
        pass #log.debug('failed to read date or data too large or too far back (1601)')
    return parser.parse('1980-01-01 00:00:00')

def sanitize_for_windows(s):
    def replace(matchobj):
        try:
            char = matchobj.group(0)
            if char:
                return f'%{ord(char):X}'
            return ''
        except ValueError as ex:
            log.exception('Error')
        return ''
    ret = re.sub(windows_bad_chars, replace, s)

    return ret

def get_meta_info(zip):
    '''Returns a meta dictionary with filepaths as keys and dict of dates as value'''
    meta = {}
    regex = re.compile(r'^results/.*((\.Search\.FileFinder)|(MacOS\.Orchard))\.json$', re.IGNORECASE) # for custom ones!
    for member in zip.namelist():
        matches = regex.findall(member)
        if matches:
            with zip.open(member, 'r') as zf:
                default_ts = '1970-01-01 00:00:00'
                for line in zf.readlines():
                    k = json.loads(line) # read json info
                    dest_file = k["OSPath"].replace('////', '//')

                    if len(dest_file) == 0: 
                        continue

                    extended_attributes = k.get("XAttr", {})

                    meta[dest_file.lower()] = {
                        "Created": convert_str_to_epoch(k.get("BTime", default_ts)), 
                        "Modified": convert_str_to_epoch(k.get("MTime", default_ts)),
                        "LastAccessed": convert_str_to_epoch(k.get("ATime", default_ts)),
                        "MetadataChanged": convert_str_to_epoch(k.get("CTime", default_ts)),
                        "XAttr": extended_attributes
                    }
                break
    return meta

def extract_file(zip, member, relative_path, out_path, metadata_collection):
    global is_windows
    #debug_orig = relative_path
    relative_path = unsanitize(relative_path)

    original_relative_path = relative_path
    relative_path = sanitize_for_windows(relative_path) # not required for linux/mac but this keeps output names the same regardless of processing platform, so do it
    if is_windows:
        relative_path = relative_path.replace('/', '\\')
    else:
        relative_path = original_relative_path
    folder_path = os.path.join(out_path, os.path.split(relative_path)[0])
    if not os.path.exists(folder_path):
        try:
            os.makedirs(folder_path)
        except OSError as ex:
            log.exception(f'Error creating folder {folder_path}')
            return
    try:
        # get metadata and set timestamps on file
        meta = None
        if metadata_collection:
            meta = metadata_collection.get('/' + original_relative_path.lower(), None)
            if meta is None and original_relative_path.endswith('.idx'):
                log.debug(f'Skipped VR metadata file: {original_relative_path}')
                return
        with zip.open(member) as zip_member_file:
            output_file_path = os.path.join(out_path, relative_path)
            with open(output_file_path, 'wb') as f:
                block_size = 1024*256 #256K
                data = zip_member_file.read(block_size)
                while data:
                    f.write(data)
                    data = zip_member_file.read(block_size)
        # set timestamps on file
        if meta:
            os.utime(output_file_path, (meta['LastAccessed'].timestamp(), meta['Modified'].timestamp()))
            if is_windows:
                setctime(output_file_path, meta['Created'].timestamp(), follow_symlinks=False)
        else:
            log.error(f'Failed to get metadata for {member} which was relative path {original_relative_path}')
    except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile) as ex:
        log.error(f'Could not write file to filesystem, path was {output_file_path} \nException was: ' + str(ex))

def export_files(zip, out_path, metadata_collection):
    '''Returns true if extracted one or more files'''
    extracted_files = False

    log.info("Starting extraction of zip...")

    regex_auto = re.compile(rf'^uploads/(?:auto|file)/(.+)')
    for member in zip.namelist():
        matches = regex_auto.findall(member)
        if matches:
            relative_path = matches[0]
            if relative_path.endswith('/'): # check for folder
                continue
            extract_file(zip, member, relative_path, out_path, metadata_collection)
            extracted_files = True
    return extracted_files

def extract_zip(input_path: str, output_path: str) -> bool:
    """Main Extract function. Returns tuple (success, metadata)

    Args:
        input_path (str): Path to zip file
        output_path (str): Path to output folder, will be created 
    """
    try:
        succeeded = False
        metadata_collection = {}
        start_time = time.time()
        zip = zipfile.ZipFile(input_path, mode='r', allowZip64 = True)
        root_folder_items = {x.split('/')[0] for x in zip.namelist()}
        if 'client_info.json' in root_folder_items:
            metadata_collection = get_meta_info(zip)
            succeeded = export_files(zip, output_path, metadata_collection)
        else:
            log.error('Could not find client_info.json. Zip is not the one expected!')
        zip.close()
        end_time = time.time()
        log.info(f'Finished extraction in {CommonFunctions.GetTimeTakenString(start_time, end_time)}!')

    except (zipfile.BadZipFile, OSError, ValueError) as ex:
        log.error(ex)

    return succeeded, metadata_collection