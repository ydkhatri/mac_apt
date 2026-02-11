'''
   Copyright (c) 2026 Yogesh Khatri 

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the 
   terms of the MIT License.
   
'''
import csv
import logging
import os
import plugins.helpers.zip_inf64 as zipfile
import re
import tarfile

from datetime import datetime
from pathlib import Path

log = logging.getLogger('MAIN.HELPERS.UAC_EXTRACTOR')

windows_bad_chars = '[<>?\'":*|]'
is_windows = (os.name == 'nt')

def to_datetime(ts_str):
    '''
    Convert Unix timestamps to datetime objects (-1 stays as None)
    
    :param ts_str: string representation of a Unix timestamp
    :return: datetime object or None
    '''
    if ts_str and ts_str != '-1':
        return datetime.fromtimestamp(int(ts_str))
    return None

def parse_bodyfile(filename):
    """
    Parse a bodyfile (TSK 3.x format) and return a dictionary.
    Skips comment lines and handles pipe delimiters with escapes.
    """
    entries = {}
    with open(filename, 'r', encoding='utf-8', errors='replace') as f:
        reader = csv.reader(f, delimiter='|')
        for row in reader:
            if not row or row[0].startswith('#'):
                continue
            if len(row) >= 11:
                path = row[1]
                sym_link = None
                if path.find(' -> ') > 0:
                    # Handle symlink paths that may contain ' -> ' by splitting on the first occurrence
                    path = row[1].split(' -> ')[0]
                    sym_link = row[1].split(' -> ')[1]
                    log.debug(f"Found symlink in bodyfile: {path} -> {sym_link}")
                entry = {
                    'md5': '' if row[0] == '0' else row[0],
                    'path': path,
                    'sym_link': sym_link,
                    'inode': row[2],
                    'mode': row[3],
                    'uid': int(row[4]),
                    'gid': int(row[5]),
                    'size': int(row[6]) if row[6] else 0,
                    'a_time': to_datetime(row[7]),
                    'm_time': to_datetime(row[8]),
                    'c_time': to_datetime(row[9]),
                    'cr_time': to_datetime(row[10])
                }
                entries[entry['path']] = entry
    return entries

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

def get_meta_info(extracted_path):
    ''' Returns a meta dictionary with filepaths as keys and dict of dates as value. 
        Expects bodyfile to be at extracted_path/bodyfile/bodyfile.txt
        The bodyfile is expected to be in TSK 3.x format with 11 fields, however
        not all files collected may be listed in the bodyfile!'''
    meta = {}
    # look for bodyfile/bodyfile.txt
    source_path = os.path.join(extracted_path, 'bodyfile', 'bodyfile.txt')
    if not os.path.exists(source_path):
        log.error(f'Bodyfile not found at expected location: {source_path}')
        return meta
    
    bodyfile_data = parse_bodyfile(source_path)
    return bodyfile_data

def extract_uac_zip(source_path, dest_dir):
    """
    Extracts all members from zip file to the destination directory.
    Creates dest_dir if needed.
    Throws RuntimeError exception on failure.
    """

    # Validate source path ends with .zip
    if not (source_path.lower().endswith('.zip')):
        log.error("Source path must end with '.zip'")
        return False, None
    
    try:
        os.makedirs(dest_dir, exist_ok=True)
    except OSError as e:
        log.error(f"Failed to create destination directory '{dest_dir}': {e}")
        return False, None
    
    try:
        with zipfile.ZipFile(source_path, 'r') as zip_file:
            for member in zip_file.infolist():
                if member.is_dir():
                    continue  # Skip directories
                try:
                    zip_file.extract(member, path=dest_dir)
                except (zipfile.BadZipFile, OSError) as e:
                    log.exception(f"Failed to extract member {member.filename}: {e}")

            log.info(f"Successfully extracted '{source_path}' to '{dest_dir}'")
            return True, get_meta_info(dest_dir)

    except zipfile.BadZipFile:
        log.error(f"Error: '{source_path}' is not a valid ZIP file.")
    except FileNotFoundError:
        log.error(f"Source file '{source_path}' not found")
    except PermissionError as e:
        log.error(f"Permission denied accessing '{source_path}' or '{dest_dir}': {e}")
    return False, None

def extract_uac_tar(source_path, dest_dir):
    """
    Extracts all members from tar or tar.gz files to the destination directory.
    Captures PaxHeader info into a separate dictionary. Creates dest_dir if needed.
    Returns a tuple of (success, meta_dict, xattributes_dict, symlinks_dict).
    """
    xattributes = {}
    symlinks = {}
    
    # Validate source path ends with .tar or .tar.gz
    if not (source_path.lower().endswith('.tar') or source_path.lower().endswith('.tar.gz')):
        raise ValueError("Source path must end with '.tar' or '.tar.gz'")
    
    try:
        os.makedirs(dest_dir, exist_ok=True)
    except OSError as e:
        raise RuntimeError(f"Failed to create destination directory '{dest_dir}': {e}")
    
    try:
        with tarfile.open(source_path, 'r:*') as tar:
            for member in tar:
                if member.pax_headers:
                    xattr_info = {}
                    for key, value in member.pax_headers.items():
                        if key.startswith('SCHILY.xattr.'):
                            attr_name = key[13:]
                            xattr_info[attr_name] = value

                    if xattr_info:
                        member_name = member.name[6:] if member.name.startswith('[root]') else member.name
                        xattributes[member_name] = xattr_info
                        print(f"XAttributes captured: {member_name}")
                    continue  # Skip extraction of PaxHeader data

                # Skip symbolic links (does not follow/dereference)
                if member.type == tarfile.SYMTYPE:
                    print(f"Got symlink: {member.name} -> {member.linkname}")
                    file_path = Path(f"{dest_dir}/{member.name}")
                    file_path.parent.mkdir(parents=True, exist_ok=True)
                    with open(file_path, 'w') as symlink_file:
                        symlink_file.write(member.linkname)
                        member_name = member.name[6:] if member.name.startswith('[root]') else member.name
                        symlinks[member_name] = member.linkname
                    continue
                # Extract regular files
                try:
                    tar.extract(member, path=dest_dir)
                    print("Extracted member:", member.name)
                except (tarfile.TarError, OSError) as e:
                    log.exception(f"Failed to extract member {member.name}: {e}")

            log.info(f"Successfully extracted '{source_path}' to '{dest_dir}'")
            log.debug(f"XAttributes found: {len(xattributes)}")
            return True, get_meta_info(dest_dir), xattributes, symlinks

    except tarfile.ReadError as e:
        log.error(f"Invalid or corrupt tar file '{source_path}': {e}")
    except tarfile.ExtractError as e:
        log.error(f"Extraction failed for '{source_path}': {e}")
    except FileNotFoundError:
        log.error(f"Source file '{source_path}' not found")
    except PermissionError as e:
        log.error(f"Permission denied accessing '{source_path}' or '{dest_dir}': {e}")
    return False, None, xattributes, symlinks
