'''
   Copyright (c) 2017 Yogesh Khatri 

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the 
   terms of the MIT License.
   
'''

import logging
import os
import posixpath
import random
import shutil
import sqlite3
import stat
import string
import struct
import sys
import tempfile
import time
import zipfile
from io import BytesIO
from uuid import UUID

import nska_deserialize as nd
import pytsk3
from plugins.helpers import decryptor
from plugins.helpers.apfs_reader import *
from plugins.helpers.common import *
from plugins.helpers.darwin_path_generator import GetDarwinPath, GetDarwinPath2
from plugins.helpers.hfs_alt import HFSVolume
from plugins.helpers.structs import *

if sys.platform == 'linux':
    from plugins.helpers.statx import statx

log = logging.getLogger('MAIN.HELPERS.MACINFO')

'''
    Common data structures for plugins 
'''
class OutputParams:
    def __init__(self):
        self.output_path = ''
        self.write_csv = False
        self.write_tsv = False
        self.write_sql = False
        self.write_xlsx = False
        self.xlsx_writer = None
        self.output_db_path = ''
        self.export_path = '' # For artifact source files
        self.export_path_rel = '' # Relative export path
        self.export_log_sqlite = None
        self.timezone = TimeZoneType.UTC

class UserInfo:
    def __init__ (self):
        self.user_name = ''
        self.real_name = ''
        self.home_dir = ''
        self.UID = '' # retain as string
        self.UUID = ''
        self.GID = '' # retain as string
        self.pw_hint = ''
        self.password = ''
        self.creation_time = None
        self.deletion_time = None
        self.failed_login_count = 0
        self.failed_login_timestamp = None
        self.last_login_timestamp = None
        self.password_last_set_time = None
        self.DARWIN_USER_DIR = '' #0  With DARWIN_USER_* folders, there may be one or more comma separated
        self.DARWIN_USER_TEMP_DIR = '' #T
        self.DARWIN_USER_CACHE_DIR = ''#C
        self._source = '' # Path of data source

class HfsVolumeInfo:
    def __init__(self):
        #self.name = ''
        self.version = 0
        self.last_mounted_version = ''
        self.date_created_local_time = None
        self.date_modified = None
        self.date_backup = None
        self.date_last_checked = None
        self.num_files = 0
        self.num_folders = 0
        self.block_size = 0
        self.total_blocks = 0
        self.free_blocks = 0
        self.is_HFSX = False

class NativeHfsParser:
    '''Native HFS+ parser - pure python implementation'''
    def __init__(self):
        self.initialized = False
        self.volume = None

    def Initialize(self, pytsk_img, offset):
        if not pytsk_img: return False
        try:
            log.debug('Initializing NativeHFSParser->HFSVolume  Vol starts @ offset 0x{:X}'.format(offset))
            self.volume = HFSVolume(pytsk_img, offset)
            self.initialized = True
            return True
        except ValueError as ex:
            log.exception('Could not initialize HFS volume class: '+ str(ex))
        return False

    def GetVolumeInfo(self):
        if not self.initialized:
            raise ValueError("Volume not loaded (initialized)!")
        try:
            hfs_info = HfsVolumeInfo()
            header = self.volume.header
            hfs_info.is_HFSX = header.signature == 0x4858
            hfs_info.block_size = header.blockSize
            hfs_info.version = 0
            hfs_info.last_mounted_version = struct.unpack("<4s", struct.pack(">I", header.lastMountedVersion))[0].decode('utf-8', 'ignore') # ugly, is there a better way?
            hfs_info.date_created_local_time = CommonFunctions.ReadMacHFSTime(header.createDate)
            hfs_info.date_modified = CommonFunctions.ReadMacHFSTime(header.modifyDate)
            hfs_info.date_backup = CommonFunctions.ReadMacHFSTime(header.backupDate)
            hfs_info.date_last_checked = CommonFunctions.ReadMacHFSTime(header.checkedDate)
            hfs_info.num_files = header.fileCount
            hfs_info.num_folders = header.folderCount
            hfs_info.total_blocks = header.totalBlocks
            hfs_info.free_blocks = header.freeBlocks
            return hfs_info
        except ValueError as ex:
            log.exception("Failed to read HFS info")
        return None

    def GetExtendedAttribute(self, path, att_name):
        return self.volume.getXattr(path, att_name)

    def GetExtendedAttributes(self, path):
        return self.volume.getXattrsByPath(path)

    def GetFileSize(self, path, error=None):
        '''For a given file path, gets logical file size, or None if error'''
        try:
            return self.volume.GetFileSize(path)
        except ValueError as ex:
            log.debug ("NativeHFSParser->Exception from GetFileSize() " + str(ex))
        return error

    def _GetSizeFromRec(self, k, v):
        '''For a file's catalog key & value , gets logical file size, or 0 if error'''
        try:
            return self.volume.GetFileSizeFromFileRecord(v)
        except ValueError as ex:
            name = getString(k)
            log.error ("NativeHFSParser->Exception from _GetSizeFromRec()" +\
                        "\nFilename=" + name + " CNID=" + str(v.data.fileID) +\
                        "\nException details: " + str(ex))
        return 0

    def Open(self, path):
        '''Open files, returns open file handle'''
        if not self.initialized:
            raise ValueError("Volume not loaded (initialized)!")
        try:
            log.debug("Trying to open file : " + path)
            size = self.GetFileSize(path)
            if size > 209715200:
                log.warning('File size > 200 MB. File size is {} bytes'.format(size))
            f = tempfile.SpooledTemporaryFile(max_size=209715200)
            self.volume.readFile(path, f)
            f.seek(0)
            return f
        except (OSError, ValueError) as ex:
            log.exception("NativeHFSParser->Failed to open file {} Error was {}".format(path, str(ex)))

        return None

    def ExtractFile(self, path, extract_to_path):
        '''Extract file, returns True or False'''
        if not self.initialized:
            raise ValueError("Volume not loaded!")
        try:
            log.debug("Trying to export file : " + path + " to " + extract_to_path)
            with open(extract_to_path, "wb") as f:
                self.volume.readFile(path, f)
                f.close()
                return True
        except (ValueError, OSError) as ex:
            log.exception("NativeHFSParser->Failed to export file {} to {}".format(path, extract_to_path))
        return False

    def GetFileMACTimes(self, file_path):
        '''
           Returns dictionary {c_time, m_time, cr_time, a_time} 
           where cr_time = created time and c_time = Last time inode/mft modified
        '''
        try:
            return self.volume.GetFileMACTimes(file_path)
        except ValueError:
            log.exception('NativeHFSParser->Error trying to get MAC times')
        return { 'c_time':None, 'm_time':None, 'cr_time':None, 'a_time':None }

    def _GetFileMACTimesFromFileRecord(self, v):
        '''Return times from file's catalog record'''
        try:
            return self.volume.GetFileMACTimesFromFileRecord(v)
        except ValueError:
            log.exception('NativeHFSParser->Error trying to get MAC times')
        return { 'c_time':None, 'm_time':None, 'cr_time':None, 'a_time':None }

    def IsSymbolicLink(self, path):
        '''Check if a path is a symbolic link'''
        try:
            return self.volume.IsSymbolicLink(path)
        except ValueError:
            log.exception('NativeHFSParser->Failed trying to check for symbolic link')
        return False

    def IsValidFilePath(self, path):
        '''Check if a file path is valid, does not check for folders!'''
        ### FOR DEBUG ONLY
        if path.find('\\') >= 0:
            log.warning(f'In NativeHfsParser::IsValidFilePath(), found \\ in path: {path}')
        ###
        try:
            return self.volume.IsValidFilePath(path)
        except ValueError:
            log.exception('NativeHFSParser->Failed trying to check valid file path')
        return False

    def IsValidFolderPath(self, path):
        '''Check if a folder path is valid'''
        ### FOR DEBUG ONLY
        if path.find('\\') >= 0:
            log.warning(f'InNativeHfsParser::IsValidFolderPath(), found \\ in path: {path}')
        ###
        try:
            return self.volume.IsValidFolderPath(path)
        except ValueError:
            log.exception('NativeHFSParser->Failed trying to check valid folder path')
        return False

    def GetUserAndGroupID(self, path):
        '''
            Returns tuple (success, UID, GID) for object identified by path
            If failed to get values, success=False
            UID & GID are returned as strings
        '''
        success, uid, gid = False, 0, 0
        try:
            uid, gid = self.volume.GetUserAndGroupID(path)
            uid = str(uid)
            gid = str(gid)
            success = True
        except ValueError as ex:
            log.error("Exception trying to get uid & gid for " + path + ' Exception details: ' + str(ex))
        return success, uid, gid

    def GetUserAndGroupIDForFile(self, path):
        '''
            Returns tuple (success, UID, GID) for file identified by path
            If failed to get values, success=False
            UID & GID are returned as strings
        '''
        return self.GetUserAndGroupID(path)

    def GetUserAndGroupIDForFolder(self, path):
        '''
            Returns tuple (success, UID, GID) for folder identified by path
            If failed to get values, success=False
            UID & GID are returned as strings
        '''
        return self.GetUserAndGroupID(path)

    def ListItemsInFolder(self, path='/', types_to_fetch=EntryType.FILES_AND_FOLDERS, include_dates=False):
        ''' 
        Returns a list of files and/or folders in a list
        Format of list = [ { 'name':'got.txt', 'type':EntryType.FILES, 'size':10, 'dates': [] }, .. ]
        'path' should be linux style using forward-slash like '/var/db/xxyy/file.tdc'
        '''
        items = [] # List of dictionaries
        try:
            k,v = self.volume.catalogTree.getRecordFromPath(path)
            if k:
                if v.recordType == kHFSPlusFolderRecord:
                    for k,v in self.volume.catalogTree.getFolderContents(v.data.folderID):
                        if v.recordType in (kHFSPlusFolderRecord, kHFSPlusFileRecord):
                            try:
                                entry_type = EntryType.FILES if v.recordType == kHFSPlusFileRecord else EntryType.FOLDERS
                                if types_to_fetch == EntryType.FILES_AND_FOLDERS:
                                    items.append( self._BuildFileListItemFromRecord(k, v, entry_type, include_dates) )
                                elif types_to_fetch == EntryType.FILES and entry_type == EntryType.FILES:
                                    items.append( self._BuildFileListItemFromRecord(k, v, entry_type, include_dates) )
                                elif types_to_fetch == EntryType.FOLDERS and entry_type == EntryType.FOLDERS:
                                    items.append( self._BuildFileListItemFromRecord(k, v, entry_type, include_dates) )
                            except Exception as ex:
                                log.error("Error accessing file/folder record: " + str(ex))
                else:
                    log.error("Can't get dir listing as this is not a folder : " + path)
            else:
                log.error('Path not found : ' + path)
        except (KeyError, ValueError, TypeError, OSError):
            log.error('Error trying to get file list from folder: ' + path)
            log.exception('')
        return items

    def _BuildFileListItemFromRecord(self, k, v, entry_type, include_dates):
        name = getString(k)
        item = None
        if include_dates:
            item = { 'name':name,
                     'type':entry_type,
                     'size':self._GetSizeFromRec(k, v) if entry_type == EntryType.FILES else 0,
                     'dates': self._GetFileMACTimesFromFileRecord(v)
                    }
        else:
            item = { 'name':name, 'type':entry_type, 'size':self._GetSizeFromRec(k, v) if entry_type == EntryType.FILES else 0 }
        return item

class MacInfo:

    def __init__(self, output_params, password='', dont_decrypt=False):
        #self.Partitions = {}   # Dictionary of all partition objects returned from pytsk LATER!
        self.pytsk_image = None
        self.macos_FS = None      # Just the FileSystem object (fs) from OSX partition
        self.macos_partition_start_offset = 0 # Container offset if APFS
        self.vol_info = None # disk_volumes
        self.output_params = output_params
        self.os_version = '0.0.0'
        self.os_version_extra = '' # Since macOS 13, for Rapid Security Response patches
        self.os_build = ''
        self.os_friendly_name = 'No name yet!'
        self.users = []
        self.hfs_native = NativeHfsParser()
        self.is_apfs = False
        self.use_native_hfs_parser = True
        # runtime platform
        self.is_windows = (os.name == 'nt')
        self.is_linux = (sys.platform == 'linux')
        # for encrypted volumes
        self.password = password
        self.dont_decrypt = dont_decrypt # To force turning off decryption in case a 3rd party tool has already decrypted image but container and volume flags still say its enc

    # Public functions, plugins can use these
    def GetAbsolutePath(self, current_abs_path, dest_rel_path):
        '''Returns the absolute (full) path to a destination file/folder given the
            current location (path) and a relative path to the destination. This is
            for relative paths that start with . or ..  '''
        # This is for linux paths only
        if dest_rel_path in ('', '/'):
            return current_abs_path
        # Strip / at start and end of dest
        dest_rel_path = dest_rel_path.rstrip('/').lstrip('/')

        if current_abs_path[-1] != '/':
            current_abs_path += '/'

        curr_paths = current_abs_path.rstrip('/').lstrip('/').split('/')
        if len(curr_paths) == 1 and curr_paths[0] == '':
            curr_paths = []
        rel_paths = posixpath.normpath(dest_rel_path).split('/')

        curr_path_index = len(curr_paths)
        for x in rel_paths:
            if x == '.':
                pass
            elif x == '..':
                if curr_path_index == 0:
                    raise ValueError('Relative path tried to go above root !')
                else:
                    curr_path_index -= 1
                    curr_paths.pop()
            elif x == '':
                raise ValueError("Relative path had // , can't parse")
            else:
                curr_paths.append(x)
                curr_path_index += 1

        final_path = ''
        for index, x in enumerate(curr_paths):
            final_path += '/' + x
            if index == curr_path_index:
                break
        if final_path == '':
            final_path = '/'
        return final_path

    def GetFileMACTimes(self, file_path):
        '''
           Returns dictionary {c_time, m_time, cr_time, a_time}
           where cr_time = created time and c_time = Last time inode/mft modified
        '''
        if self.use_native_hfs_parser:
            return self.hfs_native.GetFileMACTimes(file_path)

        times = { 'c_time':None, 'm_time':None, 'cr_time':None, 'a_time':None }
        try:
            tsk_file = self.macos_FS.open(file_path)
            times['c_time'] = CommonFunctions.ReadUnixTime(tsk_file.info.meta.ctime)
            times['m_time'] = CommonFunctions.ReadUnixTime(tsk_file.info.meta.mtime)
            times['cr_time'] = CommonFunctions.ReadUnixTime(tsk_file.info.meta.crtime)
            times['a_time'] = CommonFunctions.ReadUnixTime(tsk_file.info.meta.atime)
        except Exception as ex:
            log.exception('Error trying to get MAC times')
        return times

    def GetExtendedAttribute(self, path, att_name):
        if self.use_native_hfs_parser:
            return self.hfs_native.GetExtendedAttribute(path, att_name)

    def GetExtendedAttributes(self, path):
        if self.use_native_hfs_parser:
            return self.hfs_native.GetExtendedAttributes(path)

    def ExportFolder(self, artifact_path, subfolder_name, overwrite):
        '''Export an artifact folder to the output\Export\subfolder_name folder. This
           will export the entire folder and subfolders recursively. 
           This does not export Xattr. Return value is boolean (False if it encountered
           any errors).
        '''
        export_path = os.path.join(self.output_params.export_path, subfolder_name, os.path.basename(artifact_path))
        # create folder
        try:
            if not os.path.exists(export_path):
                os.makedirs(export_path)
        except (KeyError, ValueError, TypeError, OSError) as ex:
            log.error ("Exception while creating Export folder " + export_path + "\n Is output folder Writeable?" +
                       "Is it full? Perhaps the drive is disconnected? Exception Details: " + str(ex))
            return False
        # recursively export files/folders
        try:
            return self._ExportFolder(artifact_path, export_path, overwrite)
        except (KeyError, ValueError, TypeError, OSError):
            log.exception('Exception while exporting folder ' + artifact_path)
        return False

    def _ExportFolder(self, artifact_path, export_path, overwrite):
        '''Exports files/folders from artifact_path to export_path recursively'''
        artifact_path = artifact_path.rstrip('/')
        entries = self.ListItemsInFolder(artifact_path, EntryType.FILES_AND_FOLDERS, True)
        ret = True
        for entry in entries:
            new_path = os.path.join(export_path, self._GetSafeFilename(entry['name']))
            if entry['type'] == EntryType.FOLDERS:
                try:
                    if not os.path.exists(new_path):
                        os.mkdir(new_path)
                except:
                    log.exception("Exception while creating Export folder " + export_path)
                    ret = False
                    continue
                ret &= self._ExportFolder(artifact_path + '/' + entry['name'], new_path, overwrite)
            else: # FILE
                if entry['size'] > 0:
                    ret &= self._ExtractFile(artifact_path + '/' + entry['name'], new_path, entry['dates'])
                else:
                    log.info('Skipping export of {} as filesize=0'.format(artifact_path + '/' + entry['name']))
        return ret

    def ExportFile(self, artifact_path, subfolder_name, file_prefix='', check_for_sqlite_files=True, overwrite=False):
        '''Export an artifact (file) to the output\Export\subfolder_name folder.
           Ideally subfolder_name should be the name of the plugin.
           If 'overwrite' is set to True, it will not check for existing files. The
           default behaviour is to check and rename the newly exported file if there
           is a name collision.
           If this is an sqlite db, the -journal and -wal files will also be exported.
           The check for -journal and -wal can be skipped if  check_for_sqlite_files=False
           It is much faster to skip the check if not needed.
           The Function returns False if it fails to export the file.
        '''
        ### FOR DEBUG ONLY
        if artifact_path.find('\\') >= 0:
            log.warning(f'In MacInfo::ExportFile(), found \\ in path: {artifact_path}')
        ###
        export_path = os.path.join(self.output_params.export_path, subfolder_name)
        # create folder
        try:
            if not os.path.exists(export_path):
                os.makedirs(export_path)
        except Exception as ex:
            log.error ("Exception while creating Export folder " + export_path + "\n Is output folder Writeable?" +
                       "Is it full? Perhaps the drive is disconnected? Exception Details: " + str(ex))
            return False

        # extract each file to temp folder
        out_filename =  file_prefix + os.path.basename(artifact_path)
        out_filename = self._GetSafeFilename(out_filename) #filter filenames based on platform (Eg: Windows does not like ?<>/\:*"! in filenames)
        if overwrite:
            file_path = os.path.join(export_path, out_filename)
        else:
            file_path = CommonFunctions.GetNextAvailableFileName(os.path.join(export_path, out_filename))

        if self._ExtractFile(artifact_path, file_path):
            if check_for_sqlite_files:
                jrn_file_path = file_path + "-journal"
                wal_file_path = file_path + "-wal"
                if self.IsValidFilePath(artifact_path + "-journal"):
                    self._ExtractFile(artifact_path + "-journal", jrn_file_path)
                if self.IsValidFilePath(artifact_path + "-wal"):
                    self._ExtractFile(artifact_path + "-wal", wal_file_path)
            return True
        return False

    def _ExtractFile(self, artifact_path, export_path, mac_times=None):
        '''Internal function, just export, no checks!'''
        if self.ExtractFile(artifact_path, export_path):
            if not mac_times:
                mac_times = self.GetFileMACTimes(artifact_path)
            export_path_rel = os.path.relpath(export_path, start=self.output_params.export_path)
            if self.is_windows:
                export_path_rel = export_path_rel.replace('\\', '/')
            self.output_params.export_log_sqlite.WriteRow([artifact_path, export_path_rel, mac_times['c_time'], mac_times['m_time'], mac_times['cr_time'], mac_times['a_time']])
            return True
        else:
            log.info("Failed to export '" + artifact_path + "' to '" + export_path + "'")
        return False

    def ReadPlist(self, path, deserialize=False):
        '''Safely open and read a plist; returns tuple (True/False, plist/None, "error_message")
            If deserialize=True, returns a deserialized version of an NSKeyedArchive plist.
        '''
        log.debug("Trying to open plist file : " + path)
        error = ''
        plist = None
        try:
            f = self.Open(path)
            if f != None:
                log.debug("Trying to read plist file : " + path)
                return CommonFunctions.ReadPlist(f, deserialize)
            else:
                error = 'Failed to open file'
        except OSError as ex:
            error = 'Exception from ReadPlist, trying to open file. Exception=' + str(ex)
        return (False, None, error)

    def IsSymbolicLink(self, path):
        '''Check if path represents a symbolic link'''
        if self.use_native_hfs_parser:
            return self.hfs_native.IsSymbolicLink(path)
        return False

    def ReadSymLinkTargetPath(self, path):
        '''Returns the target file/folder's path from the sym link path provided'''
        f = self.Open(path)
        if f:
            target_path = f.read()
            f.close()
            return target_path.rstrip(b'\0').decode('utf8', 'backslashreplace')
        return ''

    def IsValidFilePath(self, path):
        '''Check if a file path is valid, does not check for folders!'''
        ### FOR DEBUG ONLY
        if path.find('\\') >= 0:
            log.warning(f'In MacInfo::IsValidFilePath(), found \\ in path: {path}')
        ###
        if self.use_native_hfs_parser:
            return self.hfs_native.IsValidFilePath(path)
        try:
            valid_file = self.macos_FS.open(path)
            return True
        except Exception:
            pass
        return False

    def IsValidFolderPath(self, path):
        '''Check if a folder path is valid'''
        ### FOR DEBUG ONLY
        if path.find('\\') >= 0:
            log.warning(f'In MacInfo::IsValidFolderPath(), found \\ in path: {path}')
        ###
        if self.use_native_hfs_parser:
            return self.hfs_native.IsValidFolderPath(path)
        try:
            valid_folder = self.macos_FS.open_dir(path)
            return True
        except Exception:
            pass
        return False

    def GetFileSize(self, path, error=None):
        '''For a given file path, gets logical file size, or None if error'''
        if self.use_native_hfs_parser:
            return self.hfs_native.GetFileSize(path)
        try:
            valid_file = self.macos_FS.open(path)
            return valid_file.info.meta.size
        except Exception as ex:
            log.debug (" Unknown exception from GetFileSize() " + str(ex) + " Perhaps file does not exist " + path)
        return error

    def ListItemsInFolder(self, path='/', types_to_fetch=EntryType.FILES_AND_FOLDERS, include_dates=False):
        '''
        Returns a list of files and/or folders in a list
        Format of list = [ { 'name':'got.txt', 'type':EntryType.FILES, 'size':10, 'dates': {} }, .. ]
        'path' should be linux style using forward-slash like '/var/db/xxyy/file.tdc'
        '''
        if self.use_native_hfs_parser:
            return self.hfs_native.ListItemsInFolder(path, types_to_fetch, include_dates)
        items = [] # List of dictionaries
        try:
            dir = self.macos_FS.open_dir(path)
            for entry in dir:
                name = self._GetName(entry)
                if name == "": continue
                elif name == "." or name == "..": continue
                elif not self._IsValidFileOrFolderEntry(entry): continue # this filters for allocated files and folders only
                entry_type = EntryType.FOLDERS if entry.info.name.type == pytsk3.TSK_FS_NAME_TYPE_DIR else EntryType.FILES
                if include_dates:
                    path_no_trailing_slash = path.rstrip('/')
                    item = { 'name':name, 'type':entry_type, 'size':self._GetSize(entry), 'dates': self.GetFileMACTimes(path_no_trailing_slash + '/' + name) }
                else:
                    item = { 'name':name, 'type':entry_type, 'size':self._GetSize(entry) }
                if types_to_fetch == EntryType.FILES_AND_FOLDERS:
                    items.append( item )
                elif types_to_fetch == EntryType.FILES and entry_type == EntryType.FILES:
                    items.append( item )
                elif types_to_fetch == EntryType.FOLDERS and entry_type == EntryType.FOLDERS:
                    items.append( item )

        except Exception as ex:
            if str(ex).find('tsk_fs_dir_open: path not found'):
                log.debug("Path not found : " + path)
            else:
                log.debug("Exception details:\n", exc_info=True)
                log.error("Failed to get dir info!")
        return items

    def Open(self, path):
        '''Open files less than 200 MB, returns open file handle'''
        if self.use_native_hfs_parser:
            return self.hfs_native.Open(path)
        try:
            log.debug("Trying to open file : " + path)
            tsk_file = self.macos_FS.open(path)
            size = tsk_file.info.meta.size
            if size > 209715200:
                raise ValueError('File size > 200 MB, use direct TSK file functions!')

            f = tempfile.SpooledTemporaryFile(max_size=209715200)
            BUFF_SIZE = 20 * 1024 * 1024
            offset = 0
            while offset < size:
                available_to_read = min(BUFF_SIZE, size - offset)
                data = tsk_file.read_random(offset, available_to_read)
                if not data: break
                offset += len(data)
                f.write(data)
            f.seek(0)
            return f
        except Exception as ex:
            if str(ex).find('tsk_fs_file_open: path not found:') > 0:
                log.error("Open() returned 'Path not found' error for path: {}".format(path))
            elif str(ex).find('tsk_fs_attrlist_get: Attribute 4352 not found') > 0 or \
                 (str(ex).find('Read error: Invalid file offset') > 0 and self._IsFileCompressed(tsk_file)) or \
                 str(ex).find('Read error: Error in metadata') > 0:
                log.debug("Known TSK bug caused Error: Failed to open file {}".format(path))
                log.debug("Trying to open with Native HFS parser")
                try:
                    if not self.hfs_native.initialized:
                        self.hfs_native.Initialize(self.pytsk_image, self.macos_partition_start_offset)
                    return self.hfs_native.Open(path)
                except (OSError, ValueError):
                    log.error("Failed to open file: " + path)
                    log.debug("Exception details:\n", exc_info=True)
            else:
                log.exception("Failed to open file {}".format(path)) 
        return None

    def ExtractFile(self, tsk_path, destination_path):
        '''Extract a file from image to provided destination path'''
        if self.use_native_hfs_parser:
            return self.hfs_native.ExtractFile(tsk_path, destination_path)
        try:
            tsk_file = self.macos_FS.open(tsk_path)
            size = tsk_file.info.meta.size

            BUFF_SIZE = 20 * 1024 * 1024
            offset = 0
            try:
                with open(destination_path, 'wb') as f:
                    while offset < size:
                        available_to_read = min(BUFF_SIZE, size - offset)
                        try:
                            data = tsk_file.read_random(offset, available_to_read)
                            if not data: break
                            offset += len(data)
                            f.write(data)
                        except Exception as ex:
                            if str(ex).find('tsk_fs_attrlist_get: Attribute 4352 not found') > 0 or \
                               (str(ex).find('Read error: Invalid file offset') > 0 and self._IsFileCompressed(tsk_file)) or \
                               str(ex).find('Read error: Error in metadata') > 0:
                                log.debug("Known TSK bug caused Error: Failed to read file {}".format(tsk_path))
                                log.debug("Trying to read with Native HFS parser")
                                try:
                                    f.close()
                                    os.remove(destination_path)
                                    if not self.hfs_native.initialized:
                                        self.hfs_native.Initialize(self.pytsk_image, self.macos_partition_start_offset)
                                    return self.hfs_native.ExtractFile(tsk_path,destination_path)
                                except Exception as ex2:
                                    log.error("Failed to export file: " + tsk_path)
                                    log.debug("Exception details:\n", exc_info=True)
                                return False
                            else:
                                log.exception("Failed to read file {}".format(tsk_path)) 
                                return False
                    f.flush()
                    f.close()
                return True
            except Exception as ex:
                log.error (" Failed to create file for writing - " + destination_path + "\n" + str(ex))
                log.debug("Exception details:", exc_info=True)
        except Exception as ex:
            if str(ex).find('tsk_fs_file_open: path not found:') > 0:
                log.debug("Open() returned 'Path not found' error for path: {}".format(tsk_path))
            else:
                log.error("Failed to open/find file: " + tsk_path)
        return False

    def GetArrayFirstElement(self, array, error=''):
        '''Safely return zero'th element'''
        try:
            return array[0]
        except IndexError:
            pass
        return error

    def GetVersionDictionary(self):
        '''Returns macOS version as dictionary {major:10, minor:5 , micro:0, extra:'(a)'}'''
        version_dict = { 'major':0, 'minor':0, 'micro':0, 'extra':self.os_version_extra }
        info = self.os_version.split(".")
        try:
            version_dict['major'] = int(info[0])
            try:
                version_dict['minor'] = int(info[1])
                try:
                    version_dict['micro'] = int(info[2])
                except (IndexError,ValueError):
                    pass
            except (IndexError,ValueError):
                pass
        except (IndexError,ValueError):
            pass
        return version_dict

    def GetUserAndGroupIDForFolder(self, path):
        '''
            Returns tuple (success, UID, GID) for folder identified by path
            If failed to get values, success=False
            UID & GID are returned as strings
        '''
        if self.use_native_hfs_parser:
            return self.hfs_native.GetUserAndGroupIDForFolder(path)
        success, uid, gid = False, 0, 0
        try:
            path_dir = self.macos_FS.open_dir(path)
            uid = str(path_dir.info.fs_file.meta.uid)
            gid = str(path_dir.info.fs_file.meta.gid)
            success = True
        except Exception as ex:
            log.error("Exception trying to get uid & gid for folder " + path + ' Exception details: ' + str(ex))
        return success, uid, gid

    def GetUserAndGroupIDForFile(self, path):
        '''
            Returns tuple (success, UID, GID) for file identified by path
            If failed to get values, success=False
            UID & GID are returned as strings
        '''
        if self.use_native_hfs_parser:
            return self.hfs_native.GetUserAndGroupIDForFile(path)
        success, uid, gid = False, 0, 0
        try:
            path_file = self.macos_FS.open(path)
            uid = str(path_file.info.meta.uid)
            gid = str(path_file.info.meta.gid)
            success = True
        except Exception as ex:
            log.error("Exception trying to get uid & gid for file " + path + ' Exception details: ' + str(ex))
        return success, uid, gid

    # Private (Internal) functions, plugins should not use these

    def _GetSafeFilename(self, name):
        '''
           Removes illegal characters from filenames
           Eg: Windows does not like ?<>/\:*"! in filename
        '''
        try:
            unsafe_chars = '?<>/\:*"!\r\n' if self.is_windows else '/'
            return ''.join([c for c in name if c not in unsafe_chars])
        except:
            pass
        return "_error_no_name_"

    def _IsFileCompressed(self, tsk_file):
        '''For a pytsk3 file entry, determines if a file is compressed'''
        try:
            return int(tsk_file.info.meta.flags) & pytsk3.TSK_FS_META_FLAG_COMP
        except Exception as ex:
            log.error (" Unknown exception from _IsFileCompressed() " + str(ex))
        return False

    def _GetSize(self, entry):
        '''For a pytsk3 file entry, gets logical file size, or 0 if error'''
        try:
            return entry.info.meta.size
        except Exception as ex:
            log.error (" Unknown exception from _GetSize() " + str(ex))
        return 0

    def _GetName(self, entry):
        '''Return utf8 filename from pytsk entry object'''
        try:
            return entry.info.name.name.decode("utf8", "ignore")
        except UnicodeError:
            #log.debug("UnicodeError getting name ")
            pass
        except Exception as ex:
            log.error (" Unknown exception from GetName:" + str(ex))
        return ""

    def _CheckFileContents(self, f):
        f.seek(0)
        header = f.read(4)
        if len(header) == 4 and header == b'\0\0\0\0':
            log.error('File header was zeroed out. If the source is an E01 file, this may be a libewf problem.'\
                ' Try to use a different version of libewf. Read more about this here:'\
                ' https://github.com/ydkhatri/mac_apt/wiki/Known-issues-and-Workarounds')

    def _IsValidFileOrFolderEntry(self, entry):
        try:
            if entry.info.name.type == pytsk3.TSK_FS_NAME_TYPE_REG:
                return True
            elif entry.info.name.type == pytsk3.TSK_FS_NAME_TYPE_DIR:
                return True
            else:
                log.warning(" Found invalid entry - " + self._GetName(entry) + "  " + str(entry.info.name.type) )
        except Exception:
            log.error(" Unknown exception from _IsValidFileOrFolderEntry:" + self._GetName(entry))
            log.debug("Exception details:\n", exc_info=True)
        return False

    def _GetDomainUserInfo(self):
        '''Populates self.users with data from /Users/'''
        log.debug('Trying to get domain profiles from /Users/')
        users_folder = self.ListItemsInFolder('/Users/', EntryType.FOLDERS)
        for folder in users_folder:
            folder_path = '/Users/' + folder['name']
            success, uid, gid = self.GetUserAndGroupIDForFolder(folder_path)
            if success:
                found_user = False
                for user in self.users:
                    if user.UID == uid:
                        found_user = True
                        break
                if found_user: continue
                else:
                    target_user = UserInfo()
                    self.users.append(target_user)
                    target_user.UID = uid
                    target_user.GID = gid
                    #target_user.UUID = unknown
                    target_user.home_dir = folder_path
                    target_user.user_name = folder['name']
                    target_user.real_name = folder['name']
                    target_user._source = folder_path

    def _ReadPasswordPolicyData(self, password_policy_data, target_user):
        f = BytesIO(password_policy_data[0])
        success, plist2, error = CommonFunctions.ReadPlist(f)
        if success:
            target_user.failed_login_count = plist2.get('failedLoginCount', 0)
            target_user.failed_login_timestamp = plist2.get('failedLoginTimestamp', None)
            target_user.last_login_timestamp = plist2.get('lastLoginTimestamp', None)
            target_user.password_last_set_time = plist2.get('passwordLastSetTime', None)
        else:
            log.exception(f'Error reading password_policy_data embedded plist for user {target_user}')

    def _ReadAccountPolicyData(self, account_policy_data, target_user):
        f = BytesIO(account_policy_data[0])
        success, plist2, error = CommonFunctions.ReadPlist(f)
        if success:
            target_user.creation_time = CommonFunctions.ReadUnixTime(plist2.get('creationTime', None))
            target_user.failed_login_count = plist2.get('failedLoginCount', 0)
            target_user.failed_login_timestamp = CommonFunctions.ReadUnixTime(plist2.get('failedLoginTimestamp', None))
            target_user.password_last_set_time = CommonFunctions.ReadUnixTime(plist2.get('passwordLastSetTime', None))
        else:
            log.exception(f'Error reading password_policy_data embedded plist for user {target_user}')

    def _GetUserInfo(self):
        '''Populates user info from plists under: /private/var/db/dslocal/nodes/Default/users/'''
        #TODO - make a better plugin that gets all user & group info
        users_path  = '/private/var/db/dslocal/nodes/Default/users'
        user_plists = self.ListItemsInFolder(users_path, EntryType.FILES)
        for plist_meta in user_plists:
            if plist_meta['size'] > 0:
                try:
                    user_plist_path = users_path + '/' + plist_meta['name']
                    f = self.Open(user_plist_path)
                    if f!= None:
                        self.ExportFile(user_plist_path, 'USERS', '', False)
                        success, plist, error = CommonFunctions.ReadPlist(f)
                        if success:
                            home_dir = self.GetArrayFirstElement(plist.get('home', ''))
                            if home_dir != '':
                                #log.info('{} :  {}'.format(plist_meta['name'], home_dir))
                                if home_dir.startswith('/var/'): home_dir = '/private' + home_dir # in mac /var is symbolic link to /private/var
                                target_user = UserInfo()
                                self.users.append(target_user)
                                target_user.UID = str(self.GetArrayFirstElement(plist.get('uid', '')))
                                target_user.GID = str(self.GetArrayFirstElement(plist.get('gid', '')))
                                target_user.UUID = self.GetArrayFirstElement(plist.get('generateduid', ''))
                                target_user.home_dir = home_dir
                                target_user.user_name = self.GetArrayFirstElement(plist.get('name', ''))
                                target_user.real_name = self.GetArrayFirstElement(plist.get('realname', ''))
                                target_user.pw_hint = self.GetArrayFirstElement(plist.get('hint', ''))
                                target_user._source = user_plist_path
                                os_version = self.GetVersionDictionary()
                                if os_version['major'] == 10 and os_version['minor'] <= 9: # Mavericks & earlier
                                    password_policy_data = plist.get('passwordpolicyoptions', None)
                                    if password_policy_data == None:
                                        log.debug('Could not find passwordpolicyoptions for user {}'.format(target_user.user_name))
                                    else:
                                        self._ReadPasswordPolicyData(password_policy_data, target_user)
                                else: # 10.10 - Yosemite & higher
                                    account_policy_data = plist.get('accountPolicyData', None)
                                    if account_policy_data == None: 
                                        pass #log.debug('Could not find accountPolicyData for user {}'.format(target_user.user_name))
                                    else:
                                        self._ReadAccountPolicyData(account_policy_data, target_user)
                            else:
                                log.error('Did not find \'home\' in ' + plist_meta['name'])
                        else:
                            log.error("failed to read plist " + user_plist_path + " Error was : " + error)
                            self._CheckFileContents(f)
                        f.close()
                except (OSError, KeyError, ValueError, IndexError, TypeError):
                    log.exception ("Could not open/read plist " + user_plist_path)
        if len(user_plists) == 0:
            # Could not retrieve user plists, let's at least add root user
            # other users will be retieved from /Users folder by _GetDomainUserInfo()
            if self.IsValidFolderPath('/private/var/root'):
                target_user = UserInfo()
                self.users.append(target_user)
                target_user.UID = '0'
                target_user.GID = '0'
                target_user.UUID = 'FFFFEEEE-DDDD-CCCC-BBBB-AAAA00000000'
                target_user.home_dir = '/private/var/root'
                target_user.user_name = 'root'
                target_user.real_name = 'System Administrator'
                target_user.DARWIN_USER_DIR = '/private/var/folders/zz/zyxvpxvq6csfxvn_n0000000000000/0'
                target_user.DARWIN_USER_TEMP_DIR = '/private/var/folders/zz/zyxvpxvq6csfxvn_n0000000000000/T'
                target_user.DARWIN_USER_CACHE_DIR = '/private/var/folders/zz/zyxvpxvq6csfxvn_n0000000000000/C'
        self._GetDomainUserInfo()
        self._GetDarwinFoldersInfo() # This probably does not apply to OSX < Mavericks !

    def _GetDarwinFoldersInfo(self):
        '''Gets DARWIN_*_DIR paths by looking up folder permissions'''
        users_dir = self.ListItemsInFolder('/private/var/folders', EntryType.FOLDERS)
        for unknown1 in users_dir:
            unknown1_name = unknown1['name']
            unknown1_dir = self.ListItemsInFolder('/private/var/folders/' + unknown1_name, EntryType.FOLDERS)
            for unknown2 in unknown1_dir:
                unknown2_name = unknown2['name']
                path = '/private/var/folders/' + unknown1_name + "/" + unknown2_name

                success, uid, gid = self.GetUserAndGroupIDForFolder(path)
                #log.debug(f'UID={uid} GID={gid} DARWIN FOLDER={path}')
                if success:
                    found_user = False
                    for user in self.users:
                        if user.UID == uid:
                            if user.DARWIN_USER_DIR: 
                                log.warning('There is already a value in DARWIN_USER_DIR {}'.format(user.DARWIN_USER_DIR))
                                #Sometimes (rare), if UUID changes, there may be another folder upon restart for DARWIN_USER, we will just concatenate with comma. If you see this, it is more likely that another user with same UID existed prior.
                                user.DARWIN_USER_DIR       += ',' + path + '/0'
                                user.DARWIN_USER_CACHE_DIR += ',' + path + '/C'
                                user.DARWIN_USER_TEMP_DIR  += ',' + path + '/T'
                            else:
                                user.DARWIN_USER_DIR       = path + '/0'
                                user.DARWIN_USER_CACHE_DIR = path + '/C'
                                user.DARWIN_USER_TEMP_DIR  = path + '/T'
                            found_user = True
                            break
                    if not found_user:
                        log.error('Could not find username for UID={} GID={} PATH={}'.format(uid, gid, path))

    def _GetSystemInfo(self):
        ''' Gets system version information'''
        try:
            log.debug("Trying to get system version from /System/Library/CoreServices/SystemVersion.plist")
            f = self.Open('/System/Library/CoreServices/SystemVersion.plist')
            if f != None:
                success, plist, error = CommonFunctions.ReadPlist(f)
                if success:
                    self.os_version = plist.get('ProductVersion', '')
                    self.os_build = plist.get('ProductBuildVersion', '')
                    if self.os_version != '':
                        if   self.os_version.startswith('10.10'): self.os_friendly_name = 'Yosemite'
                        elif self.os_version.startswith('10.11'): self.os_friendly_name = 'El Capitan'
                        elif self.os_version.startswith('10.12'): self.os_friendly_name = 'Sierra'
                        elif self.os_version.startswith('10.13'): self.os_friendly_name = 'High Sierra'
                        elif self.os_version.startswith('10.14'): self.os_friendly_name = 'Mojave'
                        elif self.os_version.startswith('10.15'): self.os_friendly_name = 'Catalina'
                        elif self.os_version.startswith('10.16'): self.os_friendly_name = 'Big Sur Beta'
                        elif self.os_version.startswith('10.0'): self.os_friendly_name = 'Cheetah'
                        elif self.os_version.startswith('10.1'): self.os_friendly_name = 'Puma'
                        elif self.os_version.startswith('10.2'): self.os_friendly_name = 'Jaguar'
                        elif self.os_version.startswith('10.3'): self.os_friendly_name = 'Panther'
                        elif self.os_version.startswith('10.4'): self.os_friendly_name = 'Tiger'
                        elif self.os_version.startswith('10.5'): self.os_friendly_name = 'Leopard'
                        elif self.os_version.startswith('10.6'): self.os_friendly_name = 'Snow Leopard'
                        elif self.os_version.startswith('10.7'): self.os_friendly_name = 'Lion'
                        elif self.os_version.startswith('10.8'): self.os_friendly_name = 'Mountain Lion'
                        elif self.os_version.startswith('10.9'): self.os_friendly_name = 'Mavericks'
                        elif self.os_version.startswith('11.'): self.os_friendly_name = 'Big Sur'
                        elif self.os_version.startswith('12.'): self.os_friendly_name = 'Monterey'
                        elif self.os_version.startswith('13.'): self.os_friendly_name = 'Ventura'
                        elif self.os_version.startswith('14.'): self.os_friendly_name = 'Sonoma'
                        else: self.os_friendly_name = 'Unknown version!'
                    log.info ('macOS version detected is: {} ({}) Build={}'.format(self.os_friendly_name, self.os_version, self.os_build))
                    f.close()
                    return True
                else:
                    log.error("Could not get ProductVersion from plist. Is it a valid xml plist? Error=" + error)
                f.close()
            else:
                log.error("Could not open plist to get system version info!")
        except:
            log.exception("Unknown error from _GetSystemInfo()")
        return False

class ApfsMacInfo(MacInfo):
    def __init__(self, output_params, password, dont_decrypt):
        super().__init__(output_params, password, dont_decrypt)
        self.apfs_container = None
        self.apfs_db = None
        self.apfs_db_path = ''
        self.apfs_sys_volume = None  # New in 10.15, a System read-only partition
        self.apfs_data_volume = None # New in 10.15, a separate Data partition
        self.apfs_preboot_volume = None # In macOS 13, it's loaded while running
        self.apfs_update_volume = None  # In macOS 13, it's loaded while running

    def UseCombinedVolume(self):
        self.macos_FS = ApfsSysDataLinkedVolume(self.apfs_sys_volume, self.apfs_data_volume)

    def CreateCombinedVolume(self):
        '''Returns True/False depending on whether system & data volumes could be combined successfully'''
        try:
            self.macos_FS = ApfsSysDataLinkedVolume(self.apfs_sys_volume, self.apfs_data_volume)
            apfs_parser = ApfsFileSystemParser(self.macos_FS, self.apfs_db)
            return apfs_parser.create_linked_volume_tables(self.apfs_sys_volume, self.apfs_data_volume, self.macos_FS.firmlinks_paths, self.macos_FS.firmlinks)
        except (ValueError, TypeError) as ex:
            log.exception('')
        log.error('Failed to create combined System + Data volume')
        return False

    def _GetSystemInfo(self):
        info = MacInfo._GetSystemInfo(self)
        if self.GetVersionDictionary()['major'] >= 13:
            # Get Rapid Security Response patch info, new in macOS 13 (Ventura)
            uuid = ''
            update_plist_path = '/nvram.plist'
            log.debug(f"Trying to read RSR related UUID from {update_plist_path}")
            if self.apfs_update_volume is None:
                log.info('No Update volume found!')
                return info
            f = self.apfs_update_volume.open(update_plist_path)
            if f != None:
                success, plist, error = CommonFunctions.ReadPlist(f)
                if success:
                    efi_boot_device = plist.get('efi-boot-device', '')
                    #if efi_boot_device:
                    #    plistlib.loads()
                    matches = re.search(r"\<key\>Path\<\/key\>\<string\>\\([^\\]+)\\", efi_boot_device)
                    if matches:
                        uuid = matches.group(1)
                    else:
                        log.warning(f"No UUID found for RSR, efi_boot_device info = {efi_boot_device}")
                    f.close()
                else:
                    log.error("Could not read plist. Error=" + error)
                f.close()
            else:
                log.error("Could not open plist to get system version info!")
                return info
            
            preboot_plist_path = f'/{uuid}/cryptex1/current/SystemVersion.plist'
            log.debug(f"Trying to get RSR patch version from {preboot_plist_path}")
            f = self.apfs_preboot_volume.open(preboot_plist_path)
            if f != None:
                success, plist, error = CommonFunctions.ReadPlist(f)
                if success:
                    self.os_version_extra = plist.get('ProductVersionExtra', '')
                    self.os_version = plist.get('ProductVersion', self.os_version)
                    self.os_build = plist.get('ProductBuildVersion', self.os_build)
                    log.info (f'macOS RSR patch version detected is: {self.os_version} {self.os_version_extra}')
                    f.close()
                else:
                    log.error("Could not read plist. Error=" + error)
                f.close()
            else:
                log.error("Could not open plist to get system version info!")
        return info

    def ReadApfsVolumes(self):
        '''Read volume information into an sqlite db'''
        decryption_key = None
        # Process Preboot volume first
        preboot_vol = self.apfs_container.preboot_volume
        if preboot_vol:
            apfs_parser = ApfsFileSystemParser(preboot_vol, self.apfs_db)
            apfs_parser.read_volume_records()
            preboot_vol.dbo = self.apfs_db
        # Process other volumes now
        for vol in self.apfs_container.volumes:
            vol.dbo = self.apfs_db
            if vol == preboot_vol:
                continue
            elif vol.is_encrypted and self.apfs_container.is_sw_encrypted and (not self.dont_decrypt): # For hardware encryption(T2), do nothing, it should have been acquired as decrypted..
                if self.password == '':
                    log.error(f'Skipping vol {vol.volume_name}. The vol is ENCRYPTED and user did not specify a password to decrypt it!' +
                                f' If you know the password, run mac_apt again with the -p option to decrypt this volume.')
                    continue

                uuid_folders = []
                preboot_dir = preboot_vol.ListItemsInFolder('/')
                for items in preboot_dir:
                    if len(items['name']) == 36: # UUID Named folder
                        if items['name'] != "00000000-0000-0000-0000-000000000000":
                            uuid_folders.append(items['name'])
                if len(uuid_folders) == 0:
                    log.error("There are no UUID like folders in the Preboot volume! Decryption cannot continue")
                else:
                    if len(uuid_folders) > 1:
                        log.warning("There are more than 1 UUID like folders:\n" + str(uuid_folders))
                    index = 1
                    num_uuid_folders = len(uuid_folders)
                    for uuid_folder in uuid_folders:
                        plist_path = uuid_folder +  "/var/db/CryptoUserInfo.plist"
                        if preboot_vol.DoesFileExist(plist_path):
                            plist_f = preboot_vol.open(plist_path)
                            success, plist, error = CommonFunctions.ReadPlist(plist_f)
                            if success:
                                decryption_key = decryptor.EncryptedVol(vol, plist, self.password).decryption_key
                                if decryption_key is None:
                                    if index < num_uuid_folders:
                                        continue
                                    log.error(f"No decryption key found. Did you enter the right password? Volume '{vol.volume_name}' cannot be decrypted! " + \
                                        "If the password contains special chars like ^ or \ or / use the password file option (-pf) instead.")
                                    if vol.role == vol.container.apfs.VolumeRoleType.data.value:
                                        sys.exit('Decryption failed for DATA volume, cannot proceed!')
                                else:
                                    log.debug(f"Starting decryption of filesystem, VEK={decryption_key.hex().upper()}")
                                    vol.encryption_key = decryption_key
                                    apfs_parser = ApfsFileSystemParser(vol, self.apfs_db)
                                    apfs_parser.read_volume_records()
                                    break
                            else:
                                log.error(f"Failed to read {plist_path}. Error was : {error}")
                        index += 1
            else:
                apfs_parser = ApfsFileSystemParser(vol, self.apfs_db)
                apfs_parser.read_volume_records()

    def GetFileMACTimes(self, file_path):
        '''Gets MACB and the 5th Index timestamp too'''
        times = { 'c_time':None, 'm_time':None, 'cr_time':None, 'a_time':None, 'i_time':None }
        try:
            apfs_file_meta = self.macos_FS.GetApfsFileMeta(file_path)
            if apfs_file_meta:
                times['c_time'] = apfs_file_meta.changed
                times['m_time'] = apfs_file_meta.modified
                times['cr_time'] = apfs_file_meta.created
                times['a_time'] = apfs_file_meta.accessed
                times['i_time'] = apfs_file_meta.date_added
            else:
                log.debug('File not found in GetFileMACTimes() query!, path was ' + file_path)
        except Exception as ex:
            log.exception('Error trying to get MAC times')
        return times

    def IsSymbolicLink(self, path):
        return self.macos_FS.IsSymbolicLink(path)

    def IsValidFilePath(self, path):
        return self.macos_FS.DoesFileExist(path)

    def IsValidFolderPath(self, path):
        return self.macos_FS.DoesFolderExist(path)

    def GetExtendedAttribute(self, path, att_name):
        return self.macos_FS.GetExtendedAttribute(path, att_name)

    def GetExtendedAttributes(self, path):
        xattrs = {}
        apfs_xattrs = self.macos_FS.GetExtendedAttributes(path)
        return { att_name:att.data for att_name,att in apfs_xattrs.items() }

    def GetFileSize(self, full_path, error=None):
        try:
            apfs_file_meta = self.macos_FS.GetFileMetadataByPath(full_path)
            if apfs_file_meta:
                return apfs_file_meta.logical_size
        except Exception as ex:
            log.debug ("APFSMacInfo->Exception from GetFileSize() " + str(ex))
        return error

    def Open(self, path):
        '''Open file and return a file-like object'''
        return self.macos_FS.open(path)

    def ExtractFile(self, tsk_path, destination_path):
        return self.macos_FS.CopyOutFile(tsk_path, destination_path)

    def _GetSize(self, entry):
        '''For file entry, gets logical file size, or 0 if error'''
        try:
            apfs_file_meta = self.macos_FS.GetFileMetadataByPath(path)
            if apfs_file_meta:
                return apfs_file_meta.logical_size
        except:
            pass
        return 0

    def GetUserAndGroupIDForFile(self, path):
        return self._GetUserAndGroupID(path)

    def GetUserAndGroupIDForFolder(self, path):
        return self._GetUserAndGroupID(path)

    def _GetUserAndGroupID(self, path):
        '''
            Returns tuple (success, UID, GID) for file/folder identified by path
            If failed to get values, success=False
            UID & GID are returned as strings
        '''
        success, uid, gid = False, 0, 0
        apfs_file_meta = self.macos_FS.GetFileMetadataByPath(path)
        if apfs_file_meta:
            uid = str(apfs_file_meta.uid)
            gid = str(apfs_file_meta.gid)
            success = True
        else:
            log.debug("Path not found in database (filesystem) : " + path)
        return success, uid, gid

    def ListItemsInFolder(self, path='/', types_to_fetch=EntryType.FILES_AND_FOLDERS, include_dates=False):
        '''Always returns dates ignoring the 'include_dates' parameter'''
        items = []
        all_items = self.macos_FS.ListItemsInFolder(path)
        if all_items:
            if types_to_fetch == EntryType.FILES_AND_FOLDERS:
                items = [] #[dict(x) for x in all_items if x['type'] in ['File', 'Folder'] ]
                for x in all_items:
                    if x['type'] in ('File', 'SymLink'):
                        x['type'] = EntryType.FILES
                        items.append(dict(x))
                    elif x['type'] == 'Folder':
                        x['type'] = EntryType.FOLDERS
                        items.append(dict(x))

            elif types_to_fetch == EntryType.FILES:
                for x in all_items:
                    if x['type'] in ('File', 'SymLink'):
                        x['type'] = EntryType.FILES
                        items.append(dict(x))
            else: # Folders
                for x in all_items:
                    if x['type'] == 'Folder':
                        x['type'] = EntryType.FOLDERS
                        items.append(dict(x))
        return items

class MountedFile():
    # This class is a file-like object, its existence is due to
    # Xways Forensics bug with reading mounted files, which can't
    # handle f.read() , only f.read(size) works and size must not
    # go beyond end of file. This class ensures that part.
    def __init__(self):
        self.pos = 0
        self.size = 0
        self._file = None
        self.closed = True

    def _check_closed(self):
        if self.closed:
            raise ValueError("File is closed!")

    # file methods
    def open(self, file_path, mode='rb'):
        self.size = os.path.getsize(file_path)
        self._file  = open(file_path, mode)
        self.closed = False
        return self

    def close(self):
        self.closed = True
        if self._file:
            self._file.close()

    def tell(self):
        return self.pos

    def seek(self, offset, whence=0):
        if self.closed:
            raise ValueError("seek of closed file")
        self._file.seek(offset, whence)
        self.pos = self._file.tell()

    def __iter__(self):
        return self

    def __next__(self):
        line = self.readline()
        if len(line) == 0:
            raise StopIteration
        return line

    def readline(self, size=None):
        ret = b''
        original_file_pos = self.tell()
        stop_at_one_iteration = True
        lf_found = False
        if size == None:
            stop_at_one_iteration = False
            size = 1024
        buffer = self.read(size)
        while buffer:
            new_line_pos = buffer.find(b'\n')
            if new_line_pos == -1: # not_found, add to line
                ret += buffer
            else:
                ret += buffer[0:new_line_pos + 1]
                lf_found = True
            self.seek(original_file_pos + len(ret))

            if stop_at_one_iteration or lf_found: break
            buffer = self.read(size)
        return ret

    def readlines(self, sizehint=None):
        lines = []
        line = self.readline()
        while line:
            lines.append(line)
            line = self.readline()
        return lines

    def read(self, size_to_read=None):
        if self.closed:
            raise ValueError("read of closed file")
        data = b''
        if size_to_read == None:
            size_to_read = self.size - self.pos
            if size_to_read > 0:
                data = self._file.read(size_to_read)
                self.pos += len(data)
        elif self.pos >= self.size: # at or beyond EOF, nothing to read
            pass
        else:
            end_pos = self.pos + size_to_read
            if end_pos > self.size:
                size_to_read = self.size - self.pos
            if size_to_read > 0:
                data = self._file.read(size_to_read)
                self.pos += len(data)
        return data

# TODO: Make this class more efficient, perhaps remove some extractions!
class MountedMacInfo(MacInfo):
    def __init__(self, root_folder_path, output_params):
        super().__init__(output_params)
        self.macos_root_folder = root_folder_path
        # TODO: if os.name == 'nt' and len (root_folder_path) == 2 and root_folder_path[2] == ':': self.macos_root_folder += '\\'
        if self.is_linux:
            log.warning('Since this is a linux (mounted) system, there is no way for python to extract created_date timestamps. '\
                        'This is a limitation of Python. Created timestamps shown/seen will actually be same as Last_Modified timestamps.')

    def BuildFullPath(self, path_in_image):
        '''
        Takes path inside image as input and returns the full path on current volume
        Eg: Image mounted at D:\Images\mac_osx\  Path=\etc\hosts  Return= D:\Images\mac_osx\etc\hosts
        '''
        full_path = ''
        path = path_in_image
        # remove leading / for os.path.join()
        if path != '/' and path.startswith('/'):
            path = path[1:]
        if self.is_windows:
            path = path.replace('/', '\\')
        try:
            full_path = os.path.join(self.macos_root_folder, path)
        except Exception:
            log.error("Exception in BuildFullPath(), path was " + path_in_image)
            log.exception("Exception details")
        #log.debug("req={} final={}".format(path_in_image, full_path))
        return full_path

    def _get_creation_time(self, local_path):
        if self.is_windows:
            return CommonFunctions.ReadUnixTime(os.path.getctime(local_path))
        elif self.is_linux:
            try:
                t = statx(local_path).get_btime() # New Linux kernel 4+ has this ability
            except (OSError, ValueError) as ex:
                t = 0 # Old linux kernel that does not support statx
            if t != 0:
                return CommonFunctions.ReadUnixTime(t)
            else: # Either old linux or a version of FUSE that does not populates btime (current does not)!
                return CommonFunctions.ReadUnixTime(os.path.getmtime(local_path)) # Since this is not possible to fetch in Linux (using python)!
        else:
            return CommonFunctions.ReadUnixTime(os.stat(local_path).st_birthtime)

    def GetFileMACTimes(self, file_path):
        file_path = self.BuildFullPath(file_path)
        times = { 'c_time':None, 'm_time':None, 'cr_time':None, 'a_time':None }
        try:
            times['c_time'] = None if self.is_windows else CommonFunctions.ReadUnixTime(os.path.getctime(file_path))
            times['m_time'] = CommonFunctions.ReadUnixTime(os.path.getmtime(file_path))
            times['cr_time'] = self._get_creation_time(file_path)
            times['a_time'] = CommonFunctions.ReadUnixTime(os.path.getatime(file_path))
        except OSError as ex:
            log.exception('Error trying to get MAC times')
        return times

    def IsSymbolicLink(self, path):
        try:
            return os.path.islink(self.BuildFullPath(path))
        except OSError as ex:
            log.exception("Exception in IsSymbolicLink() for path : {} " + path)
        return False

    def IsValidFilePath(self, path):
        ### FOR DEBUG ONLY
        if path.find('\\') >= 0:
            log.warning(f'In MountedMacInfo::IsValidFilePath(), found \\ in path: {path}')
        ###
        try:
            return os.path.lexists(self.BuildFullPath(path)) 
        except OSError as ex:
            log.exception("Exception in IsValidFilePath() for path : {} " + path)
        return False

    def IsValidFolderPath(self, path):
        return self.IsValidFilePath(path)

    def _GetFileSizeNoPathMod(self, full_path, error=None):
        '''Simply calls os.path.getsize(), BEWARE-does not build full path!'''
        try:
            return os.path.getsize(full_path)
        except OSError as ex:
            log.error("Exception in _GetFileSizeNoPathMod() : " + str(ex))
        return error

    def GetFileSize(self, full_path, error=None):
        '''Builds full path, then gets size'''
        try:
            return os.path.getsize(self.BuildFullPath(full_path))
        except OSError as ex:
            log.debug("Exception in GetFileSize() : " + str(ex) + " Perhaps file does not exist: " + full_path)
        return error

    def GetUserAndGroupIDForFile(self, path):
        return self._GetUserAndGroupID(self.BuildFullPath(path))

    def GetUserAndGroupIDForFolder(self, path):
        return self._GetUserAndGroupID(self.BuildFullPath(path))

    def ListItemsInFolder(self, path='/', types_to_fetch=EntryType.FILES_AND_FOLDERS, include_dates=False):
        '''
        Returns a list of files and/or folders in a list
        Format of list = [ {'name':'got.txt', 'type':EntryType.FILES, 'size':10}, .. ]
        'path' should be linux style using forward-slash like '/var/db/xxyy/file.tdc'
        and starting at root /
        '''
        items = [] # List of dictionaries
        try:
            mounted_path = self.BuildFullPath(path)
            dir = os.listdir(mounted_path)
            for entry in dir:
                # Exclude the mounted encase <file>.Stream which is uncompressed stream of file,
                #  not needed as we have the actual file
                if entry.find('\xB7Stream') >= 0 or entry.find('\xB7Resource') >= 0:
                    log.debug(f'Excluding {entry} as it is raw stream not FILE. If you think this should be included, let the developers know!')
                    continue
                newpath = os.path.join(mounted_path, entry)
                entry_type = EntryType.FOLDERS if os.path.isdir(newpath) else EntryType.FILES
                item = { 'name':entry, 'type':entry_type, 'size':self._GetFileSizeNoPathMod(newpath, 0)}
                if include_dates: 
                    item['dates'] = self.GetFileMACTimes(path + '/' + entry)
                if types_to_fetch == EntryType.FILES_AND_FOLDERS:
                    items.append( item )
                elif types_to_fetch == EntryType.FILES and entry_type == EntryType.FILES:
                    items.append( item )
                elif types_to_fetch == EntryType.FOLDERS and entry_type == EntryType.FOLDERS:
                    items.append( item )
        except FileNotFoundError as ex:
            if str(ex).find('There are no more files') >= 0: # known windows issue on some empty folders!! '[WinError 18] There are no more files:...'
                pass
            else:
                log.debug("Path not found : " + mounted_path)
        except Exception as ex:
            log.exception('')
            if str(ex).find('cannot find the path specified'):
                log.debug("Path not found : " + mounted_path)
            else:
                log.debug("Problem accessing path : " + mounted_path)
                log.debug("Exception details:\n", exc_info=True)
                log.error("Failed to get dir info!")
        return items

    def ReadSymLinkTargetPath(self, path):
        '''Returns the target file/folder's path from the sym link path provided'''
        target_path = ''
        try:
            if not self.is_windows:
                target_path = os.readlink(self.BuildFullPath(path))
            else:
                target_path = super().ReadSymLinkTargetPath(path)
        except:
            log.exception("Error resolving symlink : " + path)
        return target_path

    def Open(self, path):
        try:
            mounted_path = self.BuildFullPath(path)
            log.debug("Trying to open file : " + mounted_path)
            file = MountedFile().open(mounted_path, 'rb')
            return file
        except (OSError) as ex:
            log.exception("Error opening file : " + mounted_path)
        return None

    def ExtractFile(self, path_in_image, destination_path):
        source_file = self.Open(path_in_image)
        if source_file:
            size = self.GetFileSize(path_in_image)

            BUFF_SIZE = 20 * 1024 * 1024
            offset = 0
            try:
                with open(destination_path, 'wb') as f:
                    while offset < size:
                        available_to_read = min(BUFF_SIZE, size - offset)
                        data = source_file.read(available_to_read)
                        if not data: break
                        offset += len(data)
                        f.write(data)
                    f.flush()
            except (OSError) as ex:
                log.exception ("Failed to create file for writing at " + destination_path)
                source_file.close()
                return False
            source_file.close()
            return True
        return False

    def _GetUserAndGroupID(self, path):
        '''
            Returns tuple (success, UID, GID) for object identified by path.
            UID & GID are returned as strings.
            If failed to get values, success=False
        '''
        success, uid, gid = False, 0, 0
        try:
            stat = os.stat(path)
            uid = str(CommonFunctions.convert_32bit_num_to_signed(stat.st_uid))
            gid = str(CommonFunctions.convert_32bit_num_to_signed(stat.st_gid))
            success = True
        except (OSError, ValueError) as ex:
            log.error("Exception trying to get uid & gid for file " + path + ' Exception details: ' + str(ex))
        return success, uid, gid

    def _GetDarwinFoldersInfo(self):
        '''Gets DARWIN_*_DIR paths '''
        if not self.is_windows:
            # Unix/Linux or Mac mounted disks should preserve UID/GID, so we can read it normally from the files.
            super()._GetDarwinFoldersInfo()
            return

        for user in self.users:
            if user.UUID != '' and user.UID not in ('', '-2', '1', '201'): # Users nobody, daemon, guest don't have one
                darwin_path = '/private/var/folders/' + GetDarwinPath2(user.UUID, user.UID)
                if not self.IsValidFolderPath(darwin_path):
                    darwin_path = '/private/var/folders/' + GetDarwinPath(user.UUID, user.UID)
                    if not self.IsValidFolderPath(darwin_path):
                        if user.user_name.startswith('_') and user.UUID.upper().startswith('FFFFEEEE'):
                            pass
                        else:
                            log.warning(f'Could not find DARWIN_PATH for user {user.user_name}, uid={user.UID}, uuid={user.UUID}')
                        continue
                user.DARWIN_USER_DIR       = darwin_path + '/0'
                user.DARWIN_USER_CACHE_DIR = darwin_path + '/C'
                user.DARWIN_USER_TEMP_DIR  = darwin_path + '/T'

    def _GetDomainUserInfo(self):
        if not self.is_windows:
            # Unix/Linux or Mac mounted disks should preserve UID/GID, so we can read it normally from the files.
            super()._GetDomainUserInfo()
            return
        log.debug('Trying to get domain profiles from /Users/')
        domain_users = []
        users_folder = self.ListItemsInFolder('/Users/', EntryType.FOLDERS)
        for folder in users_folder:
            folder_name = folder['name']
            if folder_name in ('Shared', 'root'):
                continue
            found_user = False
            for user in self.users:
                if user.user_name == folder_name:
                    found_user = True # Existing local user
                    break
            if found_user: continue
            else:
                log.info(f'Found a domain user {folder_name} or deleted user?')
                target_user = UserInfo()
                domain_users.append(target_user)
                target_user.home_dir = '/Users/' + folder_name
                target_user.user_name = folder_name
                target_user.real_name = folder_name
                target_user._source = '/Users/' + folder_name
        if domain_users:
            known_darwin_paths = set()
            for user in self.users:
                if user.UID and user.UUID and not user.UID.startswith('-'):
                    known_darwin_paths.add('/private/var/folders/' + GetDarwinPath(user.UUID, user.UID)) # They haven't been populated yet in user!
                    known_darwin_paths.add('/private/var/folders/' + GetDarwinPath2(user.UUID, user.UID))
            # try to get darwin_cache folders
            var_folders = self.ListItemsInFolder('/private/var/folders', EntryType.FOLDERS)
            for level_1 in var_folders:
                name_1 = level_1['name']
                var_folders_level_2 = self.ListItemsInFolder(f'/private/var/folders/{name_1}', EntryType.FOLDERS)
                for level_2 in var_folders_level_2:
                    darwin_path = f'/private/var/folders/{name_1}/' + level_2['name']
                    if darwin_path in known_darwin_paths:
                        continue
                    else:
                        matched_darwin_path_to_user = False
                        font_reg_db = darwin_path + '/C/com.apple.FontRegistry/fontregistry.user'
                        if self.IsValidFilePath(font_reg_db):
                            try:
                                sqlite_wrapper = SqliteWrapper(self)
                                db = sqlite_wrapper.connect(font_reg_db)
                                if db:
                                    cursor = db.cursor()
                                    cursor.execute('SELECT path_column from dir_table WHERE domain_column=1')
                                    user_path = ''
                                    for row in cursor:
                                        user_path = row[0]
                                        break
                                    cursor.close()
                                    db.close()
                                    if user_path:
                                        if user_path.startswith('/Users/'):
                                            username = user_path.split('/')[2]
                                            for dom_user in domain_users:
                                                if dom_user.user_name == username:
                                                    dom_user.DARWIN_USER_DIR = darwin_path + '/0'
                                                    dom_user.DARWIN_USER_TEMP_DIR = darwin_path + '/T'
                                                    dom_user.DARWIN_USER_CACHE_DIR = darwin_path + '/C'
                                                    log.debug(f'Found darwin path for user {username}')
                                                    matched_darwin_path_to_user = True
                                                    # Try to get uid now.
                                                    if self.IsValidFolderPath(dom_user.DARWIN_USER_DIR + '/com.apple.LaunchServices.dv'):
                                                        for item in self.ListItemsInFolder(dom_user.DARWIN_USER_DIR + '/com.apple.LaunchServices.dv', EntryType.FILES):
                                                            name = item['name']
                                                            if name.startswith('com.apple.LaunchServices.trustedsignatures-') and name.endswith('.db'):
                                                                dom_user.UID = name[43:-3]
                                                                break
                                                    break
                                        else:
                                            log.error(f'user profile path was non-standard - {user_path}')
                                    else:
                                        log.error('Query did not yield any output!')
                                    if not matched_darwin_path_to_user:
                                        log.error(f'Could not find mapping for darwin folder {darwin_path} to user')
                            except sqlite3.Error:
                                log.exception(f'Error reading {font_reg_db}, Cannot map darwin folder to user profile!')
                        else:
                            log.error(f'Could not find {font_reg_db}, Cannot map darwin folder to user profile!')
            self.users.extend(domain_users)

class MountedMacInfoSeperateSysData(MountedMacInfo):
    '''Same as MountedMacInfo, but takes into account two volumes (SYS, DATA) mounted separately'''

    def __init__(self, sys_root_folder_path, data_root_folder_path, output_params):
        super().__init__(sys_root_folder_path, output_params)
        self.sys_volume_folder = sys_root_folder_path  # New in 10.15, a System read-only partition
        self.data_volume_folder = data_root_folder_path # New in 10.15, a separate Data partition
        self.firmlinks = {}
        self.firmlinks_paths =[]
        self.max_firmlink_depth = 0
        self._ParseFirmlinks()

    def _ParseFirmlinks(self):
        '''Read the firmlink path mappings between System & Data volumes'''
        firmlink_file_path = '/usr/share/firmlinks'
        try:
            mounted_path = super().BuildFullPath(firmlink_file_path)
            log.debug("Trying to open file : " + mounted_path)
            f = open(mounted_path, 'rb')
        except (OSError) as ex:
            log.exception("Error opening file : " + mounted_path)
            raise ValueError('Fatal : Could not find/read Firmlinks file in System volume!')

        data = [x.decode('utf8') for x in f.read().split(b'\n')]
        for item in data:
            if item:
                source, dest = item.split('\t')
                self.firmlinks[source] = dest
                self.firmlinks_paths.append(source)
                depth = len(source[1:].split('/'))
                if depth > self.max_firmlink_depth: self.max_firmlink_depth = depth
                if source[1:] != dest:
                    # Maybe this is the Beta version of Catalina, try prefix 'Device'
                    if dest.startswith('Device/'):
                        self.firmlinks[source] = dest[7:]
                    else:
                        log.warning("Firmlink not handled : Source='{}' Dest='{}'".format(source, dest))
        #add one for /System/Volumes/Data  /
        self.firmlinks['/System/Volumes/Data'] = ''
        self.firmlinks_paths.append('/System/Volumes/Data')
        f.close()

    def BuildFullPath(self, path_in_image):
        '''
        Takes path inside image as input and returns the full path on current volume
        Eg: Image mounted at D:\Images\mac_osx\  Path=\etc\hosts  Return= D:\Images\mac_osx\etc\hosts
        Takes into account firmlinks and accordingly switches to SYS or DATA volume.
        '''
        if path_in_image == '/': return self.sys_volume_folder

        if path_in_image[-1] == '/': path_in_image = path_in_image[:-1] # remove trailing /

        path_parts = path_in_image[1:].split('/')
        path = ''
        vol_folder = self.sys_volume_folder
        for index, folder_name in enumerate(path_parts):
            #log.debug("index={}, folder_name={}".format(index, folder_name))
            if index >= self.max_firmlink_depth:
                break
            else:
                #log.debug("Searched for {}".format('/' + '/'.join(path_parts[:index + 1])))
                dest = self.firmlinks.get('/' + '/'.join(path_parts[:index + 1]), None)
                if dest != None:
                    found_in_firmlink = True
                    vol_folder = self.data_volume_folder
                    path = dest
                    if index + 1 < len(path_parts):
                        rest_of_path = '/'.join(path_parts[index + 1:])
                        path += '/' + rest_of_path
                    elif path == '':
                        path = '/'

        full_path = ''
        if path == '': path = path_in_image
        if path.startswith('/'): path = path[1:] # Remove leading /
        if self.is_windows:
            path = path.replace('/', '\\')
        try:
            full_path = os.path.join(vol_folder, path)
        except Exception:
            log.error("Exception in BuildFullPath(), path was " + path_in_image)
            log.exception("Exception details")
        log.debug("req={} final={}".format(path_in_image, full_path))
        return full_path

class ZipMacInfo(MacInfo):
    def __init__(self, zip_path, output_params):
        super().__init__(output_params)
        self.zip_path = zip_path
        log.debug('Reading zip archive..')
        self.zip_file = zipfile.ZipFile(zip_path)
        log.debug('Generating list of file paths')
        self.name_list = self.zip_file.namelist()
        log.debug(f'Total files = {len(self.name_list)}')

    #def BuildFullPath(self, path_in_image):
    #    return path_in_image

    def GetFileMACTimes(self, file_path, info=None):
        '''Gets MAC timestamps for a file or folder.
           Assumes file_path starts with /
        '''
        times = { 'c_time':None, 'm_time':None, 'cr_time':None, 'a_time':None }
        if info is None:
            try:
                info = self.zip_file.getinfo(file_path[1:])
            except KeyError as ex:
                # Perhaps this is a folder, and it doesn't end in /
                file_path_folder = file_path
                if file_path_folder[-1] != '/':
                    file_path_folder += '/'
                try:
                    info = self.zip_file.getinfo(file_path_folder[1:])
                except KeyError as ex:
                    log.exception(f'Error trying to get MAC times for {file_path_folder}')
        if info and len(info.extra) > 24:
            timestamps = struct.unpack('<QQQ', info.extra[-24:])
            times['m_time'] = CommonFunctions.ReadWindowsFileTime(timestamps[0])
            times['cr_time'] = CommonFunctions.ReadWindowsFileTime(timestamps[2])
            times['a_time'] = CommonFunctions.ReadWindowsFileTime(timestamps[1])
        return times

    def IsSymbolicLink(self, path):
        # TODO 
        return False

    def IsValidFilePath(self, path):
        ### FOR DEBUG ONLY
        if path.find('\\') >= 0:
            log.warning(f'In ZipMacInfo::IsValidFilePath(), found \\ in path: {path}')
        ###
        try:
            info = self.zip_file.getinfo(path[1:])
            return not info.is_dir() # check if its not folder
        except KeyError as ex:
            pass
        return False

    def IsValidFolderPath(self, path):
        ### FOR DEBUG ONLY
        if path.find('\\') >= 0:
            log.warning(f'In ZipMacInfo::IsValidFolderPath(), found \\ in path: {path}')
        ###
        try:
            if path[-1] != '/': # For Axiom created zip files, folders have their own objects, which end in /
                path += '/'
            info = self.zip_file.getinfo(path[1:])
            return info.is_dir() # check if its folder
        except KeyError as ex:
            pass
        return False

    def GetFileSize(self, full_path, error=None):
        '''Gets file size'''
        try:
            info = self.zip_file.getinfo(full_path[1:])
            return info.file_size
        except KeyError as ex:
            log.error("Exception in GetFileSize() : " + str(ex))
        return error

    def GetUserAndGroupIDForFile(self, path):
        return self._GetUserAndGroupID(path)

    def GetUserAndGroupIDForFolder(self, path):
        return self._GetUserAndGroupID(path)

    def _ListFilesInZipFolder(self, folder_path):
        '''folder_path must begin with / '''
        if folder_path[-1] != '/':
            folder_path += '/'

        path_list = []
        reg = re.compile(f'^{folder_path}[^/]+/?$')
        for member in self.name_list:
            # Typically zip members won't have / as first character, so add it
            if reg.match('/' + member):
                path_list.append('/' + member)
        return path_list

    def ListItemsInFolder(self, path='/', types_to_fetch=EntryType.FILES_AND_FOLDERS, include_dates=False):
        '''
        Returns a list of files and/or folders in a list
        Format of list = [ {'name':'got.txt', 'type':EntryType.FILES, 'size':10}, .. ]
        'path' should be linux style using forward-slash like '/var/db/xxyy/file.tdc'
        and starting at root /
        '''
        items = [] # List of dictionaries
        if path[-1] != '/':
            path += '/'
        try:
            info = self.zip_file.getinfo(path[1:])
        except KeyError:
            log.error(f'Folder {path} not present in archive')
            return items

        dir = self._ListFilesInZipFolder(path)
        for entry in dir:
            info = self.zip_file.getinfo(entry[1:]) # removing initial / as it's not in zip, we added it
            entry_type = EntryType.FOLDERS if (entry[-1] == '/') else EntryType.FILES
            if entry[-1] == '/':
                name = os.path.basename(entry[0:-1])
            else:
                name = os.path.basename(entry)
            item = { 'name':name, 'type':entry_type, 'size':info.file_size}
            if include_dates:
                item['dates'] = self.GetFileMACTimes(entry, info)
            if types_to_fetch == EntryType.FILES_AND_FOLDERS:
                items.append( item )
            elif types_to_fetch == EntryType.FILES and entry_type == EntryType.FILES:
                items.append( item )
            elif types_to_fetch == EntryType.FOLDERS and entry_type == EntryType.FOLDERS:
                items.append( item )

        return items

    def ReadSymLinkTargetPath(self, path):
        '''Returns the target file/folder's path from the sym link path provided'''
        #TODO
        target_path = ''
        # try:
        #     if not self.is_windows:
        #         target_path = os.readlink(self.BuildFullPath(path))
        #     else:
        #         target_path = super().ReadSymLinkTargetPath(path)
        # except:
        #     log.exception("Error resolving symlink : " + path)
        return target_path

    def Open(self, path):
        try:
            log.debug("Trying to open file : " + path)
            file = self.zip_file.open(path[1:])
            return file
        except (KeyError, RuntimeError, OSError) as ex:
            log.exception("Error opening file : " + path)
        return None

    def ExtractFile(self, path_in_image, destination_path):
        #TODO - replace with self.zip_file.extract(..)
        source_file = self.Open(path_in_image)
        if source_file:
            size = self.GetFileSize(path_in_image)

            BUFF_SIZE = 20 * 1024 * 1024
            offset = 0
            try:
                with open(destination_path, 'wb') as f:
                    while offset < size:
                        available_to_read = min(BUFF_SIZE, size - offset)
                        data = source_file.read(available_to_read)
                        if not data: break
                        offset += len(data)
                        f.write(data)
                    f.flush()
            except (OSError) as ex:
                log.exception ("Failed to create file for writing at " + destination_path)
                source_file.close()
                return False
            source_file.close()
            return True
        return False

    def _GetUserAndGroupID(self, path):
        '''
            Returns tuple (success, UID, GID) for object identified by path.
            UID & GID are returned as strings.
            If failed to get values, success=False
        '''
        success, uid, gid = False, 0, 0
        log.error('_GetUserAndGroupID not present in zip files')
        return success, uid, gid

    def _GetDarwinFoldersInfo(self):
        '''Gets DARWIN_*_DIR paths '''

        for user in self.users:
            if user.UUID != '' and user.UID not in ('', '-2', '1', '201'): # Users nobody, daemon, guest don't have one
                darwin_path = '/private/var/folders/' + GetDarwinPath2(user.UUID, user.UID)
                if not self.IsValidFolderPath(darwin_path):
                    darwin_path = '/private/var/folders/' + GetDarwinPath(user.UUID, user.UID)
                    if not self.IsValidFolderPath(darwin_path):
                        if user.user_name.startswith('_') and user.UUID.upper().startswith('FFFFEEEE'):
                            pass
                        else:
                            log.warning(f'Could not find DARWIN_PATH for user {user.user_name}, uid={user.UID}, uuid={user.UUID}')
                        continue
                user.DARWIN_USER_DIR       = darwin_path + '/0'
                user.DARWIN_USER_CACHE_DIR = darwin_path + '/C'
                user.DARWIN_USER_TEMP_DIR  = darwin_path + '/T'

    def _GetDomainUserInfo(self):
        log.debug('Trying to get domain profiles from /Users/')
        domain_users = []
        users_folder = self.ListItemsInFolder('/Users/', EntryType.FOLDERS)
        for folder in users_folder:
            folder_name = folder['name']
            if folder_name in ('Shared', 'root'):
                continue
            found_user = False
            for user in self.users:
                if user.user_name == folder_name:
                    found_user = True # Existing local user
                    break
            if found_user: continue
            else:
                log.info(f'Found a domain user {folder_name} or deleted user?')
                target_user = UserInfo()
                domain_users.append(target_user)
                target_user.home_dir = '/Users/' + folder_name
                target_user.user_name = folder_name
                target_user.real_name = folder_name
                target_user._source = '/Users/' + folder_name
        if domain_users:
            known_darwin_paths = set()
            for user in self.users:
                if user.UID and user.UUID and not user.UID.startswith('-'):
                    known_darwin_paths.add('/private/var/folders/' + GetDarwinPath(user.UUID, user.UID)) # They haven't been populated yet in user!
                    known_darwin_paths.add('/private/var/folders/' + GetDarwinPath2(user.UUID, user.UID))
            # try to get darwin_cache folders
            var_folders = self.ListItemsInFolder('/private/var/folders', EntryType.FOLDERS)
            for level_1 in var_folders:
                name_1 = level_1['name']
                var_folders_level_2 = self.ListItemsInFolder(f'/private/var/folders/{name_1}', EntryType.FOLDERS)
                for level_2 in var_folders_level_2:
                    darwin_path = f'/private/var/folders/{name_1}/' + level_2['name']
                    if darwin_path in known_darwin_paths:
                        continue
                    else:
                        matched_darwin_path_to_user = False
                        font_reg_db = darwin_path + '/C/com.apple.FontRegistry/fontregistry.user'
                        if self.IsValidFilePath(font_reg_db):
                            try:
                                sqlite_wrapper = SqliteWrapper(self)
                                db = sqlite_wrapper.connect(font_reg_db)
                                if db:
                                    cursor = db.cursor()
                                    cursor.execute('SELECT path_column from dir_table WHERE domain_column=1')
                                    user_path = ''
                                    for row in cursor:
                                        user_path = row[0]
                                        break
                                    cursor.close()
                                    db.close()
                                    if user_path:
                                        if user_path.startswith('/Users/'):
                                            username = user_path.split('/')[2]
                                            for dom_user in domain_users:
                                                if dom_user.user_name == username:
                                                    dom_user.DARWIN_USER_DIR = darwin_path + '/0'
                                                    dom_user.DARWIN_USER_TEMP_DIR = darwin_path + '/T'
                                                    dom_user.DARWIN_USER_CACHE_DIR = darwin_path + '/C'
                                                    log.debug(f'Found darwin path for user {username}')
                                                    matched_darwin_path_to_user = True
                                                    # Try to get uid now.
                                                    if self.IsValidFolderPath(dom_user.DARWIN_USER_DIR + '/com.apple.LaunchServices.dv'):
                                                        for item in self.ListItemsInFolder(dom_user.DARWIN_USER_DIR + '/com.apple.LaunchServices.dv', EntryType.FILES):
                                                            name = item['name']
                                                            if name.startswith('com.apple.LaunchServices.trustedsignatures-') and name.endswith('.db'):
                                                                dom_user.UID = name[43:-3]
                                                                break
                                                    break
                                        else:
                                            log.error(f'user profile path was non-standard - {user_path}')
                                    else:
                                        log.error('Query did not yield any output!')
                                    if not matched_darwin_path_to_user:
                                        log.error(f'Could not find mapping for darwin folder {darwin_path} to user')
                            except sqlite3.Error:
                                log.exception(f'Error reading {font_reg_db}, Cannot map darwin folder to user profile!')
                        else:
                            log.error(f'Could not find {font_reg_db}, Cannot map darwin folder to user profile!')
            self.users.extend(domain_users)

class ApplicationInfo:
    def __init__(self, app_identifier):
        self.bundle_container_path = '' # /private/var/containers/Bundle/UUID1 ## Not for buitin apps
        self.bundle_identifier = app_identifier # com.xxx.yyy
        self.bundle_path = '' # <bundle_container_path>/Appname.app  or /Applications/Appname.app
        self.sandbox_path = '' # /private/var/mobile/Containers/Data/Application/UUID2

        self.uninstall_date = None
        self.bundle_uuid = None
        self.data_uuid = None

        # From <bundle_path>/Info.plist
        self.main_icon_path = '' # CFBundleIcons/CFBundlePrimaryIcon/CFBundleIconFiles (array)
        self.bundle_display_name = '' #CFBundleDisplayName  # Main App Name as it appears to user
        self.bundle_version = '' # CFBundleShortVersionString
        self.hidden = False # SBAppTags

        self.install_date = None # From deserialized BundleMetadata.plist located one level above <bundle_path>

        self.source = ''
        self.extensions = []
        self.app_groups = []
        self.sys_groups = []

        self.app_group_containers = []
        self.sys_group_containers = []
        self.ext_group_containers = []

class ContainerInfo:
    def __init__(self, identifier, uuid, path):
        self.path = path
        self.id = identifier
        self.uuid = uuid

class MountedIosInfo(MountedMacInfo):
    def __init__(self, root_folder_path, output_params):
        super().__init__(root_folder_path, output_params)
        self.apps = []

    def GetUserAndGroupIDForFile(self, path):
        raise NotImplementedError()

    def GetUserAndGroupIDForFolder(self, path):
        return NotImplementedError()

    def _GetUserAndGroupID(self, path):
        return NotImplementedError()

    def _GetDarwinFoldersInfo(self):
        '''Gets DARWIN_*_DIR paths, these do not exist on IOS'''
        return NotImplementedError()

    def _GetUserInfo(self):
        return NotImplementedError()

    def _GetSystemInfo(self, plist_path):
        ''' Gets system version information'''
        found_info = False
        try:
            log.debug(f"Trying to get system version from {plist_path}")
            f = self.Open(plist_path)
            if f != None:
                success, plist, error = CommonFunctions.ReadPlist(f)
                if success:
                    self.os_version = plist.get('ProductVersion', '')
                    self.os_build = plist.get('ProductBuildVersion', '')
                    self.os_friendly_name = plist.get('ProductName', '')
                    log.info ('iOS version detected is: {} ({}) Build={}'.format(self.os_friendly_name, self.os_version, self.os_build))
                    f.close()
                    return True
                else:
                    log.error("Could not get ProductVersion from plist. Is it a valid xml plist? Error=" + error)
                f.close()
            else:
                log.error("Could not open plist to get system version info!")
        except:
            log.exception("Unknown error from _GetSystemInfo()")
        return False

    def _GetAppDetails(self):
        '''Get app name, path, version, uuid, container path and other info'''
        app_state_db = '/private/var/mobile/Library/FrontBoard/applicationState.db'
        if self.IsValidFilePath(app_state_db):
            self.ExportFile(app_state_db, 'APPS')
            try:
                sqlite = SqliteWrapper(self)
                conn = sqlite.connect(app_state_db)
                if conn:
                    log.debug ("Opened DB {} successfully".format(os.path.basename(app_state_db)))
                    try:
                        conn.row_factory = sqlite3.Row
                        query = \
                        """
                        SELECT application_identifier_tab.application_identifier as ai, key_tab.key, value 
                        FROM application_identifier_tab, key_tab, kvs 
                        WHERE kvs.application_identifier=application_identifier_tab.id 
                            AND kvs.key=key_tab.id 
                        ORDER BY ai
                        """
                        cursor = conn.execute(query)
                        apps = []
                        last_app_name = ''
                        app_info = None
                        try:
                            for row in cursor:
                                app = row['ai']
                                key = row['key']
                                val = row['value']
                                if last_app_name != app: # new app found
                                    app_info = ApplicationInfo(app)
                                    apps.append(app_info)
                                    last_app_name = app
                                    app_info.source = app_state_db
                                # Process key/val pairs
                                if key == '__UninstallDate':
                                    if val:
                                        temp_file = BytesIO(val)
                                        success, plist, error = CommonFunctions.ReadPlist(temp_file)
                                        if success:
                                            if isinstance(plist, datetime.datetime):
                                                app_info.uninstall_date = plist
                                            else:
                                                log.error('Uninstall plist is not in the expected form, plist was ' + str(plist))
                                        else:
                                            log.error(f'Failed to read "compatibilityInfo" for {app}. {error}')
                                        temp_file.close()
                                elif key == 'XBApplicationSnapshotManifest':
                                    pass
                                elif key == 'compatibilityInfo':
                                    if val:
                                        temp_file = BytesIO(val)
                                        success, plist, error = CommonFunctions.ReadPlist(temp_file, True)
                                        if success:
                                            app_info.bundle_container_path = plist.get('bundleContainerPath', '')
                                            if app_info.bundle_container_path:
                                                app_info.bundle_uuid = UUID(os.path.basename(app_info.bundle_container_path))
                                            app_info.bundle_path = plist.get('bundlePath', '')
                                            app_info.sandbox_path = plist.get('sandboxPath', '')
                                            if app_info.sandbox_path:
                                                app_info.data_uuid = UUID(os.path.basename(app_info.sandbox_path))
                                            self._ReadInfoPlist(app_info, app_info.bundle_path + '/Info.plist')
                                            bundle_root, _ = os.path.split(app_info.bundle_path)
                                            if bundle_root != '/Applications':
                                                self._ReadBundleMetadataPlist(app_info, bundle_root + '/BundleMetadata.plist')
                                                app_info.source += ', ' + app_info.bundle_path + '/Info.plist' + ', ' + bundle_root + '/BundleMetadata.plist'
                                        else:
                                            log.error(f'Failed to read "compatibilityInfo" for {app}. {error}')
                                        temp_file.close()
                            conn.close()
                            for app in apps: # add app to main list if properties are not empty
                                if not app.bundle_display_name and not app.bundle_path \
                                    and not app.sandbox_path and not app.uninstall_date \
                                    and not app.bundle_display_name:
                                    pass
                                else:
                                    self.apps.append(app)
                        except sqlite3.Error as ex:
                            log.exception("Db cursor error while reading file " + app_state_db)
                            conn.close()
                            return False
                    except sqlite3.Error as ex:
                        log.error ("Sqlite error - \nError details: \n" + str(ex))
                        conn.close()
                        return False
                    conn.close()
                    self._GetAppGroupDetails(self.apps)
                    self._ResolveAppSysGroupFolders(self.apps)
                    return True
            except sqlite3.Error as ex:
                log.error ("Failed to open {}, is it a valid DB? Error details: ".format(os.path.basename(app_state_db)) + str(ex))
                return False
        else:
            log.error(f'Could not find {app_state_db}, cannot get Application information!')
        return False

    def _GetAppGroupDetails(self, apps):
        '''Get Appgroup information'''
        containers_db_path = '/private/var/root/Library/MobileContainerManager/containers.sqlite3'
        if self.IsValidFilePath(containers_db_path):
            self.ExportFile(containers_db_path, 'APPS')
            try:
                sqlite = SqliteWrapper(self)
                conn = sqlite.connect(containers_db_path)
                if conn:
                    log.debug ("Opened DB {} successfully".format(os.path.basename(containers_db_path)))
                    try:
                        conn.row_factory = sqlite3.Row
                        query = \
                        """
                        SELECT b.data, code_signing_id_text as app, extensions FROM (
                            SELECT code_signing_info.id, code_signing_id_text,  group_concat(child_code_signing_id_text) as extensions
                            FROM code_signing_info LEFT JOIN child_bundles ON child_bundles.parent_id = code_signing_info.id
                            WHERE code_signing_info.data_container_class=2
                            GROUP BY code_signing_id_text
                            ORDER BY code_signing_id_text, child_code_signing_id_text
                            ) a LEFT JOIN code_signing_data b on a.id=b.cs_info_id
                        WHERE INSTR(data, CAST("com.apple.security.application-groups" AS blob)) > 0 
                        or INSTR(data, CAST("com.apple.security.system-groups" AS blob)) > 0
                        """
                        cursor = conn.execute(query)
                        try:
                            for row in cursor:
                                app_name = row['app']
                                exts = [] if row['extensions'] is None else row['extensions'].split(',')
                                plist_data = row['data']
                                target_app = None
                                for app in apps:
                                    if app.bundle_identifier == app_name:
                                        target_app = app
                                        break
                                if target_app is None:
                                    target_app = ApplicationInfo(app_name)
                                    apps.append(target_app)
                                    log.info(f"App was not found in applist - {app_name}")
                                target_app.extensions = exts
                                # read plist
                                temp_file = BytesIO(plist_data)
                                success, plist, error = CommonFunctions.ReadPlist(temp_file)
                                if success:
                                    entitlements = plist.get('com.apple.MobileContainerManager.Entitlements', None)
                                    if entitlements:
                                        target_app.app_groups = entitlements.get('com.apple.security.application-groups', [])
                                        target_app.sys_groups = entitlements.get('com.apple.security.system-groups', [])
                                        if target_app.source:
                                            target_app.source += ', ' + containers_db_path
                                        else:
                                            target_app.source = containers_db_path
                                    else:
                                        log.error(f'Entitlements not found in plist for {app_name}')
                                else:
                                    log.error(f'Failed to read plist for {app_name}. {error}')
                                temp_file.close()
                        except sqlite3.Error as ex:
                            log.exception("Db cursor error while reading file " + containers_db_path)
                    except sqlite3.Error as ex:
                        log.error ("Sqlite error - \nError details: \n" + str(ex))
                    conn.close()
            except sqlite3.Error as ex:
                log.error ("Failed to open {}, is it a valid DB? Error details: ".format(os.path.basename(containers_db_path)) + str(ex))
        else:
            log.error(f'Could not find {containers_db_path}, cannot get Container information!')

    def _ResolveAppSysGroupFolders(self, apps):
        '''Get all UUID and path information from AppGroup folders'''
        app_groups_path = '/private/var/mobile/Containers/Shared/AppGroup'
        self._ResolveGroupFolders(apps, app_groups_path, 'Shared AppGroup')

        sys_groups_path = '/private/var/containers/Shared/SystemGroup'
        self._ResolveGroupFolders(apps, sys_groups_path, 'Shared SystemGroup')

        pluginkits_path = '/private/var/mobile/Containers/Data/PluginKitPlugin'
        self._ResolveGroupFolders(apps, pluginkits_path, 'PluginKitPlugin')


    def _ResolveGroupFolders(self, apps, groups_path, groups_name):
        '''Get UUID and path information from AppGroup/SystemGroup folders'''
        if self.IsValidFolderPath(groups_path):
            log.info('Resolving App Group folders')
            folder_items = self.ListItemsInFolder(groups_path, types_to_fetch=EntryType.FOLDERS, include_dates=False)
            for item in folder_items:
                uuid = item['name']
                plist_path = groups_path + '/' + uuid + '/.com.apple.mobile_container_manager.metadata.plist'
                if self.IsValidFilePath(plist_path):
                    success, plist, error = self.ReadPlist(plist_path)
                    if success:
                        identifier = plist.get('MCMMetadataIdentifier', '')
                        for app in apps:
                            for group in app.app_groups:
                                if group == identifier:
                                    container = ContainerInfo(identifier, uuid, groups_path + '/' + uuid)
                                    app.app_group_containers.append(container)
                            for group in app.sys_groups:
                                if group == identifier:
                                    container = ContainerInfo(identifier, uuid, groups_path + '/' + uuid)
                                    app.sys_group_containers.append(container)
                            for group in app.extensions:
                                if group == identifier:
                                    container = ContainerInfo(identifier, uuid, groups_path + '/' + uuid)
                                    app.ext_group_containers.append(container)
                    else:
                        log.error(f'Failed to read {plist_path}. {error}')
                else:
                    log.error(f'File not found: {plist_path}')
        else:
            log.error(f'{groups_name} not parsed - path not found - {groups_path}')

    def _ReadBundleMetadataPlist(self, app_info, plist_path):
        if self.IsValidFilePath(plist_path):
            success, plist, error = self.ReadPlist(plist_path, deserialize=True)
            if success:
                app_info.install_date = plist.get('installDate', '')
            else:
                log.error(f'Failed to read {plist_path}. {error}')
        else:
            log.error(f'File not found: {plist_path}')

    def _ReadInfoPlist(self, app_info, plist_path):
        if self.IsValidFilePath(plist_path):
            success, plist, error = self.ReadPlist(plist_path)
            if success:
                app_info.bundle_display_name = plist.get('CFBundleDisplayName', '')
                if app_info.bundle_display_name == '':
                    app_info.bundle_display_name = plist.get('CFBundleName', '')
                app_info.bundle_version = plist.get('CFBundleShortVersionString', '')
                try:
                    icon = plist['CFBundleIcons']['CFBundlePrimaryIcon']['CFBundleIconFiles'][0]
                    app_info.main_icon_path = app_info.bundle_path + '/' + icon
                except (KeyError, ValueError, IndexError, TypeError) as ex:
                    log.debug(ex)
                app_info.hidden = True if 'hidden' in plist.get('SBAppTags', []) else False
            else:
                log.error(f'Failed to read {plist_path}. {error}')
        else:
            log.error(f'File not found: {plist_path}')

class SqliteWrapper:
    '''
    Wrapper class for sqlite operations
    This is to extract the sqlite db and related files to disk before
    it can be opened. When object is destroyed, it will delete these
    temp files.

    Plugins can use this class and use the SqliteWrapper.connect()
    function to get a connection object. All other sqlite objects can be
    normally retrieved through SqliteWrapper.sqlite3. Use a new instance
    of SqliteWrapper for every database processed.

    WARNING: Keep this object/ref alive till you are using the db. And
    don't forget to call db.close() when you are done.
    '''

    def __init__(self, mac_info):
        self.mac_info = mac_info
        self.db_file_path = ''
        self.jrn_file_path = ''
        self.wal_file_path = ''
        self.db_file_path_temp = ''
        self.jrn_file_path_temp = ''
        self.wal_file_path_temp = ''
        self.db_temp_file = None
        self.shm_temp_file = None
        self.wal_temp_file = None
        self.folder_temp_path = os.path.join(mac_info.output_params.output_path, "Temp" + ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(4)))

    def _ExtractFiles(self):
        # create temp folder
        try:
            if not os.path.exists(self.folder_temp_path):
                os.makedirs(self.folder_temp_path)
        except Exception as ex:
            log.error ("Exception in _ExtractFiles(). Is ouput folder Writeable? Is it full? Perhaps the drive is disconnected? Exception Details: " + str(ex))
            return False

        # extract each file to temp folder
        self.db_file_path_temp = os.path.join(self.folder_temp_path, os.path.basename(self.db_file_path))
        self.jrn_file_path_temp = os.path.join(self.folder_temp_path, os.path.basename(self.jrn_file_path))
        self.wal_file_path_temp = os.path.join(self.folder_temp_path, os.path.basename(self.wal_file_path))

        self.db_temp_file = self.mac_info.ExtractFile(self.db_file_path, self.db_file_path_temp)
        if self.mac_info.IsValidFilePath(self.jrn_file_path):
            self.shm_temp_file = self.mac_info.ExtractFile(self.jrn_file_path, self.jrn_file_path_temp)
        if self.mac_info.IsValidFilePath(self.wal_file_path):
            self.wal_temp_file = self.mac_info.ExtractFile(self.wal_file_path, self.wal_file_path_temp)
        return True

    def _is_valid_sqlite_file(self, path):
        '''Checks file header for valid sqlite db'''
        ret = False
        with open (path, 'rb') as f:
            if f.read(16) == b'SQLite format 3\0':
                ret = True
        return ret

    def __getattr__(self, attr):
        if attr == 'connect':
            def hooked(path):
                # Get 'database' variable
                self.db_file_path = path
                self.jrn_file_path = path + "-journal"
                self.wal_file_path = path + "-wal"
                if self._ExtractFiles():
                    log.debug('Trying to extract and read db: ' + path)
                    if self._is_valid_sqlite_file(self.db_file_path_temp):
                        result = CommonFunctions.open_sqlite_db_readonly(self.db_file_path_temp) # TODO -> Why are exceptions not being raised here when bad paths are sent?
                    else:
                        log.error('File is not an SQLITE db or it is corrupted!')
                        result = None
                else:
                    result = None
                return result
            return hooked
        else:
            return attr

    def _remove_readonly(self, func, path, excinfo):
        os.chmod(path, stat.S_IWRITE)
        func(path)

    def __del__(self):
        '''Close all file handles and delete all files & temp folder'''
        # Sometimes a delay may be needed, lets try at least 3 times before failing.
        deleted = False
        count = 0
        ex_str = ''
        while (not deleted) and (count < 3):
            count += 1
            try:
                shutil.rmtree(self.folder_temp_path, onerror=self._remove_readonly)
                deleted = True
            except Exception as ex:
                ex_str = "Exception while deleting temp files/folders: " + str(ex)
                time.sleep(0.3)
        if not deleted:
            log.debug(ex_str)
