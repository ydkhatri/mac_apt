'''
   Copyright (c) 2017 Yogesh Khatri 

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the 
   terms of the MIT License.
   
'''

import pytsk3
import traceback
import biplist
import tempfile
import sqlite3
import os
import stat
import shutil
import struct
import random
import string
import time
import logging
import ast
from plugins.helpers.apfs_reader import *
from plugins.helpers.hfs_alt import HFSVolume
from plugins.helpers.common import *
from plugins.helpers.structs import *

log = logging.getLogger('MAIN.HELPERS.MACINFO')

'''
    Common data structures for plugins 
'''
class OutputParams:
    def __init__(self):
        self.output_path = ''
        self.write_csv = False
        self.write_sql = False
        self.write_xlsx = False
        self.xlsx_writer = None
        self.output_db_path = ''
        self.export_path = '' # For artifact source files
        self.export_log_csv = None
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

    def OpenSmallFile(self, path):
        '''Open files, returns open file handle'''
        if not self.initialized:
            raise ValueError("Volume not loaded (initialized)!")
        try:
            log.debug("Trying to open file : " + path)
            size = self.GetFileSize(path)
            if size > 209715200:
                log.warning('File size > 200 MB, may crash! File size is {} bytes'.format(size))
            data = self.volume.readFile(path)
            f = tempfile.SpooledTemporaryFile(max_size=size)
            f.write(data)
            f.seek(0)
            return f
        except (OSError, IOError) as ex:
            log.exception("NativeHFSParser->Failed to open file {} Error was {}".format(path, str(ex)))

        return None

    def ExtractFile(self, path, extract_to_path):
        '''
           Extract file, returns True or False
           This only works on small files currently!
        '''
        if not self.initialized:
            raise ValueError("Volume not loaded!")
        try:
            log.debug("Trying to export file : " + path + " to " + extract_to_path)
            with open(extract_to_path, "wb") as f:
                data = self.volume.readFile(path, f)
                f.close()
                return True
        except ValueError as ex:
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
        try:
            return self.volume.IsValidFilePath(path)
        except ValueError:
            log.exception('NativeHFSParser->Failed trying to check valid file path')
        return False
    
    def IsValidFolderPath(self, path):
        '''Check if a folder path is valid'''
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
        except:
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

    def __init__(self, output_params):
        #self.Partitions = {}   # Dictionary of all partition objects returned from pytsk LATER! 
        self.pytsk_image = None
        self.osx_FS = None     # Just the FileSystem object (fs) from OSX partition
        self.osx_partition_start_offset = 0
        self.vol_info = None # disk_volumes
        self.output_params = output_params
        self.osx_version = '0.0.0'
        self.osx_friendly_name = 'No name yet!'
        self.users = []
        self.hfs_native = NativeHfsParser()
        self.is_apfs = False
        self.use_native_hfs_parser = True

    # Public functions, plugins can use these
    def GetFileMACTimes(self, file_path):
        '''
           Returns dictionary {c_time, m_time, cr_time, a_time} 
           where cr_time = created time and c_time = Last time inode/mft modified
        '''
        if self.use_native_hfs_parser:
            return self.hfs_native.GetFileMACTimes(file_path)

        times = { 'c_time':None, 'm_time':None, 'cr_time':None, 'a_time':None }
        try:
            tsk_file = self.osx_FS.open(file_path)
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
        except Exception as ex:
            log.error ("Exception while creating Export folder " + export_path + "\n Is output folder Writeable?" +
                       "Is it full? Perhaps the drive is disconnected? Exception Details: " + str(ex))
            return False
        # recursively export files/folders
        try:
            return self._ExportFolder(artifact_path, export_path, overwrite)
        except:
            log.exception('Exception while exporting folder ' + artifact_path)
        return False

    def _ExportFolder(self, artifact_path, export_path, overwrite):
        '''Exports files/folders from artifact_path to export_path recursively'''
        entries = self.ListItemsInFolder(artifact_path, EntryType.FILES_AND_FOLDERS, True)
        ret = True
        for entry in entries:
            new_path = os.path.join(export_path, entry['name'])
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
                ret &= self._ExtractFile(artifact_path + '/' + entry['name'], new_path, entry['dates'])
        return ret

    def ExportFile(self, artifact_path, subfolder_name, file_prefix='', check_for_sqlite_files=True, overwrite=False):
        '''Export an artifact (file) to the output\Export\subfolder_name folder.
           Ideally subfolder_name should be the name of the plugin.
           If 'overwrite' is set to True, it will not check for existing files. The
           default behaviour is to check and rename the newly exported file if there
           is a name collision.
           If this is an sqlite db, the -shm and -wal files will also be exported.
           The check for -shm and -wal can be skipped if  check_for_sqlite_files=False
           It is much faster to skip the check if not needed.
           The Function returns False if it fails to export the file.
        '''
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
        shm_file_path = file_path + "-shm" # For sqlite db
        wal_file_path = file_path + "-wal" # For sqlite db

        if self._ExtractFile(artifact_path, file_path):
            if check_for_sqlite_files:
                if self.IsValidFilePath(artifact_path + "-shm"):
                    self._ExtractFile(artifact_path + "-shm", shm_file_path)
                if self.IsValidFilePath(artifact_path + "-wal"):
                    self._ExtractFile(artifact_path + "-wal", wal_file_path)
            return True
        return False

    def _ExtractFile(self, artifact_path, export_path, mac_times=None):
        '''Internal function, just export, no checks!'''
        if self.ExtractFile(artifact_path, export_path):
            if not mac_times:
                mac_times = self.GetFileMACTimes(artifact_path)
            self.output_params.export_log_csv.WriteRow([artifact_path, export_path, mac_times['c_time'], mac_times['m_time'], mac_times['cr_time'], mac_times['a_time']])
            return True
        else:
            log.info("Failed to export '" + artifact_path + "' to '" + export_path + "'")
        return False

    def ReadPlist(self, path):
        '''Safely open and read a plist; returns tuple (True/False, plist/None, "error_message")'''
        log.debug("Trying to open plist file : " + path)
        error = ''
        try:
            f = self.OpenSmallFile(path)
            if f != None:
                try:
                    log.debug("Trying to read plist file : " + path)
                    plist = biplist.readPlist(f)
                    return (True, plist, '')
                except biplist.InvalidPlistException as ex:
                    try:
                        # Perhaps this is manually edited or incorrectly formatted by a non-Apple utility  
                        # that has left whitespaces at the start of file before <?xml tag
                        f.seek(0)
                        data = f.read().decode('utf8')
                        data = data.lstrip(" \r\n\t").encode('utf8', 'backslashreplace')
                        plist = biplist.readPlistFromString(data)
                        return (True, plist, '')
                    except biplist.InvalidPlistException as ex:
                        error = 'Could not read plist: ' + path + " Error was : " + str(ex)
                except IOError as ex:
                    error = 'IOError while reading plist: ' + path + " Error was : " + str(ex)
            else:
                error = 'Failed to open file'
        except Exception as ex:
            error = 'Exception from ReadPlist, trying to open file. Exception=' + str(ex)
        return (False, None, error)

    def IsSymbolicLink(self, path):
        '''Check if path represents a symbolic link'''
        if self.use_native_hfs_parser:
            return self.hfs_native.IsSymbolicLink(path)
        return False

    def ReadSymLinkTargetPath(self, path):
        '''Returns the target file/folder's path from the sym link path provided'''
        f = self.OpenSmallFile(path)
        if f:
            target_path = f.read()
            f.close()
            return target_path.decode('utf8', 'backslashreplace')
        return ''

    def IsValidFilePath(self, path):
        '''Check if a file path is valid, does not check for folders!'''
        if self.use_native_hfs_parser:
            return self.hfs_native.IsValidFilePath(path)
        try:
            valid_file = self.osx_FS.open(path)
            return True
        except Exception:
            pass
        return False
    
    def IsValidFolderPath(self, path):
        '''Check if a folder path is valid'''
        if self.use_native_hfs_parser:
            return self.hfs_native.IsValidFolderPath(path)
        try:
            valid_folder = self.osx_FS.open_dir(path)
            return True
        except Exception:
            pass
        return False

    def GetFileSize(self, path, error=None):
        '''For a given file path, gets logical file size, or None if error'''
        if self.use_native_hfs_parser:
            return self.hfs_native.GetFileSize(path)
        try:
            valid_file = self.osx_FS.open(path) 
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
            dir = self.osx_FS.open_dir(path)
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
                log.debug("Exception details:\n", exc_info=True) #traceback.print_exc()
                log.error("Failed to get dir info!")
        return items

    def OpenSmallFile(self, path):
        '''Open files less than 200 MB, returns open file handle'''
        if self.use_native_hfs_parser:
            return self.hfs_native.OpenSmallFile(path)
        try:
            log.debug("Trying to open file : " + path)
            tsk_file = self.osx_FS.open(path)
            size = tsk_file.info.meta.size
            if size > 209715200:
                raise ValueError('File size > 200 MB, use direct TSK file functions!')

            f = tempfile.SpooledTemporaryFile(max_size=209715200)
            BUFF_SIZE = 1024 * 1024
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
                log.error("OpenSmallFile() returned 'Path not found' error for path: {}".format(path))
            elif str(ex).find('tsk_fs_attrlist_get: Attribute 4352 not found') > 0 or \
                 (str(ex).find('Read error: Invalid file offset') > 0 and self._IsFileCompressed(tsk_file)) or \
                 str(ex).find('Read error: Error in metadata') > 0:
                log.debug("Known TSK bug caused Error: Failed to open file {}".format(path))
                log.debug("Trying to open with Native HFS parser")
                try:
                    if not self.hfs_native.initialized:
                        self.hfs_native.Initialize(self.pytsk_image, self.osx_partition_start_offset)
                    return self.hfs_native.OpenSmallFile(path)
                except (IOError, OSError, ValueError):
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
            tsk_file = self.osx_FS.open(tsk_path)
            size = tsk_file.info.meta.size

            BUFF_SIZE = 1024 * 1024
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
                                        self.hfs_native.Initialize(self.pytsk_image, self.osx_partition_start_offset)
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
                log.debug("OpenSmallFile() returned 'Path not found' error for path: {}".format(tsk_path))
            else:
                #traceback.print_exc()
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
        '''Returns osx version as dictionary {major:10, minor:5 , micro:0}'''
        version_dict = { 'major':0, 'minor':0, 'micro':0 }
        info = self.osx_version.split(".")
        try:
            version_dict['major'] = int(info[0])
            try:
                version_dict['minor'] = int(info[1])
                try:
                    version_dict['micro'] = int(info[2])
                except Exception:
                    pass
            except Exception:
                pass
        except Exception:
            pass
        return version_dict

    def GetUserAndGroupIDForFolder(self, path):
        '''
            Returns tuple (success, UID, GID) for folder identified by path
            If failed to get values, success=False
            UID & GID are returned as strings
        '''
        success, uid, gid = False, 0, 0
        try:
            path_dir = self.osx_FS.open_dir(path)
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
        success, uid, gid = False, 0, 0
        try:
            path_file = self.osx_FS.open(path)
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
            unsafe_chars = '?<>/\:*"!' if os.name == 'nt' else '/'
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
            #traceback.print_exc()
        return False

    def _GetSize(self, entry):
        '''For a pytsk3 file entry, gets logical file size, or 0 if error'''
        try:
            return entry.info.meta.size
        except Exception as ex:
            log.error (" Unknown exception from _GetSize() " + str(ex))
            #traceback.print_exc()
        return 0

    def _GetName(self, entry):
        '''Return utf8 filename from pytsk entry object'''
        try:
            return entry.info.name.name.decode("utf8")
        except UnicodeError:
            #log.debug("UnicodeError getting name ")
            pass
        except Exception as ex:
            log.error (" Unknown exception from GetName:" + str(ex))
            #traceback.print_exc()
        return ""

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
            log.debug("Exception details:\n", exc_info=True) #traceback.print_exc()
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
        try:
            plist2 = biplist.readPlistFromString(password_policy_data[0])
            target_user.failed_login_count = plist2.get('failedLoginCount', 0)
            target_user.failed_login_timestamp = plist2.get('failedLoginTimestamp', None)
            target_user.last_login_timestamp = plist2.get('lastLoginTimestamp', None)
            target_user.password_last_set_time = plist2.get('passwordLastSetTime', None)
        except (InvalidPlistException, NotBinaryPlistException):
            log.exception('Error reading password_policy_data embedded plist')

    def _ReadAccountPolicyData(self, account_policy_data, target_user):
        try:
            plist2 = biplist.readPlistFromString(account_policy_data[0])
            target_user.creation_time = CommonFunctions.ReadUnixTime(plist2.get('creationTime', None))
            target_user.failed_login_count = plist2.get('failedLoginCount', 0)
            target_user.failed_login_timestamp = CommonFunctions.ReadUnixTime(plist2.get('failedLoginTimestamp', None))
            target_user.password_last_set_time = CommonFunctions.ReadUnixTime(plist2.get('passwordLastSetTime', None))
        except (InvalidPlistException, NotBinaryPlistException):
            log.exception('Error reading password_policy_data embedded plist')     

    def _GetUserInfo(self):
        '''Populates user info from plists under: /private/var/db/dslocal/nodes/Default/users/'''
        #TODO - make a better plugin that gets all user & group info
        users_path  = '/private/var/db/dslocal/nodes/Default/users'
        user_plists = self.ListItemsInFolder(users_path, EntryType.FILES)
        for plist_meta in user_plists:
            if plist_meta['size'] > 0:
                try:
                    user_plist_path = users_path + '/' + plist_meta['name']
                    f = self.OpenSmallFile(user_plist_path)
                    if f!= None:
                        self.ExportFile(user_plist_path, 'USERS', '', False)
                        try:
                            plist = biplist.readPlist(f)
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
                                osx_version = self.GetVersionDictionary()
                                if osx_version['major'] == 10 and osx_version['minor'] <= 9: # Mavericks & earlier
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
                        except (InvalidPlistException):
                            log.exception("biplist failed to read plist " + user_plist_path)
                except:
                    log.exception ("Could not open plist " + user_plist_path)
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
                        log.error('Could not find username for UID={} GID={}'.format(uid, gid))
   
    def _GetSystemInfo(self):
        ''' Gets system version information'''
        try:
            #plist_file = self.osx_FS.open('/System/Library/CoreServices/SystemVersion.plist')
            #plist_string = plist_file.read_random(0, plist_file.info.meta.size) # This is a small file, so this is fine!
            #plist = biplist.readPlistFromString(plist_string)
            log.debug("Trying to get system version from /System/Library/CoreServices/SystemVersion.plist")
            f = self.OpenSmallFile('/System/Library/CoreServices/SystemVersion.plist')
            if f != None:
                try:
                    plist = biplist.readPlist(f)
                    self.osx_version = plist.get('ProductVersion', '')
                    if self.osx_version != '':
                        if   self.osx_version.startswith('10.10'): self.osx_friendly_name = 'Yosemite'
                        elif self.osx_version.startswith('10.11'): self.osx_friendly_name = 'El Capitan'
                        elif self.osx_version.startswith('10.12'): self.osx_friendly_name = 'Sierra'
                        elif self.osx_version.startswith('10.13'): self.osx_friendly_name = 'High Sierra'
                        elif self.osx_version.startswith('10.14'): self.osx_friendly_name = 'Mojave'
                        elif self.osx_version.startswith('10.0'): self.osx_friendly_name = 'Cheetah'
                        elif self.osx_version.startswith('10.1'): self.osx_friendly_name = 'Puma'
                        elif self.osx_version.startswith('10.2'): self.osx_friendly_name = 'Jaguar'
                        elif self.osx_version.startswith('10.3'): self.osx_friendly_name = 'Panther'
                        elif self.osx_version.startswith('10.4'): self.osx_friendly_name = 'Tiger'
                        elif self.osx_version.startswith('10.5'): self.osx_friendly_name = 'Leopard'
                        elif self.osx_version.startswith('10.6'): self.osx_friendly_name = 'Snow Leopard'
                        elif self.osx_version.startswith('10.7'): self.osx_friendly_name = 'Lion'
                        elif self.osx_version.startswith('10.8'): self.osx_friendly_name = 'Mountain Lion'
                        elif self.osx_version.startswith('10.9'): self.osx_friendly_name = 'Mavericks'
                        else: self.osx_friendly_name = 'Unknown version!'
                    log.info ('OSX version detected is: {} ({})'.format(self.osx_friendly_name, self.osx_version))
                    return True
                except (InvalidPlistException, NotBinaryPlistException) as ex:
                    log.error ("Could not get ProductVersion from plist. Is it a valid xml plist? Error=" + str(ex))
            else:
                log.error("Could not open plist to get system version info!")
        except:
            log.exception("Unknown error from _GetSystemInfo()")
        return False

class ApfsMacInfo(MacInfo):
    def __init__(self, output_params):
        MacInfo.__init__(self, output_params)
        self.apfs_container = None
        self.apfs_db = None
        self.apfs_db_path = ''
        #self.apfs_osx_volume = self.osx_FS
        #self.apfs_container_offset = self.osx_partition_start_offset

    def ReadApfsVolumes(self):
        '''Read volume information into an sqlite db'''
        for vol in self.apfs_container.volumes:
            if vol.is_encrypted: 
                continue
            apfs_parser = ApfsFileSystemParser(vol, self.apfs_db)
            apfs_parser.read_volume_records()

    def GetFileMACTimes(self, file_path):
        '''Gets MACB and the 5th Index timestamp too'''
        times = { 'c_time':None, 'm_time':None, 'cr_time':None, 'a_time':None, 'i_time':None }
        try:
            apfs_file_meta = self.osx_FS.GetFileMetadataByPath(file_path)
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
        return self.osx_FS.IsSymbolicLink(path)

    def IsValidFilePath(self, path):
        return self.osx_FS.DoesFileExist(path)

    def IsValidFolderPath(self, path):
        return self.osx_FS.DoesFolderExist(path)

    def GetExtendedAttribute(self, path, att_name):
        return self.osx_FS.GetExtendedAttribute(path, att_name)

    def GetExtendedAttributes(self, path):
        xattrs = {}
        apfs_xattrs = self.osx_FS.GetExtendedAttributes(path)
        return { att_name:att.data for att_name,att in apfs_xattrs.items() }

    def GetFileSize(self, full_path, error=None):
        try:
            apfs_file_meta = self.osx_FS.GetFileMetadataByPath(full_path)
            if apfs_file_meta:
                return apfs_file_meta.logical_size
        except Exception as ex:
            log.debug ("APFSMacInfo->Exception from GetFileSize() " + str(ex))
        return error

    def OpenSmallFile(self, path):
        '''Open files less than 200 MB, returns open file handle'''
        return self.osx_FS.open(path) #self.osx_FS.OpenSmallFile(path)

    def open(self, path):
        '''Open file and return a file-like object'''
        return self.osx_FS.open(path)

    def ExtractFile(self, tsk_path, destination_path):
        return self.osx_FS.CopyOutFile(tsk_path, destination_path)

    def _GetSize(self, entry):
        '''For file entry, gets logical file size, or 0 if error'''
        try:
            apfs_file_meta = self.osx_FS.GetFileMetadataByPath(path)
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
        apfs_file_meta = self.osx_FS.GetFileMetadataByPath(path)
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
        all_items = self.osx_FS.ListItemsInFolder(path)
        if all_items:
            if types_to_fetch == EntryType.FILES_AND_FOLDERS:
                items = [] #[dict(x) for x in all_items if x['type'] in ['File', 'Folder'] ]
                for x in all_items:
                    if x['type'] == 'File':
                        x['type'] = EntryType.FILES
                        items.append(dict(x))
                    elif x['type'] == 'Folder':
                        x['type'] = EntryType.FOLDERS
                        items.append(dict(x))

            elif types_to_fetch == EntryType.FILES:
                for x in all_items:
                    if x['type'] == 'File':
                        x['type'] = EntryType.FILES
                        items.append(dict(x))
            else: # Folders
                for x in all_items:
                    if x['type'] == 'Folder':
                        x['type'] = EntryType.FOLDERS
                        items.append(dict(x))
        return items

# TODO: Make this class more efficient, perhaps remove some extractions!
class MountedMacInfo(MacInfo):
    def __init__(self, root_folder_path, output_params):
        MacInfo.__init__(self, output_params)
        self.osx_root_folder = root_folder_path
        # TODO: if os.name == 'nt' and len (root_folder_path) == 2 and root_folder_path[2] == ':': self.osx_root_folder += '\\'
        self.is_windows = (os.name == 'nt')

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
            full_path = os.path.join(self.osx_root_folder, path)
        except Exception:
            log.error("Exception in BuildFullPath(), path was " + path_in_image)
            log.exception("Exception details")
        #log.debug("req={} final={}".format(path_in_image, full_path))
        return full_path

    def _get_creation_time(self, local_path):
        return os.stat(local_path).st_birthtime

    def GetFileMACTimes(self, file_path):
        file_path = self.BuildFullPath(file_path)
        times = { 'c_time':None, 'm_time':None, 'cr_time':None, 'a_time':None }
        try:
            times['c_time'] = None if self.is_windows else CommonFunctions.ReadUnixTime(os.path.getctime(file_path))
            times['m_time'] = CommonFunctions.ReadUnixTime(os.path.getmtime(file_path))
            times['cr_time'] = CommonFunctions.ReadUnixTime(os.path.getctime(file_path)) if self.is_windows \
                                else CommonFunctions.ReadUnixTime(self._get_creation_time(file_path))
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
                
        except Exception as ex:
            log.exception('')
            if str(ex).find('cannot find the path specified'):
                log.debug("Path not found : " + mounted_path)
            else:
                log.debug("Problem accessing path : " + mounted_path)
                log.debug("Exception details:\n", exc_info=True) #traceback.print_exc()
                log.error("Failed to get dir info!")
        return items

    def ReadSymLinkTargetPath(self, path):
        '''Returns the target file/folder's path from the sym link path provided'''
        target_path = ''
        try:
            if not self.is_windows:
                target_path = os.readlink(self.BuildFullPath(path))
            else:
                target_path = MacInfo.ReadSymLinkTargetPath(path)
        except:
            log.exception("Error resolving symlink : " + path)
        return target_path

    def OpenSmallFile(self, path):
        try:
            mounted_path = self.BuildFullPath(path)
            log.debug("Trying to open file : " + mounted_path)
            file = open(mounted_path, 'rb')
            return file
        except (IOError, OSError) as ex:
            log.exception("Error opening file : " + mounted_path)
        return None

    def ExtractFile(self, path_in_image, destination_path):
        source_file = self.OpenSmallFile(path_in_image)
        if source_file:
            size = self.GetFileSize(path_in_image)

            BUFF_SIZE = 1024 * 1024
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
            except (IOError, OSError) as ex:
                log.exception ("Failed to create file for writing at " + destination_path)
                return False 
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
            uid = str(stat.st_uid)
            gid = str(stat.st_gid)
            success = True
        except OSError as ex:
            log.error("Exception trying to get uid & gid for file " + path + ' Exception details: ' + str(ex))
        return success, uid, gid

    def _GetDarwinFoldersInfo(self):
        '''Gets DARWIN_*_DIR paths '''
        if not self.is_windows:
            # Unix/Linux or Mac mounted disks should preserve UID/GID, so we can read it normally from the files.
            MacInfo._GetDarwinFoldersInfo(self)
            return

        users_dir = self.ListItemsInFolder('/private/var/folders', EntryType.FOLDERS)
        # In /private/var/folders/  --> Look for --> xx/yyyyyy/C/com.apple.sandbox/sandbox-cache.db
        for unknown1 in users_dir:
            unknown1_name = unknown1['name']
            unknown1_dir = self.ListItemsInFolder('/private/var/folders/' + unknown1_name, EntryType.FOLDERS)
            for unknown2 in unknown1_dir:
                unknown2_name = unknown2['name']
                found_home = False
                found_user = False
                home = ''
                # This is yyyyyy folder
                path_to_sandbox_db = '/private/var/folders/' + unknown1_name + '/' + unknown2_name + '/C/com.apple.sandbox/sandbox-cache.db'
                if self.IsValidFilePath(path_to_sandbox_db) and self.GetFileSize(path_to_sandbox_db): # This does not always exist or it may be zero in size!
                    sqlite = SqliteWrapper(self)
                    try:
                        conn = sqlite.connect(path_to_sandbox_db)
                        try:
                            if CommonFunctions.TableExists(conn, 'entry'):
                                cursor = conn.execute("select params from entry where params like '%HOME%'") # This query is for El Capitan, table 'entry' does not exist on Yosemite
                                for row in cursor:
                                    if found_home: break
                                    try:
                                        data_dict = ast.literal_eval(str(row[0]))
                                        for item in data_dict:
                                            if item.upper().lstrip('_').rstrip('_') in ('HOME', 'HOME_DIR'):
                                                home = data_dict[item]
                                                if home != '':
                                                    found_home = True
                                                    break
                                    except Exception as ex:
                                        log.error ("Unknown error while processing query output")
                                        log.debug("Exception details:\n", exc_info=True) #traceback.print_exc()
                            #    cursor = conn.execute("select params from entry where params like '%USER%'") # This query is for El Capitan, table 'entry' does not exist on Yosemite
                            #     for row in cursor:
                            #         if found_user: break;
                            #         try:
                            #             data_dict = ast.literal_eval(str(row[0]))
                            #             for item in data_dict:
                            #                 #print ('item =' + item + ' -> ' + data_dict[item])
                            #                 if item.upper().lstrip('_').rstrip('_') in ('HOME', 'HOME_DIR'):
                            #                     home = data_dict[item]
                            #                     if home != '':
                            #                         found_home = True
                            #                         break;
                            #         except Exception as ex:
                            #             log.error ("Unknown error while processing query output")
                            #             log.debug("Exception details:\n", exc_info=True) #traceback.print_exc()   
                                     
                            elif CommonFunctions.TableExists(conn, 'params'):
                                cursor = conn.execute("select distinct value from params where key like '%HOME%'  and value not like ''") # This query is for Yosemite
                                for row in cursor:
                                    home = row[0]
                                    found_home = True
                                    break;
                            else:
                                log.critical ("Unknown database type or bad database! Could not get DARWIN_USER_* paths!")
                        except sqlite3.Error as ex:
                            log.error ("Failed to execute query on db : {} Error Details:{}".format(path_to_sandbox_db, str(ex)) )
                        conn.close()
                    except sqlite3.Error as ex:
                        log.error ("Failed to connect to db " + str(ex))
                #log.debug('found_home={} found_user={}  HOME={}'.format(found_home, found_user, home))
                if found_home:# and found_user:
                    user_info = UserInfo()
                    user_info.home_dir = home
                    user_info.DARWIN_USER_DIR       = '/private/var/folders/' + unknown1_name + '/' + unknown2_name + '/0'
                    user_info.DARWIN_USER_CACHE_DIR = '/private/var/folders/' + unknown1_name + '/' + unknown2_name + '/C'
                    user_info.DARWIN_USER_TEMP_DIR  = '/private/var/folders/' + unknown1_name + '/' + unknown2_name + '/T'
                    user_info._source = path_to_sandbox_db
                    self.users.append(user_info)

    def _GetUserInfo(self):
        if not self.is_windows:
            # Unix/Linux or Mac mounted disks should preserve UID/GID, so we can read it normally from the files.
            MacInfo._GetUserInfo(self)
            return

        # on windows
        self._GetDarwinFoldersInfos() # This probably does not apply to OSX < Mavericks !

        #Get user info from plists under: \private\var\db\dslocal\nodes\Default\users\<USER>.plist
        #TODO - make a better plugin that gets all user & group info
        users_path  = '/private/var/db/dslocal/nodes/Default/users'
        user_plists = self.ListItemsInFolder(users_path, EntryType.FILES)
        for plist_meta in user_plists:
            if plist_meta['size'] > 0:
                try:
                    f = self.OpenSmallFile(users_path + '/' + plist_meta['name'])
                    if f!= None:
                        plist = biplist.readPlist(f)
                        home_dir = self.GetArrayFirstElement(plist.get('home', ''))
                        if home_dir != '':
                            log.info('{} :  {}'.format(plist_meta['name'], home_dir))
                            if home_dir.startswith('/var/'): home_dir = '/private' + home_dir # in mac /var is symbolic link to /private/var
                            # find it in self.users which was populated by _GetDarwinFoldersInfo()
                            target_user = None
                            for user in self.users:
                                if user.home_dir == home_dir:
                                    target_user = user
                                    break
                            if target_user == None:
                                target_user = UserInfo()
                                self.users.append(target_user)
                            target_user.UID = str(self.GetArrayFirstElement(plist.get('uid', '')))
                            target_user.GID = str(self.GetArrayFirstElement(plist.get('gid', '')))
                            target_user.UUID = self.GetArrayFirstElement(plist.get('generateduid', ''))
                            target_user.home_dir = home_dir
                            target_user.user_name = self.GetArrayFirstElement(plist.get('name', ''))
                            target_user.real_name = self.GetArrayFirstElement(plist.get('realname', ''))
                            # There is also accountpolicydata which contains : creation time, failed logon time, failed count, ..
                        else:
                            log.error('Did not find \'home\' in ' + plist_meta['name'])
                except Exception as ex:
                    log.error ("Could not open plist " + plist_meta['name'] + " Exception: " + str(ex))
        #TODO: Domain user uid, gid?

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
        self.sqlite3 = sqlite3
        self.db_file_path = ''
        self.shm_file_path = ''
        self.wal_file_path = ''
        self.db_file_path_temp = ''
        self.shm_file_path_temp = ''
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
        self.shm_file_path_temp = os.path.join(self.folder_temp_path, os.path.basename(self.shm_file_path))
        self.wal_file_path_temp = os.path.join(self.folder_temp_path, os.path.basename(self.wal_file_path))

        self.db_temp_file = self.mac_info.ExtractFile(self.db_file_path, self.db_file_path_temp)
        if self.mac_info.IsValidFilePath(self.shm_file_path):
            self.shm_temp_file = self.mac_info.ExtractFile(self.shm_file_path, self.shm_file_path_temp)
        if self.mac_info.IsValidFilePath(self.wal_file_path):
            self.wal_temp_file = self.mac_info.ExtractFile(self.wal_file_path, self.wal_file_path_temp)
        return True

    def __getattr__(self, attr):
        if attr == 'connect': 
            def hooked(path):
                # Get 'database' variable
                self.db_file_path = path
                self.shm_file_path = path + "-shm"
                self.wal_file_path = path + "-wal"
                if self._ExtractFiles():
                    log.debug('Trying to extract and read db: ' + path)
                    result = self.sqlite3.connect(self.db_file_path_temp) # TODO -> Why are exceptions not being raised here when bad paths are sent?
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