'''
   Copyright (c) 2019 Yogesh Khatri 

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the 
   terms of the MIT License.

'''

import plugins.helpers.UnifiedLog.Lib as UnifiedLogLib
from plugins.helpers.UnifiedLog.tracev3_file import TraceV3
from plugins.helpers.UnifiedLog.virtual_file import VirtualFile
from plugins.helpers.UnifiedLog.virtual_file_system import VirtualFileSystem

from plugins.helpers.macinfo import *
from plugins.helpers.writer import *
import logging
import os
import posixpath
import platform

__Plugin_Name = "UNIFIEDLOGS"
__Plugin_Friendly_Name = "UnifiedLogs"
__Plugin_Version = "1.0"
__Plugin_Description = "Reads macOS unified logging logs from .tracev3 files"
__Plugin_Author = "Yogesh Khatri"
__Plugin_Author_Email = "yogesh@swiftforensics.com"

__Plugin_Modes = "MACOS"
__Plugin_ArtifactOnly_Usage = 'Provide the ".logarchive" folder as input to process.'

log = logging.getLogger('MAIN.' + __Plugin_Name) # Do not rename or remove this ! This is the logger object

#---- Do not change the variable names in above section ----#

writer = None
files_processed = 0
total_logs_processed = 0
data_type_info = [ ('File',DataType.TEXT),('DecompFilePos',DataType.INTEGER),('ContinuousTime',DataType.TEXT),('TimeUtc',DataType.DATE),
              ('Thread',DataType.INTEGER),('Type',DataType.TEXT),('ActivityID',DataType.INTEGER),('ParentActivityID',DataType.INTEGER),
              ('ProcessID',DataType.INTEGER),('EffectiveUID',DataType.INTEGER),('TTL',DataType.INTEGER),('ProcessName',DataType.TEXT),
              ('SenderName',DataType.TEXT),('Subsystem',DataType.TEXT),('Category',DataType.TEXT),
              ('SignpostName',DataType.TEXT),('SignpostInfo',DataType.TEXT),
              ('ImageOffset',DataType.INTEGER),('SenderUUID',DataType.TEXT),('ProcessImageUUID',DataType.TEXT),
              ('SenderImagePath',DataType.TEXT),('ProcessImagePath',DataType.TEXT),
              ('Message',DataType.TEXT)
                 ]

class MacAptFile(VirtualFile):
    def __init__(self, mac_info, path, filetype=''):
        super().__init__(path, filetype)
        self.mac_info = mac_info

    def open(self, mode='rb'):
        try:
            self.file_pointer = self.mac_info.Open(self.path)
            return self.file_pointer
        except (OSError, ValueError) as ex:
            if not self.mac_info.IsValidFilePath(self.path):
                log.error('Failed to open as file not found {}'.format(self.path))
                self.file_not_found = True
            else:
                log.exception('Failed to open file')
            self.is_valid = False
        return None

class MacAptVfs(VirtualFileSystem):
    def __init__(self, mac_info):
        super().__init__(MacAptFile)
        self.mac_info = mac_info
    
    def path_exists(self, path):
        '''Return True if file/folder specified by 'path' exists'''
        return self.mac_info.IsValidFilePath(path) or self.mac_info.IsValidFolderPath(path)

    def listdir(self, path):
        '''Return a list of all files/folders contained at given path'''
        dir_list = []
        detailed_list = self.mac_info.ListItemsInFolder(path)
        dir_list = [ x['name'] for x in detailed_list ]
        return dir_list

    def is_dir(self, path):
        '''Return True if path is a directory'''
        return self.mac_info.IsValidFolderPath(path)
    
    def path_join(self, path, *paths):
        '''Return a joined path, unix style seperated'''
        return posixpath.join(path, *paths)

    def get_virtual_file(self, path, filetype=''):
        '''Return a VirtualFile object'''
        return MacAptFile(self.mac_info, path, filetype)

class MacAptFileLocal(VirtualFile):
    def __init__(self, path, path_local, filetype=''):
        super().__init__(path, filetype)
        self.path_local = path_local

    def open(self, mode='rb'):
        original_path = self.path
        self.path= self.path_local
        ret = super().open(mode)
        self.path = original_path
        return ret

class MacAptVfsLocal(VirtualFileSystem):
    ''' Facilitates operations on local copies of files while maintaining 
        paths to actual files in image
    '''
    def __init__(self, base_path_image, base_path_local):
        '''Both paths must not have slashes at the end'''
        super().__init__(MacAptFileLocal) # In python3 --> super().__init__(MacAptFileLocal) 
        self.base_path_image = base_path_image
        self.base_path_local = base_path_local

    def ConstructLocalPath(self, image_path):
        if image_path.find(self.base_path_image) != 0:
            raise ValueError('Problem with logic image_path={}'.format(image_path))
        relative_path = image_path[len(self.base_path_image) + 1 :].split('/')
        local_path = os.path.join(self.base_path_local, *relative_path)
        #log.debug('{} --> {}'.format(image_path, local_path))
        return local_path

    def path_exists(self, path):
        '''Return True if file/folder specified by 'path' exists'''
        return super().path_exists(self.ConstructLocalPath(path))

    def listdir(self, path):
        '''Return a list of all files/folders contained at given path'''
        return super().listdir(self.ConstructLocalPath(path))

    def is_dir(self, path):
        '''Return True if path is a directory'''
        return super().is_dir(self.ConstructLocalPath(path))
    
    def path_join(self, path, *paths):
        '''Return a joined path, unix style seperated'''
        return posixpath.join(path, *paths)

    def get_virtual_file(self, path, filetype=''):
        '''Return a VirtualFile object'''
        path_local = self.ConstructLocalPath(path)
        return MacAptFileLocal(path, path_local, filetype)

def ProcessLogsList(logs, tracev3):
    '''
    logs  = filename, log_file_pos, ct, time, thread, log_type, act_id[-1], parentActivityIdentifier, 
                pid, euid, ttl, p_name, lib, sub_sys, cat,
                signpost_name, signpost_string, 
                imageOffset, imageUUID, processImageUUID, 
                senderImagePath, processImagePath,
                log_msg
    '''

    global writer
    global total_logs_processed

    # Convert UUIDs to string and dates to human-readable for writing to db
    for log in logs:
        log[3]  = CommonFunctions.ReadAPFSTime(log[3])
        log[18] = str(log[18])
        log[19] = str(log[19])
    try:
        writer.WriteRows(logs)
        total_logs_processed += len(logs)
    except sqlite3.Error as ex:
        log.exception ("Failed to write log row data to db")

def RecurseProcessLogFiles(vfs, input_path, ts_list, uuidtext_folder_path, large_data_cache, caches):
    '''Recurse the folder located by input_path and process all .traceV3 files'''
    global files_processed
    files = vfs.listdir(input_path)
    input_path = input_path.rstrip('/')
    for file_name in files:
        input_file_path = input_path + '/' + file_name
        if file_name.lower().endswith('.tracev3') and not file_name.startswith('._'):
            log.info("Processing tracev3 file - " + input_file_path)
            v_file = vfs.get_virtual_file(input_file_path, 'traceV3')
            TraceV3(vfs, v_file, ts_list, uuidtext_folder_path, large_data_cache, caches).Parse(ProcessLogsList)
            files_processed += 1
        elif vfs.is_dir(input_file_path):
            RecurseProcessLogFiles(vfs, input_file_path, ts_list, uuidtext_folder_path, large_data_cache, caches)
        else:
            log.debug('Not a log file:' + input_file_path)

def CopyOutputParams(output_params):
    '''Creates and returns a copy of MacInfo.OutputParams object'''
    op_copy = OutputParams()
    op_copy.output_path = output_params.output_path
    op_copy.write_csv = output_params.write_csv
    op_copy.write_sql = output_params.write_sql
    op_copy.write_xlsx = output_params.write_xlsx
    op_copy.xlsx_writer = output_params.xlsx_writer
    op_copy.output_db_path = output_params.output_db_path
    op_copy.export_path = output_params.export_path
    op_copy.export_log_sqlite = output_params.export_log_sqlite
    op_copy.timezone = output_params.timezone
    return op_copy

def CreateSqliteDb(output_path, out_params):
    try:
        sqlite_path = os.path.join(output_path, "UnifiedLogs.db")
        log.info("Creating sqlite db for unified logs @ {}".format(sqlite_path))
        out_params.output_db_path = SqliteWriter.CreateSqliteDb(sqlite_path)
        return True
    except sqlite3.Error as ex:
        log.error('Sqlite db could not be created at : ' + sqlite_path)
        log.exception('Exception occurred when trying to create Sqlite db')
    return False

def SetFileDescriptorLimit(new_limit=2048):
    if platform.system() == 'Windows':
        import ctypes
        if ctypes.cdll.msvcrt._getmaxstdio() < new_limit:
            log.debug('Current the maximum number of file handlers: {}'.format(ctypes.cdll.msvcrt._getmaxstdio()))
            if ctypes.cdll.msvcrt._setmaxstdio(new_limit) < 0:
                log.error('Cannot set the maximum number of file handlers.')
                return False
            log.debug('Set the maximum number of file handlers: {}'.format(new_limit))
    elif platform.system() in ('Linux', 'Darwin'):
        import resource
        soft_limit, hard_limit = resource.getrlimit(resource.RLIMIT_NOFILE)
        log.debug('Current file descriptor limit: Soft Limit = {}, Hard Limit = {}'.format(soft_limit, hard_limit))
        if soft_limit < new_limit:
            try:
                resource.setrlimit(resource.RLIMIT_NOFILE, (new_limit, hard_limit))
                log.debug('Set file descriptor limit: Soft Limit = {}, Hard Limit = {}'.format(new_limit, hard_limit))
            except ValueError as err:
                log.error('Cannot set file descriptor limit.')
                return False
    else:
        log.error('Cannot determine the platform system.')
        return False

    return True

def Plugin_Start(mac_info):
    '''Main Entry point function for plugin'''
    global writer
    global files_processed
    global total_logs_processed

    if not SetFileDescriptorLimit():
        return

    version_info = mac_info.GetVersionDictionary()
    if version_info['major'] == 10:
        if (version_info['minor'] < 12):
            log.info('Unified Logging is not present in this version of macOS ({})'.format(mac_info.os_version))
            return
        elif (version_info['minor'] == 12) and (version_info['micro'] == 0):
            log.info('Unified Logging in macOS 10.12.0 is not yet supported!')
            return
    elif version_info['major'] > 10:
        pass
    else:
        log.info('Unified Logging is not present in this version of macOS ({})'.format(mac_info.os_version))
        return

    files_processed = 0
    traceV3_path = '/private/var/db/diagnostics'
    uuidtext_folder_path = '/private/var/db/uuidtext'

    if mac_info.IsValidFolderPath(traceV3_path) and mac_info.IsValidFolderPath(uuidtext_folder_path):
        mac_info.ExportFolder(traceV3_path, __Plugin_Name, True) 
        mac_info.ExportFolder(uuidtext_folder_path, __Plugin_Name, True)
    else:
        log.info('Unified Logging folders not found!')
        return

    vfs = MacAptVfsLocal('/private/var/db', os.path.join(mac_info.output_params.export_path, __Plugin_Name)) #MacAptVfs(mac_info)

    #Read uuidtext & dsc files
    caches = UnifiedLogLib.CachedFiles(vfs)
    caches.ParseFolder(uuidtext_folder_path)
    log.debug('Cached DSC count = {}'.format(len(caches.cached_dsc)))
    
    timesync_folder = traceV3_path + "/timesync"
    ts_list = []
    UnifiedLogLib.ReadTimesyncFolder(timesync_folder, ts_list, vfs)
    
    try:
        writer = None
        output_path = mac_info.output_params.output_path
        out_params = CopyOutputParams(mac_info.output_params)
        out_params.write_xlsx = False
        out_params.write_csv = False
        out_params.write_sql = True
        if CreateSqliteDb(output_path, out_params):
            writer = DataWriter(out_params, "UnifiedLogs", data_type_info, traceV3_path)
            large_data_cache = {}
            RecurseProcessLogFiles(vfs, traceV3_path, ts_list, uuidtext_folder_path, large_data_cache, caches)
    except:
        log.exception('')
    if writer:
        writer.FinishWrites()
    if files_processed > 0:
        log.info('{} tracev3 file{} processed'.format(files_processed, 's' if files_processed > 1 else ''))
        log.info('{} log{} entries written to db'.format(total_logs_processed, 's' if total_logs_processed > 1 else ''))
    else:
        log.info('No tracev3 files found')


if __name__ == '__main__':
    print ("This plugin is a part of a framework and does not run independently on its own!")