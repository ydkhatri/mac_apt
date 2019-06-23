'''
   Copyright (c) 2017 Yogesh Khatri 

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the 
   terms of the MIT License.
   
'''

import biplist
import datetime
import logging
import os
import pytz
from enum import IntEnum
from sqlite3 import Error as sqlite3Error
from tzlocal import get_localzone

log = logging.getLogger('MAIN.HELPERS.COMMON')

class EntryType(IntEnum):
    FILES = 1
    FOLDERS = 2
    FILES_AND_FOLDERS = 3
    SYMLINKS = 4

class TimeZoneType(IntEnum):
    LOCAL = 1
    UTC = 2

class CommonFunctions:

    @staticmethod
    def GetLocalTimeFromUtcDate(d_utc):
        '''Returns a datetime object converted to local time'''
        local_timezone = get_localzone()
        #local_tz = get_localzone()
        return d_utc.replace(tzinfo=pytz.utc).astimezone(local_timezone)

    @staticmethod
    def ReadMacAbsoluteTime(mac_abs_time): # Mac Absolute time is time epoch beginning 2001/1/1
        '''Returns datetime object, or empty string upon error'''
        if mac_abs_time not in ( 0, None, ''):
            try:
                if isinstance(mac_abs_time, str):
                    mac_abs_time = float(mac_abs_time)
                if mac_abs_time > 0xFFFFFFFF: # more than 32 bits, this should be nano-second resolution timestamp (seen only in HighSierra)
                    return datetime.datetime(2001, 1, 1) + datetime.timedelta(seconds=mac_abs_time/1000000000.)
                return datetime.datetime(2001, 1, 1) + datetime.timedelta(seconds=mac_abs_time)
            except (ValueError, OverflowError) as ex:
                log.error("ReadMacAbsoluteTime() Failed to convert timestamp from value " + str(mac_abs_time) + " Error was: " + str(ex))
        return ''

    @staticmethod
    def ReadMacHFSTime(mac_hfs_time): # Mac HFS+ timestamp is time epoch beginning 1904/1/1
        '''Returns datetime object, or empty string upon error'''
        if mac_hfs_time not in ( 0, None, ''):
            try:
                if isinstance(mac_hfs_time, str):
                    mac_hfs_time = float(mac_hfs_time)
                return datetime.datetime(1904, 1, 1) + datetime.timedelta(seconds=mac_hfs_time)
            except (ValueError, OverflowError) as ex:
                log.error("ReadMacHFSTime() Failed to convert timestamp from value " + str(mac_hfs_time) + " Error was: " + str(ex))
        return ''

    @staticmethod
    def ReadAPFSTime(mac_apfs_time): # Mac APFS timestamp is nano second time epoch beginning 1970/1/1
        '''Returns datetime object, or empty string upon error'''
        if mac_apfs_time not in ( 0, None, ''):
            try:
                if isinstance(mac_apfs_time, str):
                    mac_apfs_time = float(mac_apfs_time)
                return datetime.datetime(1970, 1, 1) + datetime.timedelta(seconds=mac_apfs_time/1000000000.)
            except (ValueError, OverflowError) as ex:
                log.error("ReadAPFSTime() Failed to convert timestamp from value " + str(mac_apfs_time) + " Error was: " + str(ex))
        return ''

    @staticmethod
    def ReadUnixTime(unix_time): # Unix timestamp is time epoch beginning 1970/1/1
        '''Returns datetime object, or empty string upon error'''
        if unix_time not in ( 0, None, ''):
            try:
                if isinstance(unix_time, str):
                    unix_time = float(unix_time)
                return datetime.datetime(1970, 1, 1) + datetime.timedelta(seconds=unix_time)
            except (ValueError, OverflowError) as ex:
                log.error("ReadUnixTime() Failed to convert timestamp from value " + str(unix_time) + " Error was: " + str(ex))
        return ''

    @staticmethod
    def IntFromStr(string, base=10, error_val=0):
        integer = error_val
        try:
            integer = int(string, base)
        except ValueError: # Will go here if string is '' or contains non-digit characters
            if string == '' or string == None: pass
            else: log.exception('Could not convert string "{}" to int'.format(string))
        return integer

    @staticmethod
    def GetNextAvailableFileName(filepath):
        '''
        Checks for existing file and returns next available file name 
        by appending file name with a number. Ex: file01.jpg
        '''
        if os.path.exists(filepath):
            split = os.path.splitext(filepath)
            filepath_without_ext = split[0]
            ext = split[1]
            index = 1
            fullpath = filepath_without_ext + '{0:02d}'.format(index) + ext
            while (os.path.exists(fullpath)):
                index += 1
                fullpath = filepath_without_ext + '{0:02d}'.format(index) + ext
            filepath = fullpath
        return filepath

    @staticmethod
    def GetFileSize(file):
        '''Return size from an open file handle'''
        current_pos = file.tell()
        file.seek(0, 2) # Seek to end
        size = file.tell()
        file.seek(current_pos) # back to original position
        return size

    @staticmethod
    def TableExists(db_conn, table_name):
        '''Checks if a table with specified name exists in an sqlite db'''
        try:
            cursor = db_conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='%s'" % table_name)
            for row in cursor:
                return True
        except sqlite3Error as ex:
            log.error ("In TableExists({}). Failed to list tables of db. Error Details:{}".format(table_name, str(ex)) )
        return False
    
    @staticmethod
    def GetTableNames(db_conn):
        '''Retrieve all table names in an sqlite database'''
        try:
            cursor = db_conn.execute("SELECT group_concat(name) from sqlite_master WHERE type='table'")
            for row in cursor:
                return row[0]
        except sqlite3Error as ex:
            log.error ("Failed to list tables on db. Error Details: {}".format(str(ex)))
        return ''

    @staticmethod
    def ReadPlist(path):
        '''
            Safely open and read a plist.
            Returns a tuple (True/False, plist/None, "error_message")
        '''
        #log.debug("Trying to open plist file : " + path)
        error = ''
        try:
            with open(path, 'rb') as f:
                if f != None:
                    try:
                        #log.debug("Trying to read plist file : " + path)
                        plist = biplist.readPlist(f)
                        return (True, plist, '')
                    except biplist.InvalidPlistException as ex:
                        try:
                            # Perhaps this is manually edited or incorrectly formatted by a non-Apple utility  
                            # that has left whitespaces at the start of file before <?xml tag
                            f.seek(0)
                            data = f.read()
                            data = data.lstrip(" \r\n\t")
                            plist = biplist.readPlistFromString(data)
                            return (True, plist, '')
                        except biplist.InvalidPlistException as ex:
                            error = 'Could not read plist: ' + path + " Error was : " + str(ex)
                    except IOError as ex:
                        error = 'IOError while reading plist: ' + path + " Error was : " + str(ex)
                else:
                    error = 'Failed to open file'
        except IOError as ex:
            error = 'Exception from ReadPlist while trying to open file. Exception=' + str(ex)
        return (False, None, error)