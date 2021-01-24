'''
   Copyright (c) 2017 Yogesh Khatri 

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the 
   terms of the MIT License.
   
'''

import biplist
import datetime
import logging
import nska_deserialize as nd
import os
import plistlib
import re
import sqlite3
import sys
#import pytz
from enum import IntEnum
from io import BytesIO
from sqlite3 import Error as sqlite3Error
#from tzlocal import get_localzone

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

    # @staticmethod
    # def GetLocalTimeFromUtcDate(d_utc):
    #     '''Returns a datetime object converted to local time'''
    #     local_timezone = get_localzone()
    #     #local_tz = get_localzone()
    #     return d_utc.replace(tzinfo=pytz.utc).astimezone(local_timezone)

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
            except (ValueError, OverflowError, TypeError) as ex:
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
            except (ValueError, OverflowError, TypeError) as ex:
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
            except (ValueError, OverflowError, TypeError) as ex:
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
            except (ValueError, OverflowError, TypeError) as ex:
                log.error("ReadUnixTime() Failed to convert timestamp from value " + str(unix_time) + " Error was: " + str(ex))
        return ''

    @staticmethod
    def ReadWindowsFileTime(file_time): # File time is time epoch beginning 1601/1/1
        '''Returns datetime object, or empty string upon error'''
        if file_time not in ( 0, None, ''):
            try:
                if isinstance(file_time, str):
                    file_time = float(file_time)
                return datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=file_time/10.)
            except (ValueError, OverflowError, TypeError) as ex:
                log.error("ReadWindowsFileTime() Failed to convert timestamp from value " + str(file_time) + " Error was: " + str(ex))
        return ''

    @staticmethod
    def ReadChromeTime(chrome_time): # Chrome time is time epoch beginning 1601/1/1 but in micro-seconds
        '''Returns datetime object, or empty string upon error'''
        if chrome_time not in ( 0, None, ''):
            try:
                if isinstance(chrome_time, str):
                    chrome_time = float(chrome_time)
                return datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=chrome_time)
            except (ValueError, OverflowError, TypeError) as ex:
                log.error("ReadChromeTime() Failed to convert timestamp from value " + str(chrome_time) + " Error was: " + str(ex))
        return ''

    @staticmethod
    def IntFromStr(string, base=10, error_val=0):
        integer = error_val
        try:
            integer = int(string, base)
        except ValueError: # Will go here if string is '' or contains non-digit characters
            if string == '' or string == None: pass
            else: log.exception('Could not convert string "{}" to int'.format(string))
        except TypeError:
            log.exception('Invalid type passed to IntFromStr()')
        return integer

    @staticmethod
    def GetNextAvailableFileName(filepath):
        '''
        Checks for existing file and returns full path with next available file name 
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
    def SanitizeName(filename, replacement_char='_'):
        '''
        Removes illegal characters (for windows) from the string passed.
        '''
        return re.sub(r'[\\/*?:"<>|\'\r\n]', replacement_char, filename)

    @staticmethod
    def GetFileSize(file):
        '''Return size from an open file handle'''
        current_pos = file.tell()
        file.seek(0, 2) # Seek to end
        size = file.tell()
        file.seek(current_pos) # back to original position
        return size

    @staticmethod
    def open_sqlite_db_readonly(path):
        '''Opens an sqlite db in read-only mode, so original db (and -wal/journal are intact)'''
        path = os.path.abspath(path)
        if path.find('\\') >= 0: # windows path
            if path.startswith('\\\\?\\UNC\\'): # UNC long path
                path = "%5C%5C%3F%5C" + path[4:]
            elif path.startswith('\\\\?\\'):    # normal long path
                path = "%5C%5C%3F%5C" + path[4:]
            elif path.startswith('\\\\'):       # UNC path
                path = "%5C%5C%3F%5C\\UNC" + path[1:]
            else:                               # normal path
                path = "%5C%5C%3F%5C" + path
        return sqlite3.connect (f"file:{path}?mode=ro", uri=True)

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
    def ColumnExists(db_conn, table_name, col_name):
        '''Checks if a specific column exists in given table in an sqlite db'''
        try:
            cursor = db_conn.execute(f'SELECT name from PRAGMA_table_info("{table_name}") where name like "{col_name}"')
            for row in cursor:
                return True
        except sqlite3Error as ex:
            log.error ("In ColumnExists({}, {}). Failed to list tables of db. Error Details:{}".format(table_name, col_name, str(ex)) )
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
    def replace_all_hex_int_with_int(xml_text):
        '''
            Returns string replacing all instances of hex integers
            in xml to their decimal equivalent 
            like \<integer>0x55\</integer>
            with \<integer>85\</integer>
            
            Exceptions: ValueError (for invalid int conversions)
        '''
        pattern = re.compile("<integer>0x[0-9a-fA-F]*</integer>")
        search_from = 0
        match = pattern.search(xml_text, search_from)
        while match:
            hex_int = xml_text[match.start() + 11:match.end()-10]
            dec_int = str(int(hex_int, 16))
            
            xml_text = xml_text[:match.start() + 9] + dec_int + xml_text[match.end()-10:]
            search_from = match.start() + 9 + len(dec_int) + 10
            match = pattern.search(xml_text, search_from)
        return xml_text

    @staticmethod
    def ReadPlist(path_or_file, deserialize=False):
        '''
            Safely open and read a plist.
            Returns a tuple (True/False, plist/None, "error_message")
        '''
        #log.debug("Trying to open plist file : " + path)
        error = ''
        path = ''
        plist = None
        f = None
        if isinstance(path_or_file, str):
            path = path_or_file
            try:
                f = open(path, 'rb')
            except OSError as ex:
                error = 'Could not open file, Error was : ' + str(ex)
        else: # its a file
            f = path_or_file

        if f:
            if deserialize:
                try:
                    plist = nd.deserialize_plist(f)
                    f.close()
                    return (True, plist, '')
                except (nd.DeserializeError, nd.biplist.NotBinaryPlistException, nd.biplist.InvalidPlistException,
                        plistlib.InvalidFileException, nd.ccl_bplist.BplistError, ValueError, TypeError, 
                        OSError, OverflowError) as ex:
                    error = 'Error deserializing plist: ' + path + " Error was : " + str(ex)
                    f.close()
                    return (False, plist, error)
            else:
                try:
                    if sys.version_info >= (3, 9):
                        plist = plistlib.load(f)
                    else:
                        plist = biplist.readPlist(f)
                    return (True, plist, '')
                except (biplist.InvalidPlistException, plistlib.InvalidFileException) as ex:
                    try:
                        # Check for XML format
                        f.seek(0)
                        file_start_bytes = f.read(10)
                        if file_start_bytes.find(b'?xml') > 0:
                            # Perhaps this is manually edited or incorrectly formatted  
                            # that has left whitespaces at the start of file before <?xml tag
                            # Or it's a bigSur (11.0) plist with hex integers
                            f.seek(0)
                            data = f.read().decode('utf8', 'ignore')
                            f.close()
                            data = CommonFunctions.replace_all_hex_int_with_int(data) # Fix for BigSur plists with hex ints
                            data = data.lstrip(" \r\n\t").encode('utf8', 'backslashreplace')

                            if sys.version_info >= (3, 9):
                                plist = plistlib.loads(data, fmt=plistlib.FMT_XML)
                            else:
                                plist = biplist.readPlistFromString(data)
                            return (True, plist, '')
                        else:
                            error = 'Not a plist! ' + path + " Error was : " + str(ex)
                    except (biplist.InvalidPlistException, ValueError, plistlib.InvalidFileException) as ex:
                        error = 'Could not read plist: ' + path + " Error was : " + str(ex)
        return (False, None, error)