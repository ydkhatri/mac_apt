'''
   Copyright (c) 2017 Yogesh Khatri 

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the 
   terms of the MIT License.
   
'''

import binascii
import collections
import csv
import jsonlines
import logging
import os
import sqlite3
import sys
import xlsxwriter

from enum import IntEnum
from plugins.helpers.common import *

log = logging.getLogger('MAIN.HELPERS.WRITER')

class DataType(IntEnum):
    INTEGER = 1 # Whole Numbers
    REAL    = 2 # Floating point numbers
    TEXT    = 3 # Strings and Text Dates
    BLOB    = 4 # Binary
    DATE    = 5 # datetime object, not a native SQLite type, will be stored as TEXT

class DataWriter:

    def FinishWrites(self):
        '''This must be called to properly close files'''
        if self.csv: self.csv_writer.Cleanup()
        if self.tsv: self.tsv_writer.Cleanup()
        if self.sql: self.sql_writer.CloseDb()
        if self.jsonl: self.jsonl_writer.Cleanup()

    def __init__(self, output_params, name, column_info, artifact_source=''):
        '''
        output_params is OutputParams object 
        column_info is an 'ordered' dictionary that defines output column names and types
         # column_info must be an OrderedDict type or a list of tuples (see below).
        column_info = [ ('Name1', DataType.TEXT), ('Name2', DataType.BLOB), ..]
        New: It is now possible to send special DB keywords for the create statement by passing it as a tuple
        into the DataType field. Tuple must be in form (DataType.xx, "KEYWORD"). See example below-
        column_info = [ ('Name1', DataType.TEXT), ('ID', (DataType.INTEGER, "PRIMARY KEY AUTOINCREMENT") ), ..]
        CAUTION: If using AUTOINCREMENT, don't pass that in the writer data to write list!
        name is suggested name for either table name and/or file name
        artifact_source is the source of an artifact (full path to source_files)
        If artifact_source is included, it will be put into a separate table in sqlite. 
        Perhaps, we can put this in a seperate .Info.txt file too for csv writer, or
        just log it!
        '''
        self.output_path = output_params.output_path
        self.name = name
        self.row_count = 0
        self.csv = False
        self.csv_writer = None
        self.tsv = False
        self.tsv_writer = None
        self.jsonl = False
        self.jsonl_writer = None
        self.xlsx = False
        self.xlsx_writer = None
        self.sql = False
        self.sql_writer = None
        self.sql_db_path = output_params.output_db_path
        self.PYTHON_VER = sys.version_info.major
        self.cols_with_blobs = None

        if output_params.write_sql:
            self.sql = True
            self.sql_writer = SqliteWriter()
            self.sql_writer.OpenSqliteDb(self.sql_db_path)
        if output_params.write_csv:
            self.csv = True
            self.csv_writer = CsvWriter()
            self.csv_writer.CreateCsvFile(os.path.join(self.output_path, name + ".csv"))
        if output_params.write_tsv:
            self.tsv = True
            self.tsv_writer = CsvWriter(is_tsv=True)
            self.tsv_writer.CreateCsvFile(os.path.join(self.output_path, name + ".tsv"))
        if output_params.write_jsonl:
            self.jsonl = True
            self.jsonl_writer = JsonlWriter()
            self.jsonl_writer.CreateJsonlFile(os.path.join(self.output_path, name + ".jsonl"))
        if output_params.write_xlsx:
            self.xlsx = True
            self.xlsx_writer = output_params.xlsx_writer

        self.column_info = collections.OrderedDict(column_info)
        self.column_info_extra_keywords = {} #key=index, value=keyword
        i = 0
        for k, v in self.column_info.items():
            if isinstance(v, tuple) or isinstance(v, list):
                column_info[k] = v[0]
                self.column_info_extra_keywords[i] = v[1]
            i += 1
        self.cols_with_blobs = None # [ ('Col_Name1', Index1), ('Col_Name2', Index2)  ] # Name not needed TODO: REMOVE name
        self.IdentifyColumnsWithBlobs()
        self.num_columns = len(self.column_info)
  
    def IdentifyColumnsWithBlobs(self):
        '''Create a list of names and indexes of columns with type BLOB'''
        i = 0
        for col, data_type in self.column_info.items():
            #if type(data_type) == tuple: data_type = data_type[0] # if col_width is specified
            if data_type == DataType.BLOB:
                if self.cols_with_blobs == None:
                    self.cols_with_blobs = []
                self.cols_with_blobs.append([col, i])
            i += 1

    def WriteHeaders(self):
        '''Writes Headings for csv/tsv/jsonl, creates Table for sqlite, creates Sheet for XLSX'''
        if self.csv:
            self.csv_writer.WriteRow(self.column_info)
        if self.tsv:
            self.tsv_writer.WriteRow(self.column_info)
        if self.sql:
            self.sql_writer.CreateTable(self.column_info, self.name, self.column_info_extra_keywords)
        if self.jsonl:
            self.jsonl_writer.AddHeaders(self.column_info)
        if self.xlsx:
            self.xlsx_writer.CreateSheet(self.name)
            self.xlsx_writer.AddHeaders(self.column_info)

    def BlobToHex(self, blob):
        '''Convert binary data to hex text'''
        s = ''
        if blob:
            s = binascii.hexlify(blob).decode("ascii").upper()
        return s

    def WriteRow(self, row):
        '''Write a single row of data, 'row' can be either a list or dictionary'''
        if self.row_count == 0: #Write Header row
            self.WriteHeaders()
        row_type = type(row)
        if not (row_type in (dict, list)):
            raise ValueError("WriteRow() can only handle list or dictionary, passed variable was " + str(row_type))
            return
        if row_type == list:
            if len(row) != self.num_columns:
                raise ValueError('Count of data items in row does not match Number of columns!')
            if self.sql: # This routine does NOT modify row, we create a list copy
                if self.cols_with_blobs:
                    row_copy = list(row)
                    for col_name, index in self.cols_with_blobs:
                        row_copy[index] = bytes(row_copy[index])
                    self.sql_writer.WriteRow(row_copy)
                else:
                    self.sql_writer.WriteRow(row)
            if self.csv or self.tsv or self.jsonl or self.xlsx: # This routine modifies row
                if self.cols_with_blobs:
                    for col_name, index in self.cols_with_blobs:
                        row[index] = self.BlobToHex(row[index])
                if self.csv: self.csv_writer.WriteRow(row)
                if self.tsv: self.tsv_writer.WriteRow(row)
                if self.jsonl: self.jsonl_writer.WriteRow(row)
                if self.xlsx: self.xlsx_writer.WriteRow(row)
        else: # Must be Dictionary!
            #list_to_write = [ row.get(col, None if self.column_info[col] in (DataType.INTEGER, DataType.BLOB, DataType.REAL) else '') \
            #                     for col in self.column_info ]
            list_to_write = [ row.get(col, '') for col in self.column_info ]
            if self.sql: 
                if self.cols_with_blobs:
                    row_copy = list(list_to_write)
                    for col_name, index in self.cols_with_blobs:
                        row_copy[index] = bytes(row_copy[index]) if row_copy[index] else b''
                    self.sql_writer.WriteRow(row_copy)
                else: self.sql_writer.WriteRow(list_to_write)
            if self.csv or self.tsv or self.jsonl or self.xlsx:
                if self.cols_with_blobs:
                    for col_name, index in self.cols_with_blobs:
                        list_to_write[index] = self.BlobToHex(list_to_write[index])
                if self.csv: self.csv_writer.WriteRow(list_to_write)
                if self.tsv: self.tsv_writer.WriteRow(list_to_write)
                if self.jsonl: self.jsonl_writer.WriteRow(list_to_write)
                if self.xlsx: self.xlsx_writer.WriteRow(list_to_write)
        self.row_count += 1

    def WriteRows(self, rows):
        '''Write multiple rows at once, 'rows' must be a 'list' of lists/dicts'''
        row_len = len(rows)
        if row_len == 0: # Nothing to write!
            return
        if self.row_count == 0: #Write Header row
            self.WriteHeaders()
        row_type = type(rows[0])
        if not (row_type in (dict, list)):
            raise ValueError("WriteRows() can only handle list or dictionary, passed variable was " + str(row_type))
            return
        if row_type == list: 
            if self.sql:
                if self.cols_with_blobs:
                    rows_copy = [list(k) for k in rows]
                    for row_copy in rows_copy:
                        for col_name, index in self.cols_with_blobs:
                            row_copy[index] = bytes(row_copy[index]) if row_copy[index] else b''
                    self.sql_writer.WriteRows(rows_copy)
                else:
                    self.sql_writer.WriteRows(rows)
            if self.csv or self.tsv or self.jsonl or self.xlsx: # This routine modifies rows
                if self.cols_with_blobs:
                    for row in rows:
                        for col_name, index in self.cols_with_blobs:
                            row[index] = self.BlobToHex(row[index])
                if self.csv: self.csv_writer.WriteRows(rows)
                if self.tsv: self.tsv_writer.WriteRows(rows)
                if self.jsonl: self.jsonl_writer.WriteRows(rows)
                if self.xlsx: self.xlsx_writer.WriteRows(rows)
        else: # Must be Dictionary!
            list_to_write = []
            for row in rows:
                #list_row = [ row.get(col, None if self.column_info[col] in (DataType.INTEGER, DataType.BLOB, DataType.REAL) else '') \
                #                 for col in self.column_info ]
                # NOTES: For csv/tsv , everything not present can be '', otherwise 'None' is printed
                #        For sql, this works too, however None is more correct.. revisit this later.
                list_row = [ row.get(col, '') for col in self.column_info ]
                list_to_write.append(list_row)
            if self.sql:
                if self.cols_with_blobs:
                    rows_copy = [list(k) for k in list_to_write]
                    for row_copy in rows_copy:
                        for col_name, index in self.cols_with_blobs:
                            row_copy[index] = bytes(row_copy[index])
                    self.sql_writer.WriteRows(rows_copy)
                else:
                    self.sql_writer.WriteRows(list_to_write)
            if self.csv or self.tsv or self.jsonl or self.xlsx: # This routine modifies list_to_write
                if self.cols_with_blobs:
                    for list_row in list_to_write:
                        for col_name, index in self.cols_with_blobs:
                            list_row[index] = self.BlobToHex(list_row[index])           
                if self.csv: self.csv_writer.WriteRows(list_to_write)
                if self.tsv: self.tsv_writer.WriteRows(list_to_write)
                if self.jsonl: self.jsonl_writer.WriteRows(list_to_write)
                if self.xlsx: self.xlsx_writer.WriteRows(list_to_write)
        self.row_count += row_len

class SqliteWriter:
    def __init__(self, asynchronous=False):
        self.filepath = ''
        self.conn = None
        self.asynchronous = asynchronous # Async mode is quite limited, only works for db with single table!
        self.async_buffer = []
        self.async_buffer_max = 100000
        self.table_names = []
        self.table_name  = ''
        self.column_infos = []
        self.column_info  = None
        self.executemany_querys = []
        self.executemany_query  = ''
    
    def OpenSqliteDb(self, filepath):
        '''Open an existing db or create it'''
        self.filepath = filepath
        try:
            self.conn = sqlite3.connect(self.filepath)
            #self.conn.execute('PRAGMA SYNCHRONOUS=OFF;') # slightly faster!
        except (OSError, sqlite3.Error) as ex:
            log.error('Failed to open/create sqlite db at path {}'.format(filepath))
            log.exception('Error details')
            raise ex

    @staticmethod
    def CreateSqliteDb(filepath):
        #Plugins MUST NOT call this function.
        filepath = CommonFunctions.GetNextAvailableFileName(filepath)
        conn = sqlite3.connect(filepath)
        conn.close()
        return filepath

    def GetNextAvailableTableName(self, name):
        '''Get unused table name by appending _xx where xx=00-99'''
        index = 1
        new_name = name + '_{0:02d}'.format(index)
        while (CommonFunctions.TableExists(self.conn, new_name)):
            index += 1
            new_name = name + '_{0:02d}'.format(index)
        return new_name

    def RunQuery(self, query, writing=False, return_named_objects=False):
        '''Execute a query on the database and return results.
           If this is an INSERT/UPDATE/CREATE query, then set writing=true 
           which internally calls commit().
           Return value is tuple (success, cursor, error_message)
        '''
        cursor = None
        success = False
        error_message = ''
        try:
            if return_named_objects: 
                self.conn.row_factory = sqlite3.Row
            cursor = self.conn.cursor()
            cursor = self.conn.execute(query)
            if writing: 
                self.conn.commit()
            success = True
        except sqlite3.Error as ex:
            log.error('Query execution error, query was - ' + query)
            error_message = str(ex)

        return success, cursor, error_message

    def _CraftCreateStatement(self, table_name, column_info_extra_keywords):
        '''
           Generate a query statement
           - column_info_extra_keywords is a dictionary key=column number, value=string
        '''
        i = 0
        query = 'CREATE TABLE "' + self.table_name + '" ('
        for k,v in self.column_info.items():
            query += '"{}" {}'.format(k,v.name if v != DataType.DATE else 'TEXT')
            if column_info_extra_keywords:
                extra_keyword = column_info_extra_keywords.get(i, '')
                query += ' ' + extra_keyword
            query += ','
            i += 1
        if query[-1] == ',':
            query = query[:-1]
        query += ')'
        return query

    def _CraftExecuteManyQuery(self, table_name, column_info, column_info_extra_keywords):
        executemany_query = 'INSERT INTO "' + table_name + '" VALUES (?' + ',?'*(len(column_info) - 1) + ')'
        return executemany_query

    def CreateTable(self, column_info, table_name, column_info_extra_keywords=None):
        '''
           Creates table with given name, if table exists, 
           a new name is selected (name_xx)
           - 'column_info' must be OrderedDict
        '''
        if column_info_extra_keywords == None:
            column_info_extra_keywords = {}
            i = 0
            for k, v in column_info.items():
                if isinstance(v, tuple) or isinstance(v, list):
                    column_info[k] = v[0]
                    column_info_extra_keywords[i] = v[1]
                i += 1
        cursor = None
        query = ''
        try:
            self.table_name = table_name
            self.column_info = column_info
            #self.CleanColumnInfo(column_info)
            cursor = self.conn.cursor()
            query = self._CraftCreateStatement(table_name, column_info_extra_keywords)
            cursor.execute(query)
            self.conn.commit()
            self.executemany_query = self._CraftExecuteManyQuery(table_name, column_info, column_info_extra_keywords)
        except sqlite3.Error as ex:
            if  str(ex).find('table "{}" already exists'.format(table_name)) >= 0:
                log.info(str(ex))
                self.table_name = self.GetNextAvailableTableName(table_name)
                log.info('Changing tablename to {}'.format(self.table_name))
                try:
                    cursor = self.conn.cursor()
                    query = self._CraftCreateStatement(self.table_name, column_info_extra_keywords)
                    cursor.execute(query)
                    self.conn.commit()
                    self.executemany_query = self._CraftExecuteManyQuery(self.table_name, column_info, column_info_extra_keywords)
                    return
                except sqlite3.Error as ex:
                    log.error(str(ex))
                    log.exception("error creating table " + self.table_name)
                    raise ex
                    return
            log.error(str(ex))
            log.exception("error creating table " + self.table_name)
            raise ex
        self.table_names.append(self.table_name)
        self.column_infos.append(self.column_info)
        self.executemany_querys.append(self.executemany_query)
        return self.table_name

    def WriteRow(self, row, table_name=None):
        '''Write row to db, where row is tuple or list (in order). 
           If a table_name is supplied, it will use the query (column_info) for 
           that table, else it will use the last created table's column_info
        '''
        self.WriteRows([row], table_name)

    def WriteRows(self, rows, table_name=None):
        '''Write rows to db, where row is tuple or list of 'tuple or list' (in order).
           If a table_name is supplied, it will use the query (column_info) for 
           that table, else it will use the last created table's column_info
        '''
        if self.asynchronous:
            self.async_buffer.extend(rows)
            if len(self.async_buffer) <= self.async_buffer_max:
                return
            else:
                rows = self.async_buffer
                self.async_buffer = []
        try:
            cursor = self.conn.cursor()
            query = self.executemany_query
            if table_name:
                try:
                    index = self.table_names.index(table_name)
                    query = self.executemany_querys[index]
                except sqlite3.Error as ex:
                    log.exception("Could not find table name {}".format(table_name))
                    raise ex
            cursor.executemany(query, rows)
            self.conn.commit()
        except (sqlite3.Error, OverflowError) as ex:
            log.error(str(ex))
            log.exception("error writing to table " + table_name if table_name else self.table_name)
            #raise ex

    def CloseDb(self):
        if self.conn != None:
            if self.async_buffer:
                self.async_buffer_max = 0 # to trigger write!
                self.WriteRows(list())
            self.conn.close()
            self.conn = None
    
    def __del__(self):
        if self.conn != None:
            raise ValueError('SqliteWriter destructor, Dear coder, you forgot to close db.')

class CsvWriter:
    def __init__(self, delete_empty_files=True, is_tsv=False):
        self.filepath = ''
        self.is_tsv = is_tsv
        if is_tsv:
            self.codec = 'utf-16'
        else:
            self.codec = 'utf-8'
            self.pycsv_writer = None
        self.file_handle = None
        self.delete_empty_files = delete_empty_files # perhaps a useful option?
    
    def CreateCsvFile(self, filepath):
        '''
        Creates a csv/tsv file with suggested name, 
        if name is not available, get the next available name
        eg: name01.csv or name02.csv or ..
        '''
        self.filepath = CommonFunctions.GetNextAvailableFileName(filepath)
        try:
            self.file_handle = open(self.filepath, 'w', encoding=self.codec, newline='')
            if not self.is_tsv:
                self.pycsv_writer = csv.writer(self.file_handle, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL, dialect='excel')
        except (OSError, csv.Error) as ex:
            log.error('Failed to create {} file at path {}'.format('tsv' if self.is_tsv else 'csv', self.filepath))
            log.exception('Error details')
            raise ex

    def SanitizeForTsv(self, row):
        '''Remove \r \n \t from each item to write'''
        safe_list = []
        for item in row:
            safe_str = str(item)
            try:
                safe_str = safe_str.replace('\r\n', ',').replace('\r', ',').replace('\n', ',').replace('\t', ' ')
            except ValueError as ex:
                log.exception()
            safe_list.append(safe_str)
        return safe_list

    def WriteRowTsv(self, row):
        row = self.SanitizeForTsv(row)
        self.file_handle.write("\t".join(map(str,row)) + ('\r\n'))

    def WriteRowCsv(self, row):
        try:
            self.pycsv_writer.writerow(row)
        except (OSError, csv.Error) as ex:
            log.exception('Failed to write csv row ' + str(row))
    
    def WriteRow(self, row):
        if self.is_tsv:
            self.WriteRowTsv(row)
        else:
            self.WriteRowCsv(row)

    def WriteRows(self, rows):
        if self.is_tsv:
            for row in rows:
                self.WriteRowTsv(row)
        else:
            try:
                self.pycsv_writer.writerows(rows)
            except (OSError, csv.Error) as ex:
                log.exception('Failed to write csv rows')

    def GetFileSize(self):
        '''Return csv/tsv's filesize or None if error'''
        try:
            return os.path.getsize(self.filepath)
        except OSError as ex:
            log.warning('Failed to retrieve file size for {}: {}'.format('TSV' if self.is_tsv else 'CSV',self.filepath))
        return None
    
    def Cleanup(self):
        if self.file_handle != None:
            self.file_handle.close()
            self.file_handle = None
        if self.delete_empty_files:
            file_size = self.GetFileSize()
            if file_size != None and file_size == 0:
                log.debug("Deleting empty file : " + self.filepath)
                os.remove(self.filepath)

    # def __del__(self): # Can't rely on destructors in python!
    #     if self.file_handle != None:
    #         self.Cleanup()

class JsonlWriter:
    def __init__(self, delete_empty_files=True):
        self.filepath = ''
        self.jsonl_writer = None
        self.column_info = None
        self.column_names = None
        self.delete_empty_files = delete_empty_files
    
    def CreateJsonlFile(self, filepath):
        '''
        Creates a jsonl file with suggested name, 
        if name is not available, get the next available name
        eg: name01.jsonl or name02.jsonl or ..
        '''
        self.filepath = CommonFunctions.GetNextAvailableFileName(filepath)
        try:
            self.jsonl_writer = jsonlines.open(self.filepath, mode='w')
        except (OSError) as ex:
            log.error(f'Failed to create JSONL file at path {self.filepath}')
            log.exception('Error details')
            raise ex

    def AddHeaders(self, column_info):
        self.column_info = column_info
        self.column_names = self.column_info.keys()

    def WriteRow(self, row):
        try:
            if isinstance(row, list):
                #to_write = dict(self.column_info.keys())
                #for i, k in enumerate(to_write.keys()):
                #    to_write[k] = row[i]
                to_write = dict(zip(self.column_names, row))
                for k, v in to_write.items():
                    if v is None:
                        to_write[k] = ''
                    elif not (isinstance(v, str) or 
                            isinstance(v, int) or 
                            isinstance(v, float)):
                        to_write[k] = str(v)
            else: # must be dict
                to_write = dict(row)
                for k, v in to_write.items():
                    if v is None:
                        to_write[k] = ''
                    elif not (isinstance(v, str) or 
                            isinstance(v, int) or 
                            isinstance(v, float)):
                        to_write[k] = str(v)
            self.jsonl_writer.write(to_write)
        except (OSError, TypeError, KeyError, ValueError) as ex:
            log.exception('Failed to write jsonl row ' + str(row))

    def WriteRows(self, rows):
        for row in rows:
            self.WriteRow(row)

    def GetFileSize(self):
        '''Return jsonl filesize or None if error'''
        try:
            return os.path.getsize(self.filepath)
        except OSError as ex:
            log.warning(f'Failed to retrieve file size for JSONL: {self.filepath}')
        return None
    
    def Cleanup(self):
        if self.jsonl_writer != None:
            self.jsonl_writer.close()
        if self.delete_empty_files:
            file_size = self.GetFileSize()
            if file_size != None and file_size == 0:
                log.debug("Deleting empty file : " + self.filepath)
                os.remove(self.filepath)

class ExcelSheetInfo:
    def __init__(self, name):
        self.name = name
        self.max_row_index = 0 # Index of last row
        self.max_col_index = 0 # Index of last col
        self.col_width_list = None # List of max_char_count in each column
        self.col_types = None # DataType of columns in the sheet
        self.column_info = None # Original column_info passed into AddHeaders()

    def StoreColWidth(self, row):
        column_index = 0
        for item in row:
            width = len(item) + 1
            if width > self.col_width_list[column_index]:
                self.col_width_list[column_index] = width
            column_index += 1

class ExcelWriter:
    def __init__(self):
        self.filepath = ''
        self.workbook = None
        self.sheet = None # will hold current worksheet
        self.row_index = 0
        self.bold = None
        self.date_format = None
        self.num_format = None
        self.col_types = None # Only good for current sheet!
        self.sheet_info_list = []
        self.current_sheet_info = None
        self.max_allowed_rows = 1000000 # Excel limit is 1,048,576

    def CreateXlsxFile(self, filepath):
        '''
        Creates an xlsx file with suggested name, 
        if name is not available, get the next available name
        eg: name01.xlsx or name02.xls or ..
        '''
        self.filepath = CommonFunctions.GetNextAvailableFileName(filepath)
        try:
            self.workbook = xlsxwriter.Workbook(self.filepath, {'strings_to_urls': False, 'constant_memory': True}) #Turning off auto-URL generation as excel freaks on \r \n in url or paths, will result in corrupt excel file
            self.bold = self.workbook.add_format({'bold': 1}) #Define formatting for later use
            self.date_format = self.workbook.add_format({'num_format':'YYYY-MM-DD HH:MM:SS'})
            self.num_format = self.workbook.add_format()
            self.num_format.set_num_format('#,###')
        except (xlsxwriter.exceptions.XlsxWriterException, OSError) as ex:
            log.error('Failed to create xlsx file at path {}'.format(self.filepath))
            log.exception('Error details')
            raise ex
    
    def CreateSheet(self, sheet_name):
        sheet_name = sheet_name.replace('_','') # Remove _ to shorten name
        if len(sheet_name) > 31:
            log.warning('Sheet name "{}" is longer than the Excel limit of 31 char. It will be truncated to 31 char!'.format(sheet_name))
            sheet_name = sheet_name[0:31]
        try:
            self.sheet = self.workbook.add_worksheet(sheet_name)
        except xlsxwriter.exceptions.XlsxWriterException as ex:
            if str(ex).find('is already in use') > 0:
                # find another sheetname
                try:
                    sheet_name = self.GetNextAvailableSheetName(sheet_name)
                    self.sheet = self.workbook.add_worksheet(sheet_name)
                except xlsxwriter.exceptions.XlsxWriterException as ex:
                    log.exception('Unknown error while adding sheet {}'.format(sheet_name))
                    raise ex
            else:
                log.exception('Unknown error while adding sheet {}'.format(sheet_name))
                raise ex
        self.row_index = 0 # Need to reset for new sheet
        info = ExcelSheetInfo(sheet_name)
        self.current_sheet_info = info
        self.sheet_info_list.append(info)

    def SheetExists(self, sheet_name):
        try:
            name = sheet_name.lower().replace('_','')
            sheets = self.workbook.worksheets()
            for sheet in sheets:
                if sheet.get_name().lower() == name:
                    return True
        except xlsxwriter.exceptions.XlsxWriterException as ex:
            log.exception('Unknown error while fetching sheet names')
        return False

    def AddHeaders(self, column_info):
        column_index = 0
        self.col_types = []
        for col_name, data in column_info.items():
            col_width = 8.43 # default excel value
            col_type = data
            self.col_types.append(col_type)
            self.sheet.write_string(self.row_index, column_index, col_name, self.bold)
            self.sheet.set_column(column_index, column_index, col_width)
            column_index += 1
        self.row_index += 1
        self.current_sheet_info.max_col_index = column_index - 1
        self.current_sheet_info.max_row_index = self.row_index - 1
        self.current_sheet_info.col_width_list = [len(col_name)+3 for col_name in column_info] # +3 is to cover autofilter dropdown button
        self.current_sheet_info.col_types = self.col_types
        self.current_sheet_info.column_info = column_info

    def GetNextAvailableSheetName(self, sheet_name):
        name = sheet_name
        if self.SheetExists(name):
            if len(name) > 29:
                sheet_name = name[0:29] # Truncate to 30 char, as excel can only handle 32 char sheetnames
                log.warning('Sheet name "{}" is in use, and has length > 29 char. Truncating to 29 char to add 2 numerical digits!'.format(name))
            index = 1
            name = sheet_name + '{0:02d}'.format(index)
            while (self.SheetExists(name)):
                name = sheet_name + '{0:02d}'.format(index)
                index += 1
        return name

    def WriteRow(self, row):
        column_index = 0
        try:
            if self.row_index > self.max_allowed_rows:
                info = self.current_sheet_info
                self.CreateSheet(info.name)
                self.AddHeaders(info.column_info)
        except xlsxwriter.exceptions.XlsxWriterException as ex:
            log.exception('Error trying to add sheet for overflow data (>1 million rows)')
        try:
            row_str = tuple(map(str, row))
            for item in row_str:
                try:
                    if item == '' or row[column_index] == None: pass
                        #self.sheet.write(self.row_index, column_index, '')
                    elif self.col_types[column_index] in [DataType.INTEGER, DataType.REAL]:
                        self.sheet.write_number(self.row_index, column_index, row[column_index], self.num_format)
                    elif (self.col_types[column_index] == DataType.DATE):
                        self.sheet.write_datetime(self.row_index, column_index, row[column_index], self.date_format)
                    else:
                        self.sheet.write(self.row_index, column_index, item)
                except (TypeError, ValueError, xlsxwriter.exceptions.XlsxWriterException):
                    log.exception('Error writing data:{} of type:{} in excel row:{} '.format(str(item), str(type(row[column_index])), self.row_index))
                column_index += 1

            self.row_index += 1
            self.current_sheet_info.max_row_index = self.row_index - 1
            self.current_sheet_info.StoreColWidth(row_str)
            
        except xlsxwriter.exceptions.XlsxWriterException as ex:
            log.exception('Error writing excel row {}'.format(self.row_index))
    
    def WriteRows(self, rows):
        for row in rows:
            self.WriteRow(row)

    def Beautify(self):
        '''Set column widths, auto filter and freeze top row'''
        for sheet_info in self.sheet_info_list:
            sheet = self.workbook.get_worksheet_by_name(sheet_info.name)
            sheet.freeze_panes(1, 0) # Freeze 1st row
            # Set column widths
            col_index = 0
            for col_width in sheet_info.col_width_list:
                if sheet_info.col_types[col_index] in [DataType.INTEGER, DataType.REAL]:
                    col_width += col_width//4 - 1
                elif sheet_info.col_types[col_index] == DataType.DATE:
                    col_width = 18
                if col_width > 60 : col_width = 60 # Setting max width to 60
                sheet.set_column(col_index, col_index, col_width)
                col_index += 1
            # Autofilter
            sheet.autofilter(0, 0, sheet_info.max_row_index, sheet_info.max_col_index)

    def CommitAndCloseFile(self):
        self.Beautify()
        if self.workbook != None:
            self.workbook.close()
            self.workbook = None
    
    def __del__(self):
        if self.workbook != None:
            raise ValueError('ExcelWriter destructor, Dear coder, you forgot to close file.')

# Plugins should call this function to write out data formatted as a spreadsheet/table
def WriteList(data_description, data_name, data_list, data_type_info, output_params, source_file=''):
    '''
    Writes a list (of either lists or dicts) provided, output types defined by output_params
    Parameters include -
    data_description : String describing what data is provided
    data_name        : Name for file or db table
    data_list        : List of (list or dict)
    data_type_info   : Ordered dict describing columns as needed by DataWriter()
    output_params    : OutputParams object
    source_file      : Source file(s) where data was extracted from
    '''
    if len(data_list) == 0: 
        log.info("No " + data_description + " was retrieved!")
        return
    try:
        log.debug ("Trying to write out " + data_description)
        writer = DataWriter(output_params, data_name, data_type_info, source_file)
        try:
            writer.WriteRows(data_list)
        except (OSError, xlsxwriter.exceptions.XlsxWriterException, sqlite3.Error) as ex:
            log.error ("Failed to write row data")
            log.exception ("Error details")
        finally:
            writer.FinishWrites()
    except (OSError, xlsxwriter.exceptions.XlsxWriterException, sqlite3.Error) as ex:
        log.error ("Failed to initilize data writer")
        log.exception ("Error details")

class ChunkedDataWriter:
    '''Plugins should use this class when writing millions of rows to avoid MemoryError situations.
       Ideally write no more than 500K rows at a time. Syntax is the same as WriteList() function.
       Call the WriteListPartial(...) to write in batches as many times.
       Just remember to call FinishWrites() at the end of all writing.
    '''
    def __init__(self) -> None:
        self.writer = None

    # Plugins should call this function to write out data formatted as a spreadsheet/table
    def WriteListPartial(self, data_description, data_name, data_list, data_type_info, output_params, source_file=''):
        '''
        Writes a list (of either lists or dicts) provided, output types defined by output_params
        Parameters include -
        data_description : String describing what data is provided
        data_name        : Name for file or db table
        data_list        : List of (list or dict)
        data_type_info   : Ordered dict describing columns as needed by DataWriter()
        output_params    : OutputParams object
        source_file      : Source file(s) where data was extracted from

        Returns True or False
        '''
        ret = False
        if len(data_list) == 0: 
            log.info("No " + data_description + " was retrieved!")
            return True
        try:
            log.debug (f"Trying to write out {len(data_list)} " + data_description)
            if self.writer == None:
                self.writer = DataWriter(output_params, data_name, data_type_info, source_file)
            try:
                self.writer.WriteRows(data_list)
                ret = True
            except (OSError, xlsxwriter.exceptions.XlsxWriterException, sqlite3.Error) as ex:
                log.error ("Failed to write row data")
                log.exception ("Error details")
                self.writer.FinishWrites()
        except (OSError, xlsxwriter.exceptions.XlsxWriterException, sqlite3.Error) as ex:
            log.error ("Failed to initilize data writer")
            log.exception ("Error details")
        return True
    
    def FinishWrites(self):
        if self.writer:
            self.writer.FinishWrites()


if __name__ == '__main__': # TESTING ONLY

    print("Testing mac HFS+ time : " + str(CommonFunctions.ReadMacHFSTime(0xD4DA7B9F)))
    
    try:
        import datetime
        from plugins.helpers.macinfo import * # OutputParams

        op = OutputParams()
        op.write_csv = True
        op.write_tsv = True
        op.write_jsonl = True
        op.write_sql = True
        op.write_xlsx = True
        op.output_path = "/Users/ykhatri/Desktop/code/test_writer" #"C:\\temp\\out"
        op.output_db_path = SqliteWriter.CreateSqliteDb(os.path.join(op.output_path, "TESTINGWRITER.db"))
        op.xlsx_writer = ExcelWriter()
        op.xlsx_writer.CreateXlsxFile(os.path.join(op.output_path, "TESTINGWRITER.xlsx"))
        columns = collections.OrderedDict([('ID',DataType.INTEGER), ('NAME',DataType.TEXT), ('Path',DataType.TEXT),
                                             ('BLOB',DataType.BLOB),('S_Date',DataType.DATE)])
        d = datetime.datetime(2016,11,10,9,20,45,9)
        writer = DataWriter(op, 'TESTINGWRITER', columns, '/var/folders/none/unknown.db')
        writer.WriteRow([1, "Joe\n,Preet", '/Users/Joe"Smith', b'\xdb]\xccY\x00\x00\x00\x00P\x87\x044\x00\x00\x00\x00', d])
        #writer.WriteRow([datetime.datetime.now(), "Moe", '/Users/MoePo', b'\x38\x39', d])# incorrect
        writer.WriteRow({'NAME':'Bill', 'ID':3, 'Path':'/users/coby', 'BLOB':b'\xdb]\xccY\x00\x00\x38\x39'})
        writer.WriteRow({'NAME':'OBoy', 'Path':'/users/piy', 'BLOB':b'\x38\x39', 'S_Date':d})
        writer.WriteRow({'NAME':'Bad', 'ID':44 })
        writer.WriteRows([[4,'Four','/four/', b'\xdb]\xccY\x00\x00\x38\x39', d],[5,"Five",'/five/', b'\x38\x39', None]])

        writer2 = DataWriter(op, 'TESTINGWRITER', columns, '/var/folders/none/unknown.db')

        d = datetime.datetime(2016,11,10,9,20,45,9)
        writer2.WriteRow([1, "Joe", '/Users/JoeSmith', b'\x38\x39', d])

        #op.xlsx_writer.CommitAndCloseFile()
        writer.FinishWrites()
        writer2.FinishWrites()

        # test partial writer
        writer = ChunkedDataWriter()
        data_list = [[4,'Four','/four/', b'\xdb]\xccY\x00\x00\x38\x39', d],[5,"Five",'/five/', b'\x38\x39', None]]
        writer.WriteListPartial('desc', 'Partial data_list', data_list, columns, op, 'blah')
        data_list = [[6,'Six','/six/', b'\xdb]\xccY\x00\x00\x38\x39', d],[7,"7",'/7/', b'\x38\x39', None]]
        writer.WriteListPartial('desc', 'Partial data_list', data_list, columns, op, 'blah')
        writer.FinishWrites()
        op.xlsx_writer.CommitAndCloseFile()
       
    except Exception as ex:
        print (ex)
        import traceback
        traceback.print_exc() 
