'''
   Copyright (c) 2017 Yogesh Khatri 

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the 
   terms of the MIT License.
   
'''
from __future__ import print_function
from __future__ import unicode_literals

import codecs
import sqlite3
import sys, os
import collections
import logging
import binascii
import xlsxwriter

from common import *
from enum import IntEnum

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
        if self.sql: self.sql_writer.CloseDb()

    def __init__(self, output_params, name, column_info, artifact_source=''):
        '''
        output_params is OutputParams object 
        column_info is an 'ordered' dictionary that defines output column names and types
         # column_info must be an OrderedDict type or a list of tuples (see below).
        column_info = [ ('Name1', DataType.TEXT), ('Name2', DataType.BLOB), ..]
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
        if output_params.write_xlsx:
            self.xlsx = True
            self.xlsx_writer = output_params.xlsx_writer

        self.column_info = collections.OrderedDict(column_info)
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
        '''Writes Headings for csv, creates Table for sqlite, creates Sheet for XLSX'''
        if self.csv:
            self.csv_writer.WriteRow(self.column_info)
        if self.sql:
            self.sql_writer.CreateTable(self.column_info, self.name)
        if self.xlsx:
            self.xlsx_writer.CreateSheet(self.name)
            self.xlsx_writer.AddHeaders(self.column_info)

    def BlobToHex(self, blob):
        '''Convert binary data to hex text'''
        s = ''
        try:
            if self.PYTHON_VER == 2: 
                s = binascii.hexlify(blob).upper()
            else:
                s = binascii.hexlify(blob).decode("ascii").upper() # For python3!
        except Exception as ex:
            log.error('Exception from BlobToHex() : ' + str(ex))
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
                        row_copy[index] = buffer(row_copy[index])
                    self.sql_writer.WriteRow(row_copy)
                else:
                    self.sql_writer.WriteRow(row)
            if self.csv or self.xlsx: # This routine modifies row
                if self.cols_with_blobs:
                    for col_name, index in self.cols_with_blobs:
                        row[index] = self.BlobToHex(row[index])
                if self.csv: self.csv_writer.WriteRow(row)
                if self.xlsx: self.xlsx_writer.WriteRow(row)
        else: # Must be Dictionary!
            #list_to_write = [ row.get(col, None if self.column_info[col] in (DataType.INTEGER, DataType.BLOB, DataType.REAL) else '') \
            #                     for col in self.column_info ]
            list_to_write = [ row.get(col, '') for col in self.column_info ]
            if self.sql: 
                if self.cols_with_blobs:
                    row_copy = list(list_to_write)
                    for col_name, index in self.cols_with_blobs:
                        row_copy[index] = buffer(row_copy[index])
                    self.sql_writer.WriteRow(row_copy)
                else: self.sql_writer.WriteRow(list_to_write)
            if self.csv or self.xlsx:
                if self.cols_with_blobs:
                    for col_name, index in self.cols_with_blobs:
                        list_to_write[index] = self.BlobToHex(list_to_write[index])
                if self.csv: self.csv_writer.WriteRow(list_to_write)
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
                            row_copy[index] = buffer(row_copy[index])
                    self.sql_writer.WriteRows(rows_copy)
                else:
                    self.sql_writer.WriteRows(rows)
            if self.csv or self.xlsx: # This routine modifies rows
                if self.cols_with_blobs:
                    for row in rows:
                        for col_name, index in self.cols_with_blobs:
                            row[index] = self.BlobToHex(row[index])
                if self.csv: self.csv_writer.WriteRows(rows)
                if self.xlsx: self.xlsx_writer.WriteRows(rows)
        else: # Must be Dictionary!
            list_to_write = []
            for row in rows:
                #list_row = [ row.get(col, None if self.column_info[col] in (DataType.INTEGER, DataType.BLOB, DataType.REAL) else '') \
                #                 for col in self.column_info ]
                # NOTES: For csv , everything not present can be '', otherwise 'None' is printed
                #        For sql, this works too, however None is more correct.. revisit this later.
                list_row = [ row.get(col, '') for col in self.column_info ]
                list_to_write.append(list_row)
            if self.sql:
                if self.cols_with_blobs:
                    rows_copy = [list(k) for k in list_to_write]
                    for row_copy in rows_copy:
                        for col_name, index in self.cols_with_blobs:
                            row_copy[index] = buffer(row_copy[index])
                    self.sql_writer.WriteRows(rows_copy)
                else:
                    self.sql_writer.WriteRows(list_to_write)
            if self.csv or self.xlsx: # This routine modifies list_to_write
                if self.cols_with_blobs:
                    for list_row in list_to_write:
                        for col_name, index in self.cols_with_blobs:
                            list_row[index] = self.BlobToHex(list_row[index])           
                if self.csv: self.csv_writer.WriteRows(list_to_write)
                if self.xlsx: self.xlsx_writer.WriteRows(list_to_write)
        self.row_count += row_len

class SqliteWriter:
    def __init__(self):
        self.filepath = ''
        self.conn = None
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
        except Exception as ex:
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
        except Exception as ex:
            log.exception('Query execution error, query was - ' + query)
            error_message = str(ex)

        return success, cursor, error_message

    def CreateTable(self, column_info, table_name):
        '''
           Creates table with given name, if table exists, 
           a new name is selected (name_xx)
           - 'column_info' must be OrderedDict
        '''
        cursor = None
        query = ''
        try:
            self.table_name = table_name
            self.column_info = column_info
            #self.CleanColumnInfo(column_info)
            cursor = self.conn.cursor()
            query = 'CREATE TABLE "' + self.table_name + '" (' + \
                    ','.join(['"{}" {}'.format(k,v.name if v != DataType.DATE else 'TEXT') for (k,v) in self.column_info.items() ]) + ')'
            cursor.execute(query)
            self.conn.commit()
            self.executemany_query = 'INSERT INTO "' + table_name + '" VALUES (?' + ',?'*(len(self.column_info) - 1) + ')'
        except Exception as ex:
            if  str(ex).find('table "{}" already exists'.format(table_name)) >= 0:
                log.info(str(ex))
                self.table_name = self.GetNextAvailableTableName(table_name)
                log.info('Changing tablename to {}'.format(self.table_name))
                try:
                    cursor = self.conn.cursor()
                    query = 'CREATE TABLE "' + self.table_name + '" (' + \
                            ','.join(['"{}" {}'.format(k,v.name if v != DataType.DATE else 'TEXT') for (k,v) in self.column_info.items() ]) + ')'
                    cursor.execute(query)
                    self.conn.commit()
                    self.executemany_query = 'INSERT INTO "' + self.table_name + '" VALUES (?' + ',?'*(len(self.column_info) - 1) + ')'
                    return
                except Exception as ex:
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
        try:
            cursor = self.conn.cursor()
            query = self.executemany_query
            if table_name:
                try:
                    index = self.table_names.index(table_name)
                    query = self.executemany_querys[index]
                except Exception as ex:
                    log.exception("Could not find table name {}".format(table_name))
                    raise ex
            cursor.executemany(query, rows)
            self.conn.commit()
        except Exception as ex:
            log.error(str(ex))
            log.exception("error writing to table " + self.table_name)
            raise ex

    def CloseDb(self):
        if self.conn != None:
            self.conn.close()
            self.conn = None
    
    def __del__(self):
        if self.conn != None:
            raise ValueError('SqliteWriter destructor, Dear coder, you forgot to close db.')

class CsvWriter:
    def __init__(self, delete_empty_files=True):
        self.filepath = ''
        self.codec = 'utf-16'
        self.file_handle = None
        self.delete_empty_files = delete_empty_files # perhaps a useful option?
    
    def CreateCsvFile(self, filepath):
        '''
        Creates a csv file with suggested name, 
        if name is not available, get the next available name
        eg: name01.csv or name02.csv or ..
        '''
        self.filepath = CommonFunctions.GetNextAvailableFileName(filepath)
        try:
            self.file_handle = codecs.open(self.filepath, 'w', encoding=self.codec)
        except Exception as ex:
            log.error('Failed to create csv file at path {}'.format(self.filepath))
            log.exception('Error details')
            raise ex

    def Sanitize(self, row):
        '''Remove \r \n \t from each item to write'''
        safe_list = []
        for item in row:
            safe_str = unicode(item)
            try:
                safe_str = safe_str.replace('\r\n', ',').replace('\r', ',').replace('\n', ',').replace('\t', ' ')
            except Exception as ex:
                log.exception()
            safe_list.append(safe_str)
        return safe_list

    def WriteRow(self, row):
        row = self.Sanitize(row)
        self.file_handle.write("\t".join(map(unicode,row)) + ('\r\n'))
    
    def WriteRows(self, rows):
        for row in rows:
            self.WriteRow(row)
    
    def GetFileSize(self):
        '''Return csv's filesize or None if error'''
        try:
            return os.path.getsize(self.filepath)
        except Exception as ex:
            log.warning('Failed to retrieve file size for CSV: {}'.format(self.filepath))
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
            self.workbook = xlsxwriter.Workbook(self.filepath, {'strings_to_urls': False}) #Turning off auto-URL generation as excel freaks on \r \n in url or paths, will result in corrupt excel file
            self.bold = self.workbook.add_format({'bold': 1}) #Define formatting for later user
            self.date_format = self.workbook.add_format({'num_format':'YYYY-MM-DD HH:MM:SS'})
            self.num_format = self.workbook.add_format()
            self.num_format.set_num_format('#,###')
        except Exception as ex:
            log.error('Failed to create xlsx file at path {}'.format(self.filepath))
            log.exception('Error details')
            raise ex
    
    def CreateSheet(self, sheet_name):
        sheet_name = sheet_name.replace('_','') # Remove _ to shorten name
        try:
            self.sheet = self.workbook.add_worksheet(sheet_name)
        except Exception as ex:
            if str(ex).find('is already in use') > 0:
                # find another sheetname
                try:
                    sheet_name = self.GetNextAvailableSheetName(sheet_name)
                    self.sheet = self.workbook.add_worksheet(sheet_name)
                except Exception as ex:
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
        except Exception as ex:
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
        except Exception as ex:
            log.exception('Error trying to add sheet for overflow data (>1 million rows)')
        try:
            row_unicode = map(unicode, row)
            for item in row_unicode:
                try:
                    if item == '' or row[column_index] == None:
                        self.sheet.write(self.row_index, column_index, '')
                    elif self.col_types[column_index] == DataType.INTEGER:
                        self.sheet.write_number(self.row_index, column_index, row[column_index], self.num_format)
                    elif (self.col_types[column_index] == DataType.DATE):
                        self.sheet.write_datetime(self.row_index, column_index, row[column_index], self.date_format)#[0:19], self.date_format)
                    else:
                        self.sheet.write(self.row_index, column_index, item)
                except:
                    log.exception('Error writing data:{} of type:{} in excel row:{} '.format(str(item), str(type(row[column_index])), self.row_index))
                column_index += 1

            self.row_index += 1
            self.current_sheet_info.max_row_index = self.row_index - 1
            self.current_sheet_info.StoreColWidth(row_unicode)
            
        except Exception as ex:
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
                if sheet_info.col_types[col_index] == DataType.INTEGER:
                    col_width += col_width/4 - 1
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
            raise Exception('ExcelWriter destructor, Dear coder, you forgot to close file.')

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
        except Exception as ex:
            log.error ("Failed to write row data")
            log.exception ("Error details")
        finally:
            writer.FinishWrites()
    except Exception as ex:
        log.error ("Failed to initilize data writer")
        log.exception ("Error details")

if __name__ == '__main__': # TESTING ONLY

    print("Testing mac HFS+ time : " + str(CommonFunctions.ReadMacHFSTime(0xD4DA7B9F)))
    
    try:
        import datetime
        from macinfo import * # OutputParams

        op = OutputParams()
        op.write_csv = True
        op.write_sql = True
        op.write_xlsx = True
        op.output_path = "C:\\temp\\out"
        op.output_db_path = SqliteWriter.CreateSqliteDb(os.path.join(op.output_path, "TESTINGWRITER.db"))
        op.xlsx_writer = ExcelWriter()
        op.xlsx_writer.CreateXlsxFile(os.path.join(op.output_path, "TESTINGWRITER.xlsx"))
        columns = collections.OrderedDict([('ID',DataType.INTEGER), ('NAME',DataType.TEXT), ('Path',DataType.TEXT),
                                             ('BLOB',DataType.BLOB),('S_Date',DataType.DATE)])
        writer = DataWriter(op, 'TESTINGWRITER', columns, '/var/folders/none/unknown.db')

        d = datetime.datetime(2016,11,10,9,20,45,9)
        writer.WriteRow([1, "Joe", '/Users/JoeSmith', b'\xdb]\xccY\x00\x00\x00\x00P\x87\x044\x00\x00\x00\x00', d])
        #writer.WriteRow([datetime.datetime.now(), "Moe", '/Users/MoePo', b'\x38\x39', d])# incorret
        writer.WriteRow({'NAME':'Bill', 'ID':3, 'Path':'/users/coby', 'BLOB':b'\xdb]\xccY\x00\x00\x38\x39'})
        writer.WriteRow({'NAME':'OBoy', 'Path':'/users/piy', 'BLOB':b'\x38\x39', 'S_Date':d})
        writer.WriteRow({'NAME':'Bad', 'ID':44 })
        writer.WriteRows([[4,'Four','/four/', b'\xdb]\xccY\x00\x00\x38\x39', d],[5,"Five",'/five/', '\x38\x39', None]])

        writer2 = DataWriter(op, 'TESTINGWRITER', columns, '/var/folders/none/unknown.db')

        d = datetime.datetime(2016,11,10,9,20,45,9)
        writer2.WriteRow([1, "Joe", '/Users/JoeSmith', b'\x38\x39', d])

        op.xlsx_writer.CommitAndCloseFile()
        writer.FinishWrites()
        writer2.FinishWrites()

    except Exception as ex:
        print (ex)
        import traceback
        traceback.print_exc() 
