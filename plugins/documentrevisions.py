'''
   Copyright (c) 2020 Yogesh Khatri 

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the 
   terms of the MIT License.

   documentrevisions.py
   ---------------
   Reads the DocumentRevisions database. The database contains information
   about files that users have opened and edited, including the full path to
   the original file, the date a generated revision was made, date last seen, 
   and the full path to the generated file revision.

'''
from plugins.helpers.common import CommonFunctions
from plugins.helpers.macinfo import *
from plugins.helpers.writer import *

import logging
import sqlite3

__Plugin_Name = "DOCUMENTREVISIONS"
__Plugin_Friendly_Name = "DocumentRevisions"
__Plugin_Version = "1.0"
__Plugin_Description = "Reads DocumentRevisions database"
__Plugin_Author = "Nicole Ibrahim"
__Plugin_Author_Email = "nicoleibrahim.us@gmail.com"

__Plugin_Modes = "MACOS,ARTIFACTONLY"
__Plugin_ArtifactOnly_Usage = 'Provide DocumentRevisions sqlite database as input to process. This is '\
                            'located at /.DocumentRevisions-V100/db-V1/db.sqlite '

log = logging.getLogger('MAIN.' + __Plugin_Name) # Do not rename or remove this ! This is the logger object

#---- Do not change the variable names in above section ----#

class Revisions:

    def __init__(self, inode, storage_id, path, exists, last_seen, generation_added, generation_path, source):
        self.inode = inode
        self.storage_id = storage_id
        self.path = path
        self.exists = exists
        self.last_seen = last_seen
        self.generation_added = generation_added
        self.generation_path = generation_path
        self.source_file = source

def PrintAll(revisions, output_params):

    revisions_info = [ ('File_Inode',DataType.INTEGER),('Storage_ID',DataType.INTEGER),('File_Path',DataType.TEXT),
                        ('Exists_On_Disk',DataType.TEXT),
                        ('File_Last_Seen_UTC',DataType.DATE),('Generation_Added_UTC',DataType.DATE),
                        ('Generation_Path',DataType.TEXT),('Source',DataType.TEXT)
                      ]

    log.info (str(len(revisions)) + " revision item(s) found")
    revisions_list = []
    for q in revisions:
        q_item =  [ q.inode, q.storage_id, q.path, q.exists,
                    CommonFunctions.ReadUnixTime(q.last_seen), CommonFunctions.ReadUnixTime(q.generation_added), 
                    q.generation_path, q.source_file
                  ]
        revisions_list.append(q_item)
    WriteList("revisions information", "DocumentRevisions", revisions_list, revisions_info, output_params, '')

def ReadRevisionsdB(db, revisions, source):
    '''Reads db.sqlite db'''
    try:
        query = "SELECT files.file_inode as inode, generations.generation_storage_id as storage_id, files.file_path as path,"\
                " files.file_last_seen as file_last_seen_utc,"\
                " generations.generation_add_time as generation_add_time_utc,"\
                " generations.generation_path as generation_path"\
                " FROM files inner join generations ON generations.generation_storage_id = files.file_storage_id"
        db.row_factory = sqlite3.Row
        cursor = db.execute(query)
        for row in cursor:
            try:
                q_event = Revisions(row['inode'], row['storage_id'], row['path'], '', row['file_last_seen_utc'], 
                                    row['generation_add_time_utc'], row['generation_path'], source)
                revisions.append(q_event)
            except (sqlite3.Error, KeyError):
                log.exception('Error fetching row data')
    except sqlite3.Error:
        log.exception('Query  execution failed. Query was: ' + query)

def OpenDb(inputPath):
    log.info ("Processing file " + inputPath)
    try:
        conn = CommonFunctions.open_sqlite_db_readonly(inputPath)
        log.debug ("Opened database successfully")
        return conn
    except sqlite3.Error:
        log.exception ("Failed to open database, is it a valid DB?")
    return None

def OpenDbFromImage(mac_info, inputPath):
    '''Returns tuple of (connection, wrapper_obj)'''
    log.info ("Processing revisions events from file {}".format(inputPath))
    try:
        sqlite = SqliteWrapper(mac_info)
        conn = sqlite.connect(inputPath)
        if conn:
            log.debug ("Opened database successfully")
        return conn, sqlite
    except sqlite3.Error as ex:
        log.exception ("Failed to open database, is it a valid DB?")
    return None, None

def ProcessDbFromPath(mac_info, revisions, source_path):
    if mac_info.IsValidFilePath(source_path):
        mac_info.ExportFile(source_path, __Plugin_Name)
        db, wrapper = OpenDbFromImage(mac_info, source_path)
        if db != None:
            ReadRevisionsdB(db, revisions, source_path)
            db.close()
    
def CheckForRevisionExistence(mac_info, revisions, root):
    if not root.endswith('/'):
        root += '/'
    for rev in revisions:
        if mac_info.IsValidFilePath(root + rev.generation_path):
            rev.exists = 'Yes'
        else:
            log.debug(f'Did not FIND -> {root + rev.generation_path}')
            rev.exists = 'No'

def Plugin_Start(mac_info):
    '''Main Entry point function for plugin'''
    revisions = []
    revisions_path = '/.DocumentRevisions-V100/db-V1/db.sqlite'
    ProcessDbFromPath(mac_info, revisions, revisions_path)
    CheckForRevisionExistence(mac_info, revisions, '/.DocumentRevisions-V100')

    revisions_path_2 = '/System/Volumes/Data/.DocumentRevisions-V100/db-V1/db.sqlite'
    ProcessDbFromPath(mac_info, revisions, revisions_path_2)
    CheckForRevisionExistence(mac_info, revisions, '/System/Volumes/Data/.DocumentRevisions-V100')

    if len(revisions) > 0:
        PrintAll(revisions, mac_info.output_params)
    else:
        log.info('No revisions item found')

def Plugin_Start_Standalone(input_files_list, output_params):
    log.info("Module Started as standalone")
    for input_path in input_files_list:
        log.debug("Input file passed was: " + input_path)
        if input_path.endswith('db.sqlite'):
            revisions = []
            db = OpenDb(input_path)
            if db != None:
                filename = os.path.basename(input_path)
                ReadRevisionsdB(db, revisions, input_path, '')
                db.close()
            else:
                log.error(f'Failed to open database {input_path}')
            if len(revisions) > 0:
                PrintAll(revisions, output_params)
            else:
                log.info('No revisions item found in {}'.format(input_path))
        else:
            log.info(f'Not a DocumentRevisions database file: {input_path}')

def Plugin_Start_Ios(ios_info):
    '''Main Entry point function for plugin'''
    revisions = []
    revisions_path = '/private/var/.DocumentRevisions-V100/db-V1/db.sqlite'
    ProcessDbFromPath(ios_info, revisions, revisions_path)
    CheckForRevisionExistence(ios_info, revisions, '/.DocumentRevisions-V100')

    if len(revisions) > 0:
        PrintAll(revisions, ios_info.output_params)
    else:
        log.info('No revisions item found')

if __name__ == '__main__':
    print ("This plugin is a part of a framework and does not run independently on its own!")
