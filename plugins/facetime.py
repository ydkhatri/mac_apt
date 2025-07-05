'''
   Copyright (c) 2025 Yogesh Khatri 

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the 
   terms of the MIT License.

'''

import logging
import sqlite3

from plugins.helpers.bookmark import *
from plugins.helpers.common import CommonFunctions
from plugins.helpers.macinfo import *
from plugins.helpers.writer import *

__Plugin_Name = "FACETIME"
__Plugin_Friendly_Name = "FaceTime"
__Plugin_Version = "1.0"
__Plugin_Description = "Reads the database for FaceTime call information"
__Plugin_Author = "Yogesh Khatri"
__Plugin_Author_Email = "yogesh@swiftforensics.com"

__Plugin_Modes = "MACOS,ARTIFACTONLY"
__Plugin_ArtifactOnly_Usage = 'Provide the facetime database located at '\
                              '/Users/$USER/Library/Application Support/FaceTime/FaceTime.sqlite3'

log = logging.getLogger('MAIN.' + __Plugin_Name) # Do not rename or remove this ! This is the logger object

#---- Do not change the variable names in above section ----#

class FaceTimeRecord:
    '''(CommonFunctions.ReadMacAbsoluteTime(row['ZCREATIONDATE']),
        CommonFunctions.ReadMacAbsoluteTime(row['ZEXPIRATIONDATE']),
        CommonFunctions.ReadMacAbsoluteTime(row['ZDELETIONDATE']),
        row['ZDELETEREASON'],
        row['ZVALUE'],
        row['ZNORMALIZEDVALUE'],
        row[''],
        user, 
        source)
    '''
    def __init__(self, creation_date, exp_date, del_date, del_reason, handle, handle_normalized, user, source):
        self.creation_date = creation_date
        self.exp_date = exp_date
        self.del_date = del_date
        self.del_reason = del_reason
        self.handle = handle
        self.handle_normalized = handle_normalized
        self.user = user
        self.source_file = source
    
def PrintAll(facetime_records, output_params):

    facetime_info = [ ('Creation Date',DataType.TEXT),('Expiration Date',DataType.DATE),('Deletion Date',DataType.DATE),
                        ('Deletion Reason',DataType.INTEGER),
                        ('Handle',DataType.TEXT),('Handle Normalized',DataType.TEXT),
                        ('User', DataType.TEXT),('Source',DataType.TEXT)
                      ]

    log.info (str(len(facetime_records)) + " facetime item(s) found")
    facetime_list = []
    for f in facetime_records:
        f_item =  [ f.creation_date, f.exp_date, f.del_date, f.del_reason, 
                    f.handle, f.handle_normalized,
                    f.user, f.source_file
                  ]
        facetime_list.append(f_item)
    WriteList("facetime information", "Facetime", facetime_list, facetime_info, output_params, '')

def ReadFacetimeDb(db, facetime_records, source, user):
    '''Reads com.apple.LaunchServices.FacetimeEventsV2 sqlite db'''
    try:
        query = """
                SELECT 
                ZCREATIONDATE, ZEXPIRATIONDATE, ZDELETIONDATE, ZDELETEREASON, 
                --ZGROUPUUID, ZPRIVATEKEY, ZPUBLICKEY, 
                --ZNAME, ZPSEUDONYM, ZORIGINATORHANDLE, 
                h.ZVALUE, h.ZNORMALIZEDVALUE
                FROM ZCONVERSATIONLINK c
                LEFT JOIN ZHANDLE h ON c.ZORIGINATORHANDLE=h.Z_PK
                """
        db.row_factory = sqlite3.Row
        cursor = db.execute(query)
        for row in cursor:
            try:
                f_event = FaceTimeRecord(CommonFunctions.ReadMacAbsoluteTime(row['ZCREATIONDATE']),
                                         CommonFunctions.ReadMacAbsoluteTime(row['ZEXPIRATIONDATE']),
                                         CommonFunctions.ReadMacAbsoluteTime(row['ZDELETIONDATE']),
                                         row['ZDELETEREASON'],
                                         row['ZVALUE'],
                                         row['ZNORMALIZEDVALUE'],
                                         user, 
                                         source)
                facetime_records.append(f_event)
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

def OpenDbFromImage(mac_info, inputPath, user):
    '''Returns tuple of (connection, wrapper_obj)'''
    log.info ("Processing tacetime events for user '{}' from file {}".format(user, inputPath))
    try:
        sqlite = SqliteWrapper(mac_info)
        conn = sqlite.connect(inputPath)
        if conn:
            log.debug ("Opened database successfully")
        return conn, sqlite
    except sqlite3.Error as ex:
        log.exception ("Failed to open database, is it a valid DB?")
    return None, None

def ProcessDbFromPath(mac_info, facetime_records, source_path, user):
    if mac_info.IsValidFilePath(source_path):
        mac_info.ExportFile(source_path, __Plugin_Name, user + "_")
        db, wrapper = OpenDbFromImage(mac_info, source_path, user)
        if db != None:
            ReadFacetimeDb(db, facetime_records, source_path, user)
            db.close()
    
def Plugin_Start(mac_info):
    '''Main Entry point function for plugin'''
    facetime_records = []
    facetime_path    = '{}/Library/Application Support/FaceTime/FaceTime.sqlite3'

    for user in mac_info.users:
        if user.home_dir == '/private/var/empty': continue # Optimization, nothing should be here!
        source_path = facetime_path.format(user.home_dir)
        ProcessDbFromPath(mac_info, facetime_records, source_path, user.user_name)

    if len(facetime_records) > 0:
        PrintAll(facetime_records, mac_info.output_params)
    else:
        log.info('No facetime events found')

def Plugin_Start_Standalone(input_files_list, output_params):
    log.info("Module Started as standalone")
    for input_path in input_files_list:
        log.debug("Input file passed was: " + input_path)
        facetime_records = []
        db = OpenDb(input_path)
        if db != None:
            ReadFacetimeDb(db, facetime_records, input_path, '')
            db.close()
        else:
            log.error(f'Failed to open database {input_path}')
        if len(facetime_records) > 0:
            PrintAll(facetime_records, output_params)
        else:
            log.info('No facetime events found in {}'.format(input_path))

if __name__ == '__main__':
    print ("This plugin is a part of a framework and does not run independently on its own!")

