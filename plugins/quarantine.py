'''
   Copyright (c) 2017 Yogesh Khatri 

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the 
   terms of the MIT License.

'''
from __future__ import print_function
#from __future__ import unicode_literals # Must disable for sqlite.row_factory

from helpers.macinfo import *
from helpers.writer import *
import logging
import sqlite3

__Plugin_Name = "QUARANTINE"
__Plugin_Friendly_Name = "Quarantine"
__Plugin_Version = "1.0"
__Plugin_Description = "Reads Quarantine V2 databases"
__Plugin_Author = "Yogesh Khatri"
__Plugin_Author_Email = "yogesh@swiftforensics.com"

__Plugin_Standalone = True
__Plugin_Standalone_Usage = 'Provide one or more Quarantine sqlite databases as input to process. These are typically '\
                            'located at /Users/$USER/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2'

log = logging.getLogger('MAIN.' + __Plugin_Name) # Do not rename or remove this ! This is the logger object

#---- Do not change the variable names in above section ----#

class Quarantine:

    def __init__(self, id, timestamp, agent_bundle_id, agent_name, data_url, sender_name, sender_add, type_number, origin_title, origin_url, origin_alias, user, source):
        self.id = id
        self.timestamp = timestamp
        self.agent_bundle_id = agent_bundle_id
        self.agent_name = agent_name
        self.data_url = data_url
        self.sender_name = sender_name
        self.sender_add = sender_add
        self.type_number = type_number
        self.origin_title = origin_title
        self.origin_url = origin_url
        self.origin_alias = origin_alias
        self.user = user
        self.source_file = source

def PrintAll(quarantined, output_params):

    quarantine_info = [ ('EventID',DataType.TEXT),('TimeStamp',DataType.DATE),('AgentBundleID',DataType.TEXT),
                        ('AgentName',DataType.TEXT),
                        ('DataUrl',DataType.TEXT),('SenderName',DataType.TEXT),('SenderAddress', DataType.TEXT),
                        ('TypeNumber',DataType.INTEGER),('OriginTitle',DataType.TEXT),('OriginUrl',DataType.TEXT),
                        ('OriginAlias', DataType.BLOB),('User', DataType.TEXT),('Source',DataType.TEXT)
                      ]

    log.info (str(len(quarantined)) + " quarantine item(s) found")
    quarantine_list = []
    for q in quarantined:
        q_item =  [ q.id, q.timestamp, q.agent_bundle_id, q.agent_name, 
                    q.data_url, q.sender_name, q.sender_add, q.type_number,
                    q.origin_title, q.origin_url, q.origin_alias,
                    q.user, q.source_file
                  ]
        quarantine_list.append(q_item)
    WriteList("quarantine information", "Quarantine", quarantine_list, quarantine_info, output_params, '')

def ReadQuarantineDb(db, quarantined, source, user):
    '''Reads com.apple.LaunchServices.QuarantineEventsV2 sqlite db'''
    try:
        query = "SELECT LSQuarantineEventIdentifier as id, LSQuarantineTimeStamp as ts, LSQuarantineAgentBundleIdentifier as bundle, "\
                " LSQuarantineAgentName as agent_name, LSQuarantineDataURLString as data_url, "\
                " LSQuarantineSenderName as sender_name, LSQuarantineSenderAddress as sender_add, LSQuarantineTypeNumber as type_num, "\
                " LSQuarantineOriginTitle as o_title, LSQuarantineOriginURLString as o_url, LSQuarantineOriginAlias as o_alias "\
                " FROM LSQuarantineEvent "\
                " ORDER BY ts"
        db.row_factory = sqlite3.Row
        cursor = db.execute(query)
        for row in cursor:
            try:
                q_event = Quarantine(row['id'], CommonFunctions.ReadMacAbsoluteTime(row['ts']), row['bundle'], row['agent_name'], 
                                    row['data_url'], row['sender_name'], row['sender_add'], row['type_num'], 
                                    row['o_title'], row['o_url'], row['o_alias'], user, source)
                quarantined.append(q_event)
            except:
                log.exception('Error fetching row data')
    except:
        log.exception('Query  execution failed. Query was: ' + query)

def OpenDb(inputPath):
    log.info ("Processing file " + inputPath)
    try:
        conn = sqlite3.connect(inputPath)
        log.debug ("Opened database successfully")
        return conn
    except:
        log.exception ("Failed to open database, is it a valid DB?")
    return None

def OpenDbFromImage(mac_info, inputPath, user):
    '''Returns tuple of (connection, wrapper_obj)'''
    log.info ("Processing quarantine events for user '{}' from file {}".format(user, inputPath))
    try:
        sqlite = SqliteWrapper(mac_info)
        conn = sqlite.connect(inputPath)
        log.debug ("Opened database successfully")
        return conn, sqlite
    except Exception as ex:
        log.exception ("Failed to open database, is it a valid DB?")
    return None

def ProcessDbFromPath(mac_info, quarantined, source_path, user):
    if mac_info.IsValidFilePath(source_path):
        mac_info.ExportFile(source_path, __Plugin_Name, user + "_")
        db, wrapper = OpenDbFromImage(mac_info, source_path, user)
        if db != None:
            ReadQuarantineDb(db, quarantined, source_path, user)
            db.close()

def Plugin_Start(mac_info):
    '''Main Entry point function for plugin'''
    quarantined = []
    quarantine_path    = '{}/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2'

    for user in mac_info.users:
        if user.home_dir == '/private/var/empty': continue # Optimization, nothing should be here!
        source_path = quarantine_path.format(user.home_dir)
        ProcessDbFromPath(mac_info, quarantined, source_path, user.user_name)

    if len(quarantined) > 0:
        PrintAll(quarantined, mac_info.output_params)
    else:
        log.info('No quarantine events found')

def Plugin_Start_Standalone(input_files_list, output_params):
    log.info("Module Started as standalone")
    for input_path in input_files_list:
        log.debug("Input file passed was: " + input_path)
        quarantined = []
        db = OpenDb(input_path)
        if db != None:
            filename = os.path.basename(input_path)
            if filename.find('V2') > 0:
                ReadQuarantineDb(db, quarantined, input_path, '')
            else:
                log.info('Unknown database type, not a recognized file name')
            db.close()
        if len(quarantined) > 0:
            PrintAll(quarantined, output_params)
        else:
            log.info('No quarantine events found in {}'.format(input_path))

if __name__ == '__main__':
    print ("This plugin is a part of a framework and does not run independently on its own!")