'''
   Copyright (c) 2024 Yogesh Khatri 

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the 
   terms of the MIT License.
   
'''
import logging

from plugins.helpers.common import CommonFunctions
from plugins.helpers.macinfo import *
from plugins.helpers.writer import *

__Plugin_Name = "CALLHISTORY"
__Plugin_Friendly_Name = "Call history"
__Plugin_Version = "1.0"
__Plugin_Description = "Reads call history database at /Users/<user>/Library/Application Support/CallHistoryDB/CallHistory.storedata"
__Plugin_Author = "Yogesh Khatri"
__Plugin_Author_Email = "yogesh@swiftforensics.com"

__Plugin_Modes = "MACOS,ARTIFACTONLY"
__Plugin_ArtifactOnly_Usage = 'Provide the path to ".../Library/Application Support/CallHistoryDB/CallHistory.storedata" as argument'

log = logging.getLogger('MAIN.' + __Plugin_Name) # Do not rename or remove this ! This is the logger object

#---- Do not change the variable names in above section ----#


class CallHistoryItem:
    def __init__(self, date, duration, provider, calltype, originated, address, answered, facetime_data, disconnected_cause, country_code, location, read, user, source):
        self.date = date
        self.duration = duration
        self.provider = provider
        self.calltype = calltype
        self.originated = originated
        self.address = address
        self.answered = answered
        self.facetime_data = facetime_data
        self.disconnected_cause = disconnected_cause
        self.country_code = country_code
        self.location = location
        self.read = read
        self.user = user
        self.source = source
        
def PrintAll(callhistory_artifacts, output_params, source_path):
    callhistory_info = [ ('Date',DataType.DATE),('Duration',DataType.TEXT),('Provider',DataType.TEXT),
                        ('Call Type',DataType.TEXT),('Originated',DataType.TEXT),('Address',DataType.TEXT),
                        ('Answered',DataType.TEXT),('Face Time Data',DataType.INTEGER),
                        ('Disconnected Cause',DataType.TEXT),('Country Code',DataType.TEXT),
                        ('Location',DataType.TEXT),('Read',DataType.INTEGER),
                        ('User', DataType.TEXT),('Source',DataType.TEXT)
                    ]
    data_list = []
    log.info (f"{len(callhistory_artifacts)} callhistory artifact(s) found")
    for item in callhistory_artifacts:
        data_list.append( [ item.date, item.duration, item.provider, item.calltype, item.originated, item.address,
                            item.answered, item.facetime_data, item.disconnected_cause, item.country_code, 
                            item.location, item.read,
                            item.user, item.source ] )
    WriteList("callhistory", "callhistory", data_list, callhistory_info, output_params, source_path)

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
    try:
        sqlite = SqliteWrapper(mac_info)
        conn = sqlite.connect(inputPath)
        if conn:
            log.debug ("Opened database successfully")
        return conn, sqlite
    except sqlite3.Error as ex:
        log.exception ("Failed to open database, is it a valid DB?")
    return None, None

def ExtractAndReadDb(mac_info, callhistory_artifacts, user, file_path, parser_function):
    if mac_info.IsValidFilePath(file_path):
        mac_info.ExportFile(file_path, __Plugin_Name, user + '_')
        db, wrapper = OpenDbFromImage(mac_info, file_path)
        if db:
            parser_function(callhistory_artifacts, db, user, file_path)
            db.close()

def OpenLocalDbAndRead(callhistory_artifacts, user, file_path, parser_function):
    conn = OpenDb(file_path)
    if conn:
        parser_function(callhistory_artifacts, conn, '', file_path)
        conn.close()

def process_callhistory(callhistory_artifacts, db, user, file_path):
    try:
        db.row_factory = sqlite3.Row
        cursor = db.cursor()
        # Below query is a modified version of one here:
        # https://github.com/abrignoni/iLEAPP/blob/a7d09784f542e12b1be022a9c57cf65f1641a4e7/scripts/artifacts/callHistory.py#L38
        query = \
        ''' 
            SELECT
            ZDATE, -- datetime(ZDATE+978307200,'unixepoch') as ZDATE,
            strftime('%H:%M:%S',ZDURATION, 'unixepoch') as ZDURATION, 
            ZSERVICE_PROVIDER,
            CASE ZCALLTYPE
                WHEN 0 then 'Third-Party App'
                WHEN 1 then 'Phone Call'
                WHEN 8 then 'FaceTime Video'
                WHEN 16 then 'FaceTime Audio'
                ELSE ZCALLTYPE
            END ZCALLTYPE,
            CASE ZORIGINATED
                WHEN 0 then 'Incoming'
                WHEN 1 then 'Outgoing'
                ELSE ZORIGINATED
            END ZORIGINATED,  
            ZADDRESS,
            CASE ZANSWERED
                WHEN 0 then 'No'
                WHEN 1 then 'Yes'
                ELSE ZANSWERED
            END ZANSWERED,
            ZFACE_TIME_DATA,
            CASE
                WHEN ZDISCONNECTED_CAUSE = 6 AND  ZSERVICE_PROVIDER LIKE '%whatsapp' AND ZDURATION <> '0.0' then 'Ended'
                WHEN ZDISCONNECTED_CAUSE = 6 AND  ZSERVICE_PROVIDER LIKE '%whatsapp' AND ZORIGINATED = 1 then 'Missed or Rejected'
                WHEN ZDISCONNECTED_CAUSE = 2 AND  ZSERVICE_PROVIDER LIKE '%whatsapp' then 'Rejected'
                WHEN ZDISCONNECTED_CAUSE = 6 AND  ZSERVICE_PROVIDER LIKE '%whatsapp' then 'Missed'
                WHEN ZDISCONNECTED_CAUSE = 0 then 'Ended'
                WHEN ZDISCONNECTED_CAUSE = 6 then 'Rejected'
                ELSE ZDISCONNECTED_CAUSE
            END ZDISCONNECTED_CAUSE,
            upper(ZISO_COUNTRY_CODE) ZISO_COUNTRY_CODE,
            ZLOCATION, 
            ZREAD
            FROM ZCALLRECORD
        '''
        cursor = db.execute(query)
        for row in cursor:
            item = CallHistoryItem(
                        CommonFunctions.ReadMacAbsoluteTime(row['ZDATE']),
                        row['ZDURATION'],
                        row['ZSERVICE_PROVIDER'],
                        row['ZCALLTYPE'],
                        row['ZORIGINATED'],
                        row['ZADDRESS'],
                        row['ZANSWERED'],
                        row['ZFACE_TIME_DATA'],
                        row['ZDISCONNECTED_CAUSE'],
                        row['ZISO_COUNTRY_CODE'],
                        row['ZLOCATION'],
                        row['ZREAD'],
                        user, 
                        file_path
                    )
            callhistory_artifacts.append(item)

    except sqlite3.Error:
        log.exception('DB read error from process_callhistory()')

def Plugin_Start(mac_info):
    '''Main Entry point function for plugin'''

    callhistory_artifacts = []
    processed_paths = []
    callhistory_path = '{}/Library/Application Support/CallHistoryDB/CallHistory.storedata'

    for user in mac_info.users:
        if user.home_dir == '/private/var/empty': continue # Optimization, nothing should be here!
        elif user.home_dir == '/private/var/root': user_name = 'root' # Some other users use the same root folder, we will list all such users as 'root', as there is no way to tell
        if user.home_dir in processed_paths: continue # Avoid processing same folder twice (some users have same folder! (Eg: root & daemon))
        processed_paths.append(user.home_dir)
        source_path = callhistory_path.format(user.home_dir)
        user_name = user.user_name
        if mac_info.IsValidFilePath(source_path):
            ExtractAndReadDb(mac_info, callhistory_artifacts, user_name, source_path, process_callhistory)
                
    if len(callhistory_artifacts) > 0:
        PrintAll(callhistory_artifacts, mac_info.output_params, '')
    else:
        log.info('No callhistory artifacts were found!')

def Plugin_Start_Standalone(input_files_list, output_params):
    '''Main entry point function when used on single artifacts (mac_apt_singleplugin), not on a full disk image'''
    log.info("Module Started as standalone")
    for input_path in input_files_list:
        log.debug("Input path passed was: " + input_path)
        callhistory_artifacts = []
        if input_path.lower() == 'callhistory.storedata':
            OpenLocalDbAndRead(callhistory_artifacts, '', input_path, process_callhistory)

        if len(callhistory_artifacts) > 0:
            PrintAll(callhistory_artifacts, output_params, input_path)
        else:
            log.info('No callhistory artifacts found in {}'.format(input_path))

def Plugin_Start_Ios(ios_info):
    '''Entry point for ios_apt plugin'''
    pass

if __name__ == '__main__':
    print ("This plugin is a part of a framework and does not run independently on its own!")