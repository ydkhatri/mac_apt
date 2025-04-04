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

__Plugin_Name = "WIFI_INTELLIGENCE"
__Plugin_Friendly_Name = "Wifi from Apple Intelligence collected data"
__Plugin_Version = "1.0"
__Plugin_Description = "Gets Wifi connect/disconnect information from Apple Intelligence db"
__Plugin_Author = "Yogesh Khatri"
__Plugin_Author_Email = "yogesh@swiftforensics.com"

__Plugin_Modes = "MACOS,ARTIFACTONLY"
__Plugin_ArtifactOnly_Usage = 'Provide the path to ".../Library/IntelligencePlatform/Artifacts/internal/views.db" as argument'

log = logging.getLogger('MAIN.' + __Plugin_Name) # Do not rename or remove this ! This is the logger object

#---- Do not change the variable names in above section ----#


class WifiItem:
    def __init__(self, site, connect_date, disconnect_date, duration, user, source):
        self.site = site
        self.connect_date = connect_date
        self.disconnect_date = disconnect_date
        self.duration = duration
        self.user = user
        self.source = source
        
def PrintAll(wifi_artifacts, output_params, source_path):
    wifi_info = [   ('Site',DataType.TEXT),
                    ('Connect',DataType.DATE),('Disconnect',DataType.DATE),('Duration',DataType.TEXT),
                    ('User', DataType.TEXT),('Source',DataType.TEXT)
                    ]
    data_list = []
    log.info (f"{len(wifi_artifacts)} wifi artifact(s) found")
    for item in wifi_artifacts:
        data_list.append( [ item.site, item.connect_date, item.disconnect_date, item.duration,
                            item.user, item.source ] )
    WriteList("wifi_intelligence", "wifi_intelligence", data_list, wifi_info, output_params, source_path)

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

def ExtractAndReadDb(mac_info, wifi_artifacts, user, file_path, parser_function):
    if mac_info.IsValidFilePath(file_path):
        mac_info.ExportFile(file_path, __Plugin_Name, user + '_')
        db, wrapper = OpenDbFromImage(mac_info, file_path)
        if db:
            parser_function(wifi_artifacts, db, user, file_path)
            db.close()

def OpenLocalDbAndRead(wifi_artifacts, user, file_path, parser_function):
    conn = OpenDb(file_path)
    if conn:
        parser_function(wifi_artifacts, conn, '', file_path)
        conn.close()

def process_wifi(wifi_artifacts, db, user, file_path):
    try:
        if not CommonFunctions.TableExists(db, 'wifiContextEvents'):
            log.warning('Table "wifiContextEvents" does not exist in db!')
            return
        db.row_factory = sqlite3.Row
        cursor = db.cursor()
        query = \
        ''' 
            SELECT behaviorType, behaviorIdentifier, timestamp FROM wifiContextEvents
            ORDER BY timestamp
        '''
        cursor = db.execute(query)
        last_timestamp = 0
        last_behavior = ''
        last_site = ''
        pending = False
        for row in cursor:
            timestamp = CommonFunctions.ReadMacAbsoluteTime(row['timestamp'])
            behaviorIdentifier = row['behaviorIdentifier']
            behavior, site = behaviorIdentifier.split(':')
            
            if behavior == 'Connect': # new connect
                # add last behavior if present
                if last_behavior:
                    if last_behavior == 'Connect':
                        AddWifiItem(wifi_artifacts, last_site, last_timestamp, '', '', user, file_path)
                    else:
                        AddWifiItem(wifi_artifacts, last_site, '', last_timestamp, '', user, file_path)
                # nothing else to do
                pending = True
            elif behavior == 'Disconnect':
                if last_behavior:
                    if last_behavior == 'Connect':
                        if last_site == site:
                            AddWifiItem(wifi_artifacts, site, last_timestamp, timestamp, '', user, file_path)
                        else:
                            # add last
                            AddWifiItem(wifi_artifacts, last_site, last_timestamp, '', '', user, file_path)
                            # add new
                            AddWifiItem(wifi_artifacts, site, '', timestamp, '', user, file_path)
                    else:
                        # add last
                        AddWifiItem(wifi_artifacts, last_site, '', last_timestamp, '', user, file_path)
                        # add new
                        AddWifiItem(wifi_artifacts, site, '', timestamp, '', user, file_path)
                else:
                    AddWifiItem(wifi_artifacts, site, '', timestamp, '', user, file_path)
                pending = False
            else:
                log.warning(f'Unknown behaviorIdentifier: {behaviorIdentifier}, timestamp: {timestamp}')
            if pending:
                last_timestamp = timestamp
                last_behavior = behavior
                last_site = site
            else:
                last_behavior = ''
        if pending:
            if last_behavior == 'Connect':
                AddWifiItem(wifi_artifacts, last_site, last_timestamp, '', '', user, file_path)
            else:
                AddWifiItem(wifi_artifacts, last_site, '', last_timestamp, '', user, file_path)

    except sqlite3.Error:
        log.exception('DB read error from process_wifi()')

def AddWifiItem(wifi_artifacts, site, connect_time, disconnect_time, duration, user, file_path):
    # calculate the duration
    if isinstance(connect_time, datetime.datetime) and isinstance(disconnect_time, datetime.datetime):
        duration = CommonFunctions.GetTimeTakenString(connect_time, disconnect_time, False)
    item = WifiItem(site, connect_time, disconnect_time, duration, user, file_path)
    wifi_artifacts.append(item)

def Plugin_Start(mac_info):
    '''Main Entry point function for plugin'''

    wifi_artifacts = [] #{} # { 'site1': [], 'site2' : [], ..}
    processed_paths = []
    wifi_path = '{}/Library/IntelligencePlatform/Artifacts/internal/views.db'

    for user in mac_info.users:
        if user.home_dir == '/private/var/empty': continue # Optimization, nothing should be here!
        elif user.home_dir == '/private/var/root': user_name = 'root' # Some other users use the same root folder, we will list all such users as 'root', as there is no way to tell
        if user.home_dir in processed_paths: continue # Avoid processing same folder twice (some users have same folder! (Eg: root & daemon))
        processed_paths.append(user.home_dir)
        source_path = wifi_path.format(user.home_dir)
        user_name = user.user_name
        if mac_info.IsValidFilePath(source_path):
            ExtractAndReadDb(mac_info, wifi_artifacts, user_name, source_path, process_wifi)
                
    if len(wifi_artifacts) > 0:
        PrintAll(wifi_artifacts, mac_info.output_params, '')
    else:
        log.info('No Apple intelligence wifi artifacts were found!')

def Plugin_Start_Standalone(input_files_list, output_params):
    '''Main entry point function when used on single artifacts (mac_apt_singleplugin), not on a full disk image'''
    log.info("Module Started as standalone")
    for input_path in input_files_list:
        log.debug("Input path passed was: " + input_path)
        wifi_artifacts = []
        if input_path.lower().endswith('views.db'):
            OpenLocalDbAndRead(wifi_artifacts, '', input_path, process_wifi)

        if len(wifi_artifacts) > 0:
            PrintAll(wifi_artifacts, output_params, input_path)
        else:
            log.info('No Apple intelligence wifi artifacts found in {}'.format(input_path))

def Plugin_Start_Ios(ios_info):
    '''Entry point for ios_apt plugin'''
    pass

if __name__ == '__main__':
    print ("This plugin is a part of a framework and does not run independently on its own!")