'''
   Copyright (c) 2026 Yogesh Khatri

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the
   terms of the MIT License.

   siri.py
   ---------------
   Reads Siri session history from AgentSessionStore.sqlite
   Attachments are not currently extracted.
'''

import os

from plugins.helpers.common import CommonFunctions
from plugins.helpers.macinfo import *
from plugins.helpers.writer import *

import logging

__Plugin_Name = "SIRI" # Cannot have spaces, and must be all caps!
__Plugin_Friendly_Name = "Siri session history"
__Plugin_Version = "1.0"
__Plugin_Description = "Read Siri session history"
__Plugin_Author = "Yogesh Khatri"
__Plugin_Author_Email = "yogesh@swiftforensics.com"

__Plugin_Modes = "MACOS,ARTIFACTONLY" # Valid values are 'MACOS', 'IOS, 'ARTIFACTONLY' 
__Plugin_ArtifactOnly_Usage = 'Provide path to ~/Library/Daemon Containers/<UUID>/Data/AgentSessionKit/AgentSessionStore.sqlite file'

log = logging.getLogger('MAIN.' + __Plugin_Name) # Do not rename or remove this ! This is the logger object

#---- Do not change the variable names in above section ----#

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

def ExtractAndReadDb(mac_info, artifacts, user, file_path, parser_function):
    if mac_info.IsValidFilePath(file_path):
        mac_info.ExportFile(file_path, __Plugin_Name, user + '_')
        db, wrapper = OpenDbFromImage(mac_info, file_path)
        if db:
            parser_function(artifacts, db, user, file_path)
            db.close()

def OpenLocalDbAndRead(artifacts, user, file_path, parser_function):
    conn = OpenDb(file_path)
    if conn:
        parser_function(artifacts, conn, '', file_path)
        conn.close()

def process_siri_session_history(artifacts, db, user, file_path):
    '''Process the AgentSessionStore.sqlite database'''
    query = '''
        SELECT 
            (SELECT  ZBUNDLEID FROM ZAGENTPROVENANCEENTITY WHERE Z_PK=ee.ZAGENTPROVENANCE) as agent,
            ee.ZSESSION as session, re.ZISPINNED as is_pinned, ee.ZCREATEDAT as event_created, 
            re.ZCREATIONDATE as record_created, re.ZLASTMODIFIEDDATE as record_last_mod,
            re.ZSUMMARY as summary, re.ZTITLE as title, ee.ZROLERAWVALUE as role_raw_value, ee.ZTEXTCONTENT as text_content, 
            --ee.ZSESSIONRESUMPTIONDATA as session_resumption_data,
            re.ZSELECTEDAGENTPROVENANCESETAT as selected_agent_provenance_set_at,
            re.ZSESSIONID as sessionid, re.ZSOURCEBUNDLEID as source_bundleid
        FROM ZAGENTSESSIONRECORDENTITY re
        LEFT JOIN ZAGENTSESSIONEVENTENTITY ee on ee.ZSESSION=re.Z_PK
        ORDER BY ee.ZSESSION ASC, ee.Z_PK ASC
    '''
    try:
        db.row_factory = sqlite3.Row
        cursor = db.cursor()
        cursor.execute(query)
        for row in cursor.fetchall():
            if row['role_raw_value'] == 'assistant' and row['text_content'] is None:
                # Skip assistant events with no text content (this is ususally the last record in the session)
                continue
            artifacts.append({
                'Session': row['session'],
                'Event Created': CommonFunctions.ReadMacAbsoluteTime(row['event_created']),
                'Title': row['title'],
                'Role Raw Value': row['role_raw_value'],
                'Text Content': row['text_content'],
                'Agent': row['agent'],
                'Is Pinned': row['is_pinned'],
                'Record Created': CommonFunctions.ReadMacAbsoluteTime(row['record_created']),
                'Record Last Mod': CommonFunctions.ReadMacAbsoluteTime(row['record_last_mod']),
                'Summary': row['summary'],
                #'Session Resumption Data': row['session_resumption_data'],
                'Selected Agent Provenance Set At': CommonFunctions.ReadMacAbsoluteTime(row['selected_agent_provenance_set_at']),
                'Session ID': row['sessionid'],
                'Source Bundle ID': row['source_bundleid'],
                'User': user,
                'Source': file_path
            })
    except (sqlite3.Error, sqlite3.OperationalError):
        log.exception("Failed to process AgentSessionStore.sqlite")

def PrintAll(history, output_params):

    history_info = [ ('Session',DataType.INTEGER),
                 ('Event Created',DataType.DATE),
                 ('Title',DataType.TEXT),
                 ('Role Raw Value',DataType.TEXT),('Text Content',DataType.TEXT),
                 ('Agent',DataType.TEXT),
                 ('Is Pinned',DataType.TEXT),
                 ('Record Created',DataType.DATE),('Record Last Mod',DataType.DATE),
                 ('Summary',DataType.TEXT),
                 #('Session Resumption Data',DataType.TEXT),
                 ('Selected Agent Provenance Set At',DataType.DATE),
                 ('Session ID',DataType.TEXT),('Source Bundle ID',DataType.TEXT),
                 ('User', DataType.TEXT),('Source',DataType.TEXT) ]

    log.info (f"{len(history)} siri history record(s) found")
    WriteList("Siri History", "Siri History", history, history_info, output_params, '')

def is_siri_plist(mac_info, plist_path):
    '''Check if the given plist file is related to Siri'''
    if mac_info is not None:
        f = mac_info.Open(plist_path)
        if f:
            success, plist_data, errors = CommonFunctions.ReadPlist(f)
            if success:
                return plist_data.get('MCMMetadataIdentifier', '') == 'com.apple.GenerativeFunctions.agentstored'
            else:
                log.error(f"Failed to read plist {plist_path}: {errors}")
        else:
            log.error(f'Failed to open file {plist_path}')
    else:
        try:
            with open(plist_path, 'rb') as f:
                plist_data = plistlib.load(f)
                return plist_data.get('MCMMetadataIdentifier', '') == 'com.apple.GenerativeFunctions.agentstored'
        except Exception:
            log.exception(f"Failed to read plist: {plist_path}")
    return False

def Plugin_Start(mac_info):
    '''Main Entry point function for plugin'''

    history = []
    daemon_container_folder = '{}/Library/Daemon Containers' #/<UUID>/Data/AgentSessionKit/AgentSessionStore.sqlite'
    processed_paths = []
    for user in mac_info.users:
        user_name = user.user_name
        if user.home_dir == '/private/var/empty': continue # Optimization, nothing should be here!
        elif user.home_dir == '/private/var/root': user_name = 'root' # Some other users use the same root folder, we will list such all users as 'root', as there is no way to tell
        if user.home_dir in processed_paths: continue # Avoid processing same folder twice (some users have same folder! (Eg: root & daemon))
        processed_paths.append(user.home_dir)
        daemon_container_path = daemon_container_folder.format(user.home_dir)
        if mac_info.IsValidFolderPath(daemon_container_path):
            folder_list = mac_info.ListItemsInFolder(daemon_container_path, EntryType.FOLDERS, False)
            if len(folder_list):
                for uuid in folder_list:
                    plist_path = f"{daemon_container_path}/{uuid['name']}/.com.apple.containermanagerd.metadata.plist"
                    if mac_info.IsValidFilePath(plist_path) and is_siri_plist(mac_info, plist_path):
                        siri_history_path = f"{daemon_container_path}/{uuid['name']}/Data/AgentSessionKit/AgentSessionStore.sqlite"
                        if mac_info.IsValidFilePath(siri_history_path):
                            ExtractAndReadDb(mac_info, history, user_name, siri_history_path, process_siri_session_history)
                            break
    if len(history) > 0:
        PrintAll(history, mac_info.output_params)
    else:
        log.info(f'No Siri session history found!')

def Plugin_Start_Standalone(input_files_list, output_params):
    '''Main entry point function when used on single artifacts (mac_apt_singleplugin), not on a full disk image'''
    log.info("Module Started as standalone")
    for input_path in input_files_list:
        log.debug("Input path passed was: " + input_path)
        history = []
        full_path = input_path
        file_name = os.path.basename(full_path)
        if file_name.lower() == 'agentsessionstore.sqlite':
            OpenLocalDbAndRead(history, '', full_path, process_siri_session_history)
            if len(history) > 0:
                PrintAll(history, output_params)
            else:
                log.info('No Siri session history found in {}'.format(input_path))

def Plugin_Start_Ios(ios_info):
    '''Entry point for ios_apt plugin'''
    pass

if __name__ == '__main__':
    print ("This plugin is a part of a framework and does not run independently on its own!")