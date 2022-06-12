'''
    Copyright (c) 2022 Minoru Kobayashi

    This file is part of mac_apt (macOS Artifact Parsing Tool).
    Usage or distribution of this software/code is subject to the
    terms of the MIT License.

    tcc.py
    ---------------
    This plugin parses TCC.db and extract date, service name, app bundle id, and so on.
    Ref : https://github.com/mac4n6/APOLLO/blob/master/modules/tcc_db.txt
'''

import logging
import os
import sqlite3
from enum import Enum, auto

from plugins.helpers.common import CommonFunctions
from plugins.helpers.macinfo import *
from plugins.helpers.writer import *

__Plugin_Name = "TCC"  # Cannot have spaces, and must be all caps!
__Plugin_Friendly_Name = "TCC"
__Plugin_Version = "1.0"
__Plugin_Description = "Parses TCC.db and extract date, service name, app bundle id, and so on."
__Plugin_Author = "Minoru Kobayashi"
__Plugin_Author_Email = "unknownbit@gmail.com"

__Plugin_Modes = "MACOS,ARTIFACTONLY"  # Valid values are 'MACOS', 'IOS, 'ARTIFACTONLY'
__Plugin_ArtifactOnly_Usage = 'Provide TCC.db file path(s).'

log = logging.getLogger('MAIN.' + __Plugin_Name) # Do not rename or remove this ! This is the logger object

#---- Do not change the variable names in above section ----#


class TccDbType(Enum):
    UNKNOWN = auto()
    MACOS1015 = auto()
    MACOS11 = auto()

tcc_db_type = TccDbType.UNKNOWN

class TccItem_MacOs1015:
    def __init__(self, last_modified, service, client, client_type, allowed, prompt_count, indirect_object_identifier, username, source):
        self.last_modified = last_modified
        self.service = service
        self.client = client
        self.client_type = client_type
        self.allowed = allowed
        self.prompt_count = prompt_count
        self.indirect_object_identifier = indirect_object_identifier
        self.username = username
        self.source = source


class TccItem_MacOs11:
    def __init__(self, last_modified, service, client, client_type, allowed, auth_reason, indirect_object_identifier, username, source):
        self.last_modified = last_modified
        self.service = service
        self.client = client
        self.client_type = client_type
        self.allowed = allowed
        self.auth_reason = auth_reason
        self.indirect_object_identifier = indirect_object_identifier
        self.username = username
        self.source = source


def OpenDb(inputPath):
    log.info("Processing file " + inputPath)
    try:
        conn = CommonFunctions.open_sqlite_db_readonly(inputPath)
        log.debug("Opened database successfully")
        return conn
    except sqlite3.Error:
        log.exception("Failed to open database, is it a valid DB?")
    return None


def OpenDbFromImage(mac_info, inputPath, user):
    '''Returns tuple of (connection, wrapper_obj)'''
    log.info("Processing TCC.db for user '{}' from file {}".format(user, inputPath))
    try:
        sqlite = SqliteWrapper(mac_info)
        conn = sqlite.connect(inputPath)
        if conn:
            log.debug("Opened database successfully")
        return conn, sqlite
    except sqlite3.Error:
        log.exception("Failed to open database, is it a valid DB?")
    return None, None


def ParseTCCEntry(db, tcc_artifacts, username, tcc_db_path):
    global tcc_db_type
    db.row_factory = sqlite3.Row

    for column in db.execute('PRAGMA table_info("access");').fetchall():
        if column[1] == 'allowed':  # <= macOS 10.15
            log.debug('Table type: <= macOS 10.15')
            tcc_db_type = TccDbType.MACOS1015
            query = """SELECT
                        DATETIME(last_modified, 'UNIXEPOCH') AS last_modified, 
                        service, client, client_type, 
                        CASE allowed
                            WHEN 0 THEN 'False'
                            WHEN 1 THEN 'True'
                        END AS allowed,
                        prompt_count, indirect_object_identifier 
                        FROM access"""
            break
        elif column[1] == 'auth_value':  # >= macOS 11
            log.debug('Table type: >= macOS 11')
            tcc_db_type = TccDbType.MACOS11
            query = """SELECT 
                        DATETIME(last_modified, 'UNIXEPOCH') AS last_modified, 
                        service, client, client_type, 
                        CASE auth_value
                            WHEN 0 THEN 'False'
                            WHEN 2 THEN 'True'
                        END AS allowed,
                        auth_reason, indirect_object_identifier 
                        FROM access"""
            break

    if tcc_db_type == TccDbType.UNKNOWN:
        log.error('Unsupported TCC.db schema: {}'.format(tcc_db_path))
        return

    cursor = db.execute(query)
    if tcc_db_type == TccDbType.MACOS1015:
        for row in cursor:
            item = TccItem_MacOs1015(row['last_modified'], row['service'], row['client'], row['client_type'], 
                                     row['allowed'], row['prompt_count'], row['indirect_object_identifier'], 
                                     username, tcc_db_path)
            tcc_artifacts.append(item)
    elif tcc_db_type == TccDbType.MACOS11:
        for row in cursor:
            item = TccItem_MacOs11(row['last_modified'], row['service'], row['client'], row['client_type'], 
                                   row['allowed'], row['auth_reason'], row['indirect_object_identifier'], 
                                   username, tcc_db_path)
            tcc_artifacts.append(item)


def ExtractAndReadTccDb(mac_info, tcc_artifacts, username, tcc_db_path):
    db, wrapper = OpenDbFromImage(mac_info, tcc_db_path, username)
    if db:
        ParseTCCEntry(db, tcc_artifacts, username, tcc_db_path)
        mac_info.ExportFile(tcc_db_path, __Plugin_Name, username + '_', False)
        db.close()


def OpenAndReadTccDb(tcc_artifacts, username, tcc_db_path):
    db = OpenDb(tcc_db_path)
    if db:
        ParseTCCEntry(db, tcc_artifacts, username, tcc_db_path)
        db.close()


def PrintAll(tcc_artifacts, output_params, source_path):
    if tcc_db_type == TccDbType.MACOS1015:
        tcc_info = [('Last_Modified', DataType.TEXT), ('Service', DataType.TEXT), ('Client', DataType.TEXT), ('Client_Type', DataType.TEXT), 
                    ('Allowed', DataType.TEXT), ('Prompt_Count', DataType.TEXT), ('Indirect_Object_Identifier', DataType.TEXT), 
                    ('User', DataType.TEXT), ('Source', DataType.TEXT)]
    elif tcc_db_type == TccDbType.MACOS11:
        tcc_info = [('Last_Modified', DataType.TEXT), ('Service', DataType.TEXT), ('Client', DataType.TEXT),  ('Client_Type', DataType.TEXT), 
                    ('Allowed', DataType.TEXT), ('Auth_Reason', DataType.TEXT), ('Indirect_Object_Identifier', DataType.TEXT), 
                    ('User', DataType.TEXT), ('Source', DataType.TEXT)]

    data_list = []
    log.info(f"{len(tcc_artifacts)} TCC artifact(s) found")
    if tcc_db_type == TccDbType.MACOS1015:
        for item in tcc_artifacts:
            data_list.append([item.last_modified, item.service, item.client, item.client_type, item.allowed, 
                              item.prompt_count, item.indirect_object_identifier, item.username, item.source])
    if tcc_db_type == TccDbType.MACOS11:
        for item in tcc_artifacts:
            data_list.append([item.last_modified, item.service, item.client, item.client_type, item.allowed, 
                             item.auth_reason, item.indirect_object_identifier, item.username, item.source])

    WriteList("TCC", "TCC", data_list, tcc_info, output_params, source_path)


def Plugin_Start(mac_info):
    '''Main Entry point function for plugin'''
    tcc_artifacts = []
    tcc_db_base_path = '{}/Library/Application Support/com.apple.TCC/TCC.db'
    processed_paths = set()

    for user in [''] + mac_info.users:
        if user:
            if user.home_dir in processed_paths:
                continue  # Avoid processing same folder twice (some users have same folder! (Eg: root & daemon))
            processed_paths.add(user.home_dir)
            tcc_db_path = tcc_db_base_path.format(user.home_dir)
            # if not mac_info.IsValidFolderPath(tcc_db_path):
            #     continue
            username = user.user_name
        else:
            tcc_db_path = tcc_db_base_path.format('')
            username = 'System'

        if mac_info.IsValidFilePath(tcc_db_path) and mac_info.GetFileSize(tcc_db_path) > 0:
            ExtractAndReadTccDb(mac_info, tcc_artifacts, username, tcc_db_path)

    if len(tcc_artifacts) > 0:
        PrintAll(tcc_artifacts, mac_info.output_params, '')
    else:
        log.info('No TCC artifacts were found!')


def Plugin_Start_Standalone(input_files_list, output_params):
    '''Main entry point function when used on single artifacts (mac_apt_singleplugin), not on a full disk image'''
    log.info("Module Started as standalone")
    tcc_artifacts = []
    for input_path in input_files_list:
        log.debug("Input file passed was: " + input_path)
        if os.path.isfile(input_path) and os.path.getsize(input_path) > 0:
            OpenAndReadTccDb(tcc_artifacts, 'N/A', input_path)

    if len(tcc_artifacts) > 0:
        PrintAll(tcc_artifacts, output_params, input_path)
    else:
        log.info('No TCC artifacts were found!')


def Plugin_Start_Ios(ios_info):
    '''Entry point for ios_apt plugin'''
    pass


if __name__ == '__main__':
    print("This plugin is a part of a framework and does not run independently on its own!")
