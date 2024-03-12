'''
   Copyright (c) 2024 Minoru Kobayashi

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the
   terms of the MIT License.

   xprotect_behavior.py
   ---------------
   This plugin parses XProtect Behavior Service database and and extract timestamp, rule name, program paths, and so on.
'''
from __future__ import annotations

import logging
import os
import sqlite3

from plugins.helpers.common import CommonFunctions
from plugins.helpers.macinfo import (DataType, MacInfo, OutputParams,
                                     SqliteWrapper)
from plugins.helpers.writer import WriteList

__Plugin_Name = "XPROTECTBEHAVIOR" # Cannot have spaces, and must be all caps!
__Plugin_Friendly_Name = "XProtect Behavior Service"
__Plugin_Version = "1.0"
__Plugin_Description = "Parses XProtect Behavior Service diagnostic database and extract timestamp, rule name, program paths, and so on."
__Plugin_Author = "Minoru Kobayashi"
__Plugin_Author_Email = "unknownbit@gmail.com"

__Plugin_Modes = "MACOS,ARTIFACTONLY" # Valid values are 'MACOS', 'IOS, 'ARTIFACTONLY'
__Plugin_ArtifactOnly_Usage = 'Provide XProtect Behavior Service diagnostic database files'

log = logging.getLogger('MAIN.' + __Plugin_Name) # Do not rename or remove this ! This is the logger object

#---- Do not change the variable names in above section ----#


class XPdbItem:
    def __init__(self, id: str, date: str, violated_rule: str,
                 exec_path: str, exec_cdhash: str, exec_signing_id: str, exec_team_id: str, exec_sha256: str, exec_is_notarized: str,
                 responsible_path: str, responsible_cdhash: str, responsible_signing_id: str, responsible_team_id: str, responsible_sha256: str, responsible_is_notarized: str,
                 reported: str, profile_hash: str, source: str) -> None:
        self.id = id
        self.date = date
        self.violated_rule = violated_rule
        self.exec_path = exec_path
        self.exec_cdhash = exec_cdhash
        self.exec_signing_id = exec_signing_id
        self.exec_team_id = exec_team_id
        self.exec_sha256 = exec_sha256
        self.exec_is_notarized = exec_is_notarized
        self.responsible_path = responsible_path
        self.responsible_cdhash = responsible_cdhash
        self.responsible_signing_id = responsible_signing_id
        self.responsible_team_id = responsible_team_id
        self.responsible_sha256 = responsible_sha256
        self.responsible_is_notarized = responsible_is_notarized
        self.reported = reported
        self.profile_hash = profile_hash
        self.source = source


def OpenDb(inputPath: str) -> sqlite3.Connection | None:
    log.info("Processing file " + inputPath)
    try:
        conn = CommonFunctions.open_sqlite_db_readonly(inputPath)
        log.debug("Opened database successfully")
        return conn
    except sqlite3.Error:
        log.exception("Failed to open database, is it a valid DB?")
    return None


def OpenDbFromImage(mac_info: MacInfo, inputPath: str) -> tuple[sqlite3.Connection | None, SqliteWrapper | None]:
    '''Returns tuple of (connection, wrapper_obj)'''
    log.info(f"Processing XPdb file {inputPath}")
    try:
        sqlite = SqliteWrapper(mac_info)
        conn = sqlite.connect(inputPath)
        if conn:
            log.debug("Opened database successfully")
        return conn, sqlite
    except sqlite3.Error:
        log.exception("Failed to open database, is it a valid DB?")
    return None, None


def CheckSchemaVersion(db: sqlite3.Connection) -> int | None:
    KnownSchemaVersions = (1, )
    db.row_factory = sqlite3.Row
    query = "SELECT name, value FROM settings"
    cursor = db.execute(query)
    schema_version = None
    for row in cursor:
        if row['name'] == 'databaseSchemaVersion':
            schema_version = int(row['value'])
            break

    if schema_version in KnownSchemaVersions:
        log.debug(f"Schema version = {schema_version}")
        return schema_version
    else:
        log.debug(f"Unknown schema version = {schema_version}")
        return None


def ParseXPdb(db: sqlite3.Connection, xbs_artifacts: list[XPdbItem], xpdb_path: str):
    db.row_factory = sqlite3.Row
    tables = CommonFunctions.GetTableNames(db)
    schema_version = None
    if 'settings' in tables:
        schema_version = CheckSchemaVersion(db)
    else:
        log.debug('There is no settings table.')

    if 'events' in tables:
        if schema_version in (1, ):
            query = """SELECT id, dt AS date, violated_rule,
                        exec_path, exec_cdhash, exec_signing_id, exec_team_id, exec_sha256,
                        CASE exec_is_notarized
                            WHEN 0 THEN 'False'
                            WHEN 1 THEN 'True'
                        END AS exec_is_notarized,
                        responsible_path, responsible_cdhash, responsible_signing_id, responsible_team_id, responsible_sha256,
                        CASE responsible_is_notarized
                            WHEN 0 THEN 'False'
                            WHEN 1 THEN 'True'
                        END AS responsible_is_notarized,
                        CASE reported
                            WHEN 0 THEN 'False'
                            WHEN 1 THEN 'True'
                        END AS reported,
                        profile_hash
                        FROM events ORDER BY id"""
            cursor = db.execute(query)
            for row in cursor:
                item = XPdbItem(row['id'], row['date'], row['violated_rule'],
                                row['exec_path'], row['exec_cdhash'], row['exec_signing_id'], row['exec_team_id'], row['exec_sha256'], row['exec_is_notarized'],
                                row['responsible_path'], row['responsible_cdhash'], row['responsible_signing_id'], row['responsible_team_id'], row['responsible_sha256'], row['responsible_is_notarized'],
                                row['reported'], row['profile_hash'], xpdb_path)
                xbs_artifacts.append(item)


def ExtractAndReadXPdb(mac_info: MacInfo, xbs_artifacts: list[XPdbItem], xpdb_path: str):
    db, wrapper = OpenDbFromImage(mac_info, xpdb_path)
    if db:
        ParseXPdb(db, xbs_artifacts, xpdb_path)
        mac_info.ExportFile(xpdb_path, __Plugin_Name, '', True)
        db.close()


def OpenAndReadXPdb(xbs_artifacts: list[XPdbItem], xpdb_path: str):
    db = OpenDb(xpdb_path)
    if db:
        ParseXPdb(db, xbs_artifacts, xpdb_path)
        db.close()


def PrintAll(xbs_artifacts: list[XPdbItem], output_params: OutputParams, source_path: str):
    xpdb_info = [('Id', DataType.TEXT), ('Date', DataType.TEXT), ('Violated_Rule', DataType.TEXT),
                 ('Exec_Path', DataType.TEXT), ('Exec_Cdhash', DataType.TEXT), ('Exec_Signing_ID', DataType.TEXT), ('Exec_Team_ID', DataType.TEXT), ('Exec_Sha256', DataType.TEXT), ('Exec_Is_Notarized', DataType.TEXT),
                 ('Responsible_Path', DataType.TEXT), ('Responsible_Cdhash', DataType.TEXT), ('Responsible_Signing_ID', DataType.TEXT), ('Responsible_Team_ID', DataType.TEXT), ('Responsible_Sha256', DataType.TEXT), ('Responsible_Is_Notarized', DataType.TEXT),
                 ('Reported', DataType.TEXT), ('Profile_Hash', DataType.TEXT), ('Source', DataType.TEXT)]

    data_list = []
    log.info(f"{len(xbs_artifacts)} XProtect Behavior Service artifact(s) found")
    for item in xbs_artifacts:
        data_list.append([item.id, item.date, item.violated_rule,
                          item.exec_path, item.exec_cdhash, item.exec_signing_id, item.exec_team_id, item.exec_sha256, item.exec_is_notarized,
                          item.responsible_path, item.responsible_cdhash, item.responsible_signing_id, item.responsible_team_id, item.responsible_sha256, item.responsible_is_notarized,
                          item.reported, item.profile_hash, item.source])

    WriteList("XProtect Behavior Service", "XProtect_Behavior", data_list, xpdb_info, output_params, source_path)


def Plugin_Start(mac_info: MacInfo) -> None:
    '''Main Entry point function for plugin'''
    xbs_artifacts: list[XPdbItem] = list()
    xpdb_path = '/private/var/protected/xprotect/XPdb'

    if mac_info.IsValidFilePath(xpdb_path) and mac_info.GetFileSize(xpdb_path) > 0:
        ExtractAndReadXPdb(mac_info, xbs_artifacts, xpdb_path)

    if len(xbs_artifacts) > 0:
        PrintAll(xbs_artifacts, mac_info.output_params, '')
    else:
        log.info('No CFURL cache artifacts were found!')


def Plugin_Start_Standalone(input_files_list: list[str], output_params: OutputParams) -> None:
    '''Main entry point function when used on single artifacts (mac_apt_singleplugin), not on a full disk image'''
    log.info("Module Started as standalone")
    xbs_artifacts: list[XPdbItem] = list()
    for input_path in input_files_list:
        log.debug("Input file passed was: " + input_path)
        if os.path.isfile(input_path) and os.path.getsize(input_path) > 0:
            OpenAndReadXPdb(xbs_artifacts, input_path)
        else:
            log.info(f"File {input_path} does not exist or is empty")

    if len(xbs_artifacts) > 0:
        PrintAll(xbs_artifacts, output_params, input_path)
    else:
        log.info('No XProtect Behavior Service artifacts were found!')


def Plugin_Start_Ios(ios_info):
    '''Entry point for ios_apt plugin'''
    pass


if __name__ == '__main__':
    print("This plugin is a part of a framework and does not run independently on its own!")
