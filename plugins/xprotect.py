'''
    Copyright (c) 2022-2024 Minoru Kobayashi

    This file is part of mac_apt (macOS Artifact Parsing Tool).
    Usage or distribution of this software/code is subject to the
    terms of the MIT License.

    xprotect.py
    ---------------
    This plugin parses XProtect diagnostic files and XProtect Behavior Service database and extract timestamp, signature/rule names, and so on.
'''

from __future__ import annotations

import logging
import os
import re
import sqlite3
import sys

from plugins.helpers.common import CommonFunctions
from plugins.helpers.macinfo import (DataType, EntryType, MacInfo,
                                     OutputParams, SqliteWrapper)
from plugins.helpers.writer import WriteList

py39 = False
if sys.version_info >= (3, 9):  # zoneinfo module is available from Python 3.9
    from datetime import datetime
    from zoneinfo import ZoneInfo
    py39 = True

__Plugin_Name = "XPROTECT"  # Cannot have spaces, and must be all caps!
__Plugin_Friendly_Name = "XProtect"
__Plugin_Version = "2.0"
__Plugin_Description = "Parses XProtect diagnostic files and XProtect Behavior Service database and extract timestamp, signature/rule names, and so on."
__Plugin_Author = "Minoru Kobayashi"
__Plugin_Author_Email = "unknownbit@gmail.com"

__Plugin_Modes = "MACOS,ARTIFACTONLY"  # Valid values are 'MACOS', 'IOS, 'ARTIFACTONLY'
__Plugin_ArtifactOnly_Usage = 'Provide folder path(s) that contains XProtect diagnostic files or XProtect Behavior Service diagnostic database files.'

log = logging.getLogger('MAIN.' + __Plugin_Name) # Do not rename or remove this ! This is the logger object

#---- Do not change the variable names in above section ----#

xp_diag_filename_regex = r'XProtect_(\d{4}-\d{2}-\d{2}-\d{2}\d{2}\d{2})_.+\.diag'


class XProtectDiagItem:
    def __init__(self, timestamp, signature_name, user_action, app_bundle_id, data_url, origin_url, download_timestamp, username, source):
        self.timestamp = timestamp
        self.signature_name = signature_name
        self.user_action = user_action
        self.app_bundle_id = app_bundle_id
        self.data_url = data_url
        self.origin_url = origin_url
        self.download_timestamp = download_timestamp
        self.username = username
        self.source = source


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


#
# Functions for processing Xprotect Diagnostic files (XProtect_YYYY-MM-DD-hhmmss_Hostname.diag)
#
def ParseXProtectDiag(plist: list, xp_diag_artifacts: list[XProtectDiagItem], username: str, xp_diag_path: str, timezone='UTC') -> None:
    filename_match = re.match(xp_diag_filename_regex, os.path.basename(xp_diag_path))
    diag_info: dict[str, str] = plist[0]
    if filename_match:
        timestamp_local = datetime.strptime(filename_match.group(1), '%Y-%m-%d-%H%M%S').astimezone(ZoneInfo(timezone))
        timestamp_utc = timestamp_local.astimezone(ZoneInfo('UTC')).strftime('%Y-%m-%d %H:%M:%S')  # Timestamps of other artifacts are usually in UTC, so local time should be converted to UTC.

        try:
            app_bundle_id = diag_info['LSQuarantineAgentBundleIdentifier']
            data_url = diag_info['LSQuarantineDataURL']
            origin_url = diag_info['LSQuarantineOriginURL']
            download_timestamp = diag_info['LSQuarantineTimeStamp']
        except KeyError:
            app_bundle_id = ''
            data_url = ''
            origin_url = ''
            download_timestamp = ''

        try:
            user_action = diag_info['UserAction']
            signature_name = diag_info['XProtectSignatureName']
        except KeyError:
            log.error('{} does not have necessary key(s).'.format(xp_diag_path))
            return

        item = XProtectDiagItem(timestamp_utc, signature_name, user_action, app_bundle_id, data_url, origin_url, download_timestamp, username, xp_diag_path)
        xp_diag_artifacts.append(item)


def ExtractAndReadXProtectDiag(mac_info: MacInfo, xp_diag_artifacts: list[XProtectDiagItem], username: str, xp_diag_path: str) -> None:
    success, plist, error = mac_info.ReadPlist(xp_diag_path)
    if success:
        log.debug(f'System timezone: {mac_info.timezone}')
        ParseXProtectDiag(plist, xp_diag_artifacts, username, xp_diag_path, mac_info.timezone)
        mac_info.ExportFile(xp_diag_path, __Plugin_Name, '', False)
    else:
        log.error('Could not open plist ' + xp_diag_path)
        log.error('Error was: ' + error)


def OpenAndReadXProtectDiag(xp_diag_artifacts: list[XProtectDiagItem], username: str, xp_diag_path: str) -> None:
    success, plist, error = CommonFunctions.ReadPlist(xp_diag_path)
    if success:
        ParseXProtectDiag(plist, xp_diag_artifacts, username, xp_diag_path)
    else:
        log.error('Could not open plist ' + xp_diag_path)
        log.error('Error was: ' + error)


def PrintAllXPDiag(xp_diag_artifacts: list[XProtectDiagItem], output_params: OutputParams, source_path: str) -> None:
    xp_diag_info = [('Date', DataType.TEXT), ('Signature_Name', DataType.TEXT), ('User_Action', DataType.TEXT),
                    ('Application_Bundle_ID', DataType.TEXT), ('DataURL', DataType.TEXT), ('OriginURL', DataType.TEXT), ('Download_Timestamp', DataType.TEXT),
                    ('User', DataType.TEXT), ('Source', DataType.TEXT)]

    data_list = []
    log.info(f"{len(xp_diag_artifacts)} XProtect Diagnostic artifact(s) found")
    for item in xp_diag_artifacts:
        data_list.append([item.timestamp, item.signature_name, item.user_action, item.app_bundle_id, item.data_url,
                          item.origin_url, item.download_timestamp, item.username, item.source])

    WriteList("XProtect Diag", "XProtect_Diag", data_list, xp_diag_info, output_params, source_path)


#
# Functions for processing XProtect Behavior Service database files (XPdb)
#
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
        log.warning(f"Unknown schema version = {schema_version}")
        return None


def ParseXPdb(db: sqlite3.Connection, xbs_artifacts: list[XPdbItem], xpdb_path: str) -> None:
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
        else:
            if schema_version is not None:
                log.error(f"Unsupported schema version: {schema_version}")
            else:
                log.error("No schema version found")
    else:
        log.error('There is no events table.')


def ExtractAndReadXPdb(mac_info: MacInfo, xbs_artifacts: list[XPdbItem], xpdb_path: str) -> None:
    db, wrapper = OpenDbFromImage(mac_info, xpdb_path)
    if db:
        ParseXPdb(db, xbs_artifacts, xpdb_path)
        mac_info.ExportFile(xpdb_path, __Plugin_Name, '', True)
        db.close()


def OpenAndReadXPdb(xbs_artifacts: list[XPdbItem], xpdb_path: str) -> None:
    db = OpenDb(xpdb_path)
    if db:
        ParseXPdb(db, xbs_artifacts, xpdb_path)
        db.close()


def PrintAllXPdb(xbs_artifacts: list[XPdbItem], output_params: OutputParams, source_path: str):
    xpdb_info = [('Id', DataType.TEXT), ('Date', DataType.TEXT), ('Violated_Rule', DataType.TEXT),
                 ('Exec_Path', DataType.TEXT), ('Exec_Cdhash', DataType.TEXT),
                 ('Exec_Signing_ID', DataType.TEXT), ('Exec_Team_ID', DataType.TEXT),
                 ('Exec_Sha256', DataType.TEXT), ('Exec_Is_Notarized', DataType.TEXT),
                 ('Responsible_Path', DataType.TEXT), ('Responsible_Cdhash', DataType.TEXT),
                 ('Responsible_Signing_ID', DataType.TEXT), ('Responsible_Team_ID', DataType.TEXT),
                 ('Responsible_Sha256', DataType.TEXT), ('Responsible_Is_Notarized', DataType.TEXT),
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
    xp_diag_artifacts: list[XProtectDiagItem] = list()
    xp_diag_base_path = '{}/Library/Logs/DiagnosticReports/'
    xbs_artifacts: list[XPdbItem] = list()
    xpdb_path = '/private/var/protected/xprotect/XPdb'
    processed_paths: set[str] = set()

    # Processing XProtect Diagnostic files
    if py39:
        for user in mac_info.users:
            if user.home_dir in processed_paths:
                continue  # Avoid processing same folder twice (some users have same folder! (Eg: root & daemon))
            processed_paths.add(user.home_dir)
            base_path = xp_diag_base_path.format(user.home_dir)
            if not mac_info.IsValidFolderPath(base_path):
                continue

            if mac_info.IsValidFilePath(base_path):
                folder_items = mac_info.ListItemsInFolder(base_path, EntryType.FILES, include_dates=False)
                xp_diag_files = [folder_item['name'] for folder_item in folder_items if re.match(xp_diag_filename_regex, folder_item['name'])]
                for xp_diag_file in xp_diag_files:
                    xp_diag_path = os.path.join(base_path, xp_diag_file)
                    if xp_diag_file['size'] > 0:
                        log.debug('Processing {}'.format(xp_diag_path))
                        ExtractAndReadXProtectDiag(mac_info, xp_diag_artifacts, user.username, xp_diag_path)
    else:
        log.warning('Python version is less than 3.9, so XProtect Diagnostic files will be skipped.')

    if len(xp_diag_artifacts) > 0:
        PrintAllXPDiag(xp_diag_artifacts, mac_info.output_params, '')
    else:
        log.info('No XProtect diag artifacts were found!')

    # Processing XProtect Behavior Service database files
    if mac_info.IsValidFilePath(xpdb_path) and mac_info.GetFileSize(xpdb_path) > 0:
        ExtractAndReadXPdb(mac_info, xbs_artifacts, xpdb_path)

    if len(xbs_artifacts) > 0:
        PrintAllXPdb(xbs_artifacts, mac_info.output_params, '')
    else:
        log.info('No XProtect Behavior Service artifacts were found!')


# def Plugin_Start_Standalone(input_folders_list, output_params):
def Plugin_Start_Standalone(input_files_list: list[str], output_params: OutputParams) -> None:
    '''Main entry point function when used on single artifacts (mac_apt_singleplugin), not on a full disk image'''
    log.info("Module Started as standalone")
    xp_diag_artifacts: list[XProtectDiagItem] = list()
    xbs_artifacts: list[XPdbItem] = list()

    if py39:
        log.warning('Since the timezone of the environment in which the diagnostic files (XProtect_YYYY-MM-DD-hhmmss_Hostname.diag) were created '
                    'cannot be determined, the timestamp in the filename is taken as UTC.')
    else:
        log.warning('Python version is less than 3.9, so XProtect Diagnostic files will be skipped.')

    for input_path in input_files_list:
        log.debug("Input file passed was: " + input_path)
        if os.path.isfile(input_path) and os.path.getsize(input_path) > 0:
            if py39 and re.match(xp_diag_filename_regex, os.path.basename(input_path)):
                log.debug('Processing {}'.format(input_path))
                OpenAndReadXProtectDiag(xp_diag_artifacts, 'N/A', input_path)
            elif os.path.basename(input_path) == 'XPdb':
                log.debug('Processing {}'.format(input_path))
                OpenAndReadXPdb(xbs_artifacts, input_path)
        else:
            log.info(f"File {input_path} does not exist or is empty.")

    if len(xp_diag_artifacts) > 0:
        PrintAllXPDiag(xp_diag_artifacts, output_params, input_path)
    else:
        log.info('No XProtect diag artifacts were found!')

    if len(xbs_artifacts) > 0:
        PrintAllXPdb(xbs_artifacts, output_params, input_path)
    else:
        log.info('No XProtect Behavior Service artifacts were found!')


def Plugin_Start_Ios(ios_info):
    '''Entry point for ios_apt plugin'''
    pass


if __name__ == '__main__':
    print("This plugin is a part of a framework and does not run independently on its own!")
