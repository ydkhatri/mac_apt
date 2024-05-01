"""
Copyright (c) 2024 Minoru Kobayashi

This file is part of mac_apt (macOS Artifact Parsing Tool).
Usage or distribution of this software/code is subject to the
terms of the MIT License.

msrdc.py
---------------
This plugin parses Microsoft Remote Desktop settings (host names, group names, last connected timestamp, and shared folders) and extracts thumbnails.

TODO: Add support for parsing the following tables: ZGATEWAYENTITY, ZWORKSPACEENTITY (These are probably related to RD Gateway and Workspaces)
"""

from __future__ import annotations

import logging
import os
import sqlite3

import nska_deserialize as nd

from plugins.helpers.common import CommonFunctions
from plugins.helpers.macinfo import DataType, MacInfo, MountedIosInfo, OutputParams, SqliteWrapper
from plugins.helpers.writer import WriteList

__Plugin_Name = "MSRDC"  # Cannot have spaces, and must be all caps!
__Plugin_Friendly_Name = "Microsoft Remote Desktop Client"
__Plugin_Version = "1.0"
__Plugin_Description = "Parses Microsoft Remote Desktop settings and extracts thumbnails"
__Plugin_Author = "Minoru Kobayashi"
__Plugin_Author_Email = "unknownbit@gmail.com"

__Plugin_Modes = "MACOS,ARTIFACTONLY"  # Valid values are 'MACOS', 'IOS, 'ARTIFACTONLY'
__Plugin_ArtifactOnly_Usage = "Provide folder path(s) that contains XProtect diagnostic files or XProtect Behavior Service diagnostic database files."

log = logging.getLogger("MAIN." + __Plugin_Name)  # Do not rename or remove this ! This is the logger object

# ---- Do not change the variable names in above section ----#


class MSRDCItem:
    def __init__(self: MSRDCItem, date: str, conn_minutes: str,
                 hostname: str, host_id: str, friendly_hostname: str, groupname: str,
                 use_credential: str, friendly_credential_name: str, username: str, nil_passwd: str,
                 folder_redirection: str, source: str) -> None:  # fmt: skip
        self.date = date
        self.conn_minutes = conn_minutes
        self.hostname = hostname
        self.host_id = host_id
        self.friendly_hostname = friendly_hostname
        self.groupname = groupname
        self.use_credential = use_credential
        self.friendly_credential_name = friendly_credential_name
        self.username = username
        self.nil_passwd = nil_passwd
        self.folder_redirection = folder_redirection
        self.source = source


def OpenDb(inputPath: str) -> sqlite3.Connection | None:
    log.info("Processing file " + inputPath)
    try:
        conn = CommonFunctions.open_sqlite_db_readonly(inputPath)
        log.debug("Opened database successfully")
    except sqlite3.Error:
        log.exception("Failed to open database, is it a valid DB?")
        return None
    else:
        return conn


def OpenDbFromImage(mac_info: MacInfo, inputPath: str) -> tuple[sqlite3.Connection | None, SqliteWrapper | None]:
    """Returns tuple of (connection, wrapper_obj)"""
    log.info(f"Processing MSRDC database {inputPath}")
    try:
        sqlite = SqliteWrapper(mac_info)
        conn = sqlite.connect(inputPath)
        if conn:
            log.debug("Opened database successfully")
    except sqlite3.Error:
        log.exception("Failed to open database, is it a valid DB?")
        return None, None
    else:
        return conn, sqlite


def ParseMSRDCdb(db: sqlite3.Connection, msrdc_artifacts: list[MSRDCItem], msrdc_path: str) -> None:
    db.row_factory = sqlite3.Row
    tables = CommonFunctions.GetTableNames(db)
    if "ZBOOKMARKENTITY" in tables:
        query = """SELECT ZLASTCONNECTED,
                    ZHOSTNAME, ZBOOKMARKENTITY.ZFRIENDLYNAME AS FriendlyPCName,
                    ZBOOKMARKFOLDERENTITY.ZTITLE,
                    CASE
                        WHEN ZCREDENTIAL IS NULL THEN 'Ask when required'
                        ELSE 'Use User Account setting'
                    END AS Credential,
                    ZCREDENTIALENTITY.ZFRIENDLYNAME AS FriendlyAccountName, ZCREDENTIALENTITY.ZUSERNAME,
                    CASE ZCREDENTIALENTITY.ZNILPASSWORD
                        WHEN 0 THEN 'False'
                        WHEN 1 THEN 'True'
                    END AS NilPassword,
                    ZFOLDERREDIRECTIONCOLLECTION, ZBOOKMARKENTITY.ZID FROM ZBOOKMARKENTITY
                    LEFT JOIN ZBOOKMARKFOLDERENTITY ON ZBOOKMARKENTITY.ZBOOKMARKFOLDER = ZBOOKMARKFOLDERENTITY.Z_PK
                    LEFT JOIN ZCREDENTIALENTITY ON ZBOOKMARKENTITY.ZCREDENTIAL = ZCREDENTIALENTITY.Z_PK"""
        cursor = db.execute(query)
        for row in cursor:
            last_connected = nd.deserialize_plist_from_string(row["ZLASTCONNECTED"])["root"].strftime("%Y-%m-%d %H:%M:%S.%f")

            folder_redirection_info = [
                f"Path: {folder_redirection['path']}, Name: {folder_redirection['name']}, ReadOnly: {folder_redirection['readOnly']}"
                for folder_redirection in nd.deserialize_plist_from_string(row["ZFOLDERREDIRECTIONCOLLECTION"])
            ]
            folder_redirection_collection = "; ".join(folder_redirection_info)

            item = MSRDCItem(last_connected, "", row['ZHOSTNAME'], row['ZID'], row['FriendlyPCName'], row['ZTITLE'],
                             row['Credential'], row['FriendlyAccountName'], row['ZUSERNAME'],
                             row['NilPassword'], folder_redirection_collection, msrdc_path)  # fmt: skip
            msrdc_artifacts.append(item)
    else:
        log.error("There is no ZBOOKMARKENTITY table.")

    if "ZCONNECTIONTIMEENTITY" in tables:
        query = """SELECT ZSTARTTIME, ZMINUTESCONNECTED,
                    ZBOOKMARKENTITY.ZHOSTNAME, ZBOOKMARKENTITY.ZFRIENDLYNAME AS FriendlyPCName,
                    ZBOOKMARKFOLDERENTITY.ZTITLE,
                    CASE
                        WHEN ZCREDENTIAL IS NULL THEN 'Ask when required'
                        ELSE 'Use User Account setting'
                    END AS Credential,
                    ZCREDENTIALENTITY.ZFRIENDLYNAME AS FriendlyAccountName, ZCREDENTIALENTITY.ZUSERNAME,
                    CASE ZCREDENTIALENTITY.ZNILPASSWORD
                        WHEN 0 THEN 'False'
                        WHEN 1 THEN 'True'
                    END AS NilPassword,
                    ZFOLDERREDIRECTIONCOLLECTION, ZBOOKMARKENTITY.ZID FROM ZCONNECTIONTIMEENTITY
                    LEFT JOIN ZBOOKMARKENTITY ON ZCONNECTIONTIMEENTITY.Z_OPT = ZBOOKMARKENTITY.Z_PK
                    LEFT JOIN ZBOOKMARKFOLDERENTITY ON ZBOOKMARKENTITY.ZBOOKMARKFOLDER = ZBOOKMARKFOLDERENTITY.Z_PK
                    LEFT JOIN ZCREDENTIALENTITY ON ZBOOKMARKENTITY.ZCREDENTIAL = ZCREDENTIALENTITY.Z_PK"""
        cursor = db.execute(query)
        for row in cursor:
            start_time = CommonFunctions.ReadMacAbsoluteTime(row["ZSTARTTIME"]).strftime("%Y-%m-%d %H:%M:%S.%f")

            folder_redirection_info = [
                f"Path: {folder_redirection['path']}, Name: {folder_redirection['name']}, ReadOnly: {folder_redirection['readOnly']}"
                for folder_redirection in nd.deserialize_plist_from_string(row["ZFOLDERREDIRECTIONCOLLECTION"])
            ]
            folder_redirection_collection = "; ".join(folder_redirection_info)

            item = MSRDCItem(start_time, row["ZMINUTESCONNECTED"], row['ZHOSTNAME'], row['ZID'], row['FriendlyPCName'], row['ZTITLE'],
                             row['Credential'], row['FriendlyAccountName'], row['ZUSERNAME'],
                             row['NilPassword'], folder_redirection_collection, msrdc_path)  # fmt: skip
            msrdc_artifacts.append(item)
    else:
        log.error("There is no ZCONNECTIONTIMEENTITY table.")


def ExtractAndReadMSRDC(mac_info: MacInfo, msrdc_artifacts: list[MSRDCItem], username: str, msrdc_path: str) -> None:
    db, wrapper = OpenDbFromImage(mac_info, msrdc_path)
    if db:
        ParseMSRDCdb(db, msrdc_artifacts, msrdc_path)
        mac_info.ExportFile(msrdc_path, __Plugin_Name, username + "_", overwrite=True)
        db.close()


def OpenAndReadMSRDC(msrdc_artifacts: list[MSRDCItem], msrdc_path: str) -> None:
    db = OpenDb(msrdc_path)
    if db:
        ParseMSRDCdb(db, msrdc_artifacts, msrdc_path)
        db.close()


def PrintAll(msrdc_artifacts: list[MSRDCItem], output_params: OutputParams, source_path: str) -> None:
    msrdc_info = [('Date', DataType.TEXT), ('Connection_Minutes', DataType.TEXT),
                  ('Hostname', DataType.TEXT), ('Friendly_Hostname', DataType.TEXT), ('Groupname', DataType.TEXT),
                  ('Use_Credential', DataType.TEXT), ('Friendly_Credential_Name', DataType.TEXT), ('Username', DataType.TEXT),
                  ('Nil_Password', DataType.TEXT), ('Folder_Redirection', DataType.TEXT), ('Host_ID', DataType.TEXT), ('Source', DataType.TEXT)]  # fmt: skip

    log.info(f"{len(msrdc_artifacts)} Microsoft Remote Desktop Client artifact(s) found")
    data_list = [[item.date, item.conn_minutes, item.hostname, item.friendly_hostname, item.groupname,
                  item.use_credential, item.friendly_credential_name, item.username, item.nil_passwd,
                  item.folder_redirection, item.host_id, item.source] for item in msrdc_artifacts]  # fmt: skip

    WriteList("MSRDC", "MSRDC", data_list, msrdc_info, output_params, source_path)


def Plugin_Start(mac_info: MacInfo) -> None:
    """Main Entry point function for plugin"""
    msrdc_artifacts: list[MSRDCItem] = []
    msrdc_db_base_path = "{}/Library/Containers/com.microsoft.rdc.macos/Data/Library/Application Support/com.microsoft.rdc.macos/com.microsoft.rdc.application-data.sqlite"
    msrdc_thumbs_base_path = "{}/Library/Containers/com.microsoft.rdc.macos/Data/Library/Application Support/com.microsoft.rdc.macos/SupportingImages/"  # fmt: skip
    processed_paths: set[str] = set()

    for user in mac_info.users:
        if user.home_dir in processed_paths:
            continue  # Avoid processing same folder twice (some users have same folder! (Eg: root & daemon))
        processed_paths.add(user.home_dir)
        msrdc_db_path = msrdc_db_base_path.format(user.home_dir)
        if mac_info.IsValidFilePath(msrdc_db_path):
            ExtractAndReadMSRDC(mac_info, msrdc_artifacts, user.user_name, msrdc_db_path)

        msrdc_thumbs_path = msrdc_thumbs_base_path.format(user.home_dir)
        if mac_info.IsValidFolderPath(msrdc_thumbs_path):
            mac_info.ExportFolder(msrdc_thumbs_path, os.path.join(__Plugin_Name, user.user_name), overwrite=True)

    if len(msrdc_artifacts) > 0:
        PrintAll(msrdc_artifacts, mac_info.output_params, "")
        log.info("The filenames of thumbnails are the same as the value of Host_ID column in the MSRDC table, and their format is TIFF.")
    else:
        log.info("No Microsoft Remote Desktop Client artifacts were found!")


def Plugin_Start_Standalone(input_files_list: list[str], output_params: OutputParams) -> None:
    """Main entry point function when used on single artifacts (mac_apt_singleplugin), not on a full disk image"""
    log.info("Module Started as standalone")
    log.info("MSRDC plugin in standalone mode does not extract thumbnails.")
    msrdc_artifacts: list[MSRDCItem] = []

    for input_path in input_files_list:
        log.debug("Input file passed was: " + input_path)
        if os.path.isfile(input_path) and os.path.getsize(input_path) > 0:
            if input_path.endswith("com.microsoft.rdc.application-data.sqlite"):
                log.debug(f"Processing {input_path}")
                OpenAndReadMSRDC(msrdc_artifacts, input_path)
        else:
            log.info(f"File {input_path} does not exist or is empty.")

    if len(msrdc_artifacts) > 0:
        PrintAll(msrdc_artifacts, output_params, input_path)
    else:
        log.info("No Microsoft Remote Desktop Client artifacts were found!")


def Plugin_Start_Ios(ios_info: MountedIosInfo) -> None:
    """Entry point for ios_apt plugin"""


if __name__ == "__main__":
    print("This plugin is a part of a framework and does not run independently on its own!")
