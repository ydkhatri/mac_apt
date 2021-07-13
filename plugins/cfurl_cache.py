'''
   Copyright (c) 2021 Minoru Kobayashi

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the
   terms of the MIT License.

   cfurl_cache.py
   ---------------
   This plugin parses CFURL cache and extract timestamp, URL, request,
   response, and received data.
'''

import os
import sqlite3
import plistlib

from plugins.helpers.common import CommonFunctions
from plugins.helpers.macinfo import *
from plugins.helpers.writer import *

import logging

__Plugin_Name = "CFURLCACHE" # Cannot have spaces, and must be all caps!
__Plugin_Friendly_Name = "CFURL cache"
__Plugin_Version = "1.0"
__Plugin_Description = "Parses CFURL cache and extract timestamp, URL, request, response, and received data."
__Plugin_Author = "Minoru Kobayashi"
__Plugin_Author_Email = "unknownbit@gmail.com"

__Plugin_Modes = "MACOS,ARTIFACTONLY" # Valid values are 'MACOS', 'IOS, 'ARTIFACTONLY' 
__Plugin_ArtifactOnly_Usage = 'Provide the path to "/Library/Cache/" folder under user home'

log = logging.getLogger('MAIN.' + __Plugin_Name) # Do not rename or remove this ! This is the logger object

# TODO
# Support iOS

#---- Do not change the variable names in above section ----#

class CfurlCacheItem:
    def __init__(self, timestamp, url, method, req_header, http_status, resp_header, isDataOnFS, received_data, username, app_bundle_id, source):
        self.timestamp = timestamp
        self.url = url
        self.method = method
        self.req_header = req_header
        self.http_status = http_status
        self.resp_header = resp_header
        self.isDataOnFS = isDataOnFS
        self.received_data = received_data
        self.username = username
        self.app_bundle_id = app_bundle_id
        self.source = source


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
    log.info ("Processing CFURL cache for user '{}' from file {}".format(user, inputPath))
    try:
        sqlite = SqliteWrapper(mac_info)
        conn = sqlite.connect(inputPath)
        if conn:
            log.debug ("Opened database successfully")
        return conn, sqlite
    except sqlite3.Error:
        log.exception ("Failed to open database, is it a valid DB?")
    return None, None

def CheckSchemaVersion(db):
    KnownSchemaVersion = (202,)
    db.row_factory = sqlite3.Row
    query = "SELECT schema_version FROM cfurl_cache_schema_version"
    cursor = db.execute(query)
    for row in cursor:
        schema_version = row['schema_version']

    if schema_version in KnownSchemaVersion:
        log.debug("Schema version = {}".format(schema_version))
        return schema_version
    else:
        log.debug("Unknown schema version = {}".format(schema_version))
        return None

def ParseRequestObject(object_data):
    object_array = plistlib.loads(object_data)['Array']
    http_req_method = object_array[18]
    header_list = object_array[19]
    req_headers = []
    for header, value in header_list.items():
        if header != '__hhaa__':
            req_headers.append("{}: {}".format(header, value))
    return http_req_method, "\r\n".join(req_headers)

def ParseResponseObject(object_data):
    object_array = plistlib.loads(object_data)['Array']
    http_status = object_array[3]
    header_list = object_array[4]
    resp_headers = []
    for header, value in header_list.items():
        if header != '__hhaa__':
            resp_headers.append("{}: {}".format(header, value))
    return http_status, "\r\n".join(resp_headers)

def ParseCFURLEntry(db, cfurl_cache_artifacts, username, app_bundle_id, cfurl_cache_db_path):
    db.row_factory = sqlite3.Row
    tables = CommonFunctions.GetTableNames(db)
    schema_version = 0
    if 'cfurl_cache_schema_version' in tables:
        schema_version = CheckSchemaVersion(db)
    else:
        log.debug('There is no cfurl_cache_schema_version table.')

    if 'cfurl_cache_response' in tables:
        if schema_version in (0, 202):
            query = """SELECT entry_ID, time_stamp, request_key, request_object, response_object, isDataOnFS, receiver_data 
                        FROM cfurl_cache_response JOIN cfurl_cache_blob_data USING (entry_ID) 
                        JOIN cfurl_cache_receiver_data USING (entry_ID)"""
            cursor = db.execute(query)
            for row in cursor:
                http_req_method, req_headers = ParseRequestObject(row['request_object'])
                http_status, resp_headers = ParseResponseObject(row['response_object'])
                if type(row['receiver_data']) == bytes:
                    received_data = row['receiver_data']
                elif type(row['receiver_data']) == str:
                    received_data = row['receiver_data'].encode()
                else:
                    log.error('Unknown type of "receiver_data": {}'.format(type(row['receiver_data'])))
                    continue

                item = CfurlCacheItem(row['time_stamp'], row['request_key'], http_req_method, req_headers, 
                                        http_status, resp_headers, row['isDataOnFS'], received_data, 
                                        username, app_bundle_id, cfurl_cache_db_path)
                cfurl_cache_artifacts.append(item)

def ExtractAndReadCFURLCache(mac_info, cfurl_cache_artifacts, username, app_bundle_id, folder_path):
    cfurl_cache_db_path = os.path.join(folder_path, 'Cache.db')
    db, wrapper = OpenDbFromImage(mac_info, cfurl_cache_db_path, username)
    if db:
        ParseCFURLEntry(db, cfurl_cache_artifacts, username, app_bundle_id, cfurl_cache_db_path)
        mac_info.ExportFolder(folder_path, os.path.join(__Plugin_Name, username), True)
        db.close()

def OpenAndReadCFURLCache(cfurl_cache_artifacts, username, app_bundle_id, folder_path):
    cfurl_cache_db_path = os.path.join(folder_path, 'Cache.db')
    db = OpenDb(cfurl_cache_db_path)
    if db:
        ParseCFURLEntry(db, cfurl_cache_artifacts, 'N/A', app_bundle_id, cfurl_cache_db_path)
        db.close()


def PrintAll(cfurl_cache_artifacts, output_params, source_path):
    cfurl_cache_info = [('Timestamp', DataType.DATE), ('URL', DataType.TEXT), ('Method', DataType.TEXT), ('Request_Header', DataType.TEXT), 
                        ('HTTP_Status', DataType.TEXT), ('Response_Header', DataType.TEXT), ('isDataOnFS', DataType.INTEGER), ('Received_Data', DataType.BLOB), 
                        ('User', DataType.TEXT), ('App_Bundle_ID', DataType.TEXT), ('Source', DataType.TEXT)]

    data_list = []
    log.info(f"{len(cfurl_cache_artifacts)} CFURL cache artifact(s) found")
    for item in cfurl_cache_artifacts:
        data_list.append([item.timestamp, item.url, item.method, item.req_header, item.http_status, item.resp_header, item.isDataOnFS, item.received_data, item.username, item.app_bundle_id, item.source])

    WriteList("CFURL cache", "cfurl_cache", data_list, cfurl_cache_info, output_params, source_path)

def Plugin_Start(mac_info):
    '''Main Entry point function for plugin'''
    cfurl_cache_artifacts = []
    cfurl_cache_base_path = '{}/Library/Caches/'

    for user in mac_info.users:
        cache_folder_list = mac_info.ListItemsInFolder(cfurl_cache_base_path.format(user.home_dir), EntryType.FOLDERS, include_dates=False)
        app_bundle_ids = [folder_item['name'] for folder_item in cache_folder_list]
        for app_bundle_id in app_bundle_ids:
            cache_folder_path = os.path.join(cfurl_cache_base_path.format(user.home_dir), app_bundle_id)
            cache_db_path = os.path.join(cache_folder_path, 'Cache.db')
            if mac_info.IsValidFilePath(cache_db_path) and mac_info.GetFileSize(cache_db_path) > 0:
                ExtractAndReadCFURLCache(mac_info, cfurl_cache_artifacts, user.user_name, app_bundle_id, cache_folder_path)

    if len(cfurl_cache_artifacts) > 0:
        PrintAll(cfurl_cache_artifacts, mac_info.output_params, '')
    else:
        log.info('No CFURL cache artifacts were found!')

def Plugin_Start_Standalone(input_files_list, output_params):
    '''Main entry point function when used on single artifacts (mac_apt_singleplugin), not on a full disk image'''
    log.info("Module Started as standalone")
    for input_path in input_files_list:
        log.debug("Input file passed was: " + input_path)
        cfurl_cache_artifacts = []
        if os.path.isdir(input_path):
            cache_folder_list = os.listdir(input_path)
            app_bundle_ids = [f for f in cache_folder_list if os.path.isdir(os.path.join(input_path, f))]
            for app_bundle_id in app_bundle_ids:
                cache_folder_path = os.path.join(input_path, app_bundle_id)
                cache_db_path = os.path.join(cache_folder_path, 'Cache.db')
                if os.path.isfile(cache_db_path) and os.path.getsize(cache_db_path) > 0:
                    OpenAndReadCFURLCache(cfurl_cache_artifacts, '', app_bundle_id, cache_folder_path)

        if len(cfurl_cache_artifacts) > 0:
            PrintAll(cfurl_cache_artifacts, output_params, input_path)
        else:
            log.info('No CFURL cache artifacts were found!')

def Plugin_Start_Ios(ios_info):
    '''Entry point for ios_apt plugin'''
    pass

if __name__ == '__main__':
    print ("This plugin is a part of a framework and does not run independently on its own!")