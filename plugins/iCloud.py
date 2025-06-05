'''
   Copyright (c) 2025 Yuya Hashimoto

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the
   terms of the MIT License.
   
'''
import json
import os
import logging
from plugins.helpers import macinfo

from enum import IntEnum
from plugins.helpers.common import CommonFunctions
from plugins.helpers.macinfo import *
from plugins.helpers.writer import *

__Plugin_Name = "ICLOUD"
__Plugin_Friendly_Name = "iCloud"
__Plugin_Version = "1.0"
__Plugin_Description =  'Extract items stored in iCloud Drive.'
__Plugin_Author = "Yuya Hashimoto"
__Plugin_Author_Email = "yhashimoto0707@gmail.com"


__Plugin_Modes = "MACOS,ARTIFACTONLY"
__Plugin_ArtifactOnly_Usage = 'Provide the path to either ".../Library/Application Support/CloudDocs/session/db" folder as argument'

log = logging.getLogger('MAIN.' + __Plugin_Name) # Do not rename or remove this ! This is the logger object

#---- Do not change the variable names in above section ----#

class iCloudDevices:
    def __init__(self, key, name, user, source):
        self.key = key
        self.name = name
        self.user = user
        self.source = source

class iCloudServerItems:
    def __init__(self, item_filename, item_path, item_birthtime, item_lastusedtime, version_device, version_device_name, version_name, version_size,
                 version_mtime,item_type_str, item_sharing_options, item_is_shared, user, source):
        self.item_filename = item_filename
        self.item_path = item_path
        self.item_birthtime = item_birthtime
        self.item_lastusedtime = item_lastusedtime
        self.version_device = version_device
        self.version_device_name = version_device_name
        self.version_name = version_name
        self.version_size = version_size
        self.version_mtime = version_mtime
        self.item_type_str = item_type_str
        self.item_sharing_options = item_sharing_options
        self.item_is_shared = item_is_shared
        self.user = user
        self.source = source

class iCloudClientItems:
    def __init__(self, rowid, item_filename, item_path, item_birthtime, item_lastusedtime, version_device, version_device_name, version_name, version_size,
                 version_mtime, app_library_name, item_type_str, item_sharing_options, item_is_shared, user, source):
        self.rowid = rowid
        self.item_filename = item_filename
        self.item_path = item_path
        self.item_birthtime = item_birthtime
        self.item_lastusedtime = item_lastusedtime
        self.version_device = version_device
        self.version_device_name = version_device_name
        self.version_name = version_name
        self.version_size = version_size
        self.version_mtime = version_mtime
        self.app_library_name = app_library_name
        self.item_type_str = item_type_str
        self.item_sharing_options = item_sharing_options
        self.item_is_shared = item_is_shared
        self.user = user
        self.source = source

def PrintAll(icloud_devices, icloud_server_items, icloud_client_items, output_params):

    icloud_device_info = [('key',DataType.INTEGER),('Name',DataType.TEXT),('User',DataType.TEXT),('Source',DataType.TEXT)]
    data_list = []
    log.info (f"{len(icloud_devices)} icloud device(s) found")
    for item in icloud_devices:
        data_list.append( [item.key, item.name, item.user, item.source] )
    WriteList("iCloudDevices", "iCloudDevices", data_list, icloud_device_info, output_params)

    icloud_server_item_info = [('item_filename',DataType.TEXT),('item_path',DataType.TEXT),('item_birthtime',DataType.DATE),
                               ('item_lastusedtime',DataType.DATE),('version_device',DataType.INTEGER),('version_device_name',DataType.TEXT),
                               ('version_name',DataType.TEXT),('version_size',DataType.INTEGER),('version_mtime',DataType.DATE),
                               ('item_type_str',DataType.TEXT),('item_sharing_options',DataType.INTEGER),('item_is_shared',DataType.TEXT),
                               ('User',DataType.TEXT),('Source',DataType.TEXT)]
    data_list = []
    log.info (f"{len(icloud_server_items)} icloud server item(s) found")
    for item in icloud_server_items:
        data_list.append( [item.item_filename, item.item_path, item.item_birthtime, item.item_lastusedtime, item.version_device,
                           item.version_device_name, item.version_name, item.version_size, item.version_mtime, item.item_type_str,
                           item.item_sharing_options, item.item_is_shared, item.user, item.source] )
    WriteList("iCloudServerItems", "iCloudServerItems", data_list, icloud_server_item_info, output_params)

    icloud_client_item_info = [('rowid',DataType.INTEGER),('item_filename',DataType.TEXT),('item_path',DataType.TEXT),
                               ('item_birthtime',DataType.DATE),('item_lastusedtime',DataType.DATE),('version_device',DataType.INTEGER),
                               ('version_device_name',DataType.TEXT),('version_name',DataType.TEXT),('version_size',DataType.INTEGER),('verion_mtime',DataType.DATE),
                               ('app_library_name',DataType.TEXT),('item_type_str',DataType.TEXT),('item_sharing_options',DataType.INTEGER),
                               ('item_is_shared',DataType.TEXT),('User',DataType.TEXT),('Source',DataType.TEXT)]
    data_list = []
    log.info (f"{len(icloud_client_items)} icloud client item(s) found")
    for item in icloud_client_items:
        data_list.append( [item.rowid, item.item_filename, item.item_path, item.item_birthtime, item.item_lastusedtime, item.version_device,
                           item.version_device_name, item.version_name, item.version_size, item.version_mtime, item.app_library_name,
                           item.item_type_str, item.item_sharing_options, item.item_is_shared, item.user, item.source] )
    WriteList("iCloudClientItems", "iCloudClientItems", data_list, icloud_client_item_info, output_params)

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

def convert_item_type(item_type):

    if item_type == 0:
        item_type_str = "Folder"
    elif item_type == 1:
        item_type_str = "File"
    else:
        item_type_str = "Unknown"

    return item_type_str

def process_server(icloud_devices, icloud_server_items, db, user, source_path):

    try:
        db.row_factory = sqlite3.Row
        cursor = db.cursor()

        query = \
        '''
            SELECT key, name FROM devices
        '''
        cursor = db.execute(query)
        for row in cursor:
            key = row['key']
            name = row['name']
            item = iCloudDevices(key, name, user, source_path)
            icloud_devices.append(item)

        query = \
        '''
            WITH RECURSIVE server_items_with_path AS (
              SELECT
                item_id,
                item_filename,
                item_filename AS item_path,
                1 AS depth,
                datetime(item_birthtime,"unixepoch") AS item_birthtime,
                datetime(item_lastusedtime,"unixepoch") AS item_lastusedtime,
                version_device,
                version_name,
                version_size,
                datetime(version_mtime,"unixepoch") AS version_mtime,
                item_type,
                item_sharing_options
              FROM server_items WHERE length(item_parent_id) < 16
              UNION ALL
              SELECT
                c.item_id,
                c.item_filename,
                p.item_path || '/' || c.item_filename,
                p.depth + 1,
                datetime(c.item_birthtime,"unixepoch"),
                datetime(c.item_lastusedtime,"unixepoch"),
                c.version_device,
                c.version_name,
                c.version_size,
                datetime(c.version_mtime,"unixepoch"),
                c.item_type,
                c.item_sharing_options
              FROM server_items c INNER JOIN server_items_with_path p ON (p.item_id = c.item_parent_id)
            )
            , ref AS (
              SELECT item_id, max(depth) as longest FROM server_items_with_path GROUP BY item_id
            )
            SELECT s.item_filename, s.item_path, s.item_birthtime, s.item_lastusedtime, s.version_device, s.version_name, s.version_size, s.version_mtime, s.item_type, s.item_sharing_options
            FROM server_items_with_path s
            INNER JOIN ref r ON (s.item_id = r.item_id)
            WHERE s.depth = r.longest
        '''
        cursor = db.execute(query)
        for row in cursor:
            item_filename = row['item_filename']
            item_path = row['item_path']
            item_birthtime = row['item_birthtime']
            item_lastusedtime = row['item_lastusedtime']
            version_device = row['version_device']
            item_type_str = convert_item_type(row['item_type'])
            version_device_name = ''
            version_name = row['version_name']
            version_size = row['version_size']
            version_mtime = row['version_mtime']
            item_sharing_options = row['item_sharing_options']
            item_is_shared = "Yes"
            if item_sharing_options == 0:
                item_is_shared = "No"
            for _d in icloud_devices:
                if _d.key == version_device:
                    version_device_name = _d.name
                    break
            item = iCloudServerItems(item_filename, item_path, item_birthtime, item_lastusedtime, version_device, version_device_name, version_name,
                                     version_size, version_mtime, item_type_str, item_sharing_options, item_is_shared, user, source_path)
            icloud_server_items.append(item)

    except sqlite3.Error:
        log.exception('DB read error from process_places()')

def process_client(icloud_client_items, icloud_devices, db, user, source_path):

    try:
        db.row_factory = sqlite3.Row
        cursor = db.cursor()

        query = \
        '''
            WITH RECURSIVE client_items_with_path AS (
              SELECT
                rowid,
                item_id,
                item_filename,
                item_filename AS item_path,
                1 AS depth,
                datetime(item_birthtime,"unixepoch") AS item_birthtime,
                datetime(item_lastusedtime,"unixepoch") AS item_lastusedtime,
                version_device,
                app_library_rowid,
                version_name,
                version_size,
                datetime(version_mtime,"unixepoch") AS version_mtime,
                item_type,
                item_sharing_options
              FROM client_items WHERE length(item_parent_id) < 16
              UNION ALL
              SELECT
                c.rowid,
                c.item_id,
                c.item_filename,
                p.item_path || '/' || c.item_filename,
                p.depth + 1,
                datetime(c.item_birthtime,"unixepoch"),
                datetime(c.item_lastusedtime,"unixepoch"),
                c.version_device,
                c.app_library_rowid,
                c.version_name,
                c.version_size,
                datetime(c.version_mtime,"unixepoch"),
                c.item_type,
                c.item_sharing_options
              FROM client_items c INNER JOIN client_items_with_path p ON (p.item_id = c.item_parent_id)
            )
            , ref AS (
              SELECT rowid, max(depth) AS longest FROM client_items_with_path GROUP BY rowid
            )
            SELECT c.rowid, c.item_filename, c.item_path, c.item_birthtime, c.item_lastusedtime, c.version_device, c.version_name, c.version_size, c.version_mtime,
                   a.app_library_name, c.item_type, c.item_type, c.item_sharing_options FROM client_items_with_path c
            INNER JOIN ref r ON (c.rowid = r.rowid)
            LEFT JOIN app_libraries a ON (c.app_library_rowid = a.rowid)
            WHERE c.depth = r.longest
        '''

        cursor = db.execute(query)
        for row in cursor:
            rowid = row['rowid']
            item_filename = row['item_filename']
            item_path = row['item_path']
            item_birthtime = row['item_birthtime']
            item_lastusedtime = row['item_lastusedtime']
            version_device = row['version_device']
            version_device_name = ''
            version_name = row['version_name']
            version_size = row['version_size']
            version_mtime = row['version_mtime']
            app_library_name = row['app_library_name']
            item_type_str = convert_item_type(row['item_type'])
            item_sharing_options = row['item_sharing_options']
            item_is_shared = "Yes"
            if item_sharing_options == 0:
                item_is_shared = "No"
            for _d in icloud_devices:
                if _d.key == version_device:
                    version_device_name = _d.name
                    break
            item = iCloudClientItems(rowid, item_filename, item_path, item_birthtime, item_lastusedtime, version_device, version_device_name, version_name, version_size,
                                     version_mtime, app_library_name, item_type_str, item_sharing_options, item_is_shared, user, source_path)
            icloud_client_items.append(item)

    except sqlite3.Error:
        log.exception('DB read error from process_places()')

def ProcessICloudServer(mac_info, source_path, user, icloud_devices, icloud_server_items):
    if mac_info.IsValidFilePath(source_path):
        mac_info.ExportFile(source_path, __Plugin_Name, user + '_')
        db, wrapper = OpenDbFromImage(mac_info, source_path)
        if db:
            process_server(icloud_devices, icloud_server_items, db, user, source_path)
            db.close()

def ProcessICloudClient(mac_info, source_path, user, icloud_client_items, icloud_devices):
    if mac_info.IsValidFilePath(source_path):
        mac_info.ExportFile(source_path, __Plugin_Name, user + '_')
        db, wrapper = OpenDbFromImage(mac_info, source_path)
        if db:
            process_client(icloud_client_items, icloud_devices, db, user, source_path)
            db.close()

def OpenServerDbAndRead(icloud_devices, icloud_server_items, user, file_path):
    conn = OpenDb(file_path)
    if conn:
        process_server(icloud_devices, icloud_server_items, conn, '', file_path)
        conn.close()

def OpenClientDbAndRead(icloud_client_items, icloud_devices, user, file_path):
    conn = OpenDb(file_path)
    if conn:
        process_client(icloud_client_items, icloud_devices, conn, '', file_path)
        conn.close()

def Plugin_Start(mac_info):
    '''Main Entry point function for plugin'''

    icloud_devices = []
    icloud_server_items = []
    icloud_client_items = []
    user_icloud_server_path = '{}/Library/Application Support/CloudDocs/session/db/server.db'
    user_icloud_client_path = '{}/Library/Application Support/CloudDocs/session/db/client.db'

    processed_paths = []

    for user in mac_info.users:
        if user.home_dir == '/private/var/empty': continue # Optimization, nothing should be here!
        elif user.home_dir == '/private/var/root': user_name = 'root' # Some other users use the same root folder, we will list all such users as 'root', as there is no way to tell
        if user.home_dir in processed_paths: continue # Avoid processing same folder twice (some users have same folder! (Eg: root & daemon))
        processed_paths.append(user.home_dir)
        source_path = user_icloud_server_path.format(user.home_dir)
        user_name = user.user_name
        if mac_info.IsValidFilePath(source_path):
            ProcessICloudServer(mac_info, source_path, user_name, icloud_devices, icloud_server_items)
        source_path = user_icloud_client_path.format(user.home_dir)
        if mac_info.IsValidFilePath(source_path):
            ProcessICloudClient(mac_info, source_path, user_name, icloud_client_items, icloud_devices)

    if len(icloud_devices) > 0 or len(icloud_server_items) or len(icloud_client_items):
        PrintAll(icloud_devices, icloud_server_items, icloud_client_items, mac_info.output_params)
    else:
        log.info('No iCloud artifacts were found!')

def Plugin_Start_Standalone(input_files_list, output_params):
    '''Main entry point function when used on single artifacts (mac_apt_singleplugin), not on a full disk image'''
    log.info("Module Started as standalone")

    for input_path in input_files_list:
        log.debug("Input path passed was: " + input_path)
        icloud_devices = []
        icloud_server_items = []
        icloud_client_items = []
        if os.path.isdir(input_path):
            file_names = os.listdir(input_path)
            for file_name in file_names:
                file_path = os.path.join(input_path, file_name)
                if file_name == 'server.db':
                    OpenServerDbAndRead(icloud_devices, icloud_server_items, '', file_path)
                elif file_name == 'client.db':
                    OpenClientDbAndRead(icloud_client_items, icloud_devices, '', file_path)
            if len(icloud_devices) > 0 or len(icloud_server_items) or len(icloud_client_items):
                PrintAll(icloud_devices, icloud_server_items, icloud_client_items, output_params)
            else:
                log.info('No iCloud artifacts found in {}'.format(input_path))
        else:
            log.error(f"Argument passed was not a folder : {input_path}")

def Plugin_Start_Ios(ios_info):
    '''Entry point for ios_apt plugin'''
    pass

if __name__ == '__main__':
    print ("This plugin is a part of a framework and does not run independently on its own!")