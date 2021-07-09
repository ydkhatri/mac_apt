'''
   Copyright (c) 2020 Yogesh Khatri

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the
   terms of the MIT License.

   chrome.py
   ---------------
   This module gets Chrome browser artifacts
'''

from construct import *
from plugins.helpers.common import CommonFunctions
from plugins.helpers.macinfo import *
from plugins.helpers.writer import *

import json
import logging
import os
import sqlite3
import re

__Plugin_Name = "CHROME"
__Plugin_Friendly_Name = "Chrome"
__Plugin_Version = "1.0"
__Plugin_Description = "Read Chrome History, Top Sites, Downloads, Tabs/Sessions and Extension info"
__Plugin_Author = "Yogesh Khatri"
__Plugin_Author_Email = "yogesh@swiftforensics.com"

__Plugin_Modes = "MACOS,ARTIFACTONLY"
__Plugin_ArtifactOnly_Usage = 'Provide the path to "/Chrome/<Profile Name>" folder as argument'

log = logging.getLogger('MAIN.' + __Plugin_Name) # Do not rename or remove this ! This is the logger object

# TODO
# -----
# Cookies - url is readable, data is encrypted
# Favicons - can get url and icon
# Login Data - can get usernames, urls, password is encrypted
# Shortcuts - Like SpotlightShortcuts
# Web Data - Autofill data
#
# DONE ----
# Top Sites
# History + Downloads
# Extensions
# Last Session, Current Session - binary format
# Last Tabs, Current Tabs - binary format

#---- Do not change the variable names in above section ----#

Utf8Str = Struct (
    "size" / Int32ul,
    "data" / Bytes(this.size),
    "padding" / If (this.size % 4,  Bytes(4 - (this.size % 4)))
)

Utf16Str = Struct (
    "size" / Int32ul,
    "data" / Bytes(this.size * 2),
    "padding" / If (this.size % 2,  Bytes(2))
)

NavigationEntry = Struct (
    "unk" / Int32ul,
    "index" / Int32ul,
    "virtual_url_spec" / Utf8Str,
    "title" / Utf16Str,
    "encoded_page_statec" / Utf8Str,
    "transition_type" / Int32ul,
    "type_mask" / Int32ul,
    "referrer" / Utf8Str,
    "ignored_referrer_policy" / Int32ul,
    "original_request_url_specc" / Utf8Str,
    "is_overriding_user_agent" / Int32ul,
    "timestamp_internal_value" / Int64ul
)


class ChromeItemType(IntEnum):
    UNKNOWN = 0
    HISTORY = 1
    TOPSITE = 2
    BOOKMARK = 3
    DOWNLOAD = 4
    LASTTAB = 5
    CURRENTTAB = 6
    EXTENSION = 7
    LASTSESSION = 8
    CURRENTSESSION = 9

    def __str__(self):
        return self.name

class ChromeItem:
    def __init__(self, type, url, name, date, end_date, local_path, referrer, other, user, source):
        self.type = type
        self.url = url
        self.name = name
        self.date = date
        self.end_date = end_date
        self.local_path = local_path
        self.referrer = referrer
        self.other_info = other
        self.user = user
        self.source = source

def InsertUnique(chrome_items_list, item):
    for x in chrome_items_list:
        if x.user == item.user:
            if x.source == item.source:
                if x.type == item.type:
                    if x.url == item.url:
                        if x.name == item.name:
                            if x.date == item.date:
                                if x.end_date == item.end_date:
                                    if x.referrer == item.referrer:
                                        if x.other_info == item.other_info:
                                            return
    chrome_items_list.append(item)

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
    log.info ("Processing Chrome database for user '{}' from file {}".format(user, inputPath))
    try:
        sqlite = SqliteWrapper(mac_info)
        conn = sqlite.connect(inputPath)
        if conn:
            log.debug ("Opened database successfully")
        return conn, sqlite
    except sqlite3.Error:
        log.exception ("Failed to open database, is it a valid DB?")
    return None, None

def ReadTabsFile(chrome_artifacts, f, file_size, user, source):
    '''Reads 'Current/Last Tabs/Sessions' binary format'''
    if source.endswith('Last Tabs'):
        source_type = ChromeItemType.LASTTAB
    elif source.endswith('Current Tabs'):
        source_type = ChromeItemType.CURRENTTAB
    elif source.endswith('Last Session'):
        source_type = ChromeItemType.LASTSESSION
    elif source.endswith('Current Session'):
        source_type = ChromeItemType.CURRENTSESSION
    sig = f.read(4)
    ver = f.read(4)
    if sig != b'SNSS':
        log.error(f"ERR, wrong sig for {source}, expected SNSS, got {sig.hex()}")
    else:
        pos = 0x8
        if ver != b'\x01\0\0\0':
            log.warning(f'Not version 1, parser may fail! Version={ver.hex()}')

        while pos < file_size:
            f.seek(pos)
            size, command = struct.unpack('<HB', f.read(3))
            if size > 25:
                if command in (1, 6):
                    data = f.read(size - 1)
                    nav = NavigationEntry.parse(data[4:])
                    #print(nav)
                    url = nav.virtual_url_spec.data.decode('utf8', 'ignore')
                    title = nav.title.data.decode('utf16', 'ignore')
                    referrer = nav.referrer.data.decode('utf8', 'ignore')
                    ts = CommonFunctions.ReadChromeTime(nav.timestamp_internal_value)
                    url2 = nav.original_request_url_specc.data.decode('utf8', 'ignore')
                    if url2:
                        url2 = 'requested_orig_url=' + url2

                    if url or title:
                        InsertUnique(chrome_artifacts, ChromeItem(source_type, url, title, ts, None, None, referrer, url2, user, source))
                else:
                    if command != 19:
                        log.debug(f'size ({size}) > 25, command = {command}')
            pos += size + 2

def ReadTopSitesDb(chrome_artifacts, db, file_size, user, source):
    db.row_factory = sqlite3.Row
    tables = CommonFunctions.GetTableNames(db)
    if 'topsites' in tables: # meta.version == 4
        cursor = db.cursor()
        query = "SELECT url, url_rank, title from top_sites ORDER BY url_rank ASC"
        cursor = db.execute(query)
        for row in cursor:
            item = ChromeItem(ChromeItemType.TOPSITE, row['url'], row['title'], None, None, None, None, f"URL_RANK={row['url_rank']}", user, source)
            chrome_artifacts.append(item)
    elif 'thumbnails' in tables: # meta.version == 3
        cursor = db.cursor()
        query = "SELECT url, url_rank, title, last_updated from thumbnails ORDER BY url_rank ASC"
        cursor = db.execute(query)
        for row in cursor:
            item = ChromeItem(ChromeItemType.TOPSITE, row['url'], row['title'], CommonFunctions.ReadChromeTime(row['last_updated']),
                                None, None, None, f"URL_RANK={row['url_rank']}", user, source)
            chrome_artifacts.append(item)

def ReadHistoryDb(chrome_artifacts, db, file_size, user, source):
    db.row_factory = sqlite3.Row
    cursor = db.cursor()

    query = """SELECT urls.url, urls.title, urls.visit_count, urls.hidden, v.visit_time, v.visit_duration, v.from_visit,
            (SELECT urls.url FROM urls LEFT JOIN visits ON urls.id = visits.url where visits.id=v.from_visit) as referrer 
            FROM urls 
			LEFT JOIN visits v ON urls.id = v.url 		
            ORDER BY v.visit_time"""
    cursor = db.execute(query)
    for row in cursor:
        visit_duration = row['visit_duration']
        visit_time = row['visit_time']
        if visit_duration and (visit_time > 0):
            end_time = CommonFunctions.ReadChromeTime(visit_time + visit_duration)
        else:
            end_time = None
        
        item = ChromeItem(ChromeItemType.HISTORY, row['url'], row['title'], 
                        CommonFunctions.ReadChromeTime(visit_time), end_time, None, row['referrer'],
                        f"VisitCount={row['visit_count']}, Hidden={row['hidden']}", 
                        user, source)
        chrome_artifacts.append(item)

    # downloaded files
    query = """SELECT current_path, target_path, start_time, end_time, 
            received_bytes, total_bytes, c.url, referrer
            FROM downloads 
			LEFT JOIN downloads_url_chains c ON c.id = downloads.id
			where c.chain_index = 0
			ORDER BY start_time"""
    cursor = db.execute(query)
    for row in cursor:
        start_time =  CommonFunctions.ReadChromeTime(row['start_time'])
        if start_time == '':
            start_time = None
        end_time = CommonFunctions.ReadChromeTime(row['end_time'])
        if end_time == '':
            end_time = None
        path = row['target_path']
        if not path:
            path = row['current_path']
        downloaded_file_name = os.path.basename(path)
        item = ChromeItem(ChromeItemType.DOWNLOAD, row['url'], downloaded_file_name, 
                        start_time, end_time, row['referrer'], path, 
                        f"Received Bytes = {row['received_bytes']}/{row['total_bytes']}", 
                        user, source)
        chrome_artifacts.append(item)

def ReadMessageFromMsgJsonLocal(possible_paths, id):
    '''Will attempt to open filepath defined in possible_paths list,
        then read and return message defined by id'''
    text = ''
    for path in possible_paths:
        if os.path.exists(path):
            with open(path, 'r') as msg_file:
                messages = json.load(msg_file)
                text = GetMessage(id, messages)
                break
    return text

def ReadMessageFromMsgJson(mac_info, possible_paths, id, user):
    '''Will attempt to open filepath defined in possible_paths list,
        then read and return message defined by id'''
    text = ''
    for path in possible_paths:
        if mac_info.IsValidFilePath(path):
            mac_info.ExportFile(path, __Plugin_Name, user + "_chrome-extension_")
            msg_file = mac_info.Open(path)
            if msg_file:
                messages = json.loads(msg_file.read().decode('utf8', 'ignore'))
                text = GetMessage(id, messages)
                break
    return text

def GetMessage(id, msg_json):
    text = ''
    try:
        text = msg_json[id]['message']
    except (KeyError, ValueError):
        # Perhaps case mismatch
        try:
            id_lower = id.lower()
            for k, v in msg_json.items():
                if k.lower() == id_lower:
                    for x, y in v.items():
                        if x.lower() == 'message':
                            text = y
                            break
                if text:
                    break
        except (KeyError, ValueError, TypeError):
            log.error('Could not get message from manifest file - {path}')
        if not text:
            log.error('Could not get message from manifest file - {path}')
    return text

def ProcessExtensionsLocal(chrome_artifacts, user, source):
    ext_obfuscated_names = os.listdir(source)
    for obfuscated_dir_name in ext_obfuscated_names:
        ext_folder_path = os.path.join(source, obfuscated_dir_name)
        if os.path.isdir(ext_folder_path):
            ext_folders = os.listdir(ext_folder_path)
            for ver_folder in ext_folders:
                if not os.path.isdir(os.path.join(source, obfuscated_dir_name, ver_folder)):
                    continue
                manifest_path = os.path.join(source, obfuscated_dir_name, ver_folder, 'manifest.json')
                locales_path = os.path.join(source, obfuscated_dir_name, ver_folder, '_locales')
                # Read manifest
                if not os.path.isfile(manifest_path):
                    log.error(f'Could not find manifest.json @ {manifest_path}')
                with open(manifest_path, 'r') as manifest_file:
                    manifest = ReadJson(manifest_file.read())
                    manifest_file.close()
                    if not manifest: continue
                    name = manifest.get('name', '')
                    desc = manifest.get('description', '')
                    version = manifest.get('version', '')

                    if name.startswith('__MSG_') or \
                        desc.startswith('__MSG_') or \
                        version.startswith('__MSG_'): # Must find it in the _locales
                        if os.path.isdir(locales_path):
                            en_path = os.path.join(locales_path, 'en', 'messages.json')
                            en_path_us = os.path.join(locales_path, 'en_US', 'messages.json')
                            en_path_gb = os.path.join(locales_path, 'en_GB', 'messages.json')
                            msg_json_possible_paths = (en_path, en_path_us, en_path_gb)
                            if name.startswith('__MSG_'):
                                name = ReadMessageFromMsgJsonLocal(msg_json_possible_paths, name[6:-2])
                            if desc.startswith('__MSG_'):
                                desc = ReadMessageFromMsgJsonLocal(msg_json_possible_paths, desc[6:-2])
                            if version.startswith('__MSG_'):
                                version = ReadMessageFromMsgJsonLocal(msg_json_possible_paths, version[6:-2])
                    log.debug(f"EXT NAME={name}, Ver={version}, DESC={desc}")
                    item = ChromeItem(ChromeItemType.EXTENSION, '', f"{name} (version {version})", None, None, None, None, desc, '', manifest_path)
                    chrome_artifacts.append(item)
                break

def ReadJson(data):
    try:
        return json.loads(data)
    except json.decoder.JSONDecodeError:
        log.error('Failed to parse json. Input Data was ' + str(data))
    return {}

def ProcessExtensions(mac_info, chrome_artifacts, user, source):
    ext_obfuscated_names = mac_info.ListItemsInFolder(source, EntryType.FOLDERS, False)
    for obfuscated_dir_name in ext_obfuscated_names:
        ext_folder_path = source + '/' + obfuscated_dir_name['name']
        if mac_info.IsValidFolderPath(ext_folder_path):
            ext_folders = mac_info.ListItemsInFolder(ext_folder_path, EntryType.FOLDERS, False)
            for ver_folder in ext_folders:
                if not mac_info.IsValidFolderPath(ext_folder_path + '/' + ver_folder['name']):
                    continue
                manifest_path = ext_folder_path + '/' + ver_folder['name'] + '/manifest.json'
                locales_path = ext_folder_path + '/' + ver_folder['name'] + '/_locales'
                # Read manifest
                if not mac_info.IsValidFilePath(manifest_path):
                    log.error(f'Could not find manifest.json @ {manifest_path}')
                mac_info.ExportFile(manifest_path, __Plugin_Name, user + '_chrome-extension_', False)
                manifest_file = mac_info.Open(manifest_path)
                if manifest_file:
                    manifest_data = manifest_file.read().decode('utf8', 'ignore')
                    manifest_file.close()
                    manifest = ReadJson(manifest_data)
                    if not manifest: continue
                    name = manifest.get('name', '')
                    desc = manifest.get('description', '')
                    version = manifest.get('version', '')
                    
                    if name.startswith('__MSG_') or \
                        desc.startswith('__MSG_') or \
                        version.startswith('__MSG_'): # Must find it in the _locales
                        if mac_info.IsValidFolderPath(locales_path):
                            en_path = locales_path + '/en/messages.json'
                            en_path_us = locales_path + '/en_US/messages.json'
                            en_path_gb = locales_path + '/en_GB/messages.json'
                            msg_json_possible_paths = (en_path, en_path_us, en_path_gb)
                            if name.startswith('__MSG_'):
                                name = ReadMessageFromMsgJson(mac_info, msg_json_possible_paths, name[6:-2], user)
                            if desc.startswith('__MSG_'):
                                desc = ReadMessageFromMsgJson(mac_info, msg_json_possible_paths, desc[6:-2], user)
                            if version.startswith('__MSG_'):
                                version = ReadMessageFromMsgJson(mac_info, msg_json_possible_paths, version[6:-2], user)
                    log.debug(f"EXT NAME={name}, Ver={version}, DESC={desc}")
                    item = ChromeItem(ChromeItemType.EXTENSION, '', f"{name} (version {version})", None, None, None, None, desc, user, manifest_path)
                    chrome_artifacts.append(item)
                else:
                    log.error(f"Failed to open {manifest_path}")
                break


def PrintAll(chrome_artifacts, output_params, source_path):
    chrome_info = [ ('Type',DataType.TEXT),('Name_or_Title',DataType.TEXT),('URL',DataType.TEXT),
                    ('Date', DataType.DATE),('End Date', DataType.DATE),
                    ('Local Path', DataType.TEXT),('Referrer or Previous Page', DataType.TEXT),
                    ('Other_Info', DataType.TEXT),('User', DataType.TEXT),
                    ('Source',DataType.TEXT) 
                  ]

    data_list = []
    log.info (f"{len(chrome_artifacts)} chrome artifact(s) found")
    for item in chrome_artifacts:
        url = item.url
        data_list.append( [ str(item.type), item.name, url, 
                            item.date, item.end_date, 
                            item.local_path, item.referrer,
                            item.other_info, item.user, item.source ] )

    WriteList("Chrome", "Chrome", data_list, chrome_info, output_params, source_path)

def ExtractAndReadDb(mac_info, chrome_artifacts, user, file_path, file_size, parser_function):
    mac_info.ExportFile(file_path, __Plugin_Name, user + '_')
    db, wrapper = OpenDbFromImage(mac_info, file_path, user)
    if db:
        parser_function(chrome_artifacts, db, file_size, user, file_path)
        db.close()

def ExtractAndReadFile(mac_info, chrome_artifacts, user, file_path, file_size, parser_function):
    mac_info.ExportFile(file_path, __Plugin_Name, user + '_')
    log.info ("Processing Chrome file {} for user {}".format(file_path, user))
    f = mac_info.Open(file_path)
    if f:
        parser_function(chrome_artifacts, f, file_size, user, file_path)
        f.close()

def OpenLocalDbAndRead(chrome_artifacts, user, file_path, file_size, parser_function):
    conn = OpenDb(file_path)
    if conn:
        parser_function(chrome_artifacts, conn, file_size, '', file_path)
        conn.close()

def OpenLocalFileAndRead(chrome_artifacts, user, file_path, file_size, parser_function):
    f = open(file_path, 'rb')
    log.info ("Processing Chrome file {}".format(file_path))
    parser_function(chrome_artifacts, f, file_size, '', file_path)
    f.close()

def Plugin_Start(mac_info):
    '''Main Entry point function for plugin'''
    chrome_artifacts = []
    chrome_profile_base_path = '{}/Library/Application Support/Google/Chrome/'
    chrome_profile_regex = '(Default|Profile \d+|Guest Profile)'
    processed_paths = []
    for user in mac_info.users:
        user_name = user.user_name
        if user.home_dir == '/private/var/empty': continue # Optimization, nothing should be here!
        elif user.home_dir == '/private/var/root': user_name = 'root' # Some other users use the same root folder, we will list all such users as 'root', as there is no way to tell
        if user.home_dir in processed_paths: continue # Avoid processing same folder twice (some users have same folder! (Eg: root & daemon))
        processed_paths.append(user.home_dir)
        folders_list = mac_info.ListItemsInFolder(chrome_profile_base_path.format(user.home_dir), EntryType.FOLDERS, include_dates=False)
        chrome_profile_names = [folder_item['name'] for folder_item in folders_list if re.match(chrome_profile_regex, folder_item['name'])]
        for chrome_profile_name in chrome_profile_names:
            source_path = os.path.join(chrome_profile_base_path.format(user.home_dir), chrome_profile_name)
            if mac_info.IsValidFolderPath(source_path):
                files_list = mac_info.ListItemsInFolder(source_path, EntryType.FILES_AND_FOLDERS, include_dates=False)
                user_profile_name = user_name + '_' + chrome_profile_name.replace(' ', '_')
                for file_entry in files_list:
                    if file_entry['type'] == EntryType.FILES:
                        if file_entry['size'] == 0: 
                            continue
                        if file_entry['name'] == 'Top Sites':
                            ExtractAndReadDb(mac_info, chrome_artifacts, user_profile_name, source_path + '/Top Sites', file_entry['size'], ReadTopSitesDb)
                        elif file_entry['name'] == 'History':
                            ExtractAndReadDb(mac_info, chrome_artifacts, user_profile_name, source_path + '/History', file_entry['size'], ReadHistoryDb)
                        elif file_entry['name'] == 'Last Tabs':
                            ExtractAndReadFile(mac_info, chrome_artifacts, user_profile_name, source_path + '/Last Tabs', file_entry['size'], ReadTabsFile)
                        elif file_entry['name'] == 'Current Tabs':
                            ExtractAndReadFile(mac_info, chrome_artifacts, user_profile_name, source_path + '/Current Tabs', file_entry['size'], ReadTabsFile)
                        elif file_entry['name'] == 'Last Session':
                            ExtractAndReadFile(mac_info, chrome_artifacts, user_profile_name, source_path + '/Last Session', file_entry['size'], ReadTabsFile)
                        elif file_entry['name'] == 'Current Session':
                            ExtractAndReadFile(mac_info, chrome_artifacts, user_profile_name, source_path + '/Current Session', file_entry['size'], ReadTabsFile)
                    else: # Folder
                        if file_entry['name'] == 'Extensions':
                            ProcessExtensions(mac_info, chrome_artifacts, user_profile_name, source_path + '/Extensions')

    if len(chrome_artifacts) > 0:
        PrintAll(chrome_artifacts, mac_info.output_params, '')
    else:
        log.info('No Chrome artifacts were found!')

def Plugin_Start_Standalone(input_files_list, output_params):
    '''Main entry point function when used on single artifacts (mac_apt_singleplugin), not on a full disk image'''
    log.info("Module Started as standalone")
    for input_path in input_files_list:
        log.debug("Input file passed was: " + input_path)
        chrome_artifacts = []
        if os.path.isdir(input_path):
            file_names = os.listdir(input_path)
            for file_name in file_names:
                file_path = os.path.join(input_path, file_name)
                file_size = os.path.getsize(file_path)
                if file_name == 'Top Sites':
                    OpenLocalDbAndRead(chrome_artifacts, '', file_path, file_size, ReadTopSitesDb)
                elif file_name == 'History':
                    OpenLocalDbAndRead(chrome_artifacts, '', file_path, file_size, ReadHistoryDb)
                elif file_name == 'Last Tabs':
                    OpenLocalFileAndRead(chrome_artifacts, '', file_path, file_size, ReadTabsFile)
                elif file_name == 'Current Tabs':
                    OpenLocalFileAndRead(chrome_artifacts, '', file_path, file_size, ReadTabsFile)
                elif file_name == 'Last Session':
                    OpenLocalFileAndRead(chrome_artifacts, '', file_path, file_size, ReadTabsFile)
                elif file_name == 'Current Session':
                    OpenLocalFileAndRead(chrome_artifacts, '', file_path, file_size, ReadTabsFile)
                elif file_name == 'Extensions' and os.path.isdir(file_path):
                    ProcessExtensionsLocal(chrome_artifacts, '', file_path)

            if len(chrome_artifacts) > 0:
                PrintAll(chrome_artifacts, output_params, input_path)
            else:
                log.info('No chrome artifacts found in {}'.format(input_path))
        else:
            log.error(f"Argument passed was not a folder : {input_path}")


def Plugin_Start_Ios(ios_info):
    '''Entry point for ios_apt plugin'''
    pass

if __name__ == '__main__':
    print ("This plugin is a part of a framework and does not run independently on its own!")