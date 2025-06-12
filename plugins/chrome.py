'''
   Copyright (c) 2020 Yogesh Khatri

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the
   terms of the MIT License.

   chrome.py
   ---------------
   This module gets Chromium (Chrome, Edge, ..) browser artifacts
'''

import json
import logging
import os
import re
import sqlite3

from construct import *

from plugins.helpers.common import CommonFunctions
from plugins.helpers.macinfo import *
from plugins.helpers.writer import *

__Plugin_Name = "CHROMIUM"
__Plugin_Friendly_Name = "Chromium"
__Plugin_Version = "3.0"
__Plugin_Description = "Read Chromium browsers (Chrome, Edge, ..) History, Top Sites, Downloads, Tabs/Sessions and Extension info"
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
# DONE 
# -----
# Top Sites
# History + Downloads
# Extensions
# Last Session, Current Session - binary format
# Last Tabs, Current Tabs - binary format
# Secure Preferences
# Preferences

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
    "window_id" / Int32ul,
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

class Account:
    def __init__(self, name, id, email, pic_url, user, source):
        self.name = name
        self.id = id
        self.email = email
        self.picture_url = pic_url
        self.user = user
        self.source = source

class ChromiumItemType(IntEnum):
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
    PROFILE = 10

    def __str__(self):
        return self.name

class ChromiumItem:
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

class Extension:
    def __init__(self, id, name, version, description, author, install_date, last_update_date, install_location, enabled, disable_reasons, user, source):
        global ExtDisableReasonValues
        global ExtLocationValues

        self.id = id
        self.name = name
        self.version = version
        self.description = description
        self.author = author
        self.install_date = install_date
        self.install_location_raw = install_location
        self.install_location = ExtLocationValues.get(install_location, f"Unknown value: {install_location}")
        self.enabled = enabled
        self.last_update_date = last_update_date
        self.user = user
        self.source = source
        self.disable_reasons_raw = disable_reasons

        if disable_reasons:
            self.disable_reasons = GetFlagsString(disable_reasons, ExtDisableReasonValues)
        else:
            self.disable_reasons = ''

ExtDisableReasonValues = {
    0x0001: "Disabled by user",
    0x0002: "DISABLE_PERMISSIONS_INCREASE",
    0x0004: "DISABLE_RELOAD",
    0x0008: "DISABLE_UNSUPPORTED_REQUIREMENT",
    0x0010: "DISABLE_SIDELOAD_WIPEOUT",
    0x0020: "DEPRECATED_DISABLE_UNKNOWN_FROM_SYNC",
    0x0040: "DISABLE_PERMISSIONS_CONSENT",
    0x0080: "DISABLE_KNOWN_DISABLED",
    0x0100: "Disabled because we could not verify the install.",
    0x0200: "DISABLE_GREYLIST",
    0x0400: "DISABLE_CORRUPTED",
    0x0800: "DISABLE_REMOTE_INSTALL",
    0x1000: "DISABLE_INACTIVE_EPHEMERAL_APP",
    0x2000: "External extensions might be disabled for user prompting.",
    0x4000: "Doesn't meet minimum version requirement.",
    0x8000: "Supervised user needs approval by custodian.",
    0x10000: "Blocked due to management policy.",
    0x20000: "DISABLE_BLOCKED_MATURE",
    0x40000: "DISABLE_REMOTELY_FOR_MALWARE",
    0x80000: "DISABLE_REINSTALL",
    0x100000: "Disabled by Safe Browsing extension allowlist enforcement.",
    0x200000: "Deprecated, do not use in new code.",
    0x400000: "Disabled by policy when the extension is unpublished from the web store.",    
    0x800000: "Disabled because the extension uses an unsupported manifest version.",
    0x1000000: "Disabled because the extension is a \"developer extension\"(for example, an unpacked extension) while the developer mode is OFF.",
    0x2000000: "Disabled because of an unknown reason. This can happen when newer versions"\
                "of the browser sync reasons which are not known to the current version. We"\
                "never actually write this to prefs. This is used to indicate (at runtime)"\
                "that unknown reasons are present in the prefs."            
}

ExtLocationValues= {
    0: "Invalid",
    1: "Installed by the user from the Chrome Web Store or as a .crx file",
    2: "Installed via external preferences (e.g., managed by IT)",
    3: "Installed via Windows registry",
    4: "Loaded unpacked (developer mode)",
    5: "Bundled with Chrome as a component extension",
    6: "Installed by enterprise policy (downloaded)",
    7: "Installed by enterprise policy (local)",
    8: "Loaded via command line",
    9: "ExternalPolicy ",
    10: "ExternalComponent"
}

def GetFlagsString(flags, flag_values):
    '''Get string names of all flags set'''
    list_flags = []
    if flags is not None:
        if not isinstance(flags, int):
            log.error(f'flags {flags} is not an integer, it is {str(type(flags))}!')
            return ''
        for k, v in list(flag_values.items()):
            if (k & flags) != 0:
                list_flags.append(v)
    return '|'.join(list_flags)

def InsertUnique(chromium_items_list, item):
    for x in chromium_items_list:
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
    chromium_items_list.append(item)

def OpenDb(inputPath):
    log.info ("Processing file " + inputPath)
    try:
        conn = CommonFunctions.open_sqlite_db_readonly(inputPath)
        log.debug ("Opened database successfully")
        return conn
    except sqlite3.Error:
        log.exception ("Failed to open database, is it a valid DB?")
    return None

def OpenDbFromImage(mac_info, inputPath, user, browser):
    '''Returns tuple of (connection, wrapper_obj)'''
    log.info (f"Processing {browser} database for user '{user}' from file {inputPath}")
    try:
        sqlite = SqliteWrapper(mac_info)
        conn = sqlite.connect(inputPath)
        if conn:
            log.debug ("Opened database successfully")
        return conn, sqlite
    except sqlite3.Error:
        log.exception ("Failed to open database, is it a valid DB?")
    return None, None

def ReadTabsFile(chromium_artifacts, f, file_size, user, source):
    '''Reads 'Current/Last Tabs/Sessions' binary format'''
    if source.endswith('Last Tabs') or os.path.basename(source).lower().startswith('tabs_'):
        source_type = ChromiumItemType.LASTTAB
    elif source.endswith('Current Tabs'):
        source_type = ChromiumItemType.CURRENTTAB
    elif source.endswith('Last Session') or os.path.basename(source).lower().startswith('session_'):
        source_type = ChromiumItemType.LASTSESSION
    elif source.endswith('Current Session'):
        source_type = ChromiumItemType.CURRENTSESSION
    sig = f.read(4)
    ver = struct.unpack("<i", f.read(4))[0]
    if sig != b'SNSS':
        log.error(f"ERR, wrong sig for {source}, expected SNSS, got {sig.hex()}")
    else:
        pos = 0x8
        if ver not in (1, 3):
            log.warning(f'Not version 1 or 3, parser may fail! Version={ver}')

        while pos < file_size:
            f.seek(pos)
            size, command = struct.unpack('<HB', f.read(3))
            if size > 25:
                if ((ver == 1) and command in (1, 6)) or \
                    ((ver == 3) and (command == 6 and source_type == ChromiumItemType.LASTSESSION)) or \
                    ((ver == 3) and (command == 1 and source_type == ChromiumItemType.LASTTAB)):
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
                        InsertUnique(chromium_artifacts, ChromiumItem(source_type, url, title, ts, None, None, referrer, url2, user, source))
                else:
                    if command != 19:
                        log.debug(f'size ({size}) > 25, command = {command}')
            pos += size + 2

def ReadTopSitesDb(chromium_artifacts, db, file_size, user, source):
    try:
        db.row_factory = sqlite3.Row
        tables = CommonFunctions.GetTableNames(db)
        if 'topsites' in tables: # meta.version == 4
            cursor = db.cursor()
            query = "SELECT url, url_rank, title from top_sites ORDER BY url_rank ASC"
            cursor = db.execute(query)
            for row in cursor:
                item = ChromiumItem(ChromiumItemType.TOPSITE, row['url'], row['title'], None, None, None, None, f"URL_RANK={row['url_rank']}", user, source)
                chromium_artifacts.append(item)
        elif 'thumbnails' in tables: # meta.version == 3
            cursor = db.cursor()
            query = "SELECT url, url_rank, title, last_updated from thumbnails ORDER BY url_rank ASC"
            cursor = db.execute(query)
            for row in cursor:
                item = ChromiumItem(ChromiumItemType.TOPSITE, row['url'], row['title'], CommonFunctions.ReadChromeTime(row['last_updated']),
                                    None, None, None, f"URL_RANK={row['url_rank']}", user, source)
                chromium_artifacts.append(item)
    except sqlite3.Error:
        log.exception('DB read error from ReadTopSitesDb()')

def ReadHistoryDb(chromium_artifacts, db, file_size, user, source):
    try:
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

            item = ChromiumItem(ChromiumItemType.HISTORY, row['url'], row['title'], 
                            CommonFunctions.ReadChromeTime(visit_time), end_time, None, row['referrer'],
                            f"VisitCount={row['visit_count']}, Hidden={row['hidden']}", 
                            user, source)
            chromium_artifacts.append(item)

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
            item = ChromiumItem(ChromiumItemType.DOWNLOAD, row['url'], downloaded_file_name, 
                            start_time, end_time, path, row['referrer'], 
                            f"Received Bytes = {row['received_bytes']}/{row['total_bytes']}", 
                            user, source)
            chromium_artifacts.append(item)
    except sqlite3.Error:
        log.exception('DB read error from ReadHistoryDb()')

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

def ReadMessageFromMsgJson(mac_info, possible_paths, id, user, browser):
    '''Will attempt to open filepath defined in possible_paths list,
        then read and return message defined by id'''
    text = ''
    for path in possible_paths:
        if mac_info.IsValidFilePath(path):
            mac_info.ExportFile(path, os.path.join(__Plugin_Name, browser), user + "_extension_")
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

def ProcessExtensionsLocal(chromium_artifacts, user, source):
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
                    item = ChromiumItem(ChromiumItemType.EXTENSION, '', f"{name} (version {version})", None, None, None, None, desc, '', manifest_path)
                    chromium_artifacts.append(item)
                break

def ReadJson(data):
    try:
        return json.loads(data)
    except json.decoder.JSONDecodeError:
        log.error('Failed to parse json. Input Data was ' + str(data))
    return {}

def ReadSecurePreferencesFile(ext_info, f, file_size, user, file_path):
    """Reads the 'Secure Preferences' json file

    Args:
        ext_info (list): _description_
        f (file): file ptr opened as 'rb'
        file_size (int): size of file
        user (str): user
        file_path (str): source file path

    Returns:
        None: 
    """
    data = f.read().decode('utf8', 'ignore')
    try:
        data = json.loads(data)
    except json.decoder.JSONDecodeError:
        log.error('Failed to parse json. Input Data was ' + str(data))
        return
    
    extensions = data.get('extensions', {}).get('settings', {})
    for ext_id, ext in extensions.items():
        location = ext.get('location', 0)
        if location == 5: # installed as default by Chrome itself
            continue
        state = ext.get('state', None)  # 1=enabled , 0=disabled
        enabled = True
        if state is not None:
            enabled = True if state == 1 else False

        disable_reasons = ext.get('disable_reasons', [])
        if len(disable_reasons) == 0 or disable_reasons[0] == 0:
            enabled = True
            disable_reasons = 0
        else:
            enabled = False
            disable_reasons = disable_reasons[0]
        
        first_install_time = CommonFunctions.ReadChromeTime(ext.get('first_install_time', None))
        last_update_time = CommonFunctions.ReadChromeTime(ext.get('last_update_time', None))
        manifest = ext.get('manifest', None)
        if manifest:
            name = manifest.get('name', '')
            version = manifest.get('version', '')
            description = manifest.get('description', '')
            author = str(manifest.get('author', ''))
            e = Extension(ext_id, name, version, description, author, first_install_time, last_update_time, location, enabled, disable_reasons, user, file_path)
            ext_info.append(e)
        elif len(ext) < 3:
            pass
        else:
            log.error(f'Could not find manifest for extension {ext_id}')

def ProcessExtensions(mac_info, chromium_artifacts, user, source, browser):
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
                mac_info.ExportFile(manifest_path, os.path.join(__Plugin_Name, browser, "Extensions"), user + '_extension_', False)
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
                                name = ReadMessageFromMsgJson(mac_info, msg_json_possible_paths, name[6:-2], user, browser)
                            if desc.startswith('__MSG_'):
                                desc = ReadMessageFromMsgJson(mac_info, msg_json_possible_paths, desc[6:-2], user, browser)
                            if version.startswith('__MSG_'):
                                version = ReadMessageFromMsgJson(mac_info, msg_json_possible_paths, version[6:-2], user, browser)
                    log.debug(f"EXT NAME={name}, Ver={version}, DESC={desc}")
                    item = ChromiumItem(ChromiumItemType.EXTENSION, '', f"{name} (version {version})", None, None, None, None, desc, user, manifest_path)
                    chromium_artifacts.append(item)
                else:
                    log.error(f"Failed to open {manifest_path}")
                break
      
def ReadProfileInfo(artifacts, f, file_size, user, file_path):
    """Reads the profile information from 'Preferences' json file

    Args:
        ext_info (list): _description_
        f (file): file ptr opened as 'rb'
        file_size (int): size of file
        user (str): user
        file_path (str): source file path

    Returns:
        None: 
    """
    data = f.read().decode('utf8', 'ignore')
    try:
        data = json.loads(data)
    except json.decoder.JSONDecodeError:
        log.error('Failed to parse json. Input Data was ' + str(data))
        return
    
    profile = data.get('profile', {})
    if profile:
        creation_time = CommonFunctions.ReadChromeTime(profile.get('creation_time', None))
        last_engagement_time = CommonFunctions.ReadChromeTime(profile.get('last_engagement_time', None))
        name = profile.get('name', '')
        #log.debug(f"Profile: {name}, Creation: {creation_time}, Last Engagement Time: {last_engagement_time}")
        artifacts.append(ChromiumItem(ChromiumItemType.PROFILE, '', name, creation_time, last_engagement_time, '', '', 'Date is creation_time, End Date is last_engagement_time', user, file_path))

def ReadPreferencesFile(accounts, f, file_size, user, file_path):
    """Reads the 'Preferences' json file

    Args:
        ext_info (list): _description_
        f (file): file ptr opened as 'rb'
        file_size (int): size of file
        user (str): user
        file_path (str): source file path

    Returns:
        None: 
    """
    data = f.read().decode('utf8', 'ignore')
    try:
        data = json.loads(data)
    except json.decoder.JSONDecodeError:
        log.error('Failed to parse json. Input Data was ' + str(data))
        return
    
    # profile = data.get('profile', {})
    # if profile:
    #     creation_time = CommonFunctions.ReadChromeTime(profile.get('creation_time', None))
    #     last_engagement_time = CommonFunctions.ReadChromeTime(profile.get('last_engagement_time', None))
    #     name = profile.get('name', '')
    #     log.info(f"Profile: {name}, Creation: {creation_time}, Last Engagement Time: {last_engagement_time}")
    
    account_info = data.get('account_info', [])
    for a in account_info:
        account_gaia_id = a.get('account_id', '')
        account_email = a.get('email', '')
        account_name = a.get('full_name', '')
        account_pic_url = a.get('picture_url', '')
        p = Account(account_name, account_gaia_id, account_email, account_pic_url, user, file_path)
        accounts.append(p)

    account_data = data.get('gaia_cookie', {}).get('last_list_accounts_data',[])
    if account_data:
        try:
            account_data = json.loads(account_data)
        except json.decoder.JSONDecodeError:
            log.error('Failed to parse json. Input Data was ' + str(account_data))
        try:
            for item in account_data[1]:
                if item[0] == 'gaia.l.a':
                    account_name = item[2]
                    account_email = item[3]
                    account_pic_url = item[4]
                    account_gaia_id = item[10]
                    p = Account(account_name, account_gaia_id, account_email, account_pic_url, user, file_path)
                    found = False
                    for account in accounts:
                        if account.email == account_email and account.user == user:
                            found = True
                            break
                    if not found:
                        accounts.append(p)
        except KeyError:
            pass

def PrintAllAccountInfo(browser, accounts, output_params, source_path):
    ext_info = [ ('Name',DataType.TEXT),('Email',DataType.TEXT),('ID',DataType.TEXT),
                    ('Picture URL',DataType.TEXT),
                    ('User', DataType.TEXT),('Source',DataType.TEXT) 
                  ]

    data_list = []
    log.info (f"{len(accounts)} {browser} account(s) found")
    for item in accounts:
        data_list.append( [ item.name, item.email, item.id, item.picture_url,
                            item.user, item.source ] )

    WriteList(f"{browser}_Accounts", f"{browser}_Accounts", data_list, ext_info, output_params, source_path)

def PrintAllExtensionInfo(browser, ext_artifacts, output_params, source_path):
    ext_info = [ ('ID',DataType.TEXT),('Name',DataType.TEXT),('Version',DataType.TEXT),
                ('Description',DataType.TEXT),('Author',DataType.TEXT),
                    ('Install Date', DataType.DATE),('Last Update Date', DataType.DATE),
                    ('Install Location', DataType.TEXT),('Install_Location_raw', DataType.INTEGER),
                    ('Enabled', DataType.TEXT),
                    ('Disable Reasons', DataType.TEXT),('Disable_Reasons_raw', DataType.INTEGER),
                    ('User', DataType.TEXT),('Source',DataType.TEXT) 
                  ]

    data_list = []
    log.info (f"{len(ext_artifacts)} {browser} extension(s) found")
    for item in ext_artifacts:
        data_list.append( [ item.id, item.name, item.version, item.description, item.author,
                            item.install_date, item.last_update_date,
                            item.install_location, item.install_location_raw,
                            item.enabled, item.disable_reasons, item.disable_reasons_raw,
                            item.user, item.source ] )

    WriteList(f"{browser}_Extensions", f"{browser}_Extensions", data_list, ext_info, output_params, source_path)

def PrintAll(browser, chromium_artifacts, output_params, source_path):
    chromium_info = [ ('Type',DataType.TEXT),('Name_or_Title',DataType.TEXT),('URL',DataType.TEXT),
                    ('Date', DataType.DATE),('End Date', DataType.DATE),
                    ('Local Path', DataType.TEXT),('Referrer or Previous Page', DataType.TEXT),
                    ('Other_Info', DataType.TEXT),('User', DataType.TEXT),
                    ('Source',DataType.TEXT) 
                  ]

    data_list = []
    log.info (f"{len(chromium_artifacts)} {browser} item(s) found")
    for item in chromium_artifacts:
        url = item.url
        data_list.append( [ str(item.type), item.name, url,
                            item.date, item.end_date,
                            item.local_path, item.referrer,
                            item.other_info, item.user, item.source ] )

    WriteList(f"{browser}", f"{browser}", data_list, chromium_info, output_params, source_path)

def ExtractAndReadDb(mac_info, chromium_artifacts, user, file_path, file_size, parser_function, browser):
    mac_info.ExportFile(file_path, os.path.join(__Plugin_Name, browser), user + '_')
    db, wrapper = OpenDbFromImage(mac_info, file_path, user, browser)
    if db:
        parser_function(chromium_artifacts, db, file_size, user, file_path)
        db.close()

def ExtractAndReadFile(mac_info, chromium_artifacts, user, file_path, file_size, parser_function, browser):
    mac_info.ExportFile(file_path, os.path.join(__Plugin_Name, browser), user + '_', overwrite=True)
    log.info (f"Processing {browser} file {file_path} for user {user}")
    f = mac_info.Open(file_path)
    if f:
        parser_function(chromium_artifacts, f, file_size, user, file_path)
        f.close()

def OpenLocalDbAndRead(chromium_artifacts, user, file_path, file_size, parser_function):
    conn = OpenDb(file_path)
    if conn:
        parser_function(chromium_artifacts, conn, file_size, '', file_path)
        conn.close()

def OpenLocalFileAndRead(chromium_artifacts, user, file_path, file_size, parser_function):
    f = open(file_path, 'rb')
    log.info ("Processing Chromium file {}".format(file_path))
    parser_function(chromium_artifacts, f, file_size, '', file_path)
    f.close()

def Plugin_Start(mac_info):
    '''Main Entry point function for plugin'''
    chromium_browsers = {'Chrome': '{}/Library/Application Support/Google/Chrome/',
                         'Edge': '{}/Library/Application Support/Microsoft Edge/',
                         'Opera': '{}/Library/Application Support/com.operasoftware.Opera/',  # Does not support multiple profiles
                         'Vivaldi': '{}/Library/Application Support/Vivaldi/',
                         'Brave': '{}/Library/Application Support/BraveSoftware/Brave-Browser/',
                         'Arc': '{}/Library/Application Support/Arc/User Data/'}

    profile_regex = r'(Default|Profile \d+|Guest Profile)'

    for browser, chromium_profile_base_path in chromium_browsers.items():
        processed_paths = []
        chromium_artifacts = []
        chromium_extension_artifacts = []
        chromium_accounts = []
        for user in mac_info.users:
            user_name = user.user_name
            if user.home_dir == '/private/var/empty': continue # Optimization, nothing should be here!
            elif user.home_dir == '/private/var/root': user_name = 'root' # Some other users use the same root folder, we will list all such users as 'root', as there is no way to tell
            if user.home_dir in processed_paths: continue # Avoid processing same folder twice (some users have same folder! (Eg: root & daemon))
            processed_paths.append(user.home_dir)
            chromium_path = chromium_profile_base_path.format(user.home_dir)
            if not mac_info.IsValidFolderPath(chromium_path):
                continue

            folders_list = mac_info.ListItemsInFolder(chromium_path, EntryType.FOLDERS, include_dates=False)
            profile_names = [folder_item['name'] for folder_item in folders_list if re.match(profile_regex, folder_item['name'])]
            if not profile_names:
                profile_names = ['']

            for profile_name in profile_names:
                if profile_name:
                    user_profile_name = user_name + '_' + profile_name.replace(' ', '_')
                    source_path = os.path.join(chromium_profile_base_path.format(user.home_dir), profile_name)
                else:
                    user_profile_name = user_name + '_' + 'NOPROFILE'
                    source_path = chromium_profile_base_path.format(user.home_dir)

                if mac_info.IsValidFolderPath(source_path):
                    files_list = mac_info.ListItemsInFolder(source_path, EntryType.FILES_AND_FOLDERS, include_dates=False)
                    for file_entry in files_list:
                        if file_entry['type'] == EntryType.FILES:
                            if file_entry['size'] == 0:
                                continue
                            if file_entry['name'] == 'Top Sites':
                                ExtractAndReadDb(mac_info, chromium_artifacts, user_profile_name, source_path + '/Top Sites', file_entry['size'], ReadTopSitesDb, browser)
                            elif file_entry['name'] == 'History':
                                ExtractAndReadDb(mac_info, chromium_artifacts, user_profile_name, source_path + '/History', file_entry['size'], ReadHistoryDb, browser)
                            elif file_entry['name'] == 'Last Tabs':
                                ExtractAndReadFile(mac_info, chromium_artifacts, user_profile_name, source_path + '/Last Tabs', file_entry['size'], ReadTabsFile, browser)
                            elif file_entry['name'] == 'Current Tabs':
                                ExtractAndReadFile(mac_info, chromium_artifacts, user_profile_name, source_path + '/Current Tabs', file_entry['size'], ReadTabsFile, browser)
                            elif file_entry['name'] == 'Last Session':
                                ExtractAndReadFile(mac_info, chromium_artifacts, user_profile_name, source_path + '/Last Session', file_entry['size'], ReadTabsFile, browser)
                            elif file_entry['name'] == 'Current Session':
                                ExtractAndReadFile(mac_info, chromium_artifacts, user_profile_name, source_path + '/Current Session', file_entry['size'], ReadTabsFile, browser)
                            elif file_entry['name'] == 'Preferences':
                                ExtractAndReadFile(mac_info, chromium_accounts, user_profile_name, source_path + '/Preferences', file_entry['size'], ReadPreferencesFile, browser)
                                ExtractAndReadFile(mac_info, chromium_artifacts, user_profile_name, source_path + '/Preferences', file_entry['size'], ReadProfileInfo, browser)
                            elif file_entry['name'] == 'Secure Preferences':
                                ExtractAndReadFile(mac_info, chromium_extension_artifacts, user_profile_name, source_path + '/Secure Preferences', file_entry['size'], ReadSecurePreferencesFile, browser)
                        else: # Folder
                            if file_entry['name'] == 'Extensions':
                                ProcessExtensions(mac_info, chromium_artifacts, user_profile_name, source_path + '/Extensions', browser)
                            elif file_entry['name'] == 'Sessions':
                                sessions_path = os.path.join(source_path, "Sessions")
                                sessions_files_list = mac_info.ListItemsInFolder(sessions_path, EntryType.FILES, include_dates=False)
                                for file_entry in sessions_files_list:
                                    if file_entry['size'] == 0: 
                                        continue
                                    filename = file_entry['name'].lower()
                                    if filename.startswith('tabs_') or filename.startswith('session_'):
                                        ExtractAndReadFile(mac_info, chromium_artifacts, user_profile_name, sessions_path + f"/{file_entry['name']}", file_entry['size'], ReadTabsFile, browser)

        if len(chromium_artifacts) > 0:
            PrintAll(browser, chromium_artifacts, mac_info.output_params, chromium_profile_base_path)
        else:
            log.info(f'No {browser} artifacts were found!')
        if len(chromium_extension_artifacts) > 0:
            PrintAllExtensionInfo(browser, chromium_extension_artifacts, mac_info.output_params, chromium_profile_base_path)
        else:
            log.debug(f'No {browser} extensions were found!')
        if len(chromium_accounts) > 0:
            PrintAllAccountInfo(browser, chromium_accounts, mac_info.output_params, chromium_profile_base_path)
        else:
            log.debug(f'No {browser} accounts were found!')

def Plugin_Start_Standalone(input_files_list, output_params):
    '''Main entry point function when used on single artifacts (mac_apt_singleplugin), not on a full disk image'''
    log.info("Module Started as standalone")
    for input_path in input_files_list:
        log.debug("Input file passed was: " + input_path)
        chromium_artifacts = []
        chromium_extension_artifacts = []
        chromium_accounts = []
        if os.path.isdir(input_path):
            file_names = os.listdir(input_path)
            for file_name in file_names:
                file_path = os.path.join(input_path, file_name)
                file_size = os.path.getsize(file_path)
                if file_name == 'Top Sites':
                    OpenLocalDbAndRead(chromium_artifacts, '', file_path, file_size, ReadTopSitesDb)
                elif file_name == 'History':
                    OpenLocalDbAndRead(chromium_artifacts, '', file_path, file_size, ReadHistoryDb)
                elif file_name in ('Last Tabs', 'Current Tabs') or file_name.lower().startswith('tabs_'):
                    OpenLocalFileAndRead(chromium_artifacts, '', file_path, file_size, ReadTabsFile)
                elif file_name in ('Last Session', 'Current Session') or file_name.lower().startswith('session_'):
                    OpenLocalFileAndRead(chromium_artifacts, '', file_path, file_size, ReadTabsFile)
                elif file_name == 'Extensions' and os.path.isdir(file_path):
                    ProcessExtensionsLocal(chromium_artifacts, '', file_path)
                elif file_name == 'Preferences':
                    OpenLocalFileAndRead(chromium_accounts, '', file_path, file_size, ReadPreferencesFile)
                    OpenLocalFileAndRead(chromium_artifacts, '', file_path, file_size, ReadProfileInfo)
                elif file_name == 'Secure Preferences':
                    OpenLocalFileAndRead(chromium_extension_artifacts, '', file_path, file_size, ReadSecurePreferencesFile)
            if len(chromium_artifacts) > 0:
                PrintAll('Browser', chromium_artifacts, output_params, input_path)
            else:
                log.info('No chrome/chromium artifacts found in {}'.format(input_path))
            if len(chromium_extension_artifacts) > 0:
                PrintAllExtensionInfo('Browser', chromium_extension_artifacts, output_params, input_path)
            else:
                log.debug('No chrome/chromium extensions found in {}'.format(input_path))
            if len(chromium_accounts) > 0:
                PrintAllAccountInfo('Browser', chromium_accounts, output_params, input_path)
            else:
                log.debug('No chrome/chromium accounts found in {}'.format(input_path))
        else:
            log.error(f"Argument passed was not a folder : {input_path}")


def Plugin_Start_Ios(ios_info):
    '''Entry point for ios_apt plugin'''
    pass

if __name__ == '__main__':
    print ("This plugin is a part of a framework and does not run independently on its own!")