'''
   Copyright (c) 2017 Yogesh Khatri 

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the 
   terms of the MIT License.
   
'''
from __future__ import annotations

import io
import logging
import os
import sqlite3
from enum import IntEnum

import nska_deserialize as nd

# import plugins.helpers.ccl_bplist as ccl_bplist
# from plugins.helpers import macinfo
from plugins.helpers.common import CommonFunctions
from plugins.helpers.macinfo import *
from plugins.helpers.writer import *

__Plugin_Name = "SAFARI"
__Plugin_Friendly_Name = "Internet history, downloaded file information, cookies and more from Safari caches"
__Plugin_Version = "2.1"
__Plugin_Description = "Gets internet history, downloaded file information, cookies and more from Safari caches"
__Plugin_Author = "Yogesh Khatri"
__Plugin_Author_Email = "yogesh@swiftforensics.com"

__Plugin_Modes = "IOS,MACOS,ARTIFACTONLY"
__Plugin_ArtifactOnly_Usage = ''

log = logging.getLogger('MAIN.' + __Plugin_Name) # Do not rename or remove this ! This is the logger object

#---- Do not change the variable names in above section ----#

''' Mavericks had History.plist, Yosemite has History.db
<Home_DIR>/Library/Preferences/com.apple.safari.plist
  RecentSearchStrings[], SuccessfulLaunchTimestamp, DownloadsPath, HomePage, FrequentlyVisitedSitesCache
<Home_DIR>/Library/Safari/ --> Bookmarks.plist, Downloads.plist, History.plist, Form Values (Encrypted!), 
  UserNotificationPermissions.plist, RecentlyClosedTabs.plist
  LastSession.plist <-- SessionVersion, SessionWindows\[xx]\TabStates\[xx]\[TabTitle & TabURL]
  TopSites.plist <-- [BannedURLStrings] , DisplayedSitesLastModified, TopSites\[xx][TopSiteTitle & TopSiteURLString]
  Extensions\Extensions.plist <-- Installed Extensions\[xx][Archive File Name & Enabled]
  ReadingListArchives/<UUID>/Page.webarchive <-- Plist, get WebResourceURL
  BrowserState.db
  CloudTabs.db
'''

class SafariItemType(IntEnum):
    UNKNOWN = 0
    HISTORY = 1
    TOPSITE = 2
    BOOKMARK = 3
    DOWNLOAD = 4
    LASTSESSION = 5
    RECENTCLOSEDTAB = 6
    EXTENSION = 7
    GENERAL = 8 # From com.apple.safari.plist
    HISTORYDOMAINS = 9
    TOPSITE_BANNED = 10
    FREQUENTLY_VISITED = 11 # From com.apple.safari.plist
    CLOUDTAB = 12
    TAB = 13 # From BrowserState
    TABHISTORY = 14 # Tab session history from BrowserState
    TAB_SNAPSHOT = 15

    def __str__(self):
        return self.name

class SafariItem:
    def __init__(self, type, url, name, date, other, user, source):
        self.type = type
        self.url = url
        self.name = name
        self.date = date
        self.other_info = other
        self.user = user
        self.source = source


class SafariProfile:
    def __init__(self, profile_uuid: str, profile_name: str, extension_uuid: str) -> None:
        self.profile_uuid = profile_uuid  # named 'external_uuid' in SafariTabs.db
        self.profile_name = profile_name  # named 'title' in SafariTabs.db
        self.extension_uuid = extension_uuid  # named 'server_id' in SafariTabs.db


def PrintAll(safari_items, output_params, source_path):
    safari_info = [ ('Type',DataType.TEXT),('Name_or_Title',DataType.TEXT),('URL',DataType.TEXT),
                    ('Date', DataType.DATE),('Other_Info', DataType.TEXT),('User', DataType.TEXT),
                    ('Source',DataType.TEXT)
                  ]

    data_list = []
    for item in safari_items:
        url = item.url
        if url.startswith('file://'):
            url = url[7:]
        data_list.append( [ str(item.type), item.name, url, item.date, item.other_info, item.user, item.source ] )

    WriteList("safari information", "Safari", data_list, safari_info, output_params, source_path)

def ReadSafariPlist(plist, safari_items, source, user):
    '''Read com.apple.safari.plist'''
    try:
        searches = plist['RecentSearchStrings'] # Mavericks
        try:
            for search in searches:
                si = SafariItem(SafariItemType.GENERAL, '', search, None, 'RECENT_SEARCH', user, source)
                safari_items.append(si)
        except ValueError as ex:
            log.exception('Error reading RecentSearchStrings from plist')
    except  KeyError: # Not found
        pass
    try:
        searches = plist['RecentWebSearches'] # Yosemite
        try:
            for search in searches:
                si = SafariItem(SafariItemType.GENERAL, '', search.get('SearchString',''), 
                                search.get('Date', None), 'RECENT_SEARCH', user, source)
                safari_items.append(si)
        except ValueError as ex:
            log.exception('Error reading RecentWebSearches from plist')
    except KeyError: # Not found
        pass
    try:
        freq_sites = plist['FrequentlyVisitedSitesCache'] # seen in  El Capitan
        try:
            for site in freq_sites:
                si = SafariItem(SafariItemType.FREQUENTLY_VISITED, site.get('URL', ''), site.get('Title',''), 
                                None, 'FrequentlyVisitedSitesCache', user, source)
                safari_items.append(si)
        except ValueError as ex:
            log.exception('Error reading FrequentlyVisitedSitesCache from plist')
    except KeyError: # Not found
        pass
    try:
        download_path = plist['DownloadsPath']
        si = SafariItem(SafariItemType.GENERAL, '', download_path, None, 'DOWNLOADS_PATH', user, source)
        safari_items.append(si) 
    except KeyError: # Not found
        pass
    try:
        home = plist['HomePage']
        si = SafariItem(SafariItemType.GENERAL, home, '', None, 'HOME_PAGE', user, source)
        safari_items.append(si) 
    except KeyError: # Not found
        pass
    try:
        last_ext_pref_selected = plist['LastExtensionSelectedInPreferences']
        si = SafariItem(SafariItemType.EXTENSION, '', last_ext_pref_selected, None, 'LastExtensionSelectedInPreferences', user, source)
        safari_items.append(si) 
    except KeyError: # Not found
        pass
    try:
        last_root_dir = plist['NSNavLastRootDirectory']
        si = SafariItem(SafariItemType.GENERAL, last_root_dir, '', None, 'NSNavLastRootDirectory', user, source)
        safari_items.append(si) 
    except KeyError: # Not found
        pass
    try:
        time = CommonFunctions.ReadMacAbsoluteTime(plist['SuccessfulLaunchTimestamp'])
        si = SafariItem(SafariItemType.GENERAL, '', '', time, 'SuccessfulLaunchTimestamp', user, source)
        safari_items.append(si)
    except KeyError: # Not found
        pass

def ProcessSafariPlist(mac_info, source_path, user, safari_items, read_plist_function, safari_profile=SafariProfile('', '', '')):
    mac_info.ExportFile(source_path, __Plugin_Name, user + "_", False)
    success, plist, error = mac_info.ReadPlist(source_path)
    if success:
        if read_plist_function in (ReadExtensionsPlist, ):
            read_plist_function(plist, safari_items, source_path, user, safari_profile)
        else:
            read_plist_function(plist, safari_items, source_path, user)
    else:
        log.info('Failed to open plist: {}'.format(source_path))
    pass

def ReadHistoryDb(conn, safari_items, source_path, user, safari_profile=SafariProfile('', '', '')):
    try:
        conn.row_factory = sqlite3.Row
        cursor = conn.execute("select title, url, load_successful, visit_time as time_utc from "
                              "history_visits left join history_items on history_visits.history_item = history_items.id")
        try:
            for row in cursor:
                try:
                    info = f"Profile: {safari_profile.profile_name}" if safari_profile.profile_uuid else ''
                    si = SafariItem(SafariItemType.HISTORY, row['url'], row['title'],
                                    CommonFunctions.ReadMacAbsoluteTime(row['time_utc']), info, user, source_path)
                    safari_items.append(si)
                except sqlite3.Error as ex:
                    log.exception ("Error while fetching row data")
        except sqlite3.Error as ex:
            log.exception ("Db cursor error while reading file " + source_path)
        conn.close()
    except sqlite3.Error as ex:
        log.exception ("Sqlite error")

def GetItemFromCloudDbPlist(plist, item_name):
    for dic_item in plist:
        for k, v in dic_item.items():
            if k == item_name:
                return v
    return None

def ReadCloudTabsDb(conn, safari_items, source_path, user):
    try:
        conn.row_factory = sqlite3.Row
        cursor = conn.execute(
            """SELECT device_name, tab_uuid, t.system_fields, title, url, is_showing_reader, is_pinned
                FROM cloud_tabs t LEFT JOIN cloud_tab_devices d on d.device_uuid=t.device_uuid
                ORDER BY device_name""")
        try:
            for row in cursor:
                try:
                    pinned = row['is_pinned']
                    system_fields = row['system_fields']
                    created = ''
                    modified = ''
                    if system_fields:
                        serialized_plist_file_obj = io.BytesIO(system_fields)
                        try:
                            deserialized_plist = nd.deserialize_plist(serialized_plist_file_obj)
                            created = GetItemFromCloudDbPlist(deserialized_plist, 'RecordCtime')
                            modified = GetItemFromCloudDbPlist(deserialized_plist, 'RecordMtime')
                        except (nd.DeserializeError, nd.biplist.NotBinaryPlistException, 
                                nd.biplist.InvalidPlistException, plistlib.InvalidFileException,
                                nd.ccl_bplist.BplistError, ValueError, TypeError, OSError, OverflowError) as ex:
                            log.exception('plist deserialization error')

                    si = SafariItem(SafariItemType.CLOUDTAB, row['url'], row['title'], created,
                                    f'Modified={modified}' + (' pinned=1' if pinned else ''),
                                    user, source_path)
                    safari_items.append(si)
                except sqlite3.Error as ex:
                    log.exception ("Error while fetching row data")
        except sqlite3.Error as ex:
            log.exception ("Db cursor error while reading file " + source_path)
        conn.close()
    except sqlite3.Error as ex:
        log.exception ("Sqlite error")


def GetSafariProfiles(mac_info: MacInfo, folder_path: str) -> dict[str, SafariProfile]:
    safaritabs_db_path = folder_path + '/SafariTabs.db'
    if mac_info.IsValidFilePath(safaritabs_db_path) and mac_info.GetFileSize(safaritabs_db_path) > 0 and \
       mac_info.IsValidFolderPath(folder_path + '/Profiles'):
        try:
            log.debug(f"Looking for Safari profiles in {folder_path}/Profiles: {mac_info.IsValidFolderPath(folder_path + '/Profiles')}")

            safari_profiles: dict[str, SafariProfile] = {}
            folders_list = mac_info.ListItemsInFolder(folder_path + '/Profiles', EntryType.FOLDERS, include_dates=False)
            uuids = [item['name'] for item in folders_list]

            for uuid in uuids:
                log.debug(f"Finding History.db in {folder_path}/Profiles/{uuid}")
                if mac_info.IsValidFilePath(folder_path + f'/Profiles/{uuid}/History.db'):
                    if uuid not in safari_profiles.keys():
                        log.debug(f"Found Safari profile uuid candidate: {uuid}")
                        safari_profiles[uuid] = SafariProfile(uuid, '', '')

            sqlite = SqliteWrapper(mac_info)
            conn = sqlite.connect(safaritabs_db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(
                """SELECT title, external_uuid, server_id
                    FROM bookmarks
                    WHERE parent == 0 AND type == 1 AND subtype == 2""")

            for row in cursor:
                for profile_uuid in safari_profiles.keys():
                    if row['external_uuid'] == profile_uuid:
                        safari_profiles[profile_uuid].profile_name = row['title']
                        safari_profiles[profile_uuid].extension_uuid = row['server_id']
                        log.info(f"Safari profile: {safari_profiles[profile_uuid].profile_name} "
                                 f"(Profile UUID={profile_uuid} / Extension UUID={safari_profiles[profile_uuid].extension_uuid})")
                        break

            conn.close()

            for profile_uuid in safari_profiles:
                if safari_profiles[profile_uuid].profile_name == '':
                    log.warning(f"Profile UUID {profile_uuid} has no name")

            return dict(**{'': SafariProfile('', '', '')}, **safari_profiles)

        except sqlite3.Error:
            log.exception("Sqlite error in SafariTabs.db")

    return {'': SafariProfile('', '', '')}


def FindSafariProfileByBookmarksId(conn: sqlite3.Connection, bookmarks_id: int) -> str:
    try:
        conn.row_factory = sqlite3.Row
        log.debug(f"Fetching bookmarks record: id = {bookmarks_id}")
        cursor = conn.execute(f"SELECT id, special_id, parent, type, subtype, title, url FROM bookmarks WHERE id = {bookmarks_id}")
        for row in cursor:
            if row['parent'] is None:
                return ''
            elif row['parent'] == 0 and row['type'] == 1 and row['subtype'] == 2 and row['url'] == '':
                return row['title']
            else:
                profile_name = FindSafariProfileByBookmarksId(conn, row['parent'])
                return profile_name
    except sqlite3.Error:
        log.exception("Sqlite error in SafariTabs.db while fetching profile name")
    return ''


def ReadSafariTabsDb(conn, safari_items, source_path, user):
    try:
        conn.row_factory = sqlite3.Row
        cursor = conn.execute(
            """SELECT id, special_id, parent, type, subtype, title, url, local_attributes, date_closed
                FROM bookmarks WHERE url not like '' """)
        try:
            for row in cursor:
                try:
                    local_attributes = row['local_attributes']
                    last_visit_ended = ''
                    last_visit_start = ''
                    if local_attributes:
                        plist_file_obj = io.BytesIO(local_attributes)
                        success, plist, error = CommonFunctions.ReadPlist(plist_file_obj)
                        if success:
                            last_visit_start = plist.get('LastVisitTime', '')
                            last_visit_ended = plist.get('DateClosed', '')
                        else:
                            log.error(error)
                    profile_name = FindSafariProfileByBookmarksId(conn, row['parent'])
                    info = f'Visit_end={last_visit_ended}' + f', Profile: {profile_name}' if profile_name else f'Visit_end={last_visit_ended}'
                    si = SafariItem(SafariItemType.TAB, row['url'], row['title'], last_visit_start,
                                    info, user, source_path)
                    safari_items.append(si)
                except sqlite3.Error as ex:
                    log.exception ("Error while fetching row data")
        except sqlite3.Error as ex:
            log.exception ("Db cursor error while reading file " + source_path)
        conn.close()
    except sqlite3.Error as ex:
        log.exception ("Sqlite error")

def ReadBrowserStateDb(conn, safari_items, source_path, user):
    try:
        conn.row_factory = sqlite3.Row
        cursor = conn.execute(
            """SELECT t.id, url, title, session_data, t.uuid
                FROM tabs t LEFT JOIN tab_sessions s on s.tab_uuid=t.uuid""")
        try:
            for row in cursor:
                try:
                    si = SafariItem(SafariItemType.TAB, row['url'], row['title'], '',
                                    f'Tab UUID={row["uuid"]}', user, source_path)
                    safari_items.append(si)
                    plist_data = row['session_data']
                    if plist_data and len(plist_data) > 10:
                        f = io.BytesIO(plist_data[4:])
                        success, plist, error = CommonFunctions.ReadPlist(f)
                        if success:
                            history = plist.get('SessionHistory', None)
                            if history:
                                #current_session = history.get('SessionHistoryCurrentIndex', 0)
                                entries = history.get('SessionHistoryEntries', [])
                                for index, entry in enumerate(entries):
                                    url = entry.get('SessionHistoryEntryURL', '')
                                    title = entry.get('SessionHistoryEntryTitle', '')
                                    if url == row['url']:
                                        continue # same as current tab, skip it
                                    si = SafariItem(SafariItemType.TABHISTORY, url, title, '',
                                                    f'Tab UUID={row["uuid"]} index={index}', user, source_path)
                                    safari_items.append(si)
                        else:
                            log.error(f'Failed to read plist for tab {row["uuid"]}, {row["id"]}. {error}')

                except sqlite3.Error as ex:
                    log.exception ("Error while fetching row data")
        except sqlite3.Error as ex:
            log.exception ("Db cursor error while reading file " + source_path)
        conn.close()
    except sqlite3.Error as ex:
        log.exception ("Sqlite error")


def ReadSafariTabSnapshotsDb(conn: sqlite3.Connection, safari_items: list[SafariItem], source_path: str, user: str) -> None:
    try:
        conn.row_factory = sqlite3.Row
        cursor = conn.execute('SELECT date_created, filename, url FROM snapshot_metadata')
        for row in cursor:
            date = CommonFunctions.ReadMacAbsoluteTime(row['date_created']).strftime("%Y-%m-%d %H:%M:%S.%f")
            si = SafariItem(SafariItemType.TAB_SNAPSHOT, row['url'], row['filename'], date, '', user, source_path)
            safari_items.append(si)
    except sqlite3.Error:
        log.exception(f"Sqlite error in {source_path}")


def ProcessTabSnapshotsFolder(mac_info: MacInfo, folder_path: str, user: str, safari_items: list[SafariItem]) -> None:
    if mac_info.IsValidFilePath(folder_path + '/Metadata.db'):
        log.debug(f"Exporting Safari TabSnapshots from {folder_path}")
        files_list = mac_info.ListItemsInFolder(folder_path, EntryType.FILES, include_dates=False)
        png_files = [file_item['name'] for file_item in files_list if file_item['name'].endswith('.png')]

        log.info(f"Found {len(png_files)} TabSnapshots in {folder_path}")
        for png_file in png_files:
            log.debug(f"Exporting TabSnapshots: {png_file}")
            mac_info.ExportFile(folder_path + '/' + png_file, __Plugin_Name + '/TabSnapshots', user + '_', False)

        ReadDbFromImage(mac_info, folder_path + '/Metadata.db', user, safari_items, ReadSafariTabSnapshotsDb, 'Safari TabSnapshots')


def ReadExtensionsPlist(plist, safari_items, source_path, user, safari_profile=SafariProfile('', '', '')):
    try:
        extensions = plist['Installed Extensions']
        for item in extensions:
            info = item.get('Enabled', '')
            if info != '':
                info = 'Enabled: ' + str(info)
            apple_signed = item.get('Apple-signed', '')
            if apple_signed != '':
                info = ', '.join([info, 'Apple-signed: ' + str(apple_signed)])
            si = SafariItem(SafariItemType.EXTENSION, '', item.get('Archive File Name', ''),
                            None, info, user, source_path)
            safari_items.append(si)
        return
    except KeyError:
        pass

    '''Safari 14 extension plist parser'''
    try:
        for ext_name, ext in plist.items():
            info = ''
            enabled = ext.get('Enabled', '')
            if enabled != '':
                info += 'Enabled:' + str(enabled)
            for key, val in ext.get('WebsiteAccess', {}).items():
                info += f', {key}:{val}'
            if safari_profile.profile_uuid:
                info = f'Profile: {safari_profile.profile_name}, {info}'
            si = SafariItem(SafariItemType.EXTENSION, '', ext_name,
                            None, info, user, source_path)
            safari_items.append(si)
    except (KeyError, ValueError, TypeError) as ex:
        log.error("Error reading extensions plist: " + source_path)

def ReadHistoryPlist(plist, safari_items, source_path, user):
    try:
        version = plist['WebHistoryFileVersion']
        if version != 1:
            log.warning('WebHistoryFileVersion is {}, this may not parse properly!'.format(version))
    except KeyError:
        log.error('WebHistoryFileVersion not found')
    try:
        history_dates = plist['WebHistoryDates']
        for item in history_dates:
            try:
                redirect_urls = ",".join(item.get('redirectURLs', ''))
                si = SafariItem(SafariItemType.HISTORY, item.get('',''), item.get('title', ''), \
                                CommonFunctions.ReadMacAbsoluteTime(item.get('lastVisitedDate', '')), \
                                '' if (redirect_urls == '') else ('REDIRECT_URLS:' + redirect_urls) , user, source_path) # Skipped visitCount
                safari_items.append(si)
            except ValueError as ex:
                log.error(str(ex))
    except KeyError:
        log.error('WebHistoryDates not found')
    try:
        history_domains = plist['WebHistoryDomains.v2']
        for item in history_domains:
            si = SafariItem(SafariItemType.HISTORYDOMAINS, '', item.get('', ''), None, 
                            'ITEMCOUNT:' + str(item.get('itemCount', 0)) , user, source_path)
            safari_items.append(si)
    except KeyError:
        log.error('WebHistoryDomains.v2 not found')

def ReadDownloadsPlist(plist, safari_items, source_path, user):
    try:
        downloads = plist['DownloadHistory']
        for item in downloads:
            si = SafariItem(SafariItemType.DOWNLOAD, item.get('DownloadEntryURL', ''), os.path.basename(item.get('DownloadEntryPath', '')), 
                            None, item.get('DownloadEntryPath', ''), user, source_path) # Skipping bookmark and file sizes
            safari_items.append(si)
    except KeyError:
        log.error('DownloadHistory not found')

def ReadBookmark(bm, path, safari_items, source_path, user):
    '''Recursive function'''
    bm_title = bm.get('Title', '')
    bm_type = bm.get('WebBookmarkType','')
    if bm_type == 'WebBookmarkTypeList':
        if path == '': # To remove extra '/' at the first one
            path = bm_title
        else:
            path = path + "/" + bm_title
        try:
            children = bm['Children']
            for item in children:
                ReadBookmark(item, path, safari_items, source_path, user)
        except KeyError:
            pass#log.debug('Error fetching bookmark children @ {}'.format(path))
    elif bm_type == 'WebBookmarkTypeProxy':
        pass# do nothing
    elif bm_type == 'WebBookmarkTypeLeaf':
        bm_url = bm.get('URLString', '')
        bm_title = bm.get('URIDictionary', {}).get('title', '')
        bm_date = None
        if path.find('com.apple.ReadingList') > 0:
            try:
                bm_date = bm['ReadingList']['DateAdded']
            except KeyError: pass
        si = SafariItem(SafariItemType.BOOKMARK, bm_url, bm_title, bm_date, path, user, source_path)
        safari_items.append(si)
    else:
        log.info('Unknown type found in bookmark : {} @ {}'.format(bm_title, path))

def ReadBookmarksPlist(plist, safari_items, source_path, user):
    try:
        version = plist['WebBookmarkFileVersion']
        if version != 1:
            log.warning('WebBookmarkFileVersion is {}, this may not parse properly!'.format(version))
    except KeyError:
        log.error('WebBookmarkFileVersion not found')
    ReadBookmark(plist, '', safari_items, source_path, user)

def ReadTopSitesPlist(plist, safari_items, source_path, user):
    ts_last_mod_date = None
    try:
        ts_last_mod_date = plist['DisplayedSitesLastModified']
        log.info('Topsites last modified on {}'.format(ts_last_mod_date))
    except KeyError:
        log.error('DisplayedSitesLastModified not found')
    try:
        banned = plist['BannedURLStrings']
        for item in banned:
            si = SafariItem(SafariItemType.TOPSITE_BANNED, item, '', ts_last_mod_date, 
                            'Date represents DisplayedSitesLastModified for all Topsites', user, source_path)
            safari_items.append(si)
    except KeyError:
        log.error('BannedURLStrings not found')
    try:
        downloads = plist['TopSites']
        for item in downloads:
            si = SafariItem(SafariItemType.TOPSITE, item.get('TopSiteURLString', ''), item.get('TopSiteTitle', ''), 
                            ts_last_mod_date, 'Date represents DisplayedSitesLastModified for all Topsites', user, source_path)
            safari_items.append(si)
    except KeyError:
        log.error('TopSites not found')

def ReadLastSessionPlist(plist, safari_items, source_path, user):
    try:
        version = plist['SessionVersion']
        if version != '1.0':
            log.warning('SessionVersion is {}, this may not parse properly!'.format(version))
    except KeyError:
        log.error('SessionVersion not found')
    try:
        session_windows = plist['SessionWindows']
        for windows in session_windows:
            selectedIndex = windows.get('SelectedTabIndex', None)
            index = 0
            for tab in windows.get('TabStates', []):
                info = 'SELECTED WINDOW' if index == selectedIndex else ''
                date_closed = tab.get('DateClosed', '')
                log.debug(date_closed)
                if date_closed:
                    if info:
                        info += ', TAB_CLOSED_DATE=' + str(date_closed)
                    else:
                        info = 'TAB_CLOSED_DATE=' + str(date_closed)
                si = SafariItem(SafariItemType.LASTSESSION, tab.get('TabURL', ''), tab.get('TabTitle', ''), 
                                CommonFunctions.ReadMacAbsoluteTime(tab.get('LastVisitTime', '')), 
                                info, user, source_path) # Skipping SessionState(its encrypted) & TabIdentifier
                safari_items.append(si)
                index += 1
    except KeyError as ex:
        log.error('SessionWindows not found or unable to parse. Error was {}'.format(str(ex)))

def ReadRecentlyClosedTabsPlist(plist, safari_items, source_path, user):
    try:
        version = plist['ClosedTabOrWindowPersistentStatesVersion']
        if version != '1':
            log.warning('ClosedTabOrWindowPersistentStatesVersion is {}, this may not parse properly!'.format(version))
    except KeyError:
        log.error('ClosedTabOrWindowPersistentStatesVersion not found')
    try:
        tabs = plist['ClosedTabOrWindowPersistentStates']
        for tab in tabs:
            state_type = tab.get('PersistentStateType', None)
            if state_type not in [0, 1]: 
                log.warning('Unknown PersistentStateType: {}'.format(state_type))
            state = tab.get('PersistentState', None)
            if state:
                date_closed = state.get('DateClosed', None)
                private_mode = state.get('IsPrivateWindow', False)
                if state_type == 0:
                    si = SafariItem(SafariItemType.RECENTCLOSEDTAB, state.get('TabURL', ''), state.get('TabTitle', ''), 
                                    date_closed, 'PRIVATE MODE' if private_mode else '', user, source_path)
                    safari_items.append(si)
                else: # assume 1 or higher
                    tab_states = state.get('TabStates', [])
                    for ts in tab_states:
                        date_closed = ts.get('DateClosed', date_closed)
                        ts.get('TabTitle')
                        si = SafariItem(SafariItemType.RECENTCLOSEDTAB, ts.get('TabURL', ''), ts.get('TabTitle', ''), 
                                        date_closed, 'PRIVATE MODE' if private_mode else '', user, source_path)
                    safari_items.append(si)
            else:
                log.error('Key PersistentState not present!')
    except KeyError as ex:
        log.error('ClosedTabOrWindowPersistentStates not found or unable to parse. Error was {}'.format(str(ex)))

def ProcessSafariFolder(mac_info, folder_path, user, safari_items, safari_profiles={'': SafariProfile('', '', '')}):
    files_list = [ ['History.plist', ReadHistoryPlist] , ['Downloads.plist', ReadDownloadsPlist], 
                    ['Bookmarks.plist', ReadBookmarksPlist], ['TopSites.plist', ReadTopSitesPlist], 
                    ['LastSession.plist', ReadLastSessionPlist], ['Extensions/Extensions.plist', ReadExtensionsPlist],
                    ['RecentlyClosedTabs.plist', ReadRecentlyClosedTabsPlist] ]
    for item in files_list:
        source_path = folder_path + '/' + item[0]
        if mac_info.IsValidFilePath(source_path):
            ProcessSafariPlist(mac_info, source_path, user, safari_items, item[1])
        else:
            log.debug('Safari File not found : {}'.format(source_path))

    for safari_profile in safari_profiles.values():
        if safari_profile.profile_uuid:
            history_db_path = folder_path + f'/Profiles/{safari_profile.profile_uuid}/History.db'
        else:
            history_db_path = folder_path + '/History.db'
        # Yosemite onwards there is History.db
        ReadDbFromImage(mac_info, history_db_path, user, safari_items, ReadHistoryDb, 'safari history', safari_profile)

    # CloudTabs.db, SafariTabs.db, BrowserState.db are used as common databases for all profiles
    ReadDbFromImage(mac_info, folder_path + '/CloudTabs.db', user, safari_items, ReadCloudTabsDb, 'safari CloudTabs')
    ReadDbFromImage(mac_info, folder_path + '/SafariTabs.db', user, safari_items, ReadSafariTabsDb, 'safari Tabs')
    ReadDbFromImage(mac_info, folder_path + '/BrowserState.db', user, safari_items, ReadBrowserStateDb, 'safari BrowserState')

def ReadDbFromImage(mac_info, source_path, user, safari_items, processing_func, description, safari_profile=SafariProfile('', '', '')):
    if mac_info.IsValidFilePath(source_path) and mac_info.GetFileSize(source_path, 0) > 0:
        if safari_profile.profile_uuid:
            prefix = user + "_" + safari_profile.profile_name + '_'
        else:
            prefix = user + '_'
        mac_info.ExportFile(source_path, __Plugin_Name, prefix)
        try:
            sqlite = SqliteWrapper(mac_info)
            conn = sqlite.connect(source_path)
            if conn:
                if processing_func in (ReadHistoryDb, ):
                    processing_func(conn, safari_items, source_path, user, safari_profile)
                else:
                    processing_func(conn, safari_items, source_path, user)
            conn.close()
        except (sqlite3.Error, OSError) as ex:
            log.exception ("Failed to open {} database '{}', is it a valid SQLITE DB?".format(description, source_path))

def Plugin_Start(mac_info):
    '''Main Entry point function for plugin'''
    safari_items = []
    user_safari_plist_paths = ('{}/Library/Preferences/com.apple.safari.plist',
                            '{}/Library/Containers/com.apple.Safari/Data/Library/Preferences/com.apple.Safari.plist')
    user_safari_path = '{}/Library/Safari'
    user_safari_path_15 = '{}/Library/Containers/com.apple.Safari/Data/Library/Safari' # Safari 15 moved some data here
    user_safari_extensions = ('{}/Library/Containers/com.apple.Safari/Data/Library/Safari/{}AppExtensions/Extensions.plist',
                            '{}/Library/Containers/com.apple.Safari/Data/Library/Safari/{}WebExtensions/Extensions.plist')
    user_safari_tabsnapshots_path = '{}/Library/Containers/com.apple.Safari/Data/Library/Caches/com.apple.Safari/TabSnapshots'
    processed_paths = []
    for user in mac_info.users:
        user_name = user.user_name
        if user.home_dir == '/private/var/empty': continue # Optimization, nothing should be here!
        elif user.home_dir == '/private/var/root': user_name = 'root' # Some other users use the same root folder, we will list such all users as 'root', as there is no way to tell
        if user.home_dir in processed_paths: continue # Avoid processing same folder twice (some users have same folder! (Eg: root & daemon))
        processed_paths.append(user.home_dir)
        for user_safari_plist_path in user_safari_plist_paths:
            source_path = user_safari_plist_path.format(user.home_dir)
            if mac_info.IsValidFilePath(source_path):
                ProcessSafariPlist(mac_info, source_path, user_name, safari_items, ReadSafariPlist)
            #else:
            #    if not user_name.startswith('_'):
            #        log.debug('File not found: {}'.format(source_path))

        source_path = user_safari_path.format(user.home_dir)
        if mac_info.IsValidFolderPath(source_path):
            ProcessSafariFolder(mac_info, source_path, user_name, safari_items)

        # Safari 17 supports multi profiles
        source_path = user_safari_path_15.format(user.home_dir)
        safari_profiles = GetSafariProfiles(mac_info, source_path)
        if mac_info.IsValidFolderPath(source_path):
            ProcessSafariFolder(mac_info, source_path, user_name, safari_items, safari_profiles)

        for ext_path in user_safari_extensions:
            for safari_profile in safari_profiles.values():
                if safari_profile.extension_uuid:
                    source_path = ext_path.format(user.home_dir, safari_profile.extension_uuid + '/')
                else:
                    source_path = ext_path.format(user.home_dir, '')
                if mac_info.IsValidFilePath(source_path):
                    ProcessSafariPlist(mac_info, source_path, user_name, safari_items, ReadExtensionsPlist, safari_profile)

        source_path = user_safari_tabsnapshots_path.format(user.home_dir)
        ProcessTabSnapshotsFolder(mac_info, source_path, user_name, safari_items)

    if len(safari_items) > 0:
        PrintAll(safari_items, mac_info.output_params, '')
    else:
        log.info('No safari items were found!')

def Plugin_Start_Standalone(input_files_list, output_params):
    log.info("Module Started as standalone")
    for input_path in input_files_list:
        log.debug("Input file passed was: " + input_path)
        safari_items = []
        if input_path.endswith('.plist'):
            try:
                success, plist, error = CommonFunctions.ReadPlist(input_path)
                if success:
                    if input_path.lower().endswith('com.apple.safari.plist'):
                        ReadSafariPlist(plist, safari_items, input_path, '')
                    elif input_path.endswith('History.plist'):
                        ReadHistoryPlist(plist, safari_items, input_path, '')
                    elif input_path.endswith('Downloads.plist'):
                        ReadDownloadsPlist(plist, safari_items, input_path, '')
                    elif input_path.endswith('Bookmarks.plist'):
                        ReadBookmarksPlist(plist, safari_items, input_path, '')
                    elif input_path.endswith('TopSites.plist'):
                        ReadTopSitesPlist(plist, safari_items, input_path, '')
                    elif input_path.endswith('LastSession.plist'):
                        ReadLastSessionPlist(plist, safari_items, input_path, '')
                    elif input_path.endswith('Extensions.plist') and not input_path.endswith('KnownExtensions.plist'):
                        ReadExtensionsPlist(plist, safari_items, input_path, '')
                    elif input_path.endswith('RecentlyClosedTabs.plist'):
                        ReadRecentlyClosedTabsPlist(plist, safari_items, input_path, '')
                    else:
                        log.error("Unknown plist type encountered: {}".format(os.path.basename(input_path)))
                else:
                    log.error(f'Failed to read plist: {os.path.basename(input_path)} : {error}')
            except ValueError as ex:
                log.exception('Failed to open file: {}'.format(input_path))
        elif input_path.endswith('History.db'):
            log.info("Processing file " + input_path)
            try:
                conn = CommonFunctions.open_sqlite_db_readonly(input_path)
                log.debug("Opened database successfully")
                ReadHistoryDb(conn, safari_items, input_path, '')
            except (sqlite3.Error, OSError) as ex:
                log.exception("Failed to open database, is it a valid SQLITE DB?")
        elif input_path.endswith('CloudTabs.db'):
            log.info("Processing file " + input_path)
            try:
                conn = CommonFunctions.open_sqlite_db_readonly(input_path)
                log.debug("Opened database successfully")
                ReadCloudTabsDb(conn, safari_items, input_path, '')
            except (sqlite3.Error, OSError) as ex:
                log.exception("Failed to open database, is it a valid SQLITE DB?")
        elif input_path.endswith('SafariTabs.db'):
            log.info("Processing file " + input_path)
            try:
                conn = CommonFunctions.open_sqlite_db_readonly(input_path)
                log.debug("Opened database successfully")
                ReadSafariTabsDb(conn, safari_items, input_path, '')
            except (sqlite3.Error, OSError) as ex:
                log.exception("Failed to open database, is it a valid SQLITE DB?")
        elif input_path.endswith('BrowserState.db'):
            log.info("Processing file " + input_path)
            try:
                conn = CommonFunctions.open_sqlite_db_readonly(input_path)
                log.debug("Opened database successfully")
                ReadBrowserStateDb(conn, safari_items, input_path, '')
            except (sqlite3.Error, OSError) as ex:
                log.exception("Failed to open database, is it a valid SQLITE DB?")
        elif input_path.endswith('Metadata.db'):
            log.info("Processing file " + input_path)
            try:
                conn = CommonFunctions.open_sqlite_db_readonly(input_path)
                log.debug("Opened database successfully")
                ReadSafariTabSnapshotsDb(conn, safari_items, input_path, '')
            except (sqlite3.Error, OSError) as ex:
                log.exception("Failed to open database, is it a valid SQLITE DB?")
        else:
            log.error('Input file {} is not a recognized name of a Safari artifact!'.format(input_path))
        if len(safari_items) > 0:
            PrintAll(safari_items, output_params, input_path)
        else:
            log.info('No safari items found in {}'.format(input_path))

def Plugin_Start_Ios(ios_info):
    '''Entry point for ios_apt plugin'''
    safari_items = []
    for app in ios_info.apps:
        if app.bundle_display_name.lower() == "safari":
            log.debug(f'Safari version {app.bundle_version} found at {app.sandbox_path}')
            safari_plist_path = f'{app.sandbox_path}/Library/Preferences/com.apple.mobilesafari.plist'

            if ios_info.IsValidFilePath(safari_plist_path):
                ProcessSafariPlist(ios_info, safari_plist_path, 'mobile', safari_items, ReadSafariPlist)
            break
    source_path = '/private/var/mobile/Library/Safari'
    if ios_info.IsValidFolderPath(source_path):
        ReadDbFromImage(ios_info, source_path + '/History.db', 'mobile', safari_items, ReadHistoryDb, 'safari History')
        ReadDbFromImage(ios_info, source_path + '/CloudTabs.db', 'mobile', safari_items, ReadCloudTabsDb, 'safari CloudTabs')
        ReadDbFromImage(ios_info, source_path + '/SafariTabs.db', 'mobile', safari_items, ReadSafariTabsDb, 'safari Tabs')
        ReadDbFromImage(ios_info, source_path + '/BrowserState.db', 'mobile', safari_items, ReadBrowserStateDb, 'safari BrowserState')
    if len(safari_items) > 0:
        PrintAll(safari_items, ios_info.output_params, '')
    else:
        log.info('No safari items were found!')

if __name__ == '__main__':
    print("This plugin is a part of a framework and does not run independently on its own!")
