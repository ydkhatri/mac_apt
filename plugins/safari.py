'''
   Copyright (c) 2017 Yogesh Khatri 

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the 
   terms of the MIT License.
   
'''
from __future__ import print_function
#from __future__ import unicode_literals # sqlite does not like
import os
import biplist
import sys
import logging
import struct
import helpers.ccl_bplist as ccl_bplist

from biplist import *
from enum import IntEnum
from helpers.macinfo import *
from helpers.writer import *


__Plugin_Name = "SAFARI"
__Plugin_Friendly_Name = "Internet history, downloaded file information, cookies and more from Safari caches"
__Plugin_Version = "1.0"
__Plugin_Description = "Gets internet history, downloaded file information, cookies and more from Safari caches"
__Plugin_Author = "Yogesh Khatri"
__Plugin_Author_Email = "yogesh@swiftforensics.com"

__Plugin_Standalone = True
__Plugin_Standalone_Usage = ''

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

def PrintAll(safari_items, output_params, source_path):
    safari_info = [ ('Type',DataType.TEXT),('Name_or_Title',DataType.TEXT),('URL',DataType.TEXT),
                    ('Date', DataType.DATE),('Other_Info', DataType.TEXT),('User', DataType.TEXT),
                    ('Source',DataType.TEXT) 
                  ]

    data_list = []
    for item in safari_items:
        data_list.append( [ str(item.type), item.name, item.url, item.date, item.other_info, item.user, item.source ] )

    WriteList("safari information", "Safari", data_list, safari_info, output_params, source_path)
    
def ReadSafariPlist(plist, safari_items, source, user):
    '''Read com.apple.safari.plist'''
    try:
        searches = plist['RecentSearchStrings'] # Mavericks
        try:
            for search in searches:
                si = SafariItem(SafariItemType.GENERAL, '', search, None, 'RECENT_SEARCH', user, source)
                safari_items.append(si)
        except Exception as ex:
            log.exception('Error reading RecentSearchStrings from plist')
    except: # Not found
        pass
    try:
        searches = plist['RecentWebSearches'] # Yosemite
        try:
            for search in searches:
                si = SafariItem(SafariItemType.GENERAL, '', search.get('SearchString',''), 
                                search.get('Date', None), 'RECENT_SEARCH', user, source)
                safari_items.append(si)
        except Exception as ex:
            log.exception('Error reading RecentWebSearches from plist')
    except: # Not found
        pass        
    try:
        freq_sites = plist['FrequentlyVisitedSitesCache'] # seen in  El Capitan
        try:
            for site in freq_sites:
                si = SafariItem(SafariItemType.FREQUENTLY_VISITED, site.get('URL', ''), search.get('Title',''), 
                                None, 'FrequentlyVisitedSitesCache', user, source)
                safari_items.append(si)
        except Exception as ex:
            log.exception('Error reading FrequentlyVisitedSitesCache from plist')
    except: # Not found
        pass     
    try:
        download_path = plist['DownloadsPath']
        si = SafariItem(SafariItemType.GENERAL, '', download_path, None, 'DOWNLOADS_PATH', user, source)
        safari_items.append(si) 
    except: # Not found
        pass
    try:
        home = plist['HomePage']
        si = SafariItem(SafariItemType.GENERAL, home, '', None, 'HOME_PAGE', user, source)
        safari_items.append(si) 
    except: # Not found
        pass
    try:
        last_ext_pref_selected = plist['LastExtensionSelectedInPreferences']
        si = SafariItem(SafariItemType.EXTENSION, '', last_ext_pref_selected, None, 'LastExtensionSelectedInPreferences', user, source)
        safari_items.append(si) 
    except: # Not found
        pass
    try:
        last_root_dir = plist['NSNavLastRootDirectory']
        si = SafariItem(SafariItemType.GENERAL, last_root_dir, '', None, 'NSNavLastRootDirectory', user, source)
        safari_items.append(si) 
    except: # Not found
        pass
    try:
        time = CommonFunctions.ReadMacAbsoluteTime(plist['SuccessfulLaunchTimestamp'])
        si = SafariItem(SafariItemType.GENERAL, '', '', time, 'SuccessfulLaunchTimestamp', user, source)
        safari_items.append(si)
    except: # Not found
        pass        

def ProcessSafariPlist(mac_info, source_path, user, safari_items, read_plist_function):
    mac_info.ExportFile(source_path, __Plugin_Name, user + "_", False)
    success, plist, error = mac_info.ReadPlist(source_path)
    if success:
        read_plist_function(plist, safari_items, source_path, user)
    else:
        log.info('Failed to open plist: {}'.format(source_path))
    pass

def ReadHistoryDb(conn, safari_items, source_path, user):
    try:
        conn.row_factory = sqlite3.Row
        cursor = conn.execute("select title, url, load_successful, visit_time as time_utc from "
                              "history_visits left join history_items on history_visits.history_item = history_items.id")
        try:
            rowcount = 0
            for row in cursor:
                try:
                    si = SafariItem(SafariItemType.HISTORY, row['url'], row['title'], 
                                    CommonFunctions.ReadMacAbsoluteTime(row['time_utc']),'', user, source_path)
                    safari_items.append(si)
                except Exception as ex:
                    log.exception ("Error while fetching row data")
        except Exception as ex:
            log.exception ("Db cursor error while reading file " + source_path)
        conn.close()
    except Exception as ex:
        log.exception ("Sqlite error")

def ReadExtensionsPlist(plist, safari_items, source_path, user):
    try:
        extensions = plist['Installed Extensions']
        for item in extensions:
            try:
                info = item.get('Enabled', '')
                if info != '':
                    info = 'Enabled: ' + str(info)
                apple_signed = item.get('Apple-signed', '')
                if apple_signed != '':
                    info = ', '.join([info, 'Apple-signed: ' + str(apple_signed)])
                si = SafariItem(SafariItemType.EXTENSION, '', item.get('Archive File Name', ''), 
                                None, info, user, source_path)
                safari_items.append(si)
            except:
                log.exception('Problem parsing extension info')
    except:
        log.error('Installed Extensions not found')

def ReadHistoryPlist(plist, safari_items, source_path, user):
    try:
        version = plist['WebHistoryFileVersion']
        if version != 1:
            log.warning('WebHistoryFileVersion is {}, this may not parse properly!'.format(version))
    except:
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
            except Exception as ex:
                log.error(str(ex))
    except:
        log.error('WebHistoryDates not found')
    try:
        history_domains = plist['WebHistoryDomains.v2']
        for item in history_domains:
            si = SafariItem(SafariItemType.HISTORYDOMAINS, '', item.get('', ''), None, 
                            'ITEMCOUNT:' + unicode(item.get('itemCount', 0)) , user, source_path)
            safari_items.append(si)
    except:
        log.error('WebHistoryDomains.v2 not found')

def ReadDownloadsPlist(plist, safari_items, source_path, user):
    try:
        downloads = plist['DownloadHistory']
        for item in downloads:
            si = SafariItem(SafariItemType.DOWNLOAD, item.get('DownloadEntryURL', ''), os.path.basename(item.get('DownloadEntryPath', '')), 
                            None, item.get('DownloadEntryPath', ''), user, source_path) # Skipping bookmark and file sizes
            safari_items.append(si)
    except:
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
        except:
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
            except: pass
        si = SafariItem(SafariItemType.BOOKMARK, bm_url, bm_title, bm_date, path, user, source_path)
        safari_items.append(si)
    else:
        log.info('Unknown type found in bookmark : {} @ {}'.format(bm_title, path))

def ReadBookmarksPlist(plist, safari_items, source_path, user):
    try:
        version = plist['WebBookmarkFileVersion']
        if version != 1:
            log.warning('WebBookmarkFileVersion is {}, this may not parse properly!'.format(version))
    except:
        log.error('WebBookmarkFileVersion not found')
    ReadBookmark(plist, '', safari_items, source_path, user)

def ReadTopSitesPlist(plist, safari_items, source_path, user):
    ts_last_mod_date = None
    try:
        ts_last_mod_date = plist['DisplayedSitesLastModified']
        log.info('Topsites last modified on {}'.format(ts_last_mod_date))
    except:
        log.error('DisplayedSitesLastModified not found')
    try:
        banned = plist['BannedURLStrings']
        for item in banned:
            si = SafariItem(SafariItemType.TOPSITE_BANNED, item, '', ts_last_mod_date, 
                            'Date represents DisplayedSitesLastModified for all Topsites', user, source_path)
            safari_items.append(si)
    except:
        log.error('BannedURLStrings not found')
    try:
        downloads = plist['TopSites']
        for item in downloads:
            si = SafariItem(SafariItemType.TOPSITE, item.get('TopSiteURLString', ''), item.get('TopSiteTitle', ''), 
                            ts_last_mod_date, 'Date represents DisplayedSitesLastModified for all Topsites', user, source_path)
            safari_items.append(si)
    except:
        log.error('TopSites not found')

def ReadLastSessionPlist(plist, safari_items, source_path, user):
    try:
        version = plist['SessionVersion']
        if version != '1.0':
            log.warning('SessionVersion is {}, this may not parse properly!'.format(version))
    except:
        log.error('SessionVersion not found')
    try:
        session_windows = plist['SessionWindows']
        for windows in session_windows:
            selectedIndex = None
            try: selectedIndex = windows['SelectedTabIndex']
            except: pass
            index = 0
            for tab in windows['TabStates']:
                si = SafariItem(SafariItemType.LASTSESSION, tab.get('TabURL', ''), tab.get('TabTitle', ''), 
                                CommonFunctions.ReadMacAbsoluteTime(tab.get('LastVisitTime', '')), 
                                'SELECTED WINDOW' if index == selectedIndex else '', user, source_path) # Skipping SessionState(its encrypted) & TabIdentifier
                safari_items.append(si)
                index += 1
    except Exception as ex:
        log.error('SessionWindows not found or unable to parse. Error was {}'.format(str(ex)))

def ReadRecentlyClosedTabsPlist(plist, safari_items, source_path, user):
    try:
        version = plist['ClosedTabOrWindowPersistentStatesVersion']
        if version != '1':
            log.warning('ClosedTabOrWindowPersistentStatesVersion is {}, this may not parse properly!'.format(version))
    except:
        log.error('ClosedTabOrWindowPersistentStatesVersion not found')
    try:
        tabs = plist['ClosedTabOrWindowPersistentStates']
        for tab in tabs:
            state_type = tab.get('PersistentStateType', None)
            if state_type not in [0, 1]: 
                log.warning('Unknown PersistentStateType: {}'.format(PersistentStateType))
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
    except Exception as ex:
        log.error('ClosedTabOrWindowPersistentStates not found or unable to parse. Error was {}'.format(str(ex)))   

def ProcessSafariFolder(mac_info, folder_path, user, safari_items):
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
    # Yosemite onwards there is History.db
    source_path = folder_path + '/History.db'
    if mac_info.IsValidFilePath(source_path) and mac_info.GetFileSize(source_path) > 0:
        mac_info.ExportFile(source_path, __Plugin_Name, user + "_")
        try:
            sqlite = SqliteWrapper(mac_info)
            conn = sqlite.connect(source_path)
            ReadHistoryDb(conn, safari_items, source_path, user)
        except Exception as ex:
            log.exception ("Failed to open safari history database '{}', is it a valid SQLITE DB?".format(source_path))

def Plugin_Start(mac_info):
    '''Main Entry point function for plugin'''
    safari_items = []
    user_safari_plist_path = '{}/Library/Preferences/com.apple.safari.plist'
    user_safari_path = '{}/Library/Safari'
    processed_paths = []
    for user in mac_info.users:
        user_name = user.user_name
        if user.home_dir == '/private/var/empty': continue # Optimization, nothing should be here!
        elif user.home_dir == '/private/var/root': user_name = 'root' # Some other users use the same root folder, we will list such all users as 'root', as there is no way to tell
        if user.home_dir in processed_paths: continue # Avoid processing same folder twice (some users have same folder! (Eg: root & daemon))
        processed_paths.append(user.home_dir)
        source_path = user_safari_plist_path.format(user.home_dir)
        if mac_info.IsValidFilePath(source_path):
            ProcessSafariPlist(mac_info, source_path, user_name, safari_items, ReadSafariPlist)
        else:
            log.debug('File not found: {}'.format(source_path))
        
        source_path = user_safari_path.format(user.home_dir)
        if mac_info.IsValidFolderPath(source_path):
            ProcessSafariFolder(mac_info, source_path, user_name, safari_items)

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
                plist = readPlist(input_path)
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
                elif input_path.endswith('Extensions.plist'):
                    ReadExtensionsPlist(plist, safari_items, input_path, '')
                elif input_path.endswith('RecentlyClosedTabs.plist'):
                    ReadRecentlyClosedTabsPlist(plist, safari_items, input_path, '')
                else:
                    log.error("Unknown plist type encountered: {}".format(os.path.basename(input_path)))
            except Exception as ex:
                log.exception('Failed to open file: {}'.format(input_path))
        elif input_path.endswith('History.db'):
            log.info ("Processing file " + input_path)
            try:
                conn = sqlite3.connect(input_path)
                log.debug ("Opened database successfully")
                ReadHistoryDb(conn, safari_items, input_path, '')
            except Exception as ex:
                log.exception ("Failed to open database, is it a valid SQLITE DB?")
        else:
            log.error('Input file {} is not a plist!'.fromat(input_path))
        if len(safari_items) > 0:
            PrintAll(safari_items, output_params, input_path)
        else:
            log.info('No safari items found in {}'.format(input_path))

if __name__ == '__main__':
    print ("This plugin is a part of a framework and does not run independently on its own!")