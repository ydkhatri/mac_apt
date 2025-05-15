'''
   Copyright (c) 2017 Yogesh Khatri 

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the 
   terms of the MIT License.

'''


import logging
import posixpath
import sqlite3
import struct

from os import path
from plistutils.alias import AliasParser
from plugins.helpers.common import CommonFunctions
from plugins.helpers.macinfo import *
from plugins.helpers.writer import *
from plugins.helpers.bookmark import *

__Plugin_Name = "MSOFFICE"
__Plugin_Friendly_Name = "MSOffice"
__Plugin_Version = "1.0"
__Plugin_Description = "Reads Word, Excel, Powerpoint and other office MRU/accessed file paths"
__Plugin_Author = "Yogesh Khatri"
__Plugin_Author_Email = "yogesh@swiftforensics.com"

__Plugin_Modes = "MACOS,ARTIFACTONLY"
__Plugin_ArtifactOnly_Usage = 'Provide any of the office plists from ~/Library/Preferences/com.microsoft.*.plist '\
                            ' '

log = logging.getLogger('MAIN.' + __Plugin_Name) # Do not rename or remove this ! This is the logger object

#---- Do not change the variable names in above section ----#

# Gets data from the following files:
#  ~/Library/Preferences/com.microsoft.office.plist
#  ~/Library/Containers/com.microsoft.<OFFICEAPP>/Data/Library/Preferences/com.microsoft.<APP>.plist
#  ~/Library/Containers/com.microsoft.<OFFICEAPP>/Data/Library/Preferences/com.microsoft.<APP>.securebookmarks.plist
#
#  And the registry database at
#  ~/Library/Group Containers/xxxxxx.Office/MicrosoftRegistrationDB.reg

def GetStringRepresentation(value, valuetype = None):
    s = ''
    if value == None:
        return s
    if valuetype == 3:  # REG_BINARY
        s = value.hex().upper()
    elif valuetype == 1: #REG_SZ
        s = value
    else:
        s = str(value)
    return s

# ONLY 1,3,4,11 have been seen so far.
def GetStringValueType(valuetype):
    s = ''
    if valuetype == None or valuetype == '':
        return s
    elif valuetype == 1: s = "REG_SZ"
    elif valuetype == 3: s = "REG_BINARY"
    elif valuetype == 4: s = "REG_DWORD"
    elif valuetype == 11: s = "REG_QWORD"
    elif valuetype == 2: s = "REG_EXPAND_SZ"
    elif valuetype == 5: s = "REG_DWORD_BIG_ENDIAN"
    elif valuetype == 6: s = "REG_LINK"
    elif valuetype == 7: s = "REG_MULTI_SZ"
    elif valuetype == 8: s = "REG_RESOURCE_LIST"
    elif valuetype == 9: s = "REG_FULL_RESOURCE_DESCRIPTOR"
    elif valuetype == 10: s = "REG_RESOURCE_REQUIREMENTS_LIST"
    else:
        s = str(valuetype)
    return s

def GetUint64Value(value):
    if value != None:
        try:
            v = struct.unpack('<Q', value[0:8])[0]
            return v
        except (IndexError, struct.error, ValueError):
            log.exception('')
    return None

def OpenDbFromImage(mac_info, inputPath, user):
    '''Returns tuple of (connection, wrapper_obj)'''
    log.info ("Processing office registry entries for user '{}' from file {}".format(user, inputPath))
    try:
        sqlite = SqliteWrapper(mac_info)
        conn = sqlite.connect(inputPath)
        if conn:
            log.debug ("Opened database successfully")
        return conn, sqlite
    except sqlite3.Error as ex:
        log.exception ("Failed to open database, is it a valid DB?")
    return None, None

def OpenDb(inputPath):
    log.info ("Processing file " + inputPath)
    try:
        conn = CommonFunctions.open_sqlite_db_readonly(inputPath)
        log.debug ("Opened database successfully")
        return conn
    except sqlite3.Error:
        log.exception ("Failed to open database, is it a valid DB?")
    return None

def ParseRegistrationDB(conn,office_reg_items, user, source):

    conn.row_factory = sqlite3.Row
    try:
        query = str("SELECT  t2.node_id as id, t2.write_time as keyLastWriteTime, path as key, HKEY_CURRENT_USER_values.name as valueName, HKEY_CURRENT_USER_values.value as value, HKEY_CURRENT_USER_values.type as valueType from ( "
                " WITH RECURSIVE "
                "   under_software(path, name, node_id, write_time) AS ( "
                "     VALUES('Software','',1, NULL) "
                "     UNION ALL "
                "     SELECT under_software.path || '\\' || HKEY_CURRENT_USER.name, HKEY_CURRENT_USER.name, HKEY_CURRENT_USER.node_id, HKEY_CURRENT_USER.write_time "
                "       FROM HKEY_CURRENT_USER JOIN under_software ON HKEY_CURRENT_USER.parent_id=under_software.node_id "
                "       ORDER BY 1 "
                "   ) "
                " SELECT name, path, write_time, node_id FROM under_software "
                " ) as t2 LEFT JOIN HKEY_CURRENT_USER_values on HKEY_CURRENT_USER_values.node_id=t2.node_id ")
        cursor = conn.execute(query)
        data = cursor.fetchall()

        try:
            for row in data:
                item = MSOfficeRegItem(row['id'], 
                                CommonFunctions.ReadWindowsFileTime(GetUint64Value(row['keyLastWriteTime'])), 
                                GetStringRepresentation(row['key']),
                                GetStringValueType(row['valueType']), 
                                GetStringRepresentation(row['valueName']), 
                                GetStringRepresentation(row['value'], row['valueType']),
                                user, source)
                office_reg_items.append(item)
        except (sqlite3.Error, ValueError, IndexError):
            log.exception('')

    except sqlite3.Error as ex:
       log.exception('Error executing query : {}'.format(query))

class MSOfficeRegItem:
    def __init__(self, id, ts, key, v_type, v_name, v_data, user, source):
        self.id = id
        self.ts = ts
        self.key = key
        self.v_type = v_type
        self.v_name = v_name
        self.v_data = v_data
        self.user = user
        self.source = source

def PrintRegItems(office_items, output_params):

    office_info = [ ('Id',DataType.INTEGER),('TimeStamp',DataType.DATE),('KeyPath',DataType.TEXT),
                        ('ValueName',DataType.TEXT),('ValueType',DataType.TEXT),('ValueData',DataType.TEXT),
                        ('User', DataType.TEXT),('Source',DataType.TEXT)
                      ]

    log.info (str(len(office_items)) + " office item(s) found")
    office_list = []
    for q in office_items:
        q_item =  [ q.id, q.ts, q.key, q.v_name, q.v_type, q.v_data,
                    q.user, q.source
                  ]
        office_list.append(q_item)
    WriteList("office registry data", "MSOfficeRegistry", office_list, office_info, output_params, '')

class MSOfficeItem:

    def __init__(self, office_app, timestamp, name, data, info, user, source):
        self.office_app = office_app
        self.timestamp = timestamp
        self.name = name
        self.data = data
        self.info = info
        self.user = user
        self.source_file = source

def PrintItems(office_items, output_params):

    office_info = [ ('App',DataType.TEXT),('TimeStamp',DataType.DATE),('Name',DataType.TEXT),
                        ('Data',DataType.TEXT),('Info',DataType.TEXT),
                        ('User', DataType.TEXT),('Source',DataType.TEXT)
                      ]

    log.info (str(len(office_items)) + " office item(s) found")
    office_list = []
    for q in office_items:
        q_item =  [ q.office_app, q.timestamp, q.name, q.data, q.info, 
                    q.user, q.source_file
                  ]
        office_list.append(q_item)
    WriteList("office information", "MSOffice", office_list, office_info, output_params, '')

def ProcessMRU(office_items, app_name, mru_list, user, source):
    for mru in mru_list:
        try:
            access_data = mru.get('Access Date', '')
            access_time = None
            try:
                v = struct.unpack('<I', access_data[2:6])[0]
                access_time = CommonFunctions.ReadMacHFSTime(v)
            except (IndexError, ValueError):
                log.exception('')
            path = ''
            alias_data = mru.get('File Alias', None)
            if alias_data:
                try:
                    alias_properties = next(AliasParser.parse(source, 0, alias_data))
                    #log.debug(alias_properties)
                    path = alias_properties.get('path', '')
                except (IndexError, ValueError, KeyError, TypeError):
                    log.exception('')
                o_item = MSOfficeItem(app_name, access_time, 'MRU', path, '', user, source)
                office_items.append(o_item)
        except (ValueError, TypeError):
            log.exception('')

def ProcessOfficeAppPlist(plist, office_items, app_name, user, source):
    for item in ('NSNavLastRootDirectory', 'SessionStartTime', 'SessionDuration'): # SessionStartTime is string, stored as local time?
        item_val = plist.get(item, None)

        if item_val:
            info = ''
            if item == 'SessionDuration': 
                pass # Get item_val in HH:MM:SS
            elif item == 'SessionStartTime': info = 'Local time?'
            o_item = MSOfficeItem(app_name, None, item, item_val, info, user, source)
            office_items.append(o_item)

    bookmark_data = plist.get('LastSaveFilePathBookmark', None)
    if bookmark_data:
        file_path = ''
        file_creation_date = None
        vol_path = ''

        try:
            bm = Bookmark.from_bytes(bookmark_data)
            # Get full file path
            vol_path = bm.tocs[0][1].get(BookmarkKey.VolumePath, '')
            vol_creation_date = bm.tocs[0][1].get(BookmarkKey.VolumeCreationDate, '')
            file_path = bm.tocs[0][1].get(BookmarkKey.Path, [])

            file_path = '/' + '/'.join(file_path)
            file_creation_date = bm.tocs[0][1].get(BookmarkKey.FileCreationDate, '')
            if vol_path and (not file_path.startswith(vol_path)):
                file_path += vol_path
            
            if user == '': # in artifact_only mode
                try:
                    user = bm.tocs[0][1].get(BookmarkKey.UserName, '')
                    if user == 'unknown':
                        user = ''
                except (IndexError, ValueError):
                    pass

            o_item = MSOfficeItem(app_name, file_creation_date, 'LastSaveFilePathBookmark', file_path, 'Date is FileCreated', user, source)
            office_items.append(o_item)
        except (IndexError, ValueError):
            log.exception('Error processing BookmarkData from {}'.format(source))
            log.debug(bm)
        
def ProcessOfficeAppSecureBookmarksPlist(plist, office_items, app_name, user, source):
    '''Process com.microsoft.<APP>.securebookmarks.plist'''
    for k, v in plist.items():
        data = v.get('kBookmarkDataKey', None)

        file_creation_date = None
        try:
            bm = Bookmark.from_bytes(data)
            file_creation_date = bm.tocs[0][1].get(BookmarkKey.FileCreationDate, '')
            if user == '': # in artifact_only mode
                try:
                    user = bm.tocs[0][1].get(BookmarkKey.UserName, '')
                    if user == 'unknown':
                        user = ''
                except (IndexError, ValueError):
                    pass
        except (IndexError, ValueError):
            log.exception('Error processing BookmarkData from {}'.format(source))
            log.debug(bm)

        o_item = MSOfficeItem(app_name, file_creation_date, 'SecureBookmark', k, 'Date is FileCreated', user, source)
        office_items.append(o_item)

def ProcessOfficePlist(plist, office_items, user, source):
    for item in ('UserName', 'UserInitials', 'UserOrganization'):
        item_val = plist.get('14\\UserInfo\\{}'.format(item), None)
        if item_val:
            o_item = MSOfficeItem('', None, item, item_val, '', user, source)
            office_items.append(o_item)
    
    for item in plist:
        if item.startswith('14\\Web\\TypedURLs\\url'):
            o_item = MSOfficeItem('', None, 'TypedURLs', plist[item], '', user, source)
            office_items.append(o_item)
        elif item.find('Most Recent MRU File Name') > 0:
            o_app = ''
            try:
                o_app = item[0:-26].split('\\')[-1]
            except (IndexError, ValueError):
                pass
            o_item = MSOfficeItem(o_app, None, item, plist[item], '', user, source)
            office_items.append(o_item)

    mru_list = plist.get('14\\File MRU\\XCEL', None)
    if mru_list and len(mru_list):
        ProcessMRU(office_items, 'Excel', mru_list, user, source)

    mru_list = plist.get('14\\File MRU\\MSWD', None)
    if mru_list and len(mru_list):
        ProcessMRU(office_items, 'Word', mru_list, user, source)

    mru_list = plist.get('14\\File MRU\\PPT3', None)
    if mru_list and len(mru_list):
        ProcessMRU(office_items, 'Powerpoint', mru_list, user, source)

def ProcessAppPlists(mac_info, home_dir, office_items, user):
    # ~\Library\Containers\com.microsoft.<OFFICEAPP>\Data\Library\Preferences\com.microsoft.<APP>.plist
    app_container_path = '{}/Library/Containers'
    path_partial = app_container_path.format(home_dir)
    if mac_info.IsValidFolderPath(path_partial):
        folders_list = mac_info.ListItemsInFolder(path_partial, EntryType.FOLDERS, False)
        for folder in folders_list:
            if folder['name'].startswith('com.microsoft.'):
                name = folder['name']
                app_name = name[14:]
                plist_path = path_partial + '/' + name + '/Data/Library/Preferences/' + name + '.plist'
                if mac_info.IsValidFilePath(plist_path):
                    mac_info.ExportFile(plist_path, __Plugin_Name, user, False)
                    success, plist, error = mac_info.ReadPlist(plist_path)
                    if success:
                        ProcessOfficeAppPlist(plist, office_items, app_name, user, plist_path)
                    else:
                        log.error("Problem reading plist {} - {}".format(plist_path, error))
                #securebookmarks
                plist_path = path_partial + '/' + name + '/Data/Library/Preferences/' + name + '.securebookmarks.plist'
                if mac_info.IsValidFilePath(plist_path):
                    mac_info.ExportFile(plist_path, __Plugin_Name, user, False)
                    success, plist, error = mac_info.ReadPlist(plist_path)
                    if success:
                        ProcessOfficeAppSecureBookmarksPlist(plist, office_items, app_name, user, plist_path)
                    else:
                        log.error("Problem reading plist {} - {}".format(plist_path, error))
                
def Plugin_Start(mac_info):
    '''Main Entry point function for plugin'''
    office_items = []
    office_reg_items = []
    processed_paths = set()
    office_plist_path = '{}/Library/Preferences/com.microsoft.office.plist'
    office_reg_path_partial = '{}/Library/Group Containers' # /xxxx.Office/MicrosoftRegistrationDB.reg

    for user in mac_info.users:
        user_name = user.user_name
        if user.home_dir == '/private/var/empty': continue # Optimization, nothing should be here!
        elif user.home_dir == '/private/var/root': user_name = 'root' # Some other users use the same root folder, we will list such all users as 'root', as there is no way to tell
        if user.home_dir in processed_paths: continue # Avoid processing same folder twice (some users have same folder! (Eg: root & daemon))
        processed_paths.add(user.home_dir)

        plist_path = office_plist_path.format(user.home_dir)
        if mac_info.IsValidFilePath(plist_path):
            mac_info.ExportFile(plist_path, __Plugin_Name, user_name, False)
            success, plist, error = mac_info.ReadPlist(plist_path)
            if success:
                ProcessOfficePlist(plist, office_items, user_name, plist_path)
            else:
                log.error("Problem reading plist {} - {}".format(plist_path, error))

        reg_path_partial = office_reg_path_partial.format(user.home_dir)
        if mac_info.IsValidFolderPath(reg_path_partial):
            ProcessAppPlists(mac_info, user.home_dir, office_items, user_name)
            continue ## DEBUG ONLY
            folders_list = mac_info.ListItemsInFolder(reg_path_partial, EntryType.FOLDERS, False)
            for folder in folders_list:
                if folder['name'].endswith('.Office'):
                    reg_path = reg_path_partial + '/' + folder['name'] + '/MicrosoftRegistrationDB.reg'
                    if mac_info.IsValidFilePath(reg_path):
                        if mac_info.IsSymbolicLink(reg_path): # sometimes this is a symlink
                            target_path = mac_info.ReadSymLinkTargetPath(reg_path)
                            log.debug('SYMLINK {} <==> {}'.format(reg_path, target_path))
                            if target_path.startswith('../') or target_path.startswith('./'):
                                reg_path = mac_info.GetAbsolutePath(posixpath.split(reg_path)[0], target_path)
                            else:
                                reg_path = target_path
                            if not mac_info.IsValidFilePath(reg_path):
                                log.error(f"symlink did not point to a valid file?? path={reg_path}")
                                continue
                        
                        mac_info.ExportFile(reg_path, __Plugin_Name, user_name, False)
                        conn, wrapper = OpenDbFromImage(mac_info, reg_path, user_name)
                        if conn:
                            ParseRegistrationDB(conn, office_reg_items, user_name, reg_path)
                            conn.close()
                    else:
                        log.debug('MicrosoftRegistrationDB.reg not found in path ' + reg_path_partial + '/' + folder['name'])

    if len(office_items) > 0:
        PrintItems(office_items, mac_info.output_params)
    else:
        log.info('No office items found')
    
    if len(office_reg_items) > 0:
        PrintRegItems(office_reg_items, mac_info.output_params)
    else:
        log.info('No office registries found')

def Plugin_Start_Standalone(input_files_list, output_params):
    log.info("Module Started as standalone")
    for input_path in input_files_list:
        log.debug("Input file passed was: " + input_path)
        office_items = []
        office_reg_items = []
        if input_path.endswith('com.microsoft.office.plist'):
            success, plist, error = CommonFunctions.ReadPlist(input_path)
            if success:
                ProcessOfficePlist(plist, office_items, '', input_path)
            else:
                log.error('Failed to read file: {}. {}'.format(input_path, error))
        else:
            basename = path.basename(input_path)
            if basename.startswith('com.microsoft.') and basename.endswith('.plist'):
                success, plist, error = CommonFunctions.ReadPlist(input_path)
                if success:
                    if basename.endswith('securebookmarks.plist'):                    
                        app_name = basename[14:-22]
                        ProcessOfficeAppSecureBookmarksPlist(plist, office_items, app_name, '', input_path)
                    else:
                        app_name = basename[14:-6]
                        ProcessOfficeAppPlist(plist, office_items, app_name, '', input_path)
                else:
                    log.error('Failed to read file: {}. {}'.format(input_path, error))

            elif input_path.endswith('MicrosoftRegistrationDB.reg'):
                conn = OpenDb(input_path)
                if conn:
                    ParseRegistrationDB(conn, office_reg_items, '', input_path)
                    conn.close()

        if len(office_items) > 0:
            PrintItems(office_items, output_params)
        else:
            log.info('No office items found in {}'.format(input_path))

        if len(office_reg_items) > 0:
            PrintRegItems(office_reg_items, output_params)
        else:
            log.info('No office registries found')

if __name__ == '__main__':
    print ("This plugin is a part of a framework and does not run independently on its own!")