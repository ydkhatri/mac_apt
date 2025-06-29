'''
   Copyright (c) 2025 Yogesh Khatri

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the
   terms of the MIT License.

   launchpad.py
   ---------------
   Reads the launchpad database for each user.

'''

import logging
from plugins.helpers.common import CommonFunctions
from plugins.helpers.bookmark import *
from plugins.helpers.macinfo import *
from plugins.helpers.writer import *

__Plugin_Name = "LAUNCHPAD"
__Plugin_Friendly_Name = "Launchpad Items"
__Plugin_Version = "1.0"
__Plugin_Description = "Reads the launchpad database for every user"
__Plugin_Author = "Yogesh Khatri"
__Plugin_Author_Email = "yogesh@swiftforensics.com"

__Plugin_Modes = "MACOS,ARTIFACTONLY"
__Plugin_ArtifactOnly_Usage = 'Provide the file located at <USER_DARWIN_DIR>/com.apple.dock.launchpad/db/db'

log = logging.getLogger('MAIN.' + __Plugin_Name) # Do not rename or remove this ! This is the logger object

#---- Do not change the variable names in above section ----#

class LaunchpadItem:
    def __init__(self, title, mod_date, file_path, bundle_id, category, user, source_path):
        
        self.title = title
        self.file_path = file_path
        self.bundle_id = bundle_id
        self.category = category
        self.db_last_modified_date = mod_date
        self.user = user
        self.source_path = source_path

def PrintAll(launchpad_items, output_params, input_path=''):
    launchpad_info = [   
                    ('App Title',DataType.TEXT),
                    ('Db Modified date',DataType.DATE),('File Path',DataType.TEXT),
                    ('Bundle ID', DataType.TEXT),('Category', DataType.TEXT),
                    ('User',DataType.TEXT),('Source',DataType.TEXT)
                ]

    log.info (str(len(launchpad_items)) + " user launchpad item(s) found")

    launchpad_list_final = []
    for item in launchpad_items:
        single_item = [ item.title, item.db_last_modified_date,
                        item.file_path, item.bundle_id, item.category,
                        item.user, item.source_path
                        ]
        launchpad_list_final.append(single_item)

    WriteList("Launchpad Information", "Launchpad Items", launchpad_list_final, launchpad_info, output_params, input_path)

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

def ExtractLaunchpadDbAndRead(mac_info, launchpad_items, user, file_path):
    if mac_info.IsValidFilePath(file_path):
        mac_info.ExportFile(file_path, __Plugin_Name, user + '_')
        db, wrapper = OpenDbFromImage(mac_info, file_path)
        if db:
            ParseLaunchpadItemsDb(db, launchpad_items, user, file_path)
            db.close()

def OpenLaunchpadDbAndRead(source_path, launchpad_items):
    conn = OpenDb(source_path)
    if conn:
        ParseLaunchpadItemsDb(conn, launchpad_items, '', source_path)
        conn.close()

def ParseLaunchpadItemsDb(db, launchpad_items, user_name, source_path):
    db.row_factory = sqlite3.Row
    db_compatible_ver = 0
    db_ver = 0

    if CommonFunctions.TableExists(db, 'dbinfo'):
        try:
            cursor = db.cursor()
            query = '''SELECT 
                    (SELECT value as version from dbinfo where key == 'version') as version,
                    (SELECT value as compatibleVersion from dbinfo where key == 'compatibleVersion') as compatibleVersion'''
            cursor = db.execute(query)
            for row in cursor:
                db_compatible_ver = row['compatibleVersion']
                db_ver = row['version']
        except sqlite3.Error as ex:
            log.error(f"Error executing query {query}, error was {ex}")
        
        if db_compatible_ver != '6':
            log.warning(f'Unknown db version ({db_ver}), compatible ver={db_compatible_ver}, still trying to read!')

        try:
            cursor = db.cursor()
            query = '''SELECT title, bundleid, categories.uti as cat, moddate, bookmark
                        FROM apps 
                        LEFT JOIN categories ON categories.rowid=apps.category_id'''
            cursor = db.execute(query)
            for row in cursor:
                app_title = row['title']
                app_bundle_id = row['bundleid']
                app_category = row['cat']
                app_moddate = CommonFunctions.ReadMacAbsoluteTime(row['moddate'])
                app_bookmark = row['bookmark']

                path = ''
                try:
                    bm = Bookmark.from_bytes(app_bookmark)
                    path = '/'.join(bm.tocs[0][1].get(BookmarkKey.Path, []))
                    vol_path = bm.tocs[0][1].get(BookmarkKey.VolumePath, '/') # in case it is different from /
                    if path:
                        path = vol_path + path
                except (KeyError, ValueError, TypeError):
                    log.exception("Failed to read path from bookmark")
                    
                di = LaunchpadItem(app_title, app_moddate, path, app_bundle_id, app_category, user_name, source_path)
                launchpad_items.append(di)
        except (sqlite3.Error) as ex:
            log.error(f"Error executing query {query}, error was {ex}")         

def Plugin_Start(mac_info):
    '''Main Entry point function for plugin'''
    launchpad_db = '{}/com.apple.dock.launchpad/db/db' # db within each user's darwin user dir.
    launchpad_items = []
    processed_paths = []
    for user in mac_info.users:
        user_name = user.user_name
        if user.home_dir == '/private/var/empty': continue # Optimization, nothing should be here!
        elif user.home_dir == '/private/var/root': user_name = 'root' # Some other users use the same root folder, we will list such all users as 'root', as there is no way to tell
        if user.home_dir in processed_paths: continue # Avoid processing same folder twice (some users have same folder! (Eg: root & daemon))
        processed_paths.append(user.home_dir)

        if user.DARWIN_USER_DIR:
            darwin_user_folders = user.DARWIN_USER_DIR.split(',')
            for darwin_user_dir in darwin_user_folders:
                db_path = launchpad_db.format(darwin_user_dir)
                if mac_info.IsValidFilePath(db_path):
                    log.debug(db_path)
                    ExtractLaunchpadDbAndRead(mac_info, launchpad_items, user_name, db_path)

    if len(launchpad_items) > 0:
        PrintAll(launchpad_items, mac_info.output_params, '')
    else:
        log.info('No launchpad items found')

def Plugin_Start_Standalone(input_files_list, output_params):
    log.info("Module Started as standalone")
    for input_path in input_files_list:
        log.debug("Input file passed was: " + input_path)
        launchpad_items = []
        OpenLaunchpadDbAndRead(input_path, launchpad_items)
        if len(launchpad_items) > 0:
            PrintAll(launchpad_items, output_params, input_path)
        else:
            log.info('No launchpad items found in {}'.format(input_path))

if __name__ == '__main__':
    print ("This plugin is a part of a framework and does not run independently on its own!")