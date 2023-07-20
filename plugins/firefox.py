'''
   Copyright (c) 2023 Yogesh Khatri 

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

__Plugin_Name = "FIREFOX"
__Plugin_Friendly_Name = "Internet history, downloaded file information, extensions and more from Mozilla Firefox"
__Plugin_Version = "1.0"
__Plugin_Description = "Gets internet history, downloaded file information, extension and more from Mozilla Firefox"
__Plugin_Author = "Yogesh Khatri"
__Plugin_Author_Email = "yogesh@swiftforensics.com"

__Plugin_Modes = "MACOS,ARTIFACTONLY"
__Plugin_ArtifactOnly_Usage = 'Provide the path to ".../Firefox/Profiles/<Profile Name>" folder as argument'

log = logging.getLogger('MAIN.' + __Plugin_Name) # Do not rename or remove this ! This is the logger object

#---- Do not change the variable names in above section ----#

class FirefoxItemType(IntEnum):
    UNKNOWN = 0
    HISTORY = 1
    EXTENSION = 2

    def __str__(self):
        return self.name

class FirefoxItem:
    def __init__(self, type, url, title, visit_date, last_visit_date, local_path, visit_count, other, user, source):
        self.type = type
        self.url = url
        self.title = title
        self.visit_date = visit_date
        self.last_visit_date = last_visit_date
        self.local_path = local_path
        self.visit_count = visit_count
        self.other_info = other
        self.user = user
        self.source = source

class FirefoxFormItem:
    def __init__(self, fieldname, value, times_used, first_used, last_used, moz_source, user, source) -> None:
        self.fieldname = fieldname
        self.value = value
        self.times_used = times_used
        self.first_used = first_used
        self.last_used = last_used
        self.moz_source = moz_source
        self.user = user
        self.source = source
        
def PrintAll(firefox_artifacts, output_params, source_path):
    firefox_info = [ ('Type',DataType.TEXT),('Name_or_Title',DataType.TEXT),('URL',DataType.TEXT),
                    ('Visit Date',DataType.DATE),('Last Visit Date',DataType.DATE),('Local Path',DataType.TEXT),
                    ('Visit Count',DataType.INTEGER),('Other Info',DataType.TEXT),
                    ('User', DataType.TEXT),('Source',DataType.TEXT)
                   ]
    data_list = []
    log.info (f"{len(firefox_artifacts)} firefox artifact(s) found")
    for item in firefox_artifacts:
        data_list.append( [ str(item.type), item.title, item.url, item.visit_date, item.last_visit_date, item.local_path,
                            item.visit_count, item.other_info, item.user, item.source ] )
    WriteList("Firefox", "Firefox", data_list, firefox_info, output_params, source_path)

def PrintFormData(firefox_form_artifacts, output_params, source_path):
    form_info = [ ('Field name',DataType.TEXT),('Value', DataType.TEXT),('Times Used',DataType.INTEGER),
                    ('First Used', DataType.DATE),('Last Used', DataType.DATE),('Form Source', DataType.TEXT),
                    ('User', DataType.TEXT),('Source',DataType.TEXT)
                ]
    data_list = []
    log.info (f"{len(firefox_form_artifacts)} firefox form artifact(s) found")
    for item in firefox_form_artifacts:
        data_list.append( [ item.fieldname, item.value, item.times_used, item.first_used, item.last_used, 
                            item.moz_source, item.user, item.source ] )

    WriteList("Firefox_FormHistory", "Firefox_FormHistory", data_list, form_info, output_params, source_path)

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

def ExtractAndReadDb(mac_info, firefox_artifacts, user, file_path, parser_function):
    if mac_info.IsValidFilePath(file_path):
        mac_info.ExportFile(file_path, __Plugin_Name, user + '_')
        db, wrapper = OpenDbFromImage(mac_info, file_path)
        if db:
            parser_function(firefox_artifacts, db, user, file_path)
            db.close()

def ExtractAndReadFile(mac_info, firefox_artifacts, user, file_path, parser_function):
    if mac_info.IsValidFilePath(file_path):
        mac_info.ExportFile(file_path, __Plugin_Name, user + '_')
        f = mac_info.Open(file_path)
        if f:
            parser_function(firefox_artifacts, f, user, file_path)
            f.close()

def OpenLocalDbAndRead(firefox_artifacts, user, file_path, parser_function):
    conn = OpenDb(file_path)
    if conn:
        parser_function(firefox_artifacts, conn, '', file_path)
        conn.close()

def OpenLocalFileAndRead(firefox_artifacts, user, file_path, parser_function):
    f = open(file_path, 'rb')
    log.info ("Processing file {}".format(file_path))
    parser_function(firefox_artifacts, f, '', file_path)
    f.close()

def process_places(firefox_artifacts, db, user, file_path):
    try:
        db.row_factory = sqlite3.Row
        cursor = db.cursor()

        query = \
        ''' 
            SELECT moz_historyvisits.visit_date, moz_places.last_visit_date,
            (SELECT content FROM  moz_annos
                LEFT JOIN moz_anno_attributes ON moz_anno_attributes.id=moz_annos.anno_attribute_id
                WHERE moz_annos.place_id=moz_places.id AND moz_anno_attributes.name LIKE 'downloads/destinationFileURI') as downloaded_path,
            (SELECT content FROM  moz_annos
                LEFT JOIN moz_anno_attributes ON moz_anno_attributes.id=moz_annos.anno_attribute_id
                WHERE moz_annos.place_id=moz_places.id AND moz_anno_attributes.name LIKE 'downloads/metaData') as download_metadata,
            
            moz_places.url, moz_places.title, moz_places.visit_count, moz_places.description,
            CASE
                WHEN moz_places.hidden = 0 THEN 'No'
                WHEN moz_places.hidden = 1 THEN 'Yes'
            END AS Hidden,
            CASE
                WHEN moz_places.typed = 0 THEN 'No'
                WHEN moz_places.typed = 1 THEN 'Yes'
            END AS Typed,
            moz_places.frecency AS Frecency,
            moz_places.preview_image_url AS PreviewImageURL
            FROM moz_historyvisits
            LEFT JOIN moz_places ON moz_places.origin_id = moz_historyvisits.id
            LEFT JOIN moz_places_metadata ON moz_places.id = moz_places_metadata.id
            WHERE url is not NULL
            ORDER BY
            moz_historyvisits.visit_date ASC 
        '''
        cursor = db.execute(query)
        for row in cursor:
            visit_date = CommonFunctions.ReadUnixMicrosecondsTime(row['visit_date'])
            last_visit_date = CommonFunctions.ReadUnixMicrosecondsTime(row['last_visit_date'])
            downloaded_path = row['downloaded_path']
            download_meta = row['download_metadata']
            description = ''
            if download_meta:
                try:
                    e = json.loads(download_meta)
                    converted_timestamp = str(CommonFunctions.ReadUnixMillisecondsTime(e['endTime']))
                    if converted_timestamp:
                        e['endTime'] = converted_timestamp
                        download_meta = json.dumps(e)
                except (json.JSONDecodeError, ValueError) as ex:
                    log.exception()
                description = f"DownloadMetadata={download_meta}"
            elif row['Description']:
                description = f"Description={row['Description']}"

            item = FirefoxItem(FirefoxItemType.HISTORY, row['url'], row['title'], 
                            visit_date, last_visit_date, downloaded_path, row['visit_count'],
                            description, user, file_path)
            firefox_artifacts.append(item)

    except sqlite3.Error:
        log.exception('DB read error from process_places()')

def process_favicons(firefox_artifacts, db, user, file_path):
    pass

def process_formhistory(firefox_form_artifacts, db, user, file_path):
    try:
        db.row_factory = sqlite3.Row
        cursor = db.cursor()

        query = \
        ''' 
            SELECT fieldname, value, timesUsed, 
            firstUsed, lastUsed, moz_sources.source as moz_source
            FROM moz_formhistory 
            LEFT JOIN moz_history_to_sources ON moz_history_to_sources.history_id=moz_formhistory.id
            LEFT JOIN moz_sources ON moz_sources.id=moz_history_to_sources.source_id
        '''
        cursor = db.execute(query)
        for row in cursor:
            item = FirefoxFormItem(row['fieldname'], row['value'], row['timesUsed'], 
                                    CommonFunctions.ReadUnixMicrosecondsTime(row['firstUsed']), 
                                    CommonFunctions.ReadUnixMicrosecondsTime(row['lastUsed']),
                                    row['moz_source'], user, file_path)
            firefox_form_artifacts.append(item)

    except sqlite3.Error:
        log.exception('DB read error from process_formhistory()')

def process_extensions(firefox_artifacts, f, user, file_path):
    try:
        extensions = json.load(f)
        log.debug(f"schemaVersion = {extensions['schemaVersion']}") # 35 in Firefox 111.0.1
        for addon in extensions['addons']:
            if addon['type'] != "extension": continue
            name = addon['defaultLocale']['name']
            desc = addon['defaultLocale'].get('description', '')
            #active = addon['active']
            installDate = CommonFunctions.ReadUnixMillisecondsTime(addon.get('installDate', None))
            path = addon.get('path')
            if path and path.lower().find('extensions') > 0:

                item = FirefoxItem(FirefoxItemType.EXTENSION, '', name, 
                                    installDate, None, path, None,
                                    desc, user, file_path)
                firefox_artifacts.append(item)

    except (json.JSONDecodeError, ValueError) as ex:
        log.exception()

def Plugin_Start(mac_info):
    '''Main Entry point function for plugin'''

    firefox_artifacts = []
    firefox_form_artifacts = []
    processed_paths = []
    firefox_path = '{}/Library/Application Support/Firefox/Profiles'

    for user in mac_info.users:
        if user.home_dir == '/private/var/empty': continue # Optimization, nothing should be here!
        elif user.home_dir == '/private/var/root': user_name = 'root' # Some other users use the same root folder, we will list all such users as 'root', as there is no way to tell
        if user.home_dir in processed_paths: continue # Avoid processing same folder twice (some users have same folder! (Eg: root & daemon))
        processed_paths.append(user.home_dir)
        source_path = firefox_path.format(user.home_dir)
        user_name = user.user_name
        if mac_info.IsValidFolderPath(source_path):
            folders_list = mac_info.ListItemsInFolder(source_path, EntryType.FOLDERS, include_dates=False)
            profile_names = (x['name'] for x in folders_list)
            for profile_name in profile_names:
                places_db_path = f'{source_path}/{profile_name}/places.sqlite'
                formhistory_db_path = f'{source_path}/{profile_name}/formhistory.sqlite'
                extensions_json_path = f'{source_path}/{profile_name}/extensions.json'

                ExtractAndReadDb(mac_info, firefox_artifacts, user_name, places_db_path, process_places)
                ExtractAndReadDb(mac_info, firefox_form_artifacts, user_name, formhistory_db_path, process_formhistory)
                ExtractAndReadFile(mac_info, firefox_artifacts, user_name, extensions_json_path, process_extensions)
                
    if len(firefox_artifacts) > 0:
        PrintAll(firefox_artifacts, mac_info.output_params, '')
    else:
        log.info('No Firefox artifacts were found!')
    
    if len(firefox_form_artifacts) > 0:
        PrintFormData(firefox_form_artifacts, mac_info.output_params, '')
    else:
        log.info('No Firefox form artifacts were found!')

def Plugin_Start_Standalone(input_files_list, output_params):
    '''Main entry point function when used on single artifacts (mac_apt_singleplugin), not on a full disk image'''
    log.info("Module Started as standalone")
    for input_path in input_files_list:
        log.debug("Input path passed was: " + input_path)
        firefox_artifacts = []
        firefox_form_artifacts = []
        if os.path.isdir(input_path):
            file_names = os.listdir(input_path)
            for file_name in file_names:
                file_path = os.path.join(input_path, file_name)
                if file_name == 'places.sqlite':
                    OpenLocalDbAndRead(firefox_artifacts, '', file_path, process_places)
                elif file_name == 'formhistory.sqlite':
                    OpenLocalDbAndRead(firefox_form_artifacts, '', file_path, process_formhistory)
                elif file_name == 'extensions.json':
                    OpenLocalFileAndRead(firefox_artifacts, '', file_path, process_extensions)

            if len(firefox_artifacts) > 0:
                PrintAll(firefox_artifacts, output_params, input_path)
            else:
                log.info('No firefox artifacts found in {}'.format(input_path))
            if len(firefox_form_artifacts) > 0:
                PrintFormData(firefox_form_artifacts, output_params, '')
            else:
                log.info('No Firefox form artifacts were found!')
        else:
            log.error(f"Argument passed was not a folder : {input_path}")

def Plugin_Start_Ios(ios_info):
    '''Entry point for ios_apt plugin'''
    pass

if __name__ == '__main__':
    print ("This plugin is a part of a framework and does not run independently on its own!")