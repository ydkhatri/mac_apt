'''
   Copyright (c) 2017 Yogesh Khatri 

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the 
   terms of the MIT License.
   
'''

import os
import logging
import struct
from plugins.helpers import spotlight_parser as spotlight_parser

from biplist import *
from plugins.helpers.macinfo import *
from plugins.helpers.writer import *

__Plugin_Name = "SPOTLIGHT"
__Plugin_Friendly_Name = "Spotlight"
__Plugin_Version = "1.0"
__Plugin_Description = "Reads spotlight indexes on volume"
__Plugin_Author = "Yogesh Khatri"
__Plugin_Author_Email = "yogesh@swiftforensics.com"

__Plugin_Standalone = True
__Plugin_ArtifactOnly_Usage = "This module reads spotlight's index database file found at: /.Spotlight-V100/Store-V2/<UUID>/store.db and also '.store.db' at the same location"

log = logging.getLogger('MAIN.' + __Plugin_Name) # Do not rename or remove this ! This is the logger object

#---- Do not change the variable names in above section ----#

writer = None
spotlight_parser.log = logging.getLogger('MAIN.' + __Plugin_Name + '.SPOTLIGHT_PARSER')
    
def ProcessStoreItem(item):
    '''Reads a single store item and processes it for output. Returns dictionary'''
    try:
        data_dict = {}
        data_dict['ID'] = item.id
        data_dict['Flags'] = item.flags
        data_dict['Parent_ID'] = item.parent_id
        data_dict['Date_Updated'] = item.ConvertEpochToUtcDateStr(item.date_updated)
        for k, v in list(item.meta_data_dict.items()):
            orig_debug = v
            if type(v) == list:
                if len(v) == 1:
                    v = v[0]
                    if type(v) == str:
                        if v.endswith('\x16\x02'):
                            v = v[:-2]
                    if type(v) == str: v = v.decode('utf-8', 'backslashreplace')
                else:
                    #if type(v[0]) == str:
                    #    v = ', '.join([x.decode('utf-8') for x in v]) # removes 'u' in string output
                    #else:
                    v = ', '.join([str(x) for x in v])
            data_dict[k] = v

        return data_dict
    except Exception as ex:
        log.exception ("Failed while processing row data before writing")

def ProcessStoreItems(store_items):
    global writer
    try:
        data_list = []
        for item in store_items:
            data = ProcessStoreItem(item)
            if data:
                data_list.append(data)
        writer.WriteRows(data_list)
    except Exception as ex:
        log.exception ("Failed to write row data")

def Get_Column_Info(store):
    '''Returns a list of columns with data types for use with writer'''
    data_info = [ ('ID',DataType.INTEGER),('Flags',DataType.INTEGER),('Parent_ID',DataType.INTEGER),
                  ('Date_Updated',DataType.TEXT) ]
    for _, prop in list(store.properties.items()):
        # prop = [name, prop_type, value_type]
        if prop[0] in ('_kMDXXXX___DUMMY', 'kMDStoreAccumulatedSizes') : continue # skip this
        if prop[2] in [0, 2, 6, 7]:
            val_type = DataType.INTEGER
        else:
            val_type = DataType.TEXT
        data_info.append((prop[0], val_type))
    return data_info

def CopyOutputParams(output_params):
    '''Creates and returns a copy of MacInfo.OutputParams object'''
    op_copy = OutputParams()
    op_copy.output_path = output_params.output_path
    op_copy.write_csv = output_params.write_csv
    op_copy.write_sql = output_params.write_sql
    op_copy.write_xlsx = output_params.write_xlsx
    op_copy.xlsx_writer = output_params.xlsx_writer
    op_copy.output_db_path = output_params.output_db_path
    op_copy.export_path = output_params.export_path
    op_copy.export_log_csv = output_params.export_log_csv
    op_copy.timezone = output_params.timezone
    return op_copy

def EnableSqliteDb(output_path, out_params, file_name_prefix):
    try:
        sqlite_path = os.path.join(output_path, file_name_prefix + "_spotlight.db")
        log.info("Creating sqlite db for spotlight output @ {}".format(sqlite_path))
        out_params.output_db_path = SqliteWriter.CreateSqliteDb(sqlite_path)
        out_params.write_sql = True
        return True
    except (sqlite3.Error, OSError) as ex:
        log.info('Sqlite db could not be created at : ' + sqlite_path)
        log.exception('Exception occurred when trying to create Sqlite db')
    return False

def ProcessStoreDb(input_file_path, input_file, output_path, output_params, items_to_compare, file_name_prefix, limit_output_types=True, no_path_file=False):
    '''Main spotlight store.db processing function
       file_name_prefix is used to name the excel sheet or sqlite table, as well as prefix for name of paths_file.
       limit_output_types=True will only write to SQLITE, else all output options are honored. This is for faster 
       processing, as writing to excel is very slow. We will still try to honor user preference if the db is small.
       items_to_compare is a dictionary used to compare and only write new items not present already
    '''
    items = {}
    global writer
    
    output_path_full_paths = os.path.join(output_path, file_name_prefix + '_fullpaths.csv')
    output_path_data = os.path.join(output_path, file_name_prefix + '_data.txt')

    log.info('Processing ' + input_file_path)
    try:
        if not os.path.exists(output_path):
            log.info("Creating output folder for spotlight at {}".format(output_path))
            os.makedirs(output_path)
        
        with open(output_path_data, 'wb') as output_file:
            output_paths_file = None
            store = spotlight_parser.SpotlightStore(input_file)
            store.ReadPageIndexesAndOtherDefinitions()
            ## create db, write table with fields.
            out_params = CopyOutputParams(output_params)
            if limit_output_types and (store.block0.item_count > 500): # Large db, limit to sqlite output
                log.warning('Since the spotlight database is large, only Sqlite output will be written!')
                out_params.write_xlsx = False
                out_params.write_csv = False
                if not out_params.write_sql: # sql is not enabled, must initialize database!
                    if not EnableSqliteDb(output_path, out_params, file_name_prefix): return None
            try:
                log.debug ("Trying to write extracted store data for {}".format(file_name_prefix))
                data_type_info = Get_Column_Info(store)
                writer = DataWriter(out_params, "Spotlight-" + file_name_prefix, data_type_info, input_file_path)
            except (sqlite3.Error, ValueError, IOError, OSError) as ex:
                log.exception ("Failed to initilize data writer")
                return None

            store.ParseMetadataBlocks(output_file, items, items_to_compare, ProcessStoreItems)
            writer.FinishWrites()
            
            # Write Paths db as csv
            if not no_path_file:
                path_type_info = [ ('ID',DataType.INTEGER),('FullPath',DataType.TEXT) ]
                fullpath_writer = DataWriter(out_params, "Spotlight-" + file_name_prefix + '-paths', path_type_info, input_file_path)
                with open(output_path_full_paths, 'wb') as output_paths_file:
                    log.info('Inodes and Path information being written to {}'.format(output_path_full_paths))
                    output_paths_file.write(b"Inode_Number\tFull_Path\r\n")
                    if items_to_compare: 
                        items_to_compare.update(items) # This updates items_to_compare ! 
                        WriteFullPaths(items, items_to_compare, output_paths_file, fullpath_writer)
                    else:
                        WriteFullPaths(items, items, output_paths_file, fullpath_writer)
                    if out_params.write_sql: 
                        CreateViewAndIndexes(data_type_info, fullpath_writer.sql_writer, file_name_prefix)
                fullpath_writer.FinishWrites()                
            return items
    except Exception as ex:
        log.exception('Exception processing spotlight store db file')

def CreateViewAndIndexes(data_type_info, sql_writer, file_name_prefix):
    desired = ['kMDItemContentTypeTree', 'kMDItemContentType', 'kMDItemKind', 'kMDItemMediaTypes', 
                '_kMDItemOwnerUserID', '_kMDItemOwnerGroupID', 'kMDItemUserCreatedUserHandle', 'kMDItemUserModifiedUserHandle', 
                'kMDItemUserPrintedUserHandle', '_kMDItemFileName', 'kMDItemDisplayName', 'kMDItemAlternateNames', 
                'kMDItemTitle', 'kMDItemPhysicalSize', 'kMDItemLogicalSize', 'kMDItemDurationSeconds', 'kMDItemPixelHeight', 
                'kMDItemPixelWidth', 'kMDItemColorSpace', 'kMDItemWhereFroms', 'kMDItemURL', 'kMDItemSubject', 
                'kMDItemRecipientEmailAddresses', 'kMDItemPrimaryRecipientEmailAddresses', 'kMDItemAdditionalRecipientEmailAddresses', 
                'kMDItemHiddenAdditionalRecipientEmailAddresses', 'kMDItemCountry', 'kMDItemCity', 'kMDItemStateOrProvince', 
                'kMDItemPhoneNumbers', 'kMDItemAuthors', 'kMDItemComment', 'kMDItemAlbum', 'kMDItemComposer', 
                'kMDItemMusicalGenre', 'kMDItemRecordingYearkMDItemAcquisitionModel', 'kMDItemExposureProgram', 
                'kMDItemLatitude', 'kMDItemLongitude', 'kMDItemTimestamp', 'kMDItemGPSDateStamp', '_kMDItemContentChangeDate', 
                '_kMDItemCreationDate', 'kMDItemContentCreationDate', 'kMDItemContentModificationDate', 'kMDItemDateAdded', 
                'kMDItemUsedDates', 'kMDItemLastUsedDate', 'kMDItemUseCount', 'kMDItemUserCreatedDate', 'kMDItemUserModifiedDate', 
                'kMDItemUserPrintedDate', 'kMDItemDownloadedDate', 'kMDItemCFBundleIdentifier', 'kMDItemCreator'
                ]
    columns = []
    for prop in desired:
        for item in data_type_info:
            if item[0] == prop:
                columns.append(prop)
                break
            
    query = "CREATE VIEW 'SpotlightDataView-{}' AS SELECT s.ID, Flags, Date_Updated, p.FullPath, ".format(file_name_prefix) +\
            ", ".join(columns) + " FROM 'Spotlight-{}' as s".format(file_name_prefix) +\
            " LEFT JOIN 'Spotlight-{}-paths' as p ON s.ID=p.ID WHERE s.ID > 1".format(file_name_prefix)

    success, cursor, error_message = sql_writer.RunQuery(query)
    if success:
        log.info("VIEW 'SpotlightDataView-{}' created for spotlight data in database".format(file_name_prefix) )
    else:
        log.error("Failed to create VIEW 'SpotlightDataView-{}'".format(file_name_prefix))
        log.error("Error was : {}".format(error_message))
    # # creating indexes, commented out for now
    # log.debug("Trying to add indexes")
    # query = "CREATE INDEX '{0}_idx_all' ON 'Spotlight-{0}' ({1})".format(file_name_prefix, ", ".join(columns))
    # success, cursor, error_message = sql_writer.RunQuery(query)
    # if success:
    #     log.info("Indexes created for 'Spotlight-{}'".format(file_name_prefix))
    # else:
    #     log.error("Failed to create Indexes 'Spotlight-{}'".format(file_name_prefix))
    #     log.error("Error was : {}".format(error_message))

    # query = "CREATE INDEX '{0}_idx_paths' ON 'Spotlight-{0}-paths' (ID, FullPath)".format(file_name_prefix, ", ".join(columns))
    # success, cursor, error_message = sql_writer.RunQuery(query)
    # if success:
    #     log.info("Indexes created for 'Spotlight-{}'".format(file_name_prefix))
    # else:
    #     log.error("Failed to create Indexes 'Spotlight-{}'".format(file_name_prefix))
    #     log.error("Error was : {}".format(error_message))

def WriteFullPaths(items, all_items, output_paths_file, fullpath_writer):
    '''
        Writes inode and full paths table to csv
        items = dictionary of items to write
        all_items = dictionary of items to recursively search full paths
    '''
    path_list = []
    for k,v in list(items.items()):
        name = v[2]
        if name:
            fullpath = spotlight_parser.RecursiveGetFullPath(v, all_items)
            to_write = str(k) + '\t' + fullpath + '\r\n'
            output_paths_file.write(to_write.encode('utf-8', 'backslashreplace'))
            path_list.append([k, fullpath])
    fullpath_writer.WriteRows(path_list)

def DropReadme(output_folder, message, filename='Readme.txt'):
    try:
        if not os.path.exists(output_folder):
            log.info("Creating output folder for {} at {}".format(filename, output_folder))
            os.makedirs(output_folder)
        output_file_path = os.path.join(output_folder, filename)
        with open(output_file_path, 'wb') as output_file:
            output_file.write(message.encode('utf-8') + b'\r\n')
    except OSError as ex:
        log.exception('Exception writing file - {}'.format(filename))

def ReadVolumeConfigPlistFromImage(mac_info, file_path):
    success, plist, error = mac_info.ReadPlist(file_path)
    if success:
        ReadVolumeConfigPlist(plist, mac_info.output_params, file_path)
    else:
        log.error('Failed to read plist {} \r\nError was: {}'.format(file_path, error))

def ReadVolumeConfigPlist(plist, output_params, file_path):
    '''Reads VolumeConfiguration.plist and gets store configurations'''
    log.info("Trying to get spotlight configuration from {}".format(file_path))
    config_info = [('StoreUUID',DataType.TEXT),('StoreCreationDate',DataType.DATE),
                    ('Version',DataType.TEXT),('IndexVersion',DataType.INTEGER),
                    ('PartialPath',DataType.TEXT),('ConfigurationModificationDate',DataType.DATE),
                    ('ConfigurationModificationVersion',DataType.TEXT),('ConfigurationVolumeUUID',DataType.TEXT),
                    ('Source',DataType.TEXT)
                    ]
    configs_list = []
    stores = plist.get('Stores', None)
    if stores:
        log.info (str(len(stores)) + " store(s) found")
        for k, v in list(stores.items()):
            store_uuid = k
            config = [ store_uuid, v.get('CreationDate', None),
                        v.get('CreationVersion', ''), v.get('IndexVersion', 0),
                        v.get('PartialPath', ''), plist.get('ConfigurationModificationDate', None),
                        plist.get('ConfigurationModificationVersion', ''), plist.get('ConfigurationVolumeUUID', ''),
                        file_path
                    ]
            configs_list.append(config)
        WriteList("spotlight store configuration", "SpotlightConfig", configs_list, config_info, output_params, file_path)
    else:
        log.info ("No spotlight stores defined in plist!")

def Process_User_DBs(mac_info):
    '''
    Process the databases located in /Users/<USER>/Library/Metadata/CoreSpotlight/index.spotlightV3/
    Seen in High Sierra (10.13) and above
    '''
    user_spotlight_store = '{}/Library/Metadata/CoreSpotlight/index.spotlightV3/store.db'
    user_spotlight_dot_store = '{}/Library/Metadata/CoreSpotlight/index.spotlightV3/.store.db'
    processed_paths = []
    for user in mac_info.users:
        user_name = user.user_name
        if user.home_dir == '/private/var/empty': continue # Optimization, nothing should be here!
        elif user.home_dir == '/private/var/root': user_name = 'root' # Some other users use the same root folder, we will list such all users as 'root', as there is no way to tell
        if user.home_dir in processed_paths: continue # Avoid processing same folder twice (some users have same folder! (Eg: root & daemon))
        processed_paths.append(user.home_dir)
        store_path_1 = user_spotlight_store.format(user.home_dir)
        store_path_2 = user_spotlight_dot_store.format(user.home_dir)
        items_1 = None
        items_2 = None
        if mac_info.IsValidFilePath(store_path_1):
            mac_info.ExportFile(store_path_1, __Plugin_Name, user_name + '_', False)
            log.info('Now processing file {} '.format(store_path_1))
            # Process store.db here
            input_file = mac_info.OpenSmallFile(store_path_1)
            output_folder = os.path.join(mac_info.output_params.output_path, 'SPOTLIGHT_DATA', user_name)
            if input_file != None:
                table_name = user_name + '-store'
                log.info("Spotlight data for user='{}' db='{}' will be saved with table/sheet name as {}".format(user_name, 'store.db', table_name))
                items_1 = ProcessStoreDb(store_path_1, input_file, output_folder, mac_info.output_params, None, table_name, True, True)
        
        if mac_info.IsValidFilePath(store_path_2):
            mac_info.ExportFile(store_path_2,  __Plugin_Name, user_name + '_', False)
            log.info('Now processing file {}'.format(store_path_2))
            # Process .store.db here
            input_file = mac_info.OpenSmallFile(store_path_2)
            output_folder = os.path.join(mac_info.output_params.output_path, 'SPOTLIGHT_DATA', user_name)
            if input_file != None:
                if items_1: 
                    log.info('Only newer items not found in store.db will be written out!')
                    DropReadme(output_folder, 'Items already present in store.db were ignored when processing the'\
                                            '.store.db file. Only new or updated items are shown in the .store-DIFF* '\
                                            'files. If you want the complete output, process the exported .store.db '\
                                            'file with mac_apt_single_plugin.py and this plugin')
                table_name = user_name + '-.store-DIFF'
                log.info("Spotlight store for user='{}' db='{}' will be saved with table/sheet name as {}".format(user_name, '.store.db', table_name))
                items_2 = ProcessStoreDb(store_path_2, input_file, output_folder, mac_info.output_params, items_1, table_name, True, True)


def Plugin_Start(mac_info):
    '''Main Entry point function for plugin'''

    Process_User_DBs(mac_info) # Usually small , 10.13+ only

    spotlight_folder = '/.Spotlight-V100/Store-V2/'
    vol_config_plist_path = '/.Spotlight-V100/VolumeConfiguration.plist'
    if mac_info.IsValidFilePath(vol_config_plist_path):
        mac_info.ExportFile(vol_config_plist_path, __Plugin_Name, '', False)
        ReadVolumeConfigPlistFromImage(mac_info, vol_config_plist_path)
    folders = mac_info.ListItemsInFolder(spotlight_folder, EntryType.FOLDERS)
    index = 0
    for folder in folders:
        index += 1
        uuid = folder['name']
        store_path_1 = spotlight_folder + uuid + '/store.db'
        store_path_2 = spotlight_folder + uuid + '/.store.db'
        items_1 = None
        items_2 = None
        if mac_info.IsValidFilePath(store_path_1):
            sub_folder = os.path.join(__Plugin_Name, str(index) + "_" + uuid)
            mac_info.ExportFile(store_path_1, sub_folder, '', False)
            log.info('Now processing file {} '.format(store_path_1))
            # Process store.db here
            input_file = mac_info.OpenSmallFile(store_path_1)
            output_folder = os.path.join(mac_info.output_params.output_path, 'SPOTLIGHT_DATA', uuid)
            if input_file != None:
                table_name = str(index) + '-store'
                log.info("Spotlight data for uuid='{}' db='{}' will be saved with table/sheet name as {}".format(uuid, 'store.db', table_name))
                items_1 = ProcessStoreDb(store_path_1, input_file, output_folder, mac_info.output_params, None, table_name, True, False)
        else:
            log.debug('File not found: {}'.format(store_path_1))

        if mac_info.IsValidFilePath(store_path_2):
            mac_info.ExportFile(store_path_2, sub_folder, '', False)
            log.info('Now processing file {}'.format(store_path_2))
            # Process .store.db here
            input_file = mac_info.OpenSmallFile(store_path_2)
            output_folder = os.path.join(mac_info.output_params.output_path, 'SPOTLIGHT_DATA', uuid)
            if input_file != None:
                if items_1: 
                    log.info('Only newer items not found in store.db will be written out!')
                    DropReadme(output_folder, 'Items already present in store.db were ignored when processing the'\
                                            '.store.db file. Only new or updated items are shown in the .store-DIFF* '\
                                            'files. If you want the complete output, process the exported .store.db '\
                                            'file with mac_apt_single_plugin.py and this plugin')
                table_name = str(index) + '-.store-DIFF'
                log.info("Spotlight store for uuid='{}' db='{}' will be saved with table/sheet name as {}".format(uuid, '.store.db', table_name))
                items_2 = ProcessStoreDb(store_path_2, input_file, output_folder, mac_info.output_params, items_1, table_name, True, False)
        else:
            log.debug('File not found: {}'.format(store_path_2))

def Plugin_Start_Standalone(input_files_list, output_params):
    log.info("Module Started as standalone")
    for input_path in input_files_list:
        log.debug("Input file passed was: " + input_path)
        if os.path.basename(input_path).lower().endswith('store.db'):
            try:
                with open(input_path, 'rb') as input_file:
                    output_folder = os.path.join(output_params.output_path, 'SPOTLIGHT_DATA')
                    log.info('Now processing file {}'.format(input_path))
                    ProcessStoreDb(input_path, input_file, output_folder, output_params, None, os.path.basename(input_path), False, False)
            except (OSError, IOError):
                log.exception('Failed to open input file ' + input_path)
        else:
            log.info("Unknown file type: {}".format(os.path.basename()))

if __name__ == '__main__':
    print ("This plugin is a part of a framework and does not run independently on its own!")