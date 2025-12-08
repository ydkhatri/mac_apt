'''
   Copyright (c) 2017 Yogesh Khatri 

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the 
   terms of the MIT License.
   
'''

import logging
import os

from plugins.helpers import spotlight_parser as spotlight_parser
from plugins.helpers.macinfo import *
from plugins.helpers.spotlight_filter import create_views_for_ios_db
from plugins.helpers.writer import *

__Plugin_Name = "SPOTLIGHT"
__Plugin_Friendly_Name = "Spotlight"
__Plugin_Version = "1.2"
__Plugin_Description = "Reads spotlight indexes (user, volume, iOS)"
__Plugin_Author = "Yogesh Khatri"
__Plugin_Author_Email = "yogesh@swiftforensics.com"

__Plugin_Modes = "IOS,MACOS,ARTIFACTONLY"
__Plugin_ArtifactOnly_Usage = "This module reads spotlight's index database file found at: /.Spotlight-V100/Store-V2/<UUID>/store.db and "\
                                "also '.store.db' at the same location. Since macOS 10.13, there are also spotlight databases for each "\
                                "user under ~/Library/Metadata/CoreSpotlight/index.spotlightV3/ \niOS spotlight databases are also "\
                                "parsed. These would be found here: /private/var/mobile/Library/Spotlight/CoreSpotlight/*/index.spotlightV2"

log = logging.getLogger('MAIN.' + __Plugin_Name) # Do not rename or remove this ! This is the logger object

#---- Do not change the variable names in above section ----#

writer = None
mac_info_obj = None
spotlight_parser.log = logging.getLogger('MAIN.' + __Plugin_Name + '.SPOTLIGHT_PARSER')

def bswap64(x: int) -> int:
    '''Converts little-endian to big-endian and vice-versa for 64-bit integer'''
    x = ((x & 0xFF00000000000000) >> 56) | \
        ((x & 0x00FF000000000000) >> 40) | \
        ((x & 0x0000FF0000000000) >> 24) | \
        ((x & 0x000000FF00000000) >> 8)  | \
        ((x & 0x00000000FF000000) << 8)  | \
        ((x & 0x0000000000FF0000) << 24) | \
        ((x & 0x000000000000FF00) << 40) | \
        ((x & 0x00000000000000FF) << 56)
    return x
    
def ProcessStoreItem(item, id_as_hex, flip_id_endianness):
    '''Reads a single store item and processes it for output. Returns dictionary'''
    try:
        data_dict = {}
        id = item.id
        parent_id = item.parent_id
        if flip_id_endianness and id != 1:
            id = bswap64(id)
            parent_id = bswap64(parent_id)
        if id_as_hex:
            id_hex_str = f'{(id & (2**64-1)):X}'
            if len(id_hex_str) % 2:
                id_hex_str = '0' + id_hex_str
            parent_id_hex_str = f'{(parent_id & (2**64-1)):X}'
            if len(parent_id_hex_str) % 2:
                parent_id_hex_str = '0' + parent_id_hex_str
            data_dict['ID_hex'] = id_hex_str
            data_dict['Parent_ID_hex'] = parent_id_hex_str
        data_dict['ID'] = str(id)
        data_dict['Parent_ID'] = str(parent_id)
        data_dict['Item_ID'] = str(item.item_id)
        data_dict['Flags'] = item.flags
        data_dict['Date_Updated'] = item.ConvertEpochToUtcDateStr(item.date_updated)
        for k, v in list(item.meta_data_dict.items()):
            orig_debug = v
            if type(v) == list:
                if len(v) == 1:
                    v = v[0]
                    if type(v) == str:
                        if v.endswith('\x16\x02'):
                            v = v[:-2]
                else:
                    v = ', '.join([str(x) for x in v])
            data_dict[k] = v

        return data_dict
    except (OSError, KeyError, ValueError) as ex:
        log.exception ("Failed while processing row data before writing")

def ProcessStoreItems(store_items, store):
    global writer
    try:
        data_list = []
        for item in store_items:
            data = ProcessStoreItem(item, store.is_ios_store, 
                                    store.flip_id_endianness if hasattr(store, 'flip_id_endianness') else False)
            if data:
                data_list.append(data)
        writer.WriteRows(data_list)
    except (OSError, KeyError, ValueError) as ex:
        log.exception ("Failed to write row data")

def Get_Column_Info(store):
    '''Returns a list of columns with data types for use with writer''' 
    if store.is_ios_store:
        data_info = [ ('ID',DataType.TEXT),('ID_hex',DataType.TEXT),('Flags',DataType.INTEGER),
                      ('Parent_ID',DataType.TEXT),
                      ('Parent_ID_hex',DataType.TEXT),('Date_Updated',DataType.TEXT) ]
    else:
        if store.version == 1:
            data_info = [ ('ID',DataType.TEXT),('Flags',DataType.INTEGER),
                      ('Item_ID',DataType.TEXT),('Date_Updated',DataType.TEXT) ]
        else:
            data_info = [ ('ID',DataType.TEXT),('Flags',DataType.INTEGER),
                        ('Parent_ID',DataType.TEXT),('Date_Updated',DataType.TEXT) ]
    if store.version == 1:
        for _, prop in list(store.properties.items()):
            # prop = [name, prop_type, value_type]
            if prop[0] in ('_kMDXXXX___DUMMY', 'kMDStoreAccumulatedSizes') : continue # skip this
            if prop[1] != 0: continue # skip as these are not columns
            val_type = DataType.TEXT

            data_info.append((prop[0], val_type))
    else:
        for _, prop in list(store.properties.items()):
            # prop = [name, prop_type, value_type]
            if prop[0] in ('_kMDXXXX___DUMMY', 'kMDStoreAccumulatedSizes') : continue # skip this
            if prop[2] in [0, 2, 6, 7]:
                if prop[1] & 2 == 2: # Multiple items
                    val_type = DataType.TEXT
                else:
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
    op_copy.write_tsv = output_params.write_tsv
    op_copy.write_sql = output_params.write_sql
    op_copy.write_xlsx = output_params.write_xlsx
    op_copy.xlsx_writer = output_params.xlsx_writer
    op_copy.output_db_path = output_params.output_db_path
    op_copy.export_path = output_params.export_path
    op_copy.export_log_sqlite = output_params.export_log_sqlite
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

def GetFileData(path, export_subfolder):
    '''Get entire file data - ios Only'''
    global mac_info_obj

    data = b''
    if mac_info_obj != None:
        mac_info_obj.ExportFile(path, export_subfolder, '', False)
        f = mac_info_obj.Open(path)
        if f:
            data = f.read()
        else:
            log.error("Failed to open file {}".format(path))
    else: # For single artifact mode
        with open(path, 'rb') as f:
            data = f.read()
    return data

def GetMapDataOffsetHeader(input_folder, id, export_subfolder):
    ''' Given an id X, this returns the data from 3 files, 
        dbStr-X.map.data, dbStr-X.map.header, dbStr-X.map.offsets. It will
        search for these files in the input_folder.
        Returns tuple (data, offsets, header)
    '''
    if mac_info_obj == None: # single artifact mode
        data_path = os.path.join(input_folder, 'dbStr-{}.map.data'.format(id))
        offsets_path = os.path.join(input_folder, 'dbStr-{}.map.offsets'.format(id))
        header_path = os.path.join(input_folder, 'dbStr-{}.map.header'.format(id))
    else:
        data_path = input_folder + '/dbStr-{}.map.data'.format(id)
        offsets_path = input_folder + '/dbStr-{}.map.offsets'.format(id)
        header_path =  input_folder + '/dbStr-{}.map.header'.format(id)
    map_data = GetFileData(data_path, export_subfolder)
    offsets_data = GetFileData(offsets_path, export_subfolder)
    header_data = GetFileData(header_path, export_subfolder)

    return (map_data, offsets_data, header_data)

def ProcessStoreDb(input_file_path, input_file, output_path, output_params, items_to_compare, file_name_prefix, limit_output_types=True, no_path_file=False, export_subfolder="", is_boot_volume=False):
    '''Main spotlight store.db processing function
       file_name_prefix is used to name the excel sheet or sqlite table, as well as prefix for name of paths_file.
       limit_output_types=True will only write to SQLITE, else all output options are honored. This is for faster 
       processing, as writing to excel is very slow. We will still try to honor user preference if the db is small.
       items_to_compare is a dictionary used to compare and only write new items not present already
    '''
    items = {}
    global writer
    
    output_path_full_paths = os.path.join(output_path, file_name_prefix + '_fullpaths.tsv')
    output_path_data = os.path.join(output_path, file_name_prefix + '_data.txt')

    log.info('Processing ' + input_file_path)
    try:
        if not os.path.exists(output_path):
            log.info("Creating output folder for spotlight at {}".format(output_path))
            os.makedirs(output_path)
        
        with open(output_path_data, 'wb') as output_file:
            output_paths_file = None
            store = spotlight_parser.SpotlightStore(input_file)
            if store.is_ios_store: # The properties, categories and indexes must be stored in external files
                input_folder = os.path.dirname(input_file_path)
                try:
                    prop_map_data, prop_map_offsets,prop_map_header = GetMapDataOffsetHeader(input_folder, 1, export_subfolder)
                    cat_map_data, cat_map_offsets, cat_map_header = GetMapDataOffsetHeader(input_folder, 2, export_subfolder)
                    idx_1_map_data, idx_1_map_offsets, idx_1_map_header = GetMapDataOffsetHeader(input_folder, 4, export_subfolder)
                    idx_2_map_data, idx_2_map_offsets, idx_2_map_header = GetMapDataOffsetHeader(input_folder, 5, export_subfolder)

                    store.ParsePropertiesFromFileData(prop_map_data, prop_map_offsets, prop_map_header)
                    store.ParseCategoriesFromFileData(cat_map_data, cat_map_offsets, cat_map_header)
                    log.debug('Trying to ParseIndexesFromFileData(1)')
                    store.ParseIndexesFromFileData(idx_1_map_data, idx_1_map_offsets, idx_1_map_header, store.indexes_1)
                    log.debug('Trying to ParseIndexesFromFileData(2)')
                    store.ParseIndexesFromFileData(idx_2_map_data, idx_2_map_offsets, idx_2_map_header, store.indexes_2, has_extra_byte=True)

                    store.ReadPageIndexesAndOtherDefinitions(True)
                except (OSError, ValueError, KeyError):
                    log.exception('Failed to find or process one or more dependency files. Cannot proceed!')
                    return None
            ##
            else:
                store.ReadPageIndexesAndOtherDefinitions()
            ## create db, write table with fields.
            out_params = CopyOutputParams(output_params)
            if limit_output_types and (store.block0.item_count > 500): # Large db, limit to sqlite output
                log.warning('Since the spotlight database is large, only Sqlite output will be written!')
                out_params.write_xlsx = False
                out_params.write_csv = False
                out_params.write_tsv = False
                if not out_params.write_sql: # sql is not enabled, must initialize database!
                    if not EnableSqliteDb(output_path, out_params, file_name_prefix): return None
            try:
                log.debug ("Trying to write extracted store data for {}".format(file_name_prefix))
                data_type_info = Get_Column_Info(store)
                writer = DataWriter(out_params, "Spotlight-" + file_name_prefix, data_type_info, input_file_path)
            except (sqlite3.Error, ValueError, OSError) as ex:
                log.exception ("Failed to initilize data writer")
                return None

            # set flip_id_endianness in store object for use later
            store.flip_id_endianness = is_boot_volume
            total_items_parsed = store.ParseMetadataBlocks(output_file, items, items_to_compare, 
                                                           process_items_func=ProcessStoreItems)
            writer.FinishWrites()

            if total_items_parsed == 0:
                log.debug('Nothing was parsed from this file!')
            # create Views in ios/user style db
            if store.is_ios_store and (total_items_parsed > 0):
                create_views_for_ios_db(writer.sql_writer.filepath, writer.sql_writer.table_name)
            
            # Write Paths db as tsv
            if (not store.version==1) and (not no_path_file):
                path_type_info = [ ('ID',DataType.TEXT),('FullPath',DataType.TEXT) ]
                fullpath_writer = DataWriter(out_params, "Spotlight-" + file_name_prefix + '-paths', path_type_info, input_file_path)
                with open(output_path_full_paths, 'wb') as output_paths_file:
                    log.info('Inodes and Path information being written to {}'.format(output_path_full_paths))
                    output_paths_file.write(b"Inode_Number\tFull_Path\r\n")
                    if items_to_compare: 
                        items_to_compare.update(items) # This updates items_to_compare ! 
                        WriteFullPaths(items, items_to_compare, output_paths_file, fullpath_writer)
                    else:
                        WriteFullPaths(items, items, output_paths_file, fullpath_writer)
                    if out_params.write_sql and (total_items_parsed > 0): 
                        CreateViewAndIndexes(data_type_info, fullpath_writer.sql_writer, file_name_prefix)
                fullpath_writer.FinishWrites()                
            return items
    except spotlight_parser.InvalidFileException as ex:
        # If this is for NSFileProtectionCompleteUnlessOpen/index.spotlightV3/.store.db or 
        # NSFileProtectionComplete/index.spotlightV3/.store.db, then these are expected to be encrypted.
        if input_file_path.find('NSFileProtectionComplete') >= 0 and input_file_path.find('NSFileProtectionCompleteUntilFirstUserAuthentication') == -1:
            log.warning(f'File signature not matching, this file is expected to be encrypted, so skipping it!')
        else:
            log.error(str(ex))
    except (KeyError, ValueError, OSError) as ex:
        log.exception(f'Exception processing spotlight store db file -> {str(ex)}')

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

def WriteFullPaths(items, all_items, output_paths_file, fullpath_writer, is_boot_volume=False):
    '''
        Writes inode and full paths table to csv
        items = dictionary of items to write
        all_items = dictionary of items to recursively search full paths
    '''
    path_list = []
    for k,v in list(items.items()):
        name = v[2]
        if name:
            fullpath = spotlight_parser.RecursiveGetFullPath(v, all_items, suppress_error_messages=(True if is_boot_volume else False))
            to_write = str(k) + '\t' + fullpath + '\r\n'
            output_paths_file.write(to_write.encode('utf-8', 'backslashreplace'))
            path_list.append([k, fullpath])
    if is_boot_volume:
        path_list = [[str(bswap64(x[0])), x[1]] for x in path_list if x[0] != 1] # convert inode numbers to strings and swap endianness if bootvolume, skip plist
    else:
        path_list = [[str(x[0]), x[1]] for x in path_list if x[0] != 1] # convert inode numbers to strings, skip plist
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

def ReadVolumeConfigPlistFromImage(mac_info, configs_list, file_path):
    success, plist, error = mac_info.ReadPlist(file_path)
    if success:
        ReadVolumeConfigPlist(plist, file_path, configs_list)
    else:
        log.error('Failed to read plist {} \r\nError was: {}'.format(file_path, error))

def ReadVolumeConfigPlist(plist, file_path, configs_list):
    '''Reads VolumeConfiguration.plist and gets store configurations'''
    log.info("Trying to get spotlight configuration from {}".format(file_path))

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
    else:
        log.info ("No spotlight stores defined in plist!")

def PrintConfigs(configs_list, output_params):
    config_info = [('StoreUUID',DataType.TEXT),('StoreCreationDate',DataType.DATE),
                ('Version',DataType.TEXT),('IndexVersion',DataType.INTEGER),
                ('PartialPath',DataType.TEXT),('ConfigurationModificationDate',DataType.DATE),
                ('ConfigurationModificationVersion',DataType.TEXT),('ConfigurationVolumeUUID',DataType.TEXT),
                ('Source',DataType.TEXT)
                ]
    if configs_list:
        WriteList("spotlight store configuration", "SpotlightConfig", configs_list, config_info, output_params)

def ProcessStoreAndDotStore(mac_info, store_path_1, store_path_2, prefix, export_subfolder):
    items_1 = None
    items_2 = None
    if mac_info.IsValidFilePath(store_path_1):
        mac_info.ExportFile(store_path_1, export_subfolder, '', False)
        log.info('Now processing file {} '.format(store_path_1))
        # Process store.db here
        input_file = mac_info.Open(store_path_1)
        output_folder = os.path.join(mac_info.output_params.output_path, 'SPOTLIGHT_DATA', prefix)
        if input_file != None:
            table_name = prefix + '-store'
            log.info("Spotlight data for user='{}' db='{}' will be saved with table/sheet name as {}".format(prefix, 'store.db', table_name))
            items_1 = ProcessStoreDb(store_path_1, input_file, output_folder, mac_info.output_params, None, table_name, True, True, export_subfolder)
    
    if mac_info.IsValidFilePath(store_path_2):
        mac_info.ExportFile(store_path_2,  export_subfolder, '', False)
        log.info('Now processing file {}'.format(store_path_2))
        # Process .store.db here
        input_file = mac_info.Open(store_path_2)
        output_folder = os.path.join(mac_info.output_params.output_path, 'SPOTLIGHT_DATA', prefix)
        if input_file != None:
            if items_1: 
                log.info('Only newer items not found in store.db will be written out!')
                DropReadme(output_folder, 'Items already present in store.db were ignored when processing the'\
                                        '.store.db file. Only new or updated items are shown in the .store-DIFF* '\
                                        'files. If you want the complete output, process the exported .store.db '\
                                        'file with mac_apt_single_plugin.py and this plugin')
            table_name = prefix + '-.store-DIFF'
            log.info("Spotlight store for user='{}' db='{}' will be saved with table/sheet name as {}".format(prefix, '.store.db', table_name))
            items_2 = ProcessStoreDb(store_path_2, input_file, output_folder, mac_info.output_params, items_1, table_name, True, True, export_subfolder)

def Process_User_DBs(mac_info):
    '''
    Process the databases located in user's home directory.
    macOS 10.13 - macOS 11: /Users/<USER>/Library/Metadata/CoreSpotlight/index.spotlightV3/
    macOS 12 and above    : /Users/<USER>/Library/Metadata/CoreSpotlight/NSFileProtectionComplete/index.spotlightV3/
                            /Users/<USER>/Library/Metadata/CoreSpotlight/NSFileProtectionCompleteUnlessOpen/index.spotlightV3/
                            /Users/<USER>/Library/Metadata/CoreSpotlight/NSFileProtectionCompleteUntilFirstUserAuthentication/index.spotlightV3/
                            /Users/<USER>/Library/Caches/com.apple.helpd/NSFileProtectionComplete/index.spotlightV3/
                            /Users/<USER>/Library/Caches/com.apple.helpd/NSFileProtectionCompleteUnlessOpen/index.spotlightV3/
                            /Users/<USER>/Library/Caches/com.apple.helpd/NSFileProtectionCompleteUntilFirstUserAuthentication/index.spotlightV3/
    '''
    user_spotlight_metadata_paths = ['{}/Library/Metadata/CoreSpotlight/index.spotlightV3/',
                                     '{}/Library/Metadata/CoreSpotlight/NSFileProtectionComplete/index.spotlightV3/',
                                     '{}/Library/Metadata/CoreSpotlight/NSFileProtectionCompleteUnlessOpen/index.spotlightV3/',
                                     '{}/Library/Metadata/CoreSpotlight/NSFileProtectionCompleteUntilFirstUserAuthentication/index.spotlightV3/']
    user_spotlight_cache_paths = ['{}/Library/Caches/com.apple.helpd/NSFileProtectionComplete/index.spotlightV3/',
                                  '{}/Library/Caches/com.apple.helpd/NSFileProtectionCompleteUnlessOpen/index.spotlightV3/',
                                  '{}/Library/Caches/com.apple.helpd/NSFileProtectionCompleteUntilFirstUserAuthentication/index.spotlightV3/']
    for spotlight_path in user_spotlight_metadata_paths + user_spotlight_cache_paths:
        processed_paths = []
        for user in mac_info.users:
            user_name = user.user_name
            if user.home_dir == '/private/var/empty': continue # Optimization, nothing should be here!
            elif user.home_dir == '/private/var/root': user_name = 'root' # Some other users use the same root folder, we will list such all users as 'root', as there is no way to tell
            if user.home_dir in processed_paths: continue # Avoid processing same folder twice (some users have same folder! (Eg: root & daemon))
            processed_paths.append(user.home_dir)
            store_path_1 = os.path.join(spotlight_path.format(user.home_dir), 'store.db')
            store_path_2 = os.path.join(spotlight_path.format(user.home_dir), '.store.db')
            path_split = store_path_1.split('/')
            export_subfolder = os.path.join(__Plugin_Name, user_name, path_split[-4], path_split[-3])
            prefix = path_split[-4] + '_' + user_name
            ProcessStoreAndDotStore(mac_info, store_path_1, store_path_2, prefix, export_subfolder)

def ProcessVolumeStore(mac_info, spotlight_base_path, configs_list, export_prefix='', is_boot_volume=False):
    '''
    Process the main Spotlight-V100 database usually found on the volume's root.
    '''

    if mac_info.IsValidFolderPath(spotlight_base_path + '/Store-V2/'):
        spotlight_folder = spotlight_base_path + '/Store-V2/'
    elif mac_info.IsValidFolderPath(spotlight_base_path + '/Store-V1/'):
        spotlight_folder = spotlight_base_path + '/Store-V1/Stores/'
    else:
        log.error(f'Neither Store-V1 or Store-V2 folders were found in {spotlight_folder}. Cannot proceed.')
        return
    vol_config_plist_path = spotlight_base_path + '/VolumeConfiguration.plist'
    if mac_info.IsValidFilePath(vol_config_plist_path):
        mac_info.ExportFile(vol_config_plist_path, __Plugin_Name, export_prefix, False)
        ReadVolumeConfigPlistFromImage(mac_info, configs_list, vol_config_plist_path)
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
            input_file = mac_info.Open(store_path_1)
            output_folder = os.path.join(mac_info.output_params.output_path, 'SPOTLIGHT_DATA', uuid)
            if input_file != None:
                table_name = ((export_prefix + '_') if export_prefix else '') + str(index) + '-store'
                log.info("Spotlight data for uuid='{}' db='{}' will be saved with table/sheet name as {}".format(uuid, 'store.db', table_name))
                items_1 = ProcessStoreDb(store_path_1, input_file, output_folder, mac_info.output_params, None, table_name, True, False, sub_folder, is_boot_volume=is_boot_volume)
        else:
            log.debug('File not found: {}'.format(store_path_1))

        if mac_info.IsValidFilePath(store_path_2):
            mac_info.ExportFile(store_path_2, sub_folder, '', False)
            log.info('Now processing file {}'.format(store_path_2))
            # Process .store.db here
            input_file = mac_info.Open(store_path_2)
            output_folder = os.path.join(mac_info.output_params.output_path, 'SPOTLIGHT_DATA', uuid)
            if input_file != None:
                if items_1: 
                    log.info('Only newer items not found in store.db will be written out!')
                    DropReadme(output_folder, 'Items already present in store.db were ignored when processing the'\
                                            '.store.db file. Only new or updated items are shown in the .store-DIFF* '\
                                            'files. If you want the complete output, process the exported .store.db '\
                                            'file with mac_apt_single_plugin.py and this plugin')
                table_name = ((export_prefix + '_') if export_prefix else '') + str(index) + '-.store-DIFF'
                log.info("Spotlight store for uuid='{}' db='{}' will be saved with table/sheet name as {}".format(uuid, '.store.db', table_name))
                items_2 = ProcessStoreDb(store_path_2, input_file, output_folder, mac_info.output_params, items_1, table_name, True, False, sub_folder, is_boot_volume=is_boot_volume)
        else:
            log.debug('File not found: {}'.format(store_path_2))

def Plugin_Start(mac_info):
    '''Main Entry point function for plugin'''
    global mac_info_obj
    mac_info_obj = mac_info
    configs_list = []

    Process_User_DBs(mac_info) # Usually small , 10.13+ only
    spotlight_base_path = '/.Spotlight-V100'
    if mac_info.IsValidFolderPath(spotlight_base_path):
        ProcessVolumeStore(mac_info, spotlight_base_path, configs_list, 'DataVolume')
    else:
        # For live/zip volume, Data may need to be accessed here:
        spotlight_base_path = '/System/Volumes/Data/.Spotlight-V100'
        if mac_info.IsValidFolderPath(spotlight_base_path):
            ProcessVolumeStore(mac_info, spotlight_base_path, configs_list, 'DataVolume')

    # For catalina's read-only volume
    spotlight_base_path = '/private/var/db/Spotlight-V100/BootVolume'
    if mac_info.IsValidFolderPath(spotlight_base_path):
        ProcessVolumeStore(mac_info, spotlight_base_path, configs_list, 'BootVolume', is_boot_volume=True)
        # For some odd reason, the BootVolume store db has id and parent_id in big-endian format

    # For Ventura's Preboot volume
    spotlight_base_path = '/private/var/db/Spotlight-V100/Preboot'
    if mac_info.IsValidFolderPath(spotlight_base_path):
        ProcessVolumeStore(mac_info, spotlight_base_path, configs_list, 'Preboot')
    
    if configs_list:
        PrintConfigs(configs_list, mac_info.output_params)

def Plugin_Start_Standalone(input_files_list, output_params):
    log.info("Module Started as standalone")
    for input_path in input_files_list:
        configs_list = []
        log.debug("Input file passed was: " + input_path)
        if os.path.basename(input_path).lower().endswith('store.db'):
            try:
                with open(input_path, 'rb') as input_file:
                    output_folder = os.path.join(output_params.output_path, 'SPOTLIGHT_DATA')
                    log.info('Now processing file {}'.format(input_path))
                    ProcessStoreDb(input_path, input_file, output_folder, output_params, None, os.path.basename(input_path), False, False, '')
                    if configs_list:
                        PrintConfigs(configs_list, output_params)
            except (OSError):
                log.exception('Failed to open input file ' + input_path)
        else:
            log.info("Unknown file type: {}".format(os.path.basename(input_path)))

def Plugin_Start_Ios(ios_info):
    '''Entry point for ios_apt plugin'''
    global mac_info_obj
    mac_info_obj = ios_info
    configs_list = []
    ios_spotlight_folders = [
                            '/private/var/mobile/Library/Spotlight/CoreSpotlight/NSFileProtectionComplete/index.spotlightV2',
                            '/private/var/mobile/Library/Spotlight/CoreSpotlight/NSFileProtectionCompleteUnlessOpen/index.spotlightV2',
                            '/private/var/mobile/Library/Spotlight/CoreSpotlight/NSFileProtectionCompleteUntilFirstUserAuthentication/index.spotlightV2' 
                            ]
    for folder in ios_spotlight_folders:
        store_path_1 = os.path.join(folder, 'store.db')
        store_path_2 = os.path.join(folder, '.store.db')
        subfolder = folder.split('/')[-2]
        ProcessStoreAndDotStore(ios_info, store_path_1, store_path_2, subfolder, subfolder)
    if configs_list:
        PrintConfigs(configs_list, mac_info_obj.output_params)
if __name__ == '__main__':
    print ("This plugin is a part of a framework and does not run independently on its own!")