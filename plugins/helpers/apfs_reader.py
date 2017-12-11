'''
   Copyright (c) 2017 Yogesh Khatri 

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the 
   terms of the MIT License.

'''
from __future__ import unicode_literals
from __future__ import print_function
from kaitaistruct import __version__ as ks_version, KaitaiStream, BytesIO
import apfs
import binascii
import collections
import logging
import lzfse
import struct
import tempfile
from writer import DataType
from common import *

import zlib

log = logging.getLogger('MAIN.HELPERS.APFS_READER')

class ApfsDbInfo:
    '''
    This class writes information about db version and volumes to the database. 
    It also checks if the db information corresponds to the currently loaded
    image's volumes.
    '''

    def __init__(self, db):
        self.db = db
        self.version = 1 # This will change if db structure changes in future
        self.ver_table_name = 'Version_Info'
        self.vol_table_name = 'Volumes_Info'
        self.version_info = collections.OrderedDict([('Version',DataType.INTEGER)])
        self.volume_info = collections.OrderedDict([('Name',DataType.TEXT),('UUID',DataType.TEXT),
                                                    ('Files',DataType.INTEGER),('Folders',DataType.INTEGER),
                                                    ('Created',DataType.INTEGER),('Updated',DataType.INTEGER)])

    def WriteVersionInfo(self):
        self.db.CreateTable(self.version_info, self.ver_table_name)
        data = [self.version]
        self.db.WriteRow(data)

    def WriteVolInfo(self, volumes):
        '''Write volume info to seperate table'''
        self.db.CreateTable(self.volume_info, self.vol_table_name)
        data = []
        for vol in volumes:
            data.append([vol.volume_name, vol.uuid, vol.num_files, vol.num_folders, vol.time_created, vol.time_updated])
        self.db.WriteRows(data, self.vol_table_name)

    def CheckVerInfo(self):
        '''Returns true if info in db matches current version number'''
        query = 'SELECT Version FROM {}'.format(self.ver_table_name)
        success, cursor, error = self.db.RunQuery(query)
        index = 0
        if success:
            for row in cursor:
                db_version = row[0]
                if db_version == self.version:
                    return True
                else:
                    log.info('Db version is {} but current version is {}'.format(db_version, self.version))
                    return False
        else:
            log.error('Error querying volume info from db: ' + error)
        return False

    def CheckVolInfo(self, volumes):
        '''Returns true if info in db matches volume objects'''
        query = 'SELECT Name, UUID, Files, Folders, Created, Updated FROM {}'.format(self.vol_table_name)
        success, cursor, error = self.db.RunQuery(query)
        index = 0
        data_is_unaltered = True
        if success:
            for row in cursor:
                if row[0] != volumes[index].volume_name or \
                    row[1] != volumes[index].uuid or \
                    row[2] != volumes[index].num_files or \
                    row[3] != volumes[index].num_folders or \
                    row[4] != volumes[index].time_created or \
                    row[5] != volumes[index].time_updated :
                        data_is_unaltered = False
                        log.info('DB volume info does not match file info! Checked {}'.format(volumes[index].name))
                        break
                index += 1
        else:
            log.error('Error querying volume info from db: ' + error)

        return index == len(volumes) and data_is_unaltered

class ApfsFileSystemParser:
    '''
    Reads and parses the file system, writes output to a database.
    '''
    def __init__(self, apfs_volume, db):
        self.name = apfs_volume.name
        self.volume = apfs_volume
        self.container = apfs_volume.container
        self.db = db

        self.num_records_read_total = 0
        self.num_records_read_batch = 0

        self.hardlink_records = []
        self.extent_records = []
        self.thread_records = []
        self.named_records = []
        self.attr_records = []
        
        self.hardlink_info = collections.OrderedDict([('CNID',DataType.INTEGER), ('Parent_CNID',DataType.INTEGER), 
                                                    ('Name',DataType.TEXT)])
        self.extent_info = collections.OrderedDict([('CNID',DataType.INTEGER), ('Offset',DataType.INTEGER), 
                                                    ('Size',DataType.INTEGER), ('Block_Num',DataType.INTEGER)])
        self.attr_info = collections.OrderedDict([('CNID',DataType.INTEGER), ('Name',DataType.TEXT),('Type',DataType.INTEGER),('Data',DataType.BLOB),
                                                    ('Logical_uncompressed_size',DataType.INTEGER),('Extent_CNID',DataType.INTEGER)])
        self.thread_info = collections.OrderedDict([('CNID',DataType.INTEGER), ('Parent_CNID',DataType.INTEGER),
                                                     ('Extent_CNID',DataType.INTEGER), ('Name',DataType.TEXT), ('Created',DataType.INTEGER), ('Modified',DataType.INTEGER), ('Changed',DataType.INTEGER), ('Accessed',DataType.INTEGER), ('Flags',DataType.INTEGER), ('Links_or_Children',DataType.INTEGER), ('BSD_flags',DataType.INTEGER), ('UID',DataType.INTEGER), ('GID',DataType.INTEGER), ('Mode',DataType.INTEGER), ('Logical_Size',DataType.INTEGER), ('Physical_Size',DataType.INTEGER)])
        self.named_info = collections.OrderedDict([('CNID',DataType.INTEGER), ('Parent_CNID',DataType.INTEGER),
                                                    ('Timestamp',DataType.INTEGER),('ItemType',DataType.INTEGER), 
                                                    ('Name',DataType.TEXT)])
        self.compressed_info = collections.OrderedDict([('CNID',DataType.INTEGER),('Data',DataType.BLOB),('Uncompressed_size',DataType.INTEGER),
                                                    ('Extent_CNID',DataType.INTEGER),('fpmc_in_extent',DataType.INTEGER),('Extent_Logical_Size',DataType.INTEGER)]) 
                                                    #TODO: Remove fpmc_in_extent, this can be detected by checking Data == None
        self.paths_info = collections.OrderedDict([('CNID',DataType.INTEGER),('Path',DataType.TEXT)])
        ## Optimization for search
        self.blocks_read = set()

        self.container_type_files = self.container.apfs.ContentType.files
        self.container_type_location = self.container.apfs.ContentType.location
        self.ptr_type = apfs.Apfs.PointerRecord
        self.ext_type = self.container.apfs.EntryType.extent.value
        self.name_type = self.container.apfs.EntryType.name.value
        self.thrd_type = self.container.apfs.EntryType.thread.value
        self.hard_type = self.container.apfs.EntryType.hardlink.value
        self.attr_type = self.container.apfs.EntryType.extattr.value
        ## End optimization

    def write_records(self):
        if  self.hardlink_records: 
            self.db.WriteRows(self.hardlink_records, self.name + '_Hardlinks')
        if self.extent_records:
            self.db.WriteRows(self.extent_records, self.name + '_Extents')
        if self.thread_records:
            self.db.WriteRows(self.thread_records, self.name + '_Threads')
        if self.attr_records:
            self.db.WriteRows(self.attr_records, self.name + '_Attributes')
        if self.named_records:
            self.db.WriteRows(self.named_records, self.name + '_IndexNodes')

    def create_tables(self):
        self.db.CreateTable(self.hardlink_info, self.name + '_Hardlinks')
        self.db.CreateTable(self.extent_info, self.name + '_Extents')
        self.db.CreateTable(self.attr_info, self.name + '_Attributes')
        self.db.CreateTable(self.thread_info, self.name + '_Threads')
        self.db.CreateTable(self.named_info, self.name + '_IndexNodes')
        self.db.CreateTable(self.compressed_info, self.name + '_Compressed_Files')
        self.db.CreateTable(self.paths_info, self.name + '_Paths')

    def clear_records(self):
        self.hardlink_records = []
        self.extent_records = []
        self.thread_records = []
        self.named_records = []
        self.attr_records = []
    
    def create_indexes(self):
        '''Create indexes on cnid and path in database'''
        index_queries = ["CREATE INDEX {0}_attribute_cnid ON {0}_Attributes (CNID)".format(self.name),
                         "CREATE INDEX {0}_extent_cnid ON {0}_Extents (CNID)".format(self.name),
                         "CREATE INDEX {0}_index_cnid ON {0}_IndexNodes (CNID)".format(self.name),
                         "CREATE INDEX {0}_paths_path_cnid ON {0}_Paths (Path, CNID)".format(self.name),
                         "CREATE INDEX {0}_threads_cnid_parent_cnid ON {0}_Threads (CNID, Parent_CNID)".format(self.name),
                         "CREATE INDEX {0}_compressed_files_cnid ON {0}_Compressed_Files (CNID)".format(self.name)]
        for query in index_queries:
            success, cursor, error = self.db.RunQuery(query, writing=True)
            if not success:
                log.error('Error creating index: ' + error)
                break
    
    def run_query(self, query, writing=True):
        '''Returns True/False on query execution'''
        success, cursor, error = self.db.RunQuery(query, writing)
        if not success:
            log.error('Error executing query : Query was {}, Error was {}'.format(query, error))
            return False
        return True

    def populate_compressed_files_table(self):
        '''Pre-process all compressed file metadata and populate the compressed file table for quick retieval later'''

        # In APFS, for compressed files, sometimes the compressed header (fpmc) is in the database, at other times
        # it is in an extent. The compressed data is also sometime inline, at other times in an extent. This table 
        # will make the lookup easier as it consolidates the data, thus avoiding multiple queries when fetching 
        # info about a file. Also, we provide the uncompressed size of the file (logical size), so its always 
        # available for listing, without having to go and read an extent.

        #Copy all decmpfs-Type2 attributes to table, where no resource forks <-- Nothing to do, just copy
        type2_no_rsrc_query = "INSERT INTO {0}_Compressed_Files select b.CNID, b.Data, "\
                " b.logical_uncompressed_size, 0 as extent_cnid, 0 as fpmc_in_extent, 0 as Extent_Logical_Size"\
                " from {0}_Attributes as b "\
                " left join {0}_Attributes as a on (a.cnid = b.cnid and a.Name = 'com.apple.ResourceFork') "\
                " where b.Name='com.apple.decmpfs' and b.Type=2 and a.cnid is null".format(self.name)
        if not self.run_query(type2_no_rsrc_query, True):
            return

        #Add all decmpfs-Type2 attributes where resource forks exist, rsrc's extent_cnid is used
        type2_rsrc_query = "INSERT INTO {0}_Compressed_Files "\
                "SELECT b.CNID, b.Data, b.logical_uncompressed_size, a.extent_cnid as extent_cnid, 0 as fpmc_in_extent, "\
                " a.logical_uncompressed_size as Extent_Logical_Size FROM {0}_Attributes as b "\
                " left join {0}_Attributes as a on (a.cnid = b.cnid and a.Name = 'com.apple.ResourceFork')"\
                " where b.Name='com.apple.decmpfs' and b.Type=2 and a.cnid is not null".format(self.name)
        if not self.run_query(type2_rsrc_query, True):
            return
         
        #Process decmpfs-Type1 attributes. Go to extent, read fpmc header to get uncompressed size
        # This query gets extents for decmpfs and rsrc but only the first one, this way there is only
        #  one row returned  for every cnid, and we are also only interested in the first extent.
        #                       0                           1                                   2
        type1_query = "select b.CNID, b.extent_cnid as decmpfs_ext_cnid,  b.logical_uncompressed_size, "\
                "e.Block_Num as decmpfs_first_ext_Block_num, a.extent_cnid as rsrc_extent_cnid , er.Block_Num as rsrc_first_extent_Block_num, "\
                " a.logical_uncompressed_size as Extent_Logical_Size from {0}_Attributes as b "\
                " left join {0}_Attributes as a on (a.cnid = b.cnid and a.Name = 'com.apple.ResourceFork') "\
                " left join {0}_Extents as e on e.cnid=b.extent_cnid "\
                " left join {0}_Extents as er on er.cnid=a.extent_cnid "\
                " where b.Name='com.apple.decmpfs' and b.Type=1"\
                " and (e.offset=0 or e.offset is null) and (er.offset = 0 or er.offset is null)".format(self.name)
        success, cursor, error = self.db.RunQuery(type1_query, writing=False)
        if success:
            block_size = self.container.apfs.block_size
            to_write = []
            for row in cursor:
                # Go to decmpfs_extent block and read uncompressed size
                logical_size = row[2]
                #uncompressed_size = 0
                #decmpfs_ext_cnid = row[1]
                self.container.seek(block_size * row[3])
                decmpfs = self.container.read(logical_size)
                #magic, compression_type, uncompressed_size = struct.unpack('<IIQ', decmpfs[0:16])
                uncompressed_size = struct.unpack('<Q', decmpfs[8:16])[0]
                #TODO: check magic if magic =='fpmc'
                if row[4] == None:
                    # No resource fork , data must be in decmpfs_extent
                    if logical_size <= 32: # If < 32 bytes, write to db, else leave in extent
                        to_write.append([row[0], buffer(decmpfs), uncompressed_size, 0, 0, 0])
                    else:
                        to_write.append([row[0], None, uncompressed_size, row[1], 1, logical_size])
                else: 
                    # resource fork has data
                    to_write.append([row[0], buffer(decmpfs), uncompressed_size, row[4], 0, row[6]])
            if to_write:
                self.db.WriteRows(to_write, self.name + '_Compressed_Files')      

        else:
            log.error('Error executing query : Query was {}, Error was {}'.format(type1_query, error))
            return
        
    def read_volume_records(self):
        ''' Get root btree node and parse all children, add 
            all information to a database.
        '''
        self.create_tables()

        root_block = self.container.read_block(self.volume.root_block_num)
        self.read_entries(self.volume.root_block_num, root_block)

        # write remaining records to db
        if self.num_records_read_batch > 0:
            self.num_records_read_batch = 0
            
            self.write_records()
            self.clear_records() # Clear the data once written   

        self.create_other_tables_and_indexes()

    def create_other_tables_and_indexes(self):
        '''Populate paths table in db, create compressed_files table and create indexes for faster queries'''
        insert_query = "INSERT INTO {0}_Paths SELECT * FROM " \
                        "( WITH RECURSIVE " \
                        "  under_root(path,name,cnid) AS " \
                        "  (  VALUES('','root',2) " \
                        "    UNION ALL " \
                        "    SELECT under_root.path || '/' || {0}_IndexNodes.name, " \
                        "{0}_IndexNodes.name, {0}_IndexNodes.cnid " \
                        "       FROM {0}_IndexNodes JOIN under_root ON " \
                        "       {0}_IndexNodes.parent_cnid=under_root.cnid " \
                        "   ORDER BY 1 " \
                        ") SELECT CNID, Path FROM under_root);"
                        
        query = insert_query.format(self.name)
        self.run_query(query, True)
        self.run_query("UPDATE {}_Paths SET path = '/' where cnid = 2;".format(self.name), True)

        self.populate_compressed_files_table()
        self.create_indexes()

    def read_entries(self, block_num, block):
        '''Read file system entries(inodes) and add to database'''
        if block_num in self.blocks_read: return # block already processed
        else: self.blocks_read.add(block_num)

        if block.header.type_content == self.container_type_files:
            for _, entry in enumerate(block.body.entries):
                if type(entry.data) == self.ptr_type: #apfs.Apfs.PointerRecord: 
                    continue
                entry_type = entry.key.type_entry
                if entry_type == self.ext_type: #container.apfs.EntryType.extent.value:
                    self.num_records_read_batch += 1
                    self.num_records_read_total += 1
                    self.extent_records.append([entry.key.key_value, entry.key.content.offset, entry.data.size, entry.data.block_num.value])
                elif entry_type == self.name_type: #container.apfs.EntryType.name.value:
                    # named key!!    
                    self.num_records_read_batch += 1
                    self.num_records_read_total += 1
                    rec = entry.data
                    self.named_records.append([rec.node_id, entry.key.key_value, rec.timestamp, rec.type_item.value, entry.key.content.dirname])
                elif entry_type == self.thrd_type: #container.apfs.EntryType.thread.value:
                    self.num_records_read_batch += 1
                    self.num_records_read_total += 1
                    rec = entry.data
                    self.thread_records.append([entry.key.key_value, rec.parent_id, rec.node_id, rec.dirname, rec.creation_timestamp, rec.modified_timestamp, rec.changed_timestamp, rec.accessed_timestamp, rec.flags, rec.nchildren_or_nlink, rec.bsdflags, rec.owner_id, rec.group_id, rec.mode, rec.size1, rec.size2])
                elif entry_type == self.hard_type: #container.apfs.EntryType.hardlink.value:
                    self.num_records_read_batch += 1
                    self.num_records_read_total += 1
                    self.hardlink_records.append([entry.key.key_value, entry.data.node_id, entry.data.dirname])
                elif entry_type == self.attr_type: #container.apfs.EntryType.extattr.value:
                    self.num_records_read_batch += 1
                    self.num_records_read_total += 1
                    rec = entry.data
                    data = buffer(rec.data)
                    rsrc_extent_cnid = 0
                    logical_size = 0
                    rec_type = rec.type_ea.value
                    if rec_type == 1: # Extent based record
                        #rsrc_extent_cnid, logical_size, physical_size = struct.unpack('<QQQ', rsrc[1][0:24]) # True for all Type 1
                        rsrc_extent_cnid, logical_size = struct.unpack('<QQ', data[0:16])
                    elif rec_type == 2: # BLOB type
                        if entry.key.content.attr_name == 'com.apple.decmpfs':
                            #magic, compression_type, uncompressed_size = struct.unpack('<IIQ', decmpfs[1][0:16])
                            logical_size = struct.unpack('<Q', data[8:16])[0] # uncompressed data size
                    self.attr_records.append([entry.key.key_value, entry.key.content.attr_name, rec.type_ea.value, data, logical_size, rsrc_extent_cnid])

        elif block.header.type_content == self.container_type_location:
            for _, entry in enumerate(block.body.entries):
                if type(entry.data) == self.ptr_type: #apfs.Apfs.PointerRecord: 
                    # Must process this!!!!
                    if type(entry.key.content) == apfs.Apfs.LocationKey:
                        newblock = self.container.read_block(entry.data.pointer)
                        self.read_entries(entry.data.pointer, newblock)
                else:
                    newblock = self.container.read_block(entry.data.block_num.value)
                    self.read_entries(entry.data.block_num.value, newblock)
        else:
            raise "unexpected entry"

        if self.num_records_read_batch > 400000:
            self.num_records_read_batch = 0
            # write to db / file
            self.write_records()
            self.clear_records() # Clear the data once written
        return

class ApfsVolume:
    def __init__(self, apfs_container, name=""):
        self.container = apfs_container
        self.root_dir_block_id = 0 # unused?
        self.block_map_block_num = 0
        self.root_block_num = 0
        # volume basic info
        self.name = name
        self.volume_name = ''
        self.num_blocks_used = 0
        self.num_files = 0
        self.num_folders = 0
        self.time_created = None
        self.time_updated = None
        self.uuid = ''

    def read_volume_info(self, volume_super_block_num):
        """Read volume information"""

        # get volume superblock
        super_block = self.container.read_block(volume_super_block_num)
        self.block_map_block_num = super_block.body.block_map_block.value  # mapping btree
        self.root_dir_block_id = super_block.body.root_dir_id 

        self.volume_name = super_block.body.volume_name
        self.name += '_' + self.volume_name.replace(' ', '_').replace("'", "''") # Replace spaces with underscore and single quotes with doubles, this is for the db
        self.num_blocks_used = super_block.body.num_blocks_used
        self.num_files = super_block.body.num_files
        self.num_folders = super_block.body.num_folders
        self.time_created = super_block.body.time_created
        self.time_updated = super_block.body.time_updated
        self.uuid = self.ReadUUID(super_block.body.volume_uuid)

        #log.debug("%s (volume, Mapping-Btree: %d, Rootdir-Block_ID: %d)" % (
        #    super_block.body.volume_name, self.block_map_block_num, self.root_dir_block_id))
        log.debug(" -- Volume information:")
        log.debug("  Vol name  = %s" % super_block.body.volume_name)
        log.debug("  Num files = %d" % super_block.body.num_files)
        log.debug("  Num dirs  = %d" % super_block.body.num_folders)
        log.debug("  Vol used  = %.2f GB" % float((super_block.body.num_blocks_used * self.container.apfs.block_size)/(1024.0*1024.0*1024.0)))

        # get volume btree
        vol_btree = self.container.read_block(self.block_map_block_num)
        self.root_block_num = vol_btree.body.root.value
        #log.debug ("root_block_num = {}".format(self.root_block_num))

    def ReadUUID(self, uuid):
        '''Return a string from binary uuid blob'''
        uuid_str =  binascii.hexlify(uuid[0:4]) + '-' + \
                    binascii.hexlify(uuid[4:6]) + '-' +\
                    binascii.hexlify(uuid[6:8]) + '-' +\
                    binascii.hexlify(uuid[8:10]) + '-' +\
                    binascii.hexlify(uuid[10:16])
        return uuid_str.upper()

    def CopyOutFolderRecursive(self, path, db, output_folder):
        '''Internal Test function'''
        if not path:
            return
        if not path.startswith('/'): 
            path = '/' + path
        if path.endswith('/') and path != '/':
            path = path[:-1]
        if not os.path.exists(output_folder):
            os.makedirs(output_folder)
        items = self.ListItemsInFolder(path, db)
        for item in items:
            type = item['type']
            if type == 'Folder':
                name = item['name']
                new_path = ('/' + name) if path == '/' else (path + '/' + name)
                new_out_path = os.path.join(output_folder, name)
                try:
                    if not os.path.exists(new_out_path):
                        os.makedirs(new_out_path)
                    self.CopyOutFolderRecursive(new_path, db, new_out_path)
                except:
                    log.exception('Error creating folder ' + new_out_path)
            elif type == 'File':
                name = item['name']
                file_path = ('/' + name) if path == '/' else (path + '/' + name)
                destination_path = os.path.join(output_folder, name)
                self.CopyOutFile(file_path, destination_path, db)

    def GetFile(self, path, db):
        '''Returns an ApfsFile object given path. Returns None if file not found'''
        if not path:
            return None
        apfs_file_meta = self.GetFileMetadataByPath(path, db)
        if apfs_file_meta:
            return ApfsFile(apfs_file_meta, apfs_file_meta.logical_size, apfs_file_meta.extents, self.container)
        return None

    def OpenSmallFile(self, path, db):
        '''Open small files (<200MB), returns open file handle'''
        log.debug("Trying to open file : " + path)
        apfs_file = self.GetFile(path, db)
        if apfs_file == None:
            log.info('File not found! Path was: ' + path)
            return None
        if apfs_file.meta.logical_size > 209715200:
            raise ValueError('File size > 200 MB')
        try:
            max_possible_size = apfs_file.meta.logical_size
            if apfs_file.meta.is_symlink:
                max_possible_size = 1024 # Symlink is a path, cannot be larger than 1024
            f = tempfile.SpooledTemporaryFile(max_size=max_possible_size)
            f.write(apfs_file.readAll())
            f.seek(0)
            return f
        except:
            log.exception("Failed to open file {}".format(path))
        return None

    def CopyOutFile(self, path, destination_path, db):
        '''Copy out file to disk'''
        retval = False
        if not path:
            return False
        apfs_file = self.GetFile(path, db)
        log.debug('Trying to copy out ' + path)
        if apfs_file:
            try:
                with open(destination_path, 'wb') as out_file:
                    out_file.write(apfs_file.readAll())
                    final_file_size = out_file.tell()
                    out_file.flush()
                    out_file.close()
                    retval = True
                    if final_file_size != apfs_file.meta.logical_size and not apfs_file.meta.is_symlink:
                        log.error ("File Size mismatch, Should be {}, but is {} for file: {}".format(apfs_file.meta.logical_size, final_file_size, path))
            except:
                log.exception ("Failed to create file for writing - " + destination_path)
        else:
            log.debug("Failed to find file for export: " + path)
        return retval

    def DoesFileExist(self, db, path):
        '''Returns True if file exists'''
        return self.DoesPathExist(db, path, EntryType.FILES)

    def DoesFolderExist(self, db, path):
        '''Returns True if folder exists'''
        return self.DoesPathExist(db, path, EntryType.FOLDERS)        

    def DoesPathExist(self, db, path, type=EntryType.FILES_AND_FOLDERS):
        '''Returns True if path exists'''
        if not path: 
            return None
        if not path.startswith('/'): 
            path = '/' + path

        if type == EntryType.FILES_AND_FOLDERS:
            query = "SELECT CNID from {0}_Paths WHERE Path = '{1}'"
        elif type == EntryType.FILES:
            query = "SELECT p.CNID from {0}_Paths as p "\
                    " left join {0}_IndexNodes as i on i.CNID = p.CNID "\
                    " WHERE Path = '{1}' AND ItemType=8"
        else: # folders
            query = "SELECT p.CNID from {0}_Paths as p "\
                    " left join {0}_IndexNodes as i on i.CNID = p.CNID "\
                    " WHERE Path = '{1}' AND ItemType=4"
        path = path.replace("'", "''") # if path contains single quote, replace with double to escape it!
        success, cursor, error_message = db.RunQuery(query.format(self.name, path))
        if success:
            for row in cursor:
                return True
        return False

    def GetFileMetadataByPath(self, path, db):
        '''Returns ApfsFileMeta object from database given path and db handle'''
        if not path: 
            return None
        if not path.startswith('/'): 
            path = '/' + path
                    #   0         1              2             3         4        5          6             7         8        9
        query = "SELECT p.CNID, p.Path, t.Parent_CNID, t.Extent_CNID, t.Name, t.Created, t.Modified, t.Changed, t.Accessed, t.Flags,"\
                " t.Links_or_Children, t.BSD_flags, t.UID, t.GID, t.Mode, t.Logical_Size, t.Physical_Size, " \
                " i.ItemType, i.TimeStamp, e.Offset as Extent_Offset, e.Size as Extent_Size, e.Block_Num as Extent_Block_Num, " \
                " c.Uncompressed_size, c.Data, c.Extent_Logical_Size, "\
                " e_c.Offset as compressed_Extent_Offset, e_c.Size as compressed_Extent_Size, e_c.Block_Num as compressed_Extent_Block_Num"\
                " from {0}_Paths as p "\
                " left join {0}_Threads as t on t.CNID = p.CNID "\
                " left join {0}_IndexNodes as i on i.CNID = p.CNID "\
                " left join {0}_Extents as e on e.CNID = t.Extent_CNID "\
                " left join {0}_Compressed_Files as c on c.CNID = t.CNID "\
                " left join {0}_Extents as e_c on e_c.CNID = c.Extent_CNID "\
                " where p.Path = '{1}' "\
                " order by Extent_Offset, compressed_Extent_Offset"
        # This query gets file metadata as well as extents for file. If compressed, it gets compressed extents.
        path = path.replace("'", "''") # if path contains single quote, replace with double to escape it!
        success, cursor, error_message = db.RunQuery(query.format(self.name, path))
        if success:
            apfs_file_meta = None
            #extent_cnid = 0
            index = 0
            prev_extent = None
            for row in cursor:
                if index == 0:
                    # sqlite does not like unicode strings as index names, hence not using dictionary row
                    apfs_file_meta = ApfsFileMeta(row[4], row[0], row[2], CommonFunctions.ReadAPFSTime(row[5]), CommonFunctions.ReadAPFSTime(row[6]), CommonFunctions.ReadAPFSTime(row[7]), CommonFunctions.ReadAPFSTime(row[8]), CommonFunctions.ReadAPFSTime(row[18]), row[9], row[10], row[11], row[12], row[13], row[14], row[15], row[16], row[17])
                    #extent_cnid = row[3]
                    if row[22] != None: # uncompressed_size
                        apfs_file_meta.logical_size = row[22]
                        apfs_file_meta.is_compressed = True
                        apfs_file_meta.decmpfs = row[23]
                        apfs_file_meta.compressed_extent_size = row[24]
                extent = ApfsExtent(row[25], row[26], row[27]) if apfs_file_meta.is_compressed else ApfsExtent(row[19], row[20], row[21])
                if prev_extent and extent.offset == prev_extent.offset:
                    #This file may have hard links, hence the same data is in another row, skip this!
                    pass
                else:
                    apfs_file_meta.extents.append(extent)
                prev_extent = extent
                index += 1
            if index == 0: # No such file!
                return None
            # Let's also get Attributes, except decmpfs and ResourceFork (we already got those in _Compressed_Files table)
            # TODO: Remove Logical_uncompressed_size, Extent_CNID, perhaps not needed now!
            attrib_query = "SELECT Name, Type, Data, Logical_uncompressed_size, Extent_CNID from {0}_Attributes WHERE cnid={1} and Name not in ('com.apple.decmpfs', 'com.apple.ResourceFork')"
            success, cursor, error_message = db.RunQuery(attrib_query.format(self.name, apfs_file_meta.cnid))
            if success:
                for row in cursor:
                    apfs_file_meta.attributes[row[0]] = [row[1], row[2], row[3], row[4]]
            else:
                log.debug('Failed to execute attribute query, error was : ' + error_message)
            return apfs_file_meta
        else:
            log.debug('Failed to execute GetFileMetadataByPath query, error was : ' + error_message)

        return None

    def ListItemsInFolder(self, path, db):
        ''' 
        Returns a list of files and/or folders in a list
        Format of list = [ { 'name':'got.txt', 'type':EntryType.FILE, 'size':10, 'dates': {} }, .. ]
        'path' should be linux style using forward-slash like '/var/db/xxyy/file.tdc'
        '''
        if path.endswith('/') and path != '/':
            path = path[:-1]
        items = [] # List of dictionaries
        query = "SELECT t.Name, p.CNID, i.ItemType, t.Logical_Size, t.Created, t.Modified, t.Changed, t.Accessed, "\
                " c.Uncompressed_size, i.TimeStamp "\
                " from {0}_Paths as p "\
                " left join {0}_Threads as t on p.cnid=t.cnid  "\
                " left join {0}_IndexNodes as i on i.CNID = t.CNID "\
                " left join {0}_Compressed_Files as c on c.CNID=t.CNID "\
                " WHERE t.Parent_CNID in (select CNID from {0}_Paths  where path='{1}')"
        try:
            path = path.replace("'", "''") # if path contains single quote, replace with double to escape it!
            success, cursor, error_message = db.RunQuery(query.format(self.name, path))
            if success:
                for row in cursor:
                    item = { 'name':row[0] }
                    if row[8] == None:
                        item['size'] = row[3]
                    else:
                        item['size'] = row[8]
                    item['dates'] = { 'c_time':CommonFunctions.ReadAPFSTime(row[6]), 'm_time':CommonFunctions.ReadAPFSTime(row[5]), 'cr_time':CommonFunctions.ReadAPFSTime(row[4]), 'a_time':CommonFunctions.ReadAPFSTime(row[7]),
                    'i_time':CommonFunctions.ReadAPFSTime(row[9]) }
                    if row[2] == 4:    item['type'] = 'Folder' #EntryType.FOLDERS
                    elif row[2] == 8:  item['type'] = 'File' #EntryType.FILES
                    elif row[2] == 10: item['type'] = 'Symlink' #EntryType.SYMLINKS
                    else:
                        item['type'] = row[2]
                    items.append(item)
            else:
                log.error('Failed to execute ListItemsInFolder query, error was : ' + error_message)
        except Exception as ex:
            log.error(str(ex))
        return items

class ApfsContainer:

    def __init__(self, image_file, apfs_container_size, offset=0):
        self.img = image_file
        self.apfs_container_offset = offset
        self.apfs_container_size = apfs_container_size
        self.volumes = []
        self.position = 0 # For self.seek()

        try:
            self.block_size = 4096 # Default, before real size is read in
            self.seek(0x20)
            magic = self.read(4)
            assert magic == b'NXSB'
        except:
            raise Exception("Not an APFS image")

        self.seek(0)
        self.apfs = apfs.Apfs(KaitaiStream(self))
        self.block_size = self.apfs.block_size
        self.containersuperblock = self.read_block(0)
        # get list of volume ids
        apfss = [x for x in self.containersuperblock.body.volumesuperblock_ids if x != 0 ] # removing the invalid ones
        block_map_block_num = self.containersuperblock.body.block_map_block.value
        self.num_volumes = len(apfss)

        log.debug("There are {} volumes in this container".format(self.num_volumes))
        #log.debug("Volume Block IDs: %s, Mapping-Btree: %d" % (apfss, block_map_block_num))

        block_map = self.read_block(block_map_block_num)
        self.apfs_locations = {}
        block_map_btree_root = self.read_block(block_map.body.root.value)
        for _, entry in enumerate(block_map_btree_root.body.entries):
            self.apfs_locations[entry.key.key_value] = entry.data.block_num.value
        #log.debug("Volume Blocks:", self.apfs_locations, "\n")
        index = 1
        for _, volume_block_num in self.apfs_locations.items():
            volume = ApfsVolume(self, 'Vol_' + str(index))
            volume.read_volume_info(volume_block_num)
            self.volumes.append(volume)
            index += 1

    def close(self):
        pass

    def seek(self, offset, from_what=0):
        if from_what == 0: # Beginning of file
            self.position = offset
        elif from_what == 1: # current position
            self.position += offset
        elif from_what == 2: # end of file (offset must be -ve)
            self.position = self.apfs_container_size + offset
        else:
            raise 'Unexpected value in from_what (only 0,1,2 are allowed), value was ' + str(from_what)

    def tell(self):
        return self.position

    def read(self, size):
        data = self.img.read(self.apfs_container_offset + self.position, size) #self.read_correct(self.apfs_container_offset + self.position, size)
        self.position += len(data)
        return data

    def get_block(self, idx):
        """ Get data of a single block """
        self.seek(idx * self.block_size)
        return self.read(self.block_size)

    def read_block(self, block_num):
        """ Parse a singe block """
        data = self.get_block(block_num)
        #data = memoryview(self.get_block(block_num)) # no improvement 
        if not data:
            return None
        block = self.apfs.Block(KaitaiStream(BytesIO(data)), self.apfs, self.apfs)
        return block

    # For pytsk - not used - remove later!
    def calculate_block_and_distance(self, offset):
        tsk_offset = offset
        offset_diff = 0 # In 'block_size' byte block, distance from block start to offset |<---diff--->*-------|

        if offset < self.block_size: 
            tsk_offset = 0
            offset_diff = offset
        elif offset > self.block_size: 
            tsk_offset = self.block_size * (offset / self.block_size)
            rem = offset % self.block_size
            if rem > 0:
                offset_diff = rem
        return tsk_offset, offset_diff

    # For pytsk - not used - remove later!
    def read_correct(self, offset, size):
        '''
        Determine which 'block_size' byte block the requested range falls into and
        make the correct request to pytsk. Strip the output only pass the 
        requested data back
        '''
        tsk_offset_start, offset_diff_start = self.calculate_block_and_distance(offset)
        tsk_offset_end, offset_diff_end = self.calculate_block_and_distance(offset + size)
        tsk_size = tsk_offset_end - tsk_offset_start + (self.block_size if offset_diff_end > 0 else 0)
        data = self.img.read(tsk_offset_start, tsk_size)
        return data[offset_diff_start:offset_diff_start + size]

class ApfsExtent:
    __slots__ = ['offset', 'size', 'block_num']

    def __init__(self, offset, size, block_num):
        self.offset = offset
        self.size = size
        self.block_num = block_num

    def GetData(self, container):
        container.seek(self.block_num * container.block_size)
        ## TODO: Create buffered read, in case of really large files!!
        #return image.read(self.size)
        return container.read(self.size)

class ApfsFile():
    def __init__(self, apfs_file_meta, logical_size, extents, apfs_container):
        self.meta = apfs_file_meta
        self.file_size = logical_size
        self.extents = extents
        self.container = apfs_container

    def _lzvn_decompress(self, compressed_stream, compressed_size, uncompressed_size):
        '''
            Adds Prefix and Postfix bytes as required by decompressor, 
            then decompresses and returns uncompressed bytes buffer
        '''
        header = b'bvxn' + struct.pack('<I', uncompressed_size) + struct.pack('<I', compressed_size)
        footer = b'bvx$'
        return lzfse.decompress(header + compressed_stream + footer)

    def _readCompressedAll(self):
        '''Read compressed data'''
        file_content = b''
        decmpfs = self.meta.decmpfs
        if decmpfs == None: # header & data in extent, data is inline with header
            decmpfs = self._GetDataFromExtents(self.extents, self.meta.compressed_extent_size)
            # Now decompress it according to compression_type
            file_content = self._DecompressInline(decmpfs)
        else: # we already have header, data is in extent or inline
            extent_data_size = self.meta.compressed_extent_size
            if extent_data_size == 0:   # data is inline
                file_content = self._DecompressInline(decmpfs)
            else:                       # data is in extent (resource fork)
                compressed_data = self._GetDataFromExtents(self.extents, extent_data_size)
                # Now decompress it according to compression_type
                file_content = self._DecompressNotInline(decmpfs, compressed_data)
        return file_content

    def _DecompressNotInline(self, decmpfs, compressed_data):
        decompressed = b''
        #compressed_data = compressed_data.tobytes()
        magic, compression_type, uncompressed_size = struct.unpack('<IIQ', decmpfs[0:16])
        if compression_type == 4: # zlib in ResourceFork
            # Read Header (HFSPlusCmpfRsrcHead)
            header_size, total_size, data_size, flags = struct.unpack('>IIII', compressed_data[0:16])
            # Read Block info
            blocks_data_size = struct.unpack('>I', compressed_data[header_size : header_size + 4])[0]
            num_blocks = struct.unpack('<I', compressed_data[header_size + 4 : header_size + 8])[0]
            base_offset = header_size + 8
            # Read chunks
            for i in xrange(num_blocks):
                chunk_offset, chunk_size = struct.unpack('<II', compressed_data[base_offset + i*8 : base_offset + i*8 + 8])
                #log.debug("ChunkOffset={} ChunkSize={} start={} end={}".format(chunk_offset, chunk_size, header_size + 4 + chunk_offset, header_size + 4 + chunk_offset + chunk_size))
                start = header_size + 4 + chunk_offset
                if compressed_data[start] == b'\xFF':
                    decompressed += compressed_data[start + 1 : start + chunk_size]
                else:
                    decompressed += zlib.decompress(compressed_data[start : start + chunk_size])
        elif compression_type == 8: # lzvn in ResourceFork
            try:
                # The following is only for lzvn, not encountered lzfse yet!
                full_uncomp = uncompressed_size
                chunk_uncomp = 65536
                i = 0

                headerSize = struct.unpack('<I', compressed_data[0:4])[0]
                num_chunkOffsets = headerSize/4  - 1
                chunkOffsets = struct.unpack('<{}I'.format(num_chunkOffsets), compressed_data[4 : 4 + (num_chunkOffsets * 4)])

                src_offset = headerSize
                for offset in chunkOffsets:
                    compressed_size = offset - src_offset
                    data = compressed_data[src_offset:offset]
                    src_offset = offset
                    if full_uncomp <= 65536:
                        chunk_uncomp = full_uncomp
                    else:
                        chunk_uncomp = 65536
                        if num_chunkOffsets == i + 1: # last chunk
                            chunk_uncomp = full_uncomp - (65536 * i)
                    if chunk_uncomp < compressed_size and data[0] == b'\x06':
                        decompressed += data[1:]
                    else:
                        decompressed += self._lzvn_decompress(data, compressed_size, chunk_uncomp)
                    i += 1
            except Exception as ex:
                log.exception("Exception from lzfse.decompress, decompression failed!")
                raise "Exception from lzfse.decompress, decompression failed!"
        # Shouldn't be any of the following:
        elif compression_type in [1,3,7,11]: # types in ResourceFork
            log.error ("compression_type = {} in DecompressNotInline --> ERROR! Should not go here!".format(compression_type))
        elif compression_type == 12:
            log.error ("compression_type = {} --> LZFSE Not seen before (not inline), don't know how to handle!".format(compression_type))
        else:
            log.error ("compression_type = {} --> Not seen before (not inline), don't know how to handle!".format(compression_type))
        return decompressed

    def _DecompressInline(self, decmpfs):
        decompressed = b''
        #decmpfs = decmpfs.tobytes()
        total_len = len(decmpfs)
        magic, compression_type, uncompressed_size = struct.unpack('<IIQ', decmpfs[0:16])

        if compression_type == 1:
            decompressed = decmpfs[16:]
        elif compression_type == 3: # zlib
            if (uncompressed_size <= total_len - 16) and (decmpfs[16] == b'\xFF'):
                decompressed = decmpfs[17:]
            else:
                decompressed = zlib.decompress(decmpfs[16:])
        elif compression_type in [4, 8, 12]: # types in ResourceFork
            log.error ("compression_type = {} in DecompressInline --> ERROR! Should not go here!".format(compression_type))
        elif compression_type == 7: # LZVN inline
            data = decmpfs[16:]
            if (uncompressed_size <= total_len - 16) and (data[0] == b'\x06'):
                    decompressed = decmpfs[17:] #tested OK
            else:
                compressed_size = total_len - 16
                compressed_stream = data
                decompressed = self._lzvn_decompress(compressed_stream, compressed_size, uncompressed_size)
        elif compression_type == 11:
            log.error ("compression_type = {} --> LZFSE Not seen before (inline), don't know how to handle!".format(compression_type))
        else:
            log.error ("compression_type = {} --> Not seen before (inline), don't know how to handle!".format(compression_type))
        return decompressed

    def _GetDataFromExtents(self, extents, total_size):
        '''Retrieves data from extents'''
        content = b''
        if total_size == 0: 
            return content
        bytes_left = total_size
        for extent in extents:
            if bytes_left <= 0:
                log.error ("Error, should not get here, mismatch between logical size and extents!")
                break
            data = extent.GetData(self.container)
            data_len = extent.size
            if data_len >= bytes_left:
                content += data[:bytes_left]
                bytes_left = 0
            else:
                content += data
                bytes_left -= data_len
        if bytes_left > 0:
            log.error ("Error, could not get all pieces of file for file - " + self.meta.name + " cnid=" + str(self.meta.cnid))
        return content

    def readAll(self):
        '''return entire file in one buffer'''
        file_content = b''
        if self.meta.is_compressed:
            return self._readCompressedAll()
        elif self.meta.is_symlink: # if symlink, return symlink  path as data
            return self.meta.attributes['com.apple.fs.symlink'][1]
        else:
            file_content = self._GetDataFromExtents(self.extents, self.meta.logical_size)
        return file_content
    

class ApfsFileMeta:
    def __init__(self, name, cnid, parent_cnid, created, modified, changed, accessed, index_time, flags, links, bsd_flags, uid, gid, mode, logical_size, physical_size, item_type):
        self.name = name
        self.cnid = cnid
        self.parent_cnid = parent_cnid
        #self.extent_cnid = extent_cnid
        self.created = created
        self.modified = modified
        self.changed = changed
        self.accessed = accessed
        self.index_time = index_time
        self.flags = flags
        self.links = links
        self.bsd_flags = bsd_flags
        self.uid = uid
        self.gid = gid
        self.mode = mode
        self.logical_size = logical_size
        self.compressed_extent_size = 0
        self.physical_size = physical_size
        self.is_symlink = False
        if   item_type == 4: self.item_type = 'Folder'
        elif item_type == 8: self.item_type = 'File'
        elif item_type ==10: 
            self.item_type = 'SymLink'
            self.is_symlink = True
        else:
            self.item_type = str(item_type)   
        self.decmpfs = None     
        self.attributes = {}
        self.extents = []
        self.is_compressed = False
        #self.is_hardlink = False

