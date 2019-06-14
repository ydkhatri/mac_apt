'''
   Copyright (c) 2017 Yogesh Khatri 

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the 
   terms of the MIT License.

'''

from kaitaistruct import __version__ as ks_version, KaitaiStream, BytesIO
import plugins.helpers.apfs as apfs
import collections
import logging
import lzfse
import struct
import tempfile
from uuid import UUID
from plugins.helpers.writer import DataType
from plugins.helpers.common import *

import zlib

log = logging.getLogger('MAIN.HELPERS.APFS_READER')

# HFSPlusBSDInfo.fileMode values:
S_ISUID = 0o004000     # set user id on execution
S_ISGID = 0o002000     # set group id on execution
S_ISTXT = 0o001000     # sticky bit

S_IRWXU = 0o000700     # RWX mask for owner
S_IRUSR = 0o000400     # R for owner
S_IWUSR = 0o000200     # W for owner
S_IXUSR = 0o000100     # X for owner

S_IRWXG = 0o000070     # RWX mask for group
S_IRGRP = 0o000040     # R for group
S_IWGRP = 0o000020     # W for group
S_IXGRP = 0o000010     # X for group

S_IRWXO = 0o000007     # RWX mask for other
S_IROTH = 0o000004     # R for other
S_IWOTH = 0o000002     # W for other
S_IXOTH = 0o000001     # X for other

S_IFMT   = 0o170000    # type of file mask
S_IFIFO  = 0o010000    # named pipe (fifo)
S_IFCHR  = 0o020000    # character special
S_IFDIR  = 0o040000    # directory
S_IFBLK  = 0o060000    # block special
S_IFREG  = 0o100000    # regular
S_IFLNK  = 0o120000    # symbolic link
S_IFSOCK = 0o140000    # socket
S_IFWHT  = 0o160000    # whiteout

class ApfsDbInfo:
    '''
    This class writes information about db version and volumes to the database. 
    It also checks if the db information corresponds to the currently loaded
    image's volumes.
    '''

    def __init__(self, db):
        self.db = db
        self.version = 2 # This will change if db structure changes in future
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
        self.inode_records = []
        self.dir_records = []
        self.attr_records = []
        self.dir_stats_records = []
        
        self.hardlink_info = collections.OrderedDict([('CNID',DataType.INTEGER), ('Parent_CNID',DataType.INTEGER), 
                                                    ('Name',DataType.TEXT)])
        self.extent_info = collections.OrderedDict([('CNID',DataType.INTEGER), ('Offset',DataType.INTEGER), 
                                                    ('Size',DataType.INTEGER), ('Block_Num',DataType.INTEGER)])
        self.attr_info = collections.OrderedDict([('CNID',DataType.INTEGER), ('Name',DataType.TEXT),('Flags',DataType.INTEGER),('Data',DataType.BLOB),
                                                    ('Logical_uncompressed_size',DataType.INTEGER),('Extent_CNID',DataType.INTEGER)])
        self.inode_info = collections.OrderedDict([('CNID',DataType.INTEGER), ('Parent_CNID',DataType.INTEGER),
                                                     ('Extent_CNID',DataType.INTEGER), ('Name',DataType.TEXT), ('Created',DataType.INTEGER), ('Modified',DataType.INTEGER), ('Changed',DataType.INTEGER), ('Accessed',DataType.INTEGER), ('Flags',DataType.INTEGER), ('Links_or_Children',DataType.INTEGER), ('BSD_flags',DataType.INTEGER), ('UID',DataType.INTEGER), ('GID',DataType.INTEGER), ('Mode',DataType.INTEGER), ('Logical_Size',DataType.INTEGER), ('Physical_Size',DataType.INTEGER)])
        self.dir_info = collections.OrderedDict([('CNID',DataType.INTEGER), ('Parent_CNID',DataType.INTEGER),
                                                    ('DateAdded',DataType.INTEGER),('ItemType',DataType.INTEGER), 
                                                    ('Name',DataType.TEXT)])
        self.compressed_info = collections.OrderedDict([('CNID',DataType.INTEGER),('Data',DataType.BLOB),('Uncompressed_size',DataType.INTEGER),
                                                    ('Extent_CNID',DataType.INTEGER),('fpmc_in_extent',DataType.INTEGER),('Extent_Logical_Size',DataType.INTEGER)]) 
                                                    #TODO: Remove fpmc_in_extent, this can be detected by checking Data == None
        self.paths_info = collections.OrderedDict([('CNID',DataType.INTEGER),('Path',DataType.TEXT)])
        self.dir_stats_info = collections.OrderedDict([('CNID',DataType.INTEGER),('NumChildren',DataType.INTEGER),('TotalSize',DataType.INTEGER),('Counter',DataType.INTEGER)])
        ## Optimization for search
        self.blocks_read = set()

        self.container_type_files = self.container.apfs.ObjType.fstree.value
        self.container_type_location = self.container.apfs.ObjType.omap.value
        self.ptr_type = apfs.Apfs.PointerRecord
        self.file_ext_type = self.container.apfs.EntryType.file_extent.value
        self.dir_rec_type = self.container.apfs.EntryType.dir_rec.value
        self.inode_type = self.container.apfs.EntryType.inode.value
        self.hard_type = self.container.apfs.EntryType.sibling_link.value
        self.attr_type = self.container.apfs.EntryType.xattr.value
        self.dir_stats_type = self.container.apfs.EntryType.dir_stats.value
        ## End optimization

        self.debug_stats = {}

    def AddToStats(self, entry_type):
        item_count = self.debug_stats.get(entry_type, 0)
        item_count += 1
        self.debug_stats[entry_type] = item_count
    
    def PrintStats(self):
        for entry_type in self.container.apfs.EntryType:
            item_count = self.debug_stats.get(entry_type.value, 0)
            if item_count:
                log.info('{} Type={}  Count={}'.format(self.name, str(entry_type)[10:], item_count))

    def write_records(self):
        if  self.hardlink_records: 
            self.db.WriteRows(self.hardlink_records, self.name + '_Hardlinks')
        if self.extent_records:
            self.db.WriteRows(self.extent_records, self.name + '_Extents')
        if self.inode_records:
            self.db.WriteRows(self.inode_records, self.name + '_Inodes')
        if self.attr_records:
            self.db.WriteRows(self.attr_records, self.name + '_Attributes')
        if self.dir_records:
            self.db.WriteRows(self.dir_records, self.name + '_IndexNodes')
        if self.dir_stats_records:
            self.db.WriteRows(self.dir_records, self.name + '_DirStats')

    def create_tables(self):
        self.db.CreateTable(self.hardlink_info, self.name + '_Hardlinks')
        self.db.CreateTable(self.extent_info, self.name + '_Extents')
        self.db.CreateTable(self.attr_info, self.name + '_Attributes')
        self.db.CreateTable(self.inode_info, self.name + '_Inodes')
        self.db.CreateTable(self.dir_info, self.name + '_IndexNodes')
        self.db.CreateTable(self.dir_stats_info, self.name + '_DirStats')
        self.db.CreateTable(self.compressed_info, self.name + '_Compressed_Files')
        self.db.CreateTable(self.paths_info, self.name + '_Paths')

    def clear_records(self):
        self.hardlink_records = []
        self.extent_records = []
        self.inode_records = []
        self.dir_records = []
        self.attr_records = []
        self.dir_stats_records = []
    
    def create_indexes(self):
        '''Create indexes on cnid and path in database'''
        index_queries = ["CREATE INDEX {0}_attribute_cnid ON {0}_Attributes (CNID)".format(self.name),
                         "CREATE INDEX {0}_extent_cnid ON {0}_Extents (CNID)".format(self.name),
                         "CREATE INDEX {0}_index_cnid ON {0}_IndexNodes (CNID)".format(self.name),
                         "CREATE INDEX {0}_paths_path_cnid ON {0}_Paths (Path, CNID)".format(self.name),
                         "CREATE INDEX {0}_inodes_cnid_parent_cnid ON {0}_Inodes (CNID, Parent_CNID)".format(self.name),
                         "CREATE INDEX {0}_compressed_files_cnid ON {0}_Compressed_Files (CNID)".format(self.name),
                         "CREATE INDEX {0}_dir_stats_cnid ON {0}_DirStats (CNID)".format(self.name)]
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
                " where b.Name='com.apple.decmpfs' and (b.Flags & 2)=2 and a.cnid is null".format(self.name)
        if not self.run_query(type2_no_rsrc_query, True):
            return

        #Add all decmpfs-Type2 attributes where resource forks exist, rsrc's extent_cnid is used
        type2_rsrc_query = "INSERT INTO {0}_Compressed_Files "\
                "SELECT b.CNID, b.Data, b.logical_uncompressed_size, a.extent_cnid as extent_cnid, 0 as fpmc_in_extent, "\
                " a.logical_uncompressed_size as Extent_Logical_Size FROM {0}_Attributes as b "\
                " left join {0}_Attributes as a on (a.cnid = b.cnid and a.Name = 'com.apple.ResourceFork')"\
                " where b.Name='com.apple.decmpfs' and (b.Flags & 2)=2 and a.cnid is not null".format(self.name)
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
                " where b.Name='com.apple.decmpfs' and (b.Flags & 1)=1"\
                " and (e.offset=0 or e.offset is null) and (er.offset = 0 or er.offset is null)".format(self.name)
        success, cursor, error = self.db.RunQuery(type1_query, writing=False)
        if success:
            block_size = self.container.apfs.block_size
            to_write = []
            for row in cursor:
                # Go to decmpfs_extent block and read uncompressed size
                logical_size = row[2]
                #decmpfs_ext_cnid = row[1]
                self.container.seek(block_size * row[3])
                decmpfs = self.container.read(logical_size)
                #magic, compression_type, uncompressed_size = struct.unpack('<IIQ', decmpfs[0:16])
                uncompressed_size = struct.unpack('<Q', decmpfs[8:16])[0]
                #TODO: check magic if magic =='fpmc'
                if row[4] == None:
                    # No resource fork , data must be in decmpfs_extent
                    if logical_size <= 32: # If < 32 bytes, write to db, else leave in extent
                        to_write.append([row[0], decmpfs, uncompressed_size, 0, 0, 0])
                    else:
                        to_write.append([row[0], None, uncompressed_size, row[1], 1, logical_size])
                else: 
                    # resource fork has data
                    to_write.append([row[0], decmpfs, uncompressed_size, row[4], 0, row[6]])
            if to_write:
                self.db.WriteRows(to_write, self.name + '_Compressed_Files')      

        else:
            log.error('Error executing query : Query was {}, Error was {}'.format(type1_query, error))
            return
        
    def read_volume_records(self):
        ''' Get tree oid from omap node and parse all children, add 
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
        self.PrintStats()

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

        if block.header.subtype == self.container_type_files:
            if block.body.level > 0: # not leaf nodes
                return
            for _, entry in enumerate(block.body.entries):
                if type(entry.data) == self.ptr_type: #apfs.Apfs.PointerRecord: 
                    continue
                entry_type = entry.key.type_entry
                self.AddToStats(entry_type)
                if entry_type == self.file_ext_type: #container.apfs.EntryType.file_extent.value:
                    self.num_records_read_batch += 1
                    self.num_records_read_total += 1
                    self.extent_records.append([entry.key.obj_id, entry.key.content.offset, entry.data.size, entry.data.phys_block_num])
                elif entry_type == self.dir_rec_type: #container.apfs.EntryType.dir_rec.value:
                    # dir_rec key!!    
                    self.num_records_read_batch += 1
                    self.num_records_read_total += 1
                    rec = entry.data
                    self.dir_records.append([rec.node_id, entry.key.obj_id, rec.date_added, rec.type_item.value, entry.key.content.name])
                elif entry_type == self.inode_type: #container.apfs.EntryType.inode.value:
                    self.num_records_read_batch += 1
                    self.num_records_read_total += 1
                    rec = entry.data
                    self.inode_records.append([entry.key.obj_id, rec.parent_id, rec.node_id, rec.name, rec.creation_timestamp, rec.modified_timestamp, rec.changed_timestamp, rec.accessed_timestamp, rec.flags, rec.nchildren_or_nlink, rec.bsdflags, rec.owner_id, rec.group_id, rec.mode, rec.logical_size, rec.physical_size])
                elif entry_type == self.hard_type: #container.apfs.EntryType.sibling_link.value:
                    self.num_records_read_batch += 1
                    self.num_records_read_total += 1
                    self.hardlink_records.append([entry.key.obj_id, entry.data.parent_id, entry.data.name])
                elif entry_type == self.dir_stats_type: #container.apfs.EntryType.dir_stats.value:
                    self.num_records_read_batch += 1
                    self.num_records_read_total += 1
                    self.dir_stats_records.append([entry.data.chained_key, entry.data.num_children, entry.data.total_size, entry.data.gen_count])
                elif entry_type == self.attr_type: #container.apfs.EntryType.xattr.value:
                    self.num_records_read_batch += 1
                    self.num_records_read_total += 1
                    rec = entry.data
                    data = rec.xdata
                    rsrc_extent_cnid = 0
                    logical_size = 0
                    rec_type = rec.flags
                    if rec_type & 1: # Extent based record
                        #rsrc_extent_cnid, logical_size, physical_size = struct.unpack('<QQQ', rsrc[1][0:24]) # True for all Type 1
                        rsrc_extent_cnid, logical_size = struct.unpack('<QQ', data[0:16])
                    elif rec_type & 2: # BLOB type
                        if entry.key.content.name == 'com.apple.decmpfs':
                            #magic, compression_type, uncompressed_size = struct.unpack('<IIQ', decmpfs[1][0:16])
                            logical_size = struct.unpack('<Q', data[8:16])[0] # uncompressed data size
                    #else:
                    #    log.warning('Unknown rec_type 0x{:X} block_num={}'.format(rec_type, block_num))
                    self.attr_records.append([entry.key.obj_id, entry.key.content.name, rec.flags, data, logical_size, rsrc_extent_cnid])
                elif entry_type == 6: # dstream_id
                    pass # this just has refcnts
                elif entry_type == 0xc: # sibling_map
                    pass # TODO: Maybe process this later
                elif entry_type >= 0xd:
                    log.warning('Unknown entry_type 0x{:X} block_num={}'.format(entry_type, block_num))
                else:
                    log.debug('Got entry_type 0x{:X} block_num={}'.format(entry_type, block_num))
        elif block.header.subtype == self.container_type_location:
            for _, entry in enumerate(block.body.entries):
                if type(entry.data) == self.ptr_type: #apfs.Apfs.PointerRecord: 
                    # Must process this!!!!
                    #if type(entry.key) == apfs.Apfs.OmapKey:
                    try:
                        if not entry.data.pointer in self.blocks_read:
                            newblock = self.container.read_block(entry.data.pointer)
                            self.read_entries(entry.data.pointer, newblock)
                    except:
                        log.exception('Exception trying to read block {}'.format(entry.data.pointer))
                else:
                    try:
                        newblock = self.container.read_block(entry.data.paddr.value)
                        self.read_entries(entry.data.paddr.value, newblock)
                    except:
                        log.exception('Exception trying to read block {}'.format(entry.data.paddr.value))
        elif block.header.subtype == 0:
            pass # invalid object type
        else:
            log.warning("unexpected entry {} in block {}".format(repr(block.header.subtype), block_num))

        if self.num_records_read_batch > 400000:
            self.num_records_read_batch = 0
            # write to db / file
            self.write_records()
            self.clear_records() # Clear the data once written
        return

class DataCache:
    '''Cache of ApfsFileMeta objects'''
    def __init__(self, max_size=2000):
        self.cache_limit = max_size
        self.cache = {} # key=path, value=(ApfsFileMeta object, id)
        self.cache_index = {} # key=id, value=path
        self.index = 0
        self.count = 0

    def Insert(self, apfs_file_meta, path):
        if self.Find(path):
            log.debug('Obj already cached for path {}'.format(path))
            return
        self.index += 1
        self.cache[path] = (apfs_file_meta, self.index)
        self.cache_index[self.index] = path
        #self.count += 1
        if self.count >= self.cache_limit: # should not got to >
            # remove oldest element
            oldest_id = self.index - self.cache_limit
            oldest_path = self.cache_index[oldest_id]
            del(self.cache_index[oldest_id])
            del(self.cache[oldest_path])
        else:
            self.count += 1
    
    def Find(self, path):
        if path.endswith('/'):
            if path != '/':
                path = path.rstrip('/')
        cached_obj = self.cache.get(path, None)
        if cached_obj:
            return cached_obj[0]
        return None   
        
#TODO Add db as class variable, remove it from functions
class ApfsVolume:
    def __init__(self, apfs_container, name=""):
        self.container = apfs_container
        self.root_dir_block_id = 0 # unused?
        self.omap_oid = 0
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
        self.files_meta_cache = DataCache()

    def read_volume_info(self, volume_super_block_num):
        """Read volume information"""

        # get volume superblock
        super_block = self.container.read_block(volume_super_block_num)
        self.omap_oid = super_block.body.omap_oid  # mapping omap
        self.root_dir_block_id = super_block.body.root_dir_id 

        self.volume_name = super_block.body.volume_name
        self.name += '_' + self.volume_name.replace(' ', '_').replace("'", "''") # Replace spaces with underscore and single quotes with doubles, this is for the db
        self.num_blocks_used = super_block.body.num_blocks_used
        self.num_files = super_block.body.num_files
        self.num_folders = super_block.body.num_folders
        self.time_created = super_block.body.time_created
        self.time_updated = super_block.body.time_updated
        self.uuid = self.ReadUUID(super_block.body.volume_uuid)
        self.is_case_sensitive = (super_block.body.feature_flags & 0x8 != 0)
        self.is_encrypted = (super_block.body.encryption_flags & 0x1 != 1)

        #log.debug("%s (volume, Mapping-omap: %d, Rootdir-Block_ID: %d)" % (
        #    super_block.body.volume_name, self.omap_oid, self.root_dir_block_id))
        log.debug(" -- Volume information:")
        log.debug("  Vol name  = %s" % super_block.body.volume_name)
        log.debug("  Num files = %d" % super_block.body.num_files)
        log.debug("  Num dirs  = %d" % super_block.body.num_folders)
        log.debug("  Vol used  = %.2f GB" % float((super_block.body.num_blocks_used * self.container.apfs.block_size)/(1024.0*1024.0*1024.0)))
        log.debug('  feature_flags=0x{:X}, encryption_flags=0x{:X}'.format(super_block.body.feature_flags, super_block.body.encryption_flags))

        if self.is_encrypted:
            log.info("Volume appears to be ENCRYPTED. Encrypted volumes are not supported right now :(")
            log.info("If you think this is incorrect (volume is not encrypted), please contact the developer.")
            return
        # get volume omap
        vol_omap = self.container.read_block(self.omap_oid)
        self.root_block_num = vol_omap.body.tree_oid
        #log.debug ("root_block_num = {}".format(self.root_block_num))

    def ReadUUID(self, uuid_bytes):
        '''Return a string from binary uuid blob'''
        uuid =  UUID(bytes=uuid_bytes)
        return str(uuid).upper()

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

    def GetFile(self, path, db, apfs_file_meta=None):
        '''Returns an ApfsFile object given path. Returns None if file not found'''
        if not path:
            return None
        if apfs_file_meta == None:
            apfs_file_meta = self.files_meta_cache.Find(path)
        if apfs_file_meta == None:
            apfs_file_meta = self.GetFileMetadataByPath(path, db)
            if apfs_file_meta:
                self.files_meta_cache.Insert(apfs_file_meta, path)
        if apfs_file_meta:
            if apfs_file_meta.is_compressed:
                return ApfsFileCompressed(apfs_file_meta, apfs_file_meta.logical_size, apfs_file_meta.extents, self.container)
            else:
                return ApfsFile(apfs_file_meta, apfs_file_meta.logical_size, apfs_file_meta.extents, self.container)
        return None

    def IsSymbolicLink(self, db, path):
        '''Returns True if the path is a symbolic link'''
        if not path:
            return False
        apfs_file_meta = self.files_meta_cache.Find(path)
        if apfs_file_meta == None:
            apfs_file_meta = self.GetFileMetadataByPath(path, db)
            if apfs_file_meta:
                return apfs_file_meta.is_symlink
        return False

    def open(self, path, db, apfs_file_meta=None):
        '''Open file, returns file-like object'''
        log.debug("Trying to open file : " + path)
        apfs_file = self.GetFile(path, db, apfs_file_meta)
        if apfs_file == None:
            log.info('File not found! Path was: ' + path)
        elif apfs_file.meta.logical_size > 209715200:
            log.debug('File size > 200 MB')
        return apfs_file

    def OpenSmallFile(self, path, db, apfs_file_meta=None):
        '''Open small files (<200MB), returns open file handle'''
        log.debug("Trying to open file : " + path)
        apfs_file = self.GetFile(path, db, apfs_file_meta)
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

    #TODO SEearch  self.files_meta_cache first!
    def DoesFileExist(self, db, path):
        '''Returns True if file exists'''
        return self.DoesPathExist(db, path, EntryType.FILES)

    #TODO SEearch  self.files_meta_cache first!
    def DoesFolderExist(self, db, path):
        '''Returns True if folder exists'''
        return self.DoesPathExist(db, path, EntryType.FOLDERS)        

    #TODO SEearch  self.files_meta_cache first!
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

    def GetFileMetadataByCnid(self, cnid, db):
        '''Returns ApfsFileMeta object from database given path and db handle'''
        cnid = int(cnid)
        if cnid <= 0: 
            return None
        where_clause = " where p.CNID={} ".format(cnid)
        return self.GetFileMetadata(where_clause, db)

    def GetFileMetadataByPath(self, path, db):
        '''Returns ApfsFileMeta object from database given path and db handle'''
        if not path: 
            return None
        if not path.startswith('/'): 
            path = '/' + path
        path = path.replace("'", "''") # if path contains single quote, replace with double to escape it!
        where_clause = " where p.Path = '{}' ".format(path)
        return self.GetFileMetadata(where_clause, db)

    def GetFilePathFromCnid(self, cnid, db):
        #TODO: add/use cacheing
        meta = self.GetFileMetadataByCnid(cnid, db)
        return meta.path

    def GetFileMetadata(self, where_clause, db):
        '''Returns ApfsFileMeta object from database. A where_clause specifies either cnid or path to find'''
                    #   0         1              2             3         4        5          6             7         8        9
        query = "SELECT p.CNID, p.Path, t.Parent_CNID, t.Extent_CNID, t.Name, t.Created, t.Modified, t.Changed, t.Accessed, t.Flags,"\
                " t.Links_or_Children, t.BSD_flags, t.UID, t.GID, t.Mode, t.Logical_Size, t.Physical_Size, " \
                " i.ItemType, i.DateAdded, e.Offset as Extent_Offset, e.Size as Extent_Size, e.Block_Num as Extent_Block_Num, " \
                " c.Uncompressed_size, c.Data, c.Extent_Logical_Size, "\
                " e_c.Offset as compressed_Extent_Offset, e_c.Size as compressed_Extent_Size, e_c.Block_Num as compressed_Extent_Block_Num"\
                " from {0}_Paths as p "\
                " left join {0}_Inodes as t on t.CNID = p.CNID "\
                " left join {0}_IndexNodes as i on i.CNID = p.CNID "\
                " left join {0}_Extents as e on e.CNID = t.Extent_CNID "\
                " left join {0}_Compressed_Files as c on c.CNID = t.CNID "\
                " left join {0}_Extents as e_c on e_c.CNID = c.Extent_CNID "\
                " {1} "\
                " order by Extent_Offset, compressed_Extent_Offset"
        # This query gets file metadata as well as extents for file. If compressed, it gets compressed extents.
        success, cursor, error_message = db.RunQuery(query.format(self.name, where_clause))
        if success:
            apfs_file_meta = None
            #extent_cnid = 0
            index = 0
            prev_extent = None
            for row in cursor:
                if index == 0:
                    # sqlite does not like unicode strings as index names, hence not using dictionary row
                    apfs_file_meta = ApfsFileMeta(row[4], row[1], row[0], row[2], CommonFunctions.ReadAPFSTime(row[5]), \
                                        CommonFunctions.ReadAPFSTime(row[6]), CommonFunctions.ReadAPFSTime(row[7]), \
                                        CommonFunctions.ReadAPFSTime(row[8]), \
                                        CommonFunctions.ReadAPFSTime(row[18]), \
                                        row[9], row[10], row[11], row[12], row[13], row[14], row[15], row[16], row[17])
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
            attrib_query = "SELECT Name, Flags, Data, Logical_uncompressed_size, Extent_CNID from {0}_Attributes "\
                            "WHERE cnid={1} and Name not in ('com.apple.decmpfs', 'com.apple.ResourceFork')"
            success, cursor, error_message = db.RunQuery(attrib_query.format(self.name, apfs_file_meta.cnid))
            if success:
                for row in cursor:
                    apfs_file_meta.attributes[row[0]] = [row[1], row[2], row[3], row[4]]
            else:
                log.debug('Failed to execute attribute query, error was : ' + error_message)
            return apfs_file_meta
        else:
            log.debug('Failed to execute GetFileMetadata query, error was : ' + error_message)

        return None

    def GetManyFileMetadataByCnids(self, cnids, db):
        '''Returns ApfsFileMeta object from database given path and db handle'''
        # for cnid in cnids:
        #     if cnid <= 0:
        #         continue # skip that
        cnids = [str(int(x)) for x in cnids]
        cnids_str = ",".join(cnids)
        where_clause = " where p.CNID IN ({}) ".format(cnids_str)
        return self.GetManyFileMetadata(where_clause, db)

    def GetManyFileMetadataByPaths(self, paths, db):
        '''Returns ApfsFileMeta object from database given path and db handle'''   
        for path in paths:
            if not path.startswith('/'): 
                path = '/' + path
            path = path.replace("'", "''") # if path contains single quote, replace with double to escape it!
            path = "'{}'".format(path)
        paths_str = ",".join(paths)
        where_clause = " where p.Path IN ({}) ".format(paths_str)
        return self.GetManyFileMetadata(where_clause, db)

    # def GetManyFilePathFromCnid(self, cnid, db):
    #     #TODO: add/use cacheing
    #     meta = self.GetManyFileMetadataByCnid(cnid, db)
    #     return meta.path

    def GetManyFileMetadata(self, where_clause, db):
        '''Returns ApfsFileMeta object from database. A where_clause specifies either cnids or paths to find. No Attribute data is returned!!'''
        apfs_file_meta_list = []
                    #   0         1              2             3         4        5          6             7         8        9
        query = "SELECT p.CNID, p.Path, t.Parent_CNID, t.Extent_CNID, t.Name, t.Created, t.Modified, t.Changed, t.Accessed, t.Flags,"\
                " t.Links_or_Children, t.BSD_flags, t.UID, t.GID, t.Mode, t.Logical_Size, t.Physical_Size, " \
                " i.ItemType, i.DateAdded, e.Offset as Extent_Offset, e.Size as Extent_Size, e.Block_Num as Extent_Block_Num, " \
                " c.Uncompressed_size, c.Data, c.Extent_Logical_Size, "\
                " e_c.Offset as compressed_Extent_Offset, e_c.Size as compressed_Extent_Size, e_c.Block_Num as compressed_Extent_Block_Num"\
                " from {0}_Paths as p "\
                " left join {0}_Inodes as t on t.CNID = p.CNID "\
                " left join {0}_IndexNodes as i on i.CNID = p.CNID "\
                " left join {0}_Extents as e on e.CNID = t.Extent_CNID "\
                " left join {0}_Compressed_Files as c on c.CNID = t.CNID "\
                " left join {0}_Extents as e_c on e_c.CNID = c.Extent_CNID "\
                " {1} "\
                " order by p.CNID, Extent_Offset, compressed_Extent_Offset"
        # This query gets file metadata as well as extents for file. If compressed, it gets compressed extents.
        success, cursor, error_message = db.RunQuery(query.format(self.name, where_clause))
        if success:
            apfs_file_meta = None
            #extent_cnid = 0
            index = 0
            prev_extent = None
            last_cnid = 0
            for row in cursor:
                if last_cnid == row[0]: # same file
                    pass
                else:                  # new file
                    if last_cnid:      # save old info
                        apfs_file_meta_list.append(apfs_file_meta)
                    index = 0
                    last_cnid = row[0]
                    prev_extent = None

                if index == 0:
                    apfs_file_meta = ApfsFileMeta(row[4], row[1], row[0], row[2], CommonFunctions.ReadAPFSTime(row[5]), \
                                        CommonFunctions.ReadAPFSTime(row[6]), CommonFunctions.ReadAPFSTime(row[7]), \
                                        CommonFunctions.ReadAPFSTime(row[8]), \
                                        CommonFunctions.ReadAPFSTime(row[18]), \
                                        row[9], row[10], row[11], row[12], row[13], row[14], row[15], row[16], row[17])
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
            #if index == 0: # No such file!
            #    return None
            # Let's also get Attributes, except decmpfs and ResourceFork (we already got those in _Compressed_Files table)
            #  Skipping this for now.
            # TODO: Remove Logical_uncompressed_size, Extent_CNID, perhaps not needed now!
            # attrib_query = "SELECT Name, Flags, Data, Logical_uncompressed_size, Extent_CNID from {0}_Attributes "\
            #                 "WHERE cnid={1} and Name not in ('com.apple.decmpfs', 'com.apple.ResourceFork')"
            # success, cursor, error_message = db.RunQuery(attrib_query.format(self.name, apfs_file_meta.cnid))
            # if success:
            #     for row in cursor:
            #         apfs_file_meta.attributes[row[0]] = [row[1], row[2], row[3], row[4]]
            # else:
            #     log.debug('Failed to execute attribute query, error was : ' + error_message)
            #return apfs_file_meta

            # get last one
            if apfs_file_meta:
                apfs_file_meta_list.append(apfs_file_meta)
        else:
            log.debug('Failed to execute GetFileMetadata query, error was : ' + error_message)

        return apfs_file_meta_list

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
                " c.Uncompressed_size, i.DateAdded "\
                " from {0}_Paths as p "\
                " left join {0}_Inodes as t on p.cnid=t.cnid  "\
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
                    if row[2] == 4:    item['type'] = 'Folder'
                    elif row[2] == 8:  item['type'] = 'File'
                    elif row[2] == 10: item['type'] = 'Symlink'
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
        if self.fletcher64_verify_block_num(0) != 0:
            log.warning("Superblock checksum failed! Still trying to parse checkpoints to find valid csb!")

        # Scanning checkpoints to get valid CSB
        base_cp_block_num = self.containersuperblock.body.xp_desc_base
        num_cp_blocks = self.containersuperblock.body.xp_desc_blocks
        if num_cp_blocks & 0x80000000: # highest bit set in xp_desc_blocks
            raise ValueError("Encountered a tree in checkpoint data, this is not yet implemented!")

        checkpoint_blocks = [self.read_block(base_cp_block_num + i) for i in range(num_cp_blocks)]

        max_xid = 0
        max_xid_cp_index = 0

        for index, cp in enumerate(checkpoint_blocks):
            if cp.header.type_block.value == 1: # containersuperblock
                if cp.header.xid >= max_xid:
                    if self.fletcher64_verify_block_num(base_cp_block_num + index) == 0:
                        max_xid = cp.header.xid
                        max_xid_cp_index = index
                    else:
                        log.error('Block {} failed checksum'.format(base_cp_block_num + index))
        if max_xid > self.containersuperblock.header.xid:
            log.info("Found newer xid={} @ block num {}".format(max_xid, base_cp_block_num + max_xid_cp_index))
            log.info("Using new XID now..")
            self.containersuperblock = cp[max_xid_cp_index]

        # get list of volume ids
        apfss = [x for x in self.containersuperblock.body.volumesuperblock_ids if x != 0 ] # removing the invalid ones
        omap_oid = self.containersuperblock.body.omap_oid
        self.num_volumes = len(apfss)

        log.debug("There are {} volumes in this container".format(self.num_volumes))
        log.debug("Volume Block IDs: %s, Mapping-omap: %d" % (apfss, omap_oid))

        block_map = self.read_block(omap_oid)
        self.apfs_locations = {}
        block_map_omap_root = self.read_block(block_map.body.tree_oid)
        for _, entry in enumerate(block_map_omap_root.body.entries):
            self.apfs_locations[entry.key.oid] = entry.data.paddr.value
        log.debug("Volume Blocks:" + str(self.apfs_locations))
        index = 1
        for _, volume_block_num in self.apfs_locations.items():
            volume = ApfsVolume(self, 'Vol_' + str(index))
            volume.read_volume_info(volume_block_num)
            self.volumes.append(volume)
            index += 1

    def close(self):
        pass

    def seek(self, offset, whence=0):
        if whence == 0: # Beginning of file
            self.position = offset
        elif whence == 1: # current position
            self.position += offset
        elif whence == 2: # end of file (offset must be -ve)
            self.position = self.apfs_container_size + offset
        else:
            raise Exception('Unexpected value in whence (only 0,1,2 are allowed), value was ' + str(whence))

    def tell(self):
        return self.position

    def read(self, size):
        data = self.img.read(self.apfs_container_offset + self.position, size)
        #self.debug_last_block_read_pos = self.apfs_container_offset + self.position
        #log.debug("debug_last_block_read_pos={}".format(self.debug_last_block_read_pos))
        self.position += len(data)
        return data

    def get_block(self, idx):
        """ Get data of a single block """
        self.seek(idx * self.block_size)
        return self.read(self.block_size)

    def read_block(self, block_num):
        """ Parse a singe block """
        data = self.get_block(block_num)
        if not data:
            return None
        block = self.apfs.Block(KaitaiStream(BytesIO(data)), self.apfs, self.apfs)
        return block
    
    def fletcher64_verify_block_num(self, block_num):
        """Fletchers checksum verification for block, given block number"""
        data = self.get_block(block_num)
        if not data:
            return None
        return self.fletcher64_verify_block_data(data, self.block_size)

    def fletcher64_verify_block_data(self, data, block_size):
        """Fletchers checksum verification for block given block data"""
        cnt = block_size//4 - 2
        data = struct.unpack('<{}I'.format(block_size//4), data)
        data_first_two_dwords = data[0:2]
        data_rest = data[2:]

        sum1 = 0
        sum2 = 0

        for k in range(cnt):
            sum1 += data_rest[k]
            sum2 += sum1

        sum1 = sum1 % 0xFFFFFFFF
        sum2 = sum2 % 0xFFFFFFFF

        # process first 2 dwords now
        sum1 += data_first_two_dwords[0]
        sum2 += sum1
        sum1 += data_first_two_dwords[1]
        sum2 += sum1

        sum1 = sum1 % 0xFFFFFFFF
        sum2 = sum2 % 0xFFFFFFFF

        return ((sum2) << 32) | (sum1)

class ApfsExtent:
    __slots__ = ['offset', 'size', 'block_num']

    def __init__(self, offset, size, block_num):
        self.offset = offset
        self.size = size
        self.block_num = block_num

    def GetData(self, container):
        container.seek(self.block_num * container.block_size)
        ## TODO: Create buffered read, in case of really large files!!
        return container.read(self.size)
    
    def GetSomeData(self, container, max_size=41943040): # max 40MB
        try:
            container.seek(self.block_num * container.block_size)
            # return data in chunks of max_size
            if self.size <= max_size:
                yield container.read(self.size)
            else:
                num_full_pieces = self.size // max_size
                for i in range(num_full_pieces):
                    yield container.read(max_size)
                if self.size % max_size:
                    yield container.read(self.size % max_size)
        except GeneratorExit:
            pass

class ApfsFile():
    def __init__(self, apfs_file_meta, logical_size, extents, apfs_container):
        self.meta = apfs_file_meta
        self.file_size = logical_size
        self.extents = extents
        self.container = apfs_container
        self.closed = False
        self._pointer = 0
        self._buffer = b''
        self._buffer_start = 0

    def _GetDataFromExtents(self, extents, total_size):
        '''Retrieves data from extents'''
        content = b''
        if total_size == 0: 
            return content
        bytes_left = total_size
        for extent in extents:
            if bytes_left <= 0:
                # Not so uncommon in reality! For files that grow and shrink, APFS does not reclaim clusters immediately.
                log.debug ("mismatch between logical size and extents!")
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

    def _GetSomeDataFromExtents(self, extents, total_size, offset, size):
        '''Retrieves data from extents, corresponding to a file offset and specific size
           It is assumed that size and offset values are sanitized and fall within
           the range of logical file content
        '''
        content = b''
        ext_content = b''
        if total_size == 0: 
            return content
        bytes_left_in_file = total_size
        bytes_consumed = 0
        desired_size = size

        break_main_loop = False
        for extent in extents:
            if bytes_left_in_file <= 0:
                # Not so uncommon in reality! For files that grow and shrink, APFS does not reclaim clusters immediately.
                log.debug ("mismatch between logical size and extents!")
                break
            data_len = extent.size
            if (bytes_consumed <= offset):
                if offset >= (bytes_consumed + data_len):
                    # not in range yet
                    bytes_consumed += data_len
                    bytes_left_in_file -= data_len
                else:
                    # reached desired start offset
                    extent_slice_consumed = 0
                    for data in extent.GetSomeData(self.container):
                        start_pos = offset - bytes_consumed - extent_slice_consumed
                        if start_pos >= len(data): # Case when extent slicing results in this, we only want let's say 3rd yield onwards!
                            extent_slice_consumed += len(data)
                            continue
                        ext_content = data[start_pos : start_pos + size] # Perhaps return full buffer, let caller truncate buffer!
                        content += ext_content
                        ext_content_len = len(ext_content)
                        
                        if ext_content_len == size: # will be <= size
                            break_main_loop = True
                            break
                        else:
                            offset += ext_content_len
                            size -= ext_content_len
                            extent_slice_consumed += len(data) #ext_content_len 

                    bytes_consumed += data_len
                    bytes_left_in_file -= data_len
                    if break_main_loop: break
            else:
                log.debug('Should it ever be here?? bytes_consumed={} offset={}, file={} cnid={}'.format(bytes_consumed, offset, self.meta.name, self.meta.cnid))
                break
        if len(content) != desired_size:
            log.error ("Error, could not get some pieces of file={} cnid={} len(content)={} desired_size={}".format(self.meta.name, self.meta.cnid, len(content), desired_size))
        return content

    def readAll(self):
        '''return entire file in one buffer'''
        self.closed = False
        file_content = b''
        if self.meta.is_symlink: # if symlink, return symlink  path as data
            file_content = self.meta.attributes['com.apple.fs.symlink'][1]
        #elif self.meta.is_compressed:
        #    file_content = self._readCompressedAll() #moved to ApfsFileCompressed
        else:
            file_content = self._GetDataFromExtents(self.extents, self.meta.logical_size)
        self.closed = True
        return file_content

    def _check_closed(self):
        if self.closed:
            raise ValueError("File is closed!")

    # file methods
    def close(self):
        self.closed = True
        self._buffer = None
        self._buffer_start = 0

    def tell(self):
        self._check_closed()
        return self._pointer

    def seek(self, offset, whence=0):
        self._check_closed()
        if whence == 0:   # absolute
            self._pointer = offset
        elif whence == 1: # relative
            self._pointer += offset
        elif whence == 2: # relative to file's end
            self._pointer = self.file_size + offset

    def read(self, size_to_read=None):
        self._check_closed()
        avail_to_read = self.file_size - self._pointer
        if avail_to_read <= 0: # at or beyond the end of file
            return b''
        if (size_to_read is None) or (size_to_read > avail_to_read):
            size_to_read = avail_to_read
        data = b''
        original_file_pointer = self._pointer
        buffer_len = len(self._buffer)
        if buffer_len:
            if  (self._pointer >= self._buffer_start) and \
                (self._pointer < (self._buffer_start + buffer_len) ):
                # Data requested (or part of it) is in our cached buffer
                start_pos = self._pointer - self._buffer_start
                data = self._buffer[start_pos : start_pos + min(size_to_read, buffer_len)]
                self._pointer += len(data)
                if size_to_read <= buffer_len: # got all required data
                    return data
                else:                          # still more data needed!
                    size_to_read -= len(data)
                    self._buffer = data

        if self.meta.is_symlink: # if symlink, return symlink  path as data
            data += self.meta.attributes['com.apple.fs.symlink'][1][0:size_to_read]
        else:
            data += self._GetSomeDataFromExtents(self.extents, self.meta.logical_size, self._pointer, size_to_read)

        self._buffer_start = original_file_pointer
        self._pointer += len(data)
        self._buffer = data
        return data

class LzvnCompressionParams(object):
    def __init__(self, header_size, chunk_offsets, uncompressed_size):
        self.header_size = header_size
        self.chunk_offsets = chunk_offsets
        self.num_blocks = len(chunk_offsets)
        self.chunk_info = [] # [ [chunk_offset, chunk_size, uncomp_offset_start, uncomp_offset_end], .. ] List of lists
        uncomp_offset_start = 0
        i = 1
        src_offset = header_size
        for offset in chunk_offsets:
            compressed_size = offset - src_offset
            if self.num_blocks == i: # last block
                uncomp_offset_end = uncompressed_size
                if uncomp_offset_end - uncomp_offset_start <= 0 or uncomp_offset_end - uncomp_offset_start > 65536:
                    log.error("Problem reading LZVN offsets, looks like corrupted data!")
            else:
                uncomp_offset_end = uncomp_offset_start + 65536
            self.chunk_info.append([src_offset, compressed_size, uncomp_offset_start, uncomp_offset_end])
            src_offset = offset
            uncomp_offset_start += 65536
            i += 1

class ZlibCompressionParams(object):
    def __init__(self, header_size, total_size, data_size, flags, blocks_data_size, num_blocks):
        self.header_size = header_size
        self.total_size = total_size
        self.data_size = data_size
        self.flags = flags
        self.blocks_data_size = blocks_data_size
        self.num_blocks = num_blocks
        self.chunk_info = [] # [ [chunk_offset, chunk_size, uncomp_offset_start, uncomp_offset_end], .. ] List of lists

class ApfsFileCompressed(ApfsFile):
    def __init__(self, apfs_file_meta, logical_size, extents, apfs_container):
        super().__init__(apfs_file_meta, logical_size, extents, apfs_container)
        self.data_is_inline = (self.meta.decmpfs == None) # header & data in extent, data is inline with header
        self.compressed_header = None
        self.magic = None
        self.compression_type = None
        self.uncompressed_size = logical_size
        if apfs_file_meta.compressed_extent_size:
            self.file_size = apfs_file_meta.compressed_extent_size # Needed, so base class can read compressed extents

        # Following will store info/data about uncompressed stream, the base class will store compressed data
        self.uncomp_pointer = 0
        self.uncomp_buffer = b''
        self.uncomp_buffer_start = 0
        self.lzvn_info = None
        self.zlib_info = None

    def getChunkList(self, chunk_info, req_offset, req_size):
        '''Returns a list of chunk_info based on required uncompressed offset and size'''
        ret_list = []
        start_found = False
        end_found = False
        req_offset_end = req_offset + req_size
        for chunk_offset, chunk_size, uncomp_offset_start, uncomp_offset_end in chunk_info:
            if not start_found:
                if uncomp_offset_start <= req_offset:
                    if req_offset < uncomp_offset_end:
                        # start found in this chunk
                        ret_list.append([chunk_offset, chunk_size, uncomp_offset_start, uncomp_offset_end])
                        start_found = True
                        if req_offset_end <= uncomp_offset_end:
                            end_found = True
                            break
                    else:
                        continue
                else:
                    log.debug("should not go here getChunkList()...")
                    break
            # looking for end
            else: # if not end_found:
                if uncomp_offset_start < req_offset_end:
                    if req_offset_end <= uncomp_offset_end:
                        # end found in this chunk
                        ret_list.append([chunk_offset, chunk_size, uncomp_offset_start, uncomp_offset_end])
                        end_found = True
                        break
                    else:
                        # not the end, but an intermediate block
                        ret_list.append([chunk_offset, chunk_size, uncomp_offset_start, uncomp_offset_end])
                else:
                    log.debug("should not go here getChunkList()....")
        return ret_list

    def _lzvn_decompress(self, compressed_stream, compressed_size, uncompressed_size):
        '''
            Adds Prefix and Postfix bytes as required by decompressor, 
            then decompresses and returns uncompressed bytes buffer
        '''
        header = b'bvxn' + struct.pack('<I', uncompressed_size) + struct.pack('<I', compressed_size)
        footer = b'bvx$'
        decompressed_stream = lzfse.decompress(header + compressed_stream + footer)
        len_dec = len(decompressed_stream)
        if len_dec != uncompressed_size:
            log.error("_lzvn_decompress ERROR - decompressed_stream size is incorrect! Decompressed={} Expected={}. Padding stream with nulls".format(len_dec, uncompressed_size))
            decompressed_stream += b'\x00'*(uncompressed_size - len_dec)
        return decompressed_stream

    def _readCompressedAll(self):
        '''Read all compressed data in a file'''
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

    def _readCompressed(self, size): #TODO complete
        '''Read compressed data given offset and size'''
        file_content = b''
        decmpfs = self.meta.decmpfs
        #if decmpfs == None: # header & data in extent, data is inline with header
        if self.data_is_inline:
            decmpfs = self._GetDataFromExtents(self.extents, self.meta.compressed_extent_size)
            # Now decompress it according to compression_type
            file_content = self._DecompressInline(decmpfs)
            self.uncomp_buffer = file_content # Buffer has whole file
            self.uncomp_buffer_start = 0
        else: # we already have header, data is in extent or inline
            extent_data_size = self.meta.compressed_extent_size
            if extent_data_size == 0:   # data is inline
                file_content = self._DecompressInline(decmpfs)
                self.uncomp_buffer = file_content # Buffer has whole file
                self.uncomp_buffer_start = 0
            else:                       # data is in extent (resource fork)
                # First read the header size first from 1st extent block, then read all those extent blocks
                if self.compressed_header == None: # read compressed header
                    compressed_header = self._GetSomeDataFromExtents(self.extents, extent_data_size, 0, min(extent_data_size, 8192)) # replace with super().read() ??
                    self.magic, self.compression_type, self.uncompressed_size = struct.unpack('<IIQ', decmpfs[0:16])
                    if self.compression_type == 4:   # zlib in ResourceFork
                        # Read Header (HFSPlusCmpfRsrcHead)
                        header_size, total_size, data_size, flags = struct.unpack('>IIII', compressed_header[0:16])
                        # Read Block info
                        blocks_data_size = struct.unpack('>I', compressed_header[header_size : header_size + 4])[0]
                        num_blocks = struct.unpack('<I', compressed_header[header_size + 4 : header_size + 8])[0]
                        base_offset = header_size + 8
                        self.zlib_info = ZlibCompressionParams(header_size, total_size, data_size, flags, blocks_data_size, num_blocks)

                        # Calculate if we need to read more extents to read all chunk info
                        farthest_pos = base_offset + (num_blocks - 1)*8 + 8
                        if farthest_pos > 8192: # fetch more data
                            compressed_header += self._GetSomeDataFromExtents(self.extents, extent_data_size, 8192, min(extent_data_size, farthest_pos))
                        # Read chunks
                        uncomp_offset_start = 0
                        for i in range(num_blocks):
                            chunk_offset, chunk_size = struct.unpack('<II', compressed_header[base_offset + i*8 : base_offset + i*8 + 8])
                            if i == num_blocks - 1: # last block
                                uncomp_offset_end = uncomp_offset_start + (self.uncompressed_size % 65536)
                            else:
                                uncomp_offset_end = uncomp_offset_start + 65536
                            self.zlib_info.chunk_info.append([header_size + 4 + chunk_offset, chunk_size, uncomp_offset_start, uncomp_offset_end])
                            uncomp_offset_start += 65536
                    elif self.compression_type == 8: # lzvn in ResourceFork
                        headerSize = struct.unpack('<I', compressed_header[0:4])[0]
                        num_chunkOffsets = headerSize//4 - 1

                        # Calculate if we need to read more extents to read all chunk info
                        farthest_pos = headerSize
                        if farthest_pos > 8192: # fetch more data
                            compressed_header += self._GetSomeDataFromExtents(self.extents, extent_data_size, 8192, min(extent_data_size, farthest_pos))
                        chunkOffsets = struct.unpack('<{}I'.format(num_chunkOffsets), compressed_header[4 : 4 + (num_chunkOffsets * 4)])
                        self.lzvn_info = LzvnCompressionParams(headerSize, chunkOffsets, self.uncompressed_size)
                
                # Read compressed_data chunks and decrypt them
                decompressed = b''
                req_start = self.uncomp_pointer
                if self.compression_type == 4:   # zlib
                   # Determine chunks to decryt
                    chunks_to_decompress = self.getChunkList(self.zlib_info.chunk_info, req_start, size)
                    for chunk_offset, chunk_size, uncomp_offset_start, uncomp_offset_end in chunks_to_decompress:
                        super().seek(self.zlib_info.header_size + 4 + chunk_offset)
                        compressed_data = super().read(chunk_size)
                        if compressed_data[0] == 0xFF:
                            decompressed += compressed_data[1 : chunk_size]
                        else:
                            decompressed += zlib.decompress(compressed_data)
                elif self.compression_type == 8: # lzvn
                    chunks_to_decompress = self.getChunkList(self.lzvn_info.chunk_info, req_start, size)
                    for chunk_offset, chunk_size, uncomp_offset_start, uncomp_offset_end in chunks_to_decompress:
                        super().seek(chunk_offset)
                        compressed_data = super().read(chunk_size)
                        if compressed_data[0] == 0x06:
                            decompressed += compressed_data[1:]
                        else:
                            decompressed += self._lzvn_decompress(compressed_data, chunk_size, uncomp_offset_end - uncomp_offset_start)

                # got all decompressed data, now slice to required part
                buffer_start = chunks_to_decompress[0][2]
                if buffer_start == req_start: pass # OK
                elif buffer_start < req_start:
                    decompressed = decompressed[req_start - buffer_start : req_start - buffer_start + size]
                else:
                    log.error("Should not be here buffer_start > req_start")

                file_content = decompressed

        #self.uncomp_buffer = file_content # TODO
        #self.uncomp_buffer_start = 0
        return file_content

    def _DecompressNotInline(self, decmpfs, compressed_data):
        decompressed = b''
        magic, compression_type, uncompressed_size = struct.unpack('<IIQ', decmpfs[0:16])
        if compression_type == 4: # zlib in ResourceFork
            # Read Header (HFSPlusCmpfRsrcHead)
            header_size, total_size, data_size, flags = struct.unpack('>IIII', compressed_data[0:16])
            # Read Block info
            blocks_data_size = struct.unpack('>I', compressed_data[header_size : header_size + 4])[0]
            num_blocks = struct.unpack('<I', compressed_data[header_size + 4 : header_size + 8])[0]
            base_offset = header_size + 8
            # Read chunks
            for i in range(num_blocks):
                chunk_offset, chunk_size = struct.unpack('<II', compressed_data[base_offset + i*8 : base_offset + i*8 + 8])
                #log.debug("ChunkOffset={} ChunkSize={} start={} end={}".format(chunk_offset, chunk_size, header_size + 4 + chunk_offset, header_size + 4 + chunk_offset + chunk_size))
                start = header_size + 4 + chunk_offset
                if compressed_data[start] == 0xFF:
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
                num_chunkOffsets = headerSize//4  - 1
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
                    if chunk_uncomp < compressed_size and data[0] == 0x06:
                        decompressed += data[1:]
                    else:
                        decompressed += self._lzvn_decompress(data, compressed_size, chunk_uncomp)
                    i += 1
            except Exception as ex:
                log.exception("Exception from lzfse.decompress, decompression failed!")
                raise Exception("Exception from lzfse.decompress, decompression failed!")
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
        total_len = len(decmpfs)
        magic, compression_type, uncompressed_size = struct.unpack('<IIQ', decmpfs[0:16])

        if compression_type == 1:
            decompressed = decmpfs[16:]
        elif compression_type == 3: # zlib
            if (uncompressed_size <= total_len - 16) and (decmpfs[16] == 0xFF):
                decompressed = decmpfs[17:]
            else:
                decompressed = zlib.decompress(decmpfs[16:])
        elif compression_type in [4, 8, 12]: # types in ResourceFork
            log.error ("compression_type = {} in DecompressInline --> ERROR! Should not go here!".format(compression_type))
        elif compression_type == 7: # LZVN inline
            data = decmpfs[16:]
            if (uncompressed_size <= total_len - 16) and (data[0] == 0x06):
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

    def readAll(self):
        '''return entire file in one buffer'''
        self.closed = False
        file_content = b''
        if self.meta.is_symlink: # if symlink, return symlink  path as data
            file_content = self.meta.attributes['com.apple.fs.symlink'][1]
            log.error("This should not happen, compressed + symlink? symlink={}".format(file_content))
        else:
            file_content = self._readCompressedAll()

        self.closed = True
        return file_content

    def close(self):
        self.uncomp_pointer = None
        self.uncomp_buffer_start = 0
        self.uncomp_buffer = None
        super().close()

    def tell(self):
        self._check_closed()
        return self.uncomp_pointer

    def seek(self, offset, whence=0):
        self._check_closed()
        if whence == 0:   # absolute
            self.uncomp_pointer = offset
        elif whence == 1: # relative
            self.uncomp_pointer += offset
        elif whence == 2: # relative to file's end
            self.uncomp_pointer = self.uncompressed_size + offset

    def read(self, size_to_read=None):
        self._check_closed()
        avail_to_read = self.uncompressed_size - self.uncomp_pointer
        if avail_to_read <= 0: # at or beyond the end of file
            return b''
        if size_to_read is None:
            size_to_read = avail_to_read
        data = b''
        original_file_pointer = self.uncomp_pointer
        buffer_len = len(self.uncomp_buffer)
        if buffer_len:
            if  (self.uncomp_pointer >= self.uncomp_buffer_start) and \
                (self.uncomp_pointer < (self.uncomp_buffer_start + buffer_len) ):
                # Data requested (or part of it) is in our cached buffer
                start_pos = self.uncomp_pointer - self.uncomp_buffer_start
                data = self.uncomp_buffer[start_pos : start_pos + min(size_to_read, buffer_len)]
                self.uncomp_pointer += len(data)
                if size_to_read <= buffer_len: # got all required data
                    return data
                else:                          # still more data needed!
                    size_to_read -= len(data)
                    self.uncomp_buffer = data

        if self.meta.is_symlink: # if symlink, return symlink  path as data 
            data += self.meta.attributes['com.apple.fs.symlink'][1][0:size_to_read]
            log.error("This should not happen, compressed + symlink?")
        
        # If file is < 10MB, read entire file
        if self.uncompressed_size < 10485760:
            self.uncomp_buffer = self._readCompressedAll()
            self.uncomp_buffer_start = 0
            data = self.uncomp_buffer[self.uncomp_pointer : self.uncomp_pointer + size_to_read]
            self.uncomp_pointer += len(data)
            return data
        else:
            data += self._readCompressed(size_to_read) # TODO

        self.uncomp_buffer_start = original_file_pointer
        self.uncomp_pointer += len(data)
        self.uncomp_buffer = data 
        return data

class ApfsFileMeta:
    def __init__(self, name, path, cnid, parent_cnid, created, modified, changed, accessed, index_time, flags, links, bsd_flags, uid, gid, mode, logical_size, physical_size, item_type):
        self.name = name
        self.path = path
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

