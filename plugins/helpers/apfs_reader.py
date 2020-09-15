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
import liblzfse
import struct
import zlib
from uuid import UUID
from plugins.helpers.writer import DataType
from plugins.helpers.common import *
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

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

    def __init__(self, db_writer):
        self.db_writer = db_writer # SqliteWriter object
        self.version = 6 # This will change if db structure changes in future
        self.ver_table_name = 'Version_Info'
        self.vol_table_name = 'Volumes_Info'
        self.version_info = collections.OrderedDict([('Version',DataType.INTEGER)])
        self.volume_info = collections.OrderedDict([('Name',DataType.TEXT),('UUID',DataType.TEXT),
                                                    ('Files',DataType.INTEGER),('Folders',DataType.INTEGER),
                                                    ('Snapshots',DataType.INTEGER),
                                                    ('Created',DataType.INTEGER),('Updated',DataType.INTEGER),
                                                    ('Role',DataType.INTEGER),('VEK',DataType.BLOB)])

    def WriteVersionInfo(self):
        self.db_writer.CreateTable(self.version_info, self.ver_table_name)
        data = [self.version]
        self.db_writer.WriteRow(data)

    def WriteVolInfo(self, volumes):
        '''Write volume info to seperate table'''
        self.db_writer.CreateTable(self.volume_info, self.vol_table_name)
        data = []
        for vol in volumes:
            data.append([vol.volume_name, vol.uuid, vol.num_files, vol.num_folders, vol.num_snapshots, 
                        vol.time_created, vol.time_updated, vol.role, vol.encryption_key])
        self.db_writer.WriteRows(data, self.vol_table_name)

    def CheckVerInfo(self):
        '''Returns true if info in db matches current version number'''
        query = 'SELECT Version FROM "{}"'.format(self.ver_table_name)
        success, cursor, error = self.db_writer.RunQuery(query)
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

    def CheckVolInfoAndGetVolEncKey(self, volumes):
        '''Returns true if info in db matches volume objects'''
        query = 'SELECT Name, UUID, Files, Folders, Snapshots, Created, Updated, Role, VEK FROM "{}"'.format(self.vol_table_name)
        success, cursor, error = self.db_writer.RunQuery(query)
        index = 0
        data_is_unaltered = True
        if success:
            for row in cursor:
                if row[0] != volumes[index].volume_name or \
                    row[1] != volumes[index].uuid or \
                    row[2] != volumes[index].num_files or \
                    row[3] != volumes[index].num_folders or \
                    row[4] != volumes[index].num_snapshots or \
                    row[5] != volumes[index].time_created or \
                    row[6] != volumes[index].time_updated or \
                    row[7] != volumes[index].role :
                        data_is_unaltered = False
                        log.info('DB volume info does not match file info! Checked {}'.format(volumes[index].name))
                        break
                if row[8]:
                    volumes[index].encryption_key = row[8]
                    volumes[index].SetupDecryption(row[8])
                index += 1
        else:
            log.error('Error querying volume info from db: ' + error)

        return index == len(volumes) and data_is_unaltered

class ApfsFileSystemParser:
    '''
    Reads and parses the file system, writes output to a database.
    '''
    def __init__(self, apfs_volume, db_writer):
        self.name = apfs_volume.name
        self.volume = apfs_volume
        self.container = apfs_volume.container
        self.dbo = db_writer
        self.encryption_key = apfs_volume.encryption_key

        self.num_records_read_total = 0
        self.num_records_read_batch = 0

        self.hardlink_records = []
        self.extent_records = []
        self.inode_records = []
        self.dir_records = []
        self.attr_records = []
        self.dir_stats_records = []
        
        self.hardlink_info = collections.OrderedDict([('XID',DataType.INTEGER),('CNID',DataType.INTEGER), ('Parent_CNID',DataType.INTEGER), 
                                                    ('Name',DataType.TEXT),('Valid',DataType.INTEGER),('DB_ID',(DataType.INTEGER,"PRIMARY KEY AUTOINCREMENT"))])
        self.extent_info = collections.OrderedDict([('XID',DataType.INTEGER),('CNID',DataType.INTEGER), ('Offset',DataType.INTEGER), 
                                                    ('Size',DataType.INTEGER), ('Block_Num',DataType.INTEGER),
                                                    ('Valid',DataType.INTEGER),('DB_ID',(DataType.INTEGER,"PRIMARY KEY AUTOINCREMENT"))])
        self.attr_info = collections.OrderedDict([('XID',DataType.INTEGER),('CNID',DataType.INTEGER), ('Name',DataType.TEXT),
                                                    ('Flags',DataType.INTEGER),('Data',DataType.BLOB),
                                                    ('Logical_uncompressed_size',DataType.INTEGER),('Extent_CNID',DataType.INTEGER),
                                                    ('Valid',DataType.INTEGER),('DB_ID',(DataType.INTEGER,"PRIMARY KEY AUTOINCREMENT"))])
        self.inode_info = collections.OrderedDict([('XID',DataType.INTEGER),('CNID',DataType.INTEGER), ('Parent_CNID',DataType.INTEGER),
                                                     ('Extent_CNID',DataType.INTEGER), ('Name',DataType.TEXT), ('Created',DataType.INTEGER), 
                                                     ('Modified',DataType.INTEGER), ('Changed',DataType.INTEGER), ('Accessed',DataType.INTEGER), 
                                                     ('Flags',DataType.INTEGER), ('Links_or_Children',DataType.INTEGER), ('BSD_flags',DataType.INTEGER), 
                                                     ('UID',DataType.INTEGER), ('GID',DataType.INTEGER), ('Mode',DataType.INTEGER), 
                                                     ('Logical_Size',DataType.INTEGER), ('Physical_Size',DataType.INTEGER),
                                                     ('Valid',DataType.INTEGER),('DB_ID',(DataType.INTEGER,"PRIMARY KEY AUTOINCREMENT"))])
        self.dir_info = collections.OrderedDict([('XID',DataType.INTEGER),('CNID',DataType.INTEGER), ('Parent_CNID',DataType.INTEGER),
                                                    ('DateAdded',DataType.INTEGER),('ItemType',DataType.INTEGER), 
                                                    ('Name',DataType.TEXT),('Valid',DataType.INTEGER),('DB_ID',(DataType.INTEGER,"PRIMARY KEY AUTOINCREMENT"))])
        self.compressed_info = collections.OrderedDict([('XID',DataType.INTEGER),('CNID',DataType.INTEGER),('Data',DataType.BLOB),('Uncompressed_size',DataType.INTEGER),
                                                    ('Extent_CNID',DataType.INTEGER),('fpmc_in_extent',DataType.INTEGER),('Extent_Logical_Size',DataType.INTEGER),
                                                    ('Valid',DataType.INTEGER),('DB_ID',(DataType.INTEGER,"PRIMARY KEY AUTOINCREMENT"))]) 
                                                    #TODO: Remove fpmc_in_extent, this can be detected by checking Data == None
        self.paths_info = collections.OrderedDict([('CNID',DataType.INTEGER),('Path',DataType.TEXT)])
        self.dir_stats_info = collections.OrderedDict([('XID',DataType.INTEGER),('CNID',DataType.INTEGER),('NumChildren',DataType.INTEGER),('TotalSize',DataType.INTEGER),('Counter',DataType.INTEGER),
                                                    ('Valid',DataType.INTEGER),('DB_ID',(DataType.INTEGER,"PRIMARY KEY AUTOINCREMENT"))]) 
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
        self.container_type_fext_tree = self.container.apfs.ObjType.fext_tree.value
        self.sealed_extent = self.container.apfs.EntryType.sealed_extent.value
        ## End optimization

        self.debug_stats = {}

    def create_linked_volume_tables(self, sys_vol, data_vol, firmlink_paths, firmlinks):
        is_beta = False
        for source, dest in firmlinks.items():
            if source[1:] != dest: # perhaps Beta version of Catalina!
                is_beta = True
                raise ValueError('Is this macOS Catalina BETA (pre-release) version? '\
                    'mac_apt does not have Firmlink support for this version as the '\
                    'scheme is different, and inode numbers aren\'t unique between volumes.')
        
        if not self.run_query('PRAGMA case_sensitive_like = true', False): return False
        paths = ['"' + x + '"' for x in firmlink_paths]
        get_firmlink_cnids_query = ' SELECT p.CNID, Parent_CNID, p.Path FROM "{0}_Paths" p'\
                        ' INNER JOIN "{0}_Inodes" i ON p.CNID=i.CNID'\
                        ' WHERE PATH IN ({1});'.format(sys_vol.name, ",".join(paths))
        
        success, cursor, error = self.dbo.RunQuery(get_firmlink_cnids_query, writing=False)
        sys_inode_paths_and_parents = {} # { inode : parent, inode2 : parent2, .. }
        if success:
            cnids = '1,2,3'
            for row in cursor:
                cnids += "," + str(row[0])
                parent = str(row[1])
                path = row[2]
                sys_inode_paths_and_parents[path] = parent
        else:
            log.error('Failed to get CNIDs for firmlinks. Error was : ' + error)
            return False
        self.create_tables()
        hardlinks_columns = ','.join([x for x in self.hardlink_info][:-1])
        extents_columns = ','.join([x for x in self.extent_info][:-1])
        attributes_columns = ','.join([x for x in self.attr_info][:-1])
        inodes_columns = ','.join([x for x in self.inode_info][:-1])
        dir_entries_columns = ','.join([x for x in self.dir_info][:-1])
        dir_stats_columns = ','.join([x for x in self.dir_stats_info][:-1])
        compressed_files_columns = ','.join([x for x in self.compressed_info][:-1])
        paths_columns = ','.join([x for x in self.paths_info])

        view_query = 'INSERT INTO "{4}_{0}" '\
                    'select {5} FROM ('\
                    'select * from "{1}_{0}" UNION ALL '\
                    'select * from "{2}_{0}" WHERE cnid not in ({3}) )'
        for table_type, columns in collections.OrderedDict([('Hardlinks', hardlinks_columns + ',NULL'),('Extents', extents_columns + ',NULL'),
                ('Attributes', attributes_columns + ',NULL'), ('Inodes', inodes_columns + ',NULL'), ('DirEntries', dir_entries_columns + ',NULL'),
                ('DirStats', dir_stats_columns + ',NULL'), ('Compressed_Files', compressed_files_columns + ',NULL'), 
                ('Paths', paths_columns)]).items():
            query = view_query.format(table_type, data_vol.name, sys_vol.name, cnids, self.name, columns)
            if not self.run_query(query, True): return False
        # if is_beta:
        #     # Just a dumb hack, remove all '/Device' from the start of all paths.
        #     query = 'UPDATE "{0}_Paths" SET Path = substr(Path, 8) WHERE Path LIKE "/Device/%"'.format(self.name)
        #     if not self.run_query(query, True): return False

        query_inodes = 'UPDATE "{}_Inodes" SET Parent_CNID={} WHERE CNID IN '\
                        '(SELECT CNID FROM "{}_Paths" WHERE PATH LIKE {}); '
        query_indexes= 'UPDATE "{}_DirEntries" SET Parent_CNID={} WHERE CNID IN '\
                        '(SELECT CNID FROM "{}_Paths" WHERE PATH LIKE {}); '
        query_hlinks = 'UPDATE "{}_Hardlinks" SET Parent_CNID={} WHERE CNID IN '\
                        '(SELECT CNID FROM "{}_Paths" WHERE PATH LIKE {}); '
        update_query = ''
        for path, parent_cnid in sys_inode_paths_and_parents.items():
            update_query += query_inodes.format(self.name, parent_cnid, data_vol.name, path)
            update_query += query_indexes.format(self.name, parent_cnid, data_vol.name, path)
            update_query += query_hlinks.format(self.name, parent_cnid, data_vol.name, path)

        self.create_indexes()
        return True

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
            self.dbo.WriteRows(self.hardlink_records, self.name + '_Hardlinks')
        if self.extent_records:
            self.dbo.WriteRows(self.extent_records, self.name + '_Extents')
        if self.inode_records:
            self.dbo.WriteRows(self.inode_records, self.name + '_Inodes')
        if self.attr_records:
            self.dbo.WriteRows(self.attr_records, self.name + '_Attributes')
        if self.dir_records:
            self.dbo.WriteRows(self.dir_records, self.name + '_DirEntries')
        if self.dir_stats_records:
            self.dbo.WriteRows(self.dir_stats_records, self.name + '_DirStats')

    def create_tables(self):
        self.dbo.CreateTable(self.hardlink_info, self.name + '_Hardlinks')
        self.dbo.CreateTable(self.extent_info, self.name + '_Extents')
        self.dbo.CreateTable(self.attr_info, self.name + '_Attributes')
        self.dbo.CreateTable(self.inode_info, self.name + '_Inodes')
        self.dbo.CreateTable(self.dir_info, self.name + '_DirEntries')
        self.dbo.CreateTable(self.dir_stats_info, self.name + '_DirStats')
        self.dbo.CreateTable(self.compressed_info, self.name + '_Compressed_Files')
        self.dbo.CreateTable(self.paths_info, self.name + '_Paths')

    def clear_records(self):
        self.hardlink_records = []
        self.extent_records = []
        self.inode_records = []
        self.dir_records = []
        self.attr_records = []
        self.dir_stats_records = []
    
    def create_indexes(self):
        '''Create indexes on cnid and path in database'''
        index_queries = ["CREATE INDEX \"{0}_attribute_cnid\" ON \"{0}_Attributes\" (CNID)".format(self.name),
                         "CREATE INDEX \"{0}_extent_cnid\" ON \"{0}_Extents\" (CNID)".format(self.name),
                         "CREATE INDEX \"{0}_index_cnid\" ON \"{0}_DirEntries\" (CNID)".format(self.name),
                         "CREATE INDEX \"{0}_paths_path_cnid\" ON \"{0}_Paths\" (Path, CNID)".format(self.name),
                         "CREATE INDEX \"{0}_inodes_cnid_parent_cnid\" ON \"{0}_Inodes\" (CNID, Parent_CNID)".format(self.name),
                         "CREATE INDEX \"{0}_compressed_files_cnid\" ON \"{0}_Compressed_Files\" (CNID)".format(self.name),
                         "CREATE INDEX \"{0}_dir_stats_cnid\" ON \"{0}_DirStats\" (CNID)".format(self.name)]
        for query in index_queries:
            success, cursor, error = self.dbo.RunQuery(query, writing=True)
            if not success:
                log.error('Error creating index: ' + error)
                break
    
    def run_query(self, query, writing=True):
        '''Returns True/False on query execution'''
        success, cursor, error = self.dbo.RunQuery(query, writing)
        if not success:
            log.error('Error executing query : Query was {}, Error was {}'.format(query, error))
            return False
        if query.find('DELETE') >= 0:
            rows_deleted = cursor.rowcount
            log.debug('{} rows deleted'.format(rows_deleted))
        return True

    def populate_compressed_files_table(self):
        '''Pre-process all compressed file metadata and populate the compressed file table for quick retieval later'''

        # In APFS, for compressed files, sometimes the compressed header (fpmc) is in the database, at other times
        # it is in an extent. The compressed data is also sometime inline, at other times in an extent. This table 
        # will make the lookup easier as it consolidates the data, thus avoiding multiple queries when fetching 
        # info about a file. Also, we provide the uncompressed size of the file (logical size), so its always 
        # available for listing, without having to go and read an extent.
        # Note - removed 'and a.XID=b.XID' from query as XID will be different for ResourceFork & decmpfs

        #Copy all decmpfs-Type2 attributes to table, where no resource forks <-- Nothing to do, just copy
        type2_no_rsrc_query = "INSERT INTO \"{0}_Compressed_Files\" select b.XID, b.CNID, b.Data, "\
                " b.logical_uncompressed_size, 0 as extent_cnid, 0 as fpmc_in_extent, 0 as Extent_Logical_Size, 0, NULL"\
                " from \"{0}_Attributes\" as b "\
                " left join \"{0}_Attributes\" as a on (a.cnid = b.cnid and a.Name = 'com.apple.ResourceFork') "\
                " where b.Name='com.apple.decmpfs' and (b.Flags & 2)=2 and a.cnid is null".format(self.name)
        if not self.run_query(type2_no_rsrc_query, True):
            return

        #Add all decmpfs-Type2 attributes where resource forks exist, rsrc's extent_cnid is used
        type2_rsrc_query = "INSERT INTO \"{0}_Compressed_Files\" "\
                "SELECT b.XID, b.CNID, b.Data, b.logical_uncompressed_size, a.extent_cnid as extent_cnid, 0 as fpmc_in_extent, "\
                " a.logical_uncompressed_size as Extent_Logical_Size, 0, NULL FROM \"{0}_Attributes\" as b "\
                " left join \"{0}_Attributes\" as a on (a.cnid = b.cnid and a.Name = 'com.apple.ResourceFork')"\
                " where b.Name='com.apple.decmpfs' and (b.Flags & 2)=2 and a.cnid is not null".format(self.name)
        if not self.run_query(type2_rsrc_query, True):
            return
         
        #Process decmpfs-Type1 attributes. Go to extent, read fpmc header to get uncompressed size
        # This query gets extents for decmpfs and rsrc but only the first one, this way there is only
        #  one row returned  for every cnid, and we are also only interested in the first extent.
        #                       0        1                  2                                  3
        type1_query = "select b.XID, b.CNID, b.extent_cnid as decmpfs_ext_cnid,  b.logical_uncompressed_size, "\
                "e.Block_Num as decmpfs_first_ext_Block_num, a.extent_cnid as rsrc_extent_cnid , er.Block_Num as rsrc_first_extent_Block_num, "\
                " a.logical_uncompressed_size as Extent_Logical_Size from \"{0}_Attributes\" as b "\
                " left join \"{0}_Attributes\" as a on (a.cnid = b.cnid and a.Name = 'com.apple.ResourceFork') "\
                " left join \"{0}_Extents\" as e on e.cnid=b.extent_cnid "\
                " left join \"{0}_Extents\" as er on er.cnid=a.extent_cnid "\
                " where b.Name='com.apple.decmpfs' and (b.Flags & 1)=1"\
                " and (e.offset=0 or e.offset is null) and (er.offset = 0 or er.offset is null)".format(self.name)
        success, cursor, error = self.dbo.RunQuery(type1_query, writing=False)
        if success:
            block_size = self.container.apfs.block_size
            to_write = []
            for row in cursor:
                # Go to decmpfs_extent block and read uncompressed size
                logical_size = row[3]
                #decmpfs_ext_cnid = row[2]
                if row[4] is None:
                    log.error('Perhaps a corrupted record in APFS volume, skipping it.'\
                        'From populate_compressed_files_table(). Got NULL for block number')
                    log.error(f'DEBUG values of row = {str(row)}')
                    continue
                decmpfs = self.volume.get_raw_decrypted_block(row[4], self.encryption_key, limit_size=512) # only read first 512 bytes of block
                #magic, compression_type, uncompressed_size = struct.unpack('<IIQ', decmpfs[0:16])
                uncompressed_size = struct.unpack('<Q', decmpfs[8:16])[0]
                #TODO: check magic if magic =='fpmc'
                if row[5] == None:
                    # No resource fork , data must be in decmpfs_extent
                    if logical_size <= 32: # If < 32 bytes, write to db, else leave in extent
                        to_write.append([row[0], row[1], decmpfs, uncompressed_size, 0, 0, 0, 0, None])
                    else:
                        to_write.append([row[0], row[1], None, uncompressed_size, row[2], 1, logical_size, 0, None])
                else: 
                    # resource fork has data
                    to_write.append([row[0], row[1], decmpfs, uncompressed_size, row[5], 0, row[7], 0, None])
            if to_write:
                try:
                    self.dbo.WriteRows(to_write, self.name + '_Compressed_Files')
                except Exception as ex:
                    log.exception(str(to_write) + " Has cased an exception, the exception was: " + str(ex))

        else:
            log.error('Error executing query : Query was {}, Error was {}'.format(type1_query, error))
            return
        
    def read_volume_records(self):
        ''' Get tree oid from omap node and parse all children, add 
            all information to a database.
        '''
        self.create_tables()
        if self.encryption_key:
            self.volume.SetupDecryption(self.encryption_key)

        root_block = self.container.read_block(self.volume.root_block_num)
        self.read_entries(self.volume.root_block_num, root_block)

        if self.volume.is_sealed: # Extents are stored in fext_tree
            extents_tree = self.container.read_block(self.volume.fext_tree_oid)
            self.read_entries(self.volume.fext_tree_oid, extents_tree)

        # write remaining records to db
        if self.num_records_read_batch > 0:
            self.num_records_read_batch = 0

            self.write_records()
            self.clear_records() # Clear the data once written

        self.create_other_tables_and_indexes()
        self.PrintStats()

    def validate_db_entries(self):
        '''Set the Valid flag in db tables for the entries with highest XID (others are stale/old)'''
        query = "UPDATE \"{0}_Attributes\" SET Valid=1 "\
                "WHERE DB_ID IN (SELECT DB_ID FROM ("\
                " SELECT DB_ID, MAX(XID) FROM \"{0}_Attributes\" "\
                " GROUP BY CNID, Name))".format(self.name)
        self.run_query(query, True)

        query = "UPDATE \"{0}_Extents\" SET Valid=1 "\
                "WHERE DB_ID IN (SELECT DB_ID FROM ("\
                " SELECT DB_ID, MAX(XID) FROM \"{0}_Extents\" "\
                " GROUP BY CNID, Offset))".format(self.name)
        self.run_query(query, True)

        query = "UPDATE \"{0}_{1}\" SET Valid=1 "\
                "WHERE DB_ID IN (SELECT DB_ID FROM ("\
                " SELECT DB_ID, MAX(XID) FROM \"{0}_{1}\" "\
                " GROUP BY CNID))"
        for table_type in ['Hardlinks','Inodes','DirEntries','DirStats','Compressed_Files']:
            self.run_query(query.format(self.name, table_type), True)

        #Now delete invalid entries
        query = "DELETE FROM \"{0}_{1}\" WHERE Valid=0 "
        for table_type in ['Attributes','Hardlinks','Extents','Inodes','DirEntries','DirStats','Compressed_Files']:
            self.run_query(query.format(self.name, table_type), True)

    def create_other_tables_and_indexes(self):
        '''Populate paths table in db, create compressed_files table and create indexes for faster queries'''

        self.populate_compressed_files_table()
        self.validate_db_entries()
        
        insert_query = "INSERT INTO \"{0}_Paths\" SELECT * FROM " \
                        "( WITH RECURSIVE " \
                        "  under_root(path,name,cnid) AS " \
                        "  (  VALUES('','root',2) " \
                        "    UNION ALL " \
                        "    SELECT under_root.path || '/' || \"{0}_DirEntries\".name, " \
                        "\"{0}_DirEntries\".name, \"{0}_DirEntries\".cnid " \
                        "       FROM \"{0}_DirEntries\" JOIN under_root ON " \
                        "       \"{0}_DirEntries\".parent_cnid=under_root.cnid WHERE \"{0}_DirEntries\".Valid=1 " \
                        "   ORDER BY 1 " \
                        ") SELECT CNID, Path FROM under_root);"
                        
        query = insert_query.format(self.name)
        self.run_query(query, True)
        self.run_query("UPDATE \"{}_Paths\" SET path = '/' where cnid = 2;".format(self.name), True)

        self.create_indexes()

    def read_entries(self, block_num, block, force_subtype_omap=False):
        '''Read file system entries(inodes) and add to database'''
        if block_num in self.blocks_read: return # block already processed
        else: self.blocks_read.add(block_num)

        xid = block.header.xid # TODO - fix for Sealed volumes where header is zeroed out

        if force_subtype_omap or \
           (block.header.subtype == self.container_type_files) or \
           ((block.header.subtype == self.container_type_fext_tree) and (block.body.level == 0)):
            if block.body.level > 0: # not leaf nodes
                return
            # For sealed vol
            if block.header.subtype == self.container_type_fext_tree:
                for _, entry in enumerate(block.body.entries):
                    entry_type = self.sealed_extent
                    self.AddToStats(entry_type)
                    self.num_records_read_batch += 1
                    self.num_records_read_total += 1
                    self.extent_records.append([xid, entry.key.private_id, entry.key.logical_addr, entry.data.size, entry.data.phys_block_num, 0, None])
                if self.num_records_read_batch > 400000:
                    self.num_records_read_batch = 0
                    # write to db / file
                    self.write_records()
                    self.clear_records() # Clear the data once written
                return
            # For Others
            for _, entry in enumerate(block.body.entries):
                if type(entry.data) == self.ptr_type: #apfs.Apfs.PointerRecord: 
                    log.debug('Skipping pointer record..')
                    continue
                entry_type = entry.key.type_entry
                self.AddToStats(entry_type)
                if entry_type == self.file_ext_type: #container.apfs.EntryType.file_extent.value:
                    self.num_records_read_batch += 1
                    self.num_records_read_total += 1
                    self.extent_records.append([xid, entry.key.obj_id, entry.key.content.offset, entry.data.size, entry.data.phys_block_num, 0, None])
                elif entry_type == self.dir_rec_type: #container.apfs.EntryType.dir_rec.value:
                    # dir_rec key!!    
                    self.num_records_read_batch += 1
                    self.num_records_read_total += 1
                    rec = entry.data
                    self.dir_records.append([xid, rec.node_id, entry.key.obj_id, rec.date_added, rec.type_item.value, entry.key.content.name, 0, None])
                elif entry_type == self.inode_type: #container.apfs.EntryType.inode.value:
                    self.num_records_read_batch += 1
                    self.num_records_read_total += 1
                    rec = entry.data
                    self.inode_records.append([xid, entry.key.obj_id, rec.parent_id, rec.node_id, rec.name, rec.creation_timestamp, rec.modified_timestamp, rec.changed_timestamp, rec.accessed_timestamp, rec.flags, rec.nchildren_or_nlink, rec.bsdflags, rec.owner_id, rec.group_id, rec.mode, rec.logical_size, rec.physical_size, 0, None])
                elif entry_type == self.hard_type: #container.apfs.EntryType.sibling_link.value:
                    self.num_records_read_batch += 1
                    self.num_records_read_total += 1
                    self.hardlink_records.append([xid, entry.key.obj_id, entry.data.parent_id, entry.data.name, 0, None])
                elif entry_type == self.dir_stats_type: #container.apfs.EntryType.dir_stats.value:
                    self.num_records_read_batch += 1
                    self.num_records_read_total += 1
                    self.dir_stats_records.append([xid, entry.data.chained_key, entry.data.num_children, entry.data.total_size, entry.data.gen_count, 0, None])
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
                    self.attr_records.append([xid, entry.key.obj_id, entry.key.content.name, rec.flags, data, logical_size, rsrc_extent_cnid, 0, None])
                elif entry_type == 6: # dstream_id
                    pass # this just has refcnts
                elif entry_type == 7: #crypto_state
                    pass
                elif entry_type in (0xc, 0xd) : # sibling_map, file_info
                    pass # TODO: Maybe process these later
                elif entry_type >= 0xe:
                    log.warning('Unknown entry_type 0x{:X} block_num={}'.format(entry_type, block_num))
                else:
                    log.debug('Got entry_type 0x{:X} block_num={}'.format(entry_type, block_num))
        elif (block.header.subtype == self.container_type_location) or \
             ((block.header.subtype == self.container_type_fext_tree) and (block.body.level > 0)):
            for _, entry in enumerate(block.body.entries):
                if type(entry.data) == self.ptr_type: #apfs.Apfs.PointerRecord: 
                    # Must process this!!!!
                    #if type(entry.key) == apfs.Apfs.OmapKey:
                    try:
                        if not entry.data.pointer in self.blocks_read:
                            newblock = self.container.read_block(entry.data.pointer) # Pointers are not encrypted blocks
                            self.read_entries(entry.data.pointer, newblock)
                    except (ValueError, EOFError, OSError):
                        log.exception('Exception trying to read block {}'.format(entry.data.pointer))
                else:
                    try:
                        if entry.data.flags & 1: #OMAP_VAL_DELETED
                            log.debug("Deleted OMAP block found, block={}".format(entry.data.paddr.value))
                            continue
                        noheader_is_set = ((entry.data.flags & 8) == 8) # OMAP_VAL_NOHEADER
                        if ( entry.data.flags & 4 ) == 4: # ENCRYPTED FLAG
                            newblock = self.volume.read_vol_block(entry.data.paddr.value, self.encryption_key, noheader=noheader_is_set)
                        else:
                            newblock = self.volume.read_vol_block(entry.data.paddr.value, noheader=noheader_is_set)
                        self.read_entries(entry.data.paddr.value, newblock, noheader_is_set)
                    except (ValueError, EOFError, OSError):
                        log.exception('Exception trying to read block {}'.format(entry.data.paddr.value))
        elif (block.header.subtype == 0):
            if (block.header.type_block.value not in (0x1D, 0x1E)):
                log.debug(f'Invalid obj type, block={block_num}, type=0x{block.header.type_block.value:X}')
        else:
            log.warning("unexpected entry type=0x{:X} subtype={} in block {}".format(block.header.type_block.value, repr(block.header.subtype), block_num))

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
        self.cache = {} # key=path, value=(ApfsFileMeta object, index)
        self.cache_index = {} # key=index, value=path
        self.index = 0
        self.count = 0
        #self.cnid_cache = {} # key=cnid, value=index

    def Insert(self, apfs_file_meta, path):
        if self.Find(path):
            log.debug('Obj already cached for path {}'.format(path))
            return
        self.index += 1
        self.cache[path] = (apfs_file_meta, self.index)
        self.cache_index[self.index] = path
        #self.cnid_cache[apfs_file_meta.cnid] = self.index
        #self.count += 1
        if self.count >= self.cache_limit: # should not got to >
            # remove oldest element
            oldest_id = self.index - self.cache_limit
            oldest_path = self.cache_index[oldest_id]
            #oldest_cnid = self.cache[oldest_path][0].cnid
            del(self.cache_index[oldest_id])
            del(self.cache[oldest_path])
            #del(self.cache_index[oldest_path])
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

    # def FindFileId(self, id):
    #     cached_path = self.cache_index.get(id, None)
    #     if cached_path:
    #         return self.cache[path][0]
    #     return None  

class ApfsExtendedAttribute:
    def __init__(self, volume, xName, xFlags, xData, xSize):
        self._volume = volume
        self.extents = []
        self.name = xName
        self.flags = xFlags
        self._data = xData
        self.size = xSize
        self._data_fetched = False
        self._real_data = None

    @property
    def data(self):
        if not self._data_fetched:
            self._real_data = b''
            if self.flags & 1: # extent based
                # get data from extents
                for extent in self.extents:
                    self._real_data += extent.GetData(self._volume)
            else: # embedded
                self._real_data = self._data
            self._data_fetched = True
        return self._real_data

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
        self.num_symlinks = 0
        self.num_snapshots = 0
        self.time_created = None
        self.time_updated = None
        self.uuid = ''
        self.role = 0
        self.files_meta_cache = DataCache()
        # Encryption related
        self.encryption_key = None
        self.apfs = apfs_container.apfs
        self.block_size = apfs_container.block_size
        self.cs_factor = self.block_size // 0x200
        #
        # SqliteWriter object to read from sqlite. 
        # This must be populated manually before calling any file/folder/symlink related method!
        self.dbo = None 

    def SetupDecryption(self, key):
        self.algorithm_aes = algorithms.AES(key)

    def get_raw_decrypted_block(self, block_num, key=None, limit_size=-1):
        """Returns raw block data (without parsing). If key is None, no decryption is performed.
           Use limit_size if you need less than one block of data. It's faster to decrypt less
           data. Use it if you don't need the whole block.
        """
        data = self.container.get_block(block_num)
        if key is not None:
            decrypted_block = self.decrypt_vol_block(data, block_num, key, limit_size)
            return decrypted_block
        return data

    def decrypt_vol_block(self, encrypted_block, block_id, key, limit_size=-1):
        
        uno = block_id * self.cs_factor
        size = self.block_size
        k = 0
        decrypted_block = b""
        if limit_size != -1:
            size = min(size, limit_size)
        while k < size:
            tweak = struct.pack("<QQ", uno, 0)
            decryptor = Cipher(self.algorithm_aes, modes.XTS(tweak), backend=default_backend()).decryptor()
            decrypted_block += decryptor.update(encrypted_block[k:k + 0x200]) + decryptor.finalize()
            uno += 1
            k += 0x200
        if limit_size != -1:
            return decrypted_block[:size]
        return decrypted_block

    def read_vol_block(self, block_num, key=None, noheader=False):
        """ Parse a single block """
        data = self.container.get_block(block_num)

        if not data:
            return None
        if key is None:
            block = self.apfs.Block(KaitaiStream(BytesIO(data)), self.apfs, self.apfs, noheader)
        else:
            decrypted_block = self.decrypt_vol_block(data, block_num, key)
            block = self.apfs.Block(KaitaiStream(BytesIO(decrypted_block)), self.apfs, self.apfs, noheader)
        return block

    def read_volume_info(self, volume_super_block_num):
        """Read volume information"""

        # get volume superblock
        super_block = self.container.read_block(volume_super_block_num)
        self.omap_oid = super_block.body.omap_oid  # mapping omap
        self.root_dir_block_id = super_block.body.root_tree_oid 

        self.volume_name = super_block.body.volume_name
        self.name += '_' + self.volume_name.replace(' ', '_').replace("'", "''") # Replace spaces with underscore and single quotes with doubles, this is for the db
        self.num_blocks_used = super_block.body.fs_alloc_count
        self.num_files = super_block.body.num_files
        self.num_folders = super_block.body.num_folders
        self.num_symlinks = super_block.body.num_symlinks
        self.num_snapshots = super_block.body.num_snapshots
        self.time_created = super_block.body.time_created
        self.time_updated = super_block.body.last_mod_time
        self.uuid = self.ReadUUID(super_block.body.volume_uuid)
        #self.is_case_insensitive = (super_block.body.incompatible_features & apfs.INCOMPAT_CASE_INSENSITIVE != 0)
        self.is_sealed = ((super_block.body.incompatible_features & apfs.INCOMPAT_SEALED_VOLUME) == apfs.INCOMPAT_SEALED_VOLUME)
        self.is_encrypted = (super_block.body.fs_flags & 0x1 != 1)
        self.role = super_block.body.apfs_role
        self.linked_data_uuid = self.ReadUUID(super_block.body.data_uuid)

        #log.debug("%s (volume, Mapping-omap: %d, Rootdir-Block_ID: %d)" % (
        #    super_block.body.volume_name, self.omap_oid, self.root_dir_block_id))
        log.debug(" -- Volume information:")
        log.debug("  Vol name  = %s" % super_block.body.volume_name)
        log.debug("  Num files = %d" % super_block.body.num_files)
        log.debug("  Num dirs  = %d" % super_block.body.num_folders)
        vol_used_size = super_block.body.fs_alloc_count * self.container.apfs.block_size
        if vol_used_size < 1073741824: # < 1GiB
            log.debug("  Vol used  = %.2f MiB" % float((super_block.body.fs_alloc_count * self.container.apfs.block_size)/(1024.0*1024.0)))
        else:
            log.debug("  Vol used  = %.2f GiB" % float((super_block.body.fs_alloc_count * self.container.apfs.block_size)/(1024.0*1024.0*1024.0)))
        log.debug('  incompatible_features=0x{:X}, fs_flags=0x{:X}'.format(super_block.body.incompatible_features, super_block.body.fs_flags))

        if self.is_encrypted:
            log.info("Volume appears to be ENCRYPTED. ")
        if self.is_sealed:
            self.fext_tree_oid = super_block.body.fext_tree_oid

        # get volume omap
        vol_omap = self.container.read_block(self.omap_oid)
        self.root_block_num = vol_omap.body.tree_oid
        log.debug ("root_block_num = {}".format(self.root_block_num))

    def ReadUUID(self, uuid_bytes):
        '''Return a string from binary uuid blob'''
        uuid =  UUID(bytes=uuid_bytes)
        return str(uuid).upper()

    def CopyOutFolderRecursive(self, path, output_folder):
        '''Internal Test function'''
        if not path:
            return
        if not path.startswith('/'): 
            path = '/' + path
        if path.endswith('/') and path != '/':
            path = path[:-1]
        if not os.path.exists(output_folder):
            os.makedirs(output_folder)
        items = self.ListItemsInFolder(path)
        for item in items:
            type = item['type']
            if type == 'Folder':
                name = item['name']
                new_path = ('/' + name) if path == '/' else (path + '/' + name)
                new_out_path = os.path.join(output_folder, name)
                try:
                    if not os.path.exists(new_out_path):
                        os.makedirs(new_out_path)
                    self.CopyOutFolderRecursive(new_path, new_out_path)
                except OSError:
                    log.exception('Error creating folder ' + new_out_path)
            elif type == 'File':
                name = item['name']
                file_path = ('/' + name) if path == '/' else (path + '/' + name)
                destination_path = os.path.join(output_folder, name)
                self.CopyOutFile(file_path, destination_path)

    def GetApfsFileMeta(self, path):
        '''Retrieve from cache or fetch from database if not found and insert into cache'''
        apfs_file_meta = self.files_meta_cache.Find(path)
        if apfs_file_meta == None:
            apfs_file_meta = self.GetFileMetadataByPath(path)
            if apfs_file_meta:
                self.files_meta_cache.Insert(apfs_file_meta, path)
        return apfs_file_meta

    def GetFile(self, path, apfs_file_meta=None):
        '''Returns an ApfsFile object given path. Returns None if file not found'''
        if not path:
            return None
        if apfs_file_meta == None:
            apfs_file_meta = self.GetApfsFileMeta(path)
        if apfs_file_meta:
            vol = self
            if isinstance(self, ApfsSysDataLinkedVolume):
                vol = self.GetUnderlyingVolume(apfs_file_meta.cnid)
            if apfs_file_meta.is_compressed:
                return ApfsFileCompressed(apfs_file_meta, apfs_file_meta.logical_size, apfs_file_meta.extents, vol)
            else:
                return ApfsFile(apfs_file_meta, apfs_file_meta.logical_size, apfs_file_meta.extents, vol)
        else:
            log.error("Failed to open file as no metadata was found for it. File path={}".format(path))
        return None

    def GetExtendedAttribute(self, path, att_name, apfs_file_meta=None):
        '''Returns Xattr's data or none if not found'''
        if not path:
            return None
        if apfs_file_meta == None:
            apfs_file_meta = self.GetApfsFileMeta(path)
        if apfs_file_meta:
            xattr = apfs_file_meta.attributes.get(att_name, None)
            if xattr:
                return xattr.data
        else:
            log.error("Failed to get Xattr as no metadata was found for this file. File path={}".format(path))
        return None

    def GetExtendedAttributes(self, path, apfs_file_meta=None):
        if not path:
            return None
        if apfs_file_meta == None:
            apfs_file_meta = self.GetApfsFileMeta(path)
        if apfs_file_meta:
            return apfs_file_meta.attributes
        else:
            log.error("Failed to get Xattr as no metadata was found for this file. File path={}".format(path))
        return None

    def IsSymbolicLink(self, path):
        '''Returns True if the path is a symbolic link'''
        if not path:
            return False
        apfs_file_meta = self.GetApfsFileMeta(path)
        if apfs_file_meta:
            return apfs_file_meta.is_symlink
        else:
            log.error("Failed to get symlink status as no metadata was found for this file. File path={}".format(path))
        return False

    def open(self, path, apfs_file_meta=None):
        '''Open file, returns file-like object'''
        log.debug("Trying to open file : " + path)
        apfs_file = self.GetFile(path, apfs_file_meta)
        if apfs_file == None:
            log.info('File not found! Path was: ' + path)
        elif apfs_file.meta.logical_size > 209715200:
            log.debug('File size > 200 MB')
        return apfs_file

    def CopyOutFile(self, path, destination_path):
        '''Copy out file to disk'''
        retval = False
        if not path:
            return False
        apfs_file = self.GetFile(path)
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
            except OSError:
                log.exception ("Failed to create file for writing - " + destination_path)
        else:
            log.debug("Failed to find file for export: " + path)
        return retval

    def DoesFileExist(self, path):
        '''Returns True if file exists'''
        apfs_file_meta = self.GetApfsFileMeta(path)
        if apfs_file_meta:
            return apfs_file_meta.item_type in (8, 10) # will also return true for symlink which may point to folder!
        return False

    def DoesFolderExist(self, path):
        '''Returns True if folder exists'''
        apfs_file_meta = self.GetApfsFileMeta(path)
        if apfs_file_meta:
            return apfs_file_meta.item_type in (4, 10) # will also return true for symlink which may point to file!
        return False

    def DoesPathExist(self, path, type=EntryType.FILES_AND_FOLDERS):
        '''Returns True if path exists'''
        if not path: 
            return None
        if not path.startswith('/'): 
            path = '/' + path

        apfs_file_meta = self.GetApfsFileMeta(path)
        if apfs_file_meta:
            return apfs_file_meta.item_type in (4, 8, 10) # folder, file, symlink
        return False

    def GetFileMetadataByCnid(self, cnid):
        '''Returns ApfsFileMeta object from database given path and db handle'''
        cnid = int(cnid)
        if cnid <= 0:
            return None
        where_clause = " where p.CNID={} ".format(cnid)
        return self.GetFileMetadata(where_clause)

    def GetFileMetadataByPath(self, path):
        '''Returns ApfsFileMeta object from database given path and db handle'''
        if not path:
            return None
        if not path.startswith('/'): 
            path = '/' + path
        path = path.replace("'", "''") # if path contains single quote, replace with double to escape it!
        where_clause = " where p.Path = '{}' ".format(path)
        return self.GetFileMetadata(where_clause)

    def GetFilePathFromCnid(self, cnid):
        apfs_file_meta = self.GetApfsFileMeta(path)
        if not apfs_file_meta:
            apfs_file_meta = self.GetFileMetadataByCnid(cnid)
        return apfs_file_meta.path

    def GetFileMetadata(self, where_clause):
        '''Returns ApfsFileMeta object from database. A where_clause specifies either cnid or path to find'''

        query = "SELECT a.name as xName, a.flags as xFlags, a.data as xData, a.Logical_uncompressed_size as xSize, "\
                " a.Extent_CNID as xCNID, ex.Offset as xExOff, ex.Size as xExSize, ex.Block_Num as xBlock_Num, "\
                " p.CNID, p.Path, i.Parent_CNID, i.Extent_CNID, i.Name, i.Created, i.Modified, i.Changed, i.Accessed, i.Flags, "\
                " i.Links_or_Children, i.BSD_flags, i.UID, i.GID, i.Mode, i.Logical_Size, i.Physical_Size, "\
                " d.ItemType, d.DateAdded, e.Offset as Extent_Offset, e.Size as Extent_Size, e.Block_Num as Extent_Block_Num, "\
                " c.Uncompressed_size, c.Data, c.Extent_Logical_Size, "\
                " ec.Offset as compressed_Extent_Offset, ec.Size as compressed_Extent_Size, ec.Block_Num as compressed_Extent_Block_Num "\
                " from \"{0}_Paths\" as p "\
                " left join \"{0}_Inodes\" as i on i.CNID = p.CNID "\
                " left join \"{0}_DirEntries\" as d on d.CNID = p.CNID "\
                " left join \"{0}_Extents\" as e on e.CNID = i.Extent_CNID "\
                " left join \"{0}_Compressed_Files\" as c on c.CNID = i.CNID "\
                " left join \"{0}_Extents\" as ec on ec.CNID = c.Extent_CNID "\
                " left join \"{0}_Attributes\" as a on a.CNID = p.CNID "\
                " left join \"{0}_Extents\" as ex on ex.CNID = a.Extent_CNID "\
                " {1} "\
                " order by Extent_Offset, compressed_Extent_Offset, xName, xExOff"
        # This query gets file metadata as well as extents for file. If compressed, it gets compressed extents.
        # It gets XAttributes, except decmpfs and ResourceFork (we already got those in _Compressed_Files table)
        success, cursor, error_message = self.dbo.RunQuery(query.format(self.name, where_clause), return_named_objects=True)
        if success:
            apfs_file_meta = None
            #extent_cnid = 0
            index = 0
            last_xattr_name = None
            extent = None
            prev_extent = None
            xattr_extent = None
            prev_xattr_extent = None
            att = None
            got_all_xattr = False
            for row in cursor:
                if index == 0:
                    apfs_file_meta = ApfsFileMeta(row['Name'], row['Path'], row['CNID'], row['Parent_CNID'], CommonFunctions.ReadAPFSTime(row['Created']), \
                                        CommonFunctions.ReadAPFSTime(row['Modified']), CommonFunctions.ReadAPFSTime(row['Changed']), \
                                        CommonFunctions.ReadAPFSTime(row['Accessed']), \
                                        CommonFunctions.ReadAPFSTime(row['DateAdded']), \
                                        row['Flags'], row['Links_or_Children'], row['BSD_flags'], row['UID'], row['GID'], row['Mode'], \
                                        row['Logical_Size'], row['Physical_Size'], row['ItemType'])

                    if row['Uncompressed_size'] != None:
                        apfs_file_meta.logical_size = row['Uncompressed_size']
                        apfs_file_meta.is_compressed = True
                        apfs_file_meta.decmpfs = row['Data']
                        apfs_file_meta.compressed_extent_size = row['Extent_Logical_Size']
                if apfs_file_meta.is_compressed:
                    extent = ApfsExtent(row['compressed_Extent_Offset'], row['compressed_Extent_Size'], row['compressed_Extent_Block_Num'])
                else:
                    extent = ApfsExtent(row['Extent_Offset'], row['Extent_Size'], row['Extent_Block_Num'])
                if prev_extent and extent.offset == prev_extent.offset:
                    #This file may have hard links, hence the same data is in another row, skip this!
                    # Or duplicated row data due to attributes being fetched in query
                    pass
                else:
                    apfs_file_meta.extents.append(extent)
                prev_extent = extent
                index += 1
                # Read attributes
                if not got_all_xattr:
                    xName = row['xName']
                    if xName:
                        if last_xattr_name == xName: # same as last
                            # check extents too
                            if row['xFlags'] & 1 == 0: # not extent based, means repeat of last, skip it
                                pass
                            else: # extent based
                                xattr_extent = ApfsExtent(row['xExOff'], row['xExSize'], row['xBlock_Num'])
                                if prev_xattr_extent.offset == xattr_extent.offset: 
                                    got_all_xattr = True # There must only be 1 xattr and its extent based and repeating now!
                                else: # not a repeat
                                    att.extents.append(xattr_extent)
                                    prev_xattr_extent = xattr_extent
                        elif apfs_file_meta.attributes.get(xName, None) != None: # check if existing
                            got_all_xattr = True # based on our query sorting, attributes will now be repeated, we got all of them, processing attribs can stop now
                        else: # new , read this
                            vol = self
                            if isinstance(self, ApfsSysDataLinkedVolume):
                                vol = self.GetUnderlyingVolume(apfs_file_meta.cnid)
                            att = ApfsExtendedAttribute(vol, xName, row['xFlags'], row['xData'], row['xSize'])
                            if row['xFlags'] & 1: #row['xExSize']:
                                xattr_extent = ApfsExtent(row['xExOff'], row['xExSize'], row['xBlock_Num'])
                                att.extents.append(xattr_extent)
                            else:
                                xattr_extent = None
                            apfs_file_meta.attributes[xName] = att
                            prev_xattr_extent = xattr_extent
                        last_xattr_name = xName

            if index == 0: # No such file!
                return None
            return apfs_file_meta
        else:
            log.debug('Failed to execute GetFileMetadata query, error was : ' + error_message)

        return None

    def GetManyFileMetadataByCnids(self, cnids):
        '''Returns ApfsFileMeta object from database given a list of cnids'''
        # for cnid in cnids:
        #     if cnid <= 0:
        #         continue # skip that
        cnids = [str(int(x)) for x in cnids]
        cnids_str = ",".join(cnids)
        where_clause = " where p.CNID IN ({}) ".format(cnids_str)
        try:
            for item in self.GetManyFileMetadata(where_clause):
                yield item
        except GeneratorExit:
            pass

    def GetManyFileMetadataByPaths(self, paths):
        '''Returns ApfsFileMeta object from database given a list of paths'''   
        for path in paths:
            if not path.startswith('/'): 
                path = '/' + path
            path = path.replace("'", "''") # if path contains single quote, replace with double to escape it!
            path = "'{}'".format(path)
        paths_str = ",".join(paths)
        where_clause = " where p.Path IN ({}) ".format(paths_str)
        try:
            for item in self.GetManyFileMetadata(where_clause):
                yield item
        except GeneratorExit:
            pass

    def GetManyFileMetadataCountOnly(self, where_clause):
        '''Only returns a count of items. A where_clause specifies either cnid or path to find'''
        query = "SELECT count(DISTINCT p.cnid)"\
                " from \"{0}_Paths\" as p "\
                " left join \"{0}_Inodes\" as i on i.CNID = p.CNID "\
                " left join \"{0}_DirEntries\" as d on d.CNID = p.CNID "\
                " left join \"{0}_Extents\" as e on e.CNID = i.Extent_CNID "\
                " left join \"{0}_Compressed_Files\" as c on c.CNID = i.CNID "\
                " left join \"{0}_Extents\" as ec on ec.CNID = c.Extent_CNID "\
                " left join \"{0}_Attributes\" as a on a.CNID = p.CNID "\
                " left join \"{0}_Extents\" as ex on ex.CNID = a.Extent_CNID "\
                " {1} "
        success, cursor, error_message = self.dbo.RunQuery(query.format(self.name, where_clause))
        if success:
            for row in cursor:
                return row[0]
        else:
            log.debug('Failed to execute GetManyFileMetadataCountOnly query, error was : ' + error_message)

    def GetManyFileMetadata(self, where_clause):
        '''Returns ApfsFileMeta object from database. A where_clause specifies either cnid or path to find'''
        #apfs_file_meta_list = []
        query = "SELECT a.name as xName, a.flags as xFlags, a.data as xData, a.Logical_uncompressed_size as xSize, "\
                " a.Extent_CNID as xCNID, ex.Offset as xExOff, ex.Size as xExSize, ex.Block_Num as xBlock_Num, "\
                " p.CNID, p.Path, i.Parent_CNID, i.Extent_CNID, i.Name, i.Created, i.Modified, i.Changed, i.Accessed, i.Flags, "\
                " i.Links_or_Children, i.BSD_flags, i.UID, i.GID, i.Mode, i.Logical_Size, i.Physical_Size, "\
                " d.ItemType, d.DateAdded, e.Offset as Extent_Offset, e.Size as Extent_Size, e.Block_Num as Extent_Block_Num, "\
                " c.Uncompressed_size, c.Data, c.Extent_Logical_Size, "\
                " ec.Offset as compressed_Extent_Offset, ec.Size as compressed_Extent_Size, ec.Block_Num as compressed_Extent_Block_Num "\
                " from \"{0}_Paths\" as p "\
                " left join \"{0}_Inodes\" as i on i.CNID = p.CNID "\
                " left join \"{0}_DirEntries\" as d on d.CNID = p.CNID "\
                " left join \"{0}_Extents\" as e on e.CNID = i.Extent_CNID "\
                " left join \"{0}_Compressed_Files\" as c on c.CNID = i.CNID "\
                " left join \"{0}_Extents\" as ec on ec.CNID = c.Extent_CNID "\
                " left join \"{0}_Attributes\" as a on a.CNID = p.CNID "\
                " left join \"{0}_Extents\" as ex on ex.CNID = a.Extent_CNID "\
                " {1} "\
                " order by p.Path, p.CNID, Extent_Offset, compressed_Extent_Offset, xName, xExOff"
        # This query gets file metadata as well as extents for file. If compressed, it gets compressed extents.
        # It gets XAttributes, except decmpfs and ResourceFork (we already got those in _Compressed_Files table)
        success, cursor, error_message = self.dbo.RunQuery(query.format(self.name, where_clause), return_named_objects=True)
        if success:
            apfs_file_meta = None
            #extent_cnid = 0
            index = 0
            last_cnid = 0
            last_xattr_name = None
            extent = None
            prev_extent = None
            xattr_extent = None
            prev_xattr_extent = None
            att = None
            got_all_xattr = False
            path = ''
            try:
                for row in cursor:
                    if last_cnid == row['CNID']: # same file
                        pass
                    else:                  # new file
                        if last_cnid:      # save old info
                            self.files_meta_cache.Insert(apfs_file_meta, path)
                            yield apfs_file_meta
                        index = 0
                        last_cnid = row['CNID']
                        last_xattr_name = None
                        extent = None
                        prev_extent = None
                        xattr_extent = None
                        prev_xattr_extent = None
                        att = None
                        got_all_xattr = False

                    if index == 0:
                        path = row['Path']
                        apfs_file_meta = ApfsFileMeta(row['Name'], row['Path'], row['CNID'], row['Parent_CNID'], CommonFunctions.ReadAPFSTime(row['Created']), \
                                            CommonFunctions.ReadAPFSTime(row['Modified']), CommonFunctions.ReadAPFSTime(row['Changed']), \
                                            CommonFunctions.ReadAPFSTime(row['Accessed']), \
                                            CommonFunctions.ReadAPFSTime(row['DateAdded']), \
                                            row['Flags'], row['Links_or_Children'], row['BSD_flags'], row['UID'], row['GID'], row['Mode'], \
                                            row['Logical_Size'], row['Physical_Size'], row['ItemType'])

                        if row['Uncompressed_size'] != None:
                            apfs_file_meta.logical_size = row['Uncompressed_size']
                            apfs_file_meta.is_compressed = True
                            apfs_file_meta.decmpfs = row['Data']
                            apfs_file_meta.compressed_extent_size = row['Extent_Logical_Size']
                    if apfs_file_meta.is_compressed:
                        extent = ApfsExtent(row['compressed_Extent_Offset'], row['compressed_Extent_Size'], row['compressed_Extent_Block_Num'])
                    else:
                        extent = ApfsExtent(row['Extent_Offset'], row['Extent_Size'], row['Extent_Block_Num'])
                    if prev_extent and extent.offset == prev_extent.offset:
                        #This file may have hard links, hence the same data is in another row, skip this!
                        # Or duplicated row data due to attributes being fetched in query
                        pass
                    else:
                        apfs_file_meta.extents.append(extent)
                    prev_extent = extent
                    index += 1
                    # Read attributes
                    if not got_all_xattr:
                        xName = row['xName']
                        if xName:
                            if last_xattr_name == xName: # same as last
                                # check extents too
                                if row['xFlags'] & 1 == 0: # not extent based, means repeat of last, skip it
                                    pass
                                else: # extent based
                                    xattr_extent = ApfsExtent(row['xExOff'], row['xExSize'], row['xBlock_Num'])
                                    if prev_xattr_extent.offset == xattr_extent.offset: 
                                        got_all_xattr = True # There must only be 1 xattr and its extent based and repeating now!
                                    else: # not a repeat
                                        att.extents.append(xattr_extent)
                                        prev_xattr_extent = xattr_extent
                            elif apfs_file_meta.attributes.get(xName, None) != None: # check if existing
                                got_all_xattr = True # based on our query sorting, attributes will now be repeated, we got all of them, processing attribs can stop now
                            else: # new , read this
                                vol = self
                                if isinstance(self, ApfsSysDataLinkedVolume):
                                    vol = self.GetUnderlyingVolume(apfs_file_meta.cnid)
                                att = ApfsExtendedAttribute(vol, xName, row['xFlags'], row['xData'], row['xSize'])
                                if row['xFlags'] & 1: #row['xExSize']:
                                    xattr_extent = ApfsExtent(row['xExOff'], row['xExSize'], row['xBlock_Num'])
                                    att.extents.append(xattr_extent)
                                else:
                                    xattr_extent = None
                                apfs_file_meta.attributes[xName] = att
                                prev_xattr_extent = xattr_extent
                            last_xattr_name = xName

                # get last one
                if apfs_file_meta:
                    # Also adding to cache
                    self.files_meta_cache.Insert(apfs_file_meta, path)
                    yield apfs_file_meta
            except GeneratorExit:
                pass
        else:
            log.debug('Failed to execute GetManyFileMetadata query, error was : ' + error_message)

    def ListItemsInFolder(self, path):
        ''' 
        Returns a list of files and/or folders in a list
        Format of list = [ { 'name':'got.txt', 'type':'File', 'size':10, 'dates': {} }, .. ]
        'path' should be linux style using forward-slash like '/var/db/xxyy/file.tdc'
        '''
        if path.endswith('/') and path != '/':
            path = path[:-1]
        items = [] # List of dictionaries

        if path == '/':
            where_clause = "where path like '/%' and path NOT like '/%/%' and path NOT like '/' "
        else:
            where_clause = "where path like '{}/%' and path NOT like '{}/%/%'".format(path, path)

        for meta_item in self.GetManyFileMetadata(where_clause):
            item = { 'name':meta_item.name, 'size':meta_item.logical_size, 
                    'type':ApfsFileMeta.ItemTypeString(meta_item.item_type) }
            item['dates'] = { 'c_time':meta_item.changed,
                                'm_time':meta_item.modified, 
                                'cr_time':meta_item.created, 
                                'a_time':meta_item.accessed,
                                'i_time':meta_item.date_added }
            items.append(item) 
        return items

class ApfsSysDataLinkedVolume(ApfsVolume):
    def __init__(self, sys_vol, data_vol):
        ApfsVolume.__init__(self, sys_vol.container, 'Combined')
        self.sys_vol = sys_vol
        self.data_vol = data_vol
        self.firmlinks_paths = []
        self.firmlinks = {}
        self.num_blocks_used = sys_vol.num_blocks_used + data_vol.num_blocks_used
        self.num_files = sys_vol.num_files + data_vol.num_files
        self.num_folders = sys_vol.num_folders + data_vol.num_folders
        self.num_symlinks = sys_vol.num_symlinks + data_vol.num_symlinks
        self.num_snapshots = data_vol.num_snapshots
        self.time_created = data_vol.time_created
        self.time_updated = data_vol.time_updated
        self.dbo = sys_vol.dbo
        self._ParseFirmlinks()

    def _ParseFirmlinks(self):
        '''Read the firmlink path mappings between System & Data volumes'''
        firmlink_file_path = '/usr/share/firmlinks'
        if self.sys_vol.DoesFileExist(firmlink_file_path):
            try:
                f = self.sys_vol.open(firmlink_file_path)
                data = [x.decode('utf8', 'backslashreplace') for x in f.read().split(b'\n')]
                for item in data:
                    if item:
                        source, dest = item.split('\t')
                        self.firmlinks[source] = dest
                        self.firmlinks_paths.append(source)
                        if source[1:] != dest:
                            # Maybe this is the Beta version of Catalina, try prefix 'Device'
                            if dest.startswith('Device/'):
                                self.firmlinks[source] = dest[7:]
                            else:
                                log.warning("Firmlink not handled : Source='{}' Dest='{}'".format(source, dest))
                # add one for /System/Volumes/Data  /
                #self.firmlinks['/System/Volumes/Data'] = ''
                #self.firmlinks_paths.append('/System/Volumes/Data')
                f.close()
            except (OSError, ValueError, TypeError) as ex:
                log.exception('Failed to open/parse firmlink file')
                raise ex
        else:
            log.error('firmlinks file is missing! Cannot proceed!')
    
    def GetUnderlyingVolume(self, file_id):
        '''Return the volume object given file's inode number(file_id)'''
        if (file_id & 0x0FFFFFFF00000000) == 0x0FFFFFFF00000000:
            return self.sys_vol
        return self.data_vol

class ApfsContainer:

    def __init__(self, image_file, apfs_container_size, offset=0):
        self.img = image_file
        self.apfs_container_offset = offset
        self.apfs_container_size = apfs_container_size
        self.volumes = []
        self.preboot_volume = None
        self.position = 0 # For self.seek()

        try:
            self.block_size = 4096 # Default, before real size is read in
            self.seek(0x20)
            magic = self.read(4)
            assert magic == b'NXSB'
        except AssertionError:
            raise ValueError("Not an APFS image")

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
            self.containersuperblock = checkpoint_blocks[max_xid_cp_index]

        self.is_sw_encrypted = (self.containersuperblock.body.flags == apfs.NX_CRYPTO_SW) # True for encrypted APFS on non-T2 macs
        log.debug(f'self.is_sw_encrypted = {self.is_sw_encrypted}')

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
            if volume.role == 16: # Preboot
                self.preboot_volume = volume
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
            raise ValueError('Unexpected value in whence (only 0,1,2 are allowed), value was ' + str(whence))

    def tell(self):
        return self.position

    def read(self, size):
        """Raw read function, will not return decrypted data in case of Encrypted blocks"""
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
        """ Parse a single block """
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

    def GetData(self, volume):
        ## TODO: Create buffered read, in case of really large files!!
        encryption_key = volume.encryption_key
        num_full_blocks_needed = self.size // volume.block_size
        partial_block_size = self.size % volume.block_size

        data = b''
        for b in range(num_full_blocks_needed):
            data += volume.get_raw_decrypted_block(self.block_num + b, encryption_key)
        if partial_block_size > 0:
            data += volume.get_raw_decrypted_block(self.block_num + num_full_blocks_needed, encryption_key, partial_block_size)
        return data
    
    def GetSomeData(self, volume, max_size=41943040): # max 40MB
        encryption_key = volume.encryption_key
        try:
            #container.seek(self.block_num * container.block_size)
            # return data in chunks of max_size
            if self.size <= max_size:
                yield self.GetData(volume)
                #yield container.read(self.size)
            else:
                block_num = self.block_num
                num_full_blocks_needed = self.size // volume.block_size
                partial_block_size = self.size % volume.block_size

                data = b''
                for b in range(num_full_blocks_needed):
                    data += volume.get_raw_decrypted_block(block_num, encryption_key)
                    block_num += 1
                    if data >= max_size:
                        yield data
                        data = b''
                if partial_block_size > 0:
                    data += volume.get_raw_decrypted_block(block_num, encryption_key, partial_block_size)
                    yield data

        except GeneratorExit:
            pass

class ApfsFile():
    def __init__(self, apfs_file_meta, logical_size, extents, volume):
        self.meta = apfs_file_meta
        self.file_size = logical_size
        self.extents = extents
        self.volume = volume
        self.closed = False
        self.mode = 'rb'
        self.name = apfs_file_meta.path
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
            data = extent.GetData(self.volume)
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
           the range of logical file content. Returned size of data may be larger than 
           requested. It reads full extent even if only partial is requested.
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
                    for data in extent.GetSomeData(self.volume):
                        start_pos = offset - bytes_consumed - extent_slice_consumed
                        if start_pos >= len(data): # Case when extent slicing results in this, we only want let's say 3rd yield onwards!
                            extent_slice_consumed += len(data)
                            continue
                        ext_content = data[start_pos : ] #start_pos + size] # Perhaps return full buffer, let caller truncate buffer!
                        content += ext_content
                        ext_content_len = len(ext_content)
                        
                        if ext_content_len >= size: # will be <= size
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
        if len(content) < desired_size:
            log.error ("Error, could not get some pieces of file={} cnid={} len(content)={} desired_size={}".format(self.meta.name, self.meta.cnid, len(content), desired_size))
        return content

    def readAll(self):
        '''return entire file in one buffer'''
        self.closed = False
        file_content = b''
        if self.meta.is_symlink: # if symlink, return symlink  path as data
            file_content = self.meta.attributes['com.apple.fs.symlink'].data
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

    def __iter__(self):
        return self

    def __next__(self):
        line = self.readline()
        if len(line) == 0:
            raise StopIteration
        return line

    def readline(self, size=None):
        self._check_closed()
        ret = b''
        original_file_pos = self.tell()
        stop_at_one_iteration = True
        lf_found = False
        if size == None:
            stop_at_one_iteration = False
            size = 1024
        buffer = self.read(size)
        while buffer:
            new_line_pos = buffer.find(b'\n')
            if new_line_pos == -1: # not_found, add to line
                ret += buffer
            else:
                ret += buffer[0:new_line_pos + 1]
                lf_found = True
            self.seek(original_file_pos + len(ret))

            if stop_at_one_iteration or lf_found: break
            buffer = self.read(size)
        return ret

    def readlines(self, sizehint=None):
        self._check_closed()
        lines = []
        line = self.readline()
        while line:
            lines.append(line)
            line = self.readline()
        return lines

    def read(self, size_to_read=None):
        self._check_closed()
        if self.meta.is_symlink:
            avail_to_read = len(self.meta.attributes['com.apple.fs.symlink'].data) - self._pointer
        else:
            avail_to_read = self.file_size - self._pointer
        if avail_to_read <= 0: # at or beyond the end of file
            return b''
        if (size_to_read is None) or (size_to_read > avail_to_read):
            size_to_read = avail_to_read
        requested_size = size_to_read
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
                if size_to_read <= len(data): # got all required data
                    return data
                else:                          # still more data needed!
                    size_to_read -= len(data)
                    self._buffer = data

        if self.meta.is_symlink: # if symlink, return symlink  path as data
            data += self.meta.attributes['com.apple.fs.symlink'].data[self._pointer : self._pointer + size_to_read]
        else:
            new_data_fetched = self._GetSomeDataFromExtents(self.extents, self.meta.logical_size, self._pointer, size_to_read)
            new_data_len = len(new_data_fetched)
            data += new_data_fetched

            if new_data_len < size_to_read:
                log.error("Did not get enough data! Debug this new_data_len={} size_to_read={}".format(new_data_len, size_to_read))            

        self._buffer_start = original_file_pointer
        self._pointer += size_to_read
        self._buffer = data
        return data[0:requested_size]

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
    def __init__(self, apfs_file_meta, logical_size, extents, volume):
        super().__init__(apfs_file_meta, logical_size, extents, volume)
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
        lzvn_end_marker = b'\x06\0\0\0\0\0\0\0'
        if compressed_stream[-8:] != lzvn_end_marker:
            log.debug("lzvn compressed size seems incorrect, trying to correct..")
            end = compressed_stream.rfind(b'\x06\0\0\0\0\0\0\0')
            if end == -1:
                log.debug("could not find end of stream..")
            else:
                original_compressed_size = compressed_size # for debug only
                compressed_size = end + 8
                log.debug(f"found end of stream, correcting now.. old size={original_compressed_size} new size={compressed_size}, diff={original_compressed_size-compressed_size}")
                compressed_stream = compressed_stream[:end + 8]

        header = b'bvxn' + struct.pack('<I', uncompressed_size) + struct.pack('<I', compressed_size)
        footer = b'bvx$'
        try:
            decompressed_stream = liblzfse.decompress(header + compressed_stream + footer)
            len_dec = len(decompressed_stream)
            if len_dec != uncompressed_size: # I don't believe this will ever happen with current liblzfse code, it will just throw an exception
                log.error("_lzvn_decompress ERROR - decompressed_stream size is incorrect! Decompressed={} Expected={}. Padding stream with nulls".format(len_dec, uncompressed_size))
                decompressed_stream += b'\x00'*(uncompressed_size - len_dec)
            return decompressed_stream
        except (MemoryError, liblzfse.error) as ex:
            log.error('lzvn error - could not decompress stream, returning nulls')
            #raise ValueError('lzvn decompression failed')
        return b'\x00'* uncompressed_size

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

    def _readCompressed(self, size):
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
                    super().seek(0)
                    initial_read_size = min(extent_data_size, 8192)
                    compressed_header = super().read(initial_read_size)
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
                        if farthest_pos > initial_read_size: # fetch more data
                            super().seek(initial_read_size)
                            compressed_header += super().read(min(extent_data_size, farthest_pos))
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
                        if farthest_pos > initial_read_size: # fetch more data
                            super().seek(initial_read_size)
                            compressed_header += super().read(min(extent_data_size, farthest_pos))
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
                    decompressed = decompressed[req_start - buffer_start : ] #req_start - buffer_start + size] Returning all decompressed data starting at req offset
                else:
                    log.error("Should not be here buffer_start > req_start")

                file_content = decompressed

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
            log.error (f"compression_type = {compression_type} in DecompressInline --> ERROR! Should not go here! data_size={len(decmpfs)}" + str(decmpfs))
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
            file_content = self.meta.attributes['com.apple.fs.symlink'].data
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
        if (size_to_read is None) or (size_to_read > avail_to_read):
            size_to_read = avail_to_read
        requested_size = size_to_read
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
            data += self.meta.attributes['com.apple.fs.symlink'].data[0:size_to_read]
            log.error("This should not happen, compressed + symlink?")
        
        # If file is < 10MB, read entire file
        if self.uncompressed_size < 10485760:
            self.uncomp_buffer = self._readCompressedAll()
            self.uncomp_buffer_start = 0
            data = self.uncomp_buffer[self.uncomp_pointer : self.uncomp_pointer + size_to_read]
            self.uncomp_pointer += len(data)
            return data
        else:
            new_data_fetched = self._readCompressed(size_to_read) # can be more than requested
            new_data_len = len(new_data_fetched)
            data += new_data_fetched

            if new_data_len < size_to_read:
                log.error("Did not get enough data in ApfsFileCompressed.read() Debug this new_data_len={} size_to_read={}".format(new_data_len, size_to_read))    

        self.uncomp_buffer_start = original_file_pointer
        self.uncomp_pointer += size_to_read
        self.uncomp_buffer = data 
        return data[:requested_size]

class ApfsFileMeta:
    __slots__ = ['name', 'path', 'cnid', 'parent_cnid', 'created', 'modified', 'changed', 'accessed', 'date_added', 
                'flags', 'links', 'bsd_flags', 'uid', 'gid', 'mode', 'logical_size', 'compressed_extent_size', 
                'physical_size', 'is_symlink', 'item_type', 'decmpfs', 'attributes', 'extents', 'is_compressed']
    def __init__(self, name, path, cnid, parent_cnid, created, modified, changed, accessed, date_added, 
                flags, links, bsd_flags, uid, gid, mode, logical_size, physical_size, item_type):
        self.name = name
        self.path = path
        self.cnid = cnid
        self.parent_cnid = parent_cnid
        #self.extent_cnid = extent_cnid
        self.created = created
        self.modified = modified
        self.changed = changed
        self.accessed = accessed
        self.date_added = date_added
        self.flags = flags
        self.links = links
        self.bsd_flags = bsd_flags
        self.uid = uid
        self.gid = gid
        self.mode = mode
        self.logical_size = logical_size
        self.compressed_extent_size = 0
        self.physical_size = physical_size
        self.is_symlink = (item_type == 10)
        self.item_type = item_type
        self.decmpfs = None 
        self.attributes = {}
        self.extents = []
        self.is_compressed = False
        #self.is_hardlink = False

    @staticmethod
    def ItemTypeString(item_type):
        type_str = ''
        if   item_type == 1: type_str = 'Named Pipe'
        elif item_type == 2: type_str = 'Character Special File'
        elif item_type == 4: type_str = 'Folder'
        elif item_type == 6: type_str = 'Block Special File'
        elif item_type == 8: type_str = 'File'
        elif item_type ==10: type_str = 'SymLink'
        elif item_type ==12: type_str = 'Socket'
        elif item_type ==14: type_str = 'Whiteout'
        else:                type_str = 'Unknown_' + str(item_type)
        return type_str
