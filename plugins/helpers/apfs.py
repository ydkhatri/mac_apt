# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

'''
   Copyright (c) 2017 Yogesh Khatri 

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the 
   terms of the MIT License.
   
   This is a generated file using apfs.ksy and kaitai-struct compiler
   This is slightly modified from the original located here:
    https://github.com/cugu/apfs.ksy 
   
   Subsequently this generated file has been edited for optimization.
'''

import logging
import struct
from enum import Enum
from pkg_resources import parse_version

from kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO

log = logging.getLogger('MAIN.HELPERS.APFS')

if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))
# FLAGS
BTNODE_ROOT = 1
BTNODE_LEAF = 2
BTNODE_FIXED_KV_SIZE = 4
BTNODE_CHECK_KOFF_INVAL = 0x8000
# Extended field flags
XF_DATA_DEPENDENT = 0x0001
XF_DO_NOT_COPY = 0x0002
XF_RESERVED_4 = 0x0004
XF_CHILDREN_INHERIT = 0x0008
XF_USER_FIELD = 0x0010
XF_SYSTEM_FIELD = 0x0020
XF_RESERVED_40 = 0x0040
XF_RESERVED_80 = 0x0080
# Extended Field Types
INO_EXT_TYPE_SNAP_XID = 1
INO_EXT_TYPE_DELTA_TREE_OID = 2
INO_EXT_TYPE_DOCUMENT_ID = 3
INO_EXT_TYPE_NAME = 4
INO_EXT_TYPE_PREV_FSIZE = 5
INO_EXT_TYPE_RESERVED_6 = 6
INO_EXT_TYPE_FINDER_INFO = 7
INO_EXT_TYPE_DSTREAM = 8
INO_EXT_TYPE_RESERVED_9 = 9
INO_EXT_TYPE_DIR_STATS_KEY = 10
INO_EXT_TYPE_FS_UUID = 11
INO_EXT_TYPE_RESERVED_12 = 12
INO_EXT_TYPE_SPARSE_BYTES = 13
INO_EXT_TYPE_RDEV = 14
# j_xattr_flags
XATTR_DATA_STREAM = 0x00000001
XATTR_DATA_EMBEDDED = 0x00000002
XATTR_FILE_SYSTEM_OWNED = 0x00000004
XATTR_RESERVED_8 = 0x00000008
# snapshot flags
OMAP_SNAPSHOT_DELETED  = 0x00000001
OMAP_SNAPSHOT_REVERTED = 0x00000002

class Apfs(KaitaiStruct):

    class InodeFlags(Enum):
        IS_APFS_PRIVATE = 0x00000001
        MAINTAIN_DIR_STATS = 0x00000002
        DIR_STATS_ORIGIN = 0x00000004
        PROT_CLASS_EXPLICIT = 0x00000008
        WAS_CLONED = 0x00000010
        FLAG_UNUSED = 0x00000020
        HAS_SECURITY_EA = 0x00000040
        BEING_TRUNCATED = 0x00000080
        HAS_FINDER_INFO = 0x00000100
        IS_SPARSE = 0x00000200
        WAS_EVER_CLONED = 0x00000400
        ACTIVE_FILE_TRIMMED = 0x00000800
        PINNED_TO_MAIN = 0x00001000
        PINNED_TO_TIER2 = 0x00002000
        HAS_RSRC_FORK = 0x00004000
        NO_RSRC_FORK = 0x00008000
        ALLOCATION_SPILLEDOVER = 0x00010000
    
    class ObjectTypeFlag(Enum):
        VIRTUAL = 0
        EPHEMERAL = 0x80000000
        PHYSICAL = 0x40000000
        NOHEADER = 0x20000000
        ENCRYPTED = 0x10000000
        NONPERSISTENT = 0x08000000

    class ObjType(Enum):
        none = 0
        containersuperblock = 1
        btree = 2
        btree_node = 3
        reserved = 4
        spaceman = 5
        spaceman_cab = 6
        allocationinfofile = 7
        spaceman_bitmap = 8
        spaceman_free_queue = 9
        extent_list_tree = 10
        omap = 11
        checkpoint = 12
        volumesuperblock = 13
        fstree = 14
        blockreftree = 15
        snapmetatree = 16
        nx_reaper = 0x11
        nx_reap_list = 0x12
        omap_snapshot = 0x13
        efi_jumpstart = 0x14
        fusion_middle_tree = 0x15
        nx_fusion_wbc = 0x16
        nx_fusion_wbc_list = 0x17
        er_stat = 0x18
        gbitmap = 0x19
        gbitmap_tree = 0x1a
        gbitmap_block = 0x1b
        # There are more types seen, like 0x1D
        unk1 = 0x1C
        unk2 = 0x1D
        unk3 = 0x1E
        unk4 = 0x1F

    class ItemType(Enum):
        unknown = 0
        fifo_named_pipe = 1
        character_special_file = 2
        folder = 4
        block_special_file = 6
        regular_file = 8
        symlink = 10
        socket = 12
        whiteout = 14

    class EntryType(Enum):
        location = 0 # any
        snap_metadata = 1
        extent = 2
        inode = 3
        xattr = 4
        sibling_link = 5
        dstream_id = 6
        crypto_state = 7
        file_extent = 8
        dir_rec = 9
        dir_stats = 10
        snap_name = 11
        sibling_map = 12
        unknown_reserved = 13
        unknown_reserved2 = 14
        invalid = 15

    class SnapshotFlag(Enum):
        deleted = 1
        reverted = 2

    class VolumeRoleType(Enum):
        none = 0
        system = 1
        user = 2
        recovery = 4
        vm = 8
        preboot = 0x10
        installer = 0x20
        data = 0x40
        baseband = 0x80
        reserved = 0x200

    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._raw_block0 = self._io.read_bytes(4096)
        io = KaitaiStream(BytesIO(self._raw_block0))
        self.block0 = self._root.Block(io, self, self._root)

    class BtreeInfo(KaitaiStruct):
        __slots__ = ['_io', '_parent', '_root', 'bt_flags', 'bt_node_size', 'bt_key_size', 
                    'bt_val_size', 'bt_longest_key', 'bt_longest_val', 'bt_key_count', 'bt_node_count']
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self.bt_flags = self._io.read_u4le()
            self.bt_node_size = self._io.read_u4le()
            self.bt_key_size = self._io.read_u4le()
            self.bt_val_size = self._io.read_u4le()
            self.bt_longest_key = self._io.read_u4le()
            self.bt_longest_val = self._io.read_u4le()
            self.bt_key_count = self._io.read_u8le()
            self.bt_node_count = self._io.read_u8le()


    class Volumesuperblock(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self.magic = self._io.ensure_fixed_contents(struct.pack('4b', 65, 80, 83, 66))
            self.fs_index = self._io.read_u4le()
            self.features = self._io.read_u8le()
            self.readonly_compatible_features = self._io.read_u8le()
            self.incompatible_features = self._io.read_u8le()
            self.unmount_time = self._io.read_s8le()
            self.fs_reserve_block_count = self._io.read_u8le()
            self.fs_quota_block_count = self._io.read_u8le()
            self.fs_alloc_count = self._io.read_u8le()
            self.apfs_meta_crypto = self._io.read_bytes(20)
            self.root_tree_type = self._io.read_u4le()
            self.extentref_tree_type = self._io.read_u4le()
            self.snap_meta_tree_type = self._io.read_u4le()
            self.omap_oid = self._io.read_u8le() #self._root.RefBlock(self._io, self, self._root)
            self.root_tree_oid = self._io.read_u8le()
            self.extentref_tree_oid = self._root.RefBlock(self._io, self, self._root)
            self.snap_meta_tree_oid = self._root.RefBlock(self._io, self, self._root)
            self.revert_to_xid = self._io.read_u8le()
            self.revert_to_sblock_oid = self._io.read_u8le()
            self.next_available_cnid = self._io.read_u8le()
            self.num_files = self._io.read_u8le()
            self.num_folders = self._io.read_u8le()
            self.num_symlinks = self._io.read_u8le()
            self.num_other_fsobjects = self._io.read_u8le()
            self.num_snapshots = self._io.read_u8le()
            self.apfs_total_blocks_alloced = self._io.read_u8le()
            self.apfs_total_blocks_freed = self._io.read_u8le()
            self.volume_uuid = self._io.read_bytes(16)
            self.last_mod_time = self._io.read_s8le()
            self.fs_flags = self._io.read_u8le()
            self.created_by = (KaitaiStream.bytes_terminate(self._io.read_bytes(32), 0, False)).decode("UTF-8")
            self.time_created = self._io.read_s8le()
            self.unknown_312 = self._io.read_bytes(392)
            self.volume_name = (KaitaiStream.bytes_terminate(self._io.read_bytes(256), 0, False)).decode("UTF-8")
            self.next_doc_id = self._io.read_u4le()
            self.apfs_role = self._io.read_u2le() #self._root.VolumeRoleType(self._io.read_u2le())
            self.reserved = self._io.read_u2le()
            self.apfs_root_to_xid = self._io.read_s8le()
            self.apfs_er_state_oid = self._io.read_s8le()
            self.unknown1 = self._io.read_s4le()
            self.unknown2 = self._io.read_s4le()
            self.unknown3 = self._io.read_s8le()
            self.unknown4 = self._io.read_s8le()
            self.data_uuid = self._io.read_bytes(16) # In both System & Data vol, Data's uuid is seen

    class FileExtentKey(KaitaiStruct):
        __slots__ = ['_io', '_parent', '_root', 'offset']
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self.offset = self._io.read_u8le()


    # class HistoryRecord(KaitaiStruct):
    #     __slots__ = ['_io', '_parent', '_root', 'unknown_0', 'unknown_4']
    #     def __init__(self, _io, _parent=None, _root=None):
    #         self._io = _io
    #         self._parent = _parent
    #         self._root = _root if _root else self
    #         self.unknown_0 = self._io.read_u4le()
    #         self.unknown_4 = self._io.read_u4le()


    class OmapKey(KaitaiStruct):
        __slots__ = ['_io', '_parent', '_root', 'oid', 'xid']
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self.oid = self._io.read_u8le()
            self.xid = self._io.read_u8le()


    class OmapRecord(KaitaiStruct):
        __slots__ = ['_io', '_parent', '_root', 'flags', 'size', 'block_num']
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self.flags = self._io.read_u4le()
            self.size = self._io.read_u4le()
            self.paddr = self._root.RefBlock(self._io, self, self._root)


    class SpacemanFreeQueueNodeEntry(KaitaiStruct):
        __slots__ = ['_io', '_parent', '_root', 'header', 'key', 'data']
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self.header = self._root.DynamicEntryHeader(self._io, self, self._root)
            _pos = self._io.pos()
            self._io.seek(((self.header.key_offset + self._parent.table_space_len) + 56))
            self.key = self._root.SpacemanFreeQueueKey(self._io, self, self._root)

            if self.header.data_offset == 0xFFFF: # no data
                self.data = None
            else:
                self._io.seek(((self._root.block_size - self.header.data_offset) - (40 * (self._parent.node_type & BTNODE_ROOT))))
                self.data = self._io.read_u8le() # val? # Do we need to check for leaf/non-leaf?
            self._io.seek(_pos)


    class OmapNodeEntry(KaitaiStruct):
        __slots__ = ['_io', '_parent', '_root', 'header', 'key', 'data']
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self.header = self._root.DynamicEntryHeader(self._io, self, self._root)
            _pos = self._io.pos()
            self._io.seek(((self.header.key_offset + self._parent.table_space_len) + 56))
            self.key = self._root.OmapKey(self._io, self, self._root)

            if self.header.data_offset == 0xFFFF: # no data
                self.data = None
            else:
                self._io.seek(((self._root.block_size - self.header.data_offset) - (40 * (self._parent.node_type & BTNODE_ROOT))))
                if self._parent.level > 0: # not a leaf
                    self.data = self._root.PointerRecord(self._io, self, self._root)
                else:
                    self.data = self._root.OmapRecord(self._io, self, self._root)
            self._io.seek(_pos)


    class NodeEntry(KaitaiStruct):
        __slots__ = ['_io', '_parent', '_root', 'header', '_m_key', 'has_m_key', '_m_data', 'has_m_data']
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self.header = self._root.DynamicEntryHeader(self._io, self, self._root)
            self.has_m_key = False
            self.has_m_data = False

        @property
        def key(self):
            if self.has_m_key:
                return self._m_key

            _pos = self._io.pos()
            self._io.seek(((self.header.key_offset + self._parent.table_space_len) + 56))
            self._m_key = self._root.Key(self._io, self, self._root)
            self.has_m_key = True
            self._io.seek(_pos)
            return self._m_key 

        @property
        def data(self):
            if self.has_m_data:
                return self._m_data

            self.has_m_data = True
            self._m_data = None
            if self.header.data_offset == 0xFFFF: # no data  
                return self._m_data

            _pos = self._io.pos()
            self._io.seek(((self._root.block_size - self.header.data_offset) - (40 * (self._parent.node_type & BTNODE_ROOT))))
            _on = self.key.type_entry
            if _on == 0:
                log.debug("Key kind was zero! treetype={} level={}".format(self._parent._parent.header.subtype, self._parent.level))
            if (self._parent.node_type & BTNODE_LEAF) == 0: # non-leaf nodes
                if _on == 2: #extent
                    self._m_data = self._io.read_u8le() # paddr ?
                elif _on in (3, 4, 5, 6, 8, 9, 10, 12):
                    self._m_data = self._io.read_u8le() # unknown val
                    log.debug("In non-leaf node, got kind 0x{:X}, treetype={}".format(_on, self._parent._parent.header.subtype))
                else:
                    log.debug("Should not go here, got kind 0x{:X}, treetype={}".format(_on, self._parent._parent.header.subtype))
            else: # Leaf nodes
                # In order of most occurrance
                if _on == 9: #self._root.EntryType.dir_rec.value:
                    self._m_data = self._root.DrecHashedRecord(self._io, self, self._root)
                elif _on == 3: #self._root.EntryType.inode.value:
                    self._m_data = self._root.InodeRecord(self._io, self, self._root)
                elif _on == 4: #self._root.EntryType.xattr.value:
                    self._m_data = self._root.XattrRecord(self._io, self, self._root)
                elif _on == 8: #self._root.EntryType.file_extent.value:
                    self._m_data = self._root.FileExtentRecord(self._io, self, self._root)
                elif _on == 6: #self._root.EntryType.dstream_id.value:
                    self._m_data = self._root.DstreamIdRecord(self._io, self, self._root)
                elif _on == 5: #self._root.EntryType.sibling_link.value:
                    self._m_data = self._root.SiblingRecord(self._io, self, self._root)
                elif _on == 12: #self._root.EntryType.sibling_map.value:
                    self._m_data = self._root.SiblingMapRecord(self._io, self, self._root)
                elif _on == 2: #self._root.EntryType.extent.value:
                    self._m_data = self._root.ExtentRecord(self._io, self, self._root)
                elif _on == 1: #self._root.EntryType.snap_metadata.value:
                    self._m_data = self._root.SnapMetadataRecord(self._io, self, self._root)
                elif _on == 11: #self._root.EntryType.snap_name.value:
                    self._m_data = self._root.SnapNameRecord(self._io, self, self._root)
                elif _on == 10: #self._root.EntryType.dir_stats.value:
                    self._m_data = self._root.DirStatsRecord(self._io, self, self._root)

            self._io.seek(_pos)
            return self._m_data


    class Allocationinfofile(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self.unknown_32 = self._io.read_bytes(4)
            self.num_entries = self._io.read_u4le()
            self.entries = [None] * (self.num_entries)
            for i in range(self.num_entries):
                self.entries[i] = self._root.AllocationinfofileEntry(self._io, self, self._root)


    class BlockHeader(KaitaiStruct):
        __slots__ = ['_io', '_parent', '_root', 'checksum', 'oid', 'xid', 
                    'type_block', 'flags', 'subtype']
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self.checksum = self._io.read_u8le()
            self.oid = self._io.read_u8le()
            self.xid = self._io.read_u8le()
            self.type_block = self._root.ObjType(self._io.read_u2le())
            self.flags = self._io.read_u2le()
            self.subtype = self._io.read_u4le()
            #self.type_content = self._root.ObjType(0xff & subtype)
            #self.type_storage = 0xc0000000 & subtype


    class CheckpointEntry(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self.type_block = self._root.ObjType(self._io.read_u2le())
            self.flags = self._io.read_u2le()
            self.type_content = self._root.ObjType(self._io.read_u4le())
            self.block_size = self._io.read_u4le()
            self.unknown_52 = self._io.read_u4le()
            self.unknown_56 = self._io.read_u4le()
            self.unknown_60 = self._io.read_u4le()
            self.block_id = self._io.read_u8le()
            self.block = self._root.RefBlock(self._io, self, self._root)


    class Containersuperblock(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self.magic = self._io.ensure_fixed_contents(struct.pack('4b', 78, 88, 83, 66))
            self.block_size = self._io.read_u4le()
            self.num_blocks = self._io.read_u8le()
            self.features = self._io.read_u8le()
            self.readonly_compatible_features = self._io.read_u8le()
            self.incompatible_features = self._io.read_u8le()
            self.uuid = self._io.read_bytes(16)
            self.next_oid = self._io.read_u8le()
            self.next_xid = self._io.read_u8le()
            self.xp_desc_blocks = self._io.read_u4le()
            self.xp_data_blocks = self._io.read_u4le()
            self.xp_desc_base = self._io.read_s8le()
            self.xp_data_base = self._io.read_s8le()
            self.xp_desc_next = self._io.read_u4le()
            self.xp_data_next = self._io.read_u4le()
            self.xp_desc_index = self._io.read_u4le()
            self.xp_desc_len = self._io.read_u4le()
            self.xp_data_index = self._io.read_u4le()
            self.xp_data_len = self._io.read_u4le()
            self.spaceman_oid = self._io.read_u8le()
            self.omap_oid = self._io.read_u8le() #self._root.RefBlock(self._io, self, self._root)
            self.reaper_oid = self._io.read_u8le()
            self.test_type = self._io.read_u4le()
            self.num_volumesuperblock_ids = self._io.read_u4le()
            self.volumesuperblock_ids = [None] * (100) # NX_MAX_FILE_SYSTEMS=100
            for i in range(100):
                self.volumesuperblock_ids[i] = self._io.read_u8le()
            self.counters = [None] * 32
            for i in range(32):
                self.counters[i] = self._io.read_u8le()
            self.blocked_out_start_paddr = self._io.read_s8le()
            self.blocked_out_block_count = self._io.read_u8le()
            self.evict_mapping_tree_oid = self._io.read_u8le()
            self.flags = self._io.read_u8le()
            self.efi_jumpstart = self._io.read_u8le()
            self.fusion_uuid = self._io.read_bytes(16)
            self.keylocker_paddr = self._io.read_u8le()
            self.keylocker_block_count = self._io.read_s8le()
            self.ephemeral_info = self._io.read_u8le() * 4
            self.test_oid = self._io.read_u8le()
            self.fusion_mt_oid = self._io.read_u8le()
            self.fusion_wbc_oid = self._io.read_u8le()
            self.fusion_wbc_paddr = self._io.read_u8le()
            self.fusion_wbc_count = self._io.read_u8le()

    class DrecHashedRecord(KaitaiStruct):
        __slots__ = ['_io', '_parent', '_root', 'node_id', 'date_added', 'type_item', 'xfields']
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self.node_id = self._io.read_u8le()
            self.date_added = self._io.read_s8le()
            self.type_item = self._root.ItemType(self._io.read_u2le() & 0xF) #DREC_TYPE_MASK = 0x000f
            self.xfields = {}
            if _parent.header.data_length > 18:  # extended fields exist!
                xf_num_exts = self._io.read_u2le()
                xf_used_data = self._io.read_u2le()
                records = [None] * xf_num_exts
                for i in range(xf_num_exts):
                    records[i] = self._root.XfHeader(self._io, self, self._root)
                pos = self._io.pos()
                skip = 0
                for i in range(xf_num_exts):
                    self._io.seek(pos + skip)
                    record = records[i]
                    skip += record.length + ((8 - record.length) % 8) # 8 byte boundary
                    if record.x_type == INO_EXT_TYPE_NAME:
                        name = (self._io.read_bytes(record.length - 1)).decode("UTF-8")
                        self.xfields[INO_EXT_TYPE_NAME] = name
                    elif record.x_type == INO_EXT_TYPE_DSTREAM:
                        x_dstream = self._root.DStream(self._io, self, self._root)
                        self.xfields[INO_EXT_TYPE_DSTREAM] = x_dstream
                    elif record.x_type == INO_EXT_TYPE_RDEV:         self.xfields[INO_EXT_TYPE_RDEV] = self._io.read_u4le()
                    elif record.x_type == INO_EXT_TYPE_SPARSE_BYTES: self.xfields[INO_EXT_TYPE_SPARSE_BYTES] = self._io.read_u8le()
                    elif record.x_type == INO_EXT_TYPE_DOCUMENT_ID:  self.xfields[INO_EXT_TYPE_DOCUMENT_ID] = self._io.read_u4le()
                    elif record.x_type == INO_EXT_TYPE_SNAP_XID:     self.xfields[INO_EXT_TYPE_SNAP_XID] = self._io.read_u8le()
                    elif record.x_type == INO_EXT_TYPE_DELTA_TREE_OID:self.xfields[INO_EXT_TYPE_DELTA_TREE_OID] = self._io.read_u8le()
                    elif record.x_type == INO_EXT_TYPE_PREV_FSIZE:   self.xfields[INO_EXT_TYPE_PREV_FSIZE] = self._io.read_u8le()
                    elif record.x_type == INO_EXT_TYPE_FINDER_INFO:  self.xfields[INO_EXT_TYPE_FINDER_INFO] = self._io.read_u4le()
                    elif record.x_type == INO_EXT_TYPE_FS_UUID:      self.xfields[INO_EXT_TYPE_FS_UUID] = self._io.read_bytes(16)
                    elif record.x_type == INO_EXT_TYPE_DIR_STATS_KEY:
                        x_dir_stats_key = self._io.read_u8le()
                        self.xfields[INO_EXT_TYPE_DIR_STATS_KEY] = x_dir_stats_key

    class DirStatsRecord(KaitaiStruct):
        __slots__ = ['_io', '_parent', '_root', 'num_children', 'total_size', 'chained_key', 'gen_count']
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self.num_children = self._io.read_u8le()
            self.total_size = self._io.read_s8le()
            self.chained_key = self._io.read_s8le()
            self.gen_count = self._io.read_s8le()


    class AllocationinfofileEntry(KaitaiStruct):
        __slots__ = ['_io', '_parent', '_root', 'xid', 'unknown_8', 'unknown_12', 'num_blocks', 'num_free_blocks', 'allocationfile_block']
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self.xid = self._io.read_u8le()
            self.unknown_8 = self._io.read_u4le()
            self.unknown_12 = self._io.read_u4le()
            self.num_blocks = self._io.read_u4le()
            self.num_free_blocks = self._io.read_u4le()
            self.allocationfile_block = self._io.read_u8le()


    class FileExtentRecord(KaitaiStruct):
        __slots__ = ['_io', '_parent', '_root', 'size', 'flags', 'phys_block_num', 'crypto_id']
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            len_and_flags = self._io.read_u8le()
            self.size = len_and_flags & 0x00ffffffffffffff
            self.flags = (len_and_flags & 0xff00000000000000) >> 56
            self.phys_block_num = self._io.read_u8le() #self._root.RefBlock(self._io, self, self._root)
            self.crypto_id = self._io.read_u8le()


    class Key(KaitaiStruct):
        __slots__ = ['_io', '_parent', '_root', 'obj_id', 'type_entry', 'content']
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            #self.key_low = self._io.read_u4le()
            #self.key_high = self._io.read_u4le()
            key_raw = self._io.read_u8le()
            self.obj_id = key_raw & 0x0FFFFFFFFFFFFFFF
            self.type_entry = key_raw >> 60
            _on = self.type_entry
            if _on == 8: #self._root.EntryType.file_extent.value:
                self.content = self._root.FileExtentKey(self._io, self, self._root)
            elif _on == 4: #self._root.EntryType.xattr.value:
                self.content = self._root.XattrKey(self._io, self, self._root)
            elif _on == 5: #self._root.EntryType.sibling_link:
                self.content = self._root.SiblingKey(self._io, self, self._root)
            elif _on == 0xb: #self._root.EntryType.snap_name:
                self.content = self._root.SnapNameKey(self._io, self, self._root)
            elif _on == 9: #self._root.EntryType.dir_rec.value:
                self.content = self._root.DrecHashedKey(self._io, self, self._root)


    class SiblingRecord(KaitaiStruct):
        __slots__ = ['_io', '_parent', '_root', 'parent_id', 'name']
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self.parent_id = self._io.read_u8le()
            namelength = self._io.read_u2le()
            self.name = (KaitaiStream.bytes_terminate(self._io.read_bytes(namelength), 0, False)).decode("UTF-8")


    class SiblingMapRecord(KaitaiStruct):
        __slots__ = ['_io', '_parent', '_root', 'file_id']
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self.file_id = self._io.read_u8le()


    class DstreamIdRecord(KaitaiStruct):
        __slots__ = ['_io', '_parent', '_root', 'refcnt']
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self.refcnt = self._io.read_u4le()


    class DynamicEntryHeader(KaitaiStruct):
        __slots__ = ['_io', '_parent', '_root', 'key_offset', 'data_offset', 'key_length', 'data_length']
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self.key_offset = self._io.read_u2le()
            if (self._parent._parent.node_type & BTNODE_FIXED_KV_SIZE) == 0:
                self.key_length = self._io.read_u2le()

            self.data_offset = self._io.read_u2le()
            if (self._parent._parent.node_type & BTNODE_FIXED_KV_SIZE) == 0:
                self.data_length = self._io.read_u2le()


    class Block(KaitaiStruct):
        __slots__ = ['_io', '_parent', '_root', 'header', 'body']
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self.header = self._root.BlockHeader(self._io, self, self._root)
            _on = self.header.type_block.value
            if _on == 3: #self._root.ObjType.btree_node:
                self.body = self._root.Node(self._io, self, self._root)
            elif _on == 7: #self._root.ObjType.allocationinfofile: Spaceman_cib
                self.body = self._root.Allocationinfofile(self._io, self, self._root)
            elif _on == 5: #self._root.ObjType.spaceman:
                self.body = self._root.Spaceman(self._io, self, self._root)
            elif _on == 11: #self._root.ObjType.omap:
                self.body = self._root.Omap(self._io, self, self._root)
            elif _on == 2: #self._root.ObjType.btree:
                self.body = self._root.Node(self._io, self, self._root)
            elif _on == 13: #self._root.ObjType.volumesuperblock:
                self.body = self._root.Volumesuperblock(self._io, self, self._root)
            elif _on == 12: #self._root.ObjType.checkpoint:
                self.body = self._root.Checkpoint(self._io, self, self._root)
            elif _on == 1: #self._root.ObjType.containersuperblock:
                self.body = self._root.Containersuperblock(self._io, self, self._root)
            elif _on == 0x13: #self._root.ObjType.omap_snapshot:
                self.body = self._root.OmapSnapshot(self._io, self, self._root)


    class PointerRecord(KaitaiStruct):
        __slots__ = ['_io', '_parent', '_root', 'pointer']
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self.pointer = self._io.read_u8le()

 
    class XattrKey(KaitaiStruct):
        __slots__ = ['_io', '_parent', '_root', 'name']
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            name_len = self._io.read_u2le()
            self.name = (KaitaiStream.bytes_terminate(self._io.read_bytes(name_len), 0, False)).decode("UTF-8")


    class XattrRecord(KaitaiStruct):
        __slots__ = ['_io', '_parent', '_root', 'flags', 'len_data', 'xdata']
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self.flags = self._io.read_u2le()
            self.xdata_len = self._io.read_u2le()
            #_on = self.flags
            #if _on == 6: #self._root.EaType.symlink:
            #    self.data = (KaitaiStream.bytes_terminate(self._io.read_bytes(self.xdata_len), 0, False)).decode(UTF-8")
            #else:
            self.xdata = self._io.read_bytes(self.xdata_len) # Either data inline or objId and DstreamRecord


    class RefBlock(KaitaiStruct):
        __slots__ = ['_io', '_parent', '_root', 'value', '_m_target', 'has_m_target']
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self.value = self._io.read_u8le()
            self.has_m_target = False

        @property
        def target(self):
            if self.has_m_target: #hasattr(self, '_m_target'):
                return self._m_target #if hasattr(self, '_m_target') else None

            io = self._root._io
            _pos = io.pos()
            io.seek((self.value * self._root.block_size))
            self._raw__m_target = io.read_bytes(self._root.block_size)
            io = KaitaiStream(BytesIO(self._raw__m_target))
            self._m_target = self._root.Block(io, self, self._root)
            self.has_m_target = True
            io.seek(_pos)
            return self._m_target #if hasattr(self, '_m_target') else None


    class SiblingKey(KaitaiStruct):
        __slots__ = ['_io', '_parent', '_root', 'sibling_id']
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self.sibling_id = self._io.read_u8le()


    class SnapNameKey(KaitaiStruct):
        __slots__ = ['_io', '_parent', '_root', 'name']
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            name_len = self._io.read_u2le()
            self.name = (KaitaiStream.bytes_terminate(self._io.read_bytes(name_len), 0, False)).decode("UTF-8")


    class SnapMetadataRecord(KaitaiStruct):
        __slots__ = ['_io', '_parent', '_root', 'extentref_tree_oid', 'sblock_oid', 'create_time', 'change_time', 
                    'inum', 'extentref_tree_type', 'flags', 'name']
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self.extentref_tree_oid = self._io.read_u8le()
            self.sblock_oid = self._io.read_u8le()
            self.create_time = self._io.read_u8le()
            self.change_time = self._io.read_u8le()
            self.inum = self._io.read_u8le()
            self.extentref_tree_type = self._io.read_u4le()
            self.flags = self._io.read_u4le()
            name_len = self._io.read_u2le()
            self.name = (KaitaiStream.bytes_terminate(self._io.read_bytes(name_len), 0, False)).decode("UTF-8")


    class SnapNameRecord(KaitaiStruct):
        __slots__ = ['_io', '_parent', '_root', 'snap_xid']
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self.snap_xid = self._io.read_u8le()


    class Checkpoint(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self.unknown_0 = self._io.read_u4le()
            self.num_entries = self._io.read_u4le()
            self.entries = [None] * (self.num_entries)
            for i in range(self.num_entries):
                self.entries[i] = self._root.CheckpointEntry(self._io, self, self._root)


    class Omap(KaitaiStruct):
        __slots__ = ['_io', '_parent', '_root', 'flags', 'snap_count','tree_type',
                        'snapshot_tree_type', 'tree_oid', 'snapshot_tree_oid', 'most_recent_snap'
                        'pending_revert_min', 'pending_revert_min']
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self.flags = self._io.read_u4le()
            self.snap_count = self._io.read_u4le()
            self.tree_type = self._io.read_u4le()
            self.snapshot_tree_type = self._io.read_u4le()
            self.tree_oid = self._io.read_u8le()
            self.snapshot_tree_oid = self._io.read_u8le()
            self.most_recent_snap = self._io.read_u8le()
            self.pending_revert_min = self._io.read_u8le()
            self.pending_revert_min = self._io.read_u8le()


    class OmapSnapshot(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self.flags = self._root.SnapshotFlag(self._io.read_u4le())
            pad = self._io.read_u4le()
            self.oid = self._io.read_u8le()


    class Node(KaitaiStruct):
        __slots__ = ['_io', '_parent', '_root', 'node_type', 'level', 'entry_count', 
                    'table_space_off', 'table_space_len', 'free_space_off', 'free_space_len',
                    'key_free_list_off', 'key_free_list_len', 'val_free_list_off', 'val_free_list_len',
                      'entries', 'btree_info']
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self.node_type = self._io.read_u2le() # 1=Root, 2=Leaf, 4=fixed_kv_size, 8=invalid
            self.level = self._io.read_u2le()
            self.entry_count = self._io.read_u4le()
            self.table_space_off = self._io.read_u2le() # 0xFFFF is invalid, denotes last entry in freelist
            self.table_space_len = self._io.read_u2le()
            self.free_space_off = self._io.read_u2le() # 0xFFFF is invalid, denotes last entry in freelist
            self.free_space_len = self._io.read_u2le()
            self.key_free_list_off = self._io.read_u2le() # 0xFFFF is invalid, denotes last entry in freelist
            self.key_free_list_len = self._io.read_u2le()
            self.val_free_list_off = self._io.read_u2le() # 0xFFFF is invalid, denotes last entry in freelist
            self.val_free_list_len = self._io.read_u2le()
            self.entries = [None] * (self.entry_count)
            subtype = _parent.header.subtype
            if subtype == 11: #omap
                for i in range(self.entry_count):
                    self.entries[i] = self._root.OmapNodeEntry(self._io, self, self._root)
            elif subtype == 9: #spaceman_free_queue
                for i in range(self.entry_count):
                    self.entries[i] = self._root.SpacemanFreeQueueNodeEntry(self._io, self, self._root)
            else:
                for i in range(self.entry_count):
                    self.entries[i] = self._root.NodeEntry(self._io, self, self._root)
            if self.node_type & BTNODE_ROOT:
                self._io.seek(self._root.block_size - 40)
                self.btree_info = self._root.BtreeInfo(self._io, self, self._root)
            else:
                self.btree_info = None


    class XfHeader(KaitaiStruct):
        __slots__ = ['_io', '_parent', '_root', 'x_type', 'x_flags', 'length']
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self.x_type = self._io.read_u1()
            self.x_flags = self._io.read_u1()
            self.length = self._io.read_u2le()


    class XfName(KaitaiStruct):
        __slots__ = ['_io', '_parent', '_root', 'name']
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self.xf_name = (KaitaiStream.bytes_terminate(self._io.read_bytes(name_len), 0, False)).decode("UTF-8")


    class DStream(KaitaiStruct):
        __slots__ = ['_io', '_parent', '_root', 'size', 'alloced_size', 'default_crypto_id', 'total_bytes_written', 'total_bytes_read']
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self.size = self._io.read_u8le()
            self.alloced_size = self._io.read_u8le()
            self.default_crypto_id = self._io.read_u8le()
            self.total_bytes_written = self._io.read_u8le()
            self.total_bytes_read = self._io.read_u8le()


    class InodeRecord(KaitaiStruct):
        __slots__ = ['_io', '_parent', '_root', 'parent_id', 'node_id', 'creation_timestamp', 'modified_timestamp', 
                    'changed_timestamp', 'accessed_timestamp', 'flags', 'nchildren_or_nlink', 'default_protection_class', 
                    'write_generation_counter', 'bsdflags', 'owner_id', 'group_id', 'mode', 'xf_num_exts', 
                    'xf_used_data', 'records','name', 'logical_size', 'physical_size', 'xfields']
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self.parent_id = self._io.read_u8le()
            self.node_id = self._io.read_u8le()
            self.creation_timestamp = self._io.read_s8le()
            self.modified_timestamp = self._io.read_s8le()
            self.changed_timestamp = self._io.read_s8le()
            self.accessed_timestamp = self._io.read_s8le()
            self.flags = self._io.read_u8le()
            self.nchildren_or_nlink = self._io.read_u4le()
            self.default_protection_class = self._io.read_u4le()
            self.write_generation_counter = self._io.read_u4le()
            self.bsdflags = self._io.read_u4le()
            self.owner_id = self._io.read_u4le()
            self.group_id = self._io.read_u4le()
            self.mode = self._io.read_u2le()
            pad1 = self._io.read_u2le()
            pad2 = self._io.read_u8le()
            self.xfields = {}
            self.name = ''
            self.logical_size = 0
            self.physical_size = 0
            if _parent.header.data_length > 92:  # extended fields exist!
                self.xf_num_exts = self._io.read_u2le()
                self.xf_used_data = self._io.read_u2le()
                self.records = [None] * (self.xf_num_exts)
                for i in range(self.xf_num_exts):
                    self.records[i] = self._root.XfHeader(self._io, self, self._root)
                pos = self._io.pos()
                skip = 0
                for i in range(self.xf_num_exts):
                    self._io.seek(pos + skip)
                    record = self.records[i]
                    skip += record.length + ((8 - record.length) % 8) # 8 byte boundary
                    if record.x_type == INO_EXT_TYPE_NAME:
                        self.name = (self._io.read_bytes(record.length - 1)).decode("UTF-8")
                        self.xfields[INO_EXT_TYPE_NAME] = self.name
                    elif record.x_type == INO_EXT_TYPE_DSTREAM:
                        x_dstream = self._root.DStream(self._io, self, self._root)
                        self.logical_size = x_dstream.size
                        self.physical_size = x_dstream.alloced_size
                        self.xfields[INO_EXT_TYPE_DSTREAM] = x_dstream
                    elif record.x_type == INO_EXT_TYPE_RDEV:         self.xfields[INO_EXT_TYPE_RDEV] = self._io.read_u4le()
                    elif record.x_type == INO_EXT_TYPE_SPARSE_BYTES: self.xfields[INO_EXT_TYPE_SPARSE_BYTES] = self._io.read_u8le()
                    elif record.x_type == INO_EXT_TYPE_DOCUMENT_ID:  self.xfields[INO_EXT_TYPE_DOCUMENT_ID] = self._io.read_u4le()
                    elif record.x_type == INO_EXT_TYPE_SNAP_XID:     self.xfields[INO_EXT_TYPE_SNAP_XID] = self._io.read_u8le()
                    elif record.x_type == INO_EXT_TYPE_DELTA_TREE_OID:self.xfields[INO_EXT_TYPE_DELTA_TREE_OID] = self._io.read_u8le()
                    elif record.x_type == INO_EXT_TYPE_PREV_FSIZE:   self.xfields[INO_EXT_TYPE_PREV_FSIZE] = self._io.read_u8le()
                    elif record.x_type == INO_EXT_TYPE_FINDER_INFO:  self.xfields[INO_EXT_TYPE_FINDER_INFO] = self._io.read_u4le()
                    elif record.x_type == INO_EXT_TYPE_FS_UUID:      self.xfields[INO_EXT_TYPE_FS_UUID] = self._io.read_bytes(16)
                    elif record.x_type == INO_EXT_TYPE_DIR_STATS_KEY:
                        x_dir_stats_key = self._io.read_u8le()
                        self.xfields[INO_EXT_TYPE_DIR_STATS_KEY] = x_dir_stats_key
                    #else:
                # END ADDED
                #self.unknown_remainder = self._io.read_bytes_full()


    class ExtentRecord(KaitaiStruct):
        __slots__ = ['_io', '_parent', '_root', 'length', 'kind', 'owning_obj_id', 'refcnt']
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            len_and_kind = self._io.read_u8le()
            self.length = len_and_kind & 0x0fffffffffffffff
            self.kind = (len_and_kind & 0xf000000000000000) >> 60
            self.owning_obj_id = self._io.read_u8le()
            self.refcnt = self._io.read_u4le()


    # class ExtentKey(KaitaiStruct):
    #     __slots__ = ['_io', '_parent', '_root', 'paddr']
    #     def __init__(self, _io, _parent=None, _root=None):
    #         self._io = _io
    #         self._parent = _parent
    #         self._root = _root if _root else self
    #         self.paddr = self._root.RefBlock(self._io, self, self._root)


    class DrecHashedKey(KaitaiStruct):
        __slots__ = ['_io', '_parent', '_root', 'hash', 'name']
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            name_len_and_hash = self._io.read_u4le()
            len_name = name_len_and_hash & 0x000003ff
            self.hash = (name_len_and_hash & 0xfffff400) >> 10
            self.name = (KaitaiStream.bytes_terminate(self._io.read_bytes(len_name), 0, False)).decode("UTF-8")


    class SpacemanFreeQueueKey(KaitaiStruct):
        __slots__ = ['_io', '_parent', '_root', 'xid', 'paddr']
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self.xid = self._io.read_u8le()
            self.paddr = self._io.read_u8le()


    class Spaceman(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self.block_size = self._io.read_u4le()
            self.unknown_36 = self._io.read_bytes(12)
            self.num_blocks = self._io.read_u8le()
            self.unknown_56 = self._io.read_bytes(8)
            self.num_entries = self._io.read_u4le()
            self.unknown_68 = self._io.read_u4le()
            self.num_free_blocks = self._io.read_u8le()
            self.ofs_entries = self._io.read_u4le()
            self.unknown_84 = self._io.read_bytes(92)
            self.prev_allocationinfofile_block = self._io.read_u8le()
            self.unknown_184 = self._io.read_bytes(200)

        @property
        def allocationinfofile_blocks(self):
            if hasattr(self, '_m_allocationinfofile_blocks'):
                return self._m_allocationinfofile_blocks #if hasattr(self, '_m_allocationinfofile_blocks') else None

            _pos = self._io.pos()
            self._io.seek(self.ofs_entries)
            self._m_allocationinfofile_blocks = [None] * (self.num_entries)
            for i in range(self.num_entries):
                self._m_allocationinfofile_blocks[i] = self._io.read_u8le()

            self._io.seek(_pos)
            return self._m_allocationinfofile_blocks #if hasattr(self, '_m_allocationinfofile_blocks') else None


    # class HistoryKey(KaitaiStruct):
    #     __slots__ = ['_io', '_parent', '_root', 'xid', 'block_num']
    #     def __init__(self, _io, _parent=None, _root=None):
    #         self._io = _io
    #         self._parent = _parent
    #         self._root = _root if _root else self
    #         self.xid = self._io.read_u8le()
    #         self.block_num = self._root.RefBlock(self._io, self, self._root)


    @property
    def block_size(self):
        if hasattr(self, '_m_block_size'):
            return self._m_block_size #if hasattr(self, '_m_block_size') else None

        self._m_block_size = self._root.block0.body.block_size
        return self._m_block_size #if hasattr(self, '_m_block_size') else None


