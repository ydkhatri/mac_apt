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

import array
import struct
import zlib
from enum import Enum
from pkg_resources import parse_version

from kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

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
        
    class ContentType(Enum):
        empty = 0
        history = 9
        location = 11
        files = 14
        extents = 15
        unknown3 = 16

    # class EaType(Enum):
    #     unknown_1 = 1
    #     generic = 2
    #     symlink = 6
    #     unknown_17 = 17 # new unknown one!

    class BlockType(Enum):
        containersuperblock = 1
        rootnode = 2
        node = 3
        reserved = 4
        spaceman = 5
        spaceman_cab = 6
        allocationinfofile = 7
        spaceman_bitmap = 8
        spaceman_free_queue = 9
        extent_list_tree = 10
        btree = 11
        checkpoint = 12
        volumesuperblock = 13
        fstree = 14
        blockreftree = 15
        snapmetatree = 16
        NX_REAPER = 0x11
        NX_REAP_LIST = 0x12
        OMAP_SNAPSHOT = 0x13
        EFI_JUMPSTART = 0x14
        FUSION_MIDDLE_TREE = 0x15
        NX_FUSION_WBC = 0x16
        NX_FUSION_WBC_LIST = 0x17
        ER_STAT = 0x18
        GBITMAP = 0x19
        GBITMAP_TREE = 0x1A
        GBITMAP_BLOCK = 0x1B
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
        location = 0
        snap_metadata = 1
        extent = 2
        inode = 3
        extattr = 4
        hardlink = 5
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

    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._raw_block0 = self._io.read_bytes(4096)
        io = KaitaiStream(BytesIO(self._raw_block0))
        self.block0 = self._root.Block(io, self, self._root)

    class Volumesuperblock(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self.magic = self._io.ensure_fixed_contents(struct.pack('4b', 65, 80, 83, 66))
            self.unknown_36 = self._io.read_bytes(20)
            self.feature_flags = self._io.read_u8le()
            self.unknown_64 = self._io.read_bytes(24)
            self.num_blocks_used = self._io.read_u8le()
            self.unknown_96 = self._io.read_bytes(32)
            self.omap_oid = self._io.read_u8le() #self._root.RefBlock(self._io, self, self._root)
            self.root_dir_id = self._io.read_u8le()
            self.inode_map_block = self._root.RefBlock(self._io, self, self._root)
            self.unknown_152_blk = self._root.RefBlock(self._io, self, self._root)
            self.unknown_160 = self._io.read_bytes(16)
            self.next_available_cnid = self._io.read_u8le()
            self.num_files = self._io.read_u8le()
            self.num_folders = self._io.read_u8le()
            self.unknown_200 = self._io.read_u8le()
            self.unknown_208 = self._io.read_u8le()
            self.existing_snapshots = self._io.read_u8le()
            self.unknown_224 = self._io.read_bytes(8)
            self.unknown_232 = self._io.read_bytes(8)
            self.volume_uuid = self._io.read_bytes(16)
            self.time_updated = self._io.read_s8le()
            self.encryption_flags = self._io.read_u8le()
            self.created_by = (KaitaiStream.bytes_terminate(self._io.read_bytes(32), 0, False)).decode("UTF-8")
            self.time_created = self._io.read_s8le()
            self.unknown_312 = self._io.read_bytes(392)
            self.volume_name = (self._io.read_bytes_term(0, False, True, True)).decode("UTF-8")


    class FileExtentKey(KaitaiStruct):
        __slots__ = ['_io', '_parent', '_root', 'offset']
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self.offset = self._io.read_u8le()


    class HistoryRecord(KaitaiStruct):
        __slots__ = ['_io', '_parent', '_root', 'unknown_0', 'unknown_4']
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self.unknown_0 = self._io.read_u4le()
            self.unknown_4 = self._io.read_u4le()


    class LocationKey(KaitaiStruct):
        __slots__ = ['_io', '_parent', '_root', 'block_id', 'version']
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self.block_id = self._io.read_u8le()
            self.version = self._io.read_u8le()

    # class DstreamIdKey(KaitaiStruct):
    #     __slots__ = ['_io', '_parent', '_root']
    #     def __init__(self, _io, _parent=None, _root=None):
    #         self._io = _io
    #         self._parent = _parent
    #         self._root = _root if _root else self

    class LocationRecord(KaitaiStruct):
        __slots__ = ['_io', '_parent', '_root', 'block_start', 'block_length', 'block_num']
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self.block_start = self._io.read_u4le()
            self.block_length = self._io.read_u4le()
            self.block_num = self._root.RefBlock(self._io, self, self._root)


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
            if self.has_m_key: #hasattr(self, '_m_key'):
                return self._m_key #if hasattr(self, '_m_key') else None

            _pos = self._io.pos()
            self._io.seek(((self.header.ofs_key + self._parent.ofs_keys) + 56))
            self._m_key = self._root.Key(self._io, self, self._root)
            self.has_m_key = True
            self._io.seek(_pos)
            return self._m_key #if hasattr(self, '_m_key') else None

        @property
        def data(self):
            if self.has_m_data:  # hasattr(self, '_m_data'):
                return self._m_data #if hasattr(self, '_m_data') else None

            _pos = self._io.pos()
            self._io.seek(((self._root.block_size - self.header.ofs_data) - (40 * (self._parent.type_flags & 1))))
            _on = ((256 if (self._parent.type_flags & 2) == 0 else 0) + (self.key.type_entry * (0 if (self._parent.type_flags & 2) == 0 else 1)))
            # In order of most occurrance
            if _on == 9: #self._root.EntryType.dir_rec.value:
                self._m_data = self._root.DrecHashedRecord(self._io, self, self._root)
                self.has_m_data = True
            elif _on == 3: #self._root.EntryType.inode.value:
                self._m_data = self._root.InodeRecord(self._io, self, self._root)
                self.has_m_data = True
            elif _on == 4: #self._root.EntryType.extattr.value:
                self._m_data = self._root.ExtattrRecord(self._io, self, self._root)
                self.has_m_data = True
            elif _on == 8: #self._root.EntryType.file_extent.value:
                self._m_data = self._root.FileExtentRecord(self._io, self, self._root)
                self.has_m_data = True
            elif _on == 6: #self._root.EntryType.dstream_id.value:
                self._m_data = self._root.DstreamIdRecord(self._io, self, self._root)
                self.has_m_data = True
            elif _on == 5: #self._root.EntryType.hardlink.value:
                self._m_data = self._root.HardlinkRecord(self._io, self, self._root)
                self.has_m_data = True
            elif _on == 12: #self._root.EntryType.sibling_map.value:
                self._m_data = self._root.SiblingMapRecord(self._io, self, self._root)
                self.has_m_data = True
            elif _on == 0: #self._root.EntryType.location.value:
                self._m_data = self._root.LocationRecord(self._io, self, self._root)
                self.has_m_data = True
            elif _on == 2: #self._root.EntryType.extent.value:
                self._m_data = self._root.ExtentRecord(self._io, self, self._root)
                self.has_m_data = True
            elif _on == 256:
                self._m_data = self._root.PointerRecord(self._io, self, self._root)
                self.has_m_data = True
            elif _on == 1: #self._root.EntryType.snap_metadata.value:
                self._m_data = self._root.SnapMetadataRecord(self._io, self, self._root)
                self.has_m_data = True
            elif _on == 11: #self._root.EntryType.snap_name.value:
                self._m_data = self._root.SnapNameRecord(self._io, self, self._root)
                self.has_m_data = True
            elif _on == 10: #self._root.EntryType.dir_stats.value:
                self._m_data = self._root.DirStatsRecord(self._io, self, self._root)
                self.has_m_data = True

            self._io.seek(_pos)
            return self._m_data if self.has_m_data else None #hasattr(self, '_m_data') else None


    class FullEntryHeader(KaitaiStruct):
        __slots__ = ['_io', '_parent', '_root', 'ofs_key', 'len_key', 'ofs_data', 'len_data']
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self.ofs_key = self._io.read_s2le()
            self.len_key = self._io.read_u2le()
            self.ofs_data = self._io.read_s2le()
            self.len_data = self._io.read_u2le()


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
        __slots__ = ['_io', '_parent', '_root', 'checksum', 'block_id', 'version', 'type_block', 'flags', 'type_content', 'padding']
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self.checksum = self._io.read_u8le()
            self.block_id = self._io.read_u8le()
            self.version = self._io.read_u8le()
            self.type_block = self._root.BlockType(self._io.read_u2le())
            self.flags = self._io.read_u2le()
            self.type_content = self._root.ContentType(self._io.read_u2le())
            self.padding = self._io.read_u2le()


    class CheckpointEntry(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self.type_block = self._root.BlockType(self._io.read_u2le())
            self.flags = self._io.read_u2le()
            self.type_content = self._root.ContentType(self._io.read_u4le())
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
            self.volumesuperblock_ids = [None] * (self.num_volumesuperblock_ids)
            for i in range(self.num_volumesuperblock_ids):
                self.volumesuperblock_ids[i] = self._io.read_u8le()
            self.counters = [None] * 32
            for i in range(32):
                self.counters[i] = self._io.read_u8le()
            self.blocked_out_start_paddr = self._io.read_s8le()
            self.blocked_out_block_count = self._io.read_u8le()
            self.evict_mapping_tree_oid = self._io.read_u8le()
            self.flags = self._io.read_u8le()


    class DrecHashedRecord(KaitaiStruct):
        __slots__ = ['_io', '_parent', '_root', 'node_id', 'date_added', 'type_item']
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self.node_id = self._io.read_u8le()
            self.date_added = self._io.read_s8le()
            self.type_item = self._root.ItemType(self._io.read_u2le() & 0xF)


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
        __slots__ = ['_io', '_parent', '_root', 'version', 'unknown_8', 'unknown_12', 'num_blocks', 'num_free_blocks', 'allocationfile_block']
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self.version = self._io.read_u8le()
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
            self.phys_block_num = self._root.RefBlock(self._io, self, self._root)
            self.crypto_id = self._io.read_u8le()


    class Key(KaitaiStruct):
        __slots__ = ['_io', '_parent', '_root', 'key_value', 'type_entry', 'content']
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            #self.key_low = self._io.read_u4le()
            #self.key_high = self._io.read_u4le()
            key_raw = self._io.read_u8le()
            self.key_value = key_raw & 0x0FFFFFFFFFFFFFFF
            self.type_entry = key_raw >> 60
            _on = self.type_entry
            if _on == 0: #self._root.EntryType.location.value:
                self.content = self._root.LocationKey(self._io, self, self._root)
            elif _on == 2: #self._root.EntryType.extent.value:
                self.content = self._root.ExtentKey(self._io, self, self._root)
            elif _on == 8: #self._root.EntryType.file_extent.value:
                self.content = self._root.FileExtentKey(self._io, self, self._root)
            elif _on == 4: #self._root.EntryType.extattr.value:
                self.content = self._root.AttrNamedKey(self._io, self, self._root)
            elif _on == 5: #self._root.EntryType.hardlink:
                self.content = self._root.HardlinkKey(self._io, self, self._root)
            elif _on == 0xb: #self._root.EntryType.snap_name:
                self.content = self._root.SnapNameKey(self._io, self, self._root)
            elif _on == 9: #self._root.EntryType.dir_rec.value:
                self.content = self._root.DrecHashedKey(self._io, self, self._root)

        #@property
        #def key_value(self):
        #    if hasattr(self, '_m_key_value'):
        #        return self._m_key_value #if hasattr(self, '_m_key_value') else None

        #    self._m_key_value = (self.key_low + ((self.key_high & 268435455) << 32))
        #    return self._m_key_value if hasattr(self, '_m_key_value') else None

        #@property
        #def type_entry(self):
        #    if hasattr(self, '_m_type_entry'):
        #        return self._m_type_entry #if hasattr(self, '_m_type_entry') else None

        #    self._m_type_entry = self._root.EntryType((self.key_high >> 28))
        #    return self._m_type_entry if hasattr(self, '_m_type_entry') else None


    class HardlinkRecord(KaitaiStruct):
        __slots__ = ['_io', '_parent', '_root', 'parent_id', 'dirname']
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self.parent_id = self._io.read_u8le()
            namelength = self._io.read_u2le()
            self.dirname = (KaitaiStream.bytes_terminate(self._io.read_bytes(namelength), 0, False)).decode("UTF-8")


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
        __slots__ = ['_io', '_parent', '_root', 'ofs_key', 'ofs_data', 'len_key', 'len_data']
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self.ofs_key = self._io.read_s2le()
            if (self._parent._parent.type_flags & 4) == 0:
                self.len_key = self._io.read_u2le()

            self.ofs_data = self._io.read_s2le()
            if (self._parent._parent.type_flags & 4) == 0:
                self.len_data = self._io.read_u2le()



    class Block(KaitaiStruct):
        __slots__ = ['_io', '_parent', '_root', 'header', 'body']
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self.header = self._root.BlockHeader(self._io, self, self._root)
            _on = self.header.type_block.value
            if _on == 3: #self._root.BlockType.node:
                self.body = self._root.Node(self._io, self, self._root)
            elif _on == 7: #self._root.BlockType.allocationinfofile:
                self.body = self._root.Allocationinfofile(self._io, self, self._root)
            elif _on == 5: #self._root.BlockType.spaceman:
                self.body = self._root.Spaceman(self._io, self, self._root)
            elif _on == 11: #self._root.BlockType.btree:
                self.body = self._root.Btree(self._io, self, self._root)
            elif _on == 2: #self._root.BlockType.rootnode:
                self.body = self._root.Node(self._io, self, self._root)
            elif _on == 13: #self._root.BlockType.volumesuperblock:
                self.body = self._root.Volumesuperblock(self._io, self, self._root)
            elif _on == 12: #self._root.BlockType.checkpoint:
                self.body = self._root.Checkpoint(self._io, self, self._root)
            elif _on == 1: #self._root.BlockType.containersuperblock:
                self.body = self._root.Containersuperblock(self._io, self, self._root)


    class PointerRecord(KaitaiStruct):
        __slots__ = ['_io', '_parent', '_root', 'pointer']
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self.pointer = self._io.read_u8le()


    class ExtattrRecord(KaitaiStruct):
        __slots__ = ['_io', '_parent', '_root', 'flags', 'len_data', 'data']
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self.flags = self._io.read_u2le()
            self.len_data = self._io.read_u2le()
            #_on = self.flags
            #if _on == 6: #self._root.EaType.symlink:
            #    self.data = (KaitaiStream.bytes_terminate(self._io.read_bytes(self.len_data), 0, False)).decode(UTF-8")
            #else:
            self.data = self._io.read_bytes(self.len_data)


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


    class SiblingMapRecord(KaitaiStruct):
        __slots__ = ['_io', '_parent', '_root', 'file_id']
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self.file_id = self._io.read_u8le()


    class HardlinkKey(KaitaiStruct):
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


    class Btree(KaitaiStruct):
        __slots__ = ['_io', '_parent', '_root', 'unknown_0', 'root']
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self.unknown_0 = self._io.read_bytes(16)
            self.root = self._root.RefBlock(self._io, self, self._root)


    class Node(KaitaiStruct):
        __slots__ = ['_io', '_parent', '_root', 'type_flags', 'leaf_distance', 'num_entries', 'unknown_40', 'ofs_keys', 'len_keys', 'ofs_data', 'meta_entry', 'entries']
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self.type_flags = self._io.read_u2le()
            self.leaf_distance = self._io.read_u2le()
            self.num_entries = self._io.read_u4le()
            self.unknown_40 = self._io.read_u2le()
            self.ofs_keys = self._io.read_u2le()
            self.len_keys = self._io.read_u2le()
            self.ofs_data = self._io.read_u2le()
            self.meta_entry = self._root.FullEntryHeader(self._io, self, self._root)
            self.entries = [None] * (self.num_entries)
            for i in range(self.num_entries):
                self.entries[i] = self._root.NodeEntry(self._io, self, self._root)



    class InodeRecord(KaitaiStruct):
        __slots__ = ['_io', '_parent', '_root', 'parent_id', 'node_id', 'creation_timestamp', 'modified_timestamp', 'changed_timestamp', 'accessed_timestamp', 'flags', 'nchildren_or_nlink', 'unknown_60', 'unknown_64', 'bsdflags', 'owner_id', 'group_id', 'mode', 'pad1', 'pad2', 'num_records', 'record_total_len', 'records','dirname', 'size1', 'size2' ]
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
            self.unknown_60 = self._io.read_u4le()
            self.unknown_64 = self._io.read_u4le()
            self.bsdflags = self._io.read_u4le()
            self.owner_id = self._io.read_u4le()
            self.group_id = self._io.read_u4le()
            self.mode = self._io.read_u2le()
            self.pad1 = self._io.read_u2le()
            self.pad2 = self._io.read_u8le()
            self.num_records = self._io.read_u2le()
            self.record_total_len = self._io.read_u2le()
            self.records = [None] * (self.num_records)
            for i in range(self.num_records):
                self.records[i] = self._root.FileMetaRecord(self._io, self, self._root)
            # ADDED
            self.dirname = ''
            self.size1 = 0
            self.size2 = 0
            #self.size3 = 0
            #self.size4 = 0
            #self.size5 = 0
            
            pos = self._io.pos()
            skip = 0
            for i in range(self.num_records):
                self._io.seek(pos + skip)
                record = self.records[i];
                skip += record.size + ((8 - record.size) % 8) # 8 byte boundary
                if record.meta_type == 0x0204: # name
                    self.dirname = (self._io.read_bytes(record.size - 1)).decode("UTF-8")
                elif record.meta_type == 0x2008: # size
                    if record.size >= 8 : self.size1 = self._io.read_u8le()
                    if record.size >= 16: self.size2 = self._io.read_u8le()
                #    if record.size >= 24: self.size3 = self._io.read_u8le()
                #    if record.size >= 32: self.size4 = self._io.read_u8le()
                #    if record.size >= 40: self.size5 = self._io.read_u8le()
                    
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


    class ExtentKey(KaitaiStruct):
        __slots__ = ['_io', '_parent', '_root', 'block_num']
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self.block_num = self._root.RefBlock(self._io, self, self._root)


    class DrecHashedKey(KaitaiStruct):
        __slots__ = ['_io', '_parent', '_root', 'hash', 'dirname']
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            name_len_and_hash = self._io.read_u4le()
            len_name = name_len_and_hash & 0x000003ff
            self.hash = (name_len_and_hash & 0xfffff400) >> 10
            self.dirname = (KaitaiStream.bytes_terminate(self._io.read_bytes(len_name), 0, False)).decode("UTF-8")


    class AttrNamedKey(KaitaiStruct):
        __slots__ = ['_io', '_parent', '_root', 'attr_name']
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            len_name = self._io.read_u2le()
            self.attr_name = (KaitaiStream.bytes_terminate(self._io.read_bytes(len_name), 0, False)).decode("UTF-8")


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


    class FileMetaRecord(KaitaiStruct):
        __slots__ = ['_io', '_parent', '_root', 'meta_type', 'size']
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self.meta_type = self._io.read_u2le()
            self.size = self._io.read_u2le()


    class HistoryKey(KaitaiStruct):
        __slots__ = ['_io', '_parent', '_root', 'version', 'block_num']
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self.version = self._io.read_u8le()
            self.block_num = self._root.RefBlock(self._io, self, self._root)


    @property
    def block_size(self):
        if hasattr(self, '_m_block_size'):
            return self._m_block_size #if hasattr(self, '_m_block_size') else None

        self._m_block_size = self._root.block0.body.block_size
        return self._m_block_size #if hasattr(self, '_m_block_size') else None


