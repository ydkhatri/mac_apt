meta:
  id: apfs
  license: MIT
  encoding: UTF-8
  endian: le

seq:
  - id: block0
    type: block
    size: 4096

instances:
  block_size:
    value: _root.block0.body.as<containersuperblock>.block_size
#  random_block:
#    pos: 0 * block_size   # enter block number here to jump directly that block in the WebIDE
#    type: block           # opens a sub stream for making positioning inside the block work
#    size: block_size

types:

# block navigation

  ref_block:
    doc: |
      Universal type to address a block: it both parses one u8-sized
      block address and provides a lazy instance to parse that block
      right away.
    seq:
      - id: value
        type: u8
    instances:
      target:
        io: _root._io
        pos: value * _root.block_size
        type: block
        size: _root.block_size
    -webide-representation: 'Blk {value:dec}'

# meta structs

  block_header:
    seq:
      - id: checksum
        type: u8
        doc: Flechters checksum, according to the docs.
      - id: block_id
        type: u8
        doc: ID of the block itself. Either the position of the block or an incrementing number starting at 1024.
      - id: version
        type: u8
        doc: Incrementing number of the version of the block (highest == latest)
      - id: type_block
        type: u2
        enum: block_type
      - id: flags
        type: u2
        doc: 0x4000 block_id = position, 0x8000 = container
      - id: type_content
        type: u2
        enum: content_type
      - id: padding
        type: u2

  block:
    seq:
      - id: header
        type: block_header
      - id: body
        #size-eos: true
        type:
          switch-on: header.type_block
          cases:
            block_type::containersuperblock: containersuperblock
            block_type::rootnode: node
            block_type::node: node
            block_type::spaceman: spaceman
            block_type::allocationinfofile: allocationinfofile
            block_type::btree: btree
            block_type::checkpoint: checkpoint
            block_type::volumesuperblock: volumesuperblock
            

# containersuperblock (type: 0x01)

  containersuperblock:
    seq:
      - id: magic
        size: 4
        contents: [NXSB]
      - id: block_size
        type: u4
      - id: num_blocks
        type: u8
      - id: padding
        size: 16
      - id: unknown_64
        type: u8
      - id: guid
        size: 16
      - id: next_free_block_id
        type: u8
      - id: next_version
        type: u8
      - id: unknown_104
        size: 32
      - id: previous_containersuperblock_block
        type: u4
      - id: unknown_140
        size: 12
      - id: spaceman_id
        type: u8
      - id: block_map_block
        type: ref_block
      - id: unknown_168_id
        type: u8
      - id: padding2
        type: u4
      - id: num_volumesuperblock_ids
        type: u4
      - id: volumesuperblock_ids
        type: u8
        repeat: expr
        repeat-expr: num_volumesuperblock_ids

# node (type: 0x02)

  node:
    seq:
      - id: type_flags
        type: u2
      - id: leaf_distance
        type: u2
        doc: Zero for leaf nodes, > 0 for branch nodes
      - id: num_entries
        type: u4
      - id: unknown_40
        type: u2
      - id: ofs_keys
        type: u2
      - id: len_keys
        type: u2
      - id: ofs_data
        type: u2
      - id: meta_entry
        type: full_entry_header
      - id: entries
        type: node_entry
        repeat: expr
        repeat-expr: num_entries

  full_entry_header:
    seq:
      - id: ofs_key
        type: s2
      - id: len_key
        type: u2
      - id: ofs_data
        type: s2
      - id: len_data
        type: u2

  dynamic_entry_header:
    seq:
      - id: ofs_key
        type: s2
      - id: len_key
        type: u2
        if: (_parent._parent.type_flags & 4) == 0
      - id: ofs_data
        type: s2
      - id: len_data
        type: u2
        if: (_parent._parent.type_flags & 4) == 0

## node entries

  node_entry:
    seq:
      - id: header
        type: dynamic_entry_header
    instances:
      key:
        pos: header.ofs_key + _parent.ofs_keys + 56
        type: key
        -webide-parse-mode: eager
      data:
        pos: _root.block_size - header.ofs_data - 40 * (_parent.type_flags & 1)
        type:
          switch-on: '(((_parent.type_flags & 2) == 0) ? 256 : 0) + key.type_entry.to_i * (((_parent.type_flags & 2) == 0) ? 0 : 1)'
          cases:
            256: pointer_record # applies to all pointer records, i.e. any entry data in index nodes
            entry_type::location.to_i: location_record
            entry_type::inode.to_i: inode_record
            entry_type::name.to_i: named_record
            entry_type::thread.to_i: thread_record
            entry_type::hardlink.to_i: hardlink_record
            entry_type::entry6.to_i: t6_record
            entry_type::extent.to_i: extent_record
            entry_type::entry12.to_i: t12_record
            entry_type::extattr.to_i: extattr_record
        -webide-parse-mode: eager
    -webide-representation: '{key}: {data}'

## node entry keys

  key:
    seq:
      - id: key_low # this is a work-around for JavaScript's inability to hande 64 bit values
        type: u4
      - id: key_high
        type: u4
      - id: content
        #size: _parent.header.len_key-8
        type:
          switch-on: type_entry
          cases:
            entry_type::location: location_key
            entry_type::inode: inode_key
            entry_type::name: named_key
            entry_type::hardlink: hardlink_key
            entry_type::extattr: attr_named_key
            entry_type::extent: extent_key
    instances:
      key_value:
        value: key_low + ((key_high & 0x0FFFFFFF) << 32)
        -webide-parse-mode: eager
      type_entry:
        value: key_high >> 28
        enum: entry_type
        -webide-parse-mode: eager
    -webide-representation: '({type_entry}) {key_value:dec} {content}'

  location_key:
    seq:
      - id: block_id
        type: u8
      - id: version
        type: u8
    -webide-representation: 'ID {block_id:dec} v{version:dec}'

  history_key:
    seq:
      - id: version
        type: u8
      - id: block_num
        type: ref_block
    -webide-representation: '{block_num} v{version:dec}'

  inode_key:
    seq:
      - id: block_num
        type: ref_block
    -webide-representation: '{block_num}'

  named_key:
    seq:
      - id: len_name
        type: u1
      - id: hash_name
        type: u1
        repeat: expr
        repeat-expr: 3
      - id: dirname
        size: len_name
        type: strz
    -webide-representation: '"{dirname}"'

  attr_named_key:
    seq:
      - id: len_name
        type: u2
      - id: attr_name
        size: len_name
        type: strz
    -webide-representation: '"{attr_name}"'

  hardlink_key:
    seq:
      - id: id2
        type: u8
    -webide-representation: '#{id2:dec}'

  extent_key:
    seq:
      - id: offset # seek pos in file
        type: u8
    -webide-representation: '{offset:dec}'

## node entry records

  pointer_record: # for any index nodes
    seq:
      - id: pointer
        type: u8
    -webide-representation: '-> {pointer:dec}'

  history_record: # ???
    seq:
      - id: unknown_0
        type: u4
      - id: unknown_4
        type: u4
    -webide-representation: '{unknown_0}, {unknown_4}'

  location_record: # 0x00
    seq:
      - id: block_start
        type: u4
      - id: block_length
        type: u4
      - id: block_num
        type: ref_block
    -webide-representation: '{block_num}, from {block_start:dec}, len {block_length:dec}'


  file_meta_record:
    seq:
      - id: meta_type
        type: u2
      - id: size
        type: u2
    -webide-representation: '{meta_type}, {size}'

  thread_record: # 0x30
    seq:
      - id: parent_id
        type: u8
      - id: node_id
        type: u8
      - id: creation_timestamp
        type: s8
      - id: modified_timestamp
        type: s8
      - id: changed_timestamp
        type: s8
      - id: accessed_timestamp
        type: s8
      - id: flags
        type: u8
      - id: nchildren_or_nlink
        type: u4
      - id: unknown_60
        type: u4
      - id: unknown_64
        type: u4
      - id: bsdflags
        type: u4
      - id: owner_id
        type: u4
      - id: group_id
        type: u4
      - id: mode
        type: u2
      - id: unknown_82
        type: u2
      - id: unknown_84
        type: u4
      - id: unknown_88
        type: u4
      - id: num_records
        type: u2
      - id: record_total_len
        type: u2
      - id: records
        type: file_meta_record
        repeat: expr
        repeat-expr: num_records
      - id: unknown_remainder
        size-eos: true

    -webide-representation: '#{node_id:dec} / #{parent_id:dec} "{name}"'

  hardlink_record: # 0x50
    seq:
      - id: node_id
        type: u8
      - id: namelength
        type: u2
      - id: dirname
        size: namelength
        type: strz
    -webide-representation: '#{node_id:dec} "{dirname}"'

  t6_record: # 0x60
    seq:
      - id: unknown_0
        type: u4
    -webide-representation: '{unknown_0}'

  inode_record: # 0x20
    seq:
      - id: block_count
        type: u4
      - id: unknown_4
        type: u2
      - id: block_size
        type: u2
      - id: inode
        type: u8
      - id: unknown_16
        type: u4
    -webide-representation: '#{inode:dec}, Cnt {block_count:dec} * {block_size:dec}, {unknown_4:dec}, {unknown_16:dec}'
  
  extent_record: # 0x80
    seq:
      - id: size
        type: u8
      - id: block_num
        type: ref_block
      - id: unknown_16
        type: u8
    -webide-representation: '{block_num}, Len {size:dec}, {unknown_16:dec}'

  named_record: # 0x90
    seq:
      - id: node_id
        type: u8
      - id: timestamp
        type: s8
      - id: type_item
        type: u2
        enum: item_type
    -webide-representation: '#{node_id:dec}, {type_item}'

  t12_record: # 0xc0
    seq:
      - id: unknown_0
        type: u8
    -webide-representation: '{unknown_0:dec}'

  extattr_record: # 0x40
    seq:
      - id: type_ea
        type: u2
        enum: ea_type
      - id: len_data
        type: u2
      - id: data
        size: len_data
        type:
          switch-on: type_ea
          cases:
            ea_type::symlink: strz # symlink
            # all remaining cases are handled as a "bunch of bytes", thanks to the "size" argument
    -webide-representation: '{type_ea} {data}'


# spaceman (type: 0x05)

  spaceman:
    seq:
      - id: block_size
        type: u4
      - id: unknown_36
        size: 12
      - id: num_blocks
        type: u8
      - id: unknown_56
        size: 8
      - id: num_entries
        type: u4
      - id: unknown_68
        type: u4
      - id: num_free_blocks
        type: u8
      - id: ofs_entries
        type: u4
      - id: unknown_84
        size: 92
      - id: prev_allocationinfofile_block
        type: u8
      - id: unknown_184
        size: 200
    instances:
      allocationinfofile_blocks:
        pos: ofs_entries
        repeat: expr
        repeat-expr: num_entries
        type: u8

# allocation info file (type: 0x07)

  allocationinfofile:
    seq:
      - id: unknown_32
        size: 4
      - id: num_entries
        type: u4
      - id: entries
        type: allocationinfofile_entry
        repeat: expr
        repeat-expr: num_entries

  allocationinfofile_entry:
    seq:
      - id: version
        type: u8
      - id: unknown_8
        type: u4
      - id: unknown_12
        type: u4
      - id: num_blocks
        type: u4
      - id: num_free_blocks
        type: u4
      - id: allocationfile_block
        type: u8

# btree (type: 0x0b)

  btree:
    seq:
      - id: unknown_0
        size: 16
      - id: root
        type: ref_block

# checkpoint (type: 0x0c)

  checkpoint:
    seq:
      - id: unknown_0
        type: u4
      - id: num_entries
        type: u4
      - id: entries
        type: checkpoint_entry
        repeat: expr
        repeat-expr: num_entries

  checkpoint_entry:
    seq:
      - id: type_block
        type: u2
        enum: block_type
      - id: flags
        type: u2
      - id: type_content
        type: u4
        enum: content_type
      - id: block_size
        type: u4
      - id: unknown_52
        type: u4
      - id: unknown_56
        type: u4
      - id: unknown_60
        type: u4
      - id: block_id
        type: u8
      - id: block
        type: ref_block

# volumesuperblock (type: 0x0d)

  volumesuperblock:
    seq:
      - id: magic
        size: 4
        contents: [APSB]
      - id: unknown_36
        size: 20
      - id: feature_flags # bit0=case-insensitive, bit3=case-sensitive, bit2=encrypted
        size: u8
      - id: unknown_64
        size: 24
      - id: num_blocks_used
        size: u8
      - id: unknown_96
        size: 32
      - id: block_map_block
        type: ref_block
        doc: 'Maps node IDs to the inode Btree nodes'
      - id: root_dir_id
        type: u8
      - id: inode_map_block
        type: ref_block
        doc: 'Maps file extents to inodes'
      - id: unknown_152_blk
        type: ref_block
      - id: unknown_160
        size: 16
      - id: next_available_cnid # 0xB0
        type: u8
      - id: num_files # 0xB8
        type: u8
      - id: num_folders # 0xC0
        type: u8
      - id: unknown_200  # 0xC8
        type: u8
      - id: unknown_208  # 0xD0
        type: u8
      - id: existing_snapshots
        type: u8
      - id: unknown_224
        size: 8
      - id: unknown_232
        size: 8
      - id: volume_uuid # 0xF0
        size: 16
      - id: time_updated
        type: s8
      - id: encryption_flags
        type: u8
      - id: created_by
        size: 32
        type: strz
      - id: time_created
        type: s8
      - id: unknown_312
        size: 392
      - id: volume_name
        type: strz

# enums

enums:

  block_type:
    1: containersuperblock
    2: rootnode
    3: node
    5: spaceman
    7: allocationinfofile
    11: btree
    12: checkpoint
    13: volumesuperblock
    17: unknown

  entry_type:
    0x0: location
    0x2: inode
    0x3: thread
    0x4: extattr
    0x5: hardlink
    0x6: entry6
    0x8: extent
    0x9: name
    0xc: entry12
# Seems entry6 (T6) is only for files, not folders
  content_type:
    0: empty
    9: history
    11: location
    14: files
    15: extents
    16: unknown3

  item_type:
    0: empty
    1: unknown_1
    4: folder
    8: file
    10: symlink
    12: unknown_12

  ea_type:
    1: unknown_1
    2: generic
    6: symlink
