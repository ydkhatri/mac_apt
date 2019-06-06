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
  
  prange:
    seq:
      - id: start_paddr
        type: s8
      - id: block_count
        type: u8

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
      - id: block_id  # APFS oid
        type: u8
        doc: ID of the block itself. Either the position of the block or an incrementing number starting at 1024.
      - id: version   # APFS xid
        type: u8
        doc: Incrementing number of the version of the block (highest == latest)
      - id: type_block  # APFS object type o_type (one 32 bit num)
        type: u2
        enum: block_type
      - id: flags
        type: u2
        doc: 0x4000 block_id = position, 0x8000 = container
      - id: type_content # APFS o_subtype
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
      - id: features
        type: u8
      - id: readonly_compatible_features
        type: u8
      - id: incompatible_features
        type: u8
      - id: uuid
        size: 16
      - id: next_oid
        type: u8
      - id: next_xid
        type: u8
      - id: xp_desc_blocks
        type: u4
      - id: xp_data_blocks
        type: u4
      - id: xp_desc_base
        type: s8
      - id: xp_data_base
        type: s8
      - id: xp_desc_next
        type: u4
      - id: xp_data_next
        type: u4
      - id: xp_desc_index
        type: u4
      - id: xp_desc_len
        type: u4
      - id: xp_data_index
        type: u4
      - id: xp_data_len
        type: u4
      - id: spaceman_oid
        type: u8
      - id: omap_oid
        type: u8 # ref_block
      - id: reaper_oid
        type: u8
      - id: test_type
        type: u4
      - id: num_volumesuperblock_ids # max_file_systems
        type: u4
      - id: volumesuperblock_ids # fs_oid
        type: u8
        repeat: expr
        repeat-expr: num_volumesuperblock_ids
      - id: counters
        type: u8
        repeat: expr
        repeat-expr: 32
      - id: blocked_out_start_paddr
        type: s8
      - id: blocked_out_block_count
        type: u8
      - id: evict_mapping_tree_oid
        type: u8
      - id: flags
        type: u8
      - id: efi_jumpstart
      

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
            entry_type::extent.to_i: extent_record
            entry_type::dir_rec.to_i: drec_hashed_record
            entry_type::inode.to_i: inode_record
            entry_type::hardlink.to_i: hardlink_record
            entry_type::dstream_id.to_i: dstream_id_record
            entry_type::file_extent.to_i: file_extent_record
            entry_type::sibling_map.to_i: sibling_map_record
            entry_type::extattr.to_i: extattr_record
            entry_type::snap_name.to_i: snap_name_record
            entry_type::snap_metadata.to_i: snap_metadata_record
            entry_type::dir_stats.to_i: dir_stats_record
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
            entry_type::extent: extent_key
            entry_type::dir_rec: drec_hashed_key
            entry_type::hardlink: hardlink_key
            entry_type::extattr: attr_named_key
            entry_type::file_extent: file_extent_key
            entry_type::snap_name:snap_name_key
            # entry_type::dstream_id: dstream_id_key
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

  extent_key: #TODO check this, spec says nothing here
    seq:
      - id: block_num
        type: ref_block
    -webide-representation: '{block_num}'

  drec_hashed_key:
    seq:
      - id: name_len_and_hash
        type: u4
      - id: dirname
        size: len_name
        type: strz
      instances:
        len_name:
          value: name_len_and_hash & 0x000003ff
        hash:
          value: (name_len_and_hash & 0xfffff400) >> 10
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
      - id: sibling_id
        type: u8
    -webide-representation: '#{sibling_id:dec}'

  file_extent_key:
    seq:
      - id: offset # seek pos in file
        type: u8
    -webide-representation: '{offset:dec}'

#  dstream_id_key:
#    seq:
#      - id: no_value
#        size: 0
  snap_name_key:
    seq:
      - id: name_len
        type: u2
      - id: name
        size: name_len
        type: strz

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

  inode_record: # 0x30
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
      - id: pad1
        type: u2
      - id: unknown_88
        type: u8
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
      - id: parent_id
        type: u8
      - id: namelength
        type: u2
      - id: dirname
        size: namelength
        type: strz
    -webide-representation: '#{parent_id:dec} "{dirname}"'

  sibling_map_record:
    seq:
      - id: file_id
        type: u8
    -webide-representation: '{file_id:dec}'

  snap_metadata_record:
    seq:
      - id: extentref_tree_oid
        type: u8
      - id: sblock_oid
        type: u8
      - id: create_time
        type: u8
      - id: change_time
        type: u8
      - id: inum
        type: u8
      - id: extentref_tree_type
        type: u4
      - id: flags
        type: u4
      - id: name_len
        type: u2
      - id: name
        size: name_len
        type: strz

  snap_name_record:
    seq:
      - id: snap_xid
        type: u8

  dir_stats_record:
    seq:
      - id: num_children
        type: u8
      - id: total_size
        type: u8
      - id: chained_key
        type: u8
      - id: gen_count
        type: u8

  dstream_id_record: # 0x60
    seq:
      - id: refcnt
        type: u4
    -webide-representation: '{refcnt:dec}'

  extent_record: # 0x20
    seq:
      - id: len_and_kind
        type: u8
      - id: owning_obj_id
        type: u8
      - id: refcnt
        type: s4
    instances:
      length:
        value: len_and_kind & 0x0fffffffffffffff
      kind:  # one of obj_kinds
        value: (len_and_kind & 0xf000000000000000) >> 60
    -webide-representation: '{owning_obj_id:dec},  {length:dec}, {kind:dec}, {refcnt:dec}'
  
  file_extent_record: # 0x80
    seq:
      - id: len_and_flags
        type: u8
      - id: phys_block_num
        type: ref_block
      - id: crypto_id
        type: u8
    instances:
      length:
        value: len_and_flags & 0x00ffffffffffffff
      flags:  # currently no flags defined as per spec
        value: (len_and_flags & 0xff00000000000000) >> 56
    -webide-representation: '{phys_block_num}, Len {size:dec}, {crypto_id:dec}'

  drec_hashed_record: # 0x90
    seq:
      - id: node_id
        type: u8
      - id: date_added
        type: s8
      - id: type_item
        type: u2
      # TODO: Add xfields
    instances:
      flags:
        value: type_item & 0xF
        enum: item_type
    -webide-representation: '#{node_id:dec}, {type_item}'

  sibling_map_record: # 0xc0
    seq:
      - id: file_id
        type: u8
    -webide-representation: '{file_id:dec}'

  extattr_record: # 0x40, j_xattr_val_t
    seq:
      - id: flags #type_ea
        type: u2
        #enum: ea_type
      - id: len_data
        type: u2
      - id: data
        size: len_data
        #type:
        #  switch-on: flags #type_ea
        #  cases:
        #    ea_type::symlink: strz # symlink
        #    # all remaining cases are handled as a "bunch of bytes", thanks to the "size" argument
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

  block_type: # APFS Object types
    0x01: containersuperblock # NX_SUPERBLOCK
    0x02: rootnode            # BTREE
    0x03: node                # BTREE_NODE
    0x04: reserved              # Not seen
    0x05: spaceman            # SPACEMAN
    0x06: spaceman_cab        # SPACEMAN_CAB # Not impl here
    0x07: allocationinfofile  # SPACEMAN_CIB
    0x08: spaceman_bitmap       # Not impl here
    0x09: spaceman_free_queue   # Not impl here
    0x0a: extent_list_tree      # Not impl here
    0x0b: btree               # OMAP
    0x0c: checkpoint           # CHECKPOINT_MAP
    0x0d: volumesuperblock    # FS
    0x0e: fstree              # FSTREE
    0x0f: blockreftree        # BLOCKREFTREE
    0x10: snapmetatree        # SNAPMETATREE
    0x11: NX_REAPER
    0x12: NX_REAP_LIST
    0x13: OMAP_SNAPSHOT
    0x14: EFI_JUMPSTART
    0x15: FUSION_MIDDLE_TREE
    0x16: NX_FUSION_WBC
    0x17: NX_FUSION_WBC_LIST
    0x18: ER_STAT
    0x19: GBITMAP
    0x1a: GBITMAP_TREE
    0x1b: GBITMAP_BLOCK

  entry_type:      # APFS j_obj_types
    0x0: location  # APFS_TYPE_ANY 
    0x1: snap_metadata
    0x2: extent
    0x3: inode
    0x4: extattr
    0x5: hardlink  # APFS SIBLING_LINK
    0x6: dstream_id
    0x7: crypto_state
    0x8: file_extent
    0x9: dir_rec      # APFS DIR_REC
    0xa: dir_stats
    0xb: snap_name
    0xc: sibling_map
    0xd: unknown_reserved
    0xe: unknown_reserved2
    0xf: invalid
# Seems dstream_id is only for files, not folders

  content_type:
    0: empty
    9: history
    11: location
    14: files
    15: extents
    16: unknown3

  item_type: # Directory Entry File types
    0: unknown
    1: fifo_named_pipe
    2: character_special_file
    4: directory
    6: block_special_file
    8: regular_file
    10: symlink
    12: socket
    14: whiteout

#  obj_kinds: # j_obj_kinds # Might be more than these documented ones!
#    0: any
#    1: new
#    2: update
#    3: dead
#    4: update_refcnt
