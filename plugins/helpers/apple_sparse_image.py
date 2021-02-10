'''
   Copyright (c) 2017 Yogesh Khatri 

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the 
   terms of the MIT License.
   
'''

from construct import *

class AppleSparseImage:

    HeaderNode = Struct(
        Const(b'sprs'),
        "version" / Int32ub,
        "sectors_per_band" / Int32ub,
        "flags" / Int32ub,
        "total_sectors_low" / Int32ub,
        "next_node_offset" / Int64ub,
        "total_sectors" / Int64ub,
        "padding" / Int32ub[7],
        "band_id" / Int32ub[0x3F0]
    )

    IndexNode = Struct(
        "magic" / Int32ub,
        "index_node_number" / Int32ub,
        "flags" / Int32ub,
        "next_node_offset" / Int64ub,
        "padding" / Int32ub[9],
        "band_id" / Int32ub[0x3F2]
    )

    def __init__(self):
        self.img = None
        self.band_size = 0
        self.size = 0
        self.band_offset = []

    def __del__(self):
        if self.img:
            self.img.close()

    def _read(self, size, offset=None):
        if offset is not None:
            self.img.seek(offset)
        pos = self.img.tell()
        data = self.img.read(size)
        if len(data) < size:
            raise ValueError(f'File is truncated, could not read {size} bytes from offset {pos}')
        return data

    def open(self, filepath):
        '''
            Opens a .sparseimage file
            Exceptions:
                ValueError if corruption encountered or other errors
        '''
        self.img = open(filepath, 'rb')
        img = self.img
        if img.read(4) != b'sprs':
            raise ValueError('Not an Apple SparseImage file!')
        img.seek(0)

        data = self._read(0x1000)
        hdr = self.HeaderNode.parse(data)
        self.size = hdr.total_sectors * 512
        self.band_size = hdr.sectors_per_band * 512
        self.band_offset = [0] * ((self.size + self.band_size - 1) // self.band_size)

        base = 0x1000

        for k in range(0x3F0):
            off = hdr.band_id[k]
            if off:
                self.band_offset[off - 1] = base + (self.band_size * k)

        next_node_offset = hdr.next_node_offset
        base = next_node_offset + 0x1000

        while next_node_offset:
            data = self._read(0x1000, next_node_offset)
            idx = self.IndexNode.parse(data)

            if idx.magic != 0x73707273: # 'sprs'
                raise ValueError('Corrupted file, node header signature not found!')

            for k in range(0x3F2):
                off = idx.band_id[k]
                if off:
                    self.band_offset[off - 1] = base + (self.band_size * k)

            next_node_offset = idx.next_node_offset
            base = next_node_offset + 0x1000

    def close(self):
        if self.img:
            self.img.close()
            self.img = None

    def read(self, offset, size):
        chunk = 0
        chunk_offs = 0
        chunk_base = 0
        read_size = 0
        data = b''

        while size > 0:
            chunk = offset >> 20
            chunk_offs = offset & (self.band_size - 1)

            read_size = size

            if (chunk_offs + read_size) > self.band_size:
                read_size = self.band_size - chunk_offs

            chunk_base = self.band_offset[chunk]

            if chunk_base:
                data += self._read(read_size, chunk_base + chunk_offs)
            else:
                data += b'\0' * read_size

            size -= read_size
            offset += read_size
        return data
