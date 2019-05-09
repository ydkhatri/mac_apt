# Parse the Spotlight store.db file from mac OSX
#
#  (c) Yogesh Khatri - 2018 www.swiftforensics.com
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You can get a copy of the complete license here:
#  <http://www.gnu.org/licenses/>.
#
# Script Name  : spotlight_parser.py
# Author       : Yogesh Khatri
# Last Updated : 10/16/2018
# Requirement  : Python 2.7 and modules ( lz4, enum34 )
#                Dependencies can be installed using the command 'pip install lz4 enum34' 
# 
# Purpose      : Parse the Spotlight store.db or .store.db file from mac OSX
#                These files are located under:
#                 /.Spotlight-V100/Store-V2/<UUID>/
#
#                Since 10.13, there are also spotlight databases for each user under
#                 ~/Library/Metadata/CoreSpotlight/index.spotlightV3/
#
# Usage        : spotlight_parser.py [-p OUTPUT_PREFIX] <path_to_database>  <output_folder>
#                Example:  python.exe spotlight_parser.py c:\store  c:\store_output
#
# Send bugs and feedback to yogesh@swiftforensics.com
#


import struct
import zlib
import lz4.block
import time
import struct
import binascii
import datetime
import os
import sys
import logging
from enum import IntEnum

__VERSION__ = '0.7'

log = logging.getLogger('SPOTLIGHT_PARSER')


class FileMetaDataListing:
    def __init__(self, file_pos, data, size):
        self.file_pos = file_pos
        self.pos = 0
        self.data = data
        self.size = size
        self.meta_data_dict = {}  # { kMDItemxxx: value1, kMCItemyyy: value2, ..}
        #
        self.id = 0  # inode number
        self.flags = 0
        self.item_id = 0
        self.parent_id = 0  # inode for parent folder
        self.date_updated = None
        self.full_path = ''

    def ReadFloat(self):
        num = struct.unpack("<f", self.data[self.pos: self.pos + 4])[0]
        self.pos += 4
        return num

    def ReadDouble(self):
        num = struct.unpack("<d", self.data[self.pos: self.pos + 8])[0]
        self.pos += 8
        return num

    def ReadDate(self):
        '''Returns date as string'''
        # Date stored as 8 byte double, it is mac absolute time (2001 epoch)
        mac_abs_time = self.ReadDouble()
        if mac_abs_time > 0:  # Sometimes, a very large number that needs to be reinterpreted as signed int
            old = mac_abs_time
            mac_abs_time = struct.unpack("<q", struct.pack("<Q", int(mac_abs_time)))[0]  # double to signed int64
            if int(old) == mac_abs_time:  # int(536198400.512156) == 536198400 = True
                mac_abs_time = old  # preserve extra precision after decimal point
        try:
            return datetime.datetime(2001, 1, 1) + datetime.timedelta(seconds=mac_abs_time)
        except:
            pass
        return ""

    def ConvertEpochToUtcDateStr(self, value):
        '''Convert Epoch microseconds timestamp to string'''
        try:
            return datetime.datetime(1970, 1, 1) + datetime.timedelta(seconds=value / 1000000.)
        except:
            pass
        return ""

    def ReadVarSizeNum(self):
        '''Returns num and bytes_read'''
        num, bytes_read = SpotlightStore.ReadVarSizeNum(self.data[self.pos: min(self.size, 9 + self.size)])
        self.pos += bytes_read
        return num, bytes_read

    def ReadStr(self):
        '''Returns single string of data and bytes_read'''
        string = ""
        size, pos = self.ReadVarSizeNum()
        for x in range(pos, size + pos):
            string += str(self.data[self.pos])
            self.pos += 1
        return string, size + pos

    def ReadStrings(self):
        '''Returns array of strings found in data and bytes_read'''
        strings = []
        string = ""
        size, pos = self.ReadVarSizeNum()
        for x in range(pos, size + pos):
            if self.data[self.pos] != b"\x00":
                string += str(self.data[self.pos])
            else:
                strings.append(string)
                string = ""
            self.pos += 1
        if string:  # sometimes no null terminator!
            strings.append(string)
        return strings, size + pos

    def ReadSingleByte(self):
        single = struct.unpack("<B", self.data[self.pos: self.pos + 1])[0]
        self.pos += 1
        return single

    def ReadManyBytes(self, count, debug_dont_advance=False):
        '''Returns tuple, does not increment file pointer'''
        many = struct.unpack("<" + str(count) + "B", self.data[self.pos: self.pos + count])
        if debug_dont_advance:
            return many
        self.pos += count
        return many

    def ReadManyBytesReturnHexString(self, count, debug_dont_advance=False):
        '''does not increment file pointer'''
        many = self.ReadManyBytes(count, debug_dont_advance)
        ret = ''.join('{:02X}'.format(x) for x in many)
        return ret

    def GetFileName(self):
        if self.meta_data_dict.get('_kStoreMetadataVersion', None) != None:  # plist, not metadata
            return '------PLIST------'
        name = self.meta_data_dict.get('_kMDItemFileName', None)
        if name == None:
            name = self.meta_data_dict.get('kMDItemDisplayName')
        if name:
            name = name[0]
            if name.endswith('\x16\x02'):
                name = name[:-2]
        else:
            name = '------NONAME------'
        return name

    def Print(self, file):
        try:
            dashed_line = "-" * 60
            info = "Inode_Num --> {}\r\nFlags --> {}\r\nStore_ID --> {}\r\nParent_Inode_Num --> {}\r\nLast_Updated --> {}\r\n".format(
                self.id, self.flags, self.item_id, self.parent_id, self.ConvertEpochToUtcDateStr(self.date_updated))

            file.write(bytes(dashed_line + '\r\n' + info, "utf-8"))
            for k, v in sorted(self.meta_data_dict.items()):
                orig_debug = v
                if type(v) == list:
                    if v:
                        if len(v) == 1:
                            v = v[0]
                            if type(v) in (str, str):
                                if v.endswith('\x16\x02'):
                                    v = v[:-2]
                            if type(v) == str: v = v.decode('utf-8')
                        else:
                            if type(v[0]) == str:
                                v = ', '.join([x.decode('utf-8') for x in v])  # removes the 'u' for unicode in output
                            else:
                                v = ', '.join([str(x) for x in v])
                    else:
                        v = ''
                file.write((str(k) + " --> " + str(v)).encode('utf-8'))
                file.write('\r\n')
        except Exception as ex:
            log.exception("Exception trying to print data : ")

    def ConvertUint64ToSigned(self, unsigned_num):
        '''Return signed version of number, Eg: 0xFFFFFFFFFFFFFFFF will return -1'''
        return struct.unpack("<q", struct.pack("<Q", unsigned_num))[0]

    def ConvertUint32ToSigned(self, unsigned_num):
        '''Return signed version of number, Eg: 0xFFFFFFFF will return -1'''
        return struct.unpack("<i", struct.pack("<I", unsigned_num))[0]

    def ParseItem(self, properties, categories, indexes_1, indexes_2):
        # global  debug_prop_types
        self.id = self.ConvertUint64ToSigned(self.ReadVarSizeNum()[0])
        self.flags = self.ReadSingleByte()
        self.item_id = self.ConvertUint64ToSigned(self.ReadVarSizeNum()[0])
        self.parent_id = self.ConvertUint64ToSigned(self.ReadVarSizeNum()[0])
        self.date_updated = self.ReadVarSizeNum()[0]

        ## type = bytes used
        #  00 = byte or varNum ?  bool?
        #  02 = byte or varNum ?
        #  06 = byte or varNum ?
        #  07 = varNum
        #  08 = ?
        #  09 = float (4 bytes)
        #  0a = double (8 bytes)
        #  0b = var (len+data)
        #  0c = double (8 bytes) --> mac_abs_time
        #  0e = var (len+data)
        #  0f = varNum?
        prop_index = 0
        last_prop = None  # for debug only
        last_filepos = 0  # for debug only
        filepos = None
        prop = None
        while self.pos < self.size:
            last_filepos = filepos
            filepos = hex(self.file_pos + 0 + self.pos)
            prop_skip_index = self.ReadVarSizeNum()[0]
            if prop_skip_index == 0:
                log.warning("Something went wrong, skip index was 0 @ {}".format(filepos))
            prop_index += prop_skip_index
            last_prop = prop  # for debug only
            prop = properties.get(prop_index, None)
            if prop == None:
                log.error(
                    "Error, cannot proceed, invalid property index {}, skip={}".format(prop_index, prop_skip_index))
                return
            else:
                prop_name = prop[0]
                prop_type = prop[1]
                value_type = prop[2]
                value = ''
                if value_type == 0:
                    value = self.ReadVarSizeNum()[0]
                elif value_type == 2:
                    value = self.ReadVarSizeNum()[0]
                elif value_type == 6:
                    value = self.ReadVarSizeNum()[0]
                elif value_type == 7:
                    if prop_type == 0x42:  # 66 com_apple_mail_gmailLabels, com_microsoft_outlook_categories
                        # unknown encoding (varint) type!
                        value = self.ReadSingleByte()
                        if value == 0x08:  # Read 1 more byte
                            value += (self.ReadSingleByte() << 8)
                        elif value == 0x10:  # Read 2 more bytes
                            value += (self.ReadSingleByte() << 8) + (self.ReadSingleByte() << 16)
                        elif value == 0x18:  # Read 3 more bytes
                            value += (self.ReadSingleByte() << 8) + (self.ReadSingleByte() << 16) + (
                                        self.ReadSingleByte() << 24)
                        else:
                            log.info(
                                'Unknown value {} found for value_type 7, prop_type 0x42, prop_name {}'.format(value,
                                                                                                               prop_name))
                    else:
                        value = self.ReadVarSizeNum()[0]
                elif value_type == 9:
                    if prop_type & 2 == 2:
                        num_values = (self.ReadVarSizeNum()[0]) / 4
                        floats = [self.ReadFloat() for x in range(num_values)]
                        value = floats
                    else:
                        value = self.ReadFloat()
                elif value_type == 0x0A:
                    if prop_type & 2 == 2:
                        num_values = (self.ReadVarSizeNum()[0]) / 8
                        doubles = [self.ReadDouble() for x in range(num_values)]
                        value = doubles
                    else:
                        value = self.ReadDouble()
                elif value_type == 0x0B:
                    value = self.ReadStrings()[0]
                elif value_type == 0x0C:
                    if prop_type & 2 == 2:
                        num_dates = (self.ReadVarSizeNum()[0]) / 8
                        dates = []
                        for x in range(num_dates):
                            dates.append(self.ReadDate())
                        value = dates
                    else:
                        value = self.ReadDate()
                elif value_type == 0x0E:
                    if prop_type & 2 == 2:
                        value = self.ReadStrings()[0]
                    else:
                        value = self.ReadStr()[0]
                    if prop_name != 'kMDStoreProperties':
                        if type(value) == list:
                            if len(value) == 1:
                                value = binascii.hexlify(value[0]).upper()
                            else:
                                value = [binascii.hexlify(item).upper() for item in value]
                        else:  # single string
                            value = binascii.hexlify(value).upper()
                elif value_type == 0x0F:
                    value = self.ConvertUint32ToSigned(self.ReadVarSizeNum()[0])
                    if value < 0:
                        value = 'INVALID ({})'.format(value)
                    else:
                        old_value = value
                        if prop_type & 3 == 3:  # in (0x83, 0xC3, 0x03): # ItemKind
                            value = indexes_2.get(value, None)
                            if value == None:
                                value = 'error getting index_2 for value {}'.format(old_value)
                            else:
                                for v in value:
                                    cat = categories.get(v, 'error getting category for index={}'.format(v))
                                    if cat.endswith('\x16\x02'):
                                        cat = cat[:-2]
                                    value = cat
                                    break  # only get first, rest are language variants!
                        elif prop_type & 0x2 == 0x2:  # == 0x4A: # ContentTypeTree ItemUserTags
                            value = indexes_1.get(value, None)
                            if value == None:
                                value = 'error getting index_1 for value {}'.format(old_value)
                            else:
                                tree = []
                                for v in value:
                                    cat = categories.get(v, 'error getting category for index={}'.format(v))
                                    tree.append(cat)
                                value = tree
                        elif prop_type & 8 == 8:  # == 0x48: # ContentType
                            value = categories.get(value, 'error getting category for index={}'.format(old_value))
                        else:
                            log.info("Not seen before value-type 0x0F item, prop_type={:X}, prop={}".format(prop_type,
                                                                                                            prop_name))
                else:
                    if prop_name != 'kMDStoreAccumulatedSizes':
                        log.info("Pos={}, Unknown value_type {}, PROPERTY={}, PROP_TYPE={} ..RETURNING!".format(filepos,
                                                                                                                value_type,
                                                                                                                prop_name,
                                                                                                                prop_type))
                    return
                self.meta_data_dict[prop_name] = value


class BlockType(IntEnum):
    UNKNOWN_0 = 0
    METADATA = 0x09
    PROPERTY = 0x11
    CATEGORY = 0x21
    UNKNOWN_41 = 0x41
    INDEX = 0x81

    def __str__(self):
        return self.name


class StoreBlock0:
    def __init__(self, data):
        self.data = data
        self.signature = struct.unpack("<I", data[0:4])[0]
        if self.signature not in [0x64626D31, 0x64626D32]:  # 1mbd or 2mbd (block 0)
            raise Exception("Unknown signature {:X} in block0! Can't parse".format(self.signature))
        self.physical_size = struct.unpack("<I", data[4:8])[0]
        self.item_count = struct.unpack("<I", data[8:12])[0]
        self.unk_zero = struct.unpack("<I", data[12:16])[0]
        self.unk_type = struct.unpack("<I", data[16:20])[0]
        # Followed by indexes [last_id_in_block, offset_index, dest_block_size]
        # If sig==1mbd, then last_id_in_block is BigEndian else LE
        # Everything else LE
        self.indexes = []
        pos = 20
        for i in range(0, self.item_count):
            index = struct.unpack("<QII", data[
                                          pos: pos + 16])  # last_id_in_block is not used, so we don't care if it is read BE/LE
            self.indexes.append(index)
            pos += 16


class StoreBlock:
    def __init__(self, data):
        self.data = data
        self.pos = 0
        self.signature = struct.unpack("<I", data[0:4])[0]
        if self.signature != 0x64627032:  # 2pbd (most blocks)
            raise Exception("Unknown signature {:X} in block! Can't parse".format(self.signature))
        self.physical_size = struct.unpack("<I", data[4:8])[0]
        self.logical_size = struct.unpack("<I", data[8:12])[0]
        self.block_type = struct.unpack("<I", data[12:16])[0]
        #
        self.unknown = struct.unpack("<I", data[16:20])[0]  # usually zero or size of uncompressed data
        self.next_block_index = struct.unpack("<I", data[20:24])[0]
        self.unknown1 = struct.unpack("<I", data[24:28])[0]
        self.unknown2 = struct.unpack("<I", data[28:32])[0]


class SpotlightStore:
    def __init__(self, file_pointer):
        self.file = file_pointer
        # self.pos = 0
        if not self.IsValidStore():
            raise Exception('Not a version 2 Spotlight store.db file, invalid format!')
        self.file.seek(0)
        self.header = self.file.read(0x1000)
        self.flags = struct.unpack("<I", self.header[4:8])[0]
        self.header_unknowns = struct.unpack("6I", self.header[12:36])
        self.header_size = self.ReadUint(self.header[36:40])
        self.block0_size = self.ReadUint(self.header[40:44])
        self.block_size = self.ReadUint(self.header[44:48])
        self.index_blocktype_11 = self.ReadUint(self.header[48:52])
        self.index_blocktype_21 = self.ReadUint(self.header[52:56])
        self.index_blocktype_41 = self.ReadUint(self.header[56:60])
        self.index_blocktype_81_1 = self.ReadUint(self.header[60:64])
        self.index_blocktype_81_2 = self.ReadUint(self.header[64:68])
        self.original_path = self.header[0x144:0x244].decode('utf-8').rstrip('\0')  # 256 bytes
        self.file_size = self.GetFileSize(self.file)

        self.properties = {}
        self.categories = {}
        self.indexes_1 = {}
        self.indexes_2 = {}
        self.block0 = None

    def GetFileSize(self, file):
        '''Return size from an open file handle'''
        current_pos = file.tell()
        file.seek(0, 2)  # Seek to end
        size = file.tell()
        file.seek(current_pos)  # back to original position
        return size

    def IsValidStore(self):
        self.file.seek(0)
        signature = self.file.read(4)
        if signature == b'\x38\x74\x73\x64':  # 8tsd
            return True
        return False

    def Seek(self, pos):
        self.pos = pos
        self.file.seek(pos)

    def ReadFromFile(self, size):
        data = self.file.read(size)
        self.pos += len(data)
        return data

    def ReadUint(self, data):
        return struct.unpack("<I", data)[0]

    def ReadUint64(self, data):
        return struct.unpack("<Q", data)[0]

    @staticmethod
    def ReadVarSizeNum(data):
        '''Returns num and bytes_read'''
        num = struct.unpack("<B", data[0:1])[0]
        extra = 0
        use_lower_nibble = True
        if num == 0:
            return num, 1
        elif (num & 0xF0) == 0xF0:  # 4 or more
            use_lower_nibble = False
            if (num & 0x0F) == 0x0F:
                extra = 8
            elif (num & 0x0E) == 0x0E:
                extra = 7
            elif (num & 0x0C) == 0x0C:
                extra = 6
            elif (num & 0x08) == 0x08:
                extra = 5
            else:
                extra = 4
                use_lower_nibble = True
                num -= 0xF0
        elif (num & 0xE0) == 0xE0:
            extra = 3
            num -= 0xE0
        elif (num & 0xC0) == 0xC0:
            extra = 2
            num -= 0xC0
        elif (num & 0x80) == 0x80:
            extra = 1
            num -= 0x80

        if extra:
            num2 = 0
            for x in range(1, extra + 1):
                num_x = struct.unpack(">B", data[x: x + 1])[0]
                num2 += (num_x << (extra - x) * 8)
            if use_lower_nibble:
                num2 = num2 + ((num) << (extra * 8))
            return num2, extra + 1
        return num, extra + 1

    def ParseProperties(self, block):
        data = block.data
        pos = 32
        size = block.logical_size
        while pos < size:
            index, value_type, prop_type = struct.unpack("<IBB", data[pos: pos + 6])
            pos += 6
            name = ""
            while pos < size:
                ch = data[pos]
                pos += 1
                if ch == b'\x00':
                    break
                name += str(ch)
            self.properties[index] = [name, prop_type, value_type]
            x = 1

    def ParseCategories(self, block):
        data = block.data
        pos = 32
        size = block.logical_size
        while pos < size:
            x = data[pos: pos + 4][0]
            index = struct.unpack("<I", data[pos: pos + 4])[0]
            pos += 4
            name = ""
            while pos < size:
                ch = data[pos]
                pos += 1
                if ch == b'\x00':
                    break
                name += str(ch)
            # sanity check
            temp = self.categories.get(index, None)
            if temp != None:
                log.error("Error, category {} already exists!!".format(temp))
            # end check
            self.categories[index] = name

    def ParseIndexes(self, block, dictionary):
        data = block.data
        pos = 32
        size = block.logical_size
        while pos < size:
            index = struct.unpack("<I", data[pos: pos + 4])[0]
            pos += 4
            index_size, bytes_moved = SpotlightStore.ReadVarSizeNum(data[pos:])
            pos += bytes_moved

            padding = index_size % 4
            pos += padding

            index_size = 4 * int(index_size // 4)
            ids = struct.unpack("<" + str(index_size // 4) + "I", data[pos:pos + index_size])
            pos += index_size

            # sanity check
            temp = dictionary.get(index, None)
            if temp != None:
                log.error("Error, category {} already exists!!".format(temp))
            # end check
            dictionary[index] = ids

    def ProcessBlock(self, block, dictionary):
        if block.block_type == BlockType.UNKNOWN_0:
            pass
        elif block.block_type == BlockType.METADATA:
            pass
        elif block.block_type == BlockType.PROPERTY:
            self.ParseProperties(block)
        elif block.block_type == BlockType.CATEGORY:
            self.ParseCategories(block)
        elif block.block_type == BlockType.UNKNOWN_41:
            pass
        elif block.block_type == BlockType.INDEX:
            self.ParseIndexes(block, dictionary)
        else:
            log.info('Unknown block type encountered: {0x:.2X}'.format(block.block_type))

    def ItemExistsInDictionary(self, items_to_compare, md_item):
        '''Check if md_item exists in the dictionary'''
        # items_to_compare[id] = [id, parent_id, name, full_path, date]
        hit = items_to_compare.get(md_item.id, None)
        if hit and (hit[4] == md_item.date_updated): return True
        return False

    def ParseMetadataBlocks(self, output_file, items, items_to_compare=None, process_items_func=None):
        # Index = [last_id_in_block, offset_index, dest_block_size]
        for index in self.block0.indexes:
            # go to offset and parse
            self.Seek(index[1] * 0x1000)
            block_data = self.ReadFromFile(self.block_size)
            compressed_block = StoreBlock(block_data)
            if compressed_block.block_type & 0xFF != BlockType.METADATA:
                raise Exception('Expected METADATA block, Unknown block type encountered: 0x{:X}'.format(
                    compressed_block.block_type))
            log.debug("Trying to decompress compressed block @ {:X}".format(index[1] * 0x1000 + 20))

            try:
                if compressed_block.block_type & 0x1000 == 0x1000:  # LZ4 compression
                    if block_data[20:24] in [b'bv41', b'bv4-']:
                        # check for bv41, version 97 in High Sierra has this header (bv41) and footer (bv4$)
                        # There are often multiple chunks  bv41.....bv41.....bv41.....bv4$
                        # Sometimes bv4- (uncompressed data) followed by 4 bytes length, then data
                        chunk_start = 20  # bv41 offset
                        uncompressed = b''
                        last_uncompressed = b''
                        header = block_data[chunk_start:chunk_start + 4]
                        while (self.block_size > chunk_start) and (header != b'bv4$'):  # b'bv41':
                            log.debug("0x{:X} - {}".format(chunk_start, header))
                            if header == b'bv41':
                                uncompressed_size, compressed_size = struct.unpack('<II', block_data[
                                                                                          chunk_start + 4:chunk_start + 12])
                                last_uncompressed = lz4.block.decompress(
                                    block_data[chunk_start + 12: chunk_start + 12 + compressed_size], uncompressed_size,
                                    dict=last_uncompressed)
                                chunk_start += 12 + compressed_size
                                uncompressed += last_uncompressed
                            elif header == b'bv4-':
                                uncompressed_size = struct.unpack('<I', block_data[chunk_start + 4:chunk_start + 8])[0]
                                uncompressed += block_data[chunk_start + 8:chunk_start + 8 + uncompressed_size]
                                chunk_start += 8 + uncompressed_size
                            else:
                                log.warning('Unknown compression value @ 0x{:X} - {}'.format(chunk_start, header))
                            header = block_data[chunk_start:chunk_start + 4]
                    else:
                        uncompressed = lz4.block.decompress(block_data[20:compressed_block.logical_size],
                                                            compressed_block.unknown - 20)
                else:  # zlib compression
                    # compressed_size = compressed_block.logical_size - 20
                    uncompressed = zlib.decompress(block_data[20:compressed_block.logical_size])
            except Exception as ex:
                log.error("Decompression error for block @ {:X}\r\n{}".format(index[1] * 0x1000 + 20, str(ex)))
                if len(uncompressed) == 0: continue

            ## Now process it!!
            items_in_block = []
            pos = 0
            count = 0
            meta_size = len(uncompressed)
            while (pos < meta_size):
                item_size = struct.unpack("<I", uncompressed[pos:pos + 4])[0]
                md_item = FileMetaDataListing(pos + 4, uncompressed[pos + 4: pos + 4 + item_size], item_size)
                try:
                    md_item.ParseItem(self.properties, self.categories, self.indexes_1, self.indexes_2)
                    if items_to_compare and self.ItemExistsInDictionary(items_to_compare, md_item):
                        pass  # if md_item exists in compare_dict, skip it, else add
                    else:
                        items_in_block.append(md_item)
                        name = md_item.GetFileName()
                        existing_item = items.get(md_item.id, None)
                        if existing_item != None:
                            log.warning('Item already present id={}, name={}, existing_name={}'.format(md_item.id, name,
                                                                                                       existing_item[
                                                                                                           2]))
                            if existing_item[1] != md_item.parent_id:
                                log.warning(
                                    "Repeat item has different parent_id, existing={}, new={}".format(existing_item[1],
                                                                                                      md_item.parent_id))
                            if name != '------NONAME------':  # got a real name
                                if existing_item[2] == '------NONAME------':
                                    existing_item[2] = name
                                else:  # has a valid name
                                    if existing_item[2] != name:
                                        log.warning("Repeat item has different name, existing={}, new={}".format(
                                            existing_item[2], name))
                        else:  # Not adding repeat elements
                            items[md_item.id] = [md_item.id, md_item.parent_id, md_item.GetFileName(),
                                                 '', md_item.date_updated]  # id, parent_id, name, path, date
                except:
                    log.exception(
                        'Error trying to process item @ block {:X} offset {}'.format(index[1] * 0x1000 + 20, pos))
                pos += item_size + 4
                count += 1

            if process_items_func:
                process_items_func(items_in_block)

            for md_item in items_in_block:
                md_item.Print(output_file)

    def ParseBlockSequence(self, initial_index, type, dictionary):
        '''Follow the sequence of next_block_index to parse all blocks in the chain'''
        self.Seek(initial_index * 0x1000)
        block_data = self.ReadFromFile(self.block_size)
        block = StoreBlock(block_data)
        if block.block_type != type:
            raise Exception('Not the right block type, got {} instead of {} !!'.format(block.block_type, type))
        self.ProcessBlock(block, dictionary)
        while block.next_block_index != 0:
            self.Seek(block.next_block_index * 0x1000)
            block_data = self.ReadFromFile(self.block_size)
            block = StoreBlock(block_data)
            if block.block_type != type:
                raise Exception('Not the right block type, got {} instead of {} !!'.format(block.block_type, type))
            self.ProcessBlock(block, dictionary)

    def ReadBlocksInSeq(self):
        '''Reads blocks by following next_block variables, that's how spotlight would read it'''

        self.Seek(self.header_size)
        block0_data = self.ReadFromFile(self.block0_size)
        self.block0 = StoreBlock0(block0_data)

        self.ParseBlockSequence(self.index_blocktype_11, BlockType.PROPERTY, self.properties)
        self.ParseBlockSequence(self.index_blocktype_21, BlockType.CATEGORY, self.categories)
        self.ParseBlockSequence(self.index_blocktype_81_1, BlockType.INDEX, self.indexes_1)
        self.ParseBlockSequence(self.index_blocktype_81_2, BlockType.INDEX, self.indexes_2)
        self.ParseBlockSequence(self.index_blocktype_41, BlockType.UNKNOWN_41, None)

    def ReadBlocksNoSeq(self):
        '''Reads all blocks as is, without consideration for sequence,, may miss or exclude some data or may read invalid data, if its a deleted chunk??'''
        # TODO: This function is incomplete! Do not use!
        self.Seek(self.header_size)
        block0_data = self.ReadFromFile(self.block0_size)
        block0 = StoreBlock0(block0_data)

        self.Seek(self.header_size + block0.physical_size)

        while self.pos < self.file_size:
            block_data = self.ReadFromFile(self.block_size)
            block = StoreBlock(block_data)
            self.ProcessBlock(block)
            if block.physical_size != self.block_size:
                raise Exception("Block size mismatch!")
            self.Seek(self.pos + self.block_size)


def RecursiveGetFullPath(item, items_list):
    '''Return full path to given item, here items_list is dictionary'''
    # item = [id, parent_id, name, full_path, date]
    if item[3]:
        return item[3]
    if item[0] == 1:  # is this plist?
        return 'plist'
    name = item[2]
    if item[0] == 2:  # This is root
        if name == '':
            name = '/'
        item[3] = name
        return name
    search_id = item[1]

    if search_id == 0:
        search_id = 2  # root
    ret_path = ''
    found_item = items_list.get(search_id, None)

    if found_item != None:
        parent_path = RecursiveGetFullPath(found_item, items_list)
        ret_path = (parent_path + '/' + name) if parent_path != '/' else (parent_path + name)
        found_item[3] = parent_path
    elif search_id == 2:  # root
        ret_path = ('/' + name) if name else '/'
    else:
        log.debug('Err, could not find path for id {} '.format(search_id))
        ret_path = '..NOT-FOUND../' + name
    return ret_path


def ProcessStoreDb(input_file_path, output_path, file_name_prefix='store'):
    '''Main processing function'''

    items = {}
    time_processing_started = time.time()

    output_path_full_paths = os.path.join(output_folder, file_name_prefix + '_fullpaths.csv')
    output_path_data = os.path.join(output_folder, file_name_prefix + '_data.txt')

    log.info('Processing ' + input_file_path)
    try:
        with open(input_file_path, 'rb') as f:
            log.info("Creating output file {}".format(output_path_data))
            with open(output_path_data, 'wb') as output_file:
                log.info("Creating output file {}".format(output_path_full_paths))
                with open(output_path_full_paths, 'wb') as output_paths_file:
                    store = SpotlightStore(f)
                    store.ReadBlocksInSeq()
                    store.ParseMetadataBlocks(output_file, items, None, None)

                    output_paths_file.write("Inode_Number\tFull_Path\r\n")
                    for k, v in list(items.items()):
                        name = v[2]
                        if name:
                            fullpath = RecursiveGetFullPath(v, items)
                            to_write = str(k) + '\t' + fullpath + '\r\n'
                            output_paths_file.write(to_write.encode('utf-8'))
    except Exception as ex:
        log.exception('')

    time_processing_ended = time.time()
    run_time = time_processing_ended - time_processing_started
    log.info("Finished in time = {}".format(time.strftime('%H:%M:%S', time.gmtime(run_time))))


if __name__ == "__main__":
    import argparse

    description = "This script will process individual Spotlight database files. These files " \
                  "are found under the volume at location '/.Spotlight-V100/Store-V2/<UUID>' " \
                  "where <UUID> represents a store id. In that folder you should find files " \
                  "named 'store' and '.store' which are the Spotlight databases. Provide these " \
                  "as input to this script. "

    arg_parser = argparse.ArgumentParser(
        description='Spotlight Parser version {} - {}'.format(__VERSION__, description))
    arg_parser.add_argument('input_path', help="Path to 'store' or '.store' file (the Spotlight db)")
    arg_parser.add_argument('output_folder', help='Path to output folder')
    arg_parser.add_argument('-p', '--output_prefix', help='Prefix for output file names')

    args = arg_parser.parse_args()

    output_folder = args.output_folder
    output_file_prefix = args.output_prefix if args.output_prefix else 'spotlight-store'

    # log
    log_level = logging.DEBUG
    log_console_handler = logging.StreamHandler()
    log_console_handler.setLevel(log_level)
    log_console_format = logging.Formatter('%(levelname)s - %(message)s')
    log_console_handler.setFormatter(log_console_format)
    log.addHandler(log_console_handler)
    log.setLevel(log_level)

    if not os.path.exists(output_folder):
        log.info("Output folder '{}' does not exist! Creating it for you.".format(output_folder))
        os.makedirs(output_folder)

    if not os.path.exists(args.input_path):
        log.error("Input file'{}' does not exist".format(args.input_path))
        sys.exit()

    ProcessStoreDb(args.input_path, output_folder, output_file_prefix)


