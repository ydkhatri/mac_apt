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
# Last Updated : 08/07/2020
# Requirement  : Python 3.7, modules ( lz4, pyliblzfse )
#                Dependencies can be installed using the command 'pip install lz4 pyliblzfse' 
# 
# Purpose      : Parse the Spotlight store.db or .store.db file from mac OSX
#                These files are located under:
#                 /.Spotlight-V100/Store-V2/<UUID>/
#
#                Since macOS 10.13, there are also spotlight databases for each user under
#                 ~/Library/Metadata/CoreSpotlight/index.spotlightV3/
#
#                iOS Spotlight databases are found at location
#                /private/var/mobile/Library/Spotlight/CoreSpotlight/***/index.spotlightV2
#                where *** is one of NSFileProtectionComplete, NSFileProtectionCompleteUnlessOpen or
#                NSFileProtectionCompleteUntilFirstUserAuthentication. For iOS databases, you
#                will need to have the files that begin with 'dbStr' (which are available 
#                in the same folder as store.db. These files are specific to that instance
#                of store.db. Ideally, just extract the whole folder instead of just the single
#                store.db file. 
#
# Usage        : spotlight_parser.py [-p OUTPUT_PREFIX] <path_to_database>  <output_folder>
#                Example:  python.exe spotlight_parser.py c:\store.db  c:\store_output
#
# Ack          : M Bartle for most of the python3 porting
#
# Feedback     : Send bugs and feedback to yogesh@swiftforensics.com
#

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

lzfse_capable = False

try:
    import liblzfse
    lzfse_capable = True
except ImportError:
    print("liblzfse not found. Won't decompress lzfse/lzvn streams")

__VERSION__ = '0.9.2'

log = logging.getLogger('SPOTLIGHT_PARSER')

class FileMetaDataListing:
    def __init__(self, file_pos, data, size):
        self.file_pos = file_pos
        self.pos = 0
        self.data = data
        self.size = size
        self.meta_data_dict = {} # { kMDItemxxx: value1, kMCItemyyy: value2, ..}
        #
        self.id = 0 # inode number
        self.flags = 0
        self.item_id = 0
        self.parent_id = 0 # inode for parent folder
        self.date_updated = None
        self.full_path = ''
       
    def ReadFloat(self):
        num = struct.unpack("<f", self.data[self.pos : self.pos + 4])[0]
        self.pos += 4
        return num

    def ReadDouble(self):
        num = struct.unpack("<d", self.data[self.pos : self.pos + 8])[0]
        self.pos += 8
        return num

    def ReadDate(self):
        '''Returns date as string'''
        # Date stored as 8 byte double, it is mac absolute time (2001 epoch)
        mac_abs_time = self.ReadDouble()
        if mac_abs_time > 0: # Sometimes, a very large number that needs to be reinterpreted as signed int
            old = mac_abs_time
            mac_abs_time = struct.unpack("<q", struct.pack("<Q", int(mac_abs_time)) )[0] # double to signed int64
            if int(old) == mac_abs_time: # int(536198400.512156) == 536198400 = True
                mac_abs_time = old # preserve extra precision after decimal point
        try:
            return datetime.datetime(2001,1,1) + datetime.timedelta(seconds = mac_abs_time)
        except (ValueError, OverflowError, struct.error):
            pass
        return ""
    
    def ConvertEpochToUtcDateStr(self, value):
        '''Convert Epoch microseconds timestamp to string'''
        try:
            return datetime.datetime(1970, 1, 1) + datetime.timedelta(seconds=value/1000000.)
        except OverflowError:
            pass
        return ""
    
    def ReadVarSizeNum(self):
        '''Returns num and bytes_read'''
        num, bytes_read = SpotlightStore.ReadVarSizeNum(self.data[self.pos : min(self.size, 9 + self.size)])
        self.pos += bytes_read
        return num, bytes_read

    def ReadStr(self, dont_decode=False):
        '''Returns single string of data and bytes_read'''
        size, pos = self.ReadVarSizeNum()
        string = self.data[self.pos:self.pos + size]
        if string[-1] == 0:
            string = string[:-1] # null character
        if string.endswith(b'\x16\x02'):
            string = string[:-2]
        self.pos += size
        if dont_decode:
            return string, size + pos
        return string.decode('utf8', "backslashreplace"), size + pos

    def ReadStrings(self, dont_decode=False):
        '''Returns array of strings found in data and bytes_read'''
        size, pos = self.ReadVarSizeNum()
        all_strings_in_one = self.data[self.pos:self.pos+size]
        strings = [x for x in all_strings_in_one.split(b'\x00') if x != b'']
        if dont_decode:
            strings = [x[:-2] if x.endswith(b'\x16\x02') else x for x in strings]
        else:
            strings = [x[:-2].decode('utf8', "backslashreplace") if x.endswith(b'\x16\x02') else x.decode('utf8', "backslashreplace") for x in strings]
        self.pos += size
        return strings, size + pos

    def ReadSingleByte(self):
        single = struct.unpack("<B", self.data[self.pos : self.pos + 1])[0]
        self.pos += 1
        return single

    def ReadManyBytes(self, count, debug_dont_advance = False):
        '''Returns tuple, does not increment file pointer'''
        many = struct.unpack("<" + str(count) + "B", self.data[self.pos : self.pos + count])
        if debug_dont_advance:
            return many
        self.pos += count
        return many

    # No usages
    def ReadManyBytesReturnHexString(self, count, debug_dont_advance = False):
        '''does not increment file pointer'''
        many = self.ReadManyBytes(count, debug_dont_advance)
        ret = ''.join('{:02X}'.format(x) for x in many)
        return ret

    def GetFileName(self):
        if self.meta_data_dict.get('_kStoreMetadataVersion', None) != None: # plist, not metadata
            return '------PLIST------'
        name = self.meta_data_dict.get('_kMDItemFileName', None)
        if name == None:
            name = self.meta_data_dict.get('kMDItemDisplayName')
        if name:
            if type(name) == list:
                name = name[0]
            if '\x16\x02' in name:
                name = name.split('\x16\x02')[0]
        else:
            name = '------NONAME------'
        return name

    def StringifyValue(self, v):
        if type(v) == list:
            if v:
                if len(v) == 1:
                    v = v[0]
                else:
                    if type(v[0]) != str:
                        v = ', '.join([str(x) for x in v])
                    else:
                        v = ', '.join(v)
            else:
                v = ''

        if type(v) not in (bytes, str):
            v = str(v)
        if type(v) == bytes:
            v = v.decode('utf-8', 'backslashreplace')
        return v

    def Print(self, file):
        try:
            dashed_line = "-"*60
            info = "Inode_Num --> {}\r\nFlags --> {}\r\nStore_ID --> {}\r\nParent_Inode_Num --> {}\r\nLast_Updated --> {}\r\n".format(self.id, self.flags, self.item_id, self.parent_id, self.ConvertEpochToUtcDateStr(self.date_updated))

            file.write((dashed_line + '\r\n' + info).encode('utf-8', 'backslashreplace'))
            for k, v in sorted(self.meta_data_dict.items()):
                orig_debug = v
                v = self.StringifyValue(v)
                file.write((k + " --> " + v).encode('utf-8', 'backslashreplace'))
                file.write(b'\r\n')
        except (UnicodeEncodeError, ValueError, TypeError) as ex:
            log.exception("Exception trying to print data : ")

    def ConvertUint64ToSigned(self, unsigned_num):
        '''Return signed version of number, Eg: 0xFFFFFFFFFFFFFFFF will return -1'''
        return struct.unpack("<q", struct.pack("<Q", unsigned_num))[0]

    def ConvertUint32ToSigned(self, unsigned_num):
        '''Return signed version of number, Eg: 0xFFFFFFFF will return -1'''
        return struct.unpack("<i", struct.pack("<I", unsigned_num))[0]

    def ParseItem(self, properties, categories, indexes_1, indexes_2):
        self.id = self.ConvertUint64ToSigned(self.ReadVarSizeNum()[0])
        self.flags = self.ReadSingleByte()
        self.item_id = self. ConvertUint64ToSigned(self.ReadVarSizeNum()[0])
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
        last_prop = None # for debug only
        last_filepos = 0 # for debug only
        filepos = None
        prop = None
        while  self.pos < self.size:
            last_filepos = filepos
            filepos = hex(self.file_pos + 0 + self.pos)
            prop_skip_index = self.ReadVarSizeNum()[0]
            if prop_skip_index == 0:
                log.warning("Something went wrong, skip index was 0 @ {}".format(filepos))
            prop_index += prop_skip_index
            last_prop = prop # for debug only
            prop = properties.get(prop_index, None)
            if prop == None:
                log.error("Error, cannot proceed, invalid property index {}, skip={}".format(prop_index, prop_skip_index))
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
                    #log.debug("Found value_type 7, prop_type=0x{:X} prop={} @ {}, pos 0x{:X}".format(prop_type, prop_name, filepos, self.pos))
                    if prop_type & 2 == 2: #  == 0x0A:
                        number = self.ConvertUint64ToSigned(self.ReadVarSizeNum()[0])
                        num_values = number >> 3
                        value = [self.ConvertUint64ToSigned(self.ReadVarSizeNum()[0]) for x in range(num_values)]
                        discarded_bits = number & 0x07
                        if discarded_bits != 0:
                            log.info('Discarded bits value was 0x{:X}'.format(discarded_bits))
                    else:
                        # 0x48 (_kMDItemDataOwnerType, _ICItemSearchResultType, kMDItemRankingHint, FPCapabilities)
                        # 0x4C (_kMDItemStorageSize, _kMDItemApplicationImporterVersion)
                        # 0x0a (_kMDItemOutgoingCounts, _kMDItemIncomingCounts) firstbyte = 0x20 , then 4 bytes
                        value = self.ConvertUint64ToSigned(self.ReadVarSizeNum()[0])
                    #if prop_type == 0x48: # Can perhaps be resolved to a category? Need to check.
                    #    print("") 
                elif value_type == 8 and prop_name != 'kMDStoreAccumulatedSizes':
                    if prop_type & 2 == 2:
                        num_values = (self.ReadVarSizeNum()[0])
                        singles = [self.ReadSingleByte() for x in range(num_values)]
                        value = singles
                    else:
                        value = self.ReadSingleByte()
                elif value_type == 9:
                    if prop_type & 2 == 2:
                        num_values = (self.ReadVarSizeNum()[0])//4
                        floats = [self.ReadFloat() for x in range(num_values)]
                        value = floats
                    else:
                        value = self.ReadFloat()
                elif value_type == 0x0A:
                    if prop_type & 2 == 2:
                        num_values = (self.ReadVarSizeNum()[0])//8
                        doubles = [self.ReadDouble() for x in range(num_values)]
                        value = doubles
                    else:
                        value = self.ReadDouble()
                elif value_type == 0x0B:
                    value = self.ReadStrings()[0]
                    if prop_type & 2 != 2:
                        if len(value) == 0:
                            value = ''
                        elif len(value) == 1:
                            value = value[0]
                        else:
                            log.warning('String was multivalue without multivalue bit set')
                elif value_type == 0x0C:
                    if prop_type & 2 == 2:
                        num_dates = (self.ReadVarSizeNum()[0])//8
                        dates = []
                        for x in range(num_dates):
                            dates.append(self.ReadDate())
                        value = dates
                    else:
                        value = self.ReadDate()
                elif value_type == 0x0E:
                    if prop_type & 2 == 2:
                        value = self.ReadStrings(dont_decode=True if prop_name != 'kMDStoreProperties' else False)[0]
                    else:
                        value = self.ReadStr(dont_decode=True if prop_name != 'kMDStoreProperties' else False)[0]
                    if prop_name != 'kMDStoreProperties':
                        if type(value) == list:
                            if len(value) == 1:
                                value = binascii.hexlify(value[0]).decode('ascii').upper()
                            else:
                                value = [binascii.hexlify(item).decode('ascii').upper() for item in value]
                        else: # single string
                            value = binascii.hexlify(value).decode('ascii').upper()
                elif value_type == 0x0F:
                    value = self.ConvertUint32ToSigned(self.ReadVarSizeNum()[0])
                    if value < 0:
                        if value == -16777217:
                            value = ''
                        else:
                            value = 'INVALID ({})'.format(value)
                    else:
                        old_value = value
                        if prop_type & 3 == 3: # in (0x83, 0xC3, 0x03): # ItemKind
                            value = indexes_2.get(value, None)
                            if value == None:
                                value = 'error getting index_2 for value {}'.format(old_value)
                            else:
                                for v in value:
                                    if v < 0: continue
                                    cat = categories.get(v, None)
                                    if cat == None:
                                        #log.error('error getting category for index={}  prop_type={}  prop_name={}'.format(v, prop_type, prop_name))
                                        value = ''
                                    else:
                                        all_translations = cat.split(b'\x16\x02')
                                        if len(all_translations) > 2:
                                            log.warning('Encountered more than one control sequence in single translation'
                                                        'string.')
                                            log.debug('Found this list: {}', other)
                                        value = all_translations[0].decode('utf8', 'backslashreplace')
                                        break # only get first, rest are language variants!
                        elif prop_type & 0x2 == 0x2: #== 0x4A: # ContentTypeTree ItemUserTags
                            value = indexes_1.get(value, None)
                            if value == None:
                                value = 'error getting index_1 for value {}'.format(old_value)
                            else:
                                tree = []
                                for v in value:
                                    if v < 0: continue
                                    cat = categories.get(v, None)
                                    if cat == None:
                                        log.error('error getting category for index={}  prop_type={}  prop_name={}'.format(v, prop_type, prop_name))
                                    else:
                                        tree.append(cat.decode('utf8', 'backslashreplace'))
                                value = tree
                        else: #elif prop_type & 8 == 8: #== 0x48: # ContentType
                            if value >= 0:
                                cat = categories.get(value, None)
                                if cat == None:
                                    log.error('error getting category for index={}  prop_type={}  prop_name={}'.format(v, prop_type, prop_name))
                                    value = ''
                                else:
                                    value = cat
                                value = value.decode('utf8', 'backslashreplace')
                            else:
                                value = ''
                        #else:
                        #    log.info("Not seen before value-type 0x0F item, prop_type={:X}, prop={}".format(prop_type, prop_name))
                else:
                    if prop_name != 'kMDStoreAccumulatedSizes':
                        log.info("Pos={}, Unknown value_type {}, PROPERTY={}, PROP_TYPE={} ..RETURNING!".format(filepos, value_type, prop_name, prop_type))
                    return
                if prop_name in self.meta_data_dict:
                    log.warning('Spotlight property {} had more than one entry for inode {}'.format(prop_name, self.id))
                self.meta_data_dict[prop_name] = value
                

class BlockType(IntEnum):
    UNKNOWN_0  = 0
    METADATA   = 0x09
    PROPERTY   = 0x11
    CATEGORY   = 0x21
    UNKNOWN_41 = 0x41
    INDEX      = 0x81

    def __str__(self):
        return self.name

class StoreBlock0:
    def __init__(self, data):
        self.data = data
        self.signature = struct.unpack("<I", data[0:4])[0]
        if self.signature not in [0x64626D31, 0x64626D32]:  #  1mbd or 2mbd (block 0)
            raise Exception("Unknown signature {:X} in block0! Can't parse".format(self.signature))
        self.physical_size = struct.unpack("<I", data[4:8])[0]
        self.item_count    = struct.unpack("<I", data[8:12])[0]
        self.unk_zero      = struct.unpack("<I", data[12:16])[0]
        self.unk_type      = struct.unpack("<I", data[16:20])[0]
        # Followed by indexes [last_id_in_block, offset_index, dest_block_size]
        # If sig==1mbd, then last_id_in_block is BigEndian else LE
        # Everything else LE
        self.indexes = []
        pos = 20
        for i in range (0, self.item_count):
            index = struct.unpack("<QII", data[pos : pos + 16]) # last_id_in_block is not used, so we don't care if it is read BE/LE
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
        self.logical_size  = struct.unpack("<I", data[8:12])[0]
        self.block_type    = struct.unpack("<I", data[12:16])[0]
        #
        self.unknown = struct.unpack("<I", data[16:20])[0] # usually zero or size of uncompressed data
        self.next_block_index = struct.unpack("<I", data[20:24])[0]
        self.unknown1 = struct.unpack("<I", data[24:28])[0]
        self.unknown2 = struct.unpack("<I", data[28:32])[0]

class DbStrMapHeader:
    def __init__(self):
        self.sig = None
        self.unk1 = 0
        self.unk2 = 0
        self.unk3 = 0
        self.next_free_location_in_map_data = 0
        self.unk5 = 0
        self.next_data_id_number = 0
        self.unk7 = 0
        self.unk8 = 0
        self.unk9 = 0
        self.num_deleted_entries = 0
        self.unk10 = 0
        self.unk11 = 0

    def Parse(self, data):
        self.sig, self.unk1, self.unk2, self.unk3, self.next_free_location_in_map_data, \
        self.unk5, self.next_data_id_number, self.unk7, self.unk8, self.unk9, \
        self.num_deleted_entries, self.unk11, self.unk12 = struct.unpack("<Q12I", data[0:56])
        if self.sig != 0x0000446174615000:
            log.warning("Header signature is different for DbStrMapHeader. Sig=0x{:X}".format(self.sig))


class SpotlightStore:
    def __init__(self, file_pointer):
        self.file = file_pointer
        #self.pos = 0
        if not self.IsValidStore():
            raise Exception('Not a version 2 Spotlight store.db file, invalid format!')
        self.file.seek(0)
        self.header = self.file.read(0x1000)
        self.flags = struct.unpack("<I", self.header[4:8])[0]
        self.header_unknowns = struct.unpack("6I", self.header[12:36])
        self.header_size = self.ReadUint(self.header[36:40])
        self.block0_size = self.ReadUint(self.header[40:44])
        self.block_size  = self.ReadUint(self.header[44:48])
        self.index_blocktype_11 = self.ReadUint(self.header[48:52])
        self.index_blocktype_21 = self.ReadUint(self.header[52:56])
        self.index_blocktype_41 = self.ReadUint(self.header[56:60])
        self.index_blocktype_81_1 = self.ReadUint(self.header[60:64])
        self.index_blocktype_81_2 = self.ReadUint(self.header[64:68])
        self.original_path = self.header[0x144:0x244].decode('utf-8', 'backslashreplace').rstrip('\0') # 256 bytes
        self.file_size = self.GetFileSize(self.file)

        self.properties = {}
        self.categories = {}
        self.indexes_1 = {}
        self.indexes_2 = {}
        self.block0 = None

        self.is_ios_store = self.index_blocktype_11 == 0

    def GetFileSize(self, file):
        '''Return size from an open file handle'''
        current_pos = file.tell()
        file.seek(0, 2) # Seek to end
        size = file.tell()
        file.seek(current_pos) # back to original position
        return size
    
    def IsValidStore(self):
        self.file.seek(0)
        signature = self.file.read(4)
        if signature == b'\x38\x74\x73\x64': # 8tsd
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
    def ReadIndexVarSizeNum(data):
        '''Returns num and bytes_read'''
        byte = struct.unpack("B", data[0:1])[0]
        num_bytes_read = 1
        ret = byte & 0x7F # remove top bit
        while (byte & 0x80) == 0x80: # highest bit set, need to read one more
            byte = struct.unpack("B", data[num_bytes_read:num_bytes_read + 1])[0]
            ret |= (byte & 0x7F) << (7 * num_bytes_read)
            num_bytes_read += 1
        return ret, num_bytes_read

    @staticmethod
    def ReadVarSizeNum(data):
        '''Returns num and bytes_read'''
        first_byte = struct.unpack("B", data[0:1])[0]
        extra = 0
        use_lower_nibble = True
        if first_byte == 0:
            return 0, 1
        elif (first_byte & 0xF0) == 0xF0: # 4 or more
            use_lower_nibble = False
            if (first_byte & 0x0F)==0x0F: extra = 8
            elif (first_byte & 0x0E)==0x0E: extra = 7
            elif (first_byte & 0x0C)==0x0C: extra = 6
            elif (first_byte & 0x08)==0x08: extra = 5
            else: 
                extra = 4
                use_lower_nibble = True
                first_byte -= 0xF0
        elif (first_byte & 0xE0) == 0xE0:
            extra = 3
            first_byte -= 0xE0
        elif (first_byte & 0xC0) == 0xC0:
            extra = 2
            first_byte -=0xC0
        elif (first_byte & 0x80) == 0x80:
            extra = 1
            first_byte -= 0x80

        if extra:
            num = 0
            num += sum(struct.unpack('B', data[x:x+1])[0] << (extra - x) * 8 for x in range(1, extra + 1))
            if use_lower_nibble:
                num = num + (first_byte << (extra*8))
            return num, extra + 1
        return first_byte, extra + 1

    def ReadOffsets(self, offsets_content):
        ''' Read offsets and index information from dbStr-x.map.offsets file data.
            Returns list of lists [ [index, offset], [index, offset], .. ]
        '''
        offsets_len = len(offsets_content)
        pos = 4
        index = 1
        offsets = [] # [ [index, offset], [index, offset], ..]
        while pos < offsets_len:
            off = struct.unpack("<I", offsets_content[pos:pos + 4])[0]
            if off == 0:
                break
            elif off != 1: # 1 is invalid (deleted)
                offsets.append([index, off])
            index += 1
            pos += 4
        return offsets

    def ParsePropertiesFromFileData(self, data_content, offsets_content, header_content):
        data_len = len(data_content)
        header_len = len(header_content)

        header = DbStrMapHeader()
        header.Parse(header_content)               
        
        # Parse offsets file
        offsets = self.ReadOffsets(offsets_content)
        
        # Parse data file
        data_version = struct.unpack("<H", data_content[0:2])
        for index, offset in offsets:
            entry_size, bytes_moved = SpotlightStore.ReadVarSizeNum(data_content[offset:])
            value_type, prop_type = struct.unpack("<BB", data_content[offset + bytes_moved : offset + bytes_moved + 2])
            name = data_content[offset + bytes_moved + 2:offset + bytes_moved + entry_size].split(b'\x00')[0]
            self.properties[index] = [name.decode('utf-8', 'backslashreplace'), prop_type, value_type]

    def ParseProperties(self, block):
        data = block.data
        pos = 32
        size = block.logical_size
        while pos < size:
            index, value_type, prop_type = struct.unpack("<IBB", data[pos : pos+6])
            pos += 6
            name = data[pos:pos+size].split(b'\x00')[0]
            pos += len(name) + 1 if len(name) < size else size
            self.properties[index] = [name.decode('utf-8', 'backslashreplace'), prop_type, value_type]

    def ParseCategoriesFromFileData(self, data_content, offsets_content, header_content):
        data_len = len(data_content)
        header_len = len(header_content)

        header = DbStrMapHeader()
        header.Parse(header_content)               
        
        # Parse offsets file
        offsets = self.ReadOffsets(offsets_content)
        
        # Parse data file
        data_version = struct.unpack("<H", data_content[0:2])
        for index, offset in offsets:
            entry_size, bytes_moved = SpotlightStore.ReadVarSizeNum(data_content[offset:])
            name = data_content[offset + bytes_moved:offset + bytes_moved + entry_size].split(b'\x00')[0]
            self.categories[index] = name

    def ParseCategories(self, block):
        data = block.data
        pos = 32
        size = block.logical_size
        while pos < size:
            index = struct.unpack("<I", data[pos : pos+4])[0]
            pos += 4
            name = data[pos:pos+size].split(b'\x00')[0]
            pos += len(name) + 1 if len(name) < size else size
            # sanity check
            temp = self.categories.get(index, None)
            if temp != None:
                log.error("Error, category {} already exists!!".format(temp))
            # end check
            self.categories[index] = name

    def ParseIndexesFromFileData(self, data_content, offsets_content, header_content, dictionary, has_extra_byte=False):
        data_len = len(data_content)
        header_len = len(header_content)

        header = DbStrMapHeader()
        header.Parse(header_content)               
        
        # Parse offsets file
        offsets = self.ReadOffsets(offsets_content)
        
        # Parse data file
        data_version = struct.unpack("<H", data_content[0:2])
        pos = 0
        for index, offset in offsets:
            pos = offset
            entry_size, bytes_moved = SpotlightStore.ReadIndexVarSizeNum(data_content[pos:])
            pos += bytes_moved
            index_size, bytes_moved = SpotlightStore.ReadVarSizeNum(data_content[pos:])
            pos += bytes_moved
            if entry_size - index_size > 2:
                log.debug("ReadIndexVarSizeNum() read the number incorrectly?") 
            #else:
            #    log.debug("index={}, offset={}, entry_size=0x{:X}, index_size=0x{:X}".format(index, offset, entry_size, index_size))

            if has_extra_byte:
                pos += 1

            index_size = 4*int(index_size//4)
            ids = struct.unpack("<" + str(index_size//4) + "i", data_content[pos:pos + index_size])
            # sanity check
            temp = dictionary.get(index, None)
            if temp != None:
                log.error("Error, category {} already exists!!".format(temp))
            # end check
            dictionary[index] = ids

    def ParseIndexes(self, block, dictionary):
        data = block.data
        pos = 32
        size = block.logical_size
        while pos < size:
            index = struct.unpack("<I", data[pos : pos+4])[0]
            pos += 4
            index_size, bytes_moved = SpotlightStore.ReadVarSizeNum(data[pos:])
            pos += bytes_moved
            
            padding = index_size % 4
            pos += padding

            index_size = 4*int(index_size//4)
            ids = struct.unpack("<" + str(index_size//4) + "i", data[pos:pos + index_size])
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
        elif block.block_type == BlockType.PROPERTY: self.ParseProperties(block)
        elif block.block_type == BlockType.CATEGORY: self.ParseCategories(block)
        elif block.block_type == BlockType.UNKNOWN_41:
            pass
        elif block.block_type == BlockType.INDEX:
            self.ParseIndexes(block, dictionary)
        else:
            log.info ('Unknown block type encountered: 0x{:.2X}'.format(block.block_type))
    
    def ItemExistsInDictionary(self, items_to_compare, md_item):
        '''Check if md_item exists in the dictionary'''
        # items_to_compare[id] = [id, parent_id, name, full_path, date]
        hit = items_to_compare.get(md_item.id, None)
        if hit and (hit[4] == md_item.date_updated): return True
        return False

    def ParseMetadataBlocks(self, output_file, items, items_to_compare=None, process_items_func=None):
        '''Parses block, return number of items written (after deduplication if items_to_compare!=None)'''
        # Index = [last_id_in_block, offset_index, dest_block_size]
        total_items_written = 0
        for index in self.block0.indexes:
            #go to offset and parse
            seek_offset = index[1] * 0x1000
            if seek_offset >= self.file_size:
                log.error(f'File may be truncated, index seeks ({seek_offset}) outside file size ({self.file_size})!')
                continue
            self.Seek(seek_offset)
            block_data = self.ReadFromFile(self.block_size)
            compressed_block = StoreBlock(block_data)
            if compressed_block.block_type & 0xFF != BlockType.METADATA:
                raise Exception('Expected METADATA block, Unknown block type encountered: 0x{:X}'.format(compressed_block.block_type))
            log.debug ("Trying to decompress compressed block @ 0x{:X}".format(index[1] * 0x1000 + 20))

            try:
                if compressed_block.block_type & 0x1000 == 0x1000: # LZ4 compression
                    if block_data[20:24] in [b'bv41', b'bv4-']:
                        # check for bv41, version 97 in High Sierra has this header (bv41) and footer (bv4$)
                        # There are often multiple chunks  bv41.....bv41.....bv41.....bv4$
                        # Sometimes bv4- (uncompressed data) followed by 4 bytes length, then data
                        chunk_start = 20 # bv41 offset
                        uncompressed = b''
                        last_uncompressed = b''
                        header = block_data[chunk_start:chunk_start + 4]
                        while (self.block_size > chunk_start) and (header != b'bv4$'):  # b'bv41':
                            log.debug("0x{:X} - {}".format(chunk_start, header))
                            if header == b'bv41':
                                uncompressed_size, compressed_size = struct.unpack('<II', block_data[chunk_start + 4:chunk_start + 12])
                                last_uncompressed = lz4.block.decompress(block_data[chunk_start + 12: chunk_start + 12 + compressed_size], uncompressed_size, dict=last_uncompressed)
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
                        uncompressed = lz4.block.decompress(block_data[20:compressed_block.logical_size], compressed_block.unknown - 20)
                elif compressed_block.block_type & 0x2000 == 0x2000: # LZFSE compression seen, also perhaps LZVN
                    if not lzfse_capable:
                        log.error('LIBLZFSE library not available for LZFSE decompression, skipping block..')
                        continue
                    if block_data[20:23] == b'bvx':
                        # check for header (bvx1 or bvx2 or bvxn) and footer (bvx$)
                        chunk_start = 20 # bvx offset
                        uncompressed = b''
                        header = block_data[chunk_start:chunk_start + 4]    
                        log.debug("0x{:X} - {}".format(chunk_start, header))
                        if header in [b'bvx1', b'bvx2', b'bvxn']:
                            uncompressed_size = struct.unpack('<I', block_data[chunk_start + 4:chunk_start + 8])[0]
                            uncompressed = liblzfse.decompress(block_data[chunk_start : compressed_block.logical_size])
                            if len(uncompressed) != uncompressed_size:
                                log.error('Decompressed size does not match stored value, DecompSize={}, Should_be={}'.format(len(uncompressed), uncompressed_size))
                        elif header == b'bvx-':
                            uncompressed_size = struct.unpack('<I', block_data[chunk_start + 4:chunk_start + 8])[0]
                            uncompressed = block_data[chunk_start + 8:chunk_start + 8 + uncompressed_size]
                        else:
                            log.warning('Unknown compression value @ 0x{:X} - {}'.format(chunk_start, header))
                    else:
                        uncompressed = lz4.block.decompress(block_data[20:compressed_block.logical_size], compressed_block.unknown - 20)
                else: # zlib compression
                    #compressed_size = compressed_block.logical_size - 20
                    uncompressed = zlib.decompress(block_data[20:compressed_block.logical_size])
            except (ValueError,  lz4.block.LZ4BlockError, liblzfse.error) as ex:
                log.error("Decompression error for block @ 0x{:X}\r\n{}".format(index[1] * 0x1000 + 20, str(ex)))
                if len(uncompressed) == 0: continue
            
            ## Now process it!!
            items_in_block = []
            pos = 0
            count = 0
            meta_size = len(uncompressed)
            while (pos < meta_size):
                item_size = struct.unpack("<I", uncompressed[pos:pos+4])[0]
                md_item = FileMetaDataListing(pos + 4, uncompressed[pos + 4 : pos + 4 + item_size], item_size)
                try:
                    md_item.ParseItem(self.properties, self.categories, self.indexes_1, self.indexes_2)
                    if items_to_compare and self.ItemExistsInDictionary(items_to_compare, md_item): pass # if md_item exists in compare_dict, skip it, else add
                    else:
                        items_in_block.append(md_item)
                        total_items_written += 1
                        name = md_item.GetFileName()
                        existing_item = items.get(md_item.id, None)
                        if existing_item != None:
                            log.warning('Item already present id={}, name={}, existing_name={}'.format(md_item.id, name, existing_item[2]))
                            if existing_item[1] != md_item.parent_id:
                                log.warning("Repeat item has different parent_id, existing={}, new={}".format(existing_item[1], md_item.parent_id))
                            if name != '------NONAME------': # got a real name
                                if existing_item[2] == '------NONAME------':
                                    existing_item[2] = name
                                else:  # has a valid name
                                    if existing_item[2] != name:
                                        log.warning("Repeat item has different name, existing={}, new={}".format(existing_item[2], name))
                        else: # Not adding repeat elements
                            items[md_item.id] = [md_item.id, md_item.parent_id, md_item.GetFileName(), None, md_item.date_updated] # id, parent_id, name, path, date
                except:
                    log.exception('Error trying to process item @ block {:X} offset {}'.format(index[1] * 0x1000 + 20, pos))
                pos += item_size + 4
                count += 1

            if process_items_func:
                process_items_func(items_in_block, self.is_ios_store)

            for md_item in items_in_block:
                md_item.Print(output_file)
                
        return total_items_written

    def ParseBlockSequence(self, initial_index, type, dictionary):
        '''Follow the sequence of next_block_index to parse all blocks in the chain'''
        if initial_index == 0:
            log.warning('initial_index for block type 0x{:X} was invalid(zero), skipping it!'.format(type))
            return
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

    def ReadPageIndexesAndOtherDefinitions(self, only_read_block_0=False):
        '''Reads block zero that lists page indexes, then reads properties, categories and indexes'''

        self.Seek(self.header_size)
        block0_data = self.ReadFromFile(self.block0_size)
        self.block0 = StoreBlock0(block0_data)
        
        if not only_read_block_0:
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
    if item[0] == 1: #is this plist?
        return 'plist'
    name = item[2]
    if item[0] == 2: # This is root
        if name == '':
            name = '/'
        item[3] = name
        return name
    search_id = item[1]

    if search_id == 0:
        search_id = 2 # root
    ret_path = ''
    found_item = items_list.get(search_id, None)

    if found_item != None:
        parent_path = RecursiveGetFullPath(found_item, items_list)
        ret_path = (parent_path + '/' + name) if parent_path != '/' else (parent_path + name)
        found_item[3] = parent_path
    elif search_id == 2: # root
        ret_path = ('/' + name) if name else '/'
    else:
        log.debug ('Err, could not find path for id {} '.format(search_id))
        ret_path = '..NOT-FOUND../' + name
    return ret_path

def GetFileData(path):
    data = b''
    with open(path, 'rb') as f:
        data = f.read()
    return data

def GetMapDataOffsetHeader(input_folder, id):
    ''' Given an id X, this returns the data from 3 files, 
        dbStr-X.map.data, dbStr-X.map.header, dbStr-X.map.offsets. It will
        search for these files in the input_folder.
        Returns tuple (data, offsets, header)
    '''
    data_path = os.path.join(input_folder, 'dbStr-{}.map.data'.format(id))
    offsets_path = os.path.join(input_folder, 'dbStr-{}.map.offsets'.format(id))
    header_path = os.path.join(input_folder, 'dbStr-{}.map.header'.format(id))

    map_data = GetFileData(data_path)
    offsets_data = GetFileData(offsets_path)
    header_data = GetFileData(header_path)

    return (map_data, offsets_data, header_data)

def ProcessStoreDb(input_file_path, output_path, file_name_prefix='store'):
    '''Main processing function'''

    items = {}
    time_processing_started = time.time()
    create_full_paths_output_file = True

    output_path_full_paths = os.path.join(output_folder, file_name_prefix + '_fullpaths.csv')
    output_path_data = os.path.join(output_folder, file_name_prefix + '_data.txt')

    log.info('Processing ' + input_file_path)
    try:
        f = open(input_file_path, 'rb')

        store = SpotlightStore(f)
        if store.is_ios_store: #store.flags & 0x00010000 == 0x00010000:
            create_full_paths_output_file = False
            log.info('This appears to be either an iOS spotlight db or a user spotlight db. '\
                "File inode numbers are not stored here, and hence full_path file won't be created!")
            # The properties, categories and indexes must be stored in external files
            # Find and parse files
            input_folder = os.path.dirname(os.path.abspath(input_file_path))
            data_path = os.path.join(input_folder, 'dbStr-1.map.data')
            if os.path.isfile(data_path):
                try:
                    prop_map_data, prop_map_offsets,prop_map_header = GetMapDataOffsetHeader(input_folder, 1)
                    cat_map_data, cat_map_offsets, cat_map_header = GetMapDataOffsetHeader(input_folder, 2)
                    idx_1_map_data, idx_1_map_offsets, idx_1_map_header = GetMapDataOffsetHeader(input_folder, 4)
                    idx_2_map_data, idx_2_map_offsets, idx_2_map_header = GetMapDataOffsetHeader(input_folder, 5)

                    store.ParsePropertiesFromFileData(prop_map_data, prop_map_offsets, prop_map_header)
                    store.ParseCategoriesFromFileData(cat_map_data, cat_map_offsets, cat_map_header)
                    store.ParseIndexesFromFileData(idx_1_map_data, idx_1_map_offsets, idx_1_map_header, store.indexes_1)
                    store.ParseIndexesFromFileData(idx_2_map_data, idx_2_map_offsets, idx_2_map_header, store.indexes_2, has_extra_byte=True)

                    store.ReadPageIndexesAndOtherDefinitions(True)
                except:
                    log.exception('Failed to find or process one or more dependency files. Cannot proceed!')
                    f.close()
                    return
            else:
                log.error('Did not find file dbStr-1.map.data in the same folder as store.db. In order to parse this file' + 
                          ' please also have all files that begin with dbStr* in the same location as store.db. It will ' +  
                          ' be in the same folder where you found store.db')
                f.close()
                return
        else:
            store.ReadPageIndexesAndOtherDefinitions()

        log.info("Creating output file {}".format(output_path_data))

        with open(output_path_data, 'wb') as output_file:
            store.ParseMetadataBlocks(output_file, items, None, None)

        if create_full_paths_output_file:
            log.info("Creating output file {}".format(output_path_full_paths))

            with open(output_path_full_paths, 'wb') as output_paths_file:
                output_paths_file.write("Inode_Number\tFull_Path\r\n".encode('utf-8'))
                for k, v in items.items():
                    name = v[2]
                    if name:
                        fullpath = RecursiveGetFullPath(v, items)
                        to_write = str(k) + '\t' + fullpath + '\r\n'
                        output_paths_file.write(to_write.encode('utf-8', 'backslashreplace'))

    except Exception as ex:
        log.exception('')
    finally:
        f.close()

    time_processing_ended = time.time()
    run_time = time_processing_ended - time_processing_started
    log.info("Finished in time = {}".format(time.strftime('%H:%M:%S', time.gmtime(run_time))))

if __name__ == "__main__":
    import argparse

    description = "This script will process individual Spotlight database files.\n"\
                    "These files are found under the volume at location \n "\
                    "'/.Spotlight-V100/Store-V2/<UUID>' where <UUID> represents a store id.\n"\
                    "In that folder you should find files named 'store' and '.store' which\n"\
                    "are the Spotlight databases. Provide these as input to this script. \n\n"\
                    "iOS Spotlight databases (store.db and .store.db) are found at locations:\n"\
                    "/private/var/mobile/Library/Spotlight/CoreSpotlight/***/index.spotlightV2\n"\
                    "where *** is one of NSFileProtectionComplete, NSFileProtectionCompleteUnlessOpen\n"\
                    "or NSFileProtectionCompleteUntilFirstUserAuthentication folders.\n\n"\
                    "For iOS databases, you will need to have the files that begin with 'dbStr'\n"\
                    "in the same folder as store.db. These files will natively be found in the\n"\
                    "same folder as store.db and are specific to that instance of store.db.\n\n"\
                    "Example:  python.exe spotlight_parser.py c:\store.db  c:\store_output\n\n"\
                    "Send bugs/comments to yogesh@swiftforensics.com "

    arg_parser = argparse.ArgumentParser(description='Spotlight Parser version {} - {}'.format(__VERSION__, description), formatter_class=argparse.RawTextHelpFormatter)
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
    log_console_format  = logging.Formatter('%(levelname)s - %(message)s')
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
