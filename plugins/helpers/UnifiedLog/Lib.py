# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # 
# Unified log reader library
# Script Name   : UnifiedLogLib.py
# Author        : Yogesh Khatri
# Last Updated  : 2019-02-05
# Purpose/Usage : This library will read unified logs (.traceV3 files)
# Notes         : Needs python2 (not python3 ready yet!)
#
# Currently this is tested on version 17(0x11) of the tracev3 file used in 
# macOS Sierra (10.12.5) and above (including Mojave 10.14.2). It will not
# work on Sierra (10.12) as it uses version 14(0xE), a later update will
# address this.
#
# MIT License
#
# Copyright (c) 2019 Yogesh Khatri (@swiftforensics)
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from __future__ import unicode_literals

import binascii
import datetime
import os
import struct
from uuid import UUID

import lz4.block

import plugins.helpers.UnifiedLog.dsc_file as dsc_file
import plugins.helpers.UnifiedLog.logger as logger
import plugins.helpers.UnifiedLog.resources as resources


# FORMAT
#  Timestamp  Thread  Type  Activity  PID  PROC_NAME: (Library) [Subsystem:Category]  MESSAGE

# Timesync in-memory and persist start values not found in Tracev3

def ReadAPFSTime(mac_apfs_time): # Mac APFS timestamp is nano second time epoch beginning 1970/1/1
    '''Returns datetime object, or empty string upon error'''
    if mac_apfs_time not in ( 0, None, ''):
        try:
            if isinstance(mac_apfs_time, str):
                mac_apfs_time = float(mac_apfs_time)
            return datetime.datetime(1970, 1, 1) + datetime.timedelta(seconds=mac_apfs_time/1000000000.)
        except Exception as ex:
            logger.error("ReadAPFSTime() Failed to convert timestamp from value " + str(mac_apfs_time) + " Error was: " + str(ex))
    return ''

def DecompressTraceV3(trace_file, out_file):
    ''' Creates an uncompressed version of the .traceV3 file.
        Input parameters:
        trace_file = file pointer to .traceV3 file (opened as 'rb')
        out_file   = file pointer to blank file (opened as 'wb')
        Returns True/False
    '''
    try:
        index = 0
        tag = trace_file.read(4)
        while tag:
            begin_pos = trace_file.tell() - 4
            trace_file.seek(begin_pos + 8)
            struct_len = struct.unpack('<Q', trace_file.read(8))[0]
            logger.debug("index={} pos=0x{:X} tag=0x{}".format(index, begin_pos, binascii.hexlify(tag)[::-1]))

            trace_file.seek(begin_pos)
            chunk_data_incl_header = trace_file.read(16 + struct_len)
            if tag == b'\x00\x10\x00\x00': # header
                out_file.write(chunk_data_incl_header) # boot_uuid header, write to output directly
            elif tag[0] == b'\x0B':
                out_file.write(chunk_data_incl_header) # uncompressed, write to output directly
            elif tag[0] == b'\x0D':
                uncompressed = DecompressChunkData(chunk_data_incl_header[16:], struct_len)
                out_file.write(chunk_data_incl_header[0:8]) # Same Header !
                out_file.write(struct.pack('<Q', len(uncompressed))) # New size
                out_file.write(uncompressed)
            else:
                logger.error('Unknown chunk tag value encountered : {}'.format(binascii.hexlify(tag)))
                out_file.write(chunk_data_incl_header)
            if struct_len % 8: # Go to QWORD boundary
                struct_len += 8 - (struct_len % 8)
            if out_file.tell() % 8: # Go to QWORD boundary on output
                out_file.write(b'\x00\x00\x00\x00\x00\x00\x00'[0:(8-out_file.tell() % 8)])
            trace_file.seek(begin_pos + 16 + struct_len)
            tag = trace_file.read(4)
            index += 1
    except Exception as ex:
        logger.exception('')
        return False
    return True

def DecompressChunkData(chunk_data, data_len):
    '''Decompress an individual compressed chunk (tag=0x600D)'''
    uncompressed = b''
    if chunk_data[0:4] in [b'bv41', b'bv4-']:
        last_uncompressed = b''
        comp_start = 0 # bv** offset
        comp_header = chunk_data[comp_start:comp_start + 4]
        while (data_len > comp_start) and (comp_header != b'bv4$'):
            if comp_header == b'bv41':
                uncompressed_size, compressed_size = struct.unpack('<II', chunk_data[comp_start + 4:comp_start + 12])
                last_uncompressed = lz4.block.decompress(chunk_data[comp_start + 12: comp_start + 12 + compressed_size], uncompressed_size, dict=last_uncompressed)
                comp_start += 12 + compressed_size
                uncompressed += last_uncompressed
            elif comp_header == b'bv4-':
                uncompressed_size = struct.unpack('<I', chunk_data[comp_start + 4:comp_start + 8])[0]
                uncompressed += chunk_data[comp_start + 8:comp_start + 8 + uncompressed_size]
                comp_start += 8 + uncompressed_size
            else:
                logger.error('Unknown compression value {} @ 0x{:X} - {}'.format(binascii.hexlify(comp_header), begin_pos + comp_start, comp_header))
                break
            comp_header = chunk_data[comp_start:comp_start + 4]
    else:
        logger.error('Unknown compression type {}'.format(binascii.hexlify(chunk_data[16:20])))
    return uncompressed

class CachedFiles(object):
    '''
        Optimization measure to parse and hold open file pointers for uuidtext/dsc files,
        so they are not parsed again and again
    '''
    def __init__(self, v_fs):
        super(CachedFiles, self).__init__()
        self.vfs = v_fs
        self.cached_dsc = {}      # Key = UUID string uppercase (no seperators), Val = Dsc object
        self.cached_uuidtext = {} # Key = UUID string uppercase (no seperators), Val = Uuidtext object

    def ParseFolder(self, uuidtext_folder_path):
        '''Parse the uuidtext folder specified and parse all uuidtext/dsc files, adding them to the cache'''
        try:
            # dsc
            dsc_path = self.vfs.path_join(uuidtext_folder_path, 'dsc')
            entries = self.vfs.listdir(dsc_path)
            for dsc_name in entries:
                if len(dsc_name) == 32:                    
                    dsc_path_obj = self.vfs.get_virtual_file(self.vfs.path_join(dsc_path, dsc_name), 'Dsc')
                    dsc = dsc_file.Dsc(dsc_path_obj)
                    dsc.Parse()
                    self.cached_dsc[dsc_name] = dsc

            # uuidtext - can't have this or python will complain of too many open files!
            # entries = self.vfs.listdir(uuidtext_folder_path)
            # index = 0
            # for index in range(0x100):
            #     folder_name = '{:02X}'.format(index)
            #     #if vfs.path_exists(folder_path):
            #     if folder_name in entries:
            #         folder_path = self.vfs.path_join(uuidtext_folder_path, folder_name)
            #         uuid_names = self.vfs.listdir(folder_path)
            #         for uuid_name in uuid_names:
            #             if len(uuid_name) == 30: # filtering out possibly other files there!
            #                 uuidtext_path = self.vfs.path_join(folder_path, uuid_name)
            #                 file_object = self.vfs.get_virtual_file(uuidtext_path, 'Uuidtext')
            #                 ut = uuidtext_file.Uuidtext(file_object, UUID(folder_name + uuid_name))
            #                 ut.Parse()
            #                 self.cached_uuidtext[folder_name + uuid_name] = ut
            #     else:
            #         logger.debug(folder_name + ' does not exist')
        except Exception:
            logger.exception('')

def ReadTimesyncFile(buffer, ts_list):
    try:
        pos = 0
        size = len(buffer)
        while pos < size:
            sig, header_size, unk1  = struct.unpack("<HHI", buffer[pos:pos+8])
            if sig != 0xBBB0:
                logger.error("not the right signature for Timesync header, got 0x{:04X} instead of 0x{:04X}, pos was 0x{:08X}".format(sig, 0x0030BBB0, pos))
                break
            uuid = UUID(bytes=buffer[pos+8:pos+24])
            ts_numer, ts_denom, t_stamp, tz, is_dst = struct.unpack("<IIqiI", buffer[pos+24:pos+48])
            ts_header = resources.TimesyncHeader(sig, unk1, uuid, ts_numer, ts_denom, t_stamp, tz, is_dst)
            pos += header_size # 0x30 (48) by default
            if header_size != 0x30:
                logger.info("Timesync header was 0x{:X} bytes instead of 0x30(48) bytes!".format(size))
            logger.debug("TIMEHEAD {}  0x{:016X}  {} {}".format(uuid, t_stamp, ReadAPFSTime(t_stamp), 'boot'))
            #TODO - TEST search ts_list for existing, not seen so far
            existing_ts = None
            for ts in ts_list:
                if ts.header.boot_uuid == uuid:
                    existing_ts = ts
                    break
            if existing_ts:
                ts_obj = existing_ts
            else:
                ts_obj = resources.Timesync(ts_header)
                ts_list.append(ts_obj)
                # Adding header timestamp as Ts type too with cont_time = 0
                timesync_item = resources.TimesyncItem(0, 0, t_stamp, tz, is_dst)
                ts_obj.items.append(timesync_item)
            while pos < size:
                if buffer[pos:pos+4] == b'Ts \x00':
                    ts_unknown, cont_time, t_stamp, bias, is_dst = struct.unpack("<IqqiI", buffer[pos+4:pos+32])
                    timesync_item = resources.TimesyncItem(ts_unknown, cont_time, t_stamp, bias, is_dst)
                    ts_obj.items.append(timesync_item)
                    logger.debug("TIMESYNC {}  0x{:016X}  {} {}".format(uuid, t_stamp, ReadAPFSTime(t_stamp), ts_unknown))
                else:
                    break # break this loop, parse as header
                pos += 32
    except Exception as ex:
        logger.exception("Exception reading TimesyncFile")

def ReadTimesyncFolder(path, ts_list, vfs):
    '''Reads files in the timesync folder specified by 'path' and populates ts_list 
       with timesync entries.
       vfs = VirtualFileSystem object
    '''
    try:
        entries = vfs.listdir(path)
        for entry in sorted(entries): # sort the files by name, so continuous time will be sequential automatically
            if entry.endswith(".timesync"):
                file_path = vfs.path_join(path, entry)
                logger.debug('Trying to read timesync file {}'.format(file_path))
                f = vfs.get_virtual_file(file_path, 'TimeSync').open()
                if f:
                    buffer = f.read() # should be a fairly small file!
                    ReadTimesyncFile(buffer, ts_list)
                    f.close()
            else:
                logger.error("In Timesync folder, found non-ts file {}".format(entry))
    except Exception:
        logger.exception('')
