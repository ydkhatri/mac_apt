# -*- coding: utf-8 -*-
'''The tracev3 file parser.'''

from __future__ import unicode_literals

import binascii
import biplist
import lz4.block
import ipaddress
import plistlib
import re
import struct
import sys
from uuid import UUID

import plugins.helpers.UnifiedLog.data_format as data_format
import plugins.helpers.UnifiedLog.dsc_file as dsc_file
import plugins.helpers.UnifiedLog.logger as logger
import plugins.helpers.UnifiedLog.resources as resources
import plugins.helpers.UnifiedLog.uuidtext_file as uuidtext_file


class TraceV3(data_format.BinaryDataFormat):
    '''Tracev3 file parser.'''

    def __init__(self, v_fs, v_file, ts_list, uuidtext_folder_path, large_data_cache, cached_files=None):
        '''
            Input params:
            v_fs    = VirtualFileSystem object for FS operations (listing dirs, opening files ,..)
            v_file  = VirtualFile object for .traceV3 file
            ts_list = List of TimeSync objects
            uuidtext_folder_path = Path to folder containing Uuidtext folders (and files)
            large_data_cache = Dictionary to store oversize data, 
                                key = ( data_ref_id << 64 | contTime ) , value = data 
            cached_files = CachedFiles object for dsc & uuidtext files (can be None)
        '''
        super(TraceV3, self).__init__()
        self._debug_log_count = 0
        self.vfs = v_fs
        self.file = v_file
        # Header info
        #self.header_unknown = 0
        self.header_data_length = 0   # 0xD0 Length of remaining header
        self.header_unknown1 = 0 # 1
        self.header_unknown2 = 0 # 1
        self.header_continuousTime = 0
        self.header_item_continuousTime = 0
        self.header_timestamp = 0 # HFS time 4 bytes
        self.header_unknown5 = 0 # 0
        self.header_unknown6 = 0
        self.header_bias_in_seconds = 0
        self.header_unknown8 = 0
        self.header_unknown9 = 0
        self.ts_list = ts_list
        self.cached_files = cached_files
        self.uuidtext_folder_path = uuidtext_folder_path
        self.dsc_folder_path = v_fs.path_join(uuidtext_folder_path, "dsc")
        self.other_uuidtext = {} # cacheing uuidtext files referenced individually
        self.regex_pattern = r"%(\{[^\}]{1,64}\})?([0-9. *\-+#']{0,6})([hljztLq]{0,2})([@dDiuUxXoOfeEgGcCsSpaAFP])"
        # Regex pattern looks for strings in this format:  % {..} flags width.precision modifier specifier
        #                                                     --   -------------------   ------   ------
        #   Groups                                            g1            g2              g3       g4
        #
        self.regex = re.compile(self.regex_pattern)
        # from header items
        self.system_boot_uuid = None
        self.large_data = large_data_cache # key = ( data_ref_id << 64 | contTime ) , value = data 
        self.boot_uuid_ts_list = None
        self.chunk_read_count = 0

    def _DecompressChunkData(self, chunk_data, data_len):
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
                    logger.error('Unknown compression value {} @ 0x{:X} - {}'.format(comp_header.hex(), begin_pos + comp_start, comp_header))
                    break
                comp_header = chunk_data[comp_start:comp_start + 4]
        else:
            logger.error('Unknown compression type {}'.format(chunk_data[16:20].hex()))
        return uncompressed

    # TODO: move this into a TimesyncList class.
    def _GetBootUuidTimeSyncList(self, ts_list, uuid):
        '''Retrieves the timesync for a specific boot identifier.

        Args:
            ts_list (list[Timesync]): timesync list.
            uuid (uuid): boot identifier.

        Returns:
          Timesync: timesync or None if not available.
        '''
        for ts in ts_list:
            if ts.header.boot_uuid == uuid:
                return ts.items
        logger.error("Could not find boot uuid {} in Timesync!".format(uuid))
        return None

    # TODO: move this into a TimesyncList class.
    def _FindClosestTimesyncItem(self, ts_list, uuid, continuousTime):
        '''Searches ts_list for the boot_id specified by uuid and time'''
        found_boot_id = False
        for ts in ts_list:
            if ts.header.boot_uuid == uuid:
                found_boot_id = True
                return self._FindClosestTimesyncItemInList(ts.items, continuousTime)

        if not found_boot_id:
            logger.error("Could not find boot uuid {} in Timesync!".format(uuid))
        return None

    # TODO: move this into a TimesyncList class.
    def _FindClosestTimesyncItemInList(self, ts_items, continuousTime):
        '''Returns the closest timesync item from the provided ts_items list'''
        if not ts_items:
            return None

        closest_tsi = ts_items[0]
        for item in ts_items:
            if item.continuousTime > continuousTime:
                break
            else: # must be <
                closest_tsi = item
        return closest_tsi

    def _Read_CLClientManagerStateTrackerState(self, data):
        ''' size=0x8 int, bool '''
        locationServicesEnabledStatus, locationRestricted = struct.unpack('<ii', data[0:8])
        return str( {"locationServicesEnabledStatus":locationServicesEnabledStatus, "locationRestricted":True if locationRestricted else False} )

    # _CLLocationManagerStateTrackerState
    # https://github.com/nst/iOS-Runtime-Headers/blob/fbb634c78269b0169efdead80955ba64eaaa2f21/Frameworks/CoreLocation.framework/CLLocationManagerStateTracker.h

    #def _Read_CLDaemonStatusStateTrackerState(self, data):
        ''' size=0x28 
            From classdump of locationd.nsxpc from:
            https://gist.github.com/razvand/578f94748b624f4d47c1533f5a02b095
            struct Battery {
                double level;
                _Bool charged;
                _Bool connected;
                int chargerType;
                _Bool wasConnected;
            };
            struct _CLDaemonStatusStateTrackerState {
                struct Battery batteryData;
                int reachability;
                int thermalLevel;
                _Bool airplaneMode;
                _Bool batterySaverModeEnabled;
                _Bool pushServiceConnected;
                _Bool restrictedMode;
            };
            Not sure how this is 0x28 bytes!
            Sample output:
            {"restrictedMode":false,
            "pushServiceConnected":false,
                "batteryData":{"wasConnected":false,"charged":false,"level":-1,"connected":false,"chargerType":"kChargerTypeUnknown"},
             "thermalLevel":-1,
             "batterySaverModeEnabled":false,
             "reachability":"kReachabilityLarge",
             "airplaneMode":false}
        '''

    def ParseChunkHeader(self, buffer, debug_file_pos):
        '''Returns tuple (tag, Subtag, DataLength)'''
        tag, subtag, data_length = struct.unpack("<IIQ", buffer)
        logger.debug("Chunk {} Tag=0x{:X} Subtag=0x{:X} Data_Length={} @ 0x{:X}".format(self.chunk_read_count, tag, subtag, data_length, debug_file_pos))
        self.chunk_read_count += 1
        return (tag, subtag, data_length)

    def ParseFileHeader(self, buffer, data_length):
        self.header_data_length = data_length
        self.header_unknown1, self.header_unknown2, self.header_continuousTime,\
        self.header_timestamp, self.header_unknown5, self.header_unknown6, self.header_bias_in_seconds,\
        self.header_unknown8, self.header_unknown9 = struct.unpack("<IIQiIIiII", buffer[0:40])
        # Read header items (Log configuration?)
        pos = 40
        while pos < data_length:
            item_id, item_length = struct.unpack("<II", buffer[pos:pos+8])
            pos += 8
            if item_id == 0x6100 :  # continuous time
                self.header_item_continuousTime = struct.unpack("<Q", buffer[pos:pos+item_length])[0]
            elif item_id == 0x6101: pass # machine hostname & model
            elif item_id == 0x6102: # uuid
                self.system_boot_uuid = UUID(bytes=buffer[pos:pos+16])
                self.boot_uuid_ts_list = self._GetBootUuidTimeSyncList(self.ts_list, self.system_boot_uuid)
                if self.boot_uuid_ts_list is None:
                    raise ValueError('Could not get Timesync for boot uuid! Cannot parse file..')
            elif item_id == 0x6103: # timezone string
                pass
            else:                   # not yet seen item
                logger.info('New header item seen, item_id=0x{:X}'.format(item_id))
            pos += item_length
        self.DebugPrintTimestampFromContTime(self.header_item_continuousTime, "File Header")

    def ProcessReferencedFile(self, uuid_string, catalog):
        '''Find, open and parse a file. Add the file object to catalog.FileObjects list'''
        # Try as dsc file, if missing, try as uuidtext, if missing, then treat as missing uuidtext
        try:
            if self.cached_files:
                dsc = self.cached_files.cached_dsc.get(uuid_string, None) # try as dsc
                if dsc:
                    catalog.FileObjects.append(dsc)
                    return
                else:
                    ut = self.cached_files.cached_uuidtext.get(uuid_string, None)
                    if ut:
                        catalog.FileObjects.append(ut)
                        return
            # Try as Dsc
            full_path = self.vfs.path_join(self.dsc_folder_path, uuid_string)
            if self.vfs.path_exists(full_path):
                dsc_path = self.vfs.get_virtual_file(full_path, 'Dsc')
                dsc = dsc_file.Dsc(dsc_path)
                dsc.Parse()
                catalog.FileObjects.append(dsc)
            else:
                # Try as uuidtext
                is_dsc = False
                full_path = self.vfs.path_join(self.uuidtext_folder_path, uuid_string[0:2], uuid_string[2:])
                file_object = self.vfs.get_virtual_file(full_path, 'Uuidtext')
                ut = uuidtext_file.Uuidtext(file_object, UUID(uuid_string))
                ut.Parse()
                catalog.FileObjects.append(ut)
        except:
            logger.exception('')

    def ProcessMetaChunk(self, chunk_data):
        '''Parses a catalog chunk data.

        The catalog chunk is a chunk with tag 0x600b.

        Args:
          chunk_data (bytes): catalog chunk data.

        Returns:
          Catalog: a catalog.

        Raises:
          struct.error: if the catalog chunk data cannot be parsed.
        '''
        catalog = resources.Catalog()

        (subsystem_strings_offset, proc_infos_offset, number_of_proc_infos,
         chunk_meta_offset, num_chunks_to_follow, self.ContinuousTime) = (
            struct.unpack('<HHHHQQ', chunk_data[0:24]))

        subsystem_strings_offset += 24
        proc_infos_offset += 24
        chunk_meta_offset += 24

        self.DebugPrintTimestampFromContTime(self.ContinuousTime, 'Catalog Chunk')

        data_offset = 24
        data_size = len(chunk_data)

        while data_offset < subsystem_strings_offset:
            end_data_offset = data_offset + 16

            file_path_data = chunk_data[data_offset:end_data_offset]
            data_offset = end_data_offset

            file_path = file_path_data.hex()
            file_path = file_path.upper()

            self.ProcessReferencedFile(file_path, catalog)

        catalog.Strings = chunk_data[data_offset:proc_infos_offset]
        data_offset = proc_infos_offset

        while data_offset < chunk_meta_offset:
            end_data_offset = data_offset + 40

            (id, flags, file_id, dsc_file_index, proc_id1, proc_id2, pid, euid,
             u6, num_extra_uuid_refs, u8) = struct.unpack(
                '<HHhhQIIIIII', chunk_data[data_offset:end_data_offset])
            data_offset = end_data_offset

            # UUID info entries are present if the process info references files.
            extra_file_refs = []

            uuid_infos_end_offset = data_offset + (16 * num_extra_uuid_refs)
            while data_offset < uuid_infos_end_offset:
                end_data_offset = data_offset + 16

                (ref_data_size, ref_u2, uuid_file_index, ref_v_offset,
                 ref_id) = struct.unpack(
                    '<IIhIh', chunk_data[data_offset:end_data_offset])
                data_offset = end_data_offset

                # sometimes uuid_file_index is -ve, 0xFF7F (-129)
                file_reference = resources.ExtraFileReference(
                    ref_data_size, uuid_file_index, ref_u2, ref_v_offset, ref_id)
                extra_file_refs.append(file_reference)

            end_data_offset = data_offset + 8

            num_subsys_cat_elements, u9 = struct.unpack(
                '<II', chunk_data[data_offset:end_data_offset])
            data_offset = end_data_offset

            proc_info = resources.ProcInfo(
                id, flags, file_id, dsc_file_index, proc_id1, proc_id2, pid,
                euid, u6, num_extra_uuid_refs, u8, num_subsys_cat_elements,
                u9, extra_file_refs)
            catalog.ProcInfos.append(proc_info)

            sub_systems_end_offset = data_offset + (6 * num_subsys_cat_elements)
            while data_offset < sub_systems_end_offset:
                end_data_offset = data_offset + 6

                item_id, subsystem_offset, category_offset = struct.unpack(
                    '<HHH', chunk_data[data_offset:end_data_offset])
                data_offset = end_data_offset

                subsystem_string = self._ReadCString(catalog.Strings[subsystem_offset:])
                category_string = self._ReadCString(catalog.Strings[category_offset:])
                proc_info.items[item_id] = (subsystem_string, category_string)

            # Skip 64-bit alignment padding.
            _, remainder = divmod(sub_systems_end_offset, 8)
            if remainder > 0:
              data_offset += 8 - remainder

        chunk_index = 0
        while data_offset < data_size:
            end_data_offset = data_offset + 24
            c_time_first, c_time_last, chunk_len, compression_alg = struct.unpack(
                '<QQII', chunk_data[data_offset:end_data_offset])
            data_offset = end_data_offset

            self.DebugPrintTimestampFromContTime(
                c_time_first, 'ChunkMeta {0:d} CTime First'.format(chunk_index))
            self.DebugPrintTimestampFromContTime(
                c_time_last, 'ChunkMeta {0:d} CTime Last'.format(chunk_index))

            chunk_meta = resources.ChunkMeta(c_time_first, c_time_last, chunk_len, compression_alg)
            catalog.ChunkMetaInfo.append(chunk_meta)

            end_data_offset = data_offset + 4
            num_proc_info_indexes = struct.unpack(
                '<I', chunk_data[data_offset:end_data_offset])[0]
            data_offset = end_data_offset

            end_data_offset = data_offset + (num_proc_info_indexes * 2)
            format_string = '<{0:d}H'.format(num_proc_info_indexes)
            chunk_meta.ProcInfo_Ids = struct.unpack(
                format_string, chunk_data[data_offset:end_data_offset])
            data_offset = end_data_offset

            for proc_info_id in chunk_meta.ProcInfo_Ids:
                # Find it in catalog.ProcInfos and insert ref in chunk_meta.ProcInfos
                #  ref is unique by using both proc_id1 and proc_id2 
                proc_info = catalog.GetProcInfoById(proc_info_id)
                if proc_info:    
                    chunk_meta.ProcInfos[ proc_info.proc_id2 | (proc_info.proc_id1 << 32) ] = proc_info

            end_data_offset = data_offset + 4
            num_string_indexes = struct.unpack(
                '<I', chunk_data[data_offset:end_data_offset])[0]
            data_offset = end_data_offset

            end_data_offset = data_offset + (num_string_indexes * 2)
            format_string = '<{0:d}H'.format(num_string_indexes)
            chunk_meta.StringIndexes = struct.unpack(
                format_string, chunk_data[data_offset:end_data_offset])
            data_offset = end_data_offset

            chunk_index += 1

            # Skip 64-bit alignment padding.
            _, remainder = divmod(end_data_offset, 8)
            if remainder > 0:
              data_offset += 8 - remainder

        return catalog

    def CreateLossMsg(self, ts, start_ct, ct_base, buffer, buf_size):
        '''Creates and returns the message body for log type LOSS'''
        if buf_size < 20:
            logger.error('Buffer too small to hold loss data! size={}, expected 20'.format(buf_size))
            msg = 'loss: <error reading this data>'
        else:
            msg = 'lost {}{} unreliable messages from {} - {}  (exact start-approx. end)'
            sign, end_ct_rel, count = struct.unpack('<IQI', buffer[0:16])
            end_ct = ct_base + end_ct_rel
            end_time = ts.time_stamp + end_ct - ts.continuousTime
            start_time = ts.time_stamp + start_ct - ts.continuousTime
            if sign == 1:
                sign == '>='
            elif sign == 4:
                sign = ''
            else:
                logger.info('Unseen sign value of {}'.format(sign))
                sign = ''
            try:
                msg = msg.format(sign, count, self._ReadAPFSTime(start_time), self._ReadAPFSTime(end_time))
            except ValueError:
                logger.exception('')
        return msg

    def ReadLogDataBuffer2(self, buffer, buf_size, strings_buffer):
        '''
            Reads log data when data descriptors are at end of buffer
            Returns a list of items read
        '''
        data = []
        descriptors = []
        if buf_size == 0:
            return data
        
        total_items = struct.unpack('<B', buffer[-1:])[0]
        pos = buf_size - 1
        if buf_size == 1:
            if total_items != 0:
                logger.error('Unknown data found in log data buffer')
            return data
        
        items_read = 0
        pos -= total_items
        while items_read < total_items:
            if pos <= 0:
                break
                logger.error('Error, no place for data!')
            item_size = struct.unpack('<B', buffer[pos : pos + 1])[0]
            descriptors.append(item_size)
            items_read += 1
            pos += 1
        items_read = 0
        pos = 0
        while items_read < total_items:
            size = descriptors[items_read]
            item_data = buffer[pos : pos + size]
            data.append( [0, size, item_data] )
            pos += size
            items_read += 1
        
        return data

    def ReadLogDataBuffer(self, buffer, buf_size, strings_buffer):
        '''Returns a list of items read as [ type, size, raw_value_binary_string ]'''
        data = []
        data_descriptors=[] # [ (data_index, offset, size, data_type), .. ]
        
        unknown, total_items = struct.unpack('<BB', buffer[0:2])
        pos = 2
        pos_debug = 0
        items_read = 0
        while items_read < total_items:
            if pos >= buf_size:
                logger.error('Trying to read past buffer size!')
                break
            item_type, item_size = struct.unpack('<BB', buffer[pos:pos+2])
            pos += 2
            # item_type & 1 == 1, then 'private' flag is ON ?
            # item_type & 2 == 1, then '{public}' is in fmt_string
            if item_type in (0, 1): # number
                data.append([item_type, item_size, buffer[pos:pos+item_size]])
            elif item_type == 2: # %p (printed as hex with 0x prefix)
                data.append([item_type, item_size, buffer[pos:pos+item_size]])
            elif item_type in (0x20, 0x21, 0x22, 0x40, 0x41, 0x42, 0x31, 0x32): # string descriptor 0x22={public}%s 0x4x shows as %@ (if size=0, then '(null)') 
                # byte 0xAB A=type(0=num,1=len??,2=string in stringsbuf,4=object)  B=style (0=normal,1=private,2={public})
                # 0x3- is for %.*P object types
                offset, size = struct.unpack('<HH', buffer[pos:pos+4])
                data_descriptors.append( (len(data), offset, size, item_type) )
                data.append('')
            elif item_type & 0xF0 == 0x10: #0x10, 0x12 seen # Item length only, this is usually followed by 0x31 or 0x32 item_type. If length is 0, then only 0x31 is seen.
                # Seen in strings where predicate specifies string length Eg: %.4s
                if item_size != 4:
                    logger.warning('Log data Item Length was 0x{:X} instead of 0x4. item_type=0x{:X}'.format(item_size, item_type))
                size = struct.unpack('<I', buffer[pos:pos+4])
                # Not using this information anywhere as it seems redundant!
            else:
                logger.warning('item_type unknown (0x{:X})'.format(item_type))
                data.append([item_type, item_size, buffer[pos:pos+item_size]])
            if item_size == 0:
                logger.warning('item_size was zero!')
                break
            pos += item_size
            items_read += 1
        # Below code is unused for now. Skipping reading the backtrace
        # if has_context_data: # there will be context data next, then the data
        #     ctx_unk1, ctx_unk2, ctx_unk3, ctx_unique_uuid_count, ctx_total_count = struct.unpack('<BBBBH', buffer[pos:pos+6])
        #     pos += 6
        #     uuids = []
        #     offsets = []
        #     context_data = [] # [ (uuid, offset), (..), ..]
        #     for x in range(ctx_unique_uuid_count):
        #         uuid = binascii.hexlify(buffer[pos:pos+16]).upper()
        #         #uuid = buffer[pos:pos+16].hex().upper() # for py 3
        #         uuids.append(uuid)
        #         pos += 16
        #     for x in range(ctx_total_count):
        #         off = struct.unpack('<I', buffer[pos:pos+4])[0]
        #         offsets.append(off)
        #         pos += 4
        #     for x in range(ctx_total_count):
        #         uuid_index = struct.unpack('<B', buffer[pos:pos+1])[0]
        #         if uuid_index >= ctx_unique_uuid_count:
        #             log.error('something went wrong')
        #             break
        #         pos += 1
        #         context_data.append( (uuids[uuid_index], offsets[x]) )
                
        pos_debug = pos
        if data_descriptors:
            for desc in data_descriptors:
                data_index, offset, size, data_type = desc
                if data_type == 0x21:
                    data[data_index] = [data_type, size, strings_buffer[offset : offset + size] if size else '<private>' ]
                elif data_type == 0x40:
                    data[data_index] = [data_type, size, buffer[pos + offset : pos + offset + size] if size else '(null)' ]
                    pos_debug += size
                elif data_type == 0x41: #Is this also a ref to something else at times??
                    data[data_index] = [data_type, size, strings_buffer[offset : offset + size] if size else '<private>' ]
                    pos_debug += size
                else:
                    data[data_index] = [data_type, size, buffer[pos + offset : pos + offset + size] ]
                    pos_debug += size
        #if (total_items > 0) or (buf_size > 2):
        #    pass #logger.debug(hex(unknown) + " ** " + str(data))
        #unused buffer
        #if pos_debug < buf_size:
        #    pass #logger.debug("Extra Data bytes ({}) @ {} ".format(buf_size-pos_debug, pos_debug) + " ## " + binascii.hexlify(buffer[pos_debug:]).decode('ascii').upper())
        return data

    def RecreateMsgFromFmtStringAndData(self, format_str, data, log_file_pos):
        msg = ''
        format_str_for_regex = format_str.replace('%%', '~') # %% is to be considered literal % but will interfere with our regex, so replace it
        format_str = format_str.replace('%%', '%')           # %% replaced with % in original. Since we aren't tokenizing, we use this hack
        len_format_str = len(format_str)
        data_count = len(data)
        format_str_consumed = 0 # No. of bytes read
        last_hit_end = 0
        index = 0
        for hit in self.regex.finditer(format_str_for_regex):
            #logger.debug('{} {} all={}  {}  {} {} {}'.format(hit.start(), hit.end(), hit.group(0), hit.group(1), hit.group(2), hit.group(3), hit.group(4)))
            hit_len = hit.end() - hit.start()
            last_hit_end = hit.end()
            msg += format_str[format_str_consumed : hit.start()] # slice from end of last hit to begin of new hit
            format_str_consumed = last_hit_end
            # Now add data from this hit
            if index >= data_count: # len(data):
                msg += '<decode: missing data>' # Message provided by 'log' program for missing data
                logger.error('missing data for log @ 0x{:X}'.format(log_file_pos))
                break
            data_item = data[index]
            # msg += data from this hit
            # data_item = [type, size, raw_data]
            try:
                custom_specifier = hit.group(1)
                flags_width_precision = hit.group(2).replace('\'', '')
                length_modifier = hit.group(3)
                specifier = hit.group(4)
                data_type = data_item[0]
                data_size = data_item[1]
                raw_data  = data_item[2]
                if (specifier not in ('p', 'P', 's', 'S')) and (flags_width_precision.find('*') >= 0): # Width and/or precision is now a variable!
                    logger.debug('Found * , data_type is {}, exp={} for log @ 0x{:X}'.format(data_type, flags_width_precision + specifier, log_file_pos))
                    var_count = flags_width_precision.count('*')
                    for i in range(0, var_count):
                        if   data_size == 1: number = struct.unpack("<b", raw_data)[0]
                        elif data_size == 4: number = struct.unpack("<i", raw_data)[0]
                        elif data_size == 8: number = struct.unpack("<q", raw_data)[0]
                        else: 
                            logger.error('data_size is {} for log @ 0x{:X}'.format(data_size, log_file_pos))
                        flags_width_precision = flags_width_precision.replace('*', str(number), 1)
                        # fetch next item as data was consumed by width/precision
                        index += 1
                        data_item = data[index]
                        data_type = data_item[0]
                        data_size = data_item[1]
                        raw_data  = data_item[2]

                ## In below code , length_modifier has been removed from format string, let python string formatter handle rest
                ## It has the same format, except for flags, where single-qoute is not supported in python.
                if specifier in ('d', 'D', 'i', 'u', 'U', 'x', 'X', 'o', 'O'): # uint32 according to spec! but can be 4 or 8 bytes
                    number = 0
                    if data_size == 0: # size
                        if data_type & 0x1:
                            msg += '<private>'
                        else:
                            logger.error('unknown err, size=0, data_type=0x{:X}'.format(data_type))
                    else: # size should be 4 or 8
                        if specifier in ('d', 'D'): # signed int32 or int64
                            specifier = 'd'  # Python does not support 'D'
                            if   data_size == 1: number = struct.unpack("<b", raw_data)[0]
                            elif data_size == 4: number = struct.unpack("<i", raw_data)[0]
                            elif data_size == 8: number = struct.unpack("<q", raw_data)[0]
                            else: logger.error('Unknown length ({}) for number '.format(data_size))
                        else:
                            if   data_size == 1: number = struct.unpack("<B", raw_data)[0]
                            elif data_size == 4: number = struct.unpack("<I", raw_data)[0]
                            elif data_size == 8: number = struct.unpack("<Q", raw_data)[0]
                            else: logger.error('Unknown length ({}) for number '.format(data_size))
                            if   specifier == 'U': specifier = 'u'  # Python does not support 'U'
                            elif specifier == 'O': specifier = 'o'  # Python does not support 'O'
                        msg += ('%'+ flags_width_precision + specifier) % number
                elif specifier in ('f', 'e', 'E', 'g', 'G', 'a', 'A', 'F'): # double 64 bit (or 32 bit float if 'lf')
                    number = 0
                    if data_size == 0: # size
                        if data_type & 0x1:
                            msg += '<private>'
                        else:
                            logger.error('unknown err, size=0, data_type=0x{:X}'.format(data_type))
                    else:
                        if   data_size == 8: number = struct.unpack("<d", raw_data)[0]
                        elif data_size == 4: number = struct.unpack("<f", raw_data)[0]
                        else: logger.error('Unknown length ({}) for float/double '.format(data_size))
                        msg += ('%'+ flags_width_precision + specifier) % number
                elif specifier in ('c', 'C', 's', 'S', '@'):  # c is Single char but stored as 4 bytes
                    # %C & %S are unicode char, but everything in log file would be encoded as utf8, so should be the same
                    # %@ is a utf8 representation of object
                    chars = ''
                    if data_size == 0:
                        if data_type == 0x40:
                            chars = '(null)'
                        elif data_type & 0x1:
                            chars = '<private>'
                    else:
                        try:
                            chars = raw_data.decode('utf8').rstrip('\x00') # , 'backslashreplace'
                        except UnicodeDecodeError as ex:
                            logger.error('Error decoding utf8 in log @ 0x{:X}, data was "{}", error was {}'.format(log_file_pos, raw_data.hex(), str(ex)))
                            chars = ''
                        chars = ('%'+ (flags_width_precision if flags_width_precision.find('*')==-1 else '')  + "s") % chars # Python does not like '%.*s'
                    msg += chars
                elif specifier == 'P':  # Pointer to data of different types!
                    if not custom_specifier:
                        msg += hit.group(0)
                        logger.info("Unknown data object with no custom specifier in log @ 0x{:X}".format(log_file_pos))
                        index += 1
                        continue
                    if data_size == 0:
                        if data_type & 0x1:
                            msg += '<private>'
                        index += 1
                        continue

                    if custom_specifier.find('uuid_t') > 0:
                        if data_size == 0: # size
                            logger.error('unknown err, size=0, data_type=0x{:X} in log @ 0x{:X}'.format(data_type, log_file_pos))
                        else:
                            uuid = UUID(bytes=raw_data)
                            msg += str(uuid).upper()
                    elif custom_specifier.find('odtypes:mbr_details') > 0:
                        unk = raw_data[0]
                        if unk == 'D': # 0x44
                            group, pos = self._ReadCStringAndEndPos(raw_data[1:], len(raw_data))
                            pos += 2
                            domain = self._ReadCString(raw_data[pos:], len(raw_data) - pos)
                            msg += 'group: {}@{}'.format(group, domain)
                        elif unk == '#': #0x23
                            uid = struct.unpack("<I", raw_data[1:5])[0]
                            domain = self._ReadCString(raw_data[5:], len(raw_data) - 5)
                            msg += 'user: {}@{}'.format(uid, domain)
                        else:
                            logger.error("Unknown value for mbr_details found 0x{} in log @ 0x{:X}".format(unk.encode('hex'), log_file_pos))
                    elif custom_specifier.find('odtypes:nt_sid_t') > 0:
                        msg += self._ReadNtSid(raw_data)
                    elif custom_specifier.find('location:SqliteResult') > 0:
                        number = struct.unpack("<I", raw_data)[0]
                        if number >= 0 and number <=28:
                            error_codes = [ 'SQLITE_OK','SQLITE_ERROR','SQLITE_INTERNAL','SQLITE_PERM','SQLITE_ABORT','SQLITE_BUSY',
                                            'SQLITE_LOCKED','SQLITE_NOMEM','SQLITE_READONLY','SQLITE_INTERRUPT','SQLITE_IOERR',
                                            'SQLITE_CORRUPT','SQLITE_NOTFOUND','SQLITE_FULL','SQLITE_CANTOPEN','SQLITE_PROTOCOL',
                                            'SQLITE_EMPTY','SQLITE_SCHEMA','SQLITE_TOOBIG','SQLITE_CONSTRAINT','SQLITE_MISMATCH',
                                            'SQLITE_MISUSE','SQLITE_NOLFS','SQLITE_AUTH','SQLITE_FORMAT','SQLITE_RANGE',
                                            'SQLITE_NOTADB','SQLITE_NOTICE','SQLITE_WARNING']
                            msg += error_codes[number]
                        elif number == 100: msg += 'SQLITE_ROW'
                        elif number == 101: msg += 'SQLITE_DONE'
                        else:
                            msg += str(number) + " - unknown sqlite result code"
                            #https://www.sqlite.org/c3ref/c_abort.html sqlite result codes
                    elif custom_specifier.find('network:sockaddr') > 0:
                        size, family = struct.unpack("<BB", raw_data[0:2])
                        if family == 0x1E: # AF_INET6 ipv6
                            port, flowinfo = struct.unpack("<HI", raw_data[2:8])
                            ipv6 = struct.unpack(">8H", raw_data[8:24])
                            ipv6_str = u'{:X}:{:X}:{:X}:{:X}:{:X}:{:X}:{:X}:{:X}'.format(ipv6[0],ipv6[1],ipv6[2],ipv6[3],ipv6[4],ipv6[5],ipv6[6],ipv6[7])#must be unicode
                            msg += ipaddress.ip_address(ipv6_str).compressed
                        elif family == 0x02: # AF_INET ipv4
                            port = struct.unpack("<H", raw_data[2:4])
                            ipv4 = struct.unpack("<BBBB", raw_data[4:8])
                            ipv4_str = '{}.{}.{}.{}'.format(ipv4[0],ipv4[1],ipv4[2],ipv4[3])
                            msg += ipv4_str # TODO- test this, not seen yet!
                        else:
                            logger.error("Unknown sock family value 0x{:X} in log @ 0x{:X}".format(family, log_file_pos))
                    # elif custom_specifier.find('_CLDaemonStatusStateTrackerState') > 0:
                    #     msg += Read_CLDaemonStatusStateTrackerState(raw_data)
                    elif custom_specifier.find('_CLClientManagerStateTrackerState') > 0:
                        msg += self._Read_CLClientManagerStateTrackerState(raw_data)
                    else:
                        msg += hit.group(0)
                        logger.info("Unknown custom data object type '{}' data size=0x{:X} in log @ 0x{:X}".format(custom_specifier, len(raw_data), log_file_pos))
                        pass #TODO
                elif specifier == 'p':  # Should be 8bytes to be displayed as uint 32/64 in hex lowercase no leading zeroes
                    number = ''
                    if data_size == 0: # size
                        if data_type & 0x1:
                            msg += '<private>'
                        else:
                            logger.error('unknown err, size=0, data_type=0x{:X} in log @ 0x{:X}'.format(data_type, log_file_pos))
                    else: # size should be 8 or 4
                        if   data_size == 8: number = struct.unpack("<Q", raw_data)[0]
                        elif data_size == 4: number = struct.unpack("<I", raw_data)[0]
                        else: logger.error('Unknown length ({}) for number in log @ 0x{:X}'.format(data_size, log_file_pos))
                        msg += '0x' + ('%' + flags_width_precision + 'x') % number
            except:
                logger.exception('exception for log @ 0x{:X}'.format(log_file_pos))
                msg += "E-R-R-O-R"
            index += 1

        if format_str_consumed < len_format_str:
            # copy remaining bytes from end of last hit to end of strings
            msg += format_str[last_hit_end:]
        elif format_str_consumed > len_format_str:
            logger.error('format_str_consumed ({}) > len_format_str ({})'.format(format_str_consumed, len_format_str))

        return msg

    def DebugPrintLog(self, file_pos, cont_time, timestamp, thread, level_type, activity, pid, euid, ttl, p_name, lib, sub_sys, cat, msg, signpost):
        time_string = self._ReadAPFSTime(timestamp)
        logger.debug('{} (0x{:X}) {} ({}) 0x{:X} {} 0x{:X} {} {} '.format(
            self._debug_log_count, file_pos, time_string, cont_time, thread,
            level_type, activity, pid, euid, ttl, p_name) + \
                    ( '[{}] '.format(signpost) if signpost else '') + \
                      '{}: '.format(p_name) + \
                    ( '({}) '.format(lib) if lib else '') + \
                    ( '[{}:{}] '.format(sub_sys, cat) if sub_sys else '') + \
                    msg
                 )

    def DebugPrintTimestampFromContTime(self, ct, msg=''):
        '''Given a continuous time value, print its human readable form'''
        ts = self._FindClosestTimesyncItemInList(self.boot_uuid_ts_list, ct)
        time_string = 'N/A'
        if ts is not None:
            time = ts.time_stamp + ct - ts.continuousTime
            time_string = self._ReadAPFSTime(time)
        logger.debug("{} timestamp={}".format(msg, time_string))

    def DebugCheckLogLengthRemaining(self, log_length, bytes_needed, log_abs_offset):
        '''Checks if we have enough space for extracting more elements'''
        if log_length < bytes_needed:
            logger.error('Log data length (0x{:X}) < {} for log @ 0x{:X}!'.format(log_length, bytes_needed, log_abs_offset))
            raise ValueError('Not enough data in log data buffer!')

    def ProcessDataChunk(self, buffer, catalog, meta_chunk_index, debug_file_pos, logs):
        '''Read chunks with flag 0x600D'''
        global debug_log_count
        len_buffer = len(buffer)
        pos = 0
        chunk_meta = catalog.ChunkMetaInfo[meta_chunk_index]
        while (pos + 16) < len_buffer:
            tag, subtag, data_size = self.ParseChunkHeader(buffer[pos:pos+16], debug_file_pos + pos)
            pos += 16
            start_skew = pos % 8 # calculate deviation from 8-byte boundary for padding later
            proc_id1, proc_id2, ttl = struct.unpack('QII', buffer[pos:pos+16]) # ttl is not for type 6001, it means something else there!
            pos2 = 16
            proc_info = self.GetProcInfo(proc_id1, proc_id2, chunk_meta)
            log_file_pos = debug_file_pos + pos + pos2 - 32
            if not proc_info: # Error checking and skipping that chunk entry, so we can parse the rest
                logger.error('Could not get proc_info, skipping log @ 0x{:X}'.format(log_file_pos))
                pos += data_size
                if ((pos - start_skew) % 8):
                    # sometimes no padding after privatedata. Try to detect null byte, if so pad it.
                    if (pos+1 < len_buffer) and (buffer[pos:pos+1] == b'\x00'): 
                        pad_len = 8 - ((pos - start_skew) % 8)
                        pos += pad_len
                    else:
                        logger.warning('Avoided padding for log ending @ 0x{:X}'.format(debug_file_pos + pos))
            pid = proc_info.pid
            euid = proc_info.euid
            if tag == 0x6001: #Firehose
                offset_strings, strings_v_offset, unknown4, unknown5, continuousTime \
                  = struct.unpack('<HHHHQ', buffer[pos + pos2 : pos + pos2 + 16])
                pos2 = 32
                if strings_v_offset < 4096: #data_size - offset_strings > 0x10: # Has strings
                    size_priv_data = 4096 - strings_v_offset
                    private_strings = buffer[pos + data_size - size_priv_data : pos + data_size]
                else:
                    private_strings = ''

                num_logs_debug = 0

                ts = self._FindClosestTimesyncItemInList(self.boot_uuid_ts_list, continuousTime)
                self.DebugPrintTimestampFromContTime(continuousTime, "Type 6001")
                
                logs_end_offset = offset_strings + 16
                while pos2 < logs_end_offset:
                    # Log item 
                    log_start_pos = pos + pos2
                    start_skew = pos2 % 8
                    u1, u2, fmt_str_v_offset, thread, ct_rel, ct_rel_upper, log_data_len = struct.unpack('<HHIQIHH', buffer[pos + pos2 : pos + pos2 + 24])
                    pos2 += 24
                    
                    ct = continuousTime + (ct_rel | (ct_rel_upper << 32))
                    # processing
                    log_file_pos = debug_file_pos + pos + pos2 - 24
                    #logger.debug('log_file_pos=0x{:X}'.format(log_file_pos))

                    ts = self._FindClosestTimesyncItemInList(self.boot_uuid_ts_list, ct)
                    time = ts.time_stamp + ct - ts.continuousTime
                    #logger.debug("Type 6001 LOG timestamp={}".format(self._ReadAPFSTime(time)))
                    try: # Big Exception block for any log uncaught exception
                        dsc_cache = catalog.FileObjects[proc_info.dsc_file_index] if (proc_info.dsc_file_index != -1) else None
                        ut_cache = catalog.FileObjects[proc_info.uuid_file_index]
                        p_name = ut_cache.library_name

                        senderImagePath = '' # Can be same as processImagePath
                        processImagePath = ut_cache.library_path
                        imageOffset = 0  # Same as senderProgramCounter
                        imageUUID = ''   # Same as senderImageUUID
                        processImageUUID = ut_cache.Uuid # Can be same as imageUUID
                        parentActivityIdentifier = 0

                        ut = None
                        format_str = ''
                        lib = '' # same as senderImage?
                        priv_str_len = 0      # when has_private_data
                        priv_str_v_offset = 0 # when has_private_data
                        sub_sys = ''
                        cat = ''
                        ttl = 0
                        act_id = [0]
                        has_msg_in_uuidtext = False # main_exe     [apple]
                        has_ttl = False             # has_rules    [apple]
                        has_act_id = False
                        has_subsys = False
                        has_alternate_uuid = False  # absolute     [apple]
                        has_msg_in_dsc = False      # shared_cache [apple]
                        has_other_act_id = False
                        has_unique_pid = False
                        has_private_data = False
                        has_sp_name = False
                        has_data_ref = False
                        has_activity_unk = False # unknown flag
                        is_activity = False
                        log_type = 'Default'
                        u1_upper_byte = (u1 >> 8)
                        is_signpost = False
                        signpost_string = 'spid 0x%x,'
                        signpost_name =''
                        if u1_upper_byte & 0x80: # signpost (Default)
                            is_signpost = True
                            if u1_upper_byte & 0xC0 == 0xC0: signpost_string += ' system,'  # signpostScope
                            else:                            signpost_string += ' process,' # signpostScope
                            if u1_upper_byte & 0x82 == 0x82: signpost_string += ' end'      # signpostType
                            elif u1_upper_byte & 0x81 == 0x81: signpost_string += ' begin'
                            else:                            signpost_string += ' event'
                        elif u1_upper_byte == 0x01:
                            log_type = 'Info'
                            if (u1 & 0x0F) == 0x02:
                                log_type ='Activity'
                                is_activity = True
                        elif u1_upper_byte == 0x02: log_type = 'Debug'
                        elif u1_upper_byte == 0x10: log_type = 'Error'
                        elif u1_upper_byte == 0x11: log_type = 'Fault'
                        elif u1 == 7: log_type = 'Loss' # New

                        if u2 & 0x7000:
                            logger.info('Unknown flag for u2 encountered u2=0x{:4X} @ 0x{:X} ct={}'.format(u2, log_file_pos, ct))
                            #raise ValueError('Unk u2 flag')
                        if u2 & 0x8000: has_sp_name = True

                        if u2 & 0x0800: has_data_ref = True
                        if u2 & 0x0400: has_ttl = True
                        if u2 & 0x0200: has_subsys = True if (not is_activity) else False 
                        if u2 & 0x0200: has_other_act_id = True if is_activity else False
                        if u2 & 0x0100: has_private_data = True if (not is_activity) else False
                        if u2 & 0x0100: has_activity_unk = True if is_activity else False

                        if u2 & 0x00E0: # E=1110
                            logger.info('Unknown flag for u2 encountered u2=0x{:4X} @ 0x{:X} ct={}'.format(u2, log_file_pos, ct))
                            #raise ValueError('Unk u2 flag')
                        if u2 & 0x0010: has_unique_pid = True

                        if u2 & 0x0008: has_alternate_uuid = True
                        if u2 & 0x0004: has_msg_in_dsc = True
                        if u2 & 0x0002: has_msg_in_uuidtext = True
                        if u2 & 0x0001: has_act_id = True

                        log_data_len2 = log_data_len
                        pos3 = pos2
                        if is_activity: # cur_aid [apple]
                            u5, u6 = struct.unpack('<II', buffer[pos + pos3 : pos + pos3 + 8]) # check for activity
                            if u6 == 0x80000000:
                                act_id.append(u5)
                                pos3 += 8
                                log_data_len2 -= 8
                            else:
                                logger.error('Expected activityID, got something else!')
                            if has_unique_pid:
                                proc_id = struct.unpack('<Q', buffer[pos + pos3 : pos + pos3 + 8])[0]
                                pos3 += 8
                                log_data_len2 -= 8
                            if has_act_id: # another act_id # new_aid [apple]
                                u5, u6 = struct.unpack('<II', buffer[pos + pos3 : pos + pos3 + 8])
                                if u6 == 0x80000000:
                                    act_id.append(u5)
                                    pos3 += 8
                                    log_data_len2 -= 8
                                else:
                                    logger.error('Expected activityID, got something else!')
                            if has_other_act_id: # yet another act_id # other_aid [apple]
                                u5, u6 = struct.unpack('<II', buffer[pos + pos3 : pos + pos3 + 8])
                                if u6 == 0x80000000:
                                    act_id.append(u5)
                                    pos3 += 8
                                    log_data_len2 -= 8
                                else:
                                    logger.error('Expected activityID, got something else!')
                        else:
                            if has_act_id:
                                u5, u6 = struct.unpack('<II', buffer[pos + pos3 : pos + pos3 + 8])
                                if u6 == 0x80000000:
                                    act_id.append(u5)
                                    pos3 += 8
                                    log_data_len2 -= 8
                                else:
                                    logger.error('Expected activityID, got something else!')

                        if has_private_data:
                            if private_strings:    
                                priv_str_v_offset, priv_str_len = struct.unpack('<HH', buffer[pos + pos3 : pos + pos3 + 4])
                                pos3 += 4
                                log_data_len2 -= 4
                            else:
                                logger.error('Did not read priv_str_v_offset as no private_strings are present @ log 0x{:X}! is_activity={}'.format(log_file_pos, bool(is_activity)))

                        u5 = struct.unpack('<I', buffer[pos + pos3 : pos + pos3 + 4])[0]
                        pos3 += 4
                        log_data_len2 -= 4

                        if has_alternate_uuid:
                            if not has_msg_in_uuidtext: # Then 2 bytes (uuid_file_index) instead of UUID
                                uuid_file_id = struct.unpack('<h', buffer[pos + pos3 : pos + pos3 + 2])[0]
                                pos3 += 2
                                log_data_len2 -= 2
                                uuid_found = False
                                for extra_ref in proc_info.extra_file_refs:
                                    if (extra_ref.id == uuid_file_id) and \
                                    ( (u5 >= extra_ref.v_offset) and ( (u5-extra_ref.v_offset) < extra_ref.data_size) ):  # found it
                                        ut = catalog.FileObjects[extra_ref.uuid_file_index]
                                        format_str = ut.ReadFmtStringFromVirtualOffset(fmt_str_v_offset)
                                        imageUUID = ut.Uuid
                                        senderImagePath = ut.library_path
                                        imageOffset = u5 - extra_ref.v_offset
                                        uuid_found = True
                                        break
                                if not uuid_found:
                                    logger.error('no uuid found for absolute pc - uuid_file_id was {} u5=0x{:X} fmt_str_v_offset=0x{:X} @ 0x{:X} ct={}'.format(uuid_file_id, u5, fmt_str_v_offset, log_file_pos, ct))
                                    format_str = '<compose failure [missing precomposed log]>' # error message from log utility
                            else:             # UUID
                                file_path = buffer[pos + pos3 : pos + pos3 + 16].hex().upper()
                                pos3 += 16
                                log_data_len2 -= 16
                                ## try to get format_str and lib from uuidtext file
                                ut = None
                                # search in existing files, likely will not find it here!
                                for obj in catalog.FileObjects:
                                    if obj._file.filename == file_path:
                                        ut = obj
                                        break
                                if not ut: # search in other_uuidtext, as we may have seen this earlier
                                    ut = self.other_uuidtext.get(file_path, None)
                                if not ut: # Not found, so open and parse new file
                                    uuidtext_full_path = self.vfs.path_join(self.uuidtext_folder_path, file_path[0:2], file_path[2:])
                                    file_object = self.vfs.get_virtual_file(uuidtext_full_path, 'Uuidtext')
                                    ut = uuidtext_file.Uuidtext(file_object, UUID(file_path))
                                    self.other_uuidtext[file_path] = ut # Add to other_uuidtext, so we don't have to parse it again
                                    if not ut.Parse():
                                        ut = None
                                        logger.error('Error parsing uuidtext file {} @ 0x{:X} ct={}'.format(uuidtext_full_path, log_file_pos, ct))
                                if ut:
                                    format_str = ut.ReadFmtStringFromVirtualOffset(fmt_str_v_offset)
                                    p_name = ut_cache.library_name
                                    lib = ut.library_name
                                    imageUUID = ut.Uuid
                                    senderImagePath = ut.library_path
                                else:
                                    logger.debug("Could not read from uuidtext {} @ 0x{:X} ct={}".format(file_path, log_file_pos, ct))

                        if not is_activity:
                            if has_subsys:
                                item_id = struct.unpack('<H', buffer[pos + pos3 : pos + pos3 + 2])[0]
                                pos3 += 2
                                log_data_len2 -= 2
                                sub_sys, cat = proc_info.GetSubSystemAndCategory(item_id)
                            
                            if has_ttl:
                                ttl = struct.unpack('<B', buffer[pos + pos3 : pos + pos3 + 1])[0]
                                pos3 += 1
                                log_data_len2 -= 1

                            if has_data_ref: #This is a ref to an object stored as type 0x0602 blob
                                data_ref_id = struct.unpack('<H', buffer[pos + pos3 : pos + pos3 + 2])[0]
                                pos3 += 2
                                log_data_len2 -= 2
                                logger.debug('Data reference ID = {:4X}'.format(data_ref_id))

                            if is_signpost:
                                spid_val = struct.unpack('<Q', buffer[pos + pos3 : pos + pos3 + 8])[0]
                                pos3 += 8
                                log_data_len2 -= 8
                                signpost_string = signpost_string % (spid_val)

                            if has_sp_name:
                                sp_name_ref = struct.unpack('<I', buffer[pos + pos3 : pos + pos3 + 4])[0]
                                pos3 += 4
                                log_data_len2 -= 4

                        # Get format_str and lib now
                        if has_msg_in_uuidtext: # u2 & 0x0002: # msg string in uuidtext file
                            imageOffset = u5
                            if has_alternate_uuid: # another uuidtext file was specified, already read that above
                                if has_sp_name:
                                    signpost_name = ut.ReadFmtStringFromVirtualOffset(sp_name_ref)
                            else:
                                imageUUID = ut_cache.Uuid
                                senderImagePath = ut_cache.library_path
                                format_str = ut_cache.ReadFmtStringFromVirtualOffset(fmt_str_v_offset)
                                if has_sp_name:
                                    signpost_name = ut_cache.ReadFmtStringFromVirtualOffset(sp_name_ref)
                        elif has_msg_in_dsc: # u2 & 0x0004: # msg string in dsc file
                            if has_sp_name:
                                try:
                                    signpost_name, c_a, c_b = dsc_cache.ReadFmtStringAndEntriesFromVirtualOffset(sp_name_ref)
                                except (KeyError, OSError):
                                    logger.error("Could not get signpost name! @ 0x{:X} ct={}".format(log_file_pos, ct))

                            cache_b1 = dsc_cache.GetUuidEntryFromVirtualOffset(u5)
                            if cache_b1:
                                lib = cache_b1[4] # senderimage_name
                                imageUUID = cache_b1[2]
                                senderImagePath = cache_b1[3]
                                imageOffset = u5 - cache_b1[0]

                            try:
                                if fmt_str_v_offset & 0x80000000: # check for highest bit
                                    format_str = "%s"
                                    logger.debug("fmt_str_v_offset highest bit set @ 0x{:X} ct={}".format(log_file_pos, ct))
                                else:
                                    format_str, cache_a, cache_b = dsc_cache.ReadFmtStringAndEntriesFromVirtualOffset(fmt_str_v_offset)
                            except (KeyError, OSError):
                                logger.error('Failed to get DSC msg string @ 0x{:X} ct={}'.format(log_file_pos, ct))

                        elif has_alternate_uuid: pass #u2 & 0x0008: # Parsed above
                        elif u1 == 7: # Loss
                            pass
                        else:
                            logger.warning("No message string flags! @ 0x{:X} ct={}".format(log_file_pos, ct))

                        if log_data_len2:
                            strings_slice = ''
                            if has_private_data:
                                if private_strings:
                                    strings_start_offset = 0
                                    strings_len = len(private_strings)
                                    strings_start_offset = priv_str_v_offset - strings_v_offset
                                    if (strings_start_offset > len(private_strings)) or (strings_start_offset < 0):
                                        logger.error('Error calculating strings virtual offset @ 0x{:X} ct={}'.format(log_file_pos, ct))
                                    strings_slice = private_strings[strings_start_offset : strings_start_offset + priv_str_len]
                                else:
                                    logger.error('Flag has_private_data but no strings present! @ 0x{:X} ct={}'.format(log_file_pos, ct))
                            else:
                                strings_slice = ''
                            if u1 & 0x7 == 0x7: pass #Loss
                            elif u1 & 0x3 == 0x3: # data_descriptor_at_buffer_end
                                log_data = self.ReadLogDataBuffer2(buffer[pos + pos3 : pos + pos3 + log_data_len2], log_data_len2, strings_slice)
                            else:
                                log_data = self.ReadLogDataBuffer(buffer[pos + pos3 : pos + pos3 + log_data_len2], log_data_len2, strings_slice)
                        else:
                            log_data = None
                        if has_data_ref:
                            unique_ref = data_ref_id << 64 | ct
                            log_data = self.large_data.get(unique_ref, None)
                            if log_data:
                                # let's delete it now from the dict, there should only be one reference!
                                del self.large_data[unique_ref]
                                log_data = log_data = self.ReadLogDataBuffer(log_data, len(log_data), '')
                            else:
                                logger.error('Data Reference not found for unique_ref=0x{:X} ct={}!'.format(unique_ref, ct))
                                format_str = "<decode: missing data>"
                                # TODO - Sometimes this data is in another file, create a mechanism to deal with that
                                # Eg: Logdata.Livedata.tracev3 will reference entries from Persist\*.tracev3 
                                #  There are very few of these in practice.

                        if u1 == 7: #Loss
                            log_msg = self.CreateLossMsg(ts, ct, continuousTime, buffer[pos + pos3 : pos + pos3 + log_data_len2], log_data_len2)
                        else:
                            log_msg = self.RecreateMsgFromFmtStringAndData(format_str, log_data, log_file_pos) if log_data else format_str
                        if len(act_id) > 2: parentActivityIdentifier = act_id[-2]
                        # TODO:For Loss type message, all other log fields are zero, confirm with more samples.
                        logs.append([self.file.filename, log_file_pos, ct, time, thread, log_type, act_id[-1], parentActivityIdentifier, \
                                        pid, euid, ttl, p_name, lib, sub_sys, cat,\
                                        signpost_name, signpost_string if is_signpost else '', 
                                        imageOffset, imageUUID, processImageUUID, senderImagePath, processImagePath,
                                        log_msg                            
                                    ])
                    except Exception as ex:
                        logger.exception("Exception while processing log @ 0x{:X} ct={}, skipping that log entry!".format(log_file_pos, ct))
                    ##
                    debug_log_count += 1
                    
                    pos2 += log_data_len
                    #padding
                    if ((pos2 - start_skew) % 8) != 0: 
                        pos2 += 8 - ((pos2 - start_skew) % 8)
                    num_logs_debug += 1

                logger.debug("Parsed {} type 6001 logs".format(num_logs_debug))

                pos += data_size
                if ((pos - start_skew) % 8):
                    # sometimes no padding after privatedata. Try to detect null byte, if so pad it.
                    if (pos+1 < len_buffer) and (buffer[pos:pos+1] == b'\x00'): 
                        pad_len = 8 - ((pos - start_skew) % 8)
                        pos += pad_len
                    else:
                        logger.debug('Avoided padding for firehose chunk ending @ 0x{:X}'.format(debug_file_pos + pos))
            elif tag == 0x6002: # Oversize
                ct, data_ref_id, data_len = struct.unpack('<QII', buffer[pos + pos2 : pos + pos2 + 16])
                pos2 += 16
                data = buffer[pos + pos2 : pos + pos2 + data_len]
                self.large_data[data_ref_id << 64 | ct] = data
                
                pos2 += data_len
                ## Debug print
                ts = self._FindClosestTimesyncItemInList(self.boot_uuid_ts_list, ct)
                time = ts.time_stamp + ct - ts.continuousTime
                logger.debug("Type 6002 timestamp={} ({}), data_ref_id=0x{:X} @ 0x{:X}".format(self._ReadAPFSTime(time), ct, data_ref_id, log_file_pos))
                pos += data_size
                if (pos - start_skew) % 8:
                    pad_len = 8 - ((pos - start_skew) % 8)
                    pos += pad_len
            elif tag == 0x6003: # State
                log_type = 'State'
                ct, activity_id, un7 = struct.unpack("<QII", buffer[pos + pos2 : pos + pos2 + 16])
                pos2 += 16
                uuid = UUID(bytes = buffer[pos + pos2 : pos + pos2 + 16])
                pos2 += 16
                data_type, data_len = struct.unpack('<II', buffer[pos + pos2 : pos + pos2 + 8])
                pos2 += 8
                if data_type == 1:
                    pos2 += 128  # type 1 does not have any strings, it is blank or random bytes
                else:
                    obj_type_str_1 = self._ReadCString(buffer[pos + pos2 : pos + pos2 + 64])
                    pos2 += 64
                    obj_type_str_2 = self._ReadCString(buffer[pos + pos2 : pos + pos2 + 64]) 
                    pos2 += 64

                name = self._ReadCString(buffer[pos + pos2 : pos + pos2 + 64], 64)
                pos2 += 64
                # datatype  1=plist, 2=custom object, 3=unknown data object
                log_msg = ''
                if data_len:
                    data = buffer[pos + pos2 : pos + pos2 + data_len]
                    if data_type == 1: # plist  # serialized NS/CF object [Apple]
                        try:
                            if sys.version_info >= (3, 9):
                                plist = plistlib.loads(data)
                            else:
                                plist = biplist.readPlistFromString(data)
                            log_msg = str(plist)
                        except:
                            logger.exception('Problem reading plist from log @ 0x{:X} ct={}'.format(log_file_pos, ct))
                    elif data_type == 2:  #custom object, not being read by log utility in many cases!
                        logger.error('Did not read data of type {}, t1={}, t2={}, length=0x{:X} from log @ 0x{:X} ct={}'.format(data_type, obj_type_str_1, obj_type_str_2, data_len, log_file_pos, ct))
                    elif data_type == 3:  # custom [Apple] #TODO - read non-plist data
                        if obj_type_str_1 == 'location' and obj_type_str_2 == '_CLClientManagerStateTrackerState':
                            log_msg = self._Read_CLClientManagerStateTrackerState(data)
                        else:
                            logger.error('Did not read data of type {}, t1={}, t2={}, length=0x{:X} from log @ 0x{:X} ct={}'.format(data_type, obj_type_str_1, obj_type_str_2, data_len, log_file_pos, ct))
                    else:
                        logger.error('Unknown data of type {}, t1={}, t2={}, length=0x{:X} from log @ 0x{:X} ct={}'.format(data_type, obj_type_str_1, obj_type_str_2, data_len, log_file_pos, ct))
                    pos2 += data_len

                try: # for any uncaught exception
                    ut_cache = catalog.FileObjects[proc_info.uuid_file_index]
                    p_name = ut_cache.library_name

                    senderImagePath = '' # Can be same as processImagePath
                    processImagePath = ut_cache.library_path
                    imageOffset = 0  # Same as senderProgramCounter
                    imageUUID = uuid
                    processImageUUID = ut_cache.Uuid

                    ts = self._FindClosestTimesyncItemInList(self.boot_uuid_ts_list, ct)
                    time = ts.time_stamp + ct - ts.continuousTime
                    #logger.debug("Type 6003 timestamp={}".format(self._ReadAPFSTime(time)))

                    logs.append([self.file.filename, log_file_pos, ct, time, 0, log_type, 0, 0, \
                                pid, euid, ttl, p_name, str(uuid).upper(), '', '',\
                                '', '', 
                                imageOffset, imageUUID, processImageUUID, senderImagePath, processImagePath, 
                                name + "\n" + log_msg                        
                                ])
                except:
                    logger.exception("Exception while processing logtype 'State' @ 0x{:X} ct={}, skipping that log entry!".format(log_file_pos, ct))
                debug_log_count += 1

                pos += data_size
                if (pos - start_skew) % 8:
                    pad_len = 8 - ((pos - start_skew) % 8)
                    pos += pad_len
            else:
                logger.info("Unexpected tag value 0x{:X} @ 0x{:X} (Expected 0x6001, 0x6002 or 0x6003)".format(tag, log_file_pos))
                pos += data_size
                pad_len = (pos - start_skew) % 8
                if pad_len:
                    pos += pad_len
            #padding,moved to individual sections due to anomaly with few files, where privatedata in 0x6001 has no padding after!

    
    def GetProcInfo(self, proc_id1, proc_id2, chunk_meta):
        proc_info = chunk_meta.ProcInfos.get( proc_id2 | (proc_id1 << 32) , None)
        if proc_info == None:
            logger.error("Could not find proc_info with proc_id1={} proc_id2={}".format(proc_id1, proc_id2))
        return proc_info

    def Parse(self, log_list_process_func=None):
        '''Parse the traceV3 file, returns True/False.
           'log_list_process_func' is a function the caller provides to 
           process a list of logs. It gets called periodically as logs are extracted.
           Its syntax is log_list_process_func(logs_list, tracev3_object)
           Here log_list = [ log_1, log_2, .. ], where each log_x item is a tuple
           log_x = ( log_file_pos, continuous_time, time, thread, log_type, 
                    activity_id, parent_activity_id, 
                    pid, euid, ttl, p_name, lib, sub_system, category,
                    signpost_name, signpost_string, 
                    image_offset, image_UUID, process_image_UUID, 
                    sender_image_path, process_image_path,
                    log_msg
                   ) 
        '''
        logger.debug("-"*100)
        logger.debug("Parsing traceV3 file {}".format(self.file.filename))
        f = self.file.open()
        if not f:
            return False
        try:
            file_size = self.file.get_file_size()
            if file_size < 16:
                logger.info('File too small to be valid! File size = {}'.format(file_size))
                return False
            chunk_header = f.read(16)
            tag, subtag, data_length = self.ParseChunkHeader(chunk_header, 0)
            if tag != 0x1000:
                logger.info('Wrong signature in traceV3 file, got 0x{:X} instead of 0x1000'.format(tag))
                return False
            if subtag != 0x11:
                logger.error('Cannot process this version of unified logging, version=0x{:X}'.format(subtag))
                return False
            
            buffer = f.read(data_length) # fileheader_data + items
            self.ParseFileHeader(buffer, data_length)
            
            pos = 16 + data_length
            catalog = None
            meta_chunk_index = 0
            global debug_log_count
            debug_log_count = 0
            uncompressed_file_pos = pos
            logs = []
            while pos < file_size:
                f.seek(pos)
                chunk_header = f.read(16)
                tag, subtag, data_length = self.ParseChunkHeader(chunk_header, uncompressed_file_pos)
                buffer = f.read(data_length)
                # Process buffer here
                if tag == 0x600B:
                    meta_chunk_index = 0
                    catalog = self.ProcessMetaChunk(buffer)
                    uncompressed_file_pos += 16 + data_length
                elif tag == 0x600D:
                    uncompressed_buffer = self._DecompressChunkData(buffer, len(buffer))
                    self.ProcessDataChunk(uncompressed_buffer, catalog, meta_chunk_index, uncompressed_file_pos + 16, logs)
                    meta_chunk_index += 1
                    uncompressed_file_pos += 16 + len(uncompressed_buffer)
                else:
                    logger.info("Unknown header for chunk - 0x{:X} , skipping chunk @ 0x{:X}!".format(tag, pos))
                    uncompressed_file_pos += 16 + data_length
                if data_length % 8: # Go to QWORD boundary
                    data_length += 8 - (data_length % 8)
                if uncompressed_file_pos % 8: # just for the uncompressed file pos
                    uncompressed_file_pos += 8 - (data_length % 8)
                pos = pos + 16 + data_length
                if log_list_process_func and (len(logs) > 100000):
                    log_list_process_func(logs, self)
                    logs = []
            # outside loop, end of file reached, write remaining logs
            if log_list_process_func and (len(logs) > 0):
                log_list_process_func(logs, self)
        except:
            logger.exception('traceV3 Parser error')
        return True
