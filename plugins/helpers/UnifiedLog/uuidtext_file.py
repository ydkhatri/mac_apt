# -*- coding: utf-8 -*-
'''The uuidtext file parser.'''

from __future__ import unicode_literals

import struct
import os
import posixpath

import plugins.helpers.UnifiedLog.data_format as data_format
import plugins.helpers.UnifiedLog.logger as logger


class Uuidtext(data_format.BinaryDataFormat):
    '''Uuidtext file parser.'''

    def __init__(self, v_file, uuid):
        '''Initializes an uuidtext file parser.

        Args:
          v_file (VirtualFile): a virtual file.
          uuid (uuid.UUID): an UUID.
        '''
        super(Uuidtext, self).__init__()
        self._entries = []   # [ [range_start_offset, data_offset, data_len], [..] , ..]
        self._file = v_file
        self.library_path = ''
        self.library_name = ''
        self.Uuid = uuid

    def _ParseFileObject(self, file_object):
        '''Parses an uuidtext file-like object.

        Args:
          file_object (file): file-like object.

        Returns:
          bool: True if the uuidtext file-like object was successfully parsed,
              False otherwise.

        Raises:
          IOError: if the uuidtext file cannot be parsed.
          OSError: if the uuidtext file cannot be parsed.
          struct.error: if the uuidtext file cannot be parsed.
        '''
        file_header_data = file_object.read(16)
        if file_header_data[0:4] != b'\x99\x88\x77\x66':
            signature_base16 = file_header_data[0:4].hex()
            logger.info((
                'Wrong signature in uuidtext file, got 0x{} instead of '
                '0x99887766').format(signature_base16))
            return False

        # Note that the flag1 and flag2 are not used.
        flag1, flag2, num_entries = struct.unpack(
            "<III", file_header_data[4:16])

        entries_data_size = 8 * num_entries
        entries_data = file_object.read(entries_data_size)

        entry_offset = 0
        data_offset = 16 + entries_data_size
        while len(self._entries) < num_entries:
            entry_end_offset = entry_offset + 8
            range_start_offset, data_len = struct.unpack(
                "<II", entries_data[entry_offset:entry_end_offset])

            entry_offset = entry_end_offset

            entry_tuple = (range_start_offset, data_offset, data_len)
            self._entries.append(entry_tuple)
            data_offset += data_len

        file_object.seek(data_offset, os.SEEK_SET)
        library_path_data = file_object.read(1024)
        self.library_path = self._ReadCString(library_path_data)
        self.library_name = posixpath.basename(self.library_path)

        return True

    def ReadFmtStringFromVirtualOffset(self, v_offset):
        '''Reads a format string for a specific virtual offset.

        Args:
          v_offset (int): virtual offset.

        Returns:
          str: a format string, '%s' if the 32-bit MSB (0x80000000) is set or
              '<compose failure [UUID]>' if the uuidtext file could not be
              parsed or there is no entry corresponding with the virtual offset.
        '''
        if not self._file.is_valid:
            # This is the value returned by the MacOS 'log' program if uuidtext
            # is not found.
            return '<compose failure [UUID]>'

        if v_offset & 0x80000000:
            return '%s'

        for range_start_offset, data_offset, data_len in self._entries:
            range_end_offset = range_start_offset + data_len
            if range_start_offset <= v_offset < range_end_offset:
                rel_offset = v_offset - range_start_offset

                file_object = self._file.file_pointer
                file_object.seek(data_offset + rel_offset)
                format_string_data = file_object.read(data_len - rel_offset)
                return self._ReadCString(format_string_data, data_len - rel_offset)

        # This is the value returned by the MacOS 'log' program if the uuidtext
        # entry is not found.
        logger.error('Invalid bounds 0x{0:X} for {1!s}'.format(v_offset, self.Uuid))
        return '<compose failure [UUID]>'

    def Parse(self):
        '''Parses a uuidtext file.

        self._file.is_valid is set to False if this method encounters issues
        parsing the file.

        Returns:
          bool: True if the dsc file-like object was successfully parsed,
              False otherwise.
        '''
        file_object = self._file.open()
        if not file_object:
          return False

        try:
            result = self._ParseFileObject(file_object)
        except (IOError, OSError, struct.error):
            logger.exception('Uuidtext Parser error')
            result = False

        if not result:
            self._file.is_valid = False

        return result
