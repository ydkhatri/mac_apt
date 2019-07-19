# -*- coding: utf-8 -*-
'''Shared functionality for parsing binary data formats.'''

from __future__ import unicode_literals

import datetime
import struct

import plugins.helpers.UnifiedLog.logger as logger


class BinaryDataFormat(object):
    '''Binary data format.'''

    def _ReadAPFSTime(self, mac_apfs_time): # Mac APFS timestamp is nano second time epoch beginning 1970/1/1
        '''Returns datetime object, or empty string upon error'''
        if mac_apfs_time not in ( 0, None, ''):
            try:
                if isinstance(mac_apfs_time, str):
                    mac_apfs_time = float(mac_apfs_time)
                return datetime.datetime(1970, 1, 1) + datetime.timedelta(seconds=mac_apfs_time/1000000000.)
            except Exception as ex:
                logger.error("ReadAPFSTime() Failed to convert timestamp from value " + str(mac_apfs_time) + " Error was: " + str(ex))
        return ''

    def _ReadCString(self, data, max_len=1024):
        '''Returns a C utf8 string (excluding terminating null)'''
        pos = 0
        max_len = min(len(data), max_len)
        string = ''
        try:
            null_pos = data.find(b'\x00', 0, max_len)
            if null_pos == -1:
                logger.warning("Possible corrupted string encountered")
                string = data.decode('utf8')
            else:
                string = data[0:null_pos].decode('utf8')
        except:
            logger.exception('Error reading C-String')

        return string

    def _ReadCStringAndEndPos(self, data, max_len=1024):
        '''Returns a tuple containing a C utf8 string (excluding terminating null)
           and the end position in the data
           ("utf8-string", pos)
        '''
        pos = 0
        max_len = min(len(data), max_len)
        string = ''
        null_pos = -1
        try:
            null_pos = data.find(b'\x00', 0, max_len)
            if null_pos == -1:
                logger.warning("Possible corrupted string encountered")
                string = data.decode('utf8')
            else:
                string = data[0:null_pos].decode('utf8')
        except:
            logger.exception('Error reading C-String')
        return string, null_pos

    def _ReadNtSid(self, data):
        '''Reads a windows SID from its raw binary form'''
        sid = ''
        size = len(data)
        if size < 8:
            logger.error('Not a windows sid')
        rev = struct.unpack("<B", data[0])[0]
        num_sub_auth = struct.unpack("<B", data[1])[0]
        authority = struct.unpack(">I", data[4:8])[0]

        if size < (8 + (num_sub_auth * 4)):
            logger.error('buffer too small or truncated - cant fit all sub_auth')
            return ''
        sub_authorities = struct.unpack('<{}I'.format(num_sub_auth), data[8:8*num_sub_auth])
        sid = 'S-{}-{}-'.format(rev, authority) + '-'.join([str(sa) for sa in sub_authorities])
        return sid
