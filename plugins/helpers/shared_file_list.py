'''
   Copyright (c) 2026 jaybird1291

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the
   terms of the MIT License.

   shared_file_list.py
   -------------------
   Shared parsing helpers for legacy shared file list artifacts (.sfl/.sfl2/.sfl3).
'''

import logging
import os
import plistlib
import struct
from dataclasses import dataclass

import nska_deserialize as nd

import plugins.helpers.ccl_bplist as ccl_bplist
from plugins.helpers.common import CommonFunctions

log = logging.getLogger('MAIN.HELPERS.SHAREDFILELIST')


@dataclass
class SharedFileListEntry:
    name: str = ''
    url: str = ''
    uuid: str = ''
    source: str = ''
    info: str = ''

    @property
    def resolved_path(self):
        return CommonFunctions.url_decode(self.url)


class _BookmarkAliasResolver:
    class BookmarkItem:
        def __init__(self):
            self.pos = 0
            self.size = 0
            self.data = None
            self.item_type = 0

        def read_data(self, bookmark):
            try:
                if self.item_type == 0x0101:
                    self.data = bookmark[self.pos + 8:self.pos + 8 + self.size].decode('utf-8', 'backslashreplace')
                elif self.item_type == 0x0901:
                    self.data = bookmark[self.pos + 8:self.pos + 8 + self.size].decode('utf-8', 'backslashreplace')
                elif self.item_type == 0x0601:
                    count = self.size // 4
                    self.data = struct.unpack("<{}L".format(count), bookmark[self.pos + 8:self.pos + 8 + self.size])
                elif self.item_type == 0x0303:
                    self.data = struct.unpack("<L", bookmark[self.pos + 8:self.pos + 8 + self.size])[0]
            except (IndexError, ValueError, struct.error) as ex:
                log.error('Problem reading bookmark data: {}'.format(str(ex)))

    def __init__(self):
        self.url = ''

    def read_alias_v2(self, alias, size=0):
        try:
            if size == 0:
                size = len(alias)
            fs_type = alias[42:44].decode('utf-8', 'backslashreplace')
            pos = 150
            while pos < size:
                tag, data_size = struct.unpack('>2H', alias[pos:pos + 4])
                if data_size > 0 and tag == 0x9 and fs_type != 'H+':
                    data = alias[pos + 6:pos + 6 + data_size - 2]
                    self.url = data[10:].decode('utf-8', 'backslashreplace').rstrip('\x00')
                    return
                if tag == 0xFFFF:
                    break
                pos += 4 + data_size
                if data_size % 2 != 0:
                    pos += 1
        except (IndexError, UnicodeDecodeError, ValueError, struct.error):
            log.exception('Exception while processing Alias_v2 data')

    def read_alias_v3(self, alias, size=0):
        try:
            if size == 0:
                size = len(alias)
            fs_type = alias[18:20].decode('utf-8', 'backslashreplace')
            pos = 58
            while pos < size:
                tag, data_size = struct.unpack('>2H', alias[pos:pos + 4])
                if data_size > 0 and tag == 0x9 and fs_type != 'H+':
                    data = alias[pos + 6:pos + 6 + data_size - 2]
                    self.url = data[10:].decode('utf-8', 'backslashreplace')
                    return
                if tag == 0xFFFF:
                    break
                pos += 4 + data_size
                if data_size % 2 != 0:
                    pos += 1
        except (IndexError, ValueError, struct.error):
            log.exception('Exception while processing Alias_v3 data')

    def read_alias(self, alias):
        try:
            size = len(alias)
            if size < 0x3B:
                return
            version = struct.unpack('>H', alias[6:8])[0]
            if version == 0x3:
                self.read_alias_v3(alias, size)
                return
            if version == 0x2:
                self.read_alias_v2(alias, size)
                return
            if size > 0x200:
                return
            pos = size - 6
            if alias[pos] == 0x00:
                pos -= 1
            reached_start = False
            data = b'\x00'
            while pos > 0x3B and not reached_start:
                if alias[pos] == 0x00:
                    reached_start = True
                else:
                    data = alias[pos:pos + 1] + data
                pos -= 1
            if reached_start:
                self.url = data.decode('utf-8', 'backslashreplace')
        except (IndexError, ValueError, struct.error):
            log.exception('Exception while processing alias data')

    def read_bookmark(self, bookmark):
        try:
            if bookmark[0:4] != b'book':
                return
            data_offset = struct.unpack("<L", bookmark[0xC:0x10])[0]
            data_length = struct.unpack("<L", bookmark[data_offset:data_offset + 4])[0]
            bookmark_items = []
            pos = data_offset + 4
            while pos < data_offset + data_length:
                item = self.BookmarkItem()
                item.pos = pos
                item.size, item.item_type = struct.unpack("<2L", bookmark[pos:pos + 8])
                item.read_data(bookmark)
                bookmark_items.append(item)
                pos += 8 + item.size
                remainder = item.size % 4
                if remainder > 0:
                    pos += 4 - remainder

            volume_path_parts = []
            parts_order = []
            for item in bookmark_items:
                if item.item_type == 0x0101:
                    volume_path_parts.append({'pos': item.pos - data_offset, 'data': item.data})
                if item.item_type == 0x0601:
                    parts_order = item.data
                    break
            if parts_order:
                folders = []
                for part in parts_order:
                    matched = [x for x in volume_path_parts if part == x['pos']]
                    if matched:
                        folders.append(matched[0]['data'])
                if folders:
                    self.url = '/'.join(folders)

            for item in bookmark_items:
                if item.item_type == 0x0901:
                    url = item.data
                    if url.find('://') > 0 and not url.startswith('file:///'):
                        self.url = url
                        return
        except (IndexError, ValueError, struct.error):
            log.exception('Exception while processing bookmark data')


def _extract_url_from_item(item):
    url = item.get('URL', '') or item.get('url', '')
    if isinstance(url, dict):
        url = url.get('NS.relative', '') or url.get('_CFURLString', '')
    if url:
        return str(url)

    bookmark = item.get('Bookmark', None)
    if bookmark is None:
        bookmark = item.get('bookmark', None)
    if isinstance(bookmark, dict):
        bookmark = bookmark.get('NS.data', None)
    if isinstance(bookmark, (bytes, bytearray)):
        resolver = _BookmarkAliasResolver()
        resolver.read_bookmark(bytes(bookmark))
        if resolver.url:
            return resolver.url

    alias = item.get('Alias', None)
    if alias is None:
        alias = item.get('alias', None)
    if isinstance(alias, dict):
        alias = alias.get('NS.data', None)
    if isinstance(alias, (bytes, bytearray)):
        resolver = _BookmarkAliasResolver()
        resolver.read_alias(bytes(alias))
        if resolver.url:
            return resolver.url

    path = item.get('path', '') or item.get('Path', '')
    return str(path or '')


def _coerce_simple_items(plist_obj):
    items = plist_obj.get('items', []) if isinstance(plist_obj, dict) else []
    entries = []
    for item in items:
        if not isinstance(item, dict):
            continue
        name = item.get('Name', '') or item.get('name', '')
        uuid = item.get('uuid', '') or item.get('UUID', '')
        entry = SharedFileListEntry(
            name=str(name or ''),
            url=_extract_url_from_item(item),
            uuid=str(uuid or ''),
            info='uuid={}'.format(uuid) if uuid else '',
        )
        entries.append(entry)
    return entries


def _parse_sfl2_records(file_handle):
    try:
        plist_obj = nd.deserialize_plist(file_handle)
        if isinstance(plist_obj, dict):
            return _coerce_simple_items(plist_obj)
    except (KeyError, nd.DeserializeError, nd.biplist.NotBinaryPlistException,
            nd.biplist.InvalidPlistException, plistlib.InvalidFileException,
            nd.ccl_bplist.BplistError, ValueError, TypeError, OSError, OverflowError):
        pass

    try:
        file_handle.seek(0)
        plist_obj = plistlib.load(file_handle)
        if isinstance(plist_obj, dict):
            return _coerce_simple_items(plist_obj)
    except Exception:
        pass
    return []


def _parse_sfl_records(file_handle):
    try:
        ccl_bplist.set_object_converter(ccl_bplist.NSKeyedArchiver_common_objects_convertor)
        plist_obj = ccl_bplist.load(file_handle)
        nska_obj = ccl_bplist.deserialise_NsKeyedArchiver(plist_obj, parse_whole_structure=True)
        root = nska_obj['root']
        items = root['items']
        entries = []
        for item in items:
            url = ''
            url_data = item.get('URL', {})
            if isinstance(url_data, dict):
                url = url_data.get('NS.relative', '')
            if not url:
                url = _extract_url_from_item(item)
            if url.find('x-apple-findertag') == 0:
                continue
            entries.append(SharedFileListEntry(
                name=item.get('name', ''),
                url=url,
            ))
        return entries
    except (ccl_bplist.BplistError, ValueError, TypeError, KeyError):
        pass

    try:
        file_handle.seek(0)
        plist_obj = plistlib.load(file_handle)
        if isinstance(plist_obj, dict):
            return _coerce_simple_items(plist_obj)
    except Exception:
        pass
    return []


def parse_shared_file_list(file_handle, source_path):
    '''Parse .sfl/.sfl2/.sfl3 content from a file-like object.'''
    basename = os.path.basename(source_path).lower()
    if basename.endswith('.sfl'):
        entries = _parse_sfl_records(file_handle)
    elif basename.endswith('.sfl2') or basename.endswith('.sfl3'):
        entries = _parse_sfl2_records(file_handle)
    else:
        entries = []
    for entry in entries:
        entry.source = source_path
    return entries


def parse_shared_file_list_path(path):
    '''Open and parse a shared file list from a local filesystem path.'''
    with open(path, 'rb') as handle:
        return parse_shared_file_list(handle, path)
