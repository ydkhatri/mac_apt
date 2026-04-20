'''
   Copyright (c) 2026 jaybird1291

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the
   terms of the MIT License.

   pkgscripts.py
   -------------
   Extracts package installer scripts (preinstall / postinstall) and links
   them to dropped persistence artifacts.

   IMPORTANT CONSTRAINT: Package scripts are transient - they execute and
   disappear.  This plugin ONLY emits rows when actual script content is
   available offline.  It does NOT fabricate visibility from package receipts
   alone (InstallHistory.plist is already handled by the INSTALLHISTORY plugin).

   Offline sources where package scripts may still be present:
     1. Flat .pkg files (xar archives) found in the evidence
        - Common locations: ~/Downloads, /tmp, /private/tmp,
          /private/var/folders/, /Users/Shared, ~/Desktop
     2. Expanded package directories containing a Scripts/ subdirectory
        with preinstall or postinstall files
     3. In-progress installer sandbox remnants:
        /private/var/installd/Library/Caches/

   xar format parsing:
     - Header: magic (0x78617221), size, version, toc_len_compressed,
               toc_len_uncompressed, checksum_alg
     - TOC: zlib-compressed XML listing all files with offsets into heap
     - Heap: raw (possibly gzip-compressed) file data
     File entries relevant to us: any file named preinstall, postinstall,
     Scripts/preinstall, Scripts/postinstall, or matching those patterns
     anywhere in the archive.

   Output tables:
     PKGSCRIPTS        - one row per package with extractable scripts
     PKGSCRIPTS_DETAIL - raw script content (first 50 lines), package metadata
'''

import bz2
import gzip
import logging
import os
import struct
import zlib
from collections import deque

from xml.etree import ElementTree

from plugins.helpers.macinfo import *
from plugins.helpers.writer import *
from plugins.helpers.persistence_common import (
    MAIN_TABLE_COLUMNS, DETAIL_TABLE_COLUMNS,
    make_main_row, make_detail_row,
    get_file_mtime, safe_user_label,
)

__Plugin_Name = "PKGSCRIPTS"
__Plugin_Friendly_Name = "Package Installer Scripts"
__Plugin_Version = "1.0"
__Plugin_Description = (
    "Extracts preinstall/postinstall scripts from .pkg files present in evidence. "
    "Emits rows only when actual script content is available offline."
)
__Plugin_Author = "jaybird1291"
__Plugin_Author_Email = ""
__Plugin_Modes = "MACOS,ARTIFACTONLY"
__Plugin_ArtifactOnly_Usage = "Provide a .pkg file or a directory containing Scripts/preinstall or Scripts/postinstall"

log = logging.getLogger('MAIN.' + __Plugin_Name)

#---- Do not change the variable names in above section ----#

# ---------------------------------------------------------------------------
# Locations to scan for .pkg files (relative to home_dir for user dirs)
# ---------------------------------------------------------------------------

SYSTEM_PKG_DIRS = [
    '/tmp',
    '/private/tmp',
    '/Users/Shared',
    '/private/var/installd/Library/Caches',
]

USER_PKG_DIRS = [
    '/Downloads',
    '/Desktop',
    '/Documents',
]

# Maximum .pkg file size to attempt to parse (avoid reading multi-GB installers)
MAX_PKG_PARSE_BYTES = 256 * 1024 * 1024  # 256 MB
MAX_VAR_FOLDERS_DEPTH = 3
MAX_VAR_FOLDERS_DIR_BUDGET = 180
MAX_VAR_FOLDERS_PER_ROOT_DIR_BUDGET = 24
MAX_VAR_FOLDERS_MAX_ROOTS = 16

# Target script names to extract from packages
SCRIPT_NAMES = {'preinstall', 'postinstall'}
SCRIPT_PATHS = {  # path variants as they appear in xar TOC
    'preinstall', 'postinstall',
    'Scripts/preinstall', 'Scripts/postinstall',
    './preinstall', './postinstall',
    './Scripts/preinstall', './Scripts/postinstall',
}

XAR_MAGIC = 0x78617221  # 'xar!'
MAX_PKG_RECURSION_DEPTH = 4  # max nesting depth for component packages inside a product archive


# ---------------------------------------------------------------------------
# Minimal xar parser
# ---------------------------------------------------------------------------

class XarParseError(Exception):
    pass


def _read_xar_header(data):
    '''Parse xar header from bytes. Returns (header_size, toc_len_c, heap_start).'''
    if len(data) < 28:
        raise XarParseError('File too small for xar header')
    magic = struct.unpack_from('>I', data, 0)[0]
    if magic != XAR_MAGIC:
        raise XarParseError('Not a xar file (bad magic)')
    hdr_size  = struct.unpack_from('>H', data, 4)[0]
    # version  = struct.unpack_from('>H', data, 6)[0]
    toc_len_c = struct.unpack_from('>Q', data, 8)[0]
    # toc_len_u = struct.unpack_from('>Q', data, 16)[0]
    heap_start = hdr_size + toc_len_c
    return hdr_size, toc_len_c, heap_start


def _parse_xar_toc(data, hdr_size, toc_len_c):
    '''Decompress and parse the xar TOC XML.
    Returns the ElementTree root.'''
    toc_compressed = data[hdr_size:hdr_size + toc_len_c]
    try:
        toc_xml = zlib.decompress(toc_compressed)
    except zlib.error as e:
        raise XarParseError('TOC decompression failed: {}'.format(e))
    try:
        return ElementTree.fromstring(toc_xml)
    except ElementTree.ParseError as e:
        raise XarParseError('TOC XML parse failed: {}'.format(e))


def _iter_toc_files(root):
    '''Yield (name, offset, length, size, encoding) for every file in the TOC.
    Handles both flat and nested <file> elements.'''
    for file_elem in root.iter('file'):
        name = file_elem.findtext('name', '')
        if not name:
            continue
        ftype = file_elem.findtext('type', 'file')
        if ftype != 'file':
            continue
        data_elem = file_elem.find('data')
        if data_elem is None:
            continue
        try:
            offset = int(data_elem.findtext('offset', '0'))
            length = int(data_elem.findtext('length', '0'))
            size   = int(data_elem.findtext('size', '0'))
        except ValueError:
            continue
        enc_elem = data_elem.find('encoding')
        encoding = enc_elem.get('style', '') if enc_elem is not None else ''
        yield name, offset, length, size, encoding


def _extract_xar_file(data, heap_start, offset, length, encoding):
    '''Extract and decompress one file from the xar heap.'''
    raw = data[heap_start + offset: heap_start + offset + length]
    if not raw:
        return b''
    enc = encoding.lower()
    if 'gzip' in enc:
        try:
            return gzip.decompress(raw)
        except Exception:
            pass
    if 'bzip2' in enc:
        try:
            return bz2.decompress(raw)
        except Exception:
            pass
    if 'zlib' in enc:
        try:
            return zlib.decompress(raw)
        except Exception:
            pass
    # No encoding / unknown: return raw
    return raw


def extract_scripts_from_xar(data, depth=0):
    '''Parse a xar archive (bytes) and extract preinstall/postinstall script content.
    Returns dict: {script_basename: bytes_content}.
    Returns empty dict if not a valid xar or no scripts found.'''
    if depth > MAX_PKG_RECURSION_DEPTH:
        log.debug('xar: max nesting depth {} reached, skipping nested package'.format(depth))
        return {}

    try:
        hdr_size, toc_len_c, heap_start = _read_xar_header(data)
        root = _parse_xar_toc(data, hdr_size, toc_len_c)
    except XarParseError as e:
        log.debug('xar parse error: {}'.format(e))
        return {}

    scripts = {}
    for name, offset, length, size, encoding in _iter_toc_files(root):
        basename = os.path.basename(name)
        if basename not in SCRIPT_NAMES:
            continue
        if length == 0:
            continue
        content = _extract_xar_file(data, heap_start, offset, length, encoding)
        if content:
            scripts[basename] = content

    # Also look for nested packages (product archive contains component pkgs)
    for file_elem in root.iter('file'):
        name = file_elem.findtext('name', '')
        if not (name.endswith('.pkg') or name.endswith('.mpkg')):
            continue
        data_elem = file_elem.find('data')
        if data_elem is None:
            continue
        try:
            offset   = int(data_elem.findtext('offset', '0'))
            length   = int(data_elem.findtext('length', '0'))
            enc_elem = data_elem.find('encoding')
            encoding = enc_elem.get('style', '') if enc_elem is not None else ''
        except (ValueError, AttributeError):
            continue
        sub_data = _extract_xar_file(data, heap_start, offset, length, encoding)
        if sub_data and sub_data[:4] == b'xar!':
            sub_scripts = extract_scripts_from_xar(sub_data, depth=depth + 1)
            for k, v in sub_scripts.items():
                if k not in scripts:
                    scripts[k] = v

    return scripts


# ---------------------------------------------------------------------------
# Package processors
# ---------------------------------------------------------------------------

def process_pkg_file(mac_info, pkg_path, user_name, uid, main_rows, detail_rows):
    '''Attempt to parse a .pkg file and extract its scripts.'''
    file_size = mac_info.GetFileSize(pkg_path)
    if not file_size:
        return
    if file_size > MAX_PKG_PARSE_BYTES:
        log.info('Skipping oversized .pkg ({} bytes): {}'.format(file_size, pkg_path))
        mac_info.ExportFile(pkg_path, __Plugin_Name, '', False)
        # Emit a presence-only row so analysts know the package exists
        main_rows.append(make_main_row(
            mechanism='Package Scripts',
            sub_mechanism='pkg_too_large',
            user=user_name,
            uid=uid,
            artifact_path=pkg_path,
            artifact_type='pkg_file',
            trigger='package install',
            label_or_name=os.path.basename(pkg_path),
            artifact_mtime=get_file_mtime(mac_info, pkg_path),
            source=pkg_path,
        ))
        return

    f = mac_info.Open(pkg_path)
    if f is None:
        return
    data = f.read(file_size)
    if isinstance(data, str):
        data = data.encode('latin-1')

    scripts = extract_scripts_from_xar(data)
    if not scripts:
        return  # No scripts found - do not emit a row (per spec)

    mac_info.ExportFile(pkg_path, __Plugin_Name, '', False)
    artifact_mtime = get_file_mtime(mac_info, pkg_path)

    for script_name, content in scripts.items():
        _emit_script_rows(pkg_path, script_name, content, user_name, uid,
                           artifact_mtime, main_rows, detail_rows)


def process_expanded_pkg_dir(mac_info, pkg_dir, user_name, uid,
                               main_rows, detail_rows):
    '''Process an expanded package directory that still contains a Scripts/ subdir.'''
    for script_name in SCRIPT_NAMES:
        for subdir in ('Scripts', '.'):
            script_path = pkg_dir + '/' + subdir + '/' + script_name
            if mac_info.IsValidFilePath(script_path):
                mac_info.ExportFile(script_path, __Plugin_Name, '', False)
                artifact_mtime = get_file_mtime(mac_info, script_path)
                f = mac_info.Open(script_path)
                content = b''
                if f:
                    try:
                        content = f.read(512 * 1024)  # cap at 512 KB
                        if isinstance(content, str):
                            content = content.encode('latin-1')
                    except Exception:
                        pass
                if content:
                    _emit_script_rows(pkg_dir, script_name, content, user_name, uid,
                                       artifact_mtime, main_rows, detail_rows)


def _emit_script_rows(source_path, script_name, content, user_name, uid,
                        artifact_mtime, main_rows, detail_rows):
    '''Emit main + detail rows for one extracted script.'''
    try:
        text = content.decode('utf-8', errors='replace')
    except Exception:
        text = repr(content[:200])

    lines = text.splitlines()
    first_cmd = ''
    for line in lines:
        stripped = line.strip()
        if stripped and not stripped.startswith('#'):
            first_cmd = stripped
            break

    main_rows.append(make_main_row(
        mechanism='Package Scripts',
        sub_mechanism=script_name,   # 'preinstall' or 'postinstall'
        user=user_name,
        uid=uid,
        artifact_path=source_path,
        artifact_type='pkg_script',
        target_path=first_cmd[:200] if first_cmd else '',
        trigger='package install',
        label_or_name=script_name + ':' + os.path.basename(source_path),
        artifact_mtime=artifact_mtime,
        source=source_path,
    ))

    # Emit up to 50 non-trivial lines as detail rows
    line_count = 0
    for lineno, line in enumerate(lines, start=1):
        stripped = line.strip()
        if stripped and not stripped.startswith('#'):
            detail_rows.append(make_detail_row(
                artifact_path=source_path,
                evidence_type='script_line',
                key_or_line='{}:line:{}'.format(script_name, lineno),
                value=stripped[:500],
                user=user_name,
            ))
            line_count += 1
            if line_count >= 50:
                break


# ---------------------------------------------------------------------------
# Directory scanner
# ---------------------------------------------------------------------------

def scan_dir_for_packages(mac_info, directory, user_name, uid,
                            main_rows, detail_rows, processed, items=None):
    '''Scan one directory for .pkg files and expanded package directories.
    Returns a list of immediate child directories for optional caller BFS.'''
    if items is None:
        if not mac_info.IsValidFolderPath(directory):
            return []
        try:
            items = mac_info.ListItemsInFolder(directory,
                                               EntryType.FILES_AND_FOLDERS, False)
        except Exception:
            return []

    child_dirs = []
    for item in items:
        item_path = directory + '/' + item['name']
        item_type = item.get('type')
        if item_type == EntryType.FOLDERS:
            child_dirs.append(item_path)
            if item_path in processed:
                continue
            # Check if it's an expanded package (has Scripts/preinstall etc.)
            has_scripts = any(
                mac_info.IsValidFilePath(item_path + '/Scripts/' + s)
                or mac_info.IsValidFilePath(item_path + '/' + s)
                for s in SCRIPT_NAMES)
            if has_scripts:
                processed.add(item_path)
                process_expanded_pkg_dir(mac_info, item_path, user_name, uid,
                                          main_rows, detail_rows)
        elif item['name'].endswith(('.pkg', '.mpkg')):
            if item_path in processed:
                continue
            processed.add(item_path)
            process_pkg_file(mac_info, item_path, user_name, uid,
                              main_rows, detail_rows)
    return child_dirs


def _get_var_folders_scan_roots(mac_info):
    '''Return a bounded, deduplicated list of Darwin temp/cache roots to scan.
    Prefer per-user Darwin roots, then supplement with hashed T/C roots only
    until the global root budget is reached.'''
    roots = []
    seen = set()

    for user in mac_info.users:
        user_name = safe_user_label(user.user_name, user.home_dir) or 'root'
        for root in (getattr(user, 'DARWIN_USER_TEMP_DIR', ''),
                     getattr(user, 'DARWIN_USER_CACHE_DIR', '')):
            if root and root not in seen:
                seen.add(root)
                roots.append((root, user_name, user.UID))
                if len(roots) >= MAX_VAR_FOLDERS_MAX_ROOTS:
                    return roots

    var_folders_root = '/private/var/folders'
    if not mac_info.IsValidFolderPath(var_folders_root) or len(roots) >= MAX_VAR_FOLDERS_MAX_ROOTS:
        return roots

    try:
        level_1_dirs = mac_info.ListItemsInFolder(var_folders_root, EntryType.FOLDERS, False)
    except Exception:
        level_1_dirs = []
    for level_1 in level_1_dirs:
        base_1 = var_folders_root + '/' + level_1['name']
        try:
            level_2_dirs = mac_info.ListItemsInFolder(base_1, EntryType.FOLDERS, False)
        except Exception:
            level_2_dirs = []
        for level_2 in level_2_dirs:
            base_2 = base_1 + '/' + level_2['name']
            for suffix in ('T', 'C'):
                candidate = base_2 + '/' + suffix
                if candidate not in seen and mac_info.IsValidFolderPath(candidate):
                    seen.add(candidate)
                    roots.append((candidate, 'root', 0))
                    if len(roots) >= MAX_VAR_FOLDERS_MAX_ROOTS:
                        return roots
    return roots


def scan_var_folders_for_packages(mac_info, main_rows, detail_rows, processed):
    '''Bounded scan for package remnants under /private/var/folders.
    The budget is global across all roots so one large image cannot force the
    plugin into an effectively unbounded crawl.'''
    roots = _get_var_folders_scan_roots(mac_info)
    total_dirs_scanned = 0

    if roots:
        log.info('Scanning up to {} /private/var/folders roots with global directory budget {}'.format(
            len(roots), MAX_VAR_FOLDERS_DIR_BUDGET))

    for root, user_name, uid in roots:
        if total_dirs_scanned >= MAX_VAR_FOLDERS_DIR_BUDGET:
            log.info('Stopping /private/var/folders scan after hitting global directory budget')
            break
        if not mac_info.IsValidFolderPath(root):
            continue
        queue = deque([(root, 0)])
        seen_dirs = set()
        dirs_scanned = 0

        while queue and dirs_scanned < MAX_VAR_FOLDERS_PER_ROOT_DIR_BUDGET and \
                total_dirs_scanned < MAX_VAR_FOLDERS_DIR_BUDGET:
            directory, depth = queue.popleft()
            if directory in seen_dirs or not mac_info.IsValidFolderPath(directory):
                continue
            seen_dirs.add(directory)
            dirs_scanned += 1
            total_dirs_scanned += 1

            try:
                items = mac_info.ListItemsInFolder(directory, EntryType.FILES_AND_FOLDERS, False)
            except Exception:
                items = []

            child_dirs = scan_dir_for_packages(mac_info, directory, user_name, uid,
                                               main_rows, detail_rows, processed,
                                               items=items)

            if depth >= MAX_VAR_FOLDERS_DEPTH:
                continue

            for child in child_dirs:
                if os.path.basename(child).startswith('.'):
                    continue
                if child not in seen_dirs:
                    queue.append((child, depth + 1))

        if dirs_scanned >= MAX_VAR_FOLDERS_PER_ROOT_DIR_BUDGET:
            log.info('Stopped scanning {} after per-root directory budget {}'.format(
                root, MAX_VAR_FOLDERS_PER_ROOT_DIR_BUDGET))


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def write_output(main_rows, detail_rows, output_params):
    main_col_info = [(c, DataType.TEXT) for c in MAIN_TABLE_COLUMNS]
    for i, (name, _) in enumerate(main_col_info):
        if name in ('ArtifactMTime', 'TargetMTime'):
            main_col_info[i] = (name, DataType.DATE)
    detail_col_info = [(c, DataType.TEXT) for c in DETAIL_TABLE_COLUMNS]

    log.info('Found {} package script item(s)'.format(len(main_rows)))
    if main_rows:
        WriteList('package scripts', 'PKGSCRIPTS', main_rows,
                  main_col_info, output_params, '')
    if detail_rows:
        WriteList('package scripts detail', 'PKGSCRIPTS_DETAIL', detail_rows,
                  detail_col_info, output_params, '')


# ---------------------------------------------------------------------------
# Plugin entry points
# ---------------------------------------------------------------------------

def Plugin_Start(mac_info):
    main_rows   = []
    detail_rows = []
    processed   = set()

    # System directories
    for directory in SYSTEM_PKG_DIRS:
        scan_dir_for_packages(mac_info, directory, 'root', 0,
                               main_rows, detail_rows, processed)
    scan_var_folders_for_packages(mac_info, main_rows, detail_rows, processed)

    # Per-user directories
    user_processed = set()
    for user in mac_info.users:
        user_name = safe_user_label(user.user_name, user.home_dir)
        if not user_name:
            continue
        if user.home_dir in user_processed:
            continue
        user_processed.add(user.home_dir)

        for rel_dir in USER_PKG_DIRS:
            scan_dir_for_packages(
                mac_info,
                user.home_dir + rel_dir,
                user_name, user.UID,
                main_rows, detail_rows, processed)

    if main_rows or detail_rows:
        write_output(main_rows, detail_rows, mac_info.output_params)
    else:
        log.info('No package script artifacts found in scanned locations')


def Plugin_Start_Standalone(input_files_list, output_params):
    log.info('Module started as standalone')
    main_rows   = []
    detail_rows = []

    for input_path in input_files_list:
        log.debug('Input path: ' + input_path)
        if os.path.isdir(input_path):
            # Treat as expanded package
            for script_name in SCRIPT_NAMES:
                for subdir in ('Scripts', '.'):
                    script_path = os.path.join(input_path, subdir, script_name)
                    if os.path.isfile(script_path):
                        try:
                            with open(script_path, 'rb') as f:
                                content = f.read(512 * 1024)
                        except OSError:
                            continue
                        if content:
                            _emit_script_rows(input_path, script_name, content,
                                               '', '', None, main_rows, detail_rows)
        elif input_path.endswith(('.pkg', '.mpkg')):
            try:
                with open(input_path, 'rb') as f:
                    data = f.read(MAX_PKG_PARSE_BYTES)
            except OSError:
                log.exception('Could not read {}'.format(input_path))
                continue
            scripts = extract_scripts_from_xar(data)
            if not scripts:
                log.info('No scripts found in {}'.format(input_path))
                continue
            for script_name, content in scripts.items():
                _emit_script_rows(input_path, script_name, content, '', '',
                                   None, main_rows, detail_rows)
        else:
            log.warning('Unrecognised package artifact: {}'.format(input_path))

    if main_rows or detail_rows:
        write_output(main_rows, detail_rows, output_params)
    else:
        log.info('No package scripts found in provided files')


if __name__ == '__main__':
    print('This plugin is part of a framework and does not run independently.')
