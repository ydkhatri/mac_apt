'''
   Copyright (c) 2026 jaybird1291

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the
   terms of the MIT License.

   appsupportpersist.py
   --------------------
   Detects low-noise persistence-style helpers staged inside
   ~/Library/Application Support/.
'''

import logging
import os
import posixpath
from collections import deque

from plugins.helpers.macinfo import *
from plugins.helpers.writer import *
from plugins.helpers.common import CommonFunctions
from plugins.helpers.codesign_offline import get_binary_codesign_info
from plugins.helpers.persistence_common import (
    MAIN_TABLE_COLUMNS, DETAIL_TABLE_COLUMNS,
    make_main_row, make_detail_row,
    get_file_mtime, safe_user_label,
)

__Plugin_Name = "APPSUPPORTPERSIST"
__Plugin_Friendly_Name = "Application Support Helpers"
__Plugin_Version = "1.0"
__Plugin_Description = (
    "Detects suspicious launch-style plists, hidden helper chains, and "
    "helper-like scripts/binaries in user Application Support folders"
)
__Plugin_Author = "jaybird1291"
__Plugin_Author_Email = ""
__Plugin_Modes = "MACOS,ARTIFACTONLY"
__Plugin_ArtifactOnly_Usage = (
    "Provide a ~/Library/Application Support directory, subdirectory, suspicious plist, or helper file"
)

log = logging.getLogger('MAIN.' + __Plugin_Name)

MAX_SCAN_DEPTH = 4
MAX_SCAN_DIRS = 250
MAX_FILE_READ = 1024 * 1024
NOISY_DIRS = {
    'caches',
    'logs',
    'crashreporter',
    'code cache',
    'gpucache',
    'service worker',
    'sessions',
    'indexeddb',
    'local storage',
    'databases',
}
HELPER_TERMS = (
    'updater',
    'helper',
    'agent',
    'daemon',
    'loader',
    'launcher',
    'monitor',
    'service',
    'worker',
)
LAUNCH_STYLE_KEYS = (
    'Label',
    'Program',
    'ProgramArguments',
    'RunAtLoad',
    'KeepAlive',
    'MachServices',
    'Sockets',
)
MACHO_MAGICS = {
    b'\xcf\xfa\xed\xfe',
    b'\xce\xfa\xed\xfe',
    b'\xfe\xed\xfa\xcf',
    b'\xfe\xed\xfa\xce',
    b'\xca\xfe\xba\xbe',
    b'\xca\xfe\xba\xbf',
}


class _StandaloneMacInfo:
    def IsValidFilePath(self, path):
        return os.path.isfile(path)

    def IsValidFolderPath(self, path):
        return os.path.isdir(path)

    def ListItemsInFolder(self, path, entry_type, include_dates=False):
        items = []
        for name in os.listdir(path):
            item_path = os.path.join(path, name)
            is_file = os.path.isfile(item_path)
            is_dir = os.path.isdir(item_path)
            if entry_type == EntryType.FILES and not is_file:
                continue
            if entry_type == EntryType.FOLDERS and not is_dir:
                continue
            if entry_type == EntryType.FILES_AND_FOLDERS and not (is_file or is_dir):
                continue
            size = os.path.getsize(item_path) if is_file else 0
            items.append({'name': name, 'size': size})
        return items

    def Open(self, path):
        return open(path, 'rb')

    def ReadPlist(self, path):
        return CommonFunctions.ReadPlist(path)

    def ExportFile(self, *_args, **_kwargs):
        return None

    def GetFileSize(self, path):
        return os.path.getsize(path)

    def GetFileMACTimes(self, path):
        stats = os.stat(path)
        return {
            'c_time': CommonFunctions.ReadUnixTime(stats.st_ctime),
            'm_time': CommonFunctions.ReadUnixTime(stats.st_mtime),
            'cr_time': CommonFunctions.ReadUnixTime(stats.st_ctime),
            'a_time': CommonFunctions.ReadUnixTime(stats.st_atime),
        }


def _has_shebang(mac_info, path):
    try:
        f = mac_info.Open(path)
        if not f:
            return False
        head = f.read(64)
        return head.startswith(b'#!')
    except Exception:
        return False


def _looks_like_macho(mac_info, path):
    try:
        f = mac_info.Open(path)
        if not f:
            return False
        return f.read(4) in MACHO_MAGICS
    except Exception:
        return False


def _has_hidden_component(path, base_path=''):
    rel_path = path
    if base_path and path.startswith(base_path):
        rel_path = path[len(base_path):].lstrip('/\\')
    parts = [p for p in rel_path.replace('\\', '/').split('/') if p not in ('', '.', '..')]
    return any(part.startswith('.') for part in parts)


def _has_helper_term(path):
    lowered = path.lower()
    return any(term in lowered for term in HELPER_TERMS)


def _is_launch_style_plist(plist):
    if not isinstance(plist, dict):
        return False
    return any(key in plist for key in LAUNCH_STYLE_KEYS)


def _resolve_candidate_path(base_dir, candidate):
    candidate = str(candidate or '').strip()
    if not candidate:
        return ''
    if candidate.startswith('/'):
        return posixpath.normpath(candidate)
    if candidate.startswith('./') or candidate.startswith('../'):
        return posixpath.normpath(posixpath.join(base_dir, candidate))
    return posixpath.normpath(posixpath.join(base_dir, candidate))


def _extract_launch_target(plist):
    program_args = plist.get('ProgramArguments', [])
    program = plist.get('Program', '')
    target_path = str(program or '')
    target_args = ''
    if not target_path and isinstance(program_args, list) and program_args:
        target_path = str(program_args[0])
    if isinstance(program_args, list) and len(program_args) > 1:
        target_args = ' '.join(str(x) for x in program_args[1:])
    return target_path, target_args


def _append_detail(detail_rows, artifact_path, evidence_type, key_or_line, value,
                   resolved_path='', user=''):
    detail_rows.append(make_detail_row(
        artifact_path=artifact_path,
        evidence_type=evidence_type,
        key_or_line=key_or_line,
        value=str(value),
        resolved_path=resolved_path,
        user=user,
    ))


def _get_codesign_info_if_small(mac_info, path):
    try:
        if mac_info.GetFileSize(path) <= MAX_FILE_READ:
            return get_binary_codesign_info(mac_info, path)
    except Exception:
        pass
    return None


def _emit_helper_file(mac_info, file_path, root_path, user_name, uid,
                      main_rows, detail_rows, emitted, linked_from=''):
    if file_path in emitted or not mac_info.IsValidFilePath(file_path):
        return

    hidden_chain = _has_hidden_component(file_path, root_path)
    helper_name = _has_helper_term(file_path)
    is_script = _has_shebang(mac_info, file_path)
    is_macho = _looks_like_macho(mac_info, file_path)
    if not ((is_script or is_macho) and (hidden_chain or helper_name)):
        return

    artifact_type = 'helper_script' if is_script else 'helper_binary'
    sub_mechanism = 'hidden_helper' if hidden_chain and not helper_name else artifact_type
    label = os.path.basename(file_path)
    cs = _get_codesign_info_if_small(mac_info, file_path)

    mac_info.ExportFile(file_path, __Plugin_Name, user_name + '_', False)
    main_rows.append(make_main_row(
        mechanism='Application Support Helper',
        sub_mechanism=sub_mechanism,
        scope='user',
        user=user_name,
        uid=uid,
        artifact_path=file_path,
        artifact_type=artifact_type,
        target_path=file_path,
        trigger='app launch / helper launch / chained autostart',
        label_or_name=label,
        team_id=cs.team_id if cs else '',
        codesign_status=cs.codesign_status if cs else '',
        sha256=cs.sha256 if cs else '',
        artifact_mtime=get_file_mtime(mac_info, file_path),
        source=file_path,
    ))
    if hidden_chain:
        _append_detail(detail_rows, file_path, 'hidden_helper_chain', 'HiddenPath', file_path, file_path, user_name)
    if helper_name:
        _append_detail(detail_rows, file_path, 'helper_name_match', 'NameHeuristic', label, file_path, user_name)
    if linked_from:
        _append_detail(detail_rows, file_path, 'linked_launch_plist', 'LaunchStylePlist', linked_from, linked_from, user_name)

    emitted.add(file_path)


def _emit_launch_style_plist(mac_info, plist_path, plist, root_path, user_name, uid,
                             main_rows, detail_rows, emitted):
    target_path, target_args = _extract_launch_target(plist)
    resolved_target = _resolve_candidate_path(posixpath.dirname(plist_path), target_path)
    label = plist.get('Label', '') or os.path.basename(plist_path)

    mac_info.ExportFile(plist_path, __Plugin_Name, user_name + '_', False)
    main_rows.append(make_main_row(
        mechanism='Application Support Helper',
        sub_mechanism='launch_style_plist',
        scope='user',
        user=user_name,
        uid=uid,
        artifact_path=plist_path,
        artifact_type='launch_style_plist',
        target_path=resolved_target or target_path,
        target_args=target_args,
        trigger='app launch / helper launch / chained autostart',
        label_or_name=label,
        artifact_mtime=get_file_mtime(mac_info, plist_path),
        target_mtime=get_file_mtime(mac_info, resolved_target) if resolved_target and mac_info.IsValidFilePath(resolved_target) else None,
        source=plist_path,
    ))

    for key in LAUNCH_STYLE_KEYS:
        if key in plist:
            _append_detail(detail_rows, plist_path, 'launch_key', key, plist.get(key, ''), resolved_target, user_name)

    if resolved_target and mac_info.IsValidFilePath(resolved_target):
        if resolved_target.startswith(root_path.rstrip('/') + '/') or resolved_target == root_path:
            _append_detail(detail_rows, plist_path, 'linked_helper', 'TargetPath', resolved_target, resolved_target, user_name)
            _emit_helper_file(mac_info, resolved_target, root_path, user_name, uid,
                              main_rows, detail_rows, emitted, linked_from=plist_path)


def _inspect_file(mac_info, file_path, root_path, user_name, uid,
                  main_rows, detail_rows, emitted):
    try:
        file_size = mac_info.GetFileSize(file_path)
    except Exception:
        file_size = 0

    if file_path.lower().endswith('.plist') and file_size <= MAX_FILE_READ:
        success, plist, _ = mac_info.ReadPlist(file_path)
        if success and _is_launch_style_plist(plist):
            _emit_launch_style_plist(mac_info, file_path, plist, root_path, user_name, uid,
                                     main_rows, detail_rows, emitted)
            return

    _emit_helper_file(mac_info, file_path, root_path, user_name, uid,
                      main_rows, detail_rows, emitted)


def scan_application_support_tree(mac_info, root_path, user_name, uid, main_rows, detail_rows):
    if not mac_info.IsValidFolderPath(root_path):
        return

    queue = deque([(root_path, 0)])
    seen_dirs = set()
    emitted = set()
    dirs_scanned = 0

    while queue and dirs_scanned < MAX_SCAN_DIRS:
        directory, depth = queue.popleft()
        if directory in seen_dirs:
            continue
        seen_dirs.add(directory)
        dirs_scanned += 1

        try:
            items = mac_info.ListItemsInFolder(directory, EntryType.FILES_AND_FOLDERS, False)
        except Exception:
            continue

        for item in sorted(items, key=lambda x: x['name'].lower()):
            name = item['name']
            if not name or name.startswith('._') or name == '.DS_Store':
                continue
            item_path = directory + '/' + name
            if mac_info.IsValidFolderPath(item_path):
                if name.lower() in NOISY_DIRS:
                    continue
                if depth < MAX_SCAN_DEPTH:
                    queue.append((item_path, depth + 1))
                continue
            _inspect_file(mac_info, item_path, root_path, user_name, uid,
                          main_rows, detail_rows, emitted)


def write_output(main_rows, detail_rows, output_params):
    main_col_info = [(c, DataType.TEXT) for c in MAIN_TABLE_COLUMNS]
    for i, (name, _) in enumerate(main_col_info):
        if name in ('ArtifactMTime', 'TargetMTime'):
            main_col_info[i] = (name, DataType.DATE)
    detail_col_info = [(c, DataType.TEXT) for c in DETAIL_TABLE_COLUMNS]

    log.info('Found {} application support helper item(s)'.format(len(main_rows)))
    if main_rows:
        WriteList('application support helper persistence', 'APPSUPPORTPERSIST',
                  main_rows, main_col_info, output_params, '')
    if detail_rows:
        WriteList('application support helper persistence detail', 'APPSUPPORTPERSIST_DETAIL',
                  detail_rows, detail_col_info, output_params, '')


def Plugin_Start(mac_info):
    main_rows = []
    detail_rows = []
    processed_homes = set()

    for user in mac_info.users:
        user_name = safe_user_label(user.user_name, user.home_dir)
        if not user_name or user.home_dir in processed_homes:
            continue
        processed_homes.add(user.home_dir)
        root_path = user.home_dir + '/Library/Application Support'
        scan_application_support_tree(
            mac_info, root_path, user_name, user.UID,
            main_rows, detail_rows,
        )

    if main_rows or detail_rows:
        write_output(main_rows, detail_rows, mac_info.output_params)
    else:
        log.info('No application support helper artifacts found')


def Plugin_Start_Standalone(input_files_list, output_params):
    log.info('Module started as standalone')
    mac_info = _StandaloneMacInfo()
    main_rows = []
    detail_rows = []

    for input_path in input_files_list:
        log.debug('Input path: ' + input_path)
        if os.path.isdir(input_path):
            scan_application_support_tree(mac_info, input_path, '', '', main_rows, detail_rows)
        elif os.path.isfile(input_path):
            root_path = os.path.dirname(input_path)
            _inspect_file(mac_info, input_path, root_path, '', '',
                          main_rows, detail_rows, set())
        else:
            log.warning('Path not found: {}'.format(input_path))

    if main_rows or detail_rows:
        write_output(main_rows, detail_rows, output_params)
    else:
        log.info('No application support helper persistence found in provided paths')
