'''
   Copyright (c) 2026 jaybird1291

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the
   terms of the MIT License.

   pystartup.py
   ------------
   Detects Python interpreter startup hooks.

   Python executes certain files automatically at interpreter startup:
     sitecustomize.py  - executed at startup before any user code
     usercustomize.py  - executed at startup from the user site-packages dir
     *.pth             - path configuration files; lines starting with "import"
                         are executed as Python code at startup

   Artifact locations scanned (both system and user site-packages trees):
     /Library/Python/<version>/site-packages/
     ~/Library/Python/<version>/lib/python/site-packages/
     /usr/local/lib/python<version>/site-packages/          (Homebrew Intel)
     /opt/homebrew/lib/python<version>/site-packages/       (Homebrew Apple Silicon)
     /usr/lib/python<version>/site-packages/

   Output tables:
     PYSTARTUP        - one row per dangerous .pth line or per sitecustomize/usercustomize file
     PYSTARTUP_DETAIL - raw import line (for .pth), file path, Python version
'''

import logging
import os
import posixpath
import re

from plugins.helpers.macinfo import *
from plugins.helpers.writer import *
from plugins.helpers.persistence_common import (
    MAIN_TABLE_COLUMNS, DETAIL_TABLE_COLUMNS,
    make_main_row, make_detail_row,
    get_file_mtime, safe_user_label, get_scope,
)

__Plugin_Name = "PYSTARTUP"
__Plugin_Friendly_Name = "Python Startup Hooks"
__Plugin_Version = "1.0"
__Plugin_Description = (
    "Detects persistence via Python startup hooks: "
    "sitecustomize.py, usercustomize.py, and executable .pth files"
)
__Plugin_Author = "jaybird1291"
__Plugin_Author_Email = ""
__Plugin_Modes = "MACOS,ARTIFACTONLY"
__Plugin_ArtifactOnly_Usage = "Provide a .pth file, sitecustomize.py, or usercustomize.py"

log = logging.getLogger('MAIN.' + __Plugin_Name)

#---- Do not change the variable names in above section ----#

# ---------------------------------------------------------------------------
# Site-packages location patterns
# ---------------------------------------------------------------------------

# System-wide site-packages (system Python + Homebrew)
# We enumerate version directories under these base paths.
SYSTEM_SITE_PACKAGE_BASES = [
    '/Library/Python',               # macOS built-in Python versions
    '/usr/local/lib',                # Homebrew (Intel)
    '/opt/homebrew/lib',             # Homebrew (Apple Silicon)
    '/usr/lib',                      # System Python (rare on macOS)
    '/Library/Developer/CommandLineTools/Library/Frameworks/'
    'Python3.framework/Versions',    # Xcode CLT Python
]

# User site-packages base (version dirs under this)
USER_SITE_PACKAGE_BASE = '/Library/Python'   # relative to home_dir

# Python directory name patterns
RE_PYTHON_VER_DIR = re.compile(r'^python3?\.\d+$|^python3?$', re.IGNORECASE)
RE_PYTHON_VER_PLAIN = re.compile(r'^python3?\.\d+$', re.IGNORECASE)
SUSPICIOUS_PTH_PREFIXES = (
    '/tmp/', '/private/tmp/', '/var/tmp/', '/users/shared/',
    '/private/var/folders/', '/private/var/tmp/',
)


def _find_site_packages_dirs(mac_info, base_dir):
    '''Yield site-packages directories under base_dir.
    Handles both /Library/Python/<ver>/site-packages
    and /usr/local/lib/python<ver>/site-packages layouts.'''
    if not mac_info.IsValidFolderPath(base_dir):
        return
    try:
        children = mac_info.ListItemsInFolder(base_dir, EntryType.FOLDERS, False)
    except Exception:
        return
    for child in children:
        name = child['name']
        if not RE_PYTHON_VER_DIR.match(name):
            continue
        # Layout 1: <base>/<ver>/site-packages/
        candidate1 = base_dir + '/' + name + '/site-packages'
        if mac_info.IsValidFolderPath(candidate1):
            yield candidate1
        # Layout 2: <base>/<ver>/lib/python/site-packages/
        candidate2 = base_dir + '/' + name + '/lib/python/site-packages'
        if mac_info.IsValidFolderPath(candidate2):
            yield candidate2
        # Layout 3: <base>/<ver>/lib/<ver>/site-packages/
        try:
            lib_children = mac_info.ListItemsInFolder(
                base_dir + '/' + name + '/lib', EntryType.FOLDERS, False)
        except Exception:
            lib_children = []
        for lc in lib_children:
            if RE_PYTHON_VER_PLAIN.match(lc['name']):
                c3 = base_dir + '/' + name + '/lib/' + lc['name'] + '/site-packages'
                if mac_info.IsValidFolderPath(c3):
                    yield c3


# ---------------------------------------------------------------------------
# Processors
# ---------------------------------------------------------------------------

def process_sitecustomize(mac_info, file_path, python_ver, user_name, uid,
                           sub_mech, main_rows, detail_rows,
                           processed_customizes=None):
    '''Emit one main row for sitecustomize.py / usercustomize.py.
    These files are ALWAYS executed at interpreter startup - any content is relevant.'''
    if processed_customizes is not None:
        if file_path in processed_customizes:
            return
        processed_customizes.add(file_path)
    if not mac_info.IsValidFilePath(file_path):
        return
    mac_info.ExportFile(file_path, __Plugin_Name, '', False)
    artifact_mtime = get_file_mtime(mac_info, file_path)

    main_rows.append(make_main_row(
        mechanism='Python Startup',
        sub_mechanism=sub_mech,
        scope=get_scope(user_name),
        user=user_name,
        uid=uid,
        artifact_path=file_path,
        artifact_type='python_startup_script',
        target_path=file_path,
        trigger='python interpreter start',
        label_or_name=os.path.basename(file_path),
        artifact_mtime=artifact_mtime,
        source=file_path,
    ))
    detail_rows.append(make_detail_row(
        artifact_path=file_path,
        evidence_type='python_version',
        key_or_line='python_version',
        value=python_ver,
        user=user_name,
    ))

    # Capture first 20 non-trivial lines
    f = mac_info.Open(file_path)
    if f is None:
        return
    try:
        for lineno, raw in enumerate(f, start=1):
            if lineno > 20:
                break
            if isinstance(raw, bytes):
                raw = raw.decode('utf-8', errors='replace')
            raw = raw.rstrip()
            if raw.strip() and not raw.strip().startswith('#'):
                detail_rows.append(make_detail_row(
                    artifact_path=file_path,
                    evidence_type='startup_script_line',
                    key_or_line='line:{}'.format(lineno),
                    value=raw.strip(),
                    user=user_name,
                ))
    except Exception:
        log.exception('Error reading {}'.format(file_path))


def _infer_home_from_path(path):
    if path.startswith('/Users/'):
        parts = path.split('/')
        if len(parts) > 2:
            return '/Users/' + parts[2]
    if path.startswith('/private/var/root/'):
        return '/private/var/root'
    if path.startswith('/var/root/'):
        return '/var/root'
    return ''


def _resolve_pth_path(file_path, raw_path):
    '''Resolve one path-only .pth line to an absolute path when feasible.'''
    raw_path = raw_path.strip()
    if not raw_path:
        return ''
    home_dir = _infer_home_from_path(file_path)
    if raw_path == '~':
        return home_dir or raw_path
    if raw_path.startswith('~/'):
        return posixpath.normpath(posixpath.join(home_dir, raw_path[2:])) if home_dir else ''
    if raw_path.startswith('/'):
        return posixpath.normpath(raw_path)
    return posixpath.normpath(posixpath.join(posixpath.dirname(file_path), raw_path))


def _is_suspicious_pth_path(resolved_path, home_dir):
    if not resolved_path:
        return False
    lower = resolved_path.lower()
    if any(lower.startswith(prefix) for prefix in SUSPICIOUS_PTH_PREFIXES):
        return True
    if '/application support/' in lower:
        return True
    if '/.' in resolved_path or os.path.basename(resolved_path).startswith('.'):
        return True
    if '/site-packages' not in lower and '/dist-packages' not in lower:
        return True
    if home_dir and resolved_path.startswith(home_dir) and \
            not resolved_path.startswith(home_dir + '/Library/Python/'):
        return True
    return False


def _follow_pth_customize_targets(mac_info, candidate_path, python_ver, user_name, uid,
                                   main_rows, detail_rows, processed_customizes):
    '''Process sitecustomize.py / usercustomize.py reached via suspicious .pth paths.'''
    if not candidate_path:
        return
    if mac_info.IsValidFilePath(candidate_path):
        basename = os.path.basename(candidate_path)
        if basename == 'sitecustomize.py':
            process_sitecustomize(mac_info, candidate_path, python_ver, user_name, uid,
                                  'sitecustomize', main_rows, detail_rows,
                                  processed_customizes)
        elif basename == 'usercustomize.py':
            process_sitecustomize(mac_info, candidate_path, python_ver, user_name, uid,
                                  'usercustomize', main_rows, detail_rows,
                                  processed_customizes)
        return

    if not mac_info.IsValidFolderPath(candidate_path):
        return
    for fname, sub_mech in (('sitecustomize.py', 'sitecustomize'),
                            ('usercustomize.py', 'usercustomize')):
        target = candidate_path.rstrip('/') + '/' + fname
        if mac_info.IsValidFilePath(target):
            process_sitecustomize(mac_info, target, python_ver, user_name, uid,
                                  sub_mech, main_rows, detail_rows,
                                  processed_customizes)


def process_pth_file(mac_info, file_path, python_ver, user_name, uid,
                      main_rows, detail_rows, processed_customizes):
    '''Parse a .pth file.
    Only "import ..." lines are executed at startup - they are the persistence risk.
    Path-addition lines are emitted as detail only.'''
    if not mac_info.IsValidFilePath(file_path):
        return
    mac_info.ExportFile(file_path, __Plugin_Name, '', False)
    artifact_mtime = get_file_mtime(mac_info, file_path)

    f = mac_info.Open(file_path)
    if f is None:
        return

    has_exec_lines = False
    home_dir = _infer_home_from_path(file_path)
    try:
        for lineno, raw in enumerate(f, start=1):
            if isinstance(raw, bytes):
                raw = raw.decode('utf-8', errors='replace')
            raw = raw.rstrip()
            stripped = raw.strip()
            if not stripped or stripped.startswith('#'):
                continue

            is_exec = stripped.startswith('import ')

            detail_rows.append(make_detail_row(
                artifact_path=file_path,
                evidence_type='pth_exec_line' if is_exec else 'pth_path_line',
                key_or_line='line:{}'.format(lineno),
                value=stripped,
                user=user_name,
            ))

            if is_exec:
                has_exec_lines = True
                main_rows.append(make_main_row(
                    mechanism='Python Startup',
                    sub_mechanism='pth',
                    scope=get_scope(user_name),
                    user=user_name,
                    uid=uid,
                    artifact_path=file_path,
                    artifact_type='pth_file',
                    target_path=stripped,
                    trigger='python interpreter start',
                    label_or_name=os.path.basename(file_path),
                    artifact_mtime=artifact_mtime,
                    source=file_path,
                ))
            else:
                resolved_path = _resolve_pth_path(file_path, stripped)
                if _is_suspicious_pth_path(resolved_path, home_dir):
                    main_rows.append(make_main_row(
                        mechanism='Python Startup',
                        sub_mechanism='pth_redirect',
                        scope=get_scope(user_name),
                        user=user_name,
                        uid=uid,
                        artifact_path=file_path,
                        artifact_type='pth_file',
                        target_path=resolved_path,
                        target_args=stripped,
                        trigger='python interpreter start',
                        label_or_name=os.path.basename(file_path),
                        artifact_mtime=artifact_mtime,
                        source=file_path,
                    ))
                    _follow_pth_customize_targets(
                        mac_info, resolved_path, python_ver, user_name, uid,
                        main_rows, detail_rows, processed_customizes)
    except Exception:
        log.exception('Error reading {}'.format(file_path))

    # Even if no exec lines, emit a main row for sitecustomize-redirecting .pth files
    if not has_exec_lines:
        # Check for sitecustomize.py path additions (a known bypass technique)
        pass  # path additions alone are not flagged - they go to detail only


def process_site_packages_dir(mac_info, site_packages_dir, python_ver,
                               user_name, uid, main_rows, detail_rows,
                               processed_customizes):
    '''Scan one site-packages directory for startup hooks.'''
    if not mac_info.IsValidFolderPath(site_packages_dir):
        return

    # sitecustomize.py / usercustomize.py
    for fname, sub_mech in (('sitecustomize.py', 'sitecustomize'),
                             ('usercustomize.py', 'usercustomize')):
        process_sitecustomize(
            mac_info,
            site_packages_dir + '/' + fname,
            python_ver, user_name, uid, sub_mech,
            main_rows, detail_rows, processed_customizes)

    # *.pth files
    try:
        items = mac_info.ListItemsInFolder(site_packages_dir, EntryType.FILES, False)
    except Exception:
        return
    for item in items:
        if item['name'].endswith('.pth'):
            process_pth_file(
                mac_info,
                site_packages_dir + '/' + item['name'],
                python_ver, user_name, uid,
                main_rows, detail_rows, processed_customizes)


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def write_output(main_rows, detail_rows, output_params):
    main_col_info = [(c, DataType.TEXT) for c in MAIN_TABLE_COLUMNS]
    for i, (name, _) in enumerate(main_col_info):
        if name in ('ArtifactMTime', 'TargetMTime'):
            main_col_info[i] = (name, DataType.DATE)
    detail_col_info = [(c, DataType.TEXT) for c in DETAIL_TABLE_COLUMNS]

    log.info('Found {} Python startup hook item(s)'.format(len(main_rows)))
    if main_rows:
        WriteList('python startup hooks', 'PYSTARTUP', main_rows,
                  main_col_info, output_params, '')
    if detail_rows:
        WriteList('python startup hooks detail', 'PYSTARTUP_DETAIL', detail_rows,
                  detail_col_info, output_params, '')


# ---------------------------------------------------------------------------
# Plugin entry points
# ---------------------------------------------------------------------------

def Plugin_Start(mac_info):
    main_rows   = []
    detail_rows = []
    processed   = set()
    processed_customizes = set()

    # System-wide site-packages
    for base in SYSTEM_SITE_PACKAGE_BASES:
        for sp_dir in _find_site_packages_dirs(mac_info, base):
            if sp_dir in processed:
                continue
            processed.add(sp_dir)
            python_ver = _guess_version_from_path(sp_dir)
            process_site_packages_dir(mac_info, sp_dir, python_ver,
                                       'root', 0, main_rows, detail_rows,
                                       processed_customizes)

    # Per-user site-packages
    user_processed = set()
    for user in mac_info.users:
        user_name = safe_user_label(user.user_name, user.home_dir)
        if not user_name:
            continue
        if user.home_dir in user_processed:
            continue
        user_processed.add(user.home_dir)

        user_base = user.home_dir + USER_SITE_PACKAGE_BASE
        for sp_dir in _find_site_packages_dirs(mac_info, user_base):
            if sp_dir in processed:
                continue
            processed.add(sp_dir)
            python_ver = _guess_version_from_path(sp_dir)
            process_site_packages_dir(mac_info, sp_dir, python_ver,
                                       user_name, user.UID,
                                       main_rows, detail_rows,
                                       processed_customizes)

    if main_rows or detail_rows:
        write_output(main_rows, detail_rows, mac_info.output_params)
    else:
        log.info('No Python startup hook artifacts found')


def _guess_version_from_path(path):
    '''Extract a Python version string from a path like .../python3.11/...'''
    m = re.search(r'python(3?\.\d+)', path, re.IGNORECASE)
    return 'python' + m.group(1) if m else 'unknown'


def Plugin_Start_Standalone(input_files_list, output_params):
    log.info('Module started as standalone')
    main_rows   = []
    detail_rows = []
    processed_customizes = set()
    fake = _StandaloneMacInfo()

    for input_path in input_files_list:
        log.debug('Input path: ' + input_path)
        basename = os.path.basename(input_path)
        python_ver = _guess_version_from_path(input_path)

        if basename == 'sitecustomize.py':
            process_sitecustomize(fake, input_path, python_ver, '', '',
                                  'sitecustomize', main_rows, detail_rows,
                                  processed_customizes)
        elif basename == 'usercustomize.py':
            process_sitecustomize(fake, input_path, python_ver, '', '',
                                  'usercustomize', main_rows, detail_rows,
                                  processed_customizes)
        elif basename.endswith('.pth'):
            process_pth_file(fake, input_path, python_ver, '', '',
                             main_rows, detail_rows, processed_customizes)
        else:
            log.warning('Unrecognised Python startup artifact: {}'.format(input_path))

    if main_rows or detail_rows:
        write_output(main_rows, detail_rows, output_params)
    else:
        log.info('No Python startup hooks found in provided files')


def _standalone_process(path, python_ver, sub_mech, main_rows, detail_rows):
    import datetime
    mtime = None
    try:
        mtime = datetime.datetime.utcfromtimestamp(os.path.getmtime(path))
    except OSError:
        pass
    main_rows.append(make_main_row(
        mechanism='Python Startup',
        sub_mechanism=sub_mech,
        artifact_path=path,
        artifact_type='python_startup_script',
        target_path=path,
        trigger='python interpreter start',
        label_or_name=os.path.basename(path),
        artifact_mtime=mtime,
        source=path,
    ))
    detail_rows.append(make_detail_row(
        artifact_path=path,
        evidence_type='python_version',
        key_or_line='python_version',
        value=python_ver,
    ))


def _standalone_pth(path, python_ver, main_rows, detail_rows):
    try:
        with open(path, 'rb') as f:
            for lineno, raw in enumerate(f, start=1):
                line = raw.decode('utf-8', errors='replace').rstrip()
                stripped = line.strip()
                if not stripped or stripped.startswith('#'):
                    continue
                is_exec = stripped.startswith('import ')
                detail_rows.append(make_detail_row(
                    artifact_path=path,
                    evidence_type='pth_exec_line' if is_exec else 'pth_path_line',
                    key_or_line='line:{}'.format(lineno),
                    value=stripped,
                ))
                if is_exec:
                    main_rows.append(make_main_row(
                        mechanism='Python Startup',
                        sub_mechanism='pth',
                        artifact_path=path,
                        artifact_type='pth_file',
                        target_path=stripped,
                        trigger='python interpreter start',
                        label_or_name=os.path.basename(path),
                        source=path,
                    ))
    except OSError:
        log.exception('Could not read {}'.format(path))


if __name__ == '__main__':
    print('This plugin is part of a framework and does not run independently.')


class _StandaloneMacInfo:
    '''Minimal stand-in for local artifact-only Python startup parsing.'''
    def IsValidFilePath(self, path):
        return os.path.isfile(path)

    def IsValidFolderPath(self, path):
        return os.path.isdir(path)

    def ExportFile(self, *args, **kwargs):
        return None

    def Open(self, path):
        try:
            return open(path, 'rb')
        except OSError:
            return None

    def GetFileMACTimes(self, path):
        try:
            import datetime
            return {'m_time': datetime.datetime.utcfromtimestamp(os.path.getmtime(path))}
        except OSError:
            return {}
