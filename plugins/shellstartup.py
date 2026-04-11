'''
   Copyright (c) 2026 jaybird1291

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the
   terms of the MIT License.

   shellstartup.py
   ---------------
   Detects persistence in shell startup files (zsh, bash, sh) and
   environment-variable indirection (ZDOTDIR, ENV, BASH_ENV).

   Artifact families covered:
     zsh  : /etc/zshenv /etc/zprofile /etc/zshrc /etc/zlogin /etc/zlogout
             ~/.zshenv  ~/.zprofile   ~/.zshrc   ~/.zlogin   ~/.zlogout
     bash : /etc/profile /etc/bashrc
             ~/.bash_profile ~/.bash_login ~/.bashrc ~/.bash_logout ~/.profile
     sh   : covered by ~/.profile / /etc/profile

   For each file, every non-blank, non-comment line is recorded.
   Lines that contain:
     - explicit source/.  → TargetPath = sourced file
     - env-indirection vars (ZDOTDIR, ENV, BASH_ENV) → SubMechanism = env-indirection
     - direct executable/script invocations → TargetPath = binary/script
   are emitted as main-table rows.  All other non-trivial lines are emitted
   only as detail rows so downstream analysis can triage them.

   Output tables:
     SHELLSTARTUP        - one row per persistence-relevant line or downstream target
     SHELLSTARTUP_DETAIL - raw non-comment lines with line number and extracted command
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
    extract_target_from_line,
)

__Plugin_Name = "SHELLSTARTUP"
__Plugin_Friendly_Name = "Shell Startup Files"
__Plugin_Version = "1.0"
__Plugin_Description = "Detects persistence in zsh/bash/sh startup files and env-variable indirection"
__Plugin_Author = "jaybird1291"
__Plugin_Author_Email = ""
__Plugin_Modes = "MACOS,ARTIFACTONLY"
__Plugin_ArtifactOnly_Usage = "Provide one or more shell startup files (e.g. .zshrc, .bash_profile)"

log = logging.getLogger('MAIN.' + __Plugin_Name)

#---- Do not change the variable names in above section ----#

# ---------------------------------------------------------------------------
# Artifact path definitions
# ---------------------------------------------------------------------------

# System-wide files: (path, shell_family)
SYSTEM_SHELL_FILES = [
    ('/private/etc/zshenv',   'zsh'),
    ('/private/etc/zprofile', 'zsh'),
    ('/private/etc/zshrc',    'zsh'),
    ('/private/etc/zlogin',   'zsh'),
    ('/private/etc/zlogout',  'zsh'),
    ('/private/etc/profile',  'sh'),
    ('/private/etc/bashrc',   'bash'),
]

# Per-user files relative to home_dir: (relative_path, shell_family)
USER_SHELL_FILES = [
    ('/.zshenv',       'zsh'),
    ('/.zprofile',     'zsh'),
    ('/.zshrc',        'zsh'),
    ('/.zlogin',       'zsh'),
    ('/.zlogout',      'zsh'),
    ('/.bash_profile', 'bash'),
    ('/.bash_login',   'bash'),
    ('/.bashrc',       'bash'),
    ('/.bash_logout',  'bash'),
    ('/.profile',      'sh'),
]

# Environment variables that redirect shell startup to a different path
ENV_INDIRECTION_VARS = {'ZDOTDIR', 'ENV', 'BASH_ENV'}
ZSH_REDIRECT_FILES = ('.zshenv', '.zprofile', '.zshrc', '.zlogin', '.zlogout')
MAX_STARTUP_RECURSION_DEPTH = 5

# Regex patterns
RE_SOURCE = re.compile(r'^(?:source|\.)\s+(?:"([^"]+)"|\'([^\']+)\'|([^\s;#]+))')
RE_ENV_VAR = re.compile(r'(?:^|[\s;])(ZDOTDIR|ENV|BASH_ENV)\s*=\s*["\']?([^"\';\s]+)["\']?')
RE_COMMENT = re.compile(r'^\s*#')
RE_BLANK   = re.compile(r'^\s*$')


# ---------------------------------------------------------------------------
# Core line parser
# ---------------------------------------------------------------------------

def classify_line(line):
    '''Classify a stripped shell line.
    Returns (line_type, target_path, args) where line_type is one of:
      'source'         – explicit source/. command
      'env-indirection'– ZDOTDIR / ENV / BASH_ENV assignment
      'exec'           – direct binary/script invocation we can extract a path from
      'other'          – non-empty, non-comment line we cannot classify further
      'skip'           – blank or comment
    '''
    raw = line.strip()
    if RE_BLANK.match(raw) or RE_COMMENT.match(raw):
        return 'skip', '', ''

    # source / . file
    m = RE_SOURCE.match(raw)
    if m:
        target = m.group(1) or m.group(2) or m.group(3) or ''
        return 'source', target, ''

    # env-indirection variable
    m = RE_ENV_VAR.search(raw)
    if m:
        return 'env-indirection', m.group(2), ''

    # direct executable invocation
    target, args = extract_target_from_line(raw)
    if target:
        return 'exec', target, args

    return 'other', '', ''


def _get_env_assignment(line):
    m = RE_ENV_VAR.search(line.strip())
    if not m:
        return '', ''
    return m.group(1), m.group(2)


def _expand_shell_vars(path, home_dir, env_map):
    if not path:
        return ''

    def repl(match):
        var = match.group(1) or match.group(2)
        if var == 'HOME':
            return home_dir or match.group(0)
        return env_map.get(var, match.group(0))

    expanded = re.sub(r'\$(\w+)|\$\{([^}]+)\}', repl, path)
    if expanded == '~':
        expanded = home_dir or expanded
    elif expanded.startswith('~/'):
        expanded = posixpath.join(home_dir, expanded[2:]) if home_dir else expanded
    return expanded


def _resolve_shell_target(raw_target, current_file_path, home_dir, env_map):
    target = _expand_shell_vars(raw_target, home_dir, env_map).strip()
    if not target:
        return ''
    if '$' in target:
        return ''
    if target.startswith('/'):
        return posixpath.normpath(target)
    return posixpath.normpath(posixpath.join(posixpath.dirname(current_file_path), target))


# ---------------------------------------------------------------------------
# Per-file processor
# ---------------------------------------------------------------------------

def process_shell_file(mac_info, file_path, shell_family, user_name, uid,
                       main_rows, detail_rows, home_dir=None,
                       visited=None, depth=0, env_map=None):
    '''Parse one shell startup file and append rows to main_rows / detail_rows.'''
    if depth > MAX_STARTUP_RECURSION_DEPTH:
        return
    if visited is None:
        visited = set()
    file_path = posixpath.normpath(file_path)
    if file_path in visited or not mac_info.IsValidFilePath(file_path):
        return
    visited.add(file_path)

    if home_dir is None:
        home_dir = ''
    if env_map is None:
        env_map = {}
    local_env = dict(env_map)
    if home_dir:
        local_env.setdefault('HOME', home_dir)

    mac_info.ExportFile(file_path, __Plugin_Name, '', False)
    artifact_mtime = get_file_mtime(mac_info, file_path)

    f = mac_info.Open(file_path)
    if f is None:
        log.error('Could not open {}'.format(file_path))
        return

    scope = get_scope(user_name)

    try:
        for lineno, raw_bytes in enumerate(f, start=1):
            if isinstance(raw_bytes, bytes):
                raw = raw_bytes.decode('utf-8', errors='replace')
            else:
                raw = raw_bytes
            raw = raw.rstrip('\n').rstrip('\r')

            line_type, target, args = classify_line(raw)
            if line_type == 'skip':
                continue
            resolved_target = _resolve_shell_target(target, file_path, home_dir, local_env) if target else ''

            # Always emit a detail row for every non-trivial line
            detail_rows.append(make_detail_row(
                artifact_path=file_path,
                evidence_type='shell_line',
                key_or_line='line:{}'.format(lineno),
                value=raw.strip(),
                resolved_path=resolved_target,
                user=user_name,
            ))

            # Emit a main row only for actionable line types
            if line_type in ('source', 'env-indirection', 'exec'):
                sub_mech = shell_family
                if line_type == 'env-indirection':
                    sub_mech = 'env-indirection'

                trigger_map = {
                    'zsh':  'login shell / interactive / logout',
                    'bash': 'login shell / interactive',
                    'sh':   'login shell',
                    'env-indirection': 'shell startup',
                }
                trigger = trigger_map.get(sub_mech, 'shell startup')

                main_rows.append(make_main_row(
                    mechanism='Shell Startup',
                    sub_mechanism=sub_mech,
                    scope=scope,
                    user=user_name,
                    uid=uid,
                    artifact_path=file_path,
                    artifact_type='shell_rc',
                    target_path=resolved_target or target,
                    target_args=args,
                    trigger=trigger,
                    label_or_name=os.path.basename(file_path),
                    artifact_mtime=artifact_mtime,
                    source=file_path,
                ))

                if line_type == 'source' and resolved_target:
                    process_shell_file(mac_info, resolved_target, shell_family,
                                       user_name, uid, main_rows, detail_rows,
                                       home_dir, visited, depth + 1, local_env)
                elif line_type == 'env-indirection':
                    env_name, env_value = _get_env_assignment(raw)
                    if env_name:
                        local_env[env_name] = resolved_target or env_value
                        if env_name == 'ZDOTDIR' and resolved_target and \
                                mac_info.IsValidFolderPath(resolved_target):
                            for fname in ZSH_REDIRECT_FILES:
                                redirected = resolved_target.rstrip('/') + '/' + fname
                                process_shell_file(
                                    mac_info, redirected, 'zsh', user_name, uid,
                                    main_rows, detail_rows, home_dir,
                                    visited, depth + 1, local_env)
                        elif env_name in ('ENV', 'BASH_ENV') and resolved_target:
                            redirected_family = 'bash' if env_name == 'BASH_ENV' else 'sh'
                            process_shell_file(
                                mac_info, resolved_target, redirected_family,
                                user_name, uid, main_rows, detail_rows,
                                home_dir, visited, depth + 1, local_env)

    except Exception:
        log.exception('Error processing {}'.format(file_path))


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def write_output(main_rows, detail_rows, output_params):
    from plugins.helpers.writer import DataType

    main_col_info = [(c, DataType.TEXT) for c in MAIN_TABLE_COLUMNS]
    # ArtifactMTime and TargetMTime are DATE
    for i, (name, _) in enumerate(main_col_info):
        if name in ('ArtifactMTime', 'TargetMTime'):
            main_col_info[i] = (name, DataType.DATE)

    detail_col_info = [(c, DataType.TEXT) for c in DETAIL_TABLE_COLUMNS]

    log.info('Found {} shell startup persistence item(s)'.format(len(main_rows)))
    if main_rows:
        WriteList('shell startup persistence', 'SHELLSTARTUP', main_rows,
                  main_col_info, output_params, '')
    if detail_rows:
        WriteList('shell startup raw lines', 'SHELLSTARTUP_DETAIL', detail_rows,
                  detail_col_info, output_params, '')


# ---------------------------------------------------------------------------
# Plugin entry points
# ---------------------------------------------------------------------------

def Plugin_Start(mac_info):
    '''Main entry point for plugin'''
    main_rows = []
    detail_rows = []
    processed_paths = set()
    visited_shell_files = set()

    # System-wide files
    for file_path, shell_family in SYSTEM_SHELL_FILES:
        if file_path in processed_paths:
            continue
        if mac_info.IsValidFilePath(file_path):
            processed_paths.add(file_path)
            process_shell_file(mac_info, file_path, shell_family, 'root', 0,
                                main_rows, detail_rows, '',
                                visited_shell_files, 0, {})

    # Per-user files
    for user in mac_info.users:
        user_name = safe_user_label(user.user_name, user.home_dir)
        if not user_name:
            continue
        if user.home_dir in processed_paths:
            continue
        processed_paths.add(user.home_dir)

        for rel_path, shell_family in USER_SHELL_FILES:
            file_path = user.home_dir + rel_path
            if file_path in processed_paths:
                continue
            if mac_info.IsValidFilePath(file_path):
                processed_paths.add(file_path)
                process_shell_file(mac_info, file_path, shell_family,
                                   user_name, user.UID,
                                   main_rows, detail_rows, user.home_dir,
                                   visited_shell_files, 0, {})

    if main_rows or detail_rows:
        write_output(main_rows, detail_rows, mac_info.output_params)
    else:
        log.info('No shell startup persistence artifacts found')


def Plugin_Start_Standalone(input_files_list, output_params):
    '''Entry point for single-artifact mode (mac_apt_artifact_only)'''
    log.info('Module started as standalone')

    # Guess shell family from filename
    _family_map = {
        'zshenv': 'zsh', 'zprofile': 'zsh', 'zshrc': 'zsh',
        'zlogin': 'zsh', 'zlogout': 'zsh',
        'bash_profile': 'bash', 'bash_login': 'bash',
        'bashrc': 'bash', 'bash_logout': 'bash',
        'profile': 'sh', 'bashrc': 'bash',
    }

    main_rows = []
    detail_rows = []
    visited_shell_files = set()
    fake = _StandaloneMacInfo()

    for input_path in input_files_list:
        log.debug('Input path: ' + input_path)
        basename = os.path.basename(input_path).lstrip('.')
        shell_family = _family_map.get(basename, 'sh')
        process_shell_file(fake, input_path, shell_family, '', '',
                           main_rows, detail_rows, '',
                           visited_shell_files, 0, {})

    if main_rows or detail_rows:
        write_output(main_rows, detail_rows, output_params)
    else:
        log.info('No shell startup persistence found in provided files')


if __name__ == '__main__':
    print('This plugin is part of a framework and does not run independently.')


class _StandaloneMacInfo:
    '''Minimal stand-in for artifact-only shell startup parsing.'''
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
