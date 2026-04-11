'''
   Copyright (c) 2026 jaybird1291

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the
   terms of the MIT License.

   schedpersist.py
   ---------------
   Parses scheduled-execution persistence mechanisms not fully covered by AUTOSTART:
     cron     : /etc/crontab, /usr/lib/cron/tabs/<user>,
                /private/var/at/tabs/<user>
     at       : /private/var/at/jobs/  (spool files)
                /private/etc/at.allow  /private/etc/at.deny
     periodic : /private/etc/periodic.conf, /private/etc/defaults/periodic.conf
                (config-only; script directories are handled by AUTOSTART)

   For cron, each schedule line is parsed into its five time fields plus command.
   For at, each spool file is exported; job metadata is extracted from the file
   header where present.

   Output tables:
     SCHEDPERSIST        - one row per cron job, at job, or policy file
     SCHEDPERSIST_DETAIL - raw schedule line, parsed fields, at-job header lines
'''

import logging
import os
import re

from plugins.helpers.macinfo import *
from plugins.helpers.writer import *
from plugins.helpers.persistence_common import (
    MAIN_TABLE_COLUMNS, DETAIL_TABLE_COLUMNS,
    make_main_row, make_detail_row,
    get_file_mtime, safe_user_label, get_scope,
    extract_target_from_line,
)

__Plugin_Name = "SCHEDPERSIST"
__Plugin_Friendly_Name = "Scheduled Persistence"
__Plugin_Version = "1.0"
__Plugin_Description = "Detects cron, at, and periodic scheduled-execution persistence"
__Plugin_Author = "jaybird1291"
__Plugin_Author_Email = ""
__Plugin_Modes = "MACOS,ARTIFACTONLY"
__Plugin_ArtifactOnly_Usage = "Provide /etc/crontab, a user crontab file, or an at spool file"

log = logging.getLogger('MAIN.' + __Plugin_Name)

#---- Do not change the variable names in above section ----#

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

SYSTEM_CRONTAB       = '/etc/crontab'
USER_CRONTABS_DIRS   = (
    '/usr/lib/cron/tabs',
    '/private/var/at/tabs',
)
AT_JOBS_DIR          = '/private/var/at/jobs'
AT_ALLOW             = '/private/etc/at.allow'
AT_DENY              = '/private/etc/at.deny'

# ---------------------------------------------------------------------------
# Cron line parser
# ---------------------------------------------------------------------------

# Standard 5-field cron: min hour dom month dow command
# @reboot/@yearly/@monthly/@weekly/@daily/@hourly shortcuts (GNU extension)
RE_CRON_STANDARD = re.compile(
    r'^'
    r'(\S+)\s+'   # minute
    r'(\S+)\s+'   # hour
    r'(\S+)\s+'   # day-of-month
    r'(\S+)\s+'   # month
    r'(\S+)\s+'   # day-of-week
    r'(.+)$'      # command
)
RE_CRON_SHORTCUT = re.compile(r'^(@\w+)\s+(.+)$')
RE_CRON_ENV      = re.compile(r'^(\w+)\s*=\s*(.*)$')


def parse_cron_line(line, has_user_field=False):
    '''Parse one crontab line.
    has_user_field=True for /etc/crontab where field 6 is a username.
    Returns dict or None for blank/comment/env lines.'''
    line = line.strip()
    if not line or line.startswith('#'):
        return None

    # Environment assignment (e.g. SHELL=/bin/bash)
    m = RE_CRON_ENV.match(line)
    if m:
        return {'type': 'env', 'key': m.group(1), 'value': m.group(2), 'raw': line}

    # @shortcut
    m = RE_CRON_SHORTCUT.match(line)
    if m:
        shortcut = m.group(1)
        rest     = m.group(2).strip()
        if has_user_field:
            parts = rest.split(None, 1)
            user  = parts[0] if parts else ''
            cmd   = parts[1].strip() if len(parts) > 1 else ''
        else:
            user = ''
            cmd  = rest
        return {
            'type':    'shortcut',
            'minute':  shortcut,
            'hour': '', 'dom': '', 'month': '', 'dow': '',
            'user':    user,
            'command': cmd,
            'trigger': shortcut,
            'raw':     line,
        }

    # Standard 5-field
    m = RE_CRON_STANDARD.match(line)
    if m:
        minute, hour, dom, month, dow, rest = m.groups()
        if has_user_field:
            parts = rest.strip().split(None, 1)
            user  = parts[0] if parts else ''
            cmd   = parts[1].strip() if len(parts) > 1 else ''
        else:
            user = ''
            cmd  = rest.strip()
        trigger = '{} {} {} {} {}'.format(minute, hour, dom, month, dow)
        return {
            'type':    'schedule',
            'minute':  minute,
            'hour':    hour,
            'dom':     dom,
            'month':   month,
            'dow':     dow,
            'user':    user,
            'command': cmd,
            'trigger': trigger,
            'raw':     line,
        }

    return None


def process_crontab(mac_info, file_path, file_user, file_uid,
                    has_user_field, main_rows, detail_rows):
    '''Parse a crontab file and append rows.'''
    mac_info.ExportFile(file_path, __Plugin_Name, '', False)
    artifact_mtime = get_file_mtime(mac_info, file_path)

    f = mac_info.Open(file_path)
    if f is None:
        log.error('Could not open {}'.format(file_path))
        return

    try:
        for lineno, raw in enumerate(f, start=1):
            if isinstance(raw, bytes):
                raw = raw.decode('utf-8', errors='replace')
            raw = raw.rstrip()
            parsed = parse_cron_line(raw, has_user_field)
            if parsed is None:
                continue

            if parsed['type'] == 'env':
                detail_rows.append(make_detail_row(
                    artifact_path=file_path,
                    evidence_type='cron_env',
                    key_or_line=parsed['key'],
                    value=parsed['value'],
                    user=file_user,
                ))
                continue

            # Resolve who runs this job
            job_user = parsed.get('user') or file_user or 'root'
            cmd      = parsed['command']
            target, args = extract_target_from_line(cmd)

            main_rows.append(make_main_row(
                mechanism='Scheduled Persistence',
                sub_mechanism='cron',
                scope=get_scope(job_user),
                user=job_user,
                uid=file_uid if not parsed.get('user') else '',
                artifact_path=file_path,
                artifact_type='crontab',
                target_path=target,
                target_args=args or (cmd if not target else ''),
                trigger=parsed['trigger'],
                label_or_name=os.path.basename(file_path),
                artifact_mtime=artifact_mtime,
                source=file_path,
            ))
            detail_rows.append(make_detail_row(
                artifact_path=file_path,
                evidence_type='cron_line',
                key_or_line='line:{}'.format(lineno),
                value=raw.strip(),
                resolved_path=target,
                user=job_user,
            ))
    except Exception:
        log.exception('Error reading {}'.format(file_path))


# ---------------------------------------------------------------------------
# at jobs processor
# ---------------------------------------------------------------------------

# at spool files are shell scripts with a header section delimited by comments.
# The header typically contains lines like:
#   #!/bin/sh
#   # atrun uid=501 gid=20
#   # mail foo 0
#   umask 22
# followed by the actual job commands.

RE_AT_UID = re.compile(r'#\s*atrun\s+uid=(\d+)\s+gid=(\d+)', re.IGNORECASE)


def process_at_job(mac_info, file_path, main_rows, detail_rows):
    '''Parse a single at spool file.'''
    mac_info.ExportFile(file_path, __Plugin_Name, '', False)
    artifact_mtime = get_file_mtime(mac_info, file_path)
    job_name = os.path.basename(file_path)

    uid_str = ''
    gid_str = ''
    header_lines = []
    cmd_lines    = []
    in_header    = True

    f = mac_info.Open(file_path)
    if f is None:
        return

    try:
        for raw in f:
            if isinstance(raw, bytes):
                raw = raw.decode('utf-8', errors='replace')
            raw = raw.rstrip()

            m = RE_AT_UID.search(raw)
            if m:
                uid_str = m.group(1)
                gid_str = m.group(2)

            if in_header and (raw.startswith('#') or raw.startswith('umask') or not raw.strip()):
                header_lines.append(raw)
            else:
                in_header = False
                if raw.strip():
                    cmd_lines.append(raw)
    except Exception:
        log.exception('Error reading at spool {}'.format(file_path))

    # Resolve uid to user name - best-effort (no mac_info.users in standalone)
    first_cmd = cmd_lines[0].strip() if cmd_lines else ''
    target, args = extract_target_from_line(first_cmd) if first_cmd else ('', '')

    main_rows.append(make_main_row(
        mechanism='Scheduled Persistence',
        sub_mechanism='at',
        scope=get_scope(uid_str),
        uid=uid_str,
        artifact_path=file_path,
        artifact_type='at_spool',
        target_path=target,
        target_args=args or (first_cmd if not target else ''),
        trigger='deferred one-shot',
        label_or_name=job_name,
        artifact_mtime=artifact_mtime,
        source=file_path,
    ))
    for i, line in enumerate(cmd_lines[:20]):  # cap detail rows per job
        detail_rows.append(make_detail_row(
            artifact_path=file_path,
            evidence_type='at_job_line',
            key_or_line='cmd:{}'.format(i + 1),
            value=line.strip(),
        ))


def process_at_policy_file(mac_info, file_path, main_rows, detail_rows):
    '''at.allow / at.deny: emit one main row for the file, detail rows per entry.'''
    mac_info.ExportFile(file_path, __Plugin_Name, '', False)
    artifact_mtime = get_file_mtime(mac_info, file_path)
    fname = os.path.basename(file_path)

    main_rows.append(make_main_row(
        mechanism='Scheduled Persistence',
        sub_mechanism='at',
        scope='system',
        user='root',
        artifact_path=file_path,
        artifact_type=fname,
        trigger='deferred one-shot',
        label_or_name=fname,
        artifact_mtime=artifact_mtime,
        source=file_path,
    ))
    f = mac_info.Open(file_path)
    if f is None:
        return
    try:
        for raw in f:
            if isinstance(raw, bytes):
                raw = raw.decode('utf-8', errors='replace')
            entry = raw.strip()
            if entry and not entry.startswith('#'):
                detail_rows.append(make_detail_row(
                    artifact_path=file_path,
                    evidence_type='at_policy_entry',
                    key_or_line=fname,
                    value=entry,
                ))
    except Exception:
        log.exception('Error reading {}'.format(file_path))


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def write_output(main_rows, detail_rows, output_params):
    main_col_info = [(c, DataType.TEXT) for c in MAIN_TABLE_COLUMNS]
    for i, (name, _) in enumerate(main_col_info):
        if name in ('ArtifactMTime', 'TargetMTime'):
            main_col_info[i] = (name, DataType.DATE)

    detail_col_info = [(c, DataType.TEXT) for c in DETAIL_TABLE_COLUMNS]

    log.info('Found {} scheduled persistence item(s)'.format(len(main_rows)))
    if main_rows:
        WriteList('scheduled persistence', 'SCHEDPERSIST', main_rows,
                  main_col_info, output_params, '')
    if detail_rows:
        WriteList('scheduled persistence detail', 'SCHEDPERSIST_DETAIL', detail_rows,
                  detail_col_info, output_params, '')


# ---------------------------------------------------------------------------
# Plugin entry points
# ---------------------------------------------------------------------------

def Plugin_Start(mac_info):
    '''Main entry point for plugin'''
    main_rows   = []
    detail_rows = []
    processed   = set()

    # System crontab (/etc/crontab has a user field)
    for cron_path in ('/etc/crontab', '/private/etc/crontab'):
        if cron_path in processed:
            continue
        if mac_info.IsValidFilePath(cron_path):
            processed.add(cron_path)
            process_crontab(mac_info, cron_path, 'root', 0,
                            has_user_field=True,
                            main_rows=main_rows, detail_rows=detail_rows)
            break  # /etc is a symlink to /private/etc; process only once

    # Per-user crontabs in legacy and modern spool locations.
    # Newer macOS versions commonly store these in /private/var/at/tabs/.
    seen_tab_names = set()
    for user_crontabs_dir in USER_CRONTABS_DIRS:
        if not mac_info.IsValidFolderPath(user_crontabs_dir):
            continue
        try:
            items = mac_info.ListItemsInFolder(user_crontabs_dir, EntryType.FILES, False)
        except Exception:
            items = []
        for item in items:
            tab_name = item['name']
            if tab_name in seen_tab_names:
                continue
            tab_path = user_crontabs_dir + '/' + tab_name
            if tab_path in processed:
                continue
            processed.add(tab_path)
            seen_tab_names.add(tab_name)
            # Resolve uid from filename if it's numeric, else use name as-is
            tab_user = tab_name
            tab_uid  = ''
            for u in mac_info.users:
                if u.user_name == tab_user:
                    tab_uid = u.UID
                    break
            process_crontab(mac_info, tab_path, tab_user, tab_uid,
                            has_user_field=False,
                            main_rows=main_rows, detail_rows=detail_rows)

    # at jobs spool
    for at_dir in (AT_JOBS_DIR, '/usr/lib/cron/jobs'):
        if at_dir in processed:
            continue
        if mac_info.IsValidFolderPath(at_dir):
            processed.add(at_dir)
            try:
                items = mac_info.ListItemsInFolder(at_dir, EntryType.FILES, False)
            except Exception:
                items = []
            for item in items:
                job_path = at_dir + '/' + item['name']
                # at spool files are typically named like "a000010185f4380"
                # Skip lock files, etc.
                if item['name'].startswith('.'):
                    continue
                process_at_job(mac_info, job_path, main_rows, detail_rows)

    # at.allow / at.deny
    for policy_path in (AT_ALLOW, AT_DENY):
        if mac_info.IsValidFilePath(policy_path):
            process_at_policy_file(mac_info, policy_path, main_rows, detail_rows)

    if main_rows or detail_rows:
        write_output(main_rows, detail_rows, mac_info.output_params)
    else:
        log.info('No scheduled persistence artifacts found')


def Plugin_Start_Standalone(input_files_list, output_params):
    '''Entry point for single-artifact mode'''
    log.info('Module started as standalone')
    main_rows   = []
    detail_rows = []
    fake = _StandaloneMacInfo()

    for input_path in input_files_list:
        log.debug('Input path: ' + input_path)
        basename = os.path.basename(input_path)

        if basename == 'crontab' or input_path.endswith('/crontab'):
            _standalone_crontab(input_path, has_user_field=(basename == 'crontab'),
                                main_rows=main_rows, detail_rows=detail_rows)
        elif basename in ('at.allow', 'at.deny'):
            _standalone_policy(input_path, main_rows, detail_rows)
        elif _looks_like_at_job(input_path):-
            process_at_job(fake, input_path, main_rows, detail_rows)
        else:
            # Treat anything else as a user crontab.
            _standalone_crontab(input_path, has_user_field=False,
                                main_rows=main_rows, detail_rows=detail_rows)

    if main_rows or detail_rows:
        write_output(main_rows, detail_rows, output_params)
    else:
        log.info('No scheduled persistence found in provided files')


def _standalone_crontab(path, has_user_field, main_rows, detail_rows):
    try:
        with open(path, 'rb') as f:
            for lineno, raw in enumerate(f, start=1):
                raw = raw.decode('utf-8', errors='replace').rstrip()
                parsed = parse_cron_line(raw, has_user_field)
                if parsed is None or parsed['type'] == 'env':
                    continue
                cmd = parsed['command']
                target, args = extract_target_from_line(cmd)
                main_rows.append(make_main_row(
                    mechanism='Scheduled Persistence',
                    sub_mechanism='cron',
                    artifact_path=path,
                    artifact_type='crontab',
                    target_path=target,
                    target_args=args or (cmd if not target else ''),
                    trigger=parsed['trigger'],
                    label_or_name=os.path.basename(path),
                    source=path,
                ))
                detail_rows.append(make_detail_row(
                    artifact_path=path,
                    evidence_type='cron_line',
                    key_or_line='line:{}'.format(lineno),
                    value=raw.strip(),
                    resolved_path=target,
                ))
    except OSError:
        log.exception('Could not read {}'.format(path))


def _standalone_policy(path, main_rows, detail_rows):
    fname = os.path.basename(path)
    main_rows.append(make_main_row(
        mechanism='Scheduled Persistence',
        sub_mechanism='at',
        artifact_path=path,
        artifact_type=fname,
        trigger='deferred one-shot',
        label_or_name=fname,
        source=path,
    ))
    try:
        with open(path, 'rb') as f:
            for raw in f:
                entry = raw.decode('utf-8', errors='replace').strip()
                if entry and not entry.startswith('#'):
                    detail_rows.append(make_detail_row(
                        artifact_path=path,
                        evidence_type='at_policy_entry',
                        key_or_line=fname,
                        value=entry,
                    ))
    except OSError:
        log.exception('Could not read {}'.format(path))


def _looks_like_at_job(path):
    '''Return True when a local file looks like an at spool job.'''
    try:
        with open(path, 'rb') as f:
            for _ in range(12):
                raw = f.readline()
                if not raw:
                    break
                line = raw.decode('utf-8', errors='replace').strip()
                if RE_AT_UID.search(line):
                    return True
                if line.startswith('# mail ') or line.startswith('umask '):
                    return True
    except OSError:
        return False
    return False


class _StandaloneMacInfo:
    '''Minimal stand-in for standalone at spool parsing.'''
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


if __name__ == '__main__':
    print('This plugin is part of a framework and does not run independently.')
