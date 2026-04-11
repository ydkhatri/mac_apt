'''
   Copyright (c) 2026 jaybird1291

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the
   terms of the MIT License.

   persistence_common.py
   ---------------------
   Shared helpers for persistence plugins:
   - Normalized row creation for main and detail tables
   - Scope/user resolution
   - Safe timestamp accessors
   - Source path normalization utilities
'''

import logging
import os

log = logging.getLogger('MAIN.HELPERS.PERSISTENCE_COMMON')


# ---------------------------------------------------------------------------
# Scope resolution
# ---------------------------------------------------------------------------

def get_scope(user):
    '''Return "system", "user", or "mixed" based on the user string.'''
    if not user or user in ('root', '0'):
        return 'system'
    return 'user'


def safe_user_label(user_name, home_dir):
    '''Return a clean user label, collapsing system pseudo-accounts to "root".'''
    if home_dir in ('/private/var/empty', '/var/empty'):
        return ''
    if home_dir in ('/private/var/root', '/var/root'):
        return 'root'
    return user_name or ''


# ---------------------------------------------------------------------------
# Main table row factory
# ---------------------------------------------------------------------------
# Column contract for all persistence main tables.
# Plugins populate what they know; unknown fields stay ''.

MAIN_TABLE_COLUMNS = [
    'Mechanism',
    'SubMechanism',
    'Scope',
    'User',
    'UID',
    'ArtifactPath',
    'ArtifactType',
    'TargetPath',
    'TargetArgs',
    'Trigger',
    'Enabled',
    'OwnerAppPath',
    'OwnerBundleID',
    'LabelOrName',
    'Signer',
    'TeamID',
    'CodeSignStatus',
    'SHA256',
    'ArtifactMTime',
    'TargetMTime',
    'Source',
]

DETAIL_TABLE_COLUMNS = [
    'ArtifactPath',
    'EvidenceType',
    'KeyOrLine',
    'Value',
    'ResolvedPath',
    'User',
    'Source',
]


def make_main_row(
    mechanism='',
    sub_mechanism='',
    scope='',
    user='',
    uid='',
    artifact_path='',
    artifact_type='',
    target_path='',
    target_args='',
    trigger='',
    enabled='',
    owner_app_path='',
    owner_bundle_id='',
    label_or_name='',
    signer='',
    team_id='',
    codesign_status='',
    sha256='',
    artifact_mtime=None,
    target_mtime=None,
    source='',
):
    '''Return an ordered list matching MAIN_TABLE_COLUMNS.
    Pass only the fields you know; everything else defaults to empty string.'''
    return [
        mechanism,
        sub_mechanism,
        scope or get_scope(user),
        user,
        str(uid) if uid not in ('', None) else '',
        artifact_path,
        artifact_type,
        target_path,
        target_args,
        trigger,
        enabled,
        owner_app_path,
        owner_bundle_id,
        label_or_name,
        signer,
        team_id,
        codesign_status,
        sha256,
        artifact_mtime,   # datetime or None; writer handles DATE type
        target_mtime,
        source or artifact_path,
    ]


def make_detail_row(
    artifact_path='',
    evidence_type='',
    key_or_line='',
    value='',
    resolved_path='',
    user='',
    source='',
):
    '''Return an ordered list matching DETAIL_TABLE_COLUMNS.'''
    return [
        artifact_path,
        evidence_type,
        key_or_line,
        value,
        resolved_path,
        user,
        source or artifact_path,
    ]


# ---------------------------------------------------------------------------
# File MAC-time helper
# ---------------------------------------------------------------------------

def get_file_mtime(mac_info, path):
    '''Return the mtime datetime for path, or None if unavailable.'''
    try:
        times = mac_info.GetFileMACTimes(path)
        return times.get('m_time', None)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Symlink resolution
# ---------------------------------------------------------------------------

def resolve_path(mac_info, path):
    '''Resolve one level of symlink. Returns the resolved path or the original.'''
    try:
        if mac_info.IsSymbolicLink(path):
            target = mac_info.ReadSymLinkTargetPath(path)
            if target:
                if target.startswith('../') or target.startswith('./'):
                    import posixpath
                    return posixpath.normpath(
                        posixpath.join(posixpath.dirname(path), target)
                    )
                return target
    except Exception:
        pass
    return path


# ---------------------------------------------------------------------------
# Target extraction from shell-ish lines
# ---------------------------------------------------------------------------

def extract_target_from_line(line):
    '''Best-effort extraction of the first executable token from a shell line.
    Returns (target_path, remaining_args) or ('', '') if line is unrecognisable.
    Very conservative - only returns something if the token looks like a path.'''
    import shlex
    line = line.strip()
    if not line or line.startswith('#'):
        return '', ''
    # Strip leading env-var assignments (FOO=bar cmd args)
    # and common prefixes like sudo, exec, nohup
    skip_tokens = {'sudo', 'exec', 'nohup', 'env', 'command'}
    try:
        tokens = shlex.split(line, posix=True)
    except ValueError:
        tokens = line.split()
    filtered = []
    for t in tokens:
        if '=' in t and not t.startswith('/') and not filtered:
            continue   # env assignment
        filtered.append(t)
    if not filtered:
        return '', ''
    cmd = filtered[0]
    while cmd in skip_tokens and len(filtered) > 1:
        filtered = filtered[1:]
        cmd = filtered[0]
    # Only claim a target if it looks like an absolute path or known relative prefix
    if cmd.startswith('/') or cmd.startswith('./') or cmd.startswith('../'):
        args = ' '.join(filtered[1:]) if len(filtered) > 1 else ''
        return cmd, args
    return '', ''
