'''
   Copyright (c) 2026 jaybird1291

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the
   terms of the MIT License.

   sshpersist.py
   -------------
   Detects SSH-based persistence and session-start execution.

   Artifact families covered:
     authorized_keys : ~/.ssh/authorized_keys
                       (command= forced commands, key access grants)
     ssh_config      : ~/.ssh/config
                       (ProxyCommand, IdentityFile to unusual paths)
     sshd_policy     : /etc/ssh/sshd_config
                       (AuthorizedKeysFile, AuthorizedKeysCommand,
                        ForceCommand, PermitRootLogin)
     ssh_rc          : ~/.ssh/rc  (executed at every SSH session start)
     security_dir    : ~/.security/ (PAM SSH / helper files)

   Output tables:
     SSHPERSIST        - one row per key entry, rc file, or high-interest directive
     SSHPERSIST_DETAIL - full key options, fingerprint, raw config lines
'''

import base64
import fnmatch
import hashlib
import logging
import os
import posixpath
import re
import shlex

from plugins.helpers.macinfo import *
from plugins.helpers.writer import *
from plugins.helpers.persistence_common import (
    MAIN_TABLE_COLUMNS, DETAIL_TABLE_COLUMNS,
    make_main_row, make_detail_row,
    get_file_mtime, safe_user_label, get_scope,
)

__Plugin_Name = "SSHPERSIST"
__Plugin_Friendly_Name = "SSH Persistence"
__Plugin_Version = "1.0"
__Plugin_Description = "Detects SSH-based persistence: authorized keys, forced commands, sshd policy, session rc"
__Plugin_Author = "jaybird1291"
__Plugin_Author_Email = ""
__Plugin_Modes = "MACOS,ARTIFACTONLY"
__Plugin_ArtifactOnly_Usage = "Provide authorized_keys, sshd_config, or ~/.ssh/rc files"

log = logging.getLogger('MAIN.' + __Plugin_Name)

#---- Do not change the variable names in above section ----#

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SSHD_CONFIG_PATHS = [
    '/private/etc/ssh/sshd_config',
    '/etc/ssh/sshd_config',
]

# Key types recognised in authorized_keys lines (longest first for matching)
KNOWN_KEY_TYPES = sorted([
    'sk-ssh-ed25519@openssh.com',
    'sk-ecdsa-sha2-nistp256@openssh.com',
    'ssh-rsa-cert-v01@openssh.com',
    'ssh-ed25519-cert-v01@openssh.com',
    'ecdsa-sha2-nistp256',
    'ecdsa-sha2-nistp384',
    'ecdsa-sha2-nistp521',
    'ssh-ed25519',
    'ssh-rsa',
    'ssh-dss',
], key=len, reverse=True)

# sshd_config directives that are persistence- or policy-relevant
SSHD_INTEREST = {
    'authorizedkeysfile',
    'authorizedkeyscommand',
    'authorizedkeyscommanduser',
    'forcecommand',
    'permitrootlogin',
    'passwordauthentication',
    'permitemptypasswords',
    'challengeresponseauthentication',
    'pubkeyauthentication',
    'usepam',
    'allowusers',
    'denyusers',
    'allowgroups',
    'denygroups',
    'match',
}

# ssh client config directives of interest
SSH_CLIENT_INTEREST = {
    'proxycommand',
    'identityfile',
    'remotecommand',
    'localcommand',
    'proxyjump',
}

RE_UNRESOLVED_TEMPLATE = re.compile(r'%(?:h|u|U)')


def _strip_unquoted_comment(line):
    '''Strip sshd-style comments while preserving quoted # characters.'''
    result = []
    quote = ''
    escape = False
    for ch in line:
        if escape:
            result.append(ch)
            escape = False
            continue
        if ch == '\\':
            result.append(ch)
            escape = True
            continue
        if quote:
            result.append(ch)
            if ch == quote:
                quote = ''
            continue
        if ch in ('"', "'"):
            result.append(ch)
            quote = ch
            continue
        if ch == '#':
            break
        result.append(ch)
    return ''.join(result)


def _split_config_value(value):
    '''Split a config value using ssh/sh quoting rules when possible.'''
    try:
        return shlex.split(value)
    except ValueError:
        return value.split()


def _parse_match_context(value):
    '''Parse a Match line into a small context record.'''
    tokens = _split_config_value(value)
    context = {
        'raw': value,
        'criteria': [],
        'user_patterns': [],
        'all': False,
        'followable': False,
    }
    if not tokens:
        return context
    if len(tokens) == 1 and tokens[0].lower() == 'all':
        context['criteria'].append(('all', ''))
        context['all'] = True
        context['followable'] = True
        return context

    i = 0
    followable = True
    while i < len(tokens):
        key = tokens[i].lower()
        if key == 'all':
            context['criteria'].append(('all', ''))
            context['all'] = True
            i += 1
            continue
        if i + 1 >= len(tokens):
            context['criteria'].append((key, ''))
            followable = False
            break
        value_token = tokens[i + 1]
        context['criteria'].append((key, value_token))
        if key == 'user':
            context['user_patterns'].extend(
                [x for x in value_token.split(',') if x]
            )
        else:
            followable = False
        i += 2
    context['followable'] = bool(context['all'] or context['user_patterns']) and followable
    return context


def _context_suffix(context):
    raw = context.get('raw', '') if isinstance(context, dict) else ''
    return ' [Match {}]'.format(raw) if raw else ''


def _context_applies_to_user(context, user_name):
    '''Return True if a Match context can be safely applied to user_name.'''
    if not context or not context.get('raw', ''):
        return True
    if not context.get('followable', False):
        return False
    if context.get('all', False):
        return True
    patterns = context.get('user_patterns', [])
    return any(fnmatch.fnmatchcase(user_name, pattern) for pattern in patterns)


def _resolve_authorized_keys_template(path_template, user_name, uid, home_dir):
    '''Resolve sshd_config AuthorizedKeysFile templates for one user.'''
    if not path_template:
        return ''
    lower = path_template.lower()
    if lower == 'none':
        return ''

    resolved = path_template.replace('%%', '%')
    replacements = {
        '%u': user_name or '',
        '%U': str(uid) if uid not in ('', None) else '',
        '%h': home_dir or '',
    }
    for token, value in replacements.items():
        if token in resolved and not value:
            return ''
        resolved = resolved.replace(token, value)

    if RE_UNRESOLVED_TEMPLATE.search(resolved):
        return ''
    if resolved == '~':
        resolved = home_dir or resolved
    elif resolved.startswith('~/'):
        if not home_dir:
            return ''
        resolved = posixpath.join(home_dir, resolved[2:])
    elif not resolved.startswith('/'):
        if not home_dir:
            return ''
        resolved = posixpath.join(home_dir, resolved)
    return posixpath.normpath(resolved)


def _collect_authorized_keys_paths_for_user(authkeys_rules, user_name, uid, home_dir):
    '''Resolve configured AuthorizedKeysFile paths for one user.'''
    resolved_paths = []
    explicit_rule = False
    seen = set()
    for rule in authkeys_rules:
        context = rule.get('context', {})
        if not _context_applies_to_user(context, user_name):
            continue
        explicit_rule = True
        for token in _split_config_value(rule.get('value', '')):
            resolved = _resolve_authorized_keys_template(token, user_name, uid, home_dir)
            if resolved and resolved not in seen:
                seen.add(resolved)
                resolved_paths.append(resolved)
    return resolved_paths, explicit_rule


# ---------------------------------------------------------------------------
# SSH key fingerprint helper
# ---------------------------------------------------------------------------

def compute_key_fingerprint(key_b64):
    '''Compute SHA256 fingerprint of an SSH public key blob.
    Returns "SHA256:<base64>" or empty string on failure.'''
    try:
        key_bytes = base64.b64decode(key_b64 + '==')  # padding tolerant
        digest = hashlib.sha256(key_bytes).digest()
        return 'SHA256:' + base64.b64encode(digest).decode('ascii').rstrip('=')
    except Exception:
        return ''


# ---------------------------------------------------------------------------
# authorized_keys line parser
# ---------------------------------------------------------------------------

# Regex to extract common options; handles doubly-quoted values
RE_COMMAND   = re.compile(r'(?:^|,)\s*command="((?:[^"\\]|\\.)*)"', re.IGNORECASE)
RE_FROM      = re.compile(r'(?:^|,)\s*from="((?:[^"\\]|\\.)*)"', re.IGNORECASE)
RE_ENVIRON   = re.compile(r'(?:^|,)\s*environment="((?:[^"\\]|\\.)*)"', re.IGNORECASE)
RE_PERMITOPEN = re.compile(r'(?:^|,)\s*permitopen="((?:[^"\\]|\\.)*)"', re.IGNORECASE)


def parse_authkeys_line(line):
    '''Parse one authorized_keys line.
    Returns dict with extracted fields, or None for blank/comment lines.'''
    line = line.strip()
    if not line or line.startswith('#'):
        return None

    # Locate the key-type token to split options from key blob
    key_type = ''
    key_b64  = ''
    comment  = ''
    options_part = line

    for kt in KNOWN_KEY_TYPES:
        # search for " keytype " or "^keytype "
        pat = r'(?:^|[ \t])(' + re.escape(kt) + r')[ \t]'
        m = re.search(pat, line)
        if m:
            key_type = kt
            after = line[m.end():].strip()
            parts = after.split(None, 1)
            key_b64  = parts[0] if parts else ''
            comment  = parts[1] if len(parts) > 1 else ''
            options_part = line[:m.start()]
            break

    if not key_type:
        # Unrecognised line (could be a cert or future type) – keep raw
        return {'forced_command': '', 'from_restriction': '', 'key_type': '',
                'key_b64': '', 'comment': line, 'options_raw': line,
                'fingerprint': ''}

    forced_command  = RE_COMMAND.search(options_part)
    forced_command  = forced_command.group(1).replace('\\"', '"') if forced_command else ''
    from_restr      = RE_FROM.search(options_part)
    from_restr      = from_restr.group(1) if from_restr else ''
    fingerprint     = compute_key_fingerprint(key_b64) if key_b64 else ''

    return {
        'forced_command':  forced_command,
        'from_restriction': from_restr,
        'key_type':        key_type,
        'key_b64':         key_b64[:32] + '...' if len(key_b64) > 32 else key_b64,
        'key_b64_full':    key_b64,
        'comment':         comment,
        'options_raw':     options_part.strip(),
        'fingerprint':     fingerprint,
    }


# ---------------------------------------------------------------------------
# authorized_keys processor
# ---------------------------------------------------------------------------

def _compute_file_sha256(mac_info, file_path):
    '''Return lowercase hex SHA-256 of file contents, or empty string on error.'''
    try:
        fh = mac_info.Open(file_path)
        if fh is None:
            return ''
        h = hashlib.sha256()
        while True:
            chunk = fh.read(65536)
            if not chunk:
                break
            if isinstance(chunk, str):
                chunk = chunk.encode('latin-1')
            h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ''


def process_authorized_keys(mac_info, file_path, user_name, uid, main_rows, detail_rows):
    mac_info.ExportFile(file_path, __Plugin_Name, user_name + '_', False)
    artifact_mtime = get_file_mtime(mac_info, file_path)
    scope = get_scope(user_name)
    file_sha256 = _compute_file_sha256(mac_info, file_path)

    f = mac_info.Open(file_path)
    if f is None:
        log.error('Could not open {}'.format(file_path))
        return

    key_index = 0
    try:
        for raw in f:
            if isinstance(raw, bytes):
                raw = raw.decode('utf-8', errors='replace')
            raw = raw.rstrip()
            parsed = parse_authkeys_line(raw)
            if parsed is None:
                continue

            key_index += 1
            label = parsed['comment'] or parsed['fingerprint'] or 'key-{}'.format(key_index)
            target = parsed['forced_command']   # empty if no forced command

            main_rows.append(make_main_row(
                mechanism='SSH Persistence',
                sub_mechanism='authorized_keys',
                scope=scope,
                user=user_name,
                uid=uid,
                artifact_path=file_path,
                artifact_type='authorized_keys',
                target_path=target,
                trigger='ssh connection',
                label_or_name=label[:120],
                sha256=file_sha256,
                artifact_mtime=artifact_mtime,
                source=file_path,
            ))

            # Detail: options string, fingerprint, from restriction
            for ev_type, key, value in [
                ('key_options',     'options',      parsed['options_raw']),
                ('key_fingerprint', 'fingerprint',  parsed['fingerprint']),
                ('key_type',        'key_type',     parsed['key_type']),
                ('from_restriction','from',         parsed['from_restriction']),
                ('forced_command',  'command',      parsed['forced_command']),
            ]:
                if value:
                    detail_rows.append(make_detail_row(
                        artifact_path=file_path,
                        evidence_type=ev_type,
                        key_or_line=key,
                        value=value,
                        user=user_name,
                    ))
    except Exception:
        log.exception('Error reading {}'.format(file_path))


# ---------------------------------------------------------------------------
# sshd_config processor
# ---------------------------------------------------------------------------

def process_sshd_config(mac_info, file_path, main_rows, detail_rows):
    mac_info.ExportFile(file_path, __Plugin_Name, '', False)
    artifact_mtime = get_file_mtime(mac_info, file_path)

    f = mac_info.Open(file_path)
    if f is None:
        log.error('Could not open {}'.format(file_path))
        return []

    authkeys_rules = []
    current_context = {
        'raw': '',
        'criteria': [],
        'user_patterns': [],
        'all': False,
        'followable': True,
    }

    try:
        for raw in f:
            if isinstance(raw, bytes):
                raw = raw.decode('utf-8', errors='replace')
            stripped = _strip_unquoted_comment(raw).strip()
            if not stripped or stripped.startswith('#'):
                continue

            parts = stripped.split(None, 1)
            directive = parts[0].lower()
            value = parts[1].strip() if len(parts) > 1 else ''

            if directive == 'match':
                current_context = _parse_match_context(value)
                detail_rows.append(make_detail_row(
                    artifact_path=file_path,
                    evidence_type='sshd_match_context',
                    key_or_line='Match',
                    value=value,
                    source=file_path,
                ))
                continue

            if len(parts) < 2:
                continue

            if directive not in SSHD_INTEREST:
                continue
            context_suffix = _context_suffix(current_context)

            # Always emit a detail row for every interesting directive
            detail_rows.append(make_detail_row(
                artifact_path=file_path,
                evidence_type='sshd_directive',
                key_or_line=parts[0] + context_suffix,
                value=value,
                source=file_path,
            ))

            # Emit main rows for directives that directly enable persistence
            if directive == 'authorizedkeysfile':
                authkeys_rules.append({
                    'value': value,
                    'context': dict(current_context),
                })
                main_rows.append(make_main_row(
                    mechanism='SSH Persistence',
                    sub_mechanism='sshd_policy',
                    scope='system',
                    user='root',
                    uid=0,
                    artifact_path=file_path,
                    artifact_type='sshd_config',
                    target_path=value,
                    trigger='ssh connection',
                    label_or_name='AuthorizedKeysFile' + context_suffix,
                    artifact_mtime=artifact_mtime,
                    source=file_path,
                ))

            elif directive == 'authorizedkeyscommand':
                main_rows.append(make_main_row(
                    mechanism='SSH Persistence',
                    sub_mechanism='sshd_policy',
                    scope='system',
                    user='root',
                    uid=0,
                    artifact_path=file_path,
                    artifact_type='sshd_config',
                    target_path=value,
                    trigger='ssh connection',
                    label_or_name='AuthorizedKeysCommand' + context_suffix,
                    artifact_mtime=artifact_mtime,
                    source=file_path,
                ))

            elif directive == 'forcecommand':
                main_rows.append(make_main_row(
                    mechanism='SSH Persistence',
                    sub_mechanism='sshd_policy',
                    scope='system',
                    user='root',
                    uid=0,
                    artifact_path=file_path,
                    artifact_type='sshd_config',
                    target_path=value,
                    trigger='ssh connection',
                    label_or_name='ForceCommand' + context_suffix,
                    artifact_mtime=artifact_mtime,
                    source=file_path,
                ))

    except Exception:
        log.exception('Error reading {}'.format(file_path))

    return authkeys_rules


# ---------------------------------------------------------------------------
# ~/.ssh/config processor
# ---------------------------------------------------------------------------

def process_ssh_client_config(mac_info, file_path, user_name, uid, main_rows, detail_rows):
    mac_info.ExportFile(file_path, __Plugin_Name, user_name + '_', False)
    artifact_mtime = get_file_mtime(mac_info, file_path)
    scope = get_scope(user_name)

    f = mac_info.Open(file_path)
    if f is None:
        return

    try:
        for raw in f:
            if isinstance(raw, bytes):
                raw = raw.decode('utf-8', errors='replace')
            raw = raw.rstrip()
            stripped = raw.strip()
            if not stripped or stripped.startswith('#'):
                continue

            parts = stripped.split(None, 1)
            if len(parts) < 2:
                continue
            directive = parts[0].lower()
            value     = parts[1].strip()

            if directive not in SSH_CLIENT_INTEREST:
                continue

            detail_rows.append(make_detail_row(
                artifact_path=file_path,
                evidence_type='ssh_client_directive',
                key_or_line=parts[0],
                value=value,
                user=user_name,
            ))

            # ProxyCommand runs a local binary; flag it as persistence-relevant
            if directive in ('proxycommand', 'localcommand', 'remotecommand'):
                main_rows.append(make_main_row(
                    mechanism='SSH Persistence',
                    sub_mechanism='ssh_config',
                    scope=scope,
                    user=user_name,
                    uid=uid,
                    artifact_path=file_path,
                    artifact_type='ssh_client_config',
                    target_path=value,
                    trigger='ssh outbound connection',
                    label_or_name=parts[0],
                    artifact_mtime=artifact_mtime,
                    source=file_path,
                ))
    except Exception:
        log.exception('Error reading {}'.format(file_path))


# ---------------------------------------------------------------------------
# ~/.ssh/rc processor
# ---------------------------------------------------------------------------

def process_ssh_rc(mac_info, file_path, user_name, uid, main_rows, detail_rows):
    '''~/.ssh/rc is executed at the start of every SSH session for this user.
    Any content is persistence-relevant.'''
    mac_info.ExportFile(file_path, __Plugin_Name, user_name + '_', False)
    artifact_mtime = get_file_mtime(mac_info, file_path)
    scope = get_scope(user_name)

    main_rows.append(make_main_row(
        mechanism='SSH Persistence',
        sub_mechanism='ssh_rc',
        scope=scope,
        user=user_name,
        uid=uid,
        artifact_path=file_path,
        artifact_type='ssh_rc',
        trigger='ssh login / session start',
        label_or_name='.ssh/rc',
        artifact_mtime=artifact_mtime,
        source=file_path,
    ))

    f = mac_info.Open(file_path)
    if f is None:
        return
    try:
        for lineno, raw in enumerate(f, start=1):
            if isinstance(raw, bytes):
                raw = raw.decode('utf-8', errors='replace')
            raw = raw.rstrip()
            if not raw.strip() or raw.strip().startswith('#'):
                continue
            detail_rows.append(make_detail_row(
                artifact_path=file_path,
                evidence_type='ssh_rc_line',
                key_or_line='line:{}'.format(lineno),
                value=raw.strip(),
                user=user_name,
            ))
    except Exception:
        log.exception('Error reading {}'.format(file_path))


# ---------------------------------------------------------------------------
# ~/.security/ scanner
# ---------------------------------------------------------------------------

def process_security_dir(mac_info, dir_path, user_name, uid, main_rows, detail_rows):
    '''~/.security/ can contain PAM SSH config or helper executables.
    Emit one main row per file found; executables are flagged.'''
    artifact_mtime = get_file_mtime(mac_info, dir_path)
    scope = get_scope(user_name)

    try:
        items = mac_info.ListItemsInFolder(dir_path, EntryType.FILES_AND_FOLDERS, False)
    except Exception:
        return

    for item in items:
        item_path = dir_path + '/' + item['name']
        mac_info.ExportFile(item_path, __Plugin_Name, user_name + '_', False)
        main_rows.append(make_main_row(
            mechanism='SSH Persistence',
            sub_mechanism='security_dir',
            scope=scope,
            user=user_name,
            uid=uid,
            artifact_path=item_path,
            artifact_type='security_dir_file',
            trigger='ssh login / session start',
            label_or_name=item['name'],
            artifact_mtime=get_file_mtime(mac_info, item_path),
            source=item_path,
        ))
        detail_rows.append(make_detail_row(
            artifact_path=dir_path,
            evidence_type='security_dir_entry',
            key_or_line=item['name'],
            value=item_path,
            user=user_name,
        ))


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def write_output(main_rows, detail_rows, output_params):
    main_col_info = [(c, DataType.TEXT) for c in MAIN_TABLE_COLUMNS]
    for i, (name, _) in enumerate(main_col_info):
        if name in ('ArtifactMTime', 'TargetMTime'):
            main_col_info[i] = (name, DataType.DATE)

    detail_col_info = [(c, DataType.TEXT) for c in DETAIL_TABLE_COLUMNS]

    log.info('Found {} SSH persistence item(s)'.format(len(main_rows)))
    if main_rows:
        WriteList('SSH persistence', 'SSHPERSIST', main_rows,
                  main_col_info, output_params, '')
    if detail_rows:
        WriteList('SSH persistence detail', 'SSHPERSIST_DETAIL', detail_rows,
                  detail_col_info, output_params, '')


# ---------------------------------------------------------------------------
# Plugin entry points
# ---------------------------------------------------------------------------

def Plugin_Start(mac_info):
    '''Main entry point for plugin'''
    main_rows   = []
    detail_rows = []
    processed   = set()
    authkeys_rules = []

    # sshd_config (system-wide, try both paths)
    for sshd_path in SSHD_CONFIG_PATHS:
        if sshd_path in processed:
            continue
        if mac_info.IsValidFilePath(sshd_path):
            processed.add(sshd_path)
            authkeys_rules = process_sshd_config(mac_info, sshd_path, main_rows, detail_rows)
            break  # only process one (they're the same file via symlink)

    # Per-user artifacts
    processed_authkeys = set()
    for user in mac_info.users:
        user_name = safe_user_label(user.user_name, user.home_dir)
        if not user_name:
            continue
        if user.home_dir in processed:
            continue
        processed.add(user.home_dir)

        configured_authkeys, explicit_rule = _collect_authorized_keys_paths_for_user(
            authkeys_rules, user_name, user.UID, user.home_dir
        )
        if configured_authkeys:
            for ak_path in configured_authkeys:
                parse_key = (user_name, ak_path)
                if parse_key in processed_authkeys:
                    continue
                processed_authkeys.add(parse_key)
                if mac_info.IsValidFilePath(ak_path):
                    process_authorized_keys(mac_info, ak_path, user_name, user.UID,
                                            main_rows, detail_rows)
        elif not explicit_rule:
            ak_path = user.home_dir + '/.ssh/authorized_keys'
            if mac_info.IsValidFilePath(ak_path):
                parse_key = (user_name, ak_path)
                if parse_key not in processed_authkeys:
                    processed_authkeys.add(parse_key)
                    process_authorized_keys(mac_info, ak_path, user_name, user.UID,
                                            main_rows, detail_rows)

        # ~/.ssh/config
        cfg_path = user.home_dir + '/.ssh/config'
        if mac_info.IsValidFilePath(cfg_path):
            process_ssh_client_config(mac_info, cfg_path, user_name, user.UID,
                                       main_rows, detail_rows)

        # ~/.ssh/rc
        rc_path = user.home_dir + '/.ssh/rc'
        if mac_info.IsValidFilePath(rc_path):
            process_ssh_rc(mac_info, rc_path, user_name, user.UID,
                           main_rows, detail_rows)

        # ~/.security/
        sec_dir = user.home_dir + '/.security'
        if mac_info.IsValidFolderPath(sec_dir):
            process_security_dir(mac_info, sec_dir, user_name, user.UID,
                                  main_rows, detail_rows)

    if main_rows or detail_rows:
        write_output(main_rows, detail_rows, mac_info.output_params)
    else:
        log.info('No SSH persistence artifacts found')


def Plugin_Start_Standalone(input_files_list, output_params):
    '''Entry point for single-artifact mode'''
    log.info('Module started as standalone')
    main_rows   = []
    detail_rows = []
    fake = _StandaloneMacInfo()
    processed_authkeys = set()

    for input_path in input_files_list:
        log.debug('Input path: ' + input_path)
        basename = os.path.basename(input_path)

        # Detect file type by name
        if basename == 'authorized_keys' or _looks_like_authorized_keys(input_path):
            if input_path not in processed_authkeys:
                processed_authkeys.add(input_path)
                process_authorized_keys(fake, input_path, '', '', main_rows, detail_rows)
        elif basename == 'sshd_config':
            rules = process_sshd_config(fake, input_path, main_rows, detail_rows)
            for ak_path in _collect_standalone_global_authorized_keys_paths(rules):
                if ak_path in processed_authkeys:
                    continue
                if fake.IsValidFilePath(ak_path):
                    processed_authkeys.add(ak_path)
                    process_authorized_keys(fake, ak_path, '', '', main_rows, detail_rows)
        elif basename in ('ssh_config', 'config'):
            process_ssh_client_config(fake, input_path, '', '', main_rows, detail_rows)
        elif basename == 'rc':
            _standalone_rc(input_path, main_rows, detail_rows)
        else:
            log.warning('Unrecognised SSH artifact filename: {}'.format(basename))

    if main_rows or detail_rows:
        write_output(main_rows, detail_rows, output_params)
    else:
        log.info('No SSH persistence found in provided files')


def _standalone_rc(path, main_rows, detail_rows):
    main_rows.append(make_main_row(
        mechanism='SSH Persistence',
        sub_mechanism='ssh_rc',
        artifact_path=path,
        artifact_type='ssh_rc',
        trigger='ssh login / session start',
        label_or_name=os.path.basename(path),
        source=path,
    ))
    try:
        with open(path, 'rb') as f:
            for lineno, raw in enumerate(f, start=1):
                raw = raw.decode('utf-8', errors='replace').rstrip()
                if not raw.strip() or raw.strip().startswith('#'):
                    continue
                detail_rows.append(make_detail_row(
                    artifact_path=path,
                    evidence_type='ssh_rc_line',
                    key_or_line='line:{}'.format(lineno),
                    value=raw.strip(),
                ))
    except OSError:
        log.exception('Could not read {}'.format(path))


class _StandaloneMacInfo:
    '''Minimal stand-in for standalone SSH artifact parsing.'''
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

    def IsValidFilePath(self, path):
        return os.path.isfile(path)


def _looks_like_authorized_keys(path):
    '''Heuristic for alternate AuthorizedKeysFile names in standalone mode.'''
    try:
        with open(path, 'rb') as f:
            for _ in range(8):
                raw = f.readline()
                if not raw:
                    break
                line = raw.decode('utf-8', errors='replace').strip()
                parsed = parse_authkeys_line(line)
                if parsed is None:
                    continue
                if parsed.get('key_type', '') or parsed.get('forced_command', ''):
                    return True
    except OSError:
        return False
    return False


def _collect_standalone_global_authorized_keys_paths(rules):
    '''Best-effort follow for standalone configs: only absolute global paths.'''
    paths = []
    seen = set()
    for rule in rules:
        context = rule.get('context', {})
        if context.get('raw', ''):
            continue
        for token in _split_config_value(rule.get('value', '')):
            if not token or token.lower() == 'none':
                continue
            if token.startswith('/') and not RE_UNRESOLVED_TEMPLATE.search(token):
                norm = posixpath.normpath(token)
                if norm not in seen:
                    seen.add(norm)
                    paths.append(norm)
    return paths


if __name__ == '__main__':
    print('This plugin is part of a framework and does not run independently.')
