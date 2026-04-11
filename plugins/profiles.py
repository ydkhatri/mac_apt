'''
   Copyright (c) 2026 jaybird1291

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the
   terms of the MIT License.

   profiles.py
   -----------
   Detects persistence and policy abuse via configuration profiles
   and managed preferences.

   Artifact families covered:
     profile_store  : /var/db/ConfigurationProfiles/Store/
     profile_settings: /var/db/ConfigurationProfiles/Settings/
     managed_prefs  : /Library/Managed Preferences/
                      /Library/Managed Preferences/<user>/
     stray_mobileconfig: .mobileconfig files in user home dirs

   Payloads of interest (flagged as high-impact):
     com.apple.TCC.configuration-profile-policy
     com.apple.system-extension-policy
     com.apple.syspolicy.kernel-extension-policy
     com.apple.servicemanagement
     com.apple.security.pkcs1 / .pem / .root  (certificate payloads)
     com.apple.ManagedClient.preferences

   Output tables:
     PROFILES        - one row per installed profile or managed pref domain
     PROFILES_DETAIL - payload type, org, profile ID, managed key/value pairs
'''

import logging
import os
import plistlib
import hashlib
from collections import deque

from plugins.helpers.macinfo import *
from plugins.helpers.writer import *
from plugins.helpers.persistence_common import (
    MAIN_TABLE_COLUMNS, DETAIL_TABLE_COLUMNS,
    make_main_row, make_detail_row,
    get_file_mtime, safe_user_label, get_scope,
)

__Plugin_Name = "PROFILES"
__Plugin_Friendly_Name = "Configuration Profiles"
__Plugin_Version = "1.0"
__Plugin_Description = "Detects persistence via configuration profiles, MDM payloads, and managed preferences"
__Plugin_Author = "jaybird1291"
__Plugin_Author_Email = ""
__Plugin_Modes = "MACOS,ARTIFACTONLY"
__Plugin_ArtifactOnly_Usage = "Provide a .mobileconfig file or a managed preferences plist"

log = logging.getLogger('MAIN.' + __Plugin_Name)

#---- Do not change the variable names in above section ----#

# ---------------------------------------------------------------------------
# High-impact payload types
# ---------------------------------------------------------------------------

HIGH_IMPACT_PAYLOADS = {
    'com.apple.tcc.configuration-profile-policy',
    'com.apple.system-extension-policy',
    'com.apple.syspolicy.kernel-extension-policy',
    'com.apple.servicemanagement',
    'com.apple.security.pkcs1',
    'com.apple.security.pem',
    'com.apple.security.root',
    'com.apple.managedclient.preferences',
    'com.apple.security.scep',
    'com.apple.security.certificateroot',
}

# Payload keys to surface in detail rows (not exhaustive; add as needed)
DETAIL_KEYS_TCC = (
    'Services', 'SystemPolicyAllFiles', 'Accessibility',
    'PostEvent', 'ListenEvent', 'ScreenCapture',
)
DETAIL_KEYS_SYSEXT = ('AllowedSystemExtensions', 'AllowedTeamIdentifiers',
                      'AllowUserOverrides', 'AllowedSystemExtensionTypes',
                      'RemovableSystemExtensions')
DETAIL_KEYS_KEXT   = ('AllowedKernelExtensions', 'AllowedTeamIdentifiers',
                      'AllowUserOverrides')
DETAIL_KEYS_SVC    = ('AllowedServices', 'Rules', 'LoginItems', 'ManagedLoginItems')
CERT_PAYLOAD_TYPES = {
    'com.apple.security.pkcs1',
    'com.apple.security.pem',
    'com.apple.security.root',
    'com.apple.security.certificateroot',
}
TEMP_MOBILECONFIG_DIRS = ('/tmp', '/private/tmp')
MAX_TEMP_SCAN_DEPTH = 2
MAX_TEMP_SCAN_DIRS = 80


# ---------------------------------------------------------------------------
# Profile / mobileconfig parser
# ---------------------------------------------------------------------------

def process_mobileconfig(mac_info, file_path, user_name, uid, main_rows, detail_rows,
                          sub_mechanism='profile'):
    '''Parse a .mobileconfig / profile plist and emit rows for each payload.'''
    if mac_info:
        mac_info.ExportFile(file_path, __Plugin_Name, '', False)
        success, plist, error = mac_info.ReadPlist(file_path)
        if not success:
            log.error('Could not read profile {}: {}'.format(file_path, error))
            return
    else:
        try:
            with open(file_path, 'rb') as f:
                plist = plistlib.load(f)
        except Exception as ex:
            log.error('Could not read profile {}: {}'.format(file_path, str(ex)))
            return

    if not isinstance(plist, dict):
        log.warning('Unexpected plist structure in {}'.format(file_path))
        return

    artifact_mtime  = get_file_mtime(mac_info, file_path) if mac_info else None
    profile_id      = plist.get('PayloadIdentifier', '')
    profile_display = plist.get('PayloadDisplayName', '') or plist.get('PayloadDescription', '')
    organization    = plist.get('PayloadOrganization', '')
    scope           = get_scope(user_name)

    # One main row per profile file
    main_rows.append(make_main_row(
        mechanism='Configuration Profile',
        sub_mechanism=sub_mechanism,
        scope=scope,
        user=user_name,
        uid=uid,
        artifact_path=file_path,
        artifact_type='mobileconfig',
        label_or_name=profile_display or profile_id or os.path.basename(file_path),
        owner_bundle_id=profile_id,
        trigger='profile install / MDM push',
        enabled='',
        artifact_mtime=artifact_mtime,
        source=file_path,
    ))

    # Detail: profile-level metadata
    for key, value in [('PayloadIdentifier',   profile_id),
                       ('PayloadDisplayName',   profile_display),
                       ('PayloadOrganization',  organization),
                       ('PayloadUUID',          plist.get('PayloadUUID', ''))]:
        if value:
            detail_rows.append(make_detail_row(
                artifact_path=file_path,
                evidence_type='profile_metadata',
                key_or_line=key,
                value=str(value),
                user=user_name,
            ))

    # Process each payload
    for payload in plist.get('PayloadContent', []):
        if not isinstance(payload, dict):
            continue
        payload_type = payload.get('PayloadType', '').lower()
        payload_id   = payload.get('PayloadIdentifier', '')
        is_high      = payload_type in HIGH_IMPACT_PAYLOADS

        # Emit a main row for every high-impact payload
        if is_high:
            main_rows.append(make_main_row(
                mechanism='Configuration Profile',
                sub_mechanism='payload',
                scope=scope,
                user=user_name,
                uid=uid,
                artifact_path=file_path,
                artifact_type='profile_payload',
                label_or_name=payload_type,
                owner_bundle_id=payload_id or profile_id,
                trigger='payload activation',
                artifact_mtime=artifact_mtime,
                source=file_path,
            ))

        detail_rows.append(make_detail_row(
            artifact_path=file_path,
            evidence_type='profile_payload',
            key_or_line='PayloadType',
            value=payload.get('PayloadType', ''),
            user=user_name,
        ))
        for meta_key in ('PayloadIdentifier', 'PayloadDisplayName', 'PayloadUUID'):
            meta_val = payload.get(meta_key, '')
            if meta_val:
                detail_rows.append(make_detail_row(
                    artifact_path=file_path,
                    evidence_type='payload_metadata',
                    key_or_line=meta_key,
                    value=str(meta_val),
                    user=user_name,
                ))

        # Drill into specific high-impact payload keys
        _emit_payload_details(payload, payload_type, file_path, user_name, detail_rows)


def _payload_value_to_text(value, limit=500):
    if isinstance(value, bytes):
        return '<{} bytes>'.format(len(value))
    return str(value)[:limit]


def _emit_flattened_payload_values(file_path, evidence_type, prefix, value,
                                    user_name, detail_rows, max_entries=24):
    '''Recursively flatten a limited number of payload values into detail rows.'''
    queue = deque([(prefix, value)])
    emitted = 0

    while queue and emitted < max_entries:
        key, current = queue.popleft()
        if isinstance(current, dict):
            for child_key, child_value in current.items():
                next_key = '{}.{}'.format(key, child_key) if key else str(child_key)
                queue.append((next_key, child_value))
        elif isinstance(current, list):
            for idx, child_value in enumerate(current):
                queue.append(('{}[{}]'.format(key, idx), child_value))
        else:
            detail_rows.append(make_detail_row(
                artifact_path=file_path,
                evidence_type=evidence_type,
                key_or_line=key,
                value=_payload_value_to_text(current),
                user=user_name,
            ))
            emitted += 1


def _emit_certificate_payload_details(payload, file_path, user_name, detail_rows):
    for key in ('PayloadCertificateFileName', 'PayloadDisplayName',
                'PayloadDescription', 'AllowAllAppsAccess'):
        val = payload.get(key)
        if val not in (None, ''):
            detail_rows.append(make_detail_row(
                artifact_path=file_path,
                evidence_type='certificate_metadata',
                key_or_line=key,
                value=str(val),
                user=user_name,
            ))
    content = payload.get('PayloadContent')
    if content not in (None, ''):
        if isinstance(content, str):
            content_bytes = content.encode('utf-8', errors='replace')
        elif isinstance(content, bytes):
            content_bytes = content
        else:
            content_bytes = repr(content).encode('utf-8', errors='replace')
        detail_rows.append(make_detail_row(
            artifact_path=file_path,
            evidence_type='certificate_metadata',
            key_or_line='PayloadContentSHA256',
            value=hashlib.sha256(content_bytes).hexdigest(),
            user=user_name,
        ))
        detail_rows.append(make_detail_row(
            artifact_path=file_path,
            evidence_type='certificate_metadata',
            key_or_line='PayloadContentLength',
            value=str(len(content_bytes)),
            user=user_name,
        ))


def _emit_payload_details(payload, payload_type, file_path, user_name, detail_rows):
    '''Emit detail rows for known interesting keys inside a payload.'''
    interest_map = {
        'com.apple.tcc.configuration-profile-policy': DETAIL_KEYS_TCC,
        'com.apple.system-extension-policy':          DETAIL_KEYS_SYSEXT,
        'com.apple.syspolicy.kernel-extension-policy': DETAIL_KEYS_KEXT,
        'com.apple.servicemanagement':                DETAIL_KEYS_SVC,
    }
    keys_to_check = interest_map.get(payload_type, ())
    for key in keys_to_check:
        val = payload.get(key)
        if val is not None:
            detail_rows.append(make_detail_row(
                artifact_path=file_path,
                evidence_type='payload_key',
                key_or_line=key,
                value=str(val)[:500],   # cap very long values
                user=user_name,
            ))

    if payload_type == 'com.apple.managedclient.preferences':
        managed_content = payload.get('PayloadContent', payload)
        if isinstance(managed_content, dict):
            _emit_flattened_payload_values(
                file_path, 'managedclient_pref', 'PayloadContent',
                managed_content, user_name, detail_rows, max_entries=36)

    if payload_type == 'com.apple.servicemanagement':
        for key in DETAIL_KEYS_SVC:
            if key in payload:
                _emit_flattened_payload_values(
                    file_path, 'servicemanagement_rule', key,
                    payload.get(key), user_name, detail_rows, max_entries=20)

    if payload_type == 'com.apple.system-extension-policy':
        for key in DETAIL_KEYS_SYSEXT:
            if key in payload:
                _emit_flattened_payload_values(
                    file_path, 'system_extension_policy', key,
                    payload.get(key), user_name, detail_rows, max_entries=20)

    if payload_type == 'com.apple.syspolicy.kernel-extension-policy':
        for key in DETAIL_KEYS_KEXT:
            if key in payload:
                _emit_flattened_payload_values(
                    file_path, 'kernel_extension_policy', key,
                    payload.get(key), user_name, detail_rows, max_entries=20)

    if payload_type in CERT_PAYLOAD_TYPES:
        _emit_certificate_payload_details(payload, file_path, user_name, detail_rows)


# ---------------------------------------------------------------------------
# Managed preferences processor
# ---------------------------------------------------------------------------

def process_managed_pref(mac_info, file_path, user_name, uid, main_rows, detail_rows):
    '''Parse one managed preferences plist (e.g. com.google.Chrome.plist).
    Emit one main row for the domain and detail rows for interesting keys.'''
    if mac_info:
        mac_info.ExportFile(file_path, __Plugin_Name, '', False)
        success, plist, error = mac_info.ReadPlist(file_path)
        if not success:
            log.error('Could not read managed pref {}: {}'.format(file_path, error))
            return
    else:
        try:
            with open(file_path, 'rb') as f:
                plist = plistlib.load(f)
        except Exception as ex:
            log.error('Could not read {}: {}'.format(file_path, str(ex)))
            return

    domain = os.path.splitext(os.path.basename(file_path))[0]
    artifact_mtime = get_file_mtime(mac_info, file_path) if mac_info else None
    scope = get_scope(user_name)

    main_rows.append(make_main_row(
        mechanism='Configuration Profile',
        sub_mechanism='managed_pref',
        scope=scope,
        user=user_name,
        uid=uid,
        artifact_path=file_path,
        artifact_type='managed_pref',
        label_or_name=domain,
        owner_bundle_id=domain,
        trigger='managed pref load',
        artifact_mtime=artifact_mtime,
        source=file_path,
    ))

    if not isinstance(plist, dict):
        return

    for key, value in plist.items():
        if key.startswith('$'):
            continue  # NSArchiver artefact
        detail_rows.append(make_detail_row(
            artifact_path=file_path,
            evidence_type='managed_pref_key',
            key_or_line=key,
            value=str(value)[:300],
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

    log.info('Found {} profile/managed-pref persistence item(s)'.format(len(main_rows)))
    if main_rows:
        WriteList('configuration profiles', 'PROFILES', main_rows,
                  main_col_info, output_params, '')
    if detail_rows:
        WriteList('configuration profiles detail', 'PROFILES_DETAIL', detail_rows,
                  detail_col_info, output_params, '')


# ---------------------------------------------------------------------------
# Plugin entry points
# ---------------------------------------------------------------------------

def Plugin_Start(mac_info):
    '''Main entry point for plugin'''
    main_rows   = []
    detail_rows = []
    processed   = set()

    # --- Profile store ---
    for store_dir in ('/var/db/ConfigurationProfiles/Store',
                      '/private/var/db/ConfigurationProfiles/Store'):
        if store_dir in processed:
            continue
        if mac_info.IsValidFolderPath(store_dir):
            processed.add(store_dir)
            _scan_dir_for_plists(mac_info, store_dir, 'root', 0, 'profile',
                                  main_rows, detail_rows, processed)
            break

    # --- Profile settings (effective state) ---
    for settings_dir in ('/var/db/ConfigurationProfiles/Settings',
                         '/private/var/db/ConfigurationProfiles/Settings'):
        if settings_dir in processed:
            continue
        if mac_info.IsValidFolderPath(settings_dir):
            processed.add(settings_dir)
            _scan_dir_for_plists(mac_info, settings_dir, 'root', 0, 'profile_settings',
                                  main_rows, detail_rows, processed)
            break

    # --- System-wide managed preferences ---
    for mgd_dir in ('/Library/Managed Preferences',):
        if mgd_dir in processed:
            continue
        if mac_info.IsValidFolderPath(mgd_dir):
            processed.add(mgd_dir)
            # Top-level plists are system-wide
            _scan_dir_for_managed_prefs(mac_info, mgd_dir, 'root', 0,
                                         main_rows, detail_rows, processed,
                                         recurse_users=True)

    # --- Per-user: stray .mobileconfig in home dirs ---
    for user in mac_info.users:
        user_name = safe_user_label(user.user_name, user.home_dir)
        if not user_name:
            continue
        if user.home_dir in processed:
            continue
        processed.add(user.home_dir)

        # Scan top-level of home dir and ~/Downloads for stray .mobileconfig
        for search_dir in (user.home_dir,
                           user.home_dir + '/Downloads',
                           user.home_dir + '/Desktop'):
            if mac_info.IsValidFolderPath(search_dir):
                _scan_for_stray_mobileconfig(mac_info, search_dir, user_name,
                                              user.UID, main_rows, detail_rows,
                                              processed)

    for temp_dir in TEMP_MOBILECONFIG_DIRS:
        _scan_temp_dirs_for_mobileconfig(mac_info, temp_dir, '', '',
                                         main_rows, detail_rows, processed)

    if main_rows or detail_rows:
        write_output(main_rows, detail_rows, mac_info.output_params)
    else:
        log.info('No configuration profile artifacts found')


def _scan_dir_for_plists(mac_info, directory, user_name, uid, sub_mech,
                          main_rows, detail_rows, processed):
    '''Recursively scan directory for .plist / .mobileconfig files and parse them.'''
    try:
        items = mac_info.ListItemsInFolder(directory, EntryType.FILES_AND_FOLDERS, False)
    except Exception:
        return
    for item in items:
        item_path = directory + '/' + item['name']
        if item_path in processed:
            continue
        if item.get('type') == EntryType.FOLDERS or mac_info.IsValidFolderPath(item_path):
            _scan_dir_for_plists(mac_info, item_path, user_name, uid, sub_mech,
                                  main_rows, detail_rows, processed)
        elif item['name'].endswith(('.plist', '.mobileconfig')):
            processed.add(item_path)
            process_mobileconfig(mac_info, item_path, user_name, uid,
                                  main_rows, detail_rows, sub_mech)


def _scan_dir_for_managed_prefs(mac_info, directory, user_name, uid,
                                  main_rows, detail_rows, processed,
                                  recurse_users=False):
    try:
        items = mac_info.ListItemsInFolder(directory, EntryType.FILES_AND_FOLDERS, False)
    except Exception:
        return
    for item in items:
        item_path = directory + '/' + item['name']
        if item_path in processed:
            continue
        # Sub-directories under Managed Preferences are per-user
        if mac_info.IsValidFolderPath(item_path) and recurse_users:
            sub_user = item['name']   # directory name is the username
            sub_uid  = ''
            for u in (mac_info.users if mac_info else []):
                if u.user_name == sub_user:
                    sub_uid = u.UID
                    break
            _scan_dir_for_managed_prefs(mac_info, item_path, sub_user, sub_uid,
                                         main_rows, detail_rows, processed,
                                         recurse_users=False)
        elif item['name'].endswith('.plist'):
            processed.add(item_path)
            process_managed_pref(mac_info, item_path, user_name, uid,
                                   main_rows, detail_rows)


def _scan_for_stray_mobileconfig(mac_info, directory, user_name, uid,
                                   main_rows, detail_rows, processed):
    try:
        items = mac_info.ListItemsInFolder(directory, EntryType.FILES, False)
    except Exception:
        return
    for item in items:
        if item['name'].endswith('.mobileconfig'):
            item_path = directory + '/' + item['name']
            if item_path in processed:
                continue
            processed.add(item_path)
            process_mobileconfig(mac_info, item_path, user_name, uid,
                                  main_rows, detail_rows, 'stray_mobileconfig')


def _scan_temp_dirs_for_mobileconfig(mac_info, directory, user_name, uid,
                                      main_rows, detail_rows, processed):
    '''Bounded recursive scan for stray profiles in temp locations.'''
    if not mac_info.IsValidFolderPath(directory):
        return
    queue = deque([(directory, 0)])
    seen_dirs = set()
    dirs_scanned = 0

    while queue and dirs_scanned < MAX_TEMP_SCAN_DIRS:
        current_dir, depth = queue.popleft()
        if current_dir in seen_dirs or not mac_info.IsValidFolderPath(current_dir):
            continue
        seen_dirs.add(current_dir)
        dirs_scanned += 1
        try:
            items = mac_info.ListItemsInFolder(current_dir, EntryType.FILES_AND_FOLDERS, False)
        except Exception:
            continue
        for item in items:
            item_path = current_dir + '/' + item['name']
            if item_path in processed:
                continue
            if item['name'].endswith('.mobileconfig'):
                processed.add(item_path)
                process_mobileconfig(mac_info, item_path, user_name, uid,
                                      main_rows, detail_rows, 'stray_mobileconfig')
            elif depth < MAX_TEMP_SCAN_DEPTH and \
                    (item.get('type') == EntryType.FOLDERS or mac_info.IsValidFolderPath(item_path)):
                queue.append((item_path, depth + 1))


def Plugin_Start_Standalone(input_files_list, output_params):
    '''Entry point for single-artifact mode'''
    log.info('Module started as standalone')
    main_rows   = []
    detail_rows = []

    for input_path in input_files_list:
        log.debug('Input path: ' + input_path)
        if input_path.endswith('.mobileconfig'):
            process_mobileconfig(None, input_path, '', '', main_rows, detail_rows)
        elif input_path.endswith('.plist'):
            process_managed_pref(None, input_path, '', '', main_rows, detail_rows)
        else:
            log.warning('Unrecognised profile artifact: {}'.format(input_path))

    if main_rows or detail_rows:
        write_output(main_rows, detail_rows, output_params)
    else:
        log.info('No profile artifacts found in provided files')


if __name__ == '__main__':
    print('This plugin is part of a framework and does not run independently.')
