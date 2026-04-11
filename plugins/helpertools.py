'''
   Copyright (c) 2026 jaybird1291

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the
   terms of the MIT License.

   helpertools.py
   --------------
   Detects modern helper-based persistence around app bundles and privileged
   services.  Plugin name: HELPERS.

   Artifact families covered:
     embedded_login_helper  : <App>.app/Contents/Library/LoginItems/
     privileged_helper      : /Library/PrivilegedHelperTools/
                              + correlated /Library/LaunchDaemons/<id>.plist
     launchservices_helper  : <App>.app/Contents/Library/LaunchServices/

   App bundle locations scanned (one level deep):
     /Applications/
     /Library/Applications/
     ~/Applications/

   Key analysis:
     - Embedded login helpers: each .app inside LoginItems is launched at login
       by the owning application.
     - Privileged helpers (SMJobBless): root-level binaries installed via the
       SMJobBless API; the owner app's Info.plist declares them via
       SMPrivilegedExecutables.  We correlate by scanning apps for that key.
     - Team ID / signer mismatches between helper and owner are surfaced in
       detail rows.

   Output tables:
     HELPERS        - one row per helper binary / bundle
     HELPERS_DETAIL - owner-helper path relation, Team ID mismatch, bundle IDs,
                      associated launchd plist, raw plist keys
'''

import logging
import os

from plugins.helpers.macinfo import *
from plugins.helpers.writer import *
from plugins.helpers.app_bundle_discovery import list_curated_app_bundles
from plugins.helpers.codesign_offline import get_bundle_info, get_binary_codesign_info
from plugins.helpers.persistence_common import (
    MAIN_TABLE_COLUMNS, DETAIL_TABLE_COLUMNS,
    make_main_row, make_detail_row,
    get_file_mtime, safe_user_label, get_scope,
)

__Plugin_Name = "HELPERS"
__Plugin_Friendly_Name = "Helper Tools Persistence"
__Plugin_Version = "1.0"
__Plugin_Description = (
    "Detects persistence via embedded login helpers, SMJobBless privileged helpers, "
    "and LaunchServices helpers inside app bundles"
)
__Plugin_Author = "jaybird1291"
__Plugin_Author_Email = ""
__Plugin_Modes = "MACOS,ARTIFACTONLY"
__Plugin_ArtifactOnly_Usage = (
    "Provide a /Library/PrivilegedHelperTools/ binary or an app bundle path"
)

log = logging.getLogger('MAIN.' + __Plugin_Name)

#---- Do not change the variable names in above section ----#

# ---------------------------------------------------------------------------
# App bundle scan locations
# ---------------------------------------------------------------------------

SYSTEM_APP_DIRS = [
    '/Applications',
    '/Library/Applications',
]

# Skipped on purpose: /System/Applications - Apple-signed, very low risk
# Per-user locations are handled in the user loop

PRIVILEGED_HELPER_DIR = '/Library/PrivilegedHelperTools'
LAUNCH_DAEMONS_DIR    = '/Library/LaunchDaemons'


# ---------------------------------------------------------------------------
# Phase 1: Build privileged-helper → owner-app correlation table
# ---------------------------------------------------------------------------

def build_priv_helper_owner_map(mac_info, bundle_paths):
    '''Scan app bundles for SMPrivilegedExecutables in Info.plist.
    Returns dict: helper_bundle_id -> owner_app_path.'''
    owner_map = {}
    for bundle_path in bundle_paths:
        info_plist = bundle_path + '/Contents/Info.plist'
        if not mac_info.IsValidFilePath(info_plist):
            continue
        success, plist, _ = mac_info.ReadPlist(info_plist)
        if not success or not isinstance(plist, dict):
            continue
        priv_execs = plist.get('SMPrivilegedExecutables', {})
        if isinstance(priv_execs, dict):
            for helper_id in priv_execs:
                if helper_id and helper_id not in owner_map:
                    owner_map[helper_id] = bundle_path
    return owner_map


# ---------------------------------------------------------------------------
# Phase 2: Process embedded login helpers
# ---------------------------------------------------------------------------

def process_embedded_login_helpers(mac_info, owner_app_path, owner_bundle_id,
                                    owner_team_id, main_rows, detail_rows):
    '''Enumerate <App>.app/Contents/Library/LoginItems/ and emit one row per helper.'''
    login_items_dir = owner_app_path + '/Contents/Library/LoginItems'
    if not mac_info.IsValidFolderPath(login_items_dir):
        return

    try:
        items = mac_info.ListItemsInFolder(login_items_dir, EntryType.FOLDERS, False)
    except Exception:
        return

    for item in items:
        helper_name = item['name']
        helper_path = login_items_dir + '/' + helper_name

        cs = get_bundle_info(mac_info, helper_path)
        artifact_mtime = get_file_mtime(mac_info, helper_path)

        # Export the helper's Info.plist as evidence
        info_plist = helper_path + '/Contents/Info.plist'
        if mac_info.IsValidFilePath(info_plist):
            mac_info.ExportFile(info_plist, __Plugin_Name, 'loginhelper_', False)

        mismatch = (owner_team_id and cs.team_id and
                    owner_team_id != cs.team_id)

        main_rows.append(make_main_row(
            mechanism='Helper Persistence',
            sub_mechanism='embedded_login_helper',
            scope='user',
            artifact_path=helper_path,
            artifact_type='login_item_bundle',
            target_path=cs.main_binary_path,
            trigger='login / app-managed helper',
            owner_app_path=owner_app_path,
            owner_bundle_id=owner_bundle_id,
            label_or_name=cs.bundle_id or helper_name,
            team_id=cs.team_id,
            codesign_status=cs.codesign_status,
            sha256=cs.sha256,
            artifact_mtime=artifact_mtime,
            source=helper_path,
        ))

        detail_rows.append(make_detail_row(
            artifact_path=helper_path,
            evidence_type='owner_helper_relation',
            key_or_line='OwnerApp',
            value=owner_app_path,
            resolved_path=helper_path,
        ))
        if cs.bundle_id:
            detail_rows.append(make_detail_row(
                artifact_path=helper_path,
                evidence_type='helper_bundle_id',
                key_or_line='CFBundleIdentifier',
                value=cs.bundle_id,
            ))
        if mismatch:
            detail_rows.append(make_detail_row(
                artifact_path=helper_path,
                evidence_type='team_id_mismatch',
                key_or_line='TeamID_mismatch',
                value='owner={} helper={}'.format(owner_team_id, cs.team_id),
            ))


# ---------------------------------------------------------------------------
# Phase 3: Process privileged helper tools
# ---------------------------------------------------------------------------

def process_privileged_helper_tools(mac_info, owner_map, main_rows, detail_rows):
    '''Enumerate /Library/PrivilegedHelperTools/ and emit one row per helper.
    Cross-reference owner_map to populate OwnerAppPath.'''
    if not mac_info.IsValidFolderPath(PRIVILEGED_HELPER_DIR):
        return

    try:
        items = mac_info.ListItemsInFolder(PRIVILEGED_HELPER_DIR, EntryType.FILES, False)
    except Exception:
        return

    for item in items:
        helper_name = item['name']
        helper_path = PRIVILEGED_HELPER_DIR + '/' + helper_name

        mac_info.ExportFile(helper_path, __Plugin_Name, 'privhelper_', False)
        cs = get_binary_codesign_info(mac_info, helper_path)
        artifact_mtime = get_file_mtime(mac_info, helper_path)

        # Try to find associated LaunchDaemon plist
        ld_plist_path = LAUNCH_DAEMONS_DIR + '/' + helper_name + '.plist'
        ld_program    = ''
        if mac_info.IsValidFilePath(ld_plist_path):
            mac_info.ExportFile(ld_plist_path, __Plugin_Name, 'privhelper_ld_', False)
            success, ld_plist, _ = mac_info.ReadPlist(ld_plist_path)
            if success and isinstance(ld_plist, dict):
                ld_program = ld_plist.get('Program', '') or \
                             (ld_plist.get('ProgramArguments', [''])[0]
                              if ld_plist.get('ProgramArguments') else '')

        # Look up owner app
        owner_app_path  = owner_map.get(helper_name, '')
        owner_bundle_id = ''
        owner_team_id   = ''
        if owner_app_path:
            owner_cs = get_bundle_info(mac_info, owner_app_path)
            owner_bundle_id = owner_cs.bundle_id
            owner_team_id   = owner_cs.team_id

        orphaned = not bool(owner_app_path)
        mismatch = (owner_team_id and cs.team_id and
                    owner_team_id != cs.team_id)

        main_rows.append(make_main_row(
            mechanism='Helper Persistence',
            sub_mechanism='privileged_helper',
            scope='system',
            user='root',
            uid=0,
            artifact_path=helper_path,
            artifact_type='privileged_helper_binary',
            target_path=ld_program or helper_path,
            trigger='boot / XPC activation',
            owner_app_path=owner_app_path,
            owner_bundle_id=owner_bundle_id,
            label_or_name=helper_name,
            team_id=cs.team_id,
            codesign_status=cs.codesign_status,
            sha256=cs.sha256,
            artifact_mtime=artifact_mtime,
            source=helper_path,
        ))

        detail_rows.append(make_detail_row(
            artifact_path=helper_path,
            evidence_type='privileged_helper_binary',
            key_or_line='HelperPath',
            value=helper_path,
        ))
        if ld_plist_path and mac_info.IsValidFilePath(ld_plist_path):
            detail_rows.append(make_detail_row(
                artifact_path=helper_path,
                evidence_type='associated_launch_daemon',
                key_or_line='LaunchDaemonPlist',
                value=ld_plist_path,
                resolved_path=ld_program,
            ))
        if owner_app_path:
            detail_rows.append(make_detail_row(
                artifact_path=helper_path,
                evidence_type='owner_helper_relation',
                key_or_line='OwnerApp',
                value=owner_app_path,
                resolved_path=owner_bundle_id,
            ))
        if orphaned:
            detail_rows.append(make_detail_row(
                artifact_path=helper_path,
                evidence_type='orphaned_helper',
                key_or_line='OwnerApp',
                value='(no owner app found in scanned locations)',
            ))
        if mismatch:
            detail_rows.append(make_detail_row(
                artifact_path=helper_path,
                evidence_type='team_id_mismatch',
                key_or_line='TeamID_mismatch',
                value='owner={} helper={}'.format(owner_team_id, cs.team_id),
            ))


# ---------------------------------------------------------------------------
# Phase 4: LaunchServices helpers inside app bundles
# ---------------------------------------------------------------------------

def process_launchservices_helpers(mac_info, owner_app_path, owner_bundle_id,
                                    main_rows, detail_rows):
    '''Enumerate <App>.app/Contents/Library/LaunchServices/ for helper executables.'''
    ls_dir = owner_app_path + '/Contents/Library/LaunchServices'
    if not mac_info.IsValidFolderPath(ls_dir):
        return

    try:
        items = mac_info.ListItemsInFolder(ls_dir, EntryType.FILES, False)
    except Exception:
        return

    for item in items:
        helper_path = ls_dir + '/' + item['name']
        mac_info.ExportFile(helper_path, __Plugin_Name, 'lshelper_', False)
        cs = get_binary_codesign_info(mac_info, helper_path)
        artifact_mtime = get_file_mtime(mac_info, helper_path)

        main_rows.append(make_main_row(
            mechanism='Helper Persistence',
            sub_mechanism='launchservices_helper',
            scope='system',
            artifact_path=helper_path,
            artifact_type='launchservices_helper_binary',
            target_path=helper_path,
            trigger='boot / XPC activation',
            owner_app_path=owner_app_path,
            owner_bundle_id=owner_bundle_id,
            label_or_name=item['name'],
            team_id=cs.team_id,
            codesign_status=cs.codesign_status,
            sha256=cs.sha256,
            artifact_mtime=artifact_mtime,
            source=helper_path,
        ))
        detail_rows.append(make_detail_row(
            artifact_path=helper_path,
            evidence_type='owner_helper_relation',
            key_or_line='OwnerApp',
            value=owner_app_path,
            resolved_path=helper_path,
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

    log.info('Found {} helper persistence item(s)'.format(len(main_rows)))
    if main_rows:
        WriteList('helper persistence', 'HELPERS', main_rows,
                  main_col_info, output_params, '')
    if detail_rows:
        WriteList('helper persistence detail', 'HELPERS_DETAIL', detail_rows,
                  detail_col_info, output_params, '')


# ---------------------------------------------------------------------------
# Plugin entry points
# ---------------------------------------------------------------------------

def Plugin_Start(mac_info):
    '''Main entry point for plugin'''
    main_rows   = []
    detail_rows = []
    app_bundle_paths = list_curated_app_bundles(mac_info)

    # Phase 1: Build privileged-helper → owner-app correlation table
    log.debug('Building privileged helper owner map...')
    owner_map = build_priv_helper_owner_map(mac_info, app_bundle_paths)
    log.debug('Found {} SMPrivilegedExecutables entries'.format(len(owner_map)))

    # Phase 2 & 4: Scan app bundles for embedded helpers and LS helpers
    for bundle_path in app_bundle_paths:
        cs = get_bundle_info(mac_info, bundle_path)
        owner_bundle_id = cs.bundle_id
        owner_team_id   = cs.team_id

        process_embedded_login_helpers(
            mac_info, bundle_path, owner_bundle_id, owner_team_id,
            main_rows, detail_rows)

        process_launchservices_helpers(
            mac_info, bundle_path, owner_bundle_id,
            main_rows, detail_rows)

    # Phase 3: Privileged helper tools
    process_privileged_helper_tools(mac_info, owner_map, main_rows, detail_rows)

    if main_rows or detail_rows:
        write_output(main_rows, detail_rows, mac_info.output_params)
    else:
        log.info('No helper persistence artifacts found')


def Plugin_Start_Standalone(input_files_list, output_params):
    '''Entry point for single-artifact mode.
    Accept: a standalone binary from /Library/PrivilegedHelperTools/ or
            the path to an app bundle (directory).'''
    log.info('Module started as standalone')
    main_rows   = []
    detail_rows = []

    for input_path in input_files_list:
        log.debug('Input path: ' + input_path)
        if input_path.endswith('.app') or os.path.isdir(input_path):
            # Treat as app bundle - scan for embedded helpers
            import plistlib
            info_plist_path = input_path + '/Contents/Info.plist'
            owner_bundle_id = ''
            if os.path.isfile(info_plist_path):
                try:
                    with open(info_plist_path, 'rb') as f:
                        p = plistlib.load(f)
                    owner_bundle_id = p.get('CFBundleIdentifier', '')
                except Exception:
                    pass
            _standalone_embedded_helpers(input_path, owner_bundle_id, main_rows, detail_rows)
        else:
            # Treat as a privileged helper binary
            _standalone_privhelper(input_path, main_rows, detail_rows)

    if main_rows or detail_rows:
        write_output(main_rows, detail_rows, output_params)
    else:
        log.info('No helper persistence found in provided paths')


def _standalone_embedded_helpers(bundle_path, owner_bundle_id, main_rows, detail_rows):
    login_items_dir = bundle_path + '/Contents/Library/LoginItems'
    if not os.path.isdir(login_items_dir):
        return
    for name in os.listdir(login_items_dir):
        helper_path = login_items_dir + '/' + name
        if not os.path.isdir(helper_path):
            continue
        import plistlib, hashlib
        info_plist = helper_path + '/Contents/Info.plist'
        helper_bundle_id = ''
        if os.path.isfile(info_plist):
            try:
                with open(info_plist, 'rb') as f:
                    p = plistlib.load(f)
                helper_bundle_id = p.get('CFBundleIdentifier', '')
            except Exception:
                pass
        main_rows.append(make_main_row(
            mechanism='Helper Persistence',
            sub_mechanism='embedded_login_helper',
            artifact_path=helper_path,
            artifact_type='login_item_bundle',
            trigger='login / app-managed helper',
            owner_app_path=bundle_path,
            owner_bundle_id=owner_bundle_id,
            label_or_name=helper_bundle_id or name,
            source=helper_path,
        ))
        detail_rows.append(make_detail_row(
            artifact_path=helper_path,
            evidence_type='owner_helper_relation',
            key_or_line='OwnerApp',
            value=bundle_path,
        ))


def _standalone_privhelper(binary_path, main_rows, detail_rows):
    import hashlib
    sha256 = ''
    try:
        h = hashlib.sha256()
        with open(binary_path, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                h.update(chunk)
        sha256 = h.hexdigest()
    except OSError:
        pass
    main_rows.append(make_main_row(
        mechanism='Helper Persistence',
        sub_mechanism='privileged_helper',
        scope='system',
        user='root',
        artifact_path=binary_path,
        artifact_type='privileged_helper_binary',
        target_path=binary_path,
        trigger='boot / XPC activation',
        label_or_name=os.path.basename(binary_path),
        sha256=sha256,
        source=binary_path,
    ))
    detail_rows.append(make_detail_row(
        artifact_path=binary_path,
        evidence_type='privileged_helper_binary',
        key_or_line='HelperPath',
        value=binary_path,
    ))


if __name__ == '__main__':
    print('This plugin is part of a framework and does not run independently.')
