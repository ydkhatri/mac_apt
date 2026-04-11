'''
   Copyright (c) 2026 jaybird1291

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the
   terms of the MIT License.

   injection.py
   ------------
   Detects environment-driven and load-command-based injection persistence.

   Sub-mechanisms:
     lsenvironment  : LSEnvironment dict in app Info.plist containing
                      DYLD_INSERT_LIBRARIES, DYLD_FRAMEWORK_PATH, etc.
     launchd_env    : EnvironmentVariables dict in LaunchDaemon/Agent plist
                      containing DYLD_* variables
     dyld_env       : (overlaps above two - used as a combined label when
                      the variable is explicitly DYLD_INSERT_LIBRARIES)
     load_dylib     : LC_LOAD_DYLIB / LC_LOAD_WEAK_DYLIB pointing to
                      suspicious or unusual locations
     reexport_proxy : LC_REEXPORT_DYLIB (proxy dylib injection pattern)

   App bundles scanned for LSEnvironment:
     /Applications/  /Library/Applications/  ~/Applications/

   Launchd plists scanned for EnvironmentVariables:
     /Library/LaunchDaemons/  /Library/LaunchAgents/
     ~/Library/LaunchAgents/  /System/Library/LaunchDaemons (skipped - low risk)

   Mach-O scan for load commands:
     Executables referenced by non-standard LaunchDaemon/Agent plists +
     main executables of installed apps.
     NOTE: Only "suspicious" and "unusual" dylib paths are flagged (see
     macho_offline.classify_dylib_path).  Standard Apple/system paths are
     suppressed to keep output low-noise.

   Output tables:
     INJECTION        - one row per injection vector
     INJECTION_DETAIL - env var name/value, host binary path, injected dylib path
'''

import logging
import os

from plugins.helpers.macinfo import *
from plugins.helpers.writer import *
from plugins.helpers.app_bundle_discovery import list_curated_app_bundles
from plugins.helpers.codesign_offline import get_bundle_info
from plugins.helpers.macho_offline import (
    parse_macho_from_mac_info, classify_dylib_path, DYLIB_CMD_MAP,
    LC_REEXPORT_DYLIB,
)
from plugins.helpers.persistence_common import (
    MAIN_TABLE_COLUMNS, DETAIL_TABLE_COLUMNS,
    make_main_row, make_detail_row,
    get_file_mtime, safe_user_label, get_scope,
)

__Plugin_Name = "INJECTION"
__Plugin_Friendly_Name = "Injection Persistence"
__Plugin_Version = "1.0"
__Plugin_Description = (
    "Detects DYLD injection via LSEnvironment in app bundles, "
    "EnvironmentVariables in launchd plists, and suspicious Mach-O load commands"
)
__Plugin_Author = "jaybird1291"
__Plugin_Author_Email = ""
__Plugin_Modes = "MACOS,ARTIFACTONLY"
__Plugin_ArtifactOnly_Usage = (
    "Provide an app Info.plist, a LaunchDaemon/Agent plist, or a Mach-O binary"
)

log = logging.getLogger('MAIN.' + __Plugin_Name)

#---- Do not change the variable names in above section ----#

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

SYSTEM_LAUNCHD_DIRS = [
    '/Library/LaunchDaemons',
    '/Library/LaunchAgents',
]

SYSTEM_APP_DIRS = ['/Applications', '/Library/Applications']

# DYLD environment variables that enable injection / path hijacking
DYLD_INJECTION_VARS = {
    'DYLD_INSERT_LIBRARIES',
    'DYLD_FRAMEWORK_PATH',
    'DYLD_LIBRARY_PATH',
    'DYLD_FALLBACK_LIBRARY_PATH',
    'DYLD_FALLBACK_FRAMEWORK_PATH',
    'DYLD_IMAGE_SUFFIX',
    'DYLD_VERSIONED_LIBRARY_PATH',
    'DYLD_VERSIONED_FRAMEWORK_PATH',
}


# ---------------------------------------------------------------------------
# LSEnvironment scanner
# ---------------------------------------------------------------------------

def scan_app_for_lsenvironment(mac_info, bundle_path, owner_bundle_id,
                                main_rows, detail_rows):
    '''Check an app bundle's Info.plist for LSEnvironment containing DYLD vars.'''
    info_plist_path = bundle_path + '/Contents/Info.plist'
    if not mac_info.IsValidFilePath(info_plist_path):
        return

    success, plist, _ = mac_info.ReadPlist(info_plist_path)
    if not success or not isinstance(plist, dict):
        return

    ls_env = plist.get('LSEnvironment', {})
    if not isinstance(ls_env, dict):
        return

    suspicious_vars = {k: v for k, v in ls_env.items()
                       if k in DYLD_INJECTION_VARS}
    if not suspicious_vars:
        return

    mac_info.ExportFile(info_plist_path, __Plugin_Name, 'lsenv_', False)
    artifact_mtime = get_file_mtime(mac_info, info_plist_path)

    for var_name, var_value in suspicious_vars.items():
        sub_mech = 'dyld_env' if 'INSERT' in var_name else 'lsenvironment'
        main_rows.append(make_main_row(
            mechanism='Injection Persistence',
            sub_mechanism=sub_mech,
            scope='user',
            artifact_path=info_plist_path,
            artifact_type='info_plist',
            target_path=str(var_value),
            trigger='target process launch',
            owner_app_path=bundle_path,
            owner_bundle_id=owner_bundle_id,
            label_or_name='{}={}'.format(var_name, str(var_value)[:80]),
            artifact_mtime=artifact_mtime,
            source=info_plist_path,
        ))
        detail_rows.append(make_detail_row(
            artifact_path=info_plist_path,
            evidence_type='lsenvironment_var',
            key_or_line=var_name,
            value=str(var_value),
            resolved_path=bundle_path,
        ))


# ---------------------------------------------------------------------------
# LaunchD EnvironmentVariables scanner
# ---------------------------------------------------------------------------

def scan_launchd_plist_for_env(mac_info, plist_path, user_name, uid,
                                main_rows, detail_rows):
    '''Check a launchd plist for EnvironmentVariables containing DYLD vars.'''
    if not mac_info.IsValidFilePath(plist_path):
        return

    success, plist, _ = mac_info.ReadPlist(plist_path)
    if not success or not isinstance(plist, dict):
        return

    env_vars = plist.get('EnvironmentVariables', {})
    if not isinstance(env_vars, dict):
        return

    suspicious = {k: v for k, v in env_vars.items()
                  if k in DYLD_INJECTION_VARS}
    if not suspicious:
        return

    mac_info.ExportFile(plist_path, __Plugin_Name, 'launchd_env_', False)
    artifact_mtime = get_file_mtime(mac_info, plist_path)

    # Get the target binary from Program/ProgramArguments
    program = plist.get('Program', '') or \
              (plist.get('ProgramArguments', [''])[0]
               if plist.get('ProgramArguments') else '')

    for var_name, var_value in suspicious.items():
        sub_mech = 'dyld_env' if 'INSERT' in var_name else 'launchd_env'
        main_rows.append(make_main_row(
            mechanism='Injection Persistence',
            sub_mechanism=sub_mech,
            scope=get_scope(user_name),
            user=user_name,
            uid=uid,
            artifact_path=plist_path,
            artifact_type='launchd_plist',
            target_path=str(var_value),
            owner_app_path=program,
            trigger='target process launch',
            label_or_name='{}={}'.format(var_name, str(var_value)[:80]),
            artifact_mtime=artifact_mtime,
            source=plist_path,
        ))
        detail_rows.append(make_detail_row(
            artifact_path=plist_path,
            evidence_type='launchd_env_var',
            key_or_line=var_name,
            value=str(var_value),
            resolved_path=program,
            user=user_name,
        ))


def scan_launchd_dir(mac_info, directory, user_name, uid, main_rows, detail_rows):
    if not mac_info.IsValidFolderPath(directory):
        return
    try:
        items = mac_info.ListItemsInFolder(directory, EntryType.FILES, False)
    except Exception:
        return
    for item in items:
        if item['name'].endswith('.plist'):
            scan_launchd_plist_for_env(
                mac_info, directory + '/' + item['name'],
                user_name, uid, main_rows, detail_rows)


# ---------------------------------------------------------------------------
# Mach-O load command scanner
# ---------------------------------------------------------------------------

def scan_binary_for_injection(mac_info, binary_path, owner_app_path,
                               owner_bundle_id, main_rows, detail_rows):
    '''Parse a Mach-O binary and flag suspicious/unusual dylib load commands.'''
    macho = parse_macho_from_mac_info(mac_info, binary_path)
    if macho.parse_error or not macho.arches:
        return

    artifact_mtime = get_file_mtime(mac_info, binary_path)

    for dylib_ref in macho.dylibs:
        classification = classify_dylib_path(dylib_ref.path)
        if classification == 'standard':
            continue  # suppress noise

        sub_mech = 'reexport_proxy' if dylib_ref.load_type == 'reexport' else 'load_dylib'

        main_rows.append(make_main_row(
            mechanism='Injection Persistence',
            sub_mechanism=sub_mech,
            scope='system' if not owner_app_path else 'user',
            artifact_path=binary_path,
            artifact_type='macho_binary',
            target_path=dylib_ref.path,
            trigger='trusted binary execution',
            owner_app_path=owner_app_path,
            owner_bundle_id=owner_bundle_id,
            label_or_name=os.path.basename(dylib_ref.path),
            codesign_status='signed' if macho.has_code_signature else 'unsigned',
            artifact_mtime=artifact_mtime,
            source=binary_path,
        ))
        detail_rows.append(make_detail_row(
            artifact_path=binary_path,
            evidence_type='dylib_load_cmd',
            key_or_line=dylib_ref.load_type,
            value=dylib_ref.path,
            resolved_path=dylib_ref.path if dylib_ref.path.startswith('/') else '',
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

    log.info('Found {} injection persistence item(s)'.format(len(main_rows)))
    if main_rows:
        WriteList('injection persistence', 'INJECTION', main_rows,
                  main_col_info, output_params, '')
    if detail_rows:
        WriteList('injection persistence detail', 'INJECTION_DETAIL', detail_rows,
                  detail_col_info, output_params, '')


# ---------------------------------------------------------------------------
# Plugin entry points
# ---------------------------------------------------------------------------

def Plugin_Start(mac_info):
    main_rows   = []
    detail_rows = []
    processed   = set()

    # --- System launchd dirs: EnvironmentVariables ---
    for ld_dir in SYSTEM_LAUNCHD_DIRS:
        scan_launchd_dir(mac_info, ld_dir, 'root', 0, main_rows, detail_rows)

    # --- App bundles: LSEnvironment + Mach-O load commands ---
    for user in mac_info.users:
        user_name = safe_user_label(user.user_name, user.home_dir)
        if not user_name or user.home_dir in processed:
            continue
        processed.add(user.home_dir)

        # Per-user LaunchAgents
        scan_launchd_dir(
            mac_info,
            user.home_dir + '/Library/LaunchAgents',
            user_name, user.UID,
            main_rows, detail_rows)

    for bundle_path in list_curated_app_bundles(mac_info):
        cs = get_bundle_info(mac_info, bundle_path)
        scan_app_for_lsenvironment(
            mac_info, bundle_path, cs.bundle_id, main_rows, detail_rows)

        if cs.main_binary_path:
            scan_binary_for_injection(
                mac_info, cs.main_binary_path,
                bundle_path, cs.bundle_id,
                main_rows, detail_rows)

    # --- /Library/PrivilegedHelperTools: Mach-O load commands ---
    priv_dir = '/Library/PrivilegedHelperTools'
    if mac_info.IsValidFolderPath(priv_dir):
        try:
            items = mac_info.ListItemsInFolder(priv_dir, EntryType.FILES, False)
        except Exception:
            items = []
        for item in items:
            helper_path = priv_dir + '/' + item['name']
            scan_binary_for_injection(
                mac_info, helper_path, '', '', main_rows, detail_rows)

    if main_rows or detail_rows:
        write_output(main_rows, detail_rows, mac_info.output_params)
    else:
        log.info('No injection persistence artifacts found')


def Plugin_Start_Standalone(input_files_list, output_params):
    log.info('Module started as standalone')
    main_rows   = []
    detail_rows = []

    for input_path in input_files_list:
        log.debug('Input path: ' + input_path)
        basename = os.path.basename(input_path)

        if basename == 'Info.plist':
            _standalone_info_plist(input_path, main_rows, detail_rows)
        elif basename.endswith('.plist'):
            _standalone_launchd_plist(input_path, main_rows, detail_rows)
        else:
            # Treat as Mach-O binary
            try:
                with open(input_path, 'rb') as f:
                    data = f.read(512 * 1024)
                from plugins.helpers.macho_offline import parse_macho
                macho = parse_macho(data, path=input_path)
                for dylib_ref in macho.dylibs:
                    if classify_dylib_path(dylib_ref.path) != 'standard':
                        main_rows.append(make_main_row(
                            mechanism='Injection Persistence',
                            sub_mechanism='reexport_proxy' if dylib_ref.load_type == 'reexport' else 'load_dylib',
                            artifact_path=input_path,
                            artifact_type='macho_binary',
                            target_path=dylib_ref.path,
                            trigger='trusted binary execution',
                            label_or_name=os.path.basename(dylib_ref.path),
                            source=input_path,
                        ))
            except OSError:
                log.exception('Could not read {}'.format(input_path))

    if main_rows or detail_rows:
        write_output(main_rows, detail_rows, output_params)
    else:
        log.info('No injection artifacts found in provided files')


def _standalone_info_plist(path, main_rows, detail_rows):
    import plistlib
    try:
        with open(path, 'rb') as f:
            plist = plistlib.load(f)
    except Exception:
        return
    ls_env = plist.get('LSEnvironment', {})
    if not isinstance(ls_env, dict):
        return
    for var_name, var_value in ls_env.items():
        if var_name in DYLD_INJECTION_VARS:
            main_rows.append(make_main_row(
                mechanism='Injection Persistence',
                sub_mechanism='lsenvironment',
                artifact_path=path,
                artifact_type='info_plist',
                target_path=str(var_value),
                trigger='target process launch',
                label_or_name='{}={}'.format(var_name, str(var_value)[:80]),
                source=path,
            ))


def _standalone_launchd_plist(path, main_rows, detail_rows):
    import plistlib
    try:
        with open(path, 'rb') as f:
            plist = plistlib.load(f)
    except Exception:
        return
    env_vars = plist.get('EnvironmentVariables', {})
    if not isinstance(env_vars, dict):
        return
    program = plist.get('Program', '')
    for var_name, var_value in env_vars.items():
        if var_name in DYLD_INJECTION_VARS:
            main_rows.append(make_main_row(
                mechanism='Injection Persistence',
                sub_mechanism='launchd_env',
                artifact_path=path,
                artifact_type='launchd_plist',
                target_path=str(var_value),
                owner_app_path=program,
                trigger='target process launch',
                label_or_name='{}={}'.format(var_name, str(var_value)[:80]),
                source=path,
            ))


if __name__ == '__main__':
    print('This plugin is part of a framework and does not run independently.')
