'''
   Copyright (c) 2026 jaybird1291

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the
   terms of the MIT License.

   extpersist.py
   -------------
   Detects extension-driven persistence across Apple and browser ecosystems.

   Extension families covered:
     system_extension    : Contents/Library/SystemExtensions/*.systemextension
                           /Library/SystemExtensions/ (activated extensions DB)
     finder_sync         : <App>.app/Contents/PlugIns/*.appex  (FinderSync type)
     safari_app_extension: owning app .appex bundles + Safari extension state
     safari_web_extension: owning app web extension bundles + Safari state
     chromium_extension  : Chrome/Chromium/Edge Extensions/ folders +
                           /Library/Managed Preferences/com.google.Chrome.plist
                           (policy force-install)

   For each extension found, the plugin resolves:
     - Owner app path and bundle ID
     - Extension bundle ID
     - Team ID (via codesign_offline)
     - Activation/enablement state where the artifact exposes it

   Output tables:
     EXTPERSIST        - one row per extension or policy entry
     EXTPERSIST_DETAIL - bundle IDs, manifest keys, policy source, owner chain
'''

import json
import logging
import os
import plistlib

from plugins.helpers.macinfo import *
from plugins.helpers.writer import *
from plugins.helpers.app_bundle_discovery import list_curated_app_bundles
from plugins.helpers.codesign_offline import get_bundle_info
from plugins.helpers.persistence_common import (
    MAIN_TABLE_COLUMNS, DETAIL_TABLE_COLUMNS,
    make_main_row, make_detail_row,
    get_file_mtime, safe_user_label, get_scope,
)

__Plugin_Name = "EXTPERSIST"
__Plugin_Friendly_Name = "Extension Persistence"
__Plugin_Version = "1.0"
__Plugin_Description = (
    "Detects persistence via system extensions, Finder Sync extensions, "
    "Safari app/web extensions, and Chromium extension policy"
)
__Plugin_Author = "jaybird1291"
__Plugin_Author_Email = ""
__Plugin_Modes = "MACOS,ARTIFACTONLY"
__Plugin_ArtifactOnly_Usage = (
    "Provide a Chrome manifest or extension directory, a .app/.appex bundle path, "
    "an activated .systemextension path, or a Safari Extensions.plist"
)

log = logging.getLogger('MAIN.' + __Plugin_Name)

#---- Do not change the variable names in above section ----#

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

SYSTEM_APP_DIRS = ['/Applications', '/Library/Applications']

# Safari extension state plists
SAFARI_APPEXT_STATE   = '~/Library/Safari/AppExtensions/Extensions.plist'
SAFARI_WEBEXT_STATE   = '~/Library/Safari/WebExtensions/Extensions.plist'

# Chromium profile base dirs (relative to user home)
CHROMIUM_PROFILE_BASES = [
    '/Library/Application Support/Google/Chrome',
    '/Library/Application Support/Google/Chrome Beta',
    '/Library/Application Support/Microsoft Edge',
    '/Library/Application Support/BraveSoftware/Brave-Browser',
    '/Library/Application Support/Chromium',
    '/Library/Application Support/Vivaldi',
    '/Library/Application Support/Arc',
]

# Managed prefs for Chromium force-install policy
CHROMIUM_MANAGED_PREFS = [
    '/Library/Managed Preferences/com.google.Chrome.plist',
    '/Library/Managed Preferences/com.google.Chrome.canary.plist',
    '/Library/Managed Preferences/com.microsoft.Edge.plist',
]

# System Extensions activated DB
SYSEXT_ACTIVATED_DIR = '/Library/SystemExtensions'

SAFARI_APP_EXTENSION_POINTS = (
    'com.apple.safari.extension',
)

SAFARI_WEB_EXTENSION_POINTS = (
    'com.apple.safari.web-extension',
)


def get_bundle_scope(bundle_path):
    '''Best-effort scope for a bundle path.'''
    if not bundle_path:
        return 'user'
    if (bundle_path.startswith('/Users/') or
            bundle_path.startswith('/private/var/root/') or
            bundle_path.startswith('/var/root/')):
        return 'user'
    return 'system'


def classify_safari_extension_point(extension_point):
    '''Return safari_app_extension / safari_web_extension based on NSExtensionPointIdentifier.'''
    ext_point = str(extension_point or '').strip().lower()
    if not ext_point:
        return ''
    if ext_point in SAFARI_WEB_EXTENSION_POINTS or 'safari.web-extension' in ext_point:
        return 'safari_web_extension'
    if ext_point in SAFARI_APP_EXTENSION_POINTS or 'safari.extension' in ext_point:
        return 'safari_app_extension'
    return ''


def _get_bundle_label(plist, bundle_id, fallback):
    return (plist.get('CFBundleDisplayName', '') or
            plist.get('CFBundleName', '') or
            bundle_id or
            fallback)


def _read_json_from_mac_info(mac_info, path):
    try:
        f = mac_info.Open(path)
        if not f:
            return {}
        raw = f.read()
        if isinstance(raw, bytes):
            raw = raw.decode('utf-8', errors='replace')
        return json.loads(raw)
    except Exception:
        return {}


def _add_safari_web_manifest_details(mac_info, appex_path, detail_rows):
    '''Extract lightweight details from a Safari web extension manifest payload.'''
    manifest_path = appex_path + '/Contents/Resources/manifest.json'
    if not mac_info.IsValidFilePath(manifest_path):
        return
    mac_info.ExportFile(manifest_path, __Plugin_Name, 'safari_webext_', False)
    manifest = _read_json_from_mac_info(mac_info, manifest_path)
    if not isinstance(manifest, dict) or not manifest:
        return

    for key in ('name', 'version', 'manifest_version'):
        if key in manifest:
            detail_rows.append(make_detail_row(
                artifact_path=appex_path,
                evidence_type='webextension_manifest',
                key_or_line=key,
                value=str(manifest.get(key, '')),
                resolved_path=manifest_path,
            ))

    permissions = manifest.get('permissions', [])
    if isinstance(permissions, list) and permissions:
        detail_rows.append(make_detail_row(
            artifact_path=appex_path,
            evidence_type='webextension_permissions',
            key_or_line='permissions',
            value=', '.join(str(p) for p in permissions[:30]),
            resolved_path=manifest_path,
        ))


def process_safari_extension_bundles(mac_info, owner_app_path, owner_bundle_id,
                                      owner_team_id, safari_bundle_index,
                                      main_rows, detail_rows):
    '''Find Safari app/web .appex bundles inside an app (Contents/PlugIns/).'''
    plugins_dir = owner_app_path + '/Contents/PlugIns'
    if not mac_info.IsValidFolderPath(plugins_dir):
        return
    try:
        items = mac_info.ListItemsInFolder(plugins_dir, EntryType.FOLDERS, False)
    except Exception:
        return

    for item in items:
        if not item['name'].endswith('.appex'):
            continue

        appex_path = plugins_dir + '/' + item['name']
        info_plist = appex_path + '/Contents/Info.plist'
        if not mac_info.IsValidFilePath(info_plist):
            continue

        success, plist, _ = mac_info.ReadPlist(info_plist)
        if not success or not isinstance(plist, dict):
            continue

        ns_ext = plist.get('NSExtension', {})
        ext_point = ns_ext.get('NSExtensionPointIdentifier', '') if isinstance(ns_ext, dict) else ''
        sub_mechanism = classify_safari_extension_point(ext_point)
        if not sub_mechanism:
            continue

        mac_info.ExportFile(info_plist, __Plugin_Name, 'safari_appex_', False)
        cs = get_bundle_info(mac_info, appex_path)
        label = _get_bundle_label(plist, cs.bundle_id, item['name'])
        team_id = cs.team_id or owner_team_id
        artifact_type = 'safari_web_appex' if sub_mechanism == 'safari_web_extension' else 'safari_app_appex'

        main_rows.append(make_main_row(
            mechanism='Extension Persistence',
            sub_mechanism=sub_mechanism,
            scope=get_bundle_scope(owner_app_path),
            artifact_path=appex_path,
            artifact_type=artifact_type,
            target_path=cs.main_binary_path,
            trigger='browser launch / extension activation',
            owner_app_path=owner_app_path,
            owner_bundle_id=owner_bundle_id,
            label_or_name=label,
            team_id=team_id,
            codesign_status=cs.codesign_status,
            sha256=cs.sha256,
            artifact_mtime=get_file_mtime(mac_info, appex_path),
            source=appex_path,
        ))
        detail_rows.append(make_detail_row(
            artifact_path=appex_path,
            evidence_type='extension_point',
            key_or_line='NSExtensionPointIdentifier',
            value=ext_point,
        ))
        detail_rows.append(make_detail_row(
            artifact_path=appex_path,
            evidence_type='appex_bundle_id',
            key_or_line='CFBundleIdentifier',
            value=cs.bundle_id,
        ))
        if owner_bundle_id:
            detail_rows.append(make_detail_row(
                artifact_path=appex_path,
                evidence_type='owner_app_bundle_id',
                key_or_line='OwnerBundleID',
                value=owner_bundle_id,
                resolved_path=owner_app_path,
            ))

        if sub_mechanism == 'safari_web_extension':
            _add_safari_web_manifest_details(mac_info, appex_path, detail_rows)

        if cs.bundle_id:
            safari_bundle_index.setdefault(sub_mechanism, {})[cs.bundle_id] = {
                'appex_path': appex_path,
                'owner_app_path': owner_app_path,
                'owner_bundle_id': owner_bundle_id,
                'target_path': cs.main_binary_path,
                'team_id': team_id,
                'codesign_status': cs.codesign_status,
                'sha256': cs.sha256,
                'label_or_name': label,
            }


# ---------------------------------------------------------------------------
# System Extensions
# ---------------------------------------------------------------------------

def _make_system_extension_owner_entry(owner_app_path, owner_bundle_id, ext_path, bundle_id,
                                       team_id, executable_name, target_path,
                                       codesign_status, sha256, label_or_name):
    return {
        'owner_app_path': owner_app_path,
        'owner_bundle_id': owner_bundle_id,
        'embedded_path': ext_path,
        'bundle_id': bundle_id,
        'team_id': team_id,
        'exec_name': executable_name,
        'target_path': target_path,
        'codesign_status': codesign_status,
        'sha256': sha256,
        'label_or_name': label_or_name,
    }


def _register_system_extension_owner(owner_index, entry):
    bundle_id = entry.get('bundle_id', '')
    team_id = entry.get('team_id', '')
    exec_name = entry.get('exec_name', '')
    if bundle_id and team_id:
        owner_index.setdefault('bundle_team', {})[(bundle_id, team_id)] = entry
    if bundle_id:
        owner_index.setdefault('bundle_id', {}).setdefault(bundle_id, entry)
    if exec_name:
        owner_index.setdefault('exec_name', {}).setdefault(exec_name, entry)


def _match_system_extension_owner(owner_index, bundle_id, team_id, exec_name):
    if bundle_id and team_id:
        match = owner_index.get('bundle_team', {}).get((bundle_id, team_id))
        if match:
            return match, 'bundle_id+team_id'
    if bundle_id:
        match = owner_index.get('bundle_id', {}).get(bundle_id)
        if match:
            return match, 'bundle_id'
    if exec_name:
        match = owner_index.get('exec_name', {}).get(exec_name)
        if match:
            return match, 'executable_basename'
    return {}, ''


def process_system_extensions_in_bundle(mac_info, owner_app_path, owner_bundle_id,
                                         owner_team_id, owner_index, main_rows, detail_rows):
    '''Find system extensions bundled inside an app (Contents/Library/SystemExtensions/).'''
    se_dir = owner_app_path + '/Contents/Library/SystemExtensions'
    if not mac_info.IsValidFolderPath(se_dir):
        return
    try:
        items = mac_info.ListItemsInFolder(se_dir, EntryType.FOLDERS, False)
    except Exception:
        return
    for item in items:
        if not item['name'].endswith('.systemextension'):
            continue
        ext_path = se_dir + '/' + item['name']
        cs = get_bundle_info(mac_info, ext_path)
        artifact_mtime = get_file_mtime(mac_info, ext_path)
        executable_name = os.path.basename(cs.main_binary_path) if cs.main_binary_path else ''

        info_plist = ext_path + '/Contents/Info.plist'
        if mac_info.IsValidFilePath(info_plist):
            mac_info.ExportFile(info_plist, __Plugin_Name, 'sysext_', False)

        _register_system_extension_owner(owner_index, _make_system_extension_owner_entry(
            owner_app_path,
            owner_bundle_id,
            ext_path,
            cs.bundle_id,
            cs.team_id or owner_team_id,
            executable_name,
            cs.main_binary_path,
            cs.codesign_status,
            cs.sha256,
            cs.bundle_id or item['name'],
        ))

        main_rows.append(make_main_row(
            mechanism='Extension Persistence',
            sub_mechanism='system_extension',
            scope='system',
            artifact_path=ext_path,
            artifact_type='systemextension_bundle',
            target_path=cs.main_binary_path,
            trigger='boot / activation / load',
            owner_app_path=owner_app_path,
            owner_bundle_id=owner_bundle_id,
            label_or_name=cs.bundle_id or item['name'],
            team_id=cs.team_id or owner_team_id,
            codesign_status=cs.codesign_status,
            sha256=cs.sha256,
            artifact_mtime=artifact_mtime,
            source=ext_path,
        ))
        detail_rows.append(make_detail_row(
            artifact_path=ext_path,
            evidence_type='sysext_bundle_id',
            key_or_line='CFBundleIdentifier',
            value=cs.bundle_id,
        ))
        if owner_app_path:
            detail_rows.append(make_detail_row(
                artifact_path=ext_path,
                evidence_type='owner_app_path',
                key_or_line='OwnerApp',
                value=owner_app_path,
                resolved_path=owner_app_path,
            ))


def process_activated_system_extensions(mac_info, owner_index, main_rows, detail_rows):
    '''Parse /Library/SystemExtensions/ for activated extension records.'''
    if not mac_info.IsValidFolderPath(SYSEXT_ACTIVATED_DIR):
        return
    _walk_for_sysext(mac_info, SYSEXT_ACTIVATED_DIR, owner_index, main_rows, detail_rows)


def _walk_for_sysext(mac_info, directory, owner_index, main_rows, detail_rows, depth=0):
    if depth > 4:
        return
    try:
        items = mac_info.ListItemsInFolder(directory, EntryType.FOLDERS, False)
    except Exception:
        return
    for item in items:
        item_path = directory + '/' + item['name']
        if item['name'].endswith('.systemextension'):
            cs = get_bundle_info(mac_info, item_path)
            exec_name = os.path.basename(cs.main_binary_path) if cs.main_binary_path else ''
            owner_match, correlation_method = _match_system_extension_owner(
                owner_index, cs.bundle_id, cs.team_id, exec_name
            )
            info_plist = item_path + '/Contents/Info.plist'
            if mac_info.IsValidFilePath(info_plist):
                mac_info.ExportFile(info_plist, __Plugin_Name, 'activated_sysext_', False)
            main_rows.append(make_main_row(
                mechanism='Extension Persistence',
                sub_mechanism='system_extension',
                scope='system',
                artifact_path=item_path,
                artifact_type='activated_systemextension',
                target_path=cs.main_binary_path,
                trigger='boot / activation / load',
                owner_app_path=owner_match.get('owner_app_path', ''),
                owner_bundle_id=owner_match.get('owner_bundle_id', ''),
                label_or_name=cs.bundle_id or item['name'],
                team_id=cs.team_id or owner_match.get('team_id', ''),
                codesign_status=cs.codesign_status or owner_match.get('codesign_status', ''),
                sha256=cs.sha256 or owner_match.get('sha256', ''),
                artifact_mtime=get_file_mtime(mac_info, item_path),
                source=item_path,
            ))
            detail_rows.append(make_detail_row(
                artifact_path=item_path,
                evidence_type='activated_sysext_bundle_id',
                key_or_line='CFBundleIdentifier',
                value=cs.bundle_id,
            ))
            if correlation_method:
                detail_rows.append(make_detail_row(
                    artifact_path=item_path,
                    evidence_type='owner_correlation',
                    key_or_line='CorrelationMethod',
                    value=correlation_method,
                    resolved_path=owner_match.get('owner_app_path', ''),
                ))
                detail_rows.append(make_detail_row(
                    artifact_path=item_path,
                    evidence_type='embedded_owner_copy',
                    key_or_line='EmbeddedSystemExtension',
                    value=owner_match.get('embedded_path', ''),
                    resolved_path=owner_match.get('embedded_path', ''),
                ))
        else:
            _walk_for_sysext(mac_info, item_path, owner_index,
                              main_rows, detail_rows, depth + 1)


# ---------------------------------------------------------------------------
# Finder Sync Extensions
# ---------------------------------------------------------------------------

def process_finder_sync_extensions(mac_info, owner_app_path, owner_bundle_id,
                                    main_rows, detail_rows):
    '''Find Finder Sync .appex bundles inside an app (Contents/PlugIns/).'''
    plugins_dir = owner_app_path + '/Contents/PlugIns'
    if not mac_info.IsValidFolderPath(plugins_dir):
        return
    try:
        items = mac_info.ListItemsInFolder(plugins_dir, EntryType.FOLDERS, False)
    except Exception:
        return
    for item in items:
        if not item['name'].endswith('.appex'):
            continue
        appex_path = plugins_dir + '/' + item['name']
        # Check Info.plist for NSExtension.NSExtensionPointIdentifier = com.apple.FinderSync
        info_plist = appex_path + '/Contents/Info.plist'
        if not mac_info.IsValidFilePath(info_plist):
            continue
        success, plist, _ = mac_info.ReadPlist(info_plist)
        if not success or not isinstance(plist, dict):
            continue
        ns_ext = plist.get('NSExtension', {})
        ext_point = ns_ext.get('NSExtensionPointIdentifier', '') if isinstance(ns_ext, dict) else ''
        if 'FinderSync' not in ext_point and 'findersync' not in ext_point.lower():
            continue

        mac_info.ExportFile(info_plist, __Plugin_Name, 'findersync_', False)
        cs = get_bundle_info(mac_info, appex_path)

        main_rows.append(make_main_row(
            mechanism='Extension Persistence',
            sub_mechanism='finder_sync',
            scope='user',
            artifact_path=appex_path,
            artifact_type='findersync_appex',
            target_path=cs.main_binary_path,
            trigger='login / Finder launch / extension activation',
            owner_app_path=owner_app_path,
            owner_bundle_id=owner_bundle_id,
            label_or_name=cs.bundle_id or item['name'],
            team_id=cs.team_id,
            codesign_status=cs.codesign_status,
            sha256=cs.sha256,
            artifact_mtime=get_file_mtime(mac_info, appex_path),
            source=appex_path,
        ))
        detail_rows.append(make_detail_row(
            artifact_path=appex_path,
            evidence_type='extension_point',
            key_or_line='NSExtensionPointIdentifier',
            value=ext_point,
        ))


# ---------------------------------------------------------------------------
# Safari Extensions
# ---------------------------------------------------------------------------

def process_safari_extension_state(mac_info, plist_path, user_name, uid,
                                    sub_mechanism, safari_bundle_index,
                                    main_rows, detail_rows):
    '''Parse a Safari AppExtensions/Extensions.plist or WebExtensions/Extensions.plist.'''
    if not mac_info.IsValidFilePath(plist_path):
        return
    mac_info.ExportFile(plist_path, __Plugin_Name, user_name + '_safari_', False)
    success, plist, error = mac_info.ReadPlist(plist_path)
    if not success:
        log.error('Could not read {}: {}'.format(plist_path, error))
        return

    artifact_mtime = get_file_mtime(mac_info, plist_path)

    # The plist is a dict keyed by extension bundle ID; each value has state info
    if not isinstance(plist, dict):
        return
    for ext_id, ext_info in plist.items():
        if not isinstance(ext_info, dict):
            continue
        enabled = ext_info.get('Enabled', '')
        name    = ext_info.get('BundleDisplayName', '') or ext_id
        bundle_match = safari_bundle_index.get(sub_mechanism, {}).get(ext_id, {})
        owner_bundle_id = bundle_match.get('owner_bundle_id', '') or ext_id
        owner_app_path = bundle_match.get('owner_app_path', '')

        main_rows.append(make_main_row(
            mechanism='Extension Persistence',
            sub_mechanism=sub_mechanism,
            scope=get_scope(user_name),
            user=user_name,
            uid=uid,
            artifact_path=plist_path,
            artifact_type='safari_extension_state',
            target_path=bundle_match.get('target_path', ''),
            trigger='browser launch / extension activation',
            label_or_name=name,
            owner_app_path=owner_app_path,
            owner_bundle_id=owner_bundle_id,
            enabled=str(enabled),
            team_id=bundle_match.get('team_id', ''),
            codesign_status=bundle_match.get('codesign_status', ''),
            sha256=bundle_match.get('sha256', ''),
            artifact_mtime=artifact_mtime,
            source=plist_path,
        ))
        detail_rows.append(make_detail_row(
            artifact_path=plist_path,
            evidence_type='safari_extension_entry',
            key_or_line=ext_id,
            value=str(ext_info)[:300],
            resolved_path=bundle_match.get('appex_path', ''),
            user=user_name,
        ))
        if bundle_match:
            detail_rows.append(make_detail_row(
                artifact_path=plist_path,
                evidence_type='resolved_extension_bundle',
                key_or_line=ext_id,
                value=bundle_match.get('appex_path', ''),
                resolved_path=bundle_match.get('appex_path', ''),
                user=user_name,
            ))


# ---------------------------------------------------------------------------
# Chromium Extensions
# ---------------------------------------------------------------------------

def process_chromium_extensions(mac_info, base_dir, user_name, uid,
                                  main_rows, detail_rows):
    '''Enumerate Chrome/Chromium profile extension directories.'''
    if not mac_info.IsValidFolderPath(base_dir):
        return
    try:
        profiles = mac_info.ListItemsInFolder(base_dir, EntryType.FOLDERS, False)
    except Exception:
        return

    for profile in profiles:
        # Profile dirs: Default, Profile 1, Profile 2, ...
        if not (profile['name'] == 'Default' or
                profile['name'].startswith('Profile ')):
            continue
        ext_dir = base_dir + '/' + profile['name'] + '/Extensions'
        if not mac_info.IsValidFolderPath(ext_dir):
            continue
        try:
            exts = mac_info.ListItemsInFolder(ext_dir, EntryType.FOLDERS, False)
        except Exception:
            continue

        for ext in exts:
            ext_id_dir = ext_dir + '/' + ext['name']
            # Each extension dir contains version subdirs
            _process_chromium_extension_id(mac_info, ext_id_dir, ext['name'],
                                            user_name, uid, main_rows, detail_rows)


def _process_chromium_extension_id(mac_info, ext_id_dir, ext_id,
                                    user_name, uid, main_rows, detail_rows):
    '''Process one Chromium extension directory (by extension ID).'''
    try:
        versions = mac_info.ListItemsInFolder(ext_id_dir, EntryType.FOLDERS, False)
    except Exception:
        return
    for ver in versions:
        ver_dir     = ext_id_dir + '/' + ver['name']
        manifest_path = ver_dir + '/manifest.json'
        if not mac_info.IsValidFilePath(manifest_path):
            continue
        mac_info.ExportFile(manifest_path, __Plugin_Name, 'chromext_', False)

        manifest = {}
        f = mac_info.Open(manifest_path)
        if f:
            try:
                raw = f.read()
                if isinstance(raw, bytes):
                    raw = raw.decode('utf-8', errors='replace')
                manifest = json.loads(raw)
            except Exception:
                pass

        name        = manifest.get('name', ext_id)
        permissions = manifest.get('permissions', [])
        bg          = manifest.get('background', {})
        bg_scripts  = bg.get('scripts', []) if isinstance(bg, dict) else []
        bg_page     = bg.get('page', '') if isinstance(bg, dict) else ''

        main_rows.append(make_main_row(
            mechanism='Extension Persistence',
            sub_mechanism='chromium_extension',
            scope=get_scope(user_name),
            user=user_name,
            uid=uid,
            artifact_path=ver_dir,
            artifact_type='chromium_extension_dir',
            trigger='browser launch / profile load',
            label_or_name=name[:120],
            owner_bundle_id=ext_id,
            artifact_mtime=get_file_mtime(mac_info, ver_dir),
            source=manifest_path,
        ))
        if permissions:
            detail_rows.append(make_detail_row(
                artifact_path=ver_dir,
                evidence_type='extension_permissions',
                key_or_line='permissions',
                value=', '.join(str(p) for p in permissions[:30]),
                user=user_name,
            ))
        for s in bg_scripts:
            detail_rows.append(make_detail_row(
                artifact_path=ver_dir,
                evidence_type='background_script',
                key_or_line='background.scripts',
                value=s,
                user=user_name,
            ))
        if bg_page:
            detail_rows.append(make_detail_row(
                artifact_path=ver_dir,
                evidence_type='background_page',
                key_or_line='background.page',
                value=bg_page,
                user=user_name,
            ))
        break  # only process the first (latest) version dir


def process_chromium_managed_prefs(mac_info, plist_path, main_rows, detail_rows):
    '''Check managed preferences for ExtensionInstallForcelist (enterprise push).'''
    if not mac_info.IsValidFilePath(plist_path):
        return
    mac_info.ExportFile(plist_path, __Plugin_Name, 'chromium_managed_', False)
    success, plist, _ = mac_info.ReadPlist(plist_path)
    if not success or not isinstance(plist, dict):
        return
    forcelist = plist.get('ExtensionInstallForcelist', [])
    if not forcelist:
        return

    artifact_mtime = get_file_mtime(mac_info, plist_path)
    for entry in forcelist:
        ext_id = str(entry).split(';')[0].strip()
        main_rows.append(make_main_row(
            mechanism='Extension Persistence',
            sub_mechanism='chromium_extension',
            scope='system',
            artifact_path=plist_path,
            artifact_type='chromium_force_install_policy',
            trigger='browser launch / profile load',
            label_or_name=ext_id,
            owner_bundle_id=ext_id,
            enabled='True',
            artifact_mtime=artifact_mtime,
            source=plist_path,
        ))
        detail_rows.append(make_detail_row(
            artifact_path=plist_path,
            evidence_type='force_install_policy',
            key_or_line='ExtensionInstallForcelist',
            value=str(entry),
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

    log.info('Found {} extension persistence item(s)'.format(len(main_rows)))
    if main_rows:
        WriteList('extension persistence', 'EXTPERSIST', main_rows,
                  main_col_info, output_params, '')
    if detail_rows:
        WriteList('extension persistence detail', 'EXTPERSIST_DETAIL', detail_rows,
                  detail_col_info, output_params, '')


def _read_local_plist(path):
    try:
        with open(path, 'rb') as f:
            return True, plistlib.load(f)
    except Exception:
        return False, None


def _read_local_json(path):
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            return json.load(f)
    except Exception:
        return {}


def _get_local_bundle_info(bundle_path):
    '''Best-effort local bundle metadata for artifact-only mode.'''
    info = {
        'bundle_id': '',
        'label': os.path.basename(bundle_path),
        'main_binary_path': '',
    }
    for plist_path in (os.path.join(bundle_path, 'Contents', 'Info.plist'),
                       os.path.join(bundle_path, 'Info.plist')):
        if not os.path.isfile(plist_path):
            continue
        success, plist = _read_local_plist(plist_path)
        if not success or not isinstance(plist, dict):
            continue
        exec_name = plist.get('CFBundleExecutable', '')
        info['bundle_id'] = plist.get('CFBundleIdentifier', '')
        info['label'] = _get_bundle_label(plist, info['bundle_id'],
                                          os.path.basename(bundle_path))
        if exec_name:
            for candidate in (
                    os.path.join(bundle_path, 'Contents', 'MacOS', exec_name),
                    os.path.join(bundle_path, 'MacOS', exec_name),
                    os.path.join(bundle_path, 'Contents', exec_name)):
                if os.path.isfile(candidate):
                    info['main_binary_path'] = candidate
                    break
        if not info['main_binary_path']:
            for candidate_dir in (
                    os.path.join(bundle_path, 'Contents', 'MacOS'),
                    os.path.join(bundle_path, 'MacOS')):
                if os.path.isdir(candidate_dir):
                    names = sorted(os.listdir(candidate_dir))
                    if names:
                        info['main_binary_path'] = os.path.join(candidate_dir, names[0])
                        break
        break
    return info


def _infer_local_owner_app_path(appex_path):
    marker = os.sep + 'Contents' + os.sep + 'PlugIns' + os.sep
    if marker in appex_path:
        owner_app_path = appex_path.split(marker, 1)[0]
        if owner_app_path.endswith('.app'):
            return owner_app_path
    return ''


def _process_local_safari_appex(appex_path, owner_app_path, owner_bundle_id,
                                safari_bundle_index, main_rows, detail_rows):
    info_plist = os.path.join(appex_path, 'Contents', 'Info.plist')
    if not os.path.isfile(info_plist):
        return

    success, plist = _read_local_plist(info_plist)
    if not success or not isinstance(plist, dict):
        return

    ns_ext = plist.get('NSExtension', {})
    ext_point = ns_ext.get('NSExtensionPointIdentifier', '') if isinstance(ns_ext, dict) else ''
    sub_mechanism = classify_safari_extension_point(ext_point)
    if not sub_mechanism:
        return

    bundle_info = _get_local_bundle_info(appex_path)
    artifact_type = 'safari_web_appex' if sub_mechanism == 'safari_web_extension' else 'safari_app_appex'

    main_rows.append(make_main_row(
        mechanism='Extension Persistence',
        sub_mechanism=sub_mechanism,
        scope=get_bundle_scope(owner_app_path or appex_path),
        artifact_path=appex_path,
        artifact_type=artifact_type,
        target_path=bundle_info.get('main_binary_path', ''),
        trigger='browser launch / extension activation',
        owner_app_path=owner_app_path,
        owner_bundle_id=owner_bundle_id,
        label_or_name=bundle_info.get('label', ''),
        source=appex_path,
    ))
    detail_rows.append(make_detail_row(
        artifact_path=appex_path,
        evidence_type='extension_point',
        key_or_line='NSExtensionPointIdentifier',
        value=ext_point,
    ))
    if bundle_info.get('bundle_id', ''):
        detail_rows.append(make_detail_row(
            artifact_path=appex_path,
            evidence_type='appex_bundle_id',
            key_or_line='CFBundleIdentifier',
            value=bundle_info.get('bundle_id', ''),
        ))
        safari_bundle_index.setdefault(sub_mechanism, {})[bundle_info['bundle_id']] = {
            'appex_path': appex_path,
            'owner_app_path': owner_app_path,
            'owner_bundle_id': owner_bundle_id,
            'target_path': bundle_info.get('main_binary_path', ''),
            'label_or_name': bundle_info.get('label', ''),
        }

    if sub_mechanism == 'safari_web_extension':
        manifest_path = os.path.join(appex_path, 'Contents', 'Resources', 'manifest.json')
        manifest = _read_local_json(manifest_path)
        if isinstance(manifest, dict) and manifest:
            for key in ('name', 'version', 'manifest_version'):
                if key in manifest:
                    detail_rows.append(make_detail_row(
                        artifact_path=appex_path,
                        evidence_type='webextension_manifest',
                        key_or_line=key,
                        value=str(manifest.get(key, '')),
                        resolved_path=manifest_path,
                    ))


def _process_local_safari_app(owner_app_path, safari_bundle_index, main_rows, detail_rows):
    bundle_info = _get_local_bundle_info(owner_app_path)
    plugins_dir = os.path.join(owner_app_path, 'Contents', 'PlugIns')
    if not os.path.isdir(plugins_dir):
        return
    for name in sorted(os.listdir(plugins_dir)):
        if not name.endswith('.appex'):
            continue
        appex_path = os.path.join(plugins_dir, name)
        if os.path.isdir(appex_path):
            _process_local_safari_appex(
                appex_path,
                owner_app_path,
                bundle_info.get('bundle_id', ''),
                safari_bundle_index,
                main_rows,
                detail_rows,
            )


def _process_local_safari_state(plist_path, sub_mechanism, safari_bundle_index,
                                main_rows, detail_rows):
    success, plist = _read_local_plist(plist_path)
    if not success or not isinstance(plist, dict):
        return
    for ext_id, ext_info in plist.items():
        if not isinstance(ext_info, dict):
            continue
        bundle_match = safari_bundle_index.get(sub_mechanism, {}).get(ext_id, {})
        main_rows.append(make_main_row(
            mechanism='Extension Persistence',
            sub_mechanism=sub_mechanism,
            scope='user',
            artifact_path=plist_path,
            artifact_type='safari_extension_state',
            target_path=bundle_match.get('target_path', ''),
            trigger='browser launch / extension activation',
            enabled=str(ext_info.get('Enabled', '')),
            owner_app_path=bundle_match.get('owner_app_path', ''),
            owner_bundle_id=bundle_match.get('owner_bundle_id', '') or ext_id,
            label_or_name=ext_info.get('BundleDisplayName', '') or ext_id,
            source=plist_path,
        ))
        detail_rows.append(make_detail_row(
            artifact_path=plist_path,
            evidence_type='safari_extension_entry',
            key_or_line=ext_id,
            value=str(ext_info)[:300],
            resolved_path=bundle_match.get('appex_path', ''),
        ))
        if bundle_match:
            detail_rows.append(make_detail_row(
                artifact_path=plist_path,
                evidence_type='resolved_extension_bundle',
                key_or_line=ext_id,
                value=bundle_match.get('appex_path', ''),
                resolved_path=bundle_match.get('appex_path', ''),
            ))


def _process_local_system_extensions_in_app(owner_app_path, owner_index, main_rows, detail_rows):
    owner_info = _get_local_bundle_info(owner_app_path)
    se_dir = os.path.join(owner_app_path, 'Contents', 'Library', 'SystemExtensions')
    if not os.path.isdir(se_dir):
        return
    for name in sorted(os.listdir(se_dir)):
        if not name.endswith('.systemextension'):
            continue
        ext_path = os.path.join(se_dir, name)
        if not os.path.isdir(ext_path):
            continue
        bundle_info = _get_local_bundle_info(ext_path)
        executable_name = os.path.basename(bundle_info.get('main_binary_path', '')) if bundle_info.get('main_binary_path', '') else ''
        _register_system_extension_owner(owner_index, _make_system_extension_owner_entry(
            owner_app_path,
            owner_info.get('bundle_id', ''),
            ext_path,
            bundle_info.get('bundle_id', ''),
            '',
            executable_name,
            bundle_info.get('main_binary_path', ''),
            '',
            '',
            bundle_info.get('label', name),
        ))
        main_rows.append(make_main_row(
            mechanism='Extension Persistence',
            sub_mechanism='system_extension',
            scope=get_bundle_scope(owner_app_path),
            artifact_path=ext_path,
            artifact_type='systemextension_bundle',
            target_path=bundle_info.get('main_binary_path', ''),
            trigger='boot / activation / load',
            owner_app_path=owner_app_path,
            owner_bundle_id=owner_info.get('bundle_id', ''),
            label_or_name=bundle_info.get('label', name),
            source=ext_path,
        ))
        detail_rows.append(make_detail_row(
            artifact_path=ext_path,
            evidence_type='sysext_bundle_id',
            key_or_line='CFBundleIdentifier',
            value=bundle_info.get('bundle_id', ''),
        ))


def _process_local_activated_system_extension(ext_path, owner_index, main_rows, detail_rows):
    bundle_info = _get_local_bundle_info(ext_path)
    exec_name = os.path.basename(bundle_info.get('main_binary_path', '')) if bundle_info.get('main_binary_path', '') else ''
    owner_match, correlation_method = _match_system_extension_owner(
        owner_index,
        bundle_info.get('bundle_id', ''),
        '',
        exec_name,
    )
    main_rows.append(make_main_row(
        mechanism='Extension Persistence',
        sub_mechanism='system_extension',
        scope='system',
        artifact_path=ext_path,
        artifact_type='activated_systemextension',
        target_path=bundle_info.get('main_binary_path', ''),
        trigger='boot / activation / load',
        owner_app_path=owner_match.get('owner_app_path', ''),
        owner_bundle_id=owner_match.get('owner_bundle_id', ''),
        label_or_name=bundle_info.get('label', os.path.basename(ext_path)),
        source=ext_path,
    ))
    detail_rows.append(make_detail_row(
        artifact_path=ext_path,
        evidence_type='activated_sysext_bundle_id',
        key_or_line='CFBundleIdentifier',
        value=bundle_info.get('bundle_id', ''),
    ))
    if correlation_method:
        detail_rows.append(make_detail_row(
            artifact_path=ext_path,
            evidence_type='owner_correlation',
            key_or_line='CorrelationMethod',
            value=correlation_method,
            resolved_path=owner_match.get('owner_app_path', ''),
        ))
        detail_rows.append(make_detail_row(
            artifact_path=ext_path,
            evidence_type='embedded_owner_copy',
            key_or_line='EmbeddedSystemExtension',
            value=owner_match.get('embedded_path', ''),
            resolved_path=owner_match.get('embedded_path', ''),
        ))


# ---------------------------------------------------------------------------
# Plugin entry points
# ---------------------------------------------------------------------------

def Plugin_Start(mac_info):
    '''Main entry point for plugin'''
    main_rows   = []
    detail_rows = []
    safari_bundle_index = {}
    owner_index = {}

    app_bundle_paths = list_curated_app_bundles(mac_info)

    # --- Chromium managed prefs (system-wide policy) ---
    for mgd_path in CHROMIUM_MANAGED_PREFS:
        if mac_info.IsValidFilePath(mgd_path):
            process_chromium_managed_prefs(mac_info, mgd_path, main_rows, detail_rows)

    # --- App bundle scan: system extensions + Finder Sync + Safari app/web appex ---
    for bundle_path in app_bundle_paths:
        cs = get_bundle_info(mac_info, bundle_path)
        process_system_extensions_in_bundle(
            mac_info, bundle_path, cs.bundle_id, cs.team_id,
            owner_index, main_rows, detail_rows)
        process_finder_sync_extensions(
            mac_info, bundle_path, cs.bundle_id,
            main_rows, detail_rows)
        process_safari_extension_bundles(
            mac_info, bundle_path, cs.bundle_id, cs.team_id,
            safari_bundle_index, main_rows, detail_rows)

    # --- Activated system extensions (global DB) ---
    process_activated_system_extensions(mac_info, owner_index, main_rows, detail_rows)

    # --- Per-user: Safari extension state + Chromium extensions ---
    processed2 = set()
    for user in mac_info.users:
        user_name = safe_user_label(user.user_name, user.home_dir)
        if not user_name:
            continue
        if user.home_dir in processed2:
            continue
        processed2.add(user.home_dir)

        # Safari
        process_safari_extension_state(
            mac_info,
            user.home_dir + '/Library/Safari/AppExtensions/Extensions.plist',
            user_name, user.UID, 'safari_app_extension', safari_bundle_index,
            main_rows, detail_rows)
        process_safari_extension_state(
            mac_info,
            user.home_dir + '/Library/Safari/WebExtensions/Extensions.plist',
            user_name, user.UID, 'safari_web_extension', safari_bundle_index,
            main_rows, detail_rows)

        # Chromium
        for profile_base in CHROMIUM_PROFILE_BASES:
            full_base = user.home_dir + profile_base
            if mac_info.IsValidFolderPath(full_base):
                process_chromium_extensions(
                    mac_info, full_base, user_name, user.UID,
                    main_rows, detail_rows)

    if main_rows or detail_rows:
        write_output(main_rows, detail_rows, mac_info.output_params)
    else:
        log.info('No extension persistence artifacts found')


def Plugin_Start_Standalone(input_files_list, output_params):
    log.info('Module started as standalone')
    main_rows   = []
    detail_rows = []
    safari_bundle_index = {}
    owner_index = {}

    for input_path in input_files_list:
        log.debug('Pre-scan input path: ' + input_path)
        if os.path.isdir(input_path) and input_path.endswith('.app'):
            _process_local_safari_app(input_path, safari_bundle_index, main_rows, detail_rows)
            _process_local_system_extensions_in_app(input_path, owner_index, main_rows, detail_rows)
        elif os.path.isdir(input_path) and input_path.endswith('.appex'):
            owner_app_path = _infer_local_owner_app_path(input_path)
            owner_bundle_id = _get_local_bundle_info(owner_app_path).get('bundle_id', '') if owner_app_path else ''
            _process_local_safari_appex(
                input_path,
                owner_app_path,
                owner_bundle_id,
                safari_bundle_index,
                main_rows,
                detail_rows,
            )

    for input_path in input_files_list:
        log.debug('Input path: ' + input_path)
        basename = os.path.basename(input_path)
        if os.path.isdir(input_path) and (input_path.endswith('.app') or input_path.endswith('.appex')):
            continue
        if os.path.isdir(input_path) and input_path.endswith('.systemextension'):
            _process_local_activated_system_extension(input_path, owner_index, main_rows, detail_rows)
        elif basename == 'manifest.json':
            # Chromium extension manifest
            try:
                with open(input_path, 'r', encoding='utf-8', errors='replace') as f:
                    manifest = json.load(f)
                name = manifest.get('name', os.path.dirname(input_path))
                main_rows.append(make_main_row(
                    mechanism='Extension Persistence',
                    sub_mechanism='chromium_extension',
                    artifact_path=os.path.dirname(input_path),
                    artifact_type='chromium_extension_dir',
                    trigger='browser launch / profile load',
                    label_or_name=name[:120],
                    source=input_path,
                ))
            except Exception:
                log.exception('Could not parse {}'.format(input_path))
        elif basename == 'Extensions.plist':
            # Safari extension state
            try:
                parent_name = os.path.basename(os.path.dirname(input_path)).lower()
                sub_mechanism = 'safari_web_extension' if parent_name == 'webextensions' else 'safari_app_extension'
                _process_local_safari_state(
                    input_path,
                    sub_mechanism,
                    safari_bundle_index,
                    main_rows,
                    detail_rows,
                )
            except Exception:
                log.exception('Could not parse {}'.format(input_path))
        else:
            log.warning('Unrecognised extension artifact: {}'.format(input_path))

    if main_rows or detail_rows:
        write_output(main_rows, detail_rows, output_params)
    else:
        log.info('No extension persistence found in provided files')


if __name__ == '__main__':
    print('This plugin is part of a framework and does not run independently.')
