'''
   Copyright (c) 2026 jaybird1291

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the
   terms of the MIT License.

   apptriggers.py
   --------------
   Detects app preference and handler-based execution triggers.

   Surfaces only keys or files with direct execution or handler impact:

     startup_script   : ~/.atom/init.coffee
                        ~/Library/Application Support/iTerm2/Scripts/AutoLaunch/
     screen_saver     : ~/Library/Preferences/ByHost/com.apple.screensaver.*.plist
                          (ModuleDict / moduleName / modulePath keys)
                        ~/Library/Screen Savers/*.saver  (user-writable bundles)
     pref_trigger     : ~/Library/Preferences/com.apple.Terminal.plist
                          (CommandString in shell profiles - startup command)
     ls_handler       : ~/Library/Preferences/com.apple.LaunchServices/
                          com.apple.launchservices.secure.plist
                          (LSHandlers - custom URL scheme / file type handlers)

   Output tables:
     APPTRIGGERS        - one row per execution-relevant key or file
     APPTRIGGERS_DETAIL - raw plist key/value, handler bundle ID, scheme
'''

import logging
import os
import re

from plugins.helpers.macinfo import *
from plugins.helpers.writer import *
from plugins.helpers.common import CommonFunctions
from plugins.helpers.codesign_offline import get_bundle_info
from plugins.helpers.persistence_common import (
    MAIN_TABLE_COLUMNS, DETAIL_TABLE_COLUMNS,
    make_main_row, make_detail_row,
    get_file_mtime, safe_user_label, get_scope,
)

__Plugin_Name = "APPTRIGGERS"
__Plugin_Friendly_Name = "App Triggers"
__Plugin_Version = "1.0"
__Plugin_Description = (
    "Detects execution triggers via app startup scripts, screensaver bundles, "
    "Terminal startup commands, and custom LaunchServices URL/file handlers"
)
__Plugin_Author = "jaybird1291"
__Plugin_Author_Email = ""
__Plugin_Modes = "MACOS,ARTIFACTONLY"
__Plugin_ArtifactOnly_Usage = (
    "Provide a com.apple.Terminal.plist, com.apple.launchservices.secure.plist, "
    "or a screensaver preferences plist"
)

log = logging.getLogger('MAIN.' + __Plugin_Name)

#---- Do not change the variable names in above section ----#

# Standard shell executable names that are not interesting as Terminal CommandStrings
STANDARD_SHELLS = {'/bin/sh', '/bin/bash', '/bin/zsh', '/bin/csh', '/bin/tcsh',
                   'sh', 'bash', 'zsh', 'csh', 'tcsh', '/usr/bin/login', 'login'}

# URL schemes that are too common to flag (http, mailto, etc.)
COMMON_URL_SCHEMES = {
    'http', 'https', 'mailto', 'ftp', 'ftps', 'ssh', 'afp', 'smb',
    'vnc', 'rdp', 'x-apple-helpviewer', 'x-apple-reminder',
    'webcal', 'itms', 'itms-apps', 'macappstore', 'maps',
}

SUSPICIOUS_DOCK_TERMS = (
    'helper', 'updater', 'agent', 'daemon', 'loader',
    'launcher', 'inject', 'monitor', 'service',
)

SYSTEM_APP_DIRS = ('/Applications', '/Library/Applications')


# ---------------------------------------------------------------------------
# Startup scripts
# ---------------------------------------------------------------------------

def process_startup_script(mac_info, file_path, user_name, uid,
                             sub_mech, trigger, main_rows, detail_rows):
    '''Emit one main row for a startup script file.'''
    if not mac_info.IsValidFilePath(file_path):
        return
    mac_info.ExportFile(file_path, __Plugin_Name, user_name + '_', False)
    artifact_mtime = get_file_mtime(mac_info, file_path)

    main_rows.append(make_main_row(
        mechanism='App Trigger',
        sub_mechanism=sub_mech,
        scope=get_scope(user_name),
        user=user_name,
        uid=uid,
        artifact_path=file_path,
        artifact_type='startup_script',
        target_path=file_path,
        trigger=trigger,
        label_or_name=os.path.basename(file_path),
        artifact_mtime=artifact_mtime,
        source=file_path,
    ))

    # Capture first few non-trivial lines as detail
    f = mac_info.Open(file_path)
    if f is None:
        return
    try:
        for lineno, raw in enumerate(f, start=1):
            if lineno > 30:
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


def process_iterm2_autolaunch(mac_info, home_dir, user_name, uid,
                               main_rows, detail_rows):
    '''Scan iTerm2 AutoLaunch directory for scripts.'''
    auto_dir = home_dir + '/Library/Application Support/iTerm2/Scripts/AutoLaunch'
    if not mac_info.IsValidFolderPath(auto_dir):
        return
    try:
        items = mac_info.ListItemsInFolder(auto_dir, EntryType.FILES, False)
    except Exception:
        return
    for item in items:
        script_path = auto_dir + '/' + item['name']
        process_startup_script(mac_info, script_path, user_name, uid,
                               'startup_script', 'iTerm2 window open',
                               main_rows, detail_rows)


def process_sublime_startup_scripts(mac_info, app_dir, user_name, uid,
                                     main_rows, detail_rows):
    '''Scan for Sublime Text startup scripts inside app bundles.'''
    if not mac_info.IsValidFolderPath(app_dir):
        return
    try:
        items = mac_info.ListItemsInFolder(app_dir, EntryType.FOLDERS, False)
    except Exception:
        return
    for item in items:
        if not (item['name'].startswith('Sublime Text') and item['name'].endswith('.app')):
            continue
        script_path = app_dir + '/' + item['name'] + '/Contents/MacOS/sublime.py'
        process_startup_script(mac_info, script_path, user_name, uid,
                               'startup_script', 'Sublime launch',
                               main_rows, detail_rows)


# ---------------------------------------------------------------------------
# Screensaver
# ---------------------------------------------------------------------------

def process_screensaver_pref(mac_info, plist_path, user_name, uid,
                               main_rows, detail_rows):
    '''Parse a com.apple.screensaver.*.plist for the active screen saver.'''
    if not mac_info.IsValidFilePath(plist_path):
        return
    mac_info.ExportFile(plist_path, __Plugin_Name, user_name + '_', False)
    success, plist, error = mac_info.ReadPlist(plist_path)
    if not success or not isinstance(plist, dict):
        return
    artifact_mtime = get_file_mtime(mac_info, plist_path)

    # modulePath / moduleName from top-level or nested ModuleDict
    module_path = plist.get('modulePath', '') or plist.get('moduleName', '')
    if not module_path and isinstance(plist.get('ModuleDict'), dict):
        module_path = plist.get('ModuleDict', {}).get('path', '')

    if not module_path:
        return

    # Enrich with codesign if the bundle exists
    team_id     = ''
    codesign_st = ''
    sha256      = ''
    if mac_info.IsValidFolderPath(module_path):
        cs = get_bundle_info(mac_info, module_path)
        team_id     = cs.team_id
        codesign_st = cs.codesign_status
        sha256      = cs.sha256

    main_rows.append(make_main_row(
        mechanism='App Trigger',
        sub_mechanism='screen_saver',
        scope=get_scope(user_name),
        user=user_name,
        uid=uid,
        artifact_path=plist_path,
        artifact_type='screensaver_pref',
        target_path=module_path,
        trigger='screensaver activation',
        label_or_name=os.path.basename(module_path),
        team_id=team_id,
        codesign_status=codesign_st,
        sha256=sha256,
        artifact_mtime=artifact_mtime,
        source=plist_path,
    ))
    detail_rows.append(make_detail_row(
        artifact_path=plist_path,
        evidence_type='screensaver_module',
        key_or_line='modulePath',
        value=module_path,
        user=user_name,
    ))


def process_screen_savers_dir(mac_info, saver_dir, user_name, uid,
                               main_rows, detail_rows):
    '''Scan ~/Library/Screen Savers/ for .saver bundles.'''
    if not mac_info.IsValidFolderPath(saver_dir):
        return
    try:
        items = mac_info.ListItemsInFolder(saver_dir, EntryType.FOLDERS, False)
    except Exception:
        return
    for item in items:
        if not item['name'].endswith('.saver'):
            continue
        saver_path = saver_dir + '/' + item['name']
        cs = get_bundle_info(mac_info, saver_path)
        info_plist = saver_path + '/Contents/Info.plist'
        if mac_info.IsValidFilePath(info_plist):
            mac_info.ExportFile(info_plist, __Plugin_Name, user_name + '_saver_', False)

        main_rows.append(make_main_row(
            mechanism='App Trigger',
            sub_mechanism='screen_saver',
            scope=get_scope(user_name),
            user=user_name,
            uid=uid,
            artifact_path=saver_path,
            artifact_type='screensaver_bundle',
            target_path=cs.main_binary_path,
            trigger='screensaver activation',
            owner_bundle_id=cs.bundle_id,
            label_or_name=cs.bundle_id or item['name'],
            team_id=cs.team_id,
            codesign_status=cs.codesign_status,
            sha256=cs.sha256,
            artifact_mtime=get_file_mtime(mac_info, saver_path),
            source=saver_path,
        ))


# ---------------------------------------------------------------------------
# Terminal startup command
# ---------------------------------------------------------------------------

def process_terminal_plist(mac_info, plist_path, user_name, uid,
                            main_rows, detail_rows):
    '''Parse com.apple.Terminal.plist for non-default CommandString values.'''
    if not mac_info.IsValidFilePath(plist_path):
        return
    mac_info.ExportFile(plist_path, __Plugin_Name, user_name + '_', False)
    success, plist, error = mac_info.ReadPlist(plist_path)
    if not success or not isinstance(plist, dict):
        return
    artifact_mtime = get_file_mtime(mac_info, plist_path)

    # Window Settings is a dict of profile_name -> profile_dict
    window_settings = plist.get('Window Settings', {})
    if not isinstance(window_settings, dict):
        return

    for profile_name, profile in window_settings.items():
        if not isinstance(profile, dict):
            continue
        cmd = profile.get('CommandString', '')
        if not cmd:
            continue
        # Only flag non-standard shell commands
        cmd_base = cmd.split()[0] if cmd.split() else cmd
        if cmd_base in STANDARD_SHELLS:
            continue

        main_rows.append(make_main_row(
            mechanism='App Trigger',
            sub_mechanism='pref_trigger',
            scope=get_scope(user_name),
            user=user_name,
            uid=uid,
            artifact_path=plist_path,
            artifact_type='terminal_pref',
            target_path=cmd_base,
            target_args=' '.join(cmd.split()[1:]) if len(cmd.split()) > 1 else '',
            trigger='new Terminal window / tab',
            label_or_name='CommandString:{}'.format(profile_name),
            artifact_mtime=artifact_mtime,
            source=plist_path,
        ))
        detail_rows.append(make_detail_row(
            artifact_path=plist_path,
            evidence_type='terminal_command_string',
            key_or_line='CommandString[{}]'.format(profile_name),
            value=cmd,
            user=user_name,
        ))


def _get_dock_target_path(tile_data):
    file_data = tile_data.get('file-data', {})
    if isinstance(file_data, dict):
        path = file_data.get('_CFURLString', '')
        if path:
            return CommonFunctions.url_decode(path)
    return ''


def _is_standard_dock_app_path(path, home_dir):
    if not path:
        return False
    if any(path.startswith(prefix + '/') or path == prefix for prefix in SYSTEM_APP_DIRS):
        return True
    if home_dir and (path.startswith(home_dir + '/Applications/') or path == home_dir + '/Applications'):
        return True
    return False


def _is_suspicious_dock_target(path, bundle_id, home_dir):
    if not path:
        return False
    lower_path = path.lower()
    lower_name = os.path.basename(lower_path)

    if lower_path.endswith(('.sh', '.py', '.rb', '.pl', '.command',
                            '.zsh', '.bash', '.scpt', '.applescript', '.plist')):
        return True
    if '/.' in path or lower_path.startswith(('/tmp/', '/private/tmp/', '/users/shared/',
                                              '/private/var/', '/library/application support/')):
        return True
    if any(term in lower_name for term in SUSPICIOUS_DOCK_TERMS):
        return True
    if not lower_path.endswith('.app'):
        return True
    if not _is_standard_dock_app_path(path, home_dir):
        return True
    if bundle_id and any(term in bundle_id.lower() for term in SUSPICIOUS_DOCK_TERMS):
        return True
    return False


def process_dock_plist(mac_info, plist_path, user_name, uid, home_dir,
                        main_rows, detail_rows):
    '''Parse com.apple.dock.plist and emit only suspicious execution-relevant items.'''
    if not mac_info.IsValidFilePath(plist_path):
        return
    mac_info.ExportFile(plist_path, __Plugin_Name, user_name + '_', False)
    success, plist, error = mac_info.ReadPlist(plist_path)
    if not success or not isinstance(plist, dict):
        return
    artifact_mtime = get_file_mtime(mac_info, plist_path)

    for key in ('persistent-apps', 'persistent-others'):
        items = plist.get(key, [])
        if not isinstance(items, list):
            continue
        for index, item in enumerate(items):
            if not isinstance(item, dict):
                continue
            tile_data = item.get('tile-data', {})
            if not isinstance(tile_data, dict):
                continue

            target_path = _get_dock_target_path(tile_data)
            bundle_id = tile_data.get('bundle-identifier', '') or item.get('bundle-identifier', '')
            if not _is_suspicious_dock_target(target_path, bundle_id, home_dir):
                continue

            label = tile_data.get('file-label', '') or bundle_id or os.path.basename(target_path) or 'Dock item'
            main_rows.append(make_main_row(
                mechanism='App Trigger',
                sub_mechanism='dock_trigger',
                scope=get_scope(user_name),
                user=user_name,
                uid=uid,
                artifact_path=plist_path,
                artifact_type='dock_pref',
                target_path=target_path,
                trigger='Dock click',
                owner_bundle_id=bundle_id,
                label_or_name=label,
                artifact_mtime=artifact_mtime,
                source=plist_path,
            ))
            detail_rows.append(make_detail_row(
                artifact_path=plist_path,
                evidence_type='dock_item',
                key_or_line='{}[{}]'.format(key, index),
                value=target_path or label,
                resolved_path=target_path,
                user=user_name,
            ))
            if bundle_id:
                detail_rows.append(make_detail_row(
                    artifact_path=plist_path,
                    evidence_type='dock_bundle_id',
                    key_or_line='bundle-identifier',
                    value=bundle_id,
                    resolved_path=target_path,
                    user=user_name,
                ))


# ---------------------------------------------------------------------------
# LaunchServices URL / file handlers
# ---------------------------------------------------------------------------

def process_launchservices_handlers(mac_info, plist_path, user_name, uid,
                                     main_rows, detail_rows):
    '''Parse com.apple.launchservices.secure.plist for custom URL/file handlers.'''
    if not mac_info.IsValidFilePath(plist_path):
        return
    mac_info.ExportFile(plist_path, __Plugin_Name, user_name + '_', False)
    success, plist, error = mac_info.ReadPlist(plist_path)
    if not success or not isinstance(plist, dict):
        return
    artifact_mtime = get_file_mtime(mac_info, plist_path)

    handlers = plist.get('LSHandlers', [])
    if not isinstance(handlers, list):
        return

    for handler in handlers:
        if not isinstance(handler, dict):
            continue

        scheme       = handler.get('LSHandlerURLScheme', '')
        content_type = handler.get('LSHandlerContentType', '')
        handler_app  = (handler.get('LSHandlerRoleAll', '')
                        or handler.get('LSHandlerRoleViewer', '')
                        or handler.get('LSHandlerRoleEditor', ''))

        if not handler_app:
            continue

        # Only flag custom URL schemes, not standard well-known ones
        if scheme and scheme.lower() in COMMON_URL_SCHEMES:
            continue

        label = scheme or content_type or 'unknown'

        main_rows.append(make_main_row(
            mechanism='App Trigger',
            sub_mechanism='ls_handler',
            scope=get_scope(user_name),
            user=user_name,
            uid=uid,
            artifact_path=plist_path,
            artifact_type='launchservices_handler',
            trigger='file open / URL scheme',
            owner_bundle_id=handler_app,
            label_or_name=label,
            artifact_mtime=artifact_mtime,
            source=plist_path,
        ))
        detail_rows.append(make_detail_row(
            artifact_path=plist_path,
            evidence_type='ls_handler_entry',
            key_or_line=label,
            value='handler={} scheme={} type={}'.format(
                handler_app, scheme, content_type),
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

    log.info('Found {} app trigger item(s)'.format(len(main_rows)))
    if main_rows:
        WriteList('app triggers', 'APPTRIGGERS', main_rows,
                  main_col_info, output_params, '')
    if detail_rows:
        WriteList('app triggers detail', 'APPTRIGGERS_DETAIL', detail_rows,
                  detail_col_info, output_params, '')


# ---------------------------------------------------------------------------
# Plugin entry points
# ---------------------------------------------------------------------------

def Plugin_Start(mac_info):
    main_rows   = []
    detail_rows = []
    processed   = set()

    for app_dir in SYSTEM_APP_DIRS:
        process_sublime_startup_scripts(
            mac_info, app_dir, 'root', 0, main_rows, detail_rows)

    for user in mac_info.users:
        user_name = safe_user_label(user.user_name, user.home_dir)
        if not user_name:
            continue
        if user.home_dir in processed:
            continue
        processed.add(user.home_dir)
        h = user.home_dir

        # --- Startup scripts ---
        process_startup_script(
            mac_info, h + '/.atom/init.coffee', user_name, user.UID,
            'startup_script', 'Atom launch', main_rows, detail_rows)

        process_iterm2_autolaunch(mac_info, h, user_name, user.UID,
                                   main_rows, detail_rows)
        process_sublime_startup_scripts(
            mac_info, h + '/Applications', user_name, user.UID,
            main_rows, detail_rows)

        # --- Screensaver preferences (ByHost) ---
        byhost_dir = h + '/Library/Preferences/ByHost'
        if mac_info.IsValidFolderPath(byhost_dir):
            try:
                items = mac_info.ListItemsInFolder(byhost_dir, EntryType.FILES, False)
            except Exception:
                items = []
            for item in items:
                if 'com.apple.screensaver' in item['name'] and item['name'].endswith('.plist'):
                    process_screensaver_pref(
                        mac_info,
                        byhost_dir + '/' + item['name'],
                        user_name, user.UID,
                        main_rows, detail_rows)

        # --- User screen saver bundles ---
        process_screen_savers_dir(
            mac_info, h + '/Library/Screen Savers',
            user_name, user.UID, main_rows, detail_rows)

        # --- Terminal startup command ---
        process_terminal_plist(
            mac_info,
            h + '/Library/Preferences/com.apple.Terminal.plist',
            user_name, user.UID, main_rows, detail_rows)
        process_dock_plist(
            mac_info,
            h + '/Library/Preferences/com.apple.dock.plist',
            user_name, user.UID, h,
            main_rows, detail_rows)

        # --- LaunchServices handlers ---
        process_launchservices_handlers(
            mac_info,
            h + '/Library/Preferences/com.apple.LaunchServices/'
                'com.apple.launchservices.secure.plist',
            user_name, user.UID, main_rows, detail_rows)

    if main_rows or detail_rows:
        write_output(main_rows, detail_rows, mac_info.output_params)
    else:
        log.info('No app trigger artifacts found')


def Plugin_Start_Standalone(input_files_list, output_params):
    log.info('Module started as standalone')
    main_rows   = []
    detail_rows = []
    import plistlib

    for input_path in input_files_list:
        log.debug('Input path: ' + input_path)
        basename = os.path.basename(input_path)

        if 'com.apple.Terminal' in basename:
            _standalone_plist_parse(input_path, process_terminal_plist,
                                    main_rows, detail_rows)
        elif 'com.apple.dock' in basename:
            _standalone_plist_parse(input_path, _standalone_process_dock_plist,
                                    main_rows, detail_rows)
        elif 'com.apple.launchservices.secure' in basename:
            _standalone_plist_parse(input_path, process_launchservices_handlers,
                                    main_rows, detail_rows)
        elif 'com.apple.screensaver' in basename:
            _standalone_plist_parse(input_path, process_screensaver_pref,
                                    main_rows, detail_rows)
        elif basename == 'sublime.py':
            _standalone_process_startup_script(
                input_path, 'startup_script', 'Sublime launch',
                main_rows, detail_rows)
        else:
            log.warning('Unrecognised app trigger artifact: {}'.format(input_path))

    if main_rows or detail_rows:
        write_output(main_rows, detail_rows, output_params)
    else:
        log.info('No app trigger artifacts found in provided files')


def _standalone_plist_parse(path, handler_fn, main_rows, detail_rows):
    '''Wrap a plist-based handler for standalone use (no mac_info).'''
    import plistlib
    try:
        with open(path, 'rb') as f:
            plist = plistlib.load(f)
    except Exception as ex:
        log.error('Could not read {}: {}'.format(path, ex))
        return

    class _FakeMacInfo:
        '''Minimal stand-in for mac_info when running standalone.'''
        def IsValidFilePath(self, p): return os.path.isfile(p)
        def IsValidFolderPath(self, p): return os.path.isdir(p)
        def ExportFile(self, *a, **kw): pass
        def ReadPlist(self, p):
            if p == path:
                return True, plist, ''
            try:
                with open(p, 'rb') as f:
                    return True, plistlib.load(f), ''
            except Exception as ex:
                return False, None, str(ex)
        def Open(self, p):
            try: return open(p, 'rb')
            except OSError: return None
        def GetFileMACTimes(self, p): return {}

    handler_fn(_FakeMacInfo(), path, '', '', main_rows, detail_rows)


def _standalone_process_dock_plist(mac_info, path, user_name, uid, main_rows, detail_rows):
    process_dock_plist(mac_info, path, user_name, uid, '', main_rows, detail_rows)


def _standalone_process_startup_script(path, sub_mech, trigger, main_rows, detail_rows):
    class _FakeMacInfo:
        def IsValidFilePath(self, p): return os.path.isfile(p)
        def ExportFile(self, *a, **kw): pass
        def Open(self, p):
            try: return open(p, 'rb')
            except OSError: return None
        def GetFileMACTimes(self, p): return {}

    process_startup_script(_FakeMacInfo(), path, '', '', sub_mech, trigger,
                           main_rows, detail_rows)


if __name__ == '__main__':
    print('This plugin is part of a framework and does not run independently.')
