'''
   Copyright (c) 2026 jaybird1291

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the
   terms of the MIT License.

   pluginpersist.py
   ----------------
   Detects plugin ecosystems that can be abused for auto-loading execution.

   Only plugin families with explicit auto-load semantics are covered:

     securityagent     : /Library/Security/SecurityAgentPlugins/
                         Loaded by securityd / Security Agent for auth dialogs.
     directoryservices : /Library/DirectoryServices/PlugIns/
                         Loaded by DirectoryService daemon.
     quicklook         : ~/Library/QuickLook  /Library/QuickLook
                         Loaded by QuickLookUIService when previewing files.
     spotlight_importer: /Library/Spotlight  ~/Library/Spotlight
                         Loaded by Spotlight when indexing files.
     xbar              : ~/Library/Application Support/xbar/plugins
                         Auto-executed by xbar (menu bar app) on startup.
     editor_plugin     : ~/.vim/plugin  ~/.vim/autoload  ~/.config/nvim/plugin
                         Auto-sourced by Vim/NeoVim at startup.

   Output tables:
     PLUGINPERSIST        - one row per plugin bundle or script
     PLUGINPERSIST_DETAIL - bundle IDs, Team ID, entry-point path
'''

import logging
import os
import re

from plugins.helpers.macinfo import *
from plugins.helpers.writer import *
from plugins.helpers.codesign_offline import get_bundle_info, get_binary_codesign_info
from plugins.helpers.persistence_common import (
    MAIN_TABLE_COLUMNS, DETAIL_TABLE_COLUMNS,
    make_main_row, make_detail_row,
    get_file_mtime, safe_user_label,
)

__Plugin_Name = "PLUGINPERSIST"
__Plugin_Friendly_Name = "Plugin Persistence"
__Plugin_Version = "1.0"
__Plugin_Description = (
    "Detects auto-loading plugin persistence: SecurityAgent, DirectoryServices, "
    "QuickLook, Spotlight, xbar, and editor plugins"
)
__Plugin_Author = "jaybird1291"
__Plugin_Author_Email = ""
__Plugin_Modes = "MACOS,ARTIFACTONLY"
__Plugin_ArtifactOnly_Usage = "Provide a plugin bundle directory or a xbar/vim plugin file"

log = logging.getLogger('MAIN.' + __Plugin_Name)

#---- Do not change the variable names in above section ----#

# ---------------------------------------------------------------------------
# Plugin directory definitions
# ---------------------------------------------------------------------------

# System-wide directories: (path, sub_mechanism, item_type)
# item_type: 'bundle' | 'script' | 'any'
SYSTEM_PLUGIN_DIRS = [
    ('/Library/Security/SecurityAgentPlugins', 'securityagent',      'bundle'),
    ('/Library/DirectoryServices/PlugIns',     'directoryservices',  'bundle'),
    ('/Library/QuickLook',                     'quicklook',          'bundle'),
    ('/Library/Spotlight',                     'spotlight_importer', 'bundle'),
    ('/Library/iTunes/iTunes Plug-ins',        'app_plugin',         'any'),
]

# Per-user directories (relative to home_dir)
USER_PLUGIN_DIRS = [
    ('/Library/QuickLook',                                   'quicklook',          'bundle'),
    ('/Library/Spotlight',                                   'spotlight_importer', 'bundle'),
    ('/Library/Application Support/xbar/plugins',            'xbar',               'script'),
    ('/Library/iTunes/iTunes Plug-ins',                      'app_plugin',         'any'),
    ('/.vim/plugin',                                         'editor_plugin',      'script'),
    ('/.vim/autoload',                                       'editor_plugin',      'script'),
    ('/.vim/after/plugin',                                   'editor_plugin',      'script'),
    ('/.config/nvim/plugin',                                 'editor_plugin',      'script'),
    ('/.config/nvim/autoload',                               'editor_plugin',      'script'),
    ('/.config/nvim/after/plugin',                           'editor_plugin',      'script'),
    ('/.local/share/nvim/site/plugin',                       'editor_plugin',      'script'),
    ('/.local/share/nvim/site/autoload',                     'editor_plugin',      'script'),
    ('/Library/Application Support/Sublime Text 3/Packages', 'editor_plugin',      'any'),
    ('/Library/Application Support/Sublime Text/Packages',   'editor_plugin',      'any'),
]

# Bundle extensions that indicate an auto-loading plugin bundle
BUNDLE_EXTS = {'.plugin', '.bundle', '.qlgenerator', '.mdimporter',
               '.SecurityAgentPlugin', '.dsplug', '.appex'}


# ---------------------------------------------------------------------------
# Core scanner
# ---------------------------------------------------------------------------

def _is_bundle(name):
    _, ext = os.path.splitext(name)
    return ext.lower() in BUNDLE_EXTS or name.endswith('.app')


def process_plugin_dir(mac_info, directory, sub_mechanism, item_type,
                        user_name, uid, main_rows, detail_rows):
    '''Scan one plugin directory and emit rows for every plugin found.'''
    if not mac_info.IsValidFolderPath(directory):
        return

    try:
        entry_type = EntryType.FILES_AND_FOLDERS
        items = mac_info.ListItemsInFolder(directory, entry_type, False)
    except Exception:
        return

    trigger_map = {
        'securityagent':      'authentication dialog',
        'directoryservices':  'directory service lookup',
        'quicklook':          'file preview',
        'spotlight_importer': 'Spotlight indexing',
        'xbar':               'menu bar app launch',
        'editor_plugin':      'editor startup',
        'app_plugin':         'host app launch / plugin discovery',
    }
    trigger = trigger_map.get(sub_mechanism, 'host launch / plugin discovery')

    for item in items:
        name      = item['name']
        item_path = directory + '/' + name

        # Skip hidden files / resource forks
        if name.startswith('._') or name.startswith('.DS_Store'):
            continue

        is_dir = mac_info.IsValidFolderPath(item_path)

        if item_type == 'bundle' and not (is_dir and _is_bundle(name)):
            continue
        if item_type == 'script' and is_dir:
            continue
        # 'any': process both files and dirs that look relevant

        cs = None
        target_path = ''
        team_id     = ''
        codesign_st = ''
        sha256      = ''
        bundle_id   = ''

        if is_dir:
            # Bundle: get codesign info
            mac_info.ExportFile(item_path + '/Contents/Info.plist',
                                __Plugin_Name, '', False) \
                if mac_info.IsValidFilePath(item_path + '/Contents/Info.plist') else None
            cs = get_bundle_info(mac_info, item_path)
            target_path = cs.main_binary_path
            team_id     = cs.team_id
            codesign_st = cs.codesign_status
            sha256      = cs.sha256
            bundle_id   = cs.bundle_id
        else:
            # Script or flat binary
            mac_info.ExportFile(item_path, __Plugin_Name, '', False)
            cs = get_binary_codesign_info(mac_info, item_path)
            target_path = item_path
            team_id     = cs.team_id
            codesign_st = cs.codesign_status
            sha256      = cs.sha256

        artifact_mtime = get_file_mtime(mac_info, item_path)

        main_rows.append(make_main_row(
            mechanism='Plugin Persistence',
            sub_mechanism=sub_mechanism,
            scope='system' if not user_name or user_name == 'root' else 'user',
            user=user_name,
            uid=uid,
            artifact_path=item_path,
            artifact_type='plugin_bundle' if is_dir else 'plugin_script',
            target_path=target_path,
            trigger=trigger,
            owner_bundle_id=bundle_id,
            label_or_name=bundle_id or name,
            team_id=team_id,
            codesign_status=codesign_st,
            sha256=sha256,
            artifact_mtime=artifact_mtime,
            source=item_path,
        ))

        if bundle_id:
            detail_rows.append(make_detail_row(
                artifact_path=item_path,
                evidence_type='plugin_bundle_id',
                key_or_line='CFBundleIdentifier',
                value=bundle_id,
                user=user_name,
            ))
        if target_path:
            detail_rows.append(make_detail_row(
                artifact_path=item_path,
                evidence_type='plugin_executable',
                key_or_line='ExecutablePath',
                value=target_path,
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

    log.info('Found {} plugin persistence item(s)'.format(len(main_rows)))
    if main_rows:
        WriteList('plugin persistence', 'PLUGINPERSIST', main_rows,
                  main_col_info, output_params, '')
    if detail_rows:
        WriteList('plugin persistence detail', 'PLUGINPERSIST_DETAIL', detail_rows,
                  detail_col_info, output_params, '')


# ---------------------------------------------------------------------------
# Plugin entry points
# ---------------------------------------------------------------------------

def Plugin_Start(mac_info):
    main_rows   = []
    detail_rows = []
    processed   = set()

    # System-wide plugin dirs
    for directory, sub_mech, item_type in SYSTEM_PLUGIN_DIRS:
        if directory in processed:
            continue
        processed.add(directory)
        process_plugin_dir(mac_info, directory, sub_mech, item_type,
                           'root', 0, main_rows, detail_rows)

    # Per-user plugin dirs
    user_processed = set()
    for user in mac_info.users:
        user_name = safe_user_label(user.user_name, user.home_dir)
        if not user_name:
            continue
        if user.home_dir in user_processed:
            continue
        user_processed.add(user.home_dir)

        for rel_path, sub_mech, item_type in USER_PLUGIN_DIRS:
            full_path = user.home_dir + rel_path
            if full_path in processed:
                continue
            processed.add(full_path)
            process_plugin_dir(mac_info, full_path, sub_mech, item_type,
                               user_name, user.UID, main_rows, detail_rows)

    if main_rows or detail_rows:
        write_output(main_rows, detail_rows, mac_info.output_params)
    else:
        log.info('No plugin persistence artifacts found')


def Plugin_Start_Standalone(input_files_list, output_params):
    log.info('Module started as standalone')
    main_rows   = []
    detail_rows = []
    for input_path in input_files_list:
        log.debug('Input path: ' + input_path)
        name = os.path.basename(input_path)
        lower_path = input_path.lower()
        sub_mechanism = 'unknown'
        if '.qlgenerator' in lower_path or '/quicklook/' in lower_path:
            sub_mechanism = 'quicklook'
        elif '/spotlight/' in lower_path or lower_path.endswith('.mdimporter'):
            sub_mechanism = 'spotlight_importer'
        elif 'securityagentplugins' in lower_path:
            sub_mechanism = 'securityagent'
        elif 'directoryservices/plugins' in lower_path:
            sub_mechanism = 'directoryservices'
        elif 'itunes plug-ins' in lower_path:
            sub_mechanism = 'app_plugin'
        elif '/.vim/' in lower_path or '/nvim/' in lower_path:
            sub_mechanism = 'editor_plugin'
        elif '/xbar/plugins/' in lower_path or re.search(r'\.\d+[smhd]?\.[^.]+$', name.lower()):
            sub_mechanism = 'xbar'
        main_rows.append(make_main_row(
            mechanism='Plugin Persistence',
            sub_mechanism=sub_mechanism,
            artifact_path=input_path,
            artifact_type='plugin_bundle' if os.path.isdir(input_path) else 'plugin_script',
            target_path=input_path,
            trigger='host launch / plugin discovery',
            label_or_name=name,
            source=input_path,
        ))
    if main_rows:
        write_output(main_rows, detail_rows, output_params)
    else:
        log.info('No plugin persistence found in provided paths')


if __name__ == '__main__':
    print('This plugin is part of a framework and does not run independently.')
