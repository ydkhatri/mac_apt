'''
   Copyright (c) 2026 jaybird1291

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the
   terms of the MIT License.

   emondpersist.py
   ---------------
   Detects emond (Event Monitor Daemon) rule-based persistence.

   emond evaluates event rules and fires configured actions.
   An attacker can drop a rule file into /etc/emond.d/rules/ that runs
   an arbitrary command when a system event is triggered (e.g. network
   coming up, system startup, user login).

   Artifacts covered:
     /etc/emond.d/rules/          - rule plists (each file = one ruleset)
     /private/var/db/emondClients - registered client list (presence indicator)
     /System/Library/LaunchDaemons/com.apple.emond.plist - context only (not parsed)

   Output tables:
     EMONDPERSIST        - one row per actionable rule command target
     EMONDPERSIST_DETAIL - condition type, action type, raw plist key/value
'''

import logging
import os

from plugins.helpers.macinfo import *
from plugins.helpers.writer import *
from plugins.helpers.persistence_common import (
    MAIN_TABLE_COLUMNS, DETAIL_TABLE_COLUMNS,
    make_main_row, make_detail_row,
    get_file_mtime,
)

__Plugin_Name = "EMONDPERSIST"
__Plugin_Friendly_Name = "Emond Persistence"
__Plugin_Version = "1.0"
__Plugin_Description = "Detects emond rule-based persistence (/etc/emond.d/rules/)"
__Plugin_Author = "jaybird1291"
__Plugin_Author_Email = ""
__Plugin_Modes = "MACOS,ARTIFACTONLY"
__Plugin_ArtifactOnly_Usage = "Provide an emond rule plist file from /etc/emond.d/rules/"

log = logging.getLogger('MAIN.' + __Plugin_Name)

#---- Do not change the variable names in above section ----#

EMOND_RULES_DIRS = [
    '/etc/emond.d/rules',
    '/private/etc/emond.d/rules',
]
EMOND_CLIENTS_PATH = '/private/var/db/emondClients'

# Action types that have an execution target (only these produce main-table rows)
EXEC_ACTION_TYPES = {'RunCommand'}


# ---------------------------------------------------------------------------
# Rule plist parser
# ---------------------------------------------------------------------------

def process_emond_rule_file(mac_info, file_path, main_rows, detail_rows):
    '''Parse one emond rule plist file.
    Each plist is a list of rule dicts; each rule has conditions and actions.'''
    if mac_info:
        mac_info.ExportFile(file_path, __Plugin_Name, '', False)
        success, plist, error = mac_info.ReadPlist(file_path)
        if not success:
            log.error('Could not read emond rule {}: {}'.format(file_path, error))
            return
    else:
        import plistlib
        try:
            with open(file_path, 'rb') as f:
                plist = plistlib.load(f)
        except Exception as ex:
            log.error('Could not read {}: {}'.format(file_path, str(ex)))
            return

    artifact_mtime = get_file_mtime(mac_info, file_path) if mac_info else None

    # Rule file may be a list of rules or a single rule dict
    if isinstance(plist, dict):
        rules = [plist]
    elif isinstance(plist, list):
        rules = plist
    else:
        log.warning('Unexpected emond plist structure in {}'.format(file_path))
        return

    for rule_idx, rule in enumerate(rules):
        if not isinstance(rule, dict):
            continue

        rule_name = rule.get('name', 'rule-{}'.format(rule_idx))
        enabled   = str(rule.get('enabled', True))

        # Summarise conditions for the trigger field
        conditions = rule.get('conditions', [])
        trigger_parts = []
        for cond in (conditions if isinstance(conditions, list) else [conditions]):
            if isinstance(cond, dict):
                cond_type = cond.get('type', '')
                if cond_type:
                    trigger_parts.append(cond_type)
                detail_rows.append(make_detail_row(
                    artifact_path=file_path,
                    evidence_type='emond_condition',
                    key_or_line='condition.type',
                    value=str(cond),
                ))
        trigger = ', '.join(trigger_parts) or 'event-driven'

        # Process actions
        actions = rule.get('actions', [])
        for action in (actions if isinstance(actions, list) else [actions]):
            if not isinstance(action, dict):
                continue

            action_type = action.get('type', '')
            # Command target lives in different keys depending on action type
            if action_type == 'RunCommand':
                command = action.get('command', '')
                args    = ' '.join(action.get('arguments', []))
                target  = command
            else:
                command = ''
                args    = ''
                target  = ''

            detail_rows.append(make_detail_row(
                artifact_path=file_path,
                evidence_type='emond_action',
                key_or_line='action.type',
                value=str(action),
            ))

            # Emit a main row only for actions that execute something
            if action_type in EXEC_ACTION_TYPES:
                main_rows.append(make_main_row(
                    mechanism='Emond Persistence',
                    sub_mechanism='emond_rule',
                    scope='system',
                    user='root',
                    uid=0,
                    artifact_path=file_path,
                    artifact_type='emond_rule',
                    target_path=target,
                    target_args=args,
                    trigger=trigger,
                    enabled=enabled,
                    label_or_name=rule_name,
                    artifact_mtime=artifact_mtime,
                    source=file_path,
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

    log.info('Found {} emond persistence item(s)'.format(len(main_rows)))
    if main_rows:
        WriteList('emond persistence', 'EMONDPERSIST', main_rows,
                  main_col_info, output_params, '')
    if detail_rows:
        WriteList('emond persistence detail', 'EMONDPERSIST_DETAIL', detail_rows,
                  detail_col_info, output_params, '')


# ---------------------------------------------------------------------------
# Plugin entry points
# ---------------------------------------------------------------------------

def Plugin_Start(mac_info):
    '''Main entry point for plugin'''
    main_rows   = []
    detail_rows = []
    processed   = set()

    # emond rules directories
    for rules_dir in EMOND_RULES_DIRS:
        if rules_dir in processed:
            continue
        if mac_info.IsValidFolderPath(rules_dir):
            processed.add(rules_dir)
            try:
                items = mac_info.ListItemsInFolder(rules_dir, EntryType.FILES, False)
            except Exception:
                items = []
            for item in items:
                rule_path = rules_dir + '/' + item['name']
                if rule_path in processed:
                    continue
                if item['name'].endswith('.plist') or '.' not in item['name']:
                    processed.add(rule_path)
                    process_emond_rule_file(mac_info, rule_path, main_rows, detail_rows)
            break  # /etc → /private/etc symlink; process only once

    # emondClients: presence indicates emond was (or is) active
    if mac_info.IsValidFilePath(EMOND_CLIENTS_PATH):
        mac_info.ExportFile(EMOND_CLIENTS_PATH, __Plugin_Name, '', False)
        detail_rows.append(make_detail_row(
            artifact_path=EMOND_CLIENTS_PATH,
            evidence_type='emond_clients',
            key_or_line='presence',
            value=EMOND_CLIENTS_PATH,
        ))

    if main_rows or detail_rows:
        write_output(main_rows, detail_rows, mac_info.output_params)
    else:
        log.info('No emond persistence artifacts found')


def Plugin_Start_Standalone(input_files_list, output_params):
    '''Entry point for single-artifact mode'''
    log.info('Module started as standalone')
    main_rows   = []
    detail_rows = []

    for input_path in input_files_list:
        log.debug('Input path: ' + input_path)
        process_emond_rule_file(None, input_path, main_rows, detail_rows)

    if main_rows or detail_rows:
        write_output(main_rows, detail_rows, output_params)
    else:
        log.info('No emond persistence found in provided files')


if __name__ == '__main__':
    print('This plugin is part of a framework and does not run independently.')
