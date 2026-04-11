'''
   Copyright (c) 2026 jaybird1291

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the
   terms of the MIT License.

   eventkitpersist.py
   ------------------
   Detects calendar-event-based persistence via EventKit procedure alarms.

   Calendar events can carry alarms with ZACTION=4 ("procedure" / "open file")
   that execute a script or application when the alarm fires.  This technique
   has been observed in macOS malware (e.g., Bundlore variants) and allows
   persistence that survives reboots through recurring events.

   Only ZACTION=4 alarms are reported; display (0), email (1), and sound (2)
   alarms are suppressed to keep output noise-free.

   Artifacts scanned:
     ~/Library/Calendars/Calendar Cache   (EventKit CoreData SQLite, per user)

   Schema notes:
     The Calendar Cache uses CoreData with Z_ table prefixes.  Key tables:
       ZCALALARM  - alarm records; ZACTION=4 means "open file / run procedure"
       ZCALEVENT  - event records; joined via ZCALALARM.ZEVENT = ZCALEVENT.Z_PK
       ZCALENDAR  - calendar records
     Apple CoreData epoch: seconds since 2001-01-01 (add 978307200 for Unix epoch).
     The column holding the procedure path varies by macOS version:
       - "ZSCRIPT"       (older, up to ~macOS 12)
       - "ZPROCEDUREPATH" (newer)
     Both are tried; whichever is NULL/absent is silently ignored.

   Output tables:
     EVENTKITPERSIST        - one row per procedure alarm
     EVENTKITPERSIST_DETAIL - raw field values (event title, offset, calendar)
'''

import datetime
import logging
import os
import sqlite3

from plugins.helpers.macinfo import *
from plugins.helpers.writer import *
from plugins.helpers.common import CommonFunctions
from plugins.helpers.persistence_common import (
    MAIN_TABLE_COLUMNS, DETAIL_TABLE_COLUMNS,
    make_main_row, make_detail_row,
    get_file_mtime, safe_user_label, get_scope,
)

__Plugin_Name = "EVENTKITPERSIST"
__Plugin_Friendly_Name = "EventKit / Calendar Persistence"
__Plugin_Version = "1.0"
__Plugin_Description = (
    "Detects EventKit procedure alarms (ZACTION=4) that execute scripts or "
    "applications on a calendar-event schedule - a known macOS persistence technique"
)
__Plugin_Author = "jaybird1291"
__Plugin_Author_Email = ""
__Plugin_Modes = "MACOS,ARTIFACTONLY"
__Plugin_ArtifactOnly_Usage = "Provide a 'Calendar Cache' SQLite file path"

log = logging.getLogger('MAIN.' + __Plugin_Name)

#---- Do not change the variable names in above section ----#

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CALENDAR_CACHE_REL = '/Library/Calendars/Calendar Cache'

# CoreData Apple epoch offset (seconds from Unix epoch to 2001-01-01 00:00:00 UTC)
APPLE_EPOCH_OFFSET = 978307200

# ZCALALARM.ZACTION values
ALARM_ACTION_DISPLAY   = 0
ALARM_ACTION_EMAIL     = 1
ALARM_ACTION_SOUND     = 2
ALARM_ACTION_PROCEDURE = 4   # open file / run script - only this is flagged


# ---------------------------------------------------------------------------
# Schema introspection helpers
# ---------------------------------------------------------------------------

def _table_exists(conn, table_name):
    cur = conn.execute(
        "SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?",
        (table_name,))
    return cur.fetchone()[0] > 0


def _column_names(conn, table_name):
    '''Return set of column names (lower-case) for table_name.'''
    try:
        cur = conn.execute('PRAGMA table_info("{}")'.format(table_name))
        return {row[1].lower() for row in cur.fetchall()}
    except Exception:
        return set()


def _apple_epoch_to_datetime(value):
    '''Convert CoreData Apple-epoch float/int to datetime (UTC), or None.'''
    if value is None:
        return None
    try:
        unix_ts = float(value) + APPLE_EPOCH_OFFSET
        return datetime.datetime.utcfromtimestamp(unix_ts)
    except (TypeError, ValueError, OverflowError, OSError):
        return None


def _format_offset(seconds):
    '''Format a relative alarm offset (seconds) as a human-readable string.'''
    if seconds is None:
        return ''
    try:
        secs = int(seconds)
    except (TypeError, ValueError):
        return str(seconds)
    if secs == 0:
        return 'at event time'
    sign  = 'before' if secs < 0 else 'after'
    secs  = abs(secs)
    days, rem  = divmod(secs, 86400)
    hours, rem = divmod(rem, 3600)
    mins, secs = divmod(rem, 60)
    parts = []
    if days:  parts.append('{} day{}'.format(days,  's' if days  != 1 else ''))
    if hours: parts.append('{} hour{}'.format(hours, 's' if hours != 1 else ''))
    if mins:  parts.append('{} min{}'.format(mins,   's' if mins  != 1 else ''))
    if secs:  parts.append('{} sec'.format(secs))
    return '{} {}'.format(', '.join(parts) or '0 sec', sign)


# ---------------------------------------------------------------------------
# Database query
# ---------------------------------------------------------------------------

def _build_query(alarm_cols, event_cols, calendar_cols):
    '''Build a SELECT query adapted to the available columns.
    Returns (query_string, has_startdate, script_col_name_or_None).'''

    # Procedure path column (varies by macOS version)
    script_col = None
    for candidate in ('zscript', 'zprocedurepath'):
        if candidate in alarm_cols:
            script_col = candidate
            break

    # Event start date
    has_startdate    = 'zstartdate'    in event_cols
    has_recurrences  = 'zhasrecurrences' in event_cols
    has_summary      = 'zsummary'      in event_cols

    # Calendar title / type
    has_cal_title = 'ztitle' in calendar_cols
    has_cal_type  = 'ztype'  in calendar_cols

    select_parts = [
        'a.Z_PK AS alarm_pk',
        'a.ZACTION AS action',
        'a.ZRELATIVEOFFSET AS rel_offset',
        'a.ZEVENT AS event_fk',
    ]
    if script_col:
        select_parts.append('a.{} AS script_path'.format(script_col.upper()))
    else:
        select_parts.append("'' AS script_path")

    if has_summary:
        select_parts.append('e.ZSUMMARY AS event_summary')
    else:
        select_parts.append("'' AS event_summary")

    if has_startdate:
        select_parts.append('e.ZSTARTDATE AS start_date')
    else:
        select_parts.append('NULL AS start_date')

    if has_recurrences:
        select_parts.append('e.ZHASRECURRENCES AS has_recurrences')
    else:
        select_parts.append('0 AS has_recurrences')

    if has_cal_title:
        select_parts.append('c.ZTITLE AS calendar_title')
    else:
        select_parts.append("'' AS calendar_title")

    if has_cal_type:
        select_parts.append('c.ZTYPE AS calendar_type')
    else:
        select_parts.append("'' AS calendar_type")

    query = (
        'SELECT ' + ', '.join(select_parts) +
        ' FROM ZCALALARM a'
        ' LEFT OUTER JOIN ZCALEVENT e ON e.Z_PK = a.ZEVENT'
        ' LEFT OUTER JOIN ZCALENDAR c ON c.Z_PK = e.ZCALENDAR'
        ' WHERE a.ZACTION = {}'.format(ALARM_ACTION_PROCEDURE)
    )
    return query, has_startdate, script_col


def parse_calendar_cache(conn, db_path, user_name, uid,
                          main_rows, detail_rows):
    '''Parse an open Calendar Cache SQLite connection for procedure alarms.'''
    if not _table_exists(conn, 'ZCALALARM'):
        log.debug('ZCALALARM table not found in: {}'.format(db_path))
        return

    alarm_cols    = _column_names(conn, 'ZCALALARM')
    event_cols    = _column_names(conn, 'ZCALEVENT')    if _table_exists(conn, 'ZCALEVENT')   else set()
    calendar_cols = _column_names(conn, 'ZCALENDAR')   if _table_exists(conn, 'ZCALENDAR')  else set()

    query, has_startdate, script_col = _build_query(
        alarm_cols, event_cols, calendar_cols)
    log.debug('EventKit query ({}): {}'.format(db_path, query))

    try:
        conn.row_factory = sqlite3.Row
        cursor = conn.execute(query)
    except sqlite3.Error as exc:
        log.error('Query failed for {}: {}'.format(db_path, exc))
        return

    scope = get_scope(user_name)

    for row in cursor:
        script_path = (row['script_path'] or '').strip()
        if not script_path:
            # Alarm exists but has no target path - skip (not actionable)
            log.debug('Procedure alarm (pk={}) has no script path - skipped'.format(
                row['alarm_pk']))
            continue

        event_summary  = (row['event_summary'] or '').strip()
        rel_offset     = row['rel_offset']
        offset_label   = _format_offset(rel_offset)
        start_dt       = _apple_epoch_to_datetime(row['start_date'])
        has_recur      = bool(row['has_recurrences'])
        cal_title      = (row['calendar_title'] or '').strip()
        cal_type       = str(row['calendar_type'] or '').strip()

        trigger_desc = 'calendar alarm (recurring event)' if has_recur \
                       else 'calendar alarm (one-shot event)'
        label = event_summary or 'alarm pk={}'.format(row['alarm_pk'])
        if offset_label:
            trigger_desc += ' - ' + offset_label

        main_rows.append(make_main_row(
            mechanism='EventKit / Calendar Persistence',
            sub_mechanism='procedure_alarm',
            scope=scope,
            user=user_name,
            uid=uid,
            artifact_path=db_path,
            artifact_type='calendar_cache_db',
            target_path=script_path,
            trigger=trigger_desc,
            owner_app_path='',
            label_or_name=label[:200],
            artifact_mtime=None,
            target_mtime=None,
            source=db_path,
        ))

        detail_rows.append(make_detail_row(
            artifact_path=db_path,
            evidence_type='eventkit_procedure_alarm',
            key_or_line='alarm_pk={}'.format(row['alarm_pk']),
            value='script={!r} event={!r} calendar={!r} type={} recurring={} '
                  'start={} offset_secs={}'.format(
                      script_path, event_summary, cal_title, cal_type,
                      has_recur,
                      start_dt.isoformat() if start_dt else 'unknown',
                      rel_offset if rel_offset is not None else ''),
            resolved_path=script_path if script_path.startswith('/') else '',
            user=user_name,
            source=db_path,
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

    log.info('Found {} EventKit persistence item(s)'.format(len(main_rows)))
    if main_rows:
        WriteList('eventkit persistence', 'EVENTKITPERSIST', main_rows,
                  main_col_info, output_params, '')
    if detail_rows:
        WriteList('eventkit persistence detail', 'EVENTKITPERSIST_DETAIL',
                  detail_rows, detail_col_info, output_params, '')


# ---------------------------------------------------------------------------
# Plugin entry points
# ---------------------------------------------------------------------------

def Plugin_Start(mac_info):
    main_rows   = []
    detail_rows = []
    processed   = set()

    for user in mac_info.users:
        user_name = safe_user_label(user.user_name, user.home_dir)
        if not user_name:
            continue
        if user.home_dir in processed:
            continue
        processed.add(user.home_dir)

        db_path = user.home_dir + CALENDAR_CACHE_REL
        if not mac_info.IsValidFilePath(db_path):
            log.debug('Calendar Cache not found for user {}: {}'.format(
                user_name, db_path))
            continue

        mac_info.ExportFile(db_path, __Plugin_Name, user_name + '_', False)

        sqlite = SqliteWrapper(mac_info)
        conn   = sqlite.connect(db_path)
        if conn is None:
            log.error('Could not open Calendar Cache for user {}: {}'.format(
                user_name, db_path))
            continue
        try:
            parse_calendar_cache(conn, db_path, user_name, user.UID,
                                  main_rows, detail_rows)
        finally:
            conn.close()

    if main_rows or detail_rows:
        write_output(main_rows, detail_rows, mac_info.output_params)
    else:
        log.info('No EventKit persistence artifacts found')


def Plugin_Start_Standalone(input_files_list, output_params):
    log.info('Module started as standalone')
    main_rows   = []
    detail_rows = []

    for input_path in input_files_list:
        log.debug('Input path: ' + input_path)
        db = None
        try:
            db = CommonFunctions.open_sqlite_db_readonly(input_path)
            if db is None:
                log.error('Could not open: {}'.format(input_path))
                continue
            parse_calendar_cache(db, input_path, '', '',
                                  main_rows, detail_rows)
        except sqlite3.Error:
            log.exception('SQLite error opening: {}'.format(input_path))
        finally:
            if db:
                db.close()

    if main_rows or detail_rows:
        write_output(main_rows, detail_rows, output_params)
    else:
        log.info('No EventKit persistence found in provided files')


if __name__ == '__main__':
    print('This plugin is part of a framework and does not run independently.')
