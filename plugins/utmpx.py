'''
   Copyright (c) 2021 Minoru Kobayashi

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the
   terms of the MIT License.

   utmpx.py
   ---------------
   This plugin parses /private/var/run/utmpx and extracts username, terminal name, timestamp, and so on.
   utmpx has been DEPRECATED on macOS, but we can still take advantage of it.
   Ref 1 : https://github.com/log2timeline/plaso/blob/main/plaso/parsers/utmpx.py
   Ref 2 : https://github.com/jjarava/mac-osx-forensics/blob/master/utmpx.py
'''

import os
import sys
import time
from construct import *

from plugins.helpers.macinfo import *
from plugins.helpers.writer import *

import logging

__Plugin_Name = "UTMPX" # Cannot have spaces, and must be all caps!
__Plugin_Friendly_Name = "utmpx"
__Plugin_Version = "1.0"
__Plugin_Description = "Read utmpx entries"
__Plugin_Author = "Minoru Kobayashi"
__Plugin_Author_Email = "unknownbit@gmail.com"

__Plugin_Modes = "MACOS,ARTIFACTONLY" # Valid values are 'MACOS', 'IOS, 'ARTIFACTONLY' 
__Plugin_ArtifactOnly_Usage = 'Provide the file path to utmpx'

log = logging.getLogger('MAIN.' + __Plugin_Name) # Do not rename or remove this ! This is the logger object

#---- Do not change the variable names in above section ----#

UTMPX_MAGIC = 'utmpx-1.00'

UtmpxEntry = Struct(
    "user" / PaddedString(256, "utf8"),
    "terminal_id" / Int32ul,
    "terminal" / PaddedString(32, "ascii"),
    "pid" / Int32ul,
    "type" / Int32ul,
    "timestamp" / Int32ul,
    "timestamp_microseconds" / Int32ul,
    "hostname" / PaddedString(256, "utf8"),
    Padding(64)
)


UtmpxType = {
    0 : 'EMPTY',
    1 : 'RUN_LVL',
    2 : 'BOOT_TIME',
    3 : 'OLD_TIME',
    4 : 'NEW_TIME',
    5 : 'INIT_PROCESS',
    6 : 'LOGIN_PROCESS',
    7 : 'USER_PROCESS',
    8 : 'DEAD_PROCESS'
}


class UtmpxItem:
    def __init__(self, user, terminal_id, terminal, pid, type, timestamp, timestamp_microseconds, hostname):
        self.user = user
        self.terminal_id = terminal_id
        self.terminal = terminal
        self.pid = pid
        self.type = type
        self.timestamp = timestamp
        self.timestamp_microseconds = timestamp_microseconds
        self.hostname = hostname


def ReadUtmpxEntry(utmpx_file):
    data = utmpx_file.read(UtmpxEntry.sizeof())
    if len(data) != UtmpxEntry.sizeof():
        return False
    try:
        entry = UtmpxEntry.parse(data)
    except Exception:
        log.error('Unable to parse utmpx entry.')
        return False

    user = entry.user
    if not user:
        user = 'N/A'

    terminal = entry.terminal
    if not terminal:
        terminal = 'N/A'

    hostname = entry.hostname
    if not hostname:
        hostname = 'localhost'

    return UtmpxItem(user, entry.terminal_id, terminal, entry.pid, entry.type, entry.timestamp, entry.timestamp_microseconds, hostname)


def ProcessUtmpx(mac_info, utmpx_artifacts, file_path):
    if mac_info.IsValidFilePath(file_path):
        mac_info.ExportFile(file_path, __Plugin_Name)
        utmpx_file = mac_info.Open(file_path)
        if utmpx_file:
            try:
                header = UtmpxEntry.parse_stream(utmpx_file)
            except Exception:
                log.error('Unable to parse utmpx header.')
                return False
            if header.user != UTMPX_MAGIC:
                log.error('utmpx header not found.')
                return False

        item = True
        while item:
            item = ReadUtmpxEntry(utmpx_file)
            if item:
                utmpx_artifacts.append(item)

        return True


def ProcessUtmpxStandalone(utmpx_artifacts, file_path):
    if os.path.isfile(file_path):
        with open(file_path, "rb") as utmpx_file:
            if utmpx_file:
                try:
                    header = UtmpxEntry.parse_stream(utmpx_file)
                except Exception:
                    log.error('Unable to parse utmpx header.')
                    return False
                if header.user != UTMPX_MAGIC:
                    log.error('utmpx header not found.')
                    return False

            item = True
            while item:
                item = ReadUtmpxEntry(utmpx_file)
                if item:
                    utmpx_artifacts.append(item)

            return True


def PrintAll(utmpx_artifacts, output_params, source_path):
    utmpx_info = [('User', DataType.TEXT), ('Terminal_ID', DataType.INTEGER), ('Terminal', DataType.TEXT), ('PID', DataType.INTEGER),
                  ('Type', DataType.INTEGER), ('Type_Name', DataType.TEXT), ('Timestamp', DataType.DATE), ('Hostname', DataType.TEXT)]

    data_list = []
    log.info(f"{len(utmpx_artifacts)} utmpx artifact(s) found")
    for item in utmpx_artifacts:
        type_name = UtmpxType.get(item.type, 'N/A')
        timestamp = "{}.{:0>6}".format(time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(item.timestamp)), item.timestamp_microseconds)
        data_list.append([item.user, item.terminal_id, item.terminal, item.pid, item.type, type_name, timestamp, item.hostname])

    WriteList("utmpx entry", "utmpx", data_list, utmpx_info, output_params, source_path)


def Plugin_Start(mac_info):
    '''Main Entry point function for plugin'''
    utmpx_artifacts = []
    utmpx_path = '/private/var/run/utmpx'

    if ProcessUtmpx(mac_info, utmpx_artifacts, utmpx_path):
        if len(utmpx_artifacts) > 0:
            PrintAll(utmpx_artifacts, mac_info.output_params, '')
        else:
            log.info('No utmpx artifacts were found!')

def Plugin_Start_Standalone(input_files_list, output_params):
    '''Main entry point function when used on single artifacts (mac_apt_singleplugin), not on a full disk image'''
    log.info("Module Started as standalone")
    for input_path in input_files_list:
        log.debug("Input file passed was: " + input_path)
        utmpx_artifacts = []
        if ProcessUtmpxStandalone(utmpx_artifacts, input_path):
            if len(utmpx_artifacts) > 0:
                PrintAll(utmpx_artifacts, output_params, input_path)
            else:
                log.info('No utmpx artifacts were found!')

def Plugin_Start_Ios(ios_info):
    '''Entry point for ios_apt plugin'''
    pass

if __name__ == '__main__':
    print ("This plugin is a part of a framework and does not run independently on its own!")
