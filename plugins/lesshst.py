'''
   Copyright (c) 2026 Abdelrahman Mohamed

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the
   terms of the MIT License.

   lesshst.py
   ---------------
   This plugin reads the history file of the 'less' pager (.lesshst),
   which holds search patterns, shell commands and marks for every user.
'''

import logging
from plugins.helpers.macinfo import *
from plugins.helpers.writer import *


__Plugin_Name = "LESSHST" # Cannot have spaces, and must be all caps!
__Plugin_Friendly_Name = "Less History"
__Plugin_Version = "1.0"
__Plugin_Description = "Reads less pager history (search patterns, shell commands & marks) for every user"
__Plugin_Author = "Abdelrahman Mohamed"
__Plugin_Author_Email = "abusharawey2020@gmail.com"

__Plugin_Modes = "MACOS,ARTIFACTONLY" # Valid values are 'MACOS', 'IOS, 'ARTIFACTONLY'
__Plugin_ArtifactOnly_Usage = 'Provide the less history file /Users/<USER>/.lesshst (or /Users/<USER>/.local/state/lesshst) as input'

log = logging.getLogger('MAIN.' + __Plugin_Name) # Do not rename or remove this ! This is the logger object

#---- Do not change the variable names in above section ----#

# less writes this as the first line of its history file, and ignores the file without it
LESSHST_FIRST_LINE = '.less-history-file:'
# Section headers, and the type each one is reported as
LESSHST_SECTIONS = { '.search': 'SEARCH', '.shell': 'SHELL', '.mark': 'MARK' }

class LessHistoryItem():
    def __init__(self, item_type, order, value, mark, line_num, file_pos, user, source):
        self.item_type = item_type
        self.order = order
        self.value = value
        self.mark = mark
        self.line_num = line_num
        self.file_pos = file_pos
        self.user = user
        self.source = source

def PrintAll(less_items, output_params):

    less_info = [ ('Type',DataType.TEXT),('Order',DataType.INTEGER),('Value',DataType.TEXT),
                  ('Mark',DataType.TEXT),('Line',DataType.INTEGER),('File_Position',DataType.INTEGER),
                  ('User', DataType.TEXT),('Source',DataType.TEXT)
                ]

    log.info (str(len(less_items)) + " less history item(s) found")
    less_list = []
    for item in less_items:
        less_list.append( [ item.item_type, item.order, item.value,
                            item.mark, item.line_num, item.file_pos,
                            item.user, item.source
                          ] )
    WriteList("less history", "LessHistory", less_list, less_info, output_params, '')

def ParseLessHistory(less_items, data, user, source):
    '''Parses the content (bytes) of a .lesshst file. Entries are in the order
       less stores them, oldest first, so Order 1 is the oldest in each section.
    '''
    lines = data.decode('utf-8', 'backslashreplace').splitlines()
    if not lines or not lines[0].startswith(LESSHST_FIRST_LINE):
        log.warning('{} does not start with "{}", not a less history file?'.format(source, LESSHST_FIRST_LINE))
        return
    item_type = None
    order = 0
    for line in lines[1:]:
        if line in LESSHST_SECTIONS:
            item_type = LESSHST_SECTIONS[line]
            order = 0
        elif line.startswith('"'):
            if item_type in ('SEARCH', 'SHELL'):
                order += 1
                less_items.append(LessHistoryItem(item_type, order, line[1:], '', None, None, user, source))
        elif line.startswith('m'):
            # Format is "m <mark letter> <screen line> <file position> <file name>"
            parts = line.split(None, 4)
            if len(parts) == 5:
                order += 1
                try:
                    line_num = int(parts[2])
                    file_pos = int(parts[3])
                except ValueError:
                    log.warning('Could not read numbers in mark entry "{}" in {}'.format(line, source))
                    line_num = None
                    file_pos = None
                less_items.append(LessHistoryItem('MARK', order, parts[4], parts[1], line_num, file_pos, user, source))
            else:
                log.warning('Unexpected mark entry "{}" in {}'.format(line, source))
        elif line.startswith('.'):
            log.debug('Skipping unknown section "{}" in {}'.format(line, source))
            item_type = None
        elif line:
            log.debug('Skipping unknown line "{}" in {}'.format(line, source))

def ReadLessHistoryFromImage(mac_info, less_items, user, file_path):
    mac_info.ExportFile(file_path, __Plugin_Name, user + '_', False)
    f = mac_info.Open(file_path)
    if f != None:
        try:
            ParseLessHistory(less_items, f.read(), user, file_path)
        except (OSError, ValueError):
            log.exception('Error reading {}'.format(file_path))
    else:
        log.error('Could not open file {}'.format(file_path))

def Plugin_Start(mac_info):
    '''Main Entry point function for plugin'''
    processed_paths = []
    less_items = []
    # Older less versions (as shipped with macOS) use ~/.lesshst, newer ones use
    # ~/.local/state/lesshst if the ~/.local/state folder exists
    less_history_paths = ('{}/.lesshst', '{}/.local/state/lesshst')

    for user in mac_info.users:
        user_name = user.user_name
        if user.home_dir == '/private/var/empty': continue # Optimization, nothing should be here!
        elif user.home_dir == '/private/var/root': user_name = 'root' # Some other users use the same root folder, we will list all such users as 'root', as there is no way to tell
        if user.home_dir in processed_paths: continue # Avoid processing same folder twice (some users have same folder! (Eg: root & daemon))
        processed_paths.append(user.home_dir)
        for less_history_path in less_history_paths:
            source_path = less_history_path.format(user.home_dir)
            if mac_info.IsValidFilePath(source_path):
                ReadLessHistoryFromImage(mac_info, less_items, user_name, source_path)

    if len(less_items) > 0:
        PrintAll(less_items, mac_info.output_params)
    else:
        log.info('No less history found')

def Plugin_Start_Standalone(input_files_list, output_params):
    '''Main entry point function when used on single artifacts (mac_apt_singleplugin), not on a full disk image'''
    log.info("Module Started as standalone")
    less_items = []
    for input_path in input_files_list:
        log.debug("Input file passed was: " + input_path)
        try:
            with open(input_path, 'rb') as f:
                ParseLessHistory(less_items, f.read(), '', input_path)
        except OSError:
            log.exception('Could not open file {}'.format(input_path))
    if len(less_items) > 0:
        PrintAll(less_items, output_params)
    else:
        log.info('No less history found')

def Plugin_Start_Ios(ios_info):
    '''Entry point for ios_apt plugin'''
    pass

if __name__ == '__main__':
    print ("This plugin is a part of a framework and does not run independently on its own!")
