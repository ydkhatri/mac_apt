'''
   Copyright (c) 2017 Yogesh Khatri 

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the 
   terms of the MIT License.
   
'''


import os
import binascii
import logging
from plugins.helpers.macinfo import *
from plugins.helpers.writer import *

__Plugin_Name = "BASHSESSIONS" # Cannot have spaces, and must be all caps!
__Plugin_Friendly_Name = "Bash Sessions & History"
__Plugin_Version = "1.0"
__Plugin_Description = "Reads bash (Terminal) sessions & history for every user"
__Plugin_Author = "Yogesh Khatri"
__Plugin_Author_Email = "yogesh@swiftforensics.com"

__Plugin_Standalone = False
__Plugin_Standalone_Usage = ""

log = logging.getLogger('MAIN.' + __Plugin_Name) # Do not rename or remove this ! This is the logger object


#---- Do not change the variable names in above section ----#

class BashSession:
    def __init__(self, user, source, source_type):
        self.start_date = None 
        self.end_date = None
        self.uuid = ''
        self.restore_string = ''
        self.new_content = ''
        self.all_content = ''
        self.user = user
        self.source = source
        self.source_type = source_type

def ReadFile(mac_info, path):
    f = mac_info.OpenSmallFile(path)
    if f != None:
        lines = f.readlines()
        lines_utf8 = []
        for line in lines:
            try:
                lines_utf8.append(line.decode('utf-8', 'backslashreplace')) # This is needed as file was opened in binary mode
            except UnicodeDecodeError:
                log.error('Failed to convert string to utf-8' + binascii.hexlify(line))
        return lines_utf8
    else:
        log.error('Could not open file {}'.format(path))
    return []

def GetDiff(first, second):
    '''Diff on two lists, returns a list'''
    len1 = len(first)
    len2 = len(second)

    if len2 == len1:
        # Lists should be the same, still check them!
        count = 0
        while (len1 > count) and (first[count] == second[count]):
            count += 1
        if count != len1:
            log.info('Problem, the data does not seem contiguous, some sessions may have been deleted')
            return second[count:]
        else:
            return [] # All OK

    elif len2 > len1: # expected behavior
        count = 0
        while (len1 > count) and (first[count] == second[count]):
            count += 1
        
        return second[count:]
            
    else: # len1 > len2   #Should not happen
        log.info('Unexpected behavior l1 > l2')
    return []

def PrintAll(sessions, output_params, source_path):
    session_info = [ ('Source_Type',DataType.TEXT),('Session_Start',DataType.DATE),('Session_End',DataType.DATE),
                     ('Session_Commands',DataType.TEXT),('All_Commands',DataType.TEXT),('User', DataType.TEXT),
                     ('Session_UUID',DataType.TEXT),('Source',DataType.TEXT)
                   ]

    data_list = []
    log.info("Found {} session(s)".format(len(sessions)))
    for session in sessions:
        data_list.append( [ session.source_type, session.start_date, session.end_date, session.new_content, 
                            session.all_content, session.user, session.uuid, session.source ] )

    WriteList("bash session & history", "BashSessions", data_list, session_info, output_params, source_path)
    
def FindSession(bash_sessions, uuid):
    for session in bash_sessions:
        if session.uuid == uuid:
            return session
    return None

def ProcessBashSessionsForUser(mac_info, bash_sessions, source_folder, user_name):
    files_list = mac_info.ListItemsInFolder(source_folder,EntryType.FILES, True)
    if len(files_list) > 0:
        files_list = sorted(files_list, key=lambda x:x['dates']['cr_time'])
        content = None
        prev_content = None
        for file_entry in files_list:
            mac_info.ExportFile(source_folder + '/' + file_entry['name'], __Plugin_Name, user_name + "_", False)
            if file_entry['name'].endswith('.history'):
                session = BashSession(user_name, source_folder + '/' + file_entry['name'], 'BASH_SESSION')
                bash_sessions.append(session)
                session.uuid = file_entry['name'].split('.')[0]
                session.end_date = file_entry['dates']['cr_time']
                content = ReadFile(mac_info, source_folder + '/' + file_entry['name'])
                if prev_content != None:
                    diff = GetDiff(prev_content, content)
                    session.new_content = ''.join(diff)
                else:
                    session.new_content = ''.join(content) # This is oldest session, no way to tell if this was all from this session or carried from before!
                session.all_content = ''.join(content)
                # Get .historynew file
                try:
                    historynew_entry = [x for x in files_list if x['name'] == session.uuid + '.historynew'][0]
                    if historynew_entry != None:
                        session.start_date = historynew_entry['dates']['cr_time']
                        if historynew_entry['size'] > 0:
                            if session.new_content == '':
                                session.new_content = ''.join(ReadFile(mac_info, source_folder + '/' + historynew_entry['name']))
                            else:
                                log.info('{} has data in it ! There is history content too!'.format(historynew_entry['name']))
                                session.new_content += '\n' + ''.join(ReadFile(mac_info, source_folder + '/' + historynew_entry['name']))
                            if session.all_content == '': # Nothing was present in history file!
                                session.source = source_folder + '/' + historynew_entry['name']
                            else: # There was data in history too ! # Not seen this.
                                session.source += ', ' + source_folder + '/' + historynew_entry['name']
                        
                except (IndexError, KeyError, ValueError):
                    log.exception('Error getting historynew')
                # setting variables for next loop iteration
                prev_content = content
                content = []
        # Proces any .historynew file that was missed (if it didnt have a corresp .history file)
        for file_entry in files_list:
            file_name = file_entry['name']
            if file_name.endswith('.historynew') and file_entry['size'] > 0:
                uuid = file_name.split('.')[0]
                existing_session = FindSession(bash_sessions, uuid)
                if not existing_session:
                    log.info('Found a .historynew file with no corresponding .history files! - {}'.format(file_name))
                    session = BashSession(user_name, source_folder + '/' + file_name, 'BASH_SESSION')
                    bash_sessions.append(session)
                    session.uuid = uuid
                    session.start_date = file_entry['dates']['cr_time']
                    session.end_date = file_entry['dates']['m_time']
                    session.new_content = ''.join(ReadFile(mac_info, source_folder + '/' + file_name))
    else:
        log.info('No files found under {}, bash sessions may have been manually deleted!'.format(source_folder))

def Plugin_Start(mac_info):
    '''Main Entry point function for plugin'''
    history_path = '{}/.bash_sessions'
    processed_paths = []
    bash_sessions = []
    for user in mac_info.users:
        user_name = user.user_name
        if user.home_dir == '/private/var/empty': continue # Optimization, nothing should be here!
        elif user.home_dir == '/private/var/root': user_name = 'root' # Some other users use the same root folder, we will list such all users as 'root', as there is no way to tell
        if user.home_dir in processed_paths: continue # Avoid processing same folder twice (some users have same folder! (Eg: root & daemon))
        processed_paths.append(user.home_dir)
        source_folder = history_path.format(user.home_dir)
        if mac_info.IsValidFolderPath(source_folder):
            ProcessBashSessionsForUser(mac_info, bash_sessions, source_folder, user_name)
        
        #Export .bash_history file
        bash_history_path = user.home_dir + ('/.sh_history' if user_name == 'root' else '/.bash_history')
        if mac_info.IsValidFilePath(bash_history_path):
            mac_info.ExportFile(bash_history_path , __Plugin_Name, user_name + "_", False)
            content = ReadFile(mac_info, bash_history_path)
            session = BashSession(user_name, bash_history_path, 'BASH_HISTORY')
            bash_sessions.append(session)
            session.all_content = ''.join(content)
    if len(bash_sessions) > 0:
        PrintAll(bash_sessions, mac_info.output_params, '')
    else:
        log.info('No bash sessions or history found!')
    
if __name__ == '__main__':
    print("This plugin is a part of a framework and does not run independently on its own!")
