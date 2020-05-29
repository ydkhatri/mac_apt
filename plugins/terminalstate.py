'''
   Copyright (c) 2017 Yogesh Khatri

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the
   terms of the MIT License.

   terminalstate.py
   ---------------
   This plugin reads Terminal Saved State information which includes
   full text content of terminal window.
'''

import biplist
import io
import logging
import os
import struct
from Crypto.Cipher import AES
from plugins.helpers.deserializer import process_nsa_plist
from plugins.helpers.macinfo import *
from plugins.helpers.writer import *


__Plugin_Name = "TERMINALSTATE" # Cannot have spaces, and must be all caps!
__Plugin_Friendly_Name = "Terminal Saved State"
__Plugin_Version = "1.0"
__Plugin_Description = "Reads Terminal saved state files which includes full text content of terminal windows"
__Plugin_Author = "Yogesh Khatri"
__Plugin_Author_Email = "yogesh@swiftforensics.com"

__Plugin_Modes = "MACOS,ARTIFACTONLY" # Valid values are 'MACOS', 'IOS, 'ARTIFACTONLY' 
__Plugin_ArtifactOnly_Usage = 'Provide the folder /Users/<USER>/Library/Saved Application State/com.apple.Terminal.savedState as input'

log = logging.getLogger('MAIN.' + __Plugin_Name) # Do not rename or remove this ! This is the logger object

#---- Do not change the variable names in above section ----#

class TerminalWindowInfo():
    def __init__(self, title, working_dir, content, user, source):
        self.content = content
        self.title = title
        self.working_dir = working_dir
        self.user = user
        self.source = source
        # self.file_created_time = ''
        # self.file_modified_time = ''

def PrintAll(terminals, output_params):

    terminal_info = [ ('Title',DataType.TEXT),('WorkingDir',DataType.TEXT),('Content',DataType.TEXT),
                        ('User', DataType.TEXT),('Source',DataType.TEXT)
                      ]

    log.info (str(len(terminals)) + " terminal saved state(s) found")
    terminals_list = []
    for t in terminals:
        t_item =  [ t.title, t.working_dir, t.content, 
                    t.user, t.source
                  ]
        terminals_list.append(t_item)
    WriteList("terminal saved state", "TerminalState", terminals_list, terminal_info, output_params, '')

def get_decoded_plist_data(data):
    data_size = len(data)
    name = ''
    if data_size > 8:
        name_len = struct.unpack('>I', data[4:8])[0]
        name = data[8 : 8 + name_len]
        log.debug('NSName = {}'.format(name))
        rchv = data[8 + name_len : 12 + name_len] # "rchv"
        if rchv != b"rchv":
            log.warning('magic was not "rchv", it was {}'.format(str(rchv)))
        nsa_plist_len = struct.unpack('>I', data[12 + name_len : 16 + name_len])[0]
        nsa_plist = data[16 + name_len : 16 + name_len + nsa_plist_len]

        f = io.BytesIO(nsa_plist)
        try:
            deserialized_plist = process_nsa_plist("", f)
        except Exception as ex:
            log.exception("")
            f.close()
            return (name, None)
        f.close()
        return (name, deserialized_plist)
    else:
        log.warning('Plist seems empty!')
    return (name, None)

def read_plist(plist_file_path):
    try:
        plist = biplist.readPlist(plist_file_path)
        return plist
    except (NotBinaryPlistException, InvalidPlistException):
        log.exception("Error reading plist")
    return None

def get_key_for_window_id(plist, ns_window_id):
    key = None
    for item in plist:
        w_id = item.get('NSWindowID', None)
        if w_id == ns_window_id:
            key = item.get('NSDataKey', None)
            if key == None:
                log.error("Error fetching key, key was not found for windowID={}!".format(ns_window_id))
            break
    return key

def decrypt(enc_data, key, iv):
    '''Decrypts the data given encrypted data, key and IV'''
    try:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        dec_data = cipher.decrypt(enc_data)
        return dec_data
    except (KeyError, ValueError) as ex:
        log.exception('Decryption error:')
    return b''

def ParseTerminalPlist_NSWindow(plist):
    '''Returns terminal (Title, Working Dir, Contents) as a tuple'''
    title = ''
    working_dir = ''
    contents = ''
    if isinstance(plist, dict): 
        return # not a list
    try:
        for item in plist:
            for k, v in item.items():
                if k == 'NSTitle':
                    title = v
                elif k == 'TTWindowState':
                    window_settings = v.get('Window Settings', None)
                    if not window_settings: continue
                    for w in window_settings:
                        for key, value in w.items():
                            if key in ('Tab Contents', 'Tab Contents v2'):
                                for content in value:
                                    if isinstance(content, bytes):
                                        contents += content.decode('utf8', 'backslashreplace')
                            elif key in ('Tab Working Directory URL String', 'Tab Working Directory URL'):
                                working_dir = value
    except ValueError as ex:
        log.error("Error reading terminal plist, error was: {}".format(str(ex)))
    return (title, working_dir, contents)

def ProcessFile(windows_plist_file_path, data_file_path, terminals):
    windows_plist = read_plist(windows_plist_file_path)
    if windows_plist:
        with open(data_file_path, 'rb') as f:
            all_data = f.read() # Should be a small file
            Process(windows_plist, all_data, terminals, '', data_file_path)

def AddUnique(terminal_info, terminals):
    duplicate_found = False
    for t in terminals:
        if (t.source == terminal_info.source) and \
           (t.user == terminal_info.user) and \
           (t.working_dir == terminal_info.working_dir) and \
           (t.content == terminal_info.content) and \
           (t.title == terminal_info.title):
            duplicate_found = True
            break
    if not duplicate_found:
        terminals.append(terminal_info)

def Process(windows_plist, all_data, terminals, user, data_source):
    iv = struct.pack("<IIII", 0, 0, 0, 0)

    if windows_plist:
        pos = 0
        # Parsing data.data
        size_data = len(all_data)
        while (pos + 16) < size_data:
            magic = all_data[pos:pos+8]
            ns_window_id, rec_length = struct.unpack(">II", all_data[pos+8:pos+16])
            pos += 16
            rec_length -= 16
            if (pos + rec_length) <= size_data:
                enc_data = all_data[pos:pos + rec_length]
                if magic != b"NSCR1000":
                    log.error("Unknown header:" + str(magic))

                key = get_key_for_window_id(windows_plist, ns_window_id)

                if key:
                    dec_data = decrypt(enc_data, key, iv)
                    data_name, new_data = get_decoded_plist_data(dec_data)
                    if new_data and data_name == b'_NSWindow':
                        title, working_dir, contents = ParseTerminalPlist_NSWindow(new_data)
                        if not(len(contents) == 0 and len(working_dir) == 0 and len(title) == 0):
                            t = TerminalWindowInfo(title, working_dir, contents, user, data_source)
                            #terminals.append(t)
                            AddUnique(t, terminals)
                else:
                    print('key not found for window_id={}'.format(ns_window_id))
            pos += rec_length

def Plugin_Start(mac_info):
    '''Main Entry point function for plugin'''
    processed_paths = []
    terminals = []
    saved_state_path = '{}/Library/Saved Application State/com.apple.Terminal.savedState'

    for user in mac_info.users:
        if user.home_dir == '/private/var/empty': continue # Optimization, nothing should be here!
        elif user.home_dir == '/private/var/root': user_name = 'root' # Some other users use the same root folder, we will list all such users as 'root', as there is no way to tell
        if user.home_dir in processed_paths: continue # Avoid processing same folder twice (some users have same folder! (Eg: root & daemon))
        processed_paths.append(user.home_dir)
        source_path = saved_state_path.format(user.home_dir)
        windows_plist_path = source_path + '/windows.plist'
        data_path = source_path + '/data.data'
        if mac_info.IsValidFolderPath(source_path) and mac_info.IsValidFilePath(windows_plist_path) and mac_info.IsValidFilePath(data_path):
            
            mac_info.ExportFile(windows_plist_path, __Plugin_Name, user.user_name + "_", False)
            mac_info.ExportFile(data_path, __Plugin_Name, user.user_name + "_", False)
            success, windows_plist, error = mac_info.ReadPlist(windows_plist_path)
            if success:
                try:
                    all_data_file = mac_info.Open(data_path)
                    if (all_data_file):
                        all_data = all_data_file.read()
                        Process(windows_plist, all_data, terminals, user.user_name, data_path)
                    else:
                        log.error('Failed to open data.data file - {}'.format(data_path))
                except (ValueError, OSError):
                    log.exception('')
            else:
                log.error('Failed to open windows.plist: {}'.format(windows_plist_path))

    if len(terminals) > 0:
        PrintAll(terminals, mac_info.output_params)
    else:
        log.info('No Terminal saved state found')


def Plugin_Start_Standalone(input_files_list, output_params):
    '''Main entry point function when used on single artifacts (mac_apt_singleplugin), not on a full disk image'''
    log.info("Module Started as standalone")
    terminals = []
    for input_path in input_files_list:
        log.debug("Input folder passed was: " + input_path)

        if os.path.isdir(input_path):
            windows_plist_path = os.path.join(input_path, 'windows.plist')
            data_path = os.path.join(input_path, 'data.data')
            ProcessFile(windows_plist_path, data_path, terminals)
        else:
            log.error('Input path "{}" is not a folder. Provide the input path to folder com.apple.Terminal.savedState'.format(input_path))

    if len(terminals) > 0:
        PrintAll(terminals, output_params)
    else:
        log.info('No Terminal saved state found')    

def Plugin_Start_Ios(ios_info):
    '''Entry point for ios_apt plugin'''
    pass

if __name__ == '__main__':
    print ("This plugin is a part of a framework and does not run independently on its own!")