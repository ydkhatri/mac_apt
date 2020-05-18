'''
   Copyright (c) 2020 Yogesh Khatri

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the
   terms of the MIT License.

   cookies.py
   ---------------
   Reads Cookie information from .binarycookies, .cookies files and HSTS.plist for each user.

'''

import logging
import plugins.helpers.common
import struct
from biplist import *
from plugins.helpers.macinfo import *
from plugins.helpers.writer import *

__Plugin_Name = "COOKIES"
__Plugin_Friendly_Name = "Cookies"
__Plugin_Version = "1.0"
__Plugin_Description = "Reads .binarycookies, .cookies files and HSTS.plist for each user"
__Plugin_Author = "Yogesh Khatri"
__Plugin_Author_Email = "yogesh@swiftforensics.com"

__Plugin_Modes = "MACOS,ARTIFACTONLY"
__Plugin_ArtifactOnly_Usage = 'Provide the HSTS.plist file located at /Users/<USER>/Library/Cookielication Support/com.apple.spotlight/appList.dat'

log = logging.getLogger('MAIN.' + __Plugin_Name) # Do not rename or remove this ! This is the logger object

#---- Do not change the variable names in above section ----#

class Cookie:
    def __init__(self, host, create_time, expiry_time, name, path, value, user, source_path):
        self.host = host
        self.create_time = create_time
        self.expiry_time = expiry_time
        self.name = name
        self.path = path
        self.value = value
        self.user = user
        self.source_path = source_path

def PrintAll(cookies, output_params, input_path=''):
    cookies_info = [   ('Host',DataType.TEXT),
                    ('Create Time',DataType.DATE),
                    ('Expiry Time',DataType.DATE),
                    ('Name',DataType.TEXT),
                    ('Path',DataType.TEXT),
                    ('Value',DataType.TEXT),
                    ('User',DataType.TEXT),
                    ('Source',DataType.TEXT)
                ]

    log.info (str(len(cookies)) + " cookie(s) found")

    cookies_list_final = []
    for item in cookies:
        single_cookie_item = [item.host, item.create_time, item.expiry_time, 
                            item.name, item.path, item.value,
                            item.user, item.source_path ]
        cookies_list_final.append(single_cookie_item)

    WriteList("Cookies List", "Cookies", cookies_list_final, cookies_info, output_params, input_path)

def read_cstring(buffer):
    pos = buffer.find(b'\0')
    ret = ''
    if pos == -1:
        ret = buffer
    else:
        ret = buffer[0:pos]
    try:
        ret = ret.decode('utf8', 'backslashreplace')
    except UnicodeDecodeError:
        ret = ''
    return ret

# BinaryCookie parsing based on Satishb's code from 
# https://github.com/as0ler/BinaryCookieReader/blob/master/BinaryCookieReader.py

def parse_cookie_file(cookie_file, cookies, user_name, file_path):
    '''Parse .binarycookies or .cookies file'''
    data = cookie_file.read()
    if data[0:4] == b'cook':
        num_pages = struct.unpack('>I', data[4:8])[0]
        if num_pages == 0:
            return
        page_sizes = []
        pos = 8
        for x in range(num_pages):
            page_sizes.append(struct.unpack('>I', data[pos : pos + 4])[0])
            pos +=4
        
        page_start = pos
        for page_size in page_sizes:
            # read page
            pos = page_start
            pos += 4
            num_cookies = struct.unpack('<I', data[pos : pos + 4])[0]
            pos += 4
            offsets = []
            for y in range(num_cookies):
                offsets.append(struct.unpack('<I', data[pos : pos + 4])[0])
                pos += 4
            for offset in offsets:
                cookie_data = data[page_start + offset : page_start + page_size]
                length, unk1, flags, unk2, url_offset, \
                name_offset, path_offset, value_offset, \
                unk3, expiry_time, create_time = struct.unpack('<IIIIIIIIQdd', cookie_data[0:56])
                url = read_cstring(cookie_data[url_offset:])
                name = read_cstring(cookie_data[name_offset:])
                path = read_cstring(cookie_data[path_offset:])
                value = read_cstring(cookie_data[value_offset:])
                
                if url and url[0] == '.':
                    url = url[1:]
                expiry_time = CommonFunctions.ReadMacAbsoluteTime(expiry_time)
                create_time = CommonFunctions.ReadMacAbsoluteTime(create_time)
                cookies.append(Cookie(url, create_time, expiry_time, name, path, value, user_name, file_path))
            page_start = page_start + page_size
    else:
        log.error('Not the expected header for cookie file. Got {} instead of "cook"'.format(str(dat[0:4])))

def parse_hsts_plist(plist, cookies, user_name, plist_path):
    '''Parse plist and add items to cookies list'''
    hsts_store = plist.get('com.apple.CFNetwork.defaultStorageSession', None)

    for site, items in hsts_store.items():
        c_time = CommonFunctions.ReadMacAbsoluteTime(items.get('Create Time', None))
        e_time = items.get('Expiry', None)
        if e_time == float('inf'):
            e_time = None
        else:
            e_time = CommonFunctions.ReadMacAbsoluteTime(e_time)

        cookies.append(Cookie(site, c_time, e_time, '', '','', user_name, plist_path))

def read_plist_from_image(mac_info, plist_path):
    success, plist, error = mac_info.ReadPlist(plist_path)
    if success:
        return plist
    else:
        log.error(error)
    return None

def Plugin_Start(mac_info):
    '''Main Entry point function for plugin'''
    cookies_folder_path = '{}/Library/Cookies'

    cookies = []
    processed_paths = []
    for user in mac_info.users:
        user_name = user.user_name
        if user.home_dir == '/private/var/empty': continue # Optimization, nothing should be here!
        elif user.home_dir == '/private/var/root': user_name = 'root' # Some other users use the same root folder, we will list such all users as 'root', as there is no way to tell
        if user.home_dir in processed_paths: continue # Avoid processing same folder twice (some users have same folder! (Eg: root & daemon))
        processed_paths.append(user.home_dir)
        source_path = cookies_folder_path.format(user.home_dir)
        if not mac_info.IsValidFolderPath(source_path):
            continue
        files_list = mac_info.ListItemsInFolder(source_path, EntryType.FILES, False)
        if len(files_list):
            for file in files_list:
                file_name = file['name']
                full_path = source_path + '/' + file_name
                extension = os.path.splitext(file_name)[1].lower()
                if file_name == 'HSTS.plist':
                    mac_info.ExportFile(full_path, __Plugin_Name, user_name + "_", False)
                    plist = read_plist_from_image(mac_info, full_path)
                    if plist:
                        parse_hsts_plist(plist, cookies, user_name, full_path)
                elif extension in ('.cookies', '.binarycookies'):
                    mac_info.ExportFile(full_path, __Plugin_Name, user_name + "_", False)
                    f = mac_info.OpenSmallFile(full_path)
                    if f != None:
                        parse_cookie_file(f, cookies, user_name, full_path)
                    else:
                        log.error('Could not open file {}'.format(full_path))
                else:
                    log.debug(f'Found unknown file - {full_path}')
        #else:
        #    log.debug(f'No cookie files or hsts.plist for user {user_name}')

    if len(cookies) > 0:
        PrintAll(cookies, mac_info.output_params, '')
    else:
        log.info('No cookies found')

def read_hsts_plist_file(input_file, cookies):
    try:
        plist = readPlist(input_file)
        parse_hsts_plist(plist, cookies, '', input_file)
    except (InvalidPlistException, OSError):
        log.exception("Could not open/process plist")

def Plugin_Start_Standalone(input_files_list, output_params):
    log.info("Module Started as standalone")
    for input_path in input_files_list:
        log.debug("Input file passed was: " + input_path)
        cookies = []
        extension = os.path.splitext(input_path)[1].lower()
        if input_path.lower().endswith('hsts.plist'):
            read_hsts_plist_file(input_path, cookies)
        elif extension in ('.cookies', '.binarycookies'):
            try:
                with open(input_path, 'rb') as f:
                    parse_cookie_file(f, cookies, '', input_path)
            except OSError:
                log.exception(f"Could not open file {input_path}")
        if len(cookies) > 0:
            PrintAll(cookies, output_params, input_path)
        else:
            log.info('No cookies found in {}'.format(input_path))

if __name__ == '__main__':
    print ("This plugin is a part of a framework and does not run independently on its own!")