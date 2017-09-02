'''
   Copyright (c) 2017 Yogesh Khatri 

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the 
   terms of the MIT License.
   
'''
from __future__ import print_function
from __future__ import unicode_literals
import os
import biplist
import sys
import logging
import struct
import helpers.ccl_bplist as ccl_bplist

from biplist import *
from enum import IntEnum
from binascii import unhexlify
from helpers.macinfo import *
from helpers.writer import *


__Plugin_Name = "RECENTITEMS"
__Plugin_Friendly_Name = "Recently accessed Servers, Documents, Hosts, Volumes & Applications"
__Plugin_Version = "1.2"
__Plugin_Description = "Gets recently accessed Servers, Documents, Hosts & Applications from .plist and .sfl files. Also gets recent searches and places for each user"
__Plugin_Author = "Yogesh Khatri"
__Plugin_Author_Email = "yogesh@swiftforensics.com"

__Plugin_Standalone = True
__Plugin_Standalone_Usage = 'This module parses recently accessed information from plist and SFL files found under /Users/<USER>/Library/Preferences/'

log = logging.getLogger('MAIN.' + __Plugin_Name) # Do not rename or remove this ! This is the logger object

#---- Do not change the variable names in above section ----#

#  Processes com.apple.recentitems.plist
#  Processes *.LSSharedFileList plist files too!
#      All seem to be located under \Users\USER\Library\Preferences\
#          On elcapitan, also under \Users\USER\Library\Application Support\com.*\com.*.LSSharedFileList.*\*.sfl
#          .SFL files are keyed archives.
#      All have Bookmark blobs to parse.
#  Processes NSNavRecentPlaces and SGTRecentFileSearches from <USER>/Library/Preferences/.GlobalPreferences.plist
#  Processes FXDesktopVolumePositions & FXRecentFolders from <USER>/Library/Preferences/com.apple.finder.plist

class RecentType(IntEnum):
    UNKNOWN = 0
    HOST = 1
    APPLICATION = 2
    DOCUMENT = 3
    SERVER = 4
    PLACE = 5  # For NSNavRecentPlaces
    SEARCH = 6 # For SGTRecentFileSearches
    VOLUME = 7 # For FXDesktopVolumePositions

    def __str__(self):
        return self.name # This returns 'UNKNOWN' instead of 'RecentType.UNKNOWN'

class RecentItem: 

    class BookmarkItem:
        def __init__(self):
            self.Pos = 0
            self.Size = 0 # Data size
            self.Data = None
            self.Type = 0
            
        def ReadData(self, bookmark):
            try:
                if self.Type == 0x0101: # UFT8 string
                    self.Data = bookmark[self.Pos + 8:self.Pos + 8 + self.Size].decode('utf-8')
                elif self.Type == 0x0901: # UFT8 string for URL
                    self.Data = bookmark[self.Pos + 8:self.Pos + 8 + self.Size].decode('utf-8')
                elif self.Type == 0x0601:
                    num = self.Size / 4
                    self.Data = struct.unpack("<{}L".format(num), bookmark[self.Pos + 8:self.Pos + 8 + self.Size]) # array is returned
                elif self.Type == 0x0303: # uint
                    self.Data = struct.unpack("<L", bookmark[self.Pos + 8:self.Pos + 8 + self.Size])[0]
            except Exception as ex:
                log.error('Problem reading Bookmark data, exception was: {}'.format(str(ex)))

    def __init__(self, name, url, source, recent_type, user):
        self.Name = name
        self.URL = url
        self.Source = source
        self.Type = recent_type
        self.User = user
    
    def ReadAlias(self, alias):
        try:
            # alias is a binary blob, only the last string in it is relevant
            size = len(alias)
            if size < 0x3B: return 
            if size > 0x200: return # likely non-standard, below method won't work!
            pos = size - 6 # alias ends with ...relevant_data.. 00 FF FF 00 00
            if alias[pos] == b'\x00': pos -= 1
            reached_start = False
            data = b'\x00'
            while (pos > 0x3B and not reached_start):
                if alias[pos] == b'\x00':
                    reached_start = True
                else:
                    data = alias[pos] + data
                pos -= 1
            if reached_start:
                self.URL = data.decode("utf-8") 
                #TODO: Since this isn't a perfect method, sometimes this needs filtering
                #self.URL.translate(None, '\x09\x00')
            else:
                log.error('Something went wrong! Could not read alias data!')
        except Exception as ex:
            log.exception('Exception while processing data in Alias field')

    def ReadBookmark(self, bookmark):
        try:
            if bookmark[0:4] != b'book': # checking format
                log.info('Incorrect format for Bookmark, unknown header found: {}'.format(bookmark[0:4]))
                return
            data_offset = struct.unpack("<L", bookmark[0xC:0x10])[0]
            data_length = struct.unpack("<L", bookmark[data_offset:data_offset+4])[0]
            if data_offset + data_length > len(bookmark):
                log.error("Error, something does not seem right, data size passing end of bookmark!")
            bookmark_items = []
            pos = data_offset + 4
            while (pos < data_offset + data_length):
                bi = self.BookmarkItem()
                bi.Pos = pos
                bi.Size, bi.Type = struct.unpack("<2L", bookmark[pos:pos+8])
                bi.ReadData(bookmark)
                bookmark_items.append(bi)
                pos += 8 + bi.Size 
                remainder = bi.Size % 4   # There is padding to int boundary                
                if remainder > 0: 
                    pos += 4 - remainder
                
            # Now read all the items
            # First set of type 0x0101 are folder names in path
            # Next 0x0101 is Volume Name
            # Next 0x0101 is Volume UUID
            # Next 0x0101 is '/' 
            found_volume_path_parts = False
            found_volume_name = False
            found_volume_uuid = False
            volume_path_parts = []
            parts_order = []
            for bi in bookmark_items:
                if bi.Type == 0x0101:
                    volume_path_parts.append({'Pos':bi.Pos - data_offset, 'Data':bi.Data})
                if bi.Type == 0x0601:
                    found_volume_path_parts = True
                    parts_order = bi.Data
                    break
            if found_volume_path_parts:
                folders = []
                for part in parts_order:
                    item = [x for x in volume_path_parts if part == x['Pos']][0] 
                    folders.append(item['Data'])
                self.URL = '/'.join(folders)

            #For smb or afp or ftp ones, there may be a better url stored:
            for bi in bookmark_items:
                if bi.Type == 0x0901:
                    url = bi.Data
                    if url.find('://') > 0 and not url.startswith('file:///'): # Catch protocols, smb://, afp://, ftp..
                        self.URL = url
                        return
            
        except Exception as ex:
            log.exception('Exception while processing data in Bookmark field')

def PrintAll(recent_items, output_params, source_path):
    recent_info = [ ('Type',DataType.TEXT),('Name',DataType.TEXT),('URL',DataType.TEXT),
                    ('User', DataType.TEXT),('Source',DataType.TEXT)
                   ]

    data_list = []
    for item in recent_items:
        data_list.append( [ str(item.Type), item.Name, item.URL, item.User, item.Source ] )

    WriteList("Recent item information", "RecentItems", data_list, recent_info, output_params, source_path)
    
# # # MAIN PROGRAM BELOW # # # 

def ParseRecentFile(input_file):
    recent_items = []
    basename = os.path.basename(input_file).lower()
    if basename.endswith('.sfl'):
        try:
            with open(input_file, "rb") as f:
                ReadSFLPlist(f, recent_items, input_file, '')
        except Exception as ex:
            log.exception('Failed to open file: {}'.format(input_file))
    elif basename.endswith('.plist'):
        try:
            plist = readPlist(input_file)
            if input_file.endswith('.GlobalPreferences.plist'):
                ReadGlobalPrefPlist(plist, recent_items, input_file)
            elif input_file.endswith('com.apple.finder.plist'):
                ReadFinderPlist(plist, recent_items, input_file)
            else:
                ReadRecentPlist(plist, recent_items, input_file)
        except:
            log.exception ("Could not open plist {}".format(input_file))
    else:
        log.info ('Unknown file: {} '.format(basename))
    
    return recent_items

def ReadFinderPlist(plist, recent_items, source, user=''):
    try:
        vol_dict = plist['FXDesktopVolumePositions']
        try:
            for vol in vol_dict:
                ri = RecentItem('FXDesktopVolumePositions', vol, source, RecentType.VOLUME, user)
                recent_items.append(ri)
        except Exception as ex:
            log.exception('Error reading FXDesktopVolumePositions from plist')   
    except: # Not found
        pass    
    try:
        last_connected_url = plist['FXConnectToLastURL']
        ri = RecentItem('FXConnectToLastURL', last_connected_url, source, RecentType.SERVER, user)
        recent_items.append(ri)
    except: # Not found
        pass
    try:
        last_dir = plist['NSNavLastRootDirectory']
        ri = RecentItem('NSNavLastRootDirectory', last_dir, source, RecentType.PLACE, user)
        recent_items.append(ri)
    except: # Not found
        pass
    try:
        last_dir = plist['NSNavLastCurrentDirectory']
        ri = RecentItem('NSNavLastCurrentDirectory', last_dir, source, RecentType.PLACE, user)
        recent_items.append(ri)
    except: # Not found
        pass
    try:
        recent_folders = plist['FXRecentFolders']
        try:
            for folder in recent_folders:
                ri = RecentItem(folder['name'], '', source, RecentType.PLACE, user)
                data = folder.get('file-bookmark', None)
                if data != None:
                    ri.ReadBookmark(data) 
                else: # Perhaps its osx < 10.9
                    data = folder.get('file-data')
                    if data != None:
                        data = data.get('_CFURLAliasData', None)
                        if data != None:
                            ri.ReadAlias(data) # TODO: Does not parse right, fix!
                        else:
                            log.error('Could not find _CFURLAliasData in item:{}'.format(ri.Name))
                    else:
                        log.error('Could not find file-bookmark or file-data in FXRecentFolders item:{}'.format(ri.Name))
                recent_items.append(ri)
        except Exception as ex:
            log.exception('Error reading FXRecentFolders from plist')   
    except: # Not found
        pass 

def ReadGlobalPrefPlist(plist, recent_items, source='', user=''):
    try:
        recent_places = plist['NSNavRecentPlaces']
        try:
            for place in recent_places:
                ri = RecentItem('NSNavRecentPlaces', place, source, RecentType.PLACE, user)
                recent_items.append(ri)
        except Exception as ex:
            log.exception('Error reading NSNavRecentPlaces from plist')   
    except: # Not found
        pass
    try:
        recent_searches = plist['SGTRecentFileSearches']
        try:
            for search in recent_searches:
                ri = RecentItem('SGTRecentFileSearches:' + search['type'], search['name'], source, RecentType.SEARCH, user)
                recent_items.append(ri)
        except Exception as ex:
            log.exception('Error reading SGTRecentFileSearches from plist')   

    except: # Not found
        pass

def ReadRecentPlist(plist, recent_items, source='', user=''):
    try:
        for item_type in plist:
            if  item_type == 'Hosts':
                try:
                    for item in plist['Hosts']['CustomListItems']:
                        ri = RecentItem(item['Name'], item['URL'], source, RecentType.HOST, user)
                        recent_items.append(ri)
                except Exception as ex:
                    log.error('Error reading Hosts from plist, error was {}'.format(str(ex)))
            elif item_type == 'RecentApplications':
                try:
                    for item in plist['RecentApplications']['CustomListItems']:
                        ri = RecentItem(item['Name'], '', source, RecentType.APPLICATION, user)
                        recent_items.append(ri)
                except Exception as ex:
                    log.error('Error reading RecentApplications from plist, error was {}'.format(str(ex)))
            elif item_type == 'RecentDocuments':
                try:
                    for item in plist['RecentDocuments']['CustomListItems']:
                        ri = RecentItem(item['Name'], '', source, RecentType.DOCUMENT, user)
                        ri.ReadBookmark(item['Bookmark'])                        
                        recent_items.append(ri)
                except Exception as ex:
                    log.error('Error reading RecentDocuments from plist, error was {}'.format(str(ex)))
            elif item_type == 'RecentServers':
                try:
                    for item in plist['RecentServers']['CustomListItems']:
                        ri = RecentItem(item['Name'], '', source, RecentType.SERVER, user)
                        data = item.get('Alias', None) 
                        if data == None: # Yosemite onwards it is a bookmark!
                            data = item.get('Bookmark', None)
                            if data == None:
                                log.error('Could not find Bookmark or Alias to read in RecentServers for name={}!'.format(ri.Name))
                            else:
                                ri.ReadBookmark(data)
                        else:
                            ri.ReadAlias(data)
                        recent_items.append(ri)
                except Exception as ex:
                    log.error('Error reading RecentServers from plist, error was {}'.format(str(ex)))
            else:
                log.info("Found unknown item {} in plist".format(item_type))
    except Exception as ex:
        log.exception('Error reading plist')   

def ReadSFLPlist(file_handle, recent_items, source, user=''):
    try:
        ccl_bplist.set_object_converter(ccl_bplist.NSKeyedArchiver_common_objects_convertor)
        plist = ccl_bplist.load(file_handle)

        ns_keyed_archiver_obj = ccl_bplist.deserialise_NsKeyedArchiver(plist, parse_whole_structure=True)

        root = ns_keyed_archiver_obj['root']
        log.debug('Version of SFL is {}'.format(root['version'])) # Currently we parse version 1
        items = root['items']
        count = len(items)

        for item in items:
            url = ''
            try: url = item['URL']['NS.relative']
            except: pass
            if url.find('x-apple-findertag') == 0: continue # skipping these items
            name = item['name']
            recent_type = RecentType.UNKNOWN
            basename = os.path.basename(source).lower()
            if basename.find('recentservers') >=0 : recent_type = RecentType.SERVER
            elif basename.find('recenthosts') >=0 : recent_type = RecentType.HOST
            elif basename.find('recentdocuments') >=0 : recent_type = RecentType.DOCUMENT
            elif basename.find('recentapplications') >=0 : recent_type = RecentType.APPLICATION

            ri = RecentItem(name, url, source, recent_type, user)
            recent_items.append(ri)
            # try: # Not reading bookmark right now, but this code should work!
            #     bm = item['bookmark']
            #     if type(bm) == ccl_bplist.NsKeyedArchiverDictionary: # Soemtimes its 'str', otherwise this
            #         bm = bm['NS.data']
            #     #print "bookmark bytes=", len(bm)
            # except:
            #     pass # Not everything has bookmarks
    except Exception as ex:
        log.exception('Error reading SFL plist')

def ProcessSFLFolder(mac_info, user_path, recent_items):
    processed_paths = []
    for user in mac_info.users:
        user_name = user.user_name
        if user.home_dir == '/private/var/empty': continue # Optimization, nothing should be here!
        elif user.home_dir == '/private/var/root': user_name = 'root' # Some other users use the same root folder, we will list such all users as 'root', as there is no way to tell
        if user.home_dir in processed_paths: continue # Avoid processing same folder twice (some users have same folder! (Eg: root & daemon))
        processed_paths.append(user.home_dir)
        source_folder = user_path.format(user.home_dir)
        if mac_info.IsValidFolderPath(source_folder):
            files_list = mac_info.ListItemsInFolder(source_folder,EntryType.FILES)
            for file_entry in files_list:
                if file_entry['name'].lower().endswith('.sfl') and (file_entry['size'] > 446): # 446 is an empty plist, only keyed class data
                    source_path = source_folder + '/' + file_entry['name']
                    mac_info.ExportFile(source_path, __Plugin_Name, user_name + "_")
                    f = mac_info.OpenSmallFile(source_path)
                    if f != None:
                        ReadSFLPlist(f, recent_items, source_path, user_name)
    
def ProcessSFL(mac_info, recent_items):
    '''Processes .SFL files '''
    user_path_1 = '{}/Library/Application Support/com.apple.sharedfilelist'
    ProcessSFLFolder(mac_info, user_path_1, recent_items)

    user_path_2 = '{}/Library/Application Support/com.apple.sharedfilelist/com.apple.LSSharedFileList.ApplicationRecentDocuments'
    ProcessSFLFolder(mac_info, user_path_2, recent_items)

def ProcessSinglePlist(mac_info, source_path, user, recent_items):
    mac_info.ExportFile(source_path, __Plugin_Name, user + "_")
    success, plist, error = mac_info.ReadPlist(source_path)
    if success:
        if source_path.endswith('.GlobalPreferences.plist'):
            ReadGlobalPrefPlist(plist, recent_items, source_path, user)
        elif source_path.endswith('com.apple.finder.plist'):
            ReadFinderPlist(plist, recent_items, source_path, user)
        else:
            ReadRecentPlist(plist, recent_items, source_path, user)
    else:
        log.info('Failed to open plist: {}'.format(source_path))

def ProcessPreferencesFolder(mac_info, recent_items):
    '''Process .plist files in Preferences folder'''
    user_path = '{}/Library/Preferences'
    processed_paths = []
    for user in mac_info.users:
        user_name = user.user_name
        if user.home_dir == '/private/var/empty': continue # Optimization, nothing should be here!
        elif user.home_dir == '/private/var/root': user_name = 'root' # Some other users use the same root folder, we will list such all users as 'root', as there is no way to tell
        if user.home_dir in processed_paths: continue # Avoid processing same folder twice (some users have same folder! (Eg: root & daemon))
        processed_paths.append(user.home_dir)
        source_folder = user_path.format(user.home_dir)
        if mac_info.IsValidFolderPath(source_folder):
            files_list = mac_info.ListItemsInFolder(source_folder,EntryType.FILES)
            for file_entry in files_list:
                if file_entry['name'].lower().endswith('.plist') and \
                  (file_entry['name'].lower().find('lssharedfilelist') > 0) and (file_entry['size'] > 120): 
                    source_path = source_folder + '/' + file_entry['name']
                    mac_info.ExportFile(source_path, __Plugin_Name, user_name + "_")
                    ProcessSinglePlist(mac_info, source_path, user_name, recent_items)

def Plugin_Start(mac_info):
    '''Main Entry point function for plugin'''
    recent_items = []
    user_recent_plist_path = '{}/Library/Preferences/com.apple.recentitems.plist'
    user_global_pref_plist_path = '{}/Library/Preferences/.GlobalPreferences.plist'
    user_finder_plist_path = '{}/Library/Preferences/com.apple.finder.plist'
    processed_paths = []
    for user in mac_info.users:
        user_name = user.user_name
        if user.home_dir == '/private/var/empty': continue # Optimization, nothing should be here!
        elif user.home_dir == '/private/var/root': user_name = 'root' # Some other users use the same root folder, we will list such all users as 'root', as there is no way to tell
        if user.home_dir in processed_paths: continue # Avoid processing same folder twice (some users have same folder! (Eg: root & daemon))
        processed_paths.append(user.home_dir)
        source_path = user_recent_plist_path.format(user.home_dir)
        if mac_info.IsValidFilePath(source_path):
            ProcessSinglePlist(mac_info, source_path, user_name, recent_items)
        #else:
        #    log.debug('File not found: {}'.format(source_path))
        
        #Process .Globalpreferences.plist
        source_path = user_global_pref_plist_path.format(user.home_dir)
        if mac_info.IsValidFilePath(source_path):
            ProcessSinglePlist(mac_info, source_path, user_name, recent_items)
        # Process com.apple.finder.plist
        source_path = user_finder_plist_path.format(user.home_dir)
        if mac_info.IsValidFilePath(source_path):
            ProcessSinglePlist(mac_info, source_path, user_name, recent_items)
        
    ProcessPreferencesFolder(mac_info, recent_items)
    ProcessSFL(mac_info, recent_items) # Elcapitan & higher (mostly)

    if len(recent_items) > 0:
        PrintAll(recent_items, mac_info.output_params, '')
    else:
        log.info('No recent items were found!')

def Plugin_Start_Standalone(input_files_list, output_params):
    log.info("Module Started as standalone")
    for input_path in input_files_list:
        log.debug("Input file passed was: " + input_path)
        recent_items = ParseRecentFile(input_path)
        if len(recent_items) > 0:
            PrintAll(recent_items, output_params, input_path)
        else:
            log.info('No recent items found in {}'.format(input_path))

if __name__ == '__main__':
    print ("This plugin is a part of a framework and does not run independently on its own!")