'''
   Copyright (c) 2017 Yogesh Khatri 

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the 
   terms of the MIT License.
   
'''
from __future__ import print_function
#from __future__ import unicode_literals <-- left out as sqlite3 has issues with it !
import codecs
import sqlite3
import sys
import os
import biplist
from biplist import *
import logging
from helpers.macinfo import *
from helpers.writer import *
from helpers.common import *

__Plugin_Name = "NOTIFICATIONS" # Cannot have spaces, and must be all caps!
__Plugin_Friendly_Name = "Notifications"
__Plugin_Version = "1.0"
__Plugin_Description = "Reads notification databases"
__Plugin_Author = "Yogesh Khatri"
__Plugin_Author_Email = "yogesh@swiftforensics.com"

__Plugin_Standalone = True
__Plugin_Standalone_Usage = '''This module parses the notification database for a user. 

For OSX Mavericks (and earlier), this is found at:
/Users/<profile>/Library/Application Support/NotificationCenter/<UUID>.db

For Yosemite onwards, this is at: 
/private/var/folders/<xx>/<yyyyyyy>/0/com.apple.notificationcenter/db
 where the path <xx>/<yyyyyyy> represents the DARWIN_USER_DIR for a user
'''
log = logging.getLogger('MAIN.' + __Plugin_Name) # Do not rename or remove this ! This is the logger object

#---- Do not change the variable names in above section ----#

notifications = []
data_info = [('User', DataType.TEXT),('Date', DataType.DATE),('Shown', DataType.INTEGER), \
            ('Bundle', DataType.TEXT),('AppPath', DataType.TEXT),('UUID', DataType.TEXT), \
            ('Title', DataType.TEXT),('SubTitle', DataType.TEXT),('Message', DataType.TEXT), \
            ('SourceFilePath', DataType.TEXT)]

def RemoveTabsNewLines(str):
    return str.replace("\t", " ").replace("\r", " ").replace("\n", "")

def ProcessNotificationDb(inputPath, output_params):
    log.info ("Processing file " + inputPath)
    try:
        conn = sqlite3.connect(inputPath)
        log.debug ("Opened database successfully")
        ParseDb(conn, inputPath, '', output_params.timezone)
    except Exception as ex:
        log.error ("Failed to open database, is it a valid Notification DB? \nError details: " + str(ex.args))

def ProcessNotificationDb_Wrapper(inputPath, mac_info, user):
    log.info ("Processing notifications for user '{}' from file {}".format(user, inputPath))
    try:
        sqlite = SqliteWrapper(mac_info)
        conn = sqlite.connect(inputPath)
        log.debug ("Opened database successfully")
        ParseDb(conn, inputPath, user, mac_info.output_params.timezone)
    except Exception as ex:
        log.error ("Failed to open database, is it a valid Notification DB? Error details: " + str(ex)) 

def GetText(string_or_binary):
    '''Converts binary or text string into text string. UUID in Sierra is now binary blob instead of hex text.'''
    text = ''
    try:
        if type(string_or_binary) == buffer or type(string_or_binary) == bytes: # Python3 is 'bytes'
            text = ''.join('{:02X}'.format(ord(x)) for x in string_or_binary)
        else:
            text = string_or_binary
    except Exception as ex:
        log.error('Error trying to convert binary value to hex text. Details: ' + str(ex))
    return text

def ParseDb(conn, inputPath, user, timezone):
    '''variable 'timezone' is not being currently used'''
    try:
        conn.row_factory = sqlite3.Row
        cursor = conn.execute("SELECT date_presented as time_utc, actually_presented AS shown, "
                                "(SELECT bundleid from app_info WHERE app_info.app_id = presented_notifications.app_id)  AS bundle, "
                                "(SELECT last_known_path from app_loc WHERE app_loc.app_id = presented_notifications.app_id)  AS appPath, "
                                "(SELECT uuid from notifications WHERE notifications.note_id = presented_notifications.note_id) AS uuid, "
                                "(SELECT encoded_data from notifications WHERE notifications.note_id = presented_notifications.note_id) AS dataPlist "
                                "from presented_notifications ")
        try:
            rowcount = 0
            for row in cursor:
                rowcount += 1
                title    = ''
                subtitle = ''
                message  = ''
                try:
                    plist = readPlistFromString(row['dataPlist'])
                    title_index = 2 # by default
                    subtitle_index = -1 # mostly absent!
                    text_index = 3 # by default
                    try:
                        title_index = int(plist['$objects'][1]['NSTitle'])
                    except Exception: pass
                    try:
                        subtitle_index = int(plist['$objects'][1]['NSSubtitle'])
                    except Exception: pass
                    try:
                        text_index = int(plist['$objects'][1]['NSInformativetext'])
                    except Exception: pass
                    try:
                        title = RemoveTabsNewLines(plist['$objects'][title_index])
                    except Exception: pass
                    try:
                        subtitle = RemoveTabsNewLines(plist['$objects'][subtitle_index]) if subtitle_index > -1 else ""
                    except Exception: pass                        
                    try:
                        message = RemoveTabsNewLines(plist['$objects'][text_index])
                    except Exception: pass
                except (InvalidPlistException, NotBinaryPlistException, Exception) as e:
                    log.error ("Invalid plist in table." + str(e) )
                try:
                    notifications.append([user, CommonFunctions.ReadMacAbsoluteTime(row['time_utc']) , 
                                         row['shown'], row['bundle'], row['appPath'], GetText(row['uuid']), 
                                         title, subtitle, message, inputPath])
                except Exception as ex:
                    log.error ("Error while fetching row data, error details:\n" + str(ex))
        except Exception as ex:
            log.error ("Db cursor error while reading file " + inputPath)
            log.exception("Exception Details")
        conn.close()
    except Exception as ex:
        log.error ("Sqlite error - \nError details: \n" + str(ex))

def WriteOutput(output_params):
    if len(notifications) == 0: 
        log.info("No notification data was retrieved!")
        return
    try:
        log.debug ("Trying to write out parsed notifications data")
        writer = DataWriter(output_params, "Notifications", data_info)
        try:
            writer.WriteRows(notifications)
        except Exception as ex:
            log.error ("Failed to write row  data")
            log.exception ("Error details")
        finally:
            writer.FinishWrites()
    except Exception as ex:
        log.error ("Failed to initilize data writer")
        log.exception ("Error details")

def Plugin_Start(mac_info):
    version_dict = mac_info.GetVersionDictionary()
    if version_dict['major'] == 10 and version_dict['minor'] <= 9:   # older than yosemite, ie, mavericks or earlier
        users_dir = mac_info.ListItemsInFolder('/Users', EntryType.FOLDERS)
        for user in users_dir:
            temp_path = '/Users/' + user['name'] + '/Library/Application Support/NotificationCenter'
            files = mac_info.ListItemsInFolder(temp_path, EntryType.FILES)
            for db in files:
                # Not sure if this is the only file here
                if db['name'].endswith('.db') and db['size'] > 0 :
                    db_path = '/Users/' + user['name'] + '/Library/Application Support/NotificationCenter/' + db['name']
                    ProcessNotificationDb_Wrapper(db_path, mac_info, user['name'])
                    mac_info.ExportFile(db_path, __Plugin_Name, user['name'] + '_')
                    break
            
    elif version_dict['major'] == 10 and version_dict['minor'] >= 10: # Yosemite or higher
        for user in mac_info.users:
            if not user.DARWIN_USER_DIR or not user.user_name: continue # TODO: revisit this later!
            else:
                darwin_user_folders = user.DARWIN_USER_DIR.split(',')
                for darwin_user_dir in darwin_user_folders:
                    db_path = darwin_user_dir + '/com.apple.notificationcenter/db/db'
                    if not mac_info.IsValidFilePath(db_path): continue
                    else:
                        ProcessNotificationDb_Wrapper(db_path, mac_info, user.user_name)
                        mac_info.ExportFile(db_path, __Plugin_Name, user.user_name + '_')
    WriteOutput(mac_info.output_params)

## Standalone Plugin call

def Plugin_Start_Standalone(input_files_list, output_params):
    log.info("Module Started as standalone")
    for input_path in input_files_list:
        if os.path.isfile(input_path):
            ProcessNotificationDb(input_path, output_params)
        else:
            log.error("Input path is not a file! Please provide the path to a notifications database file")
    WriteOutput(output_params)

## 
if __name__ == '__main__':
    print("This plugin is a part of a framework and does not run independently on its own!")

	
