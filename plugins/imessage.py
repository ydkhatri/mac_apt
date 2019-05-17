'''
   Copyright (c) 2017 Yogesh Khatri
   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the
   terms of the MIT License.

'''

import sqlite3
from helpers.macinfo import *
from helpers.writer import *
from helpers.common import *
import logging
import os

__Plugin_Name = "IMESSAGE" # Cannot have spaces, and must be all caps!
__Plugin_Friendly_Name = "iMessage Info"
__Plugin_Version = "1.0"
__Plugin_Description = "Parses iMessage conversations, exports messages and attachments"
__Plugin_Author = "Jack Farley, Yogesh Khatri"
__Plugin_Author_Email = "jack.farley@mymail.champlain.edu, yogesh@swiftforensics.com"

__Plugin_Standalone = True
__Plugin_Standalone_Usage = 'Provide one or more iMessage databases (chat.db) found at /Users/<USER>/Library/Messages/'

log = logging.getLogger('MAIN.' + __Plugin_Name) # Do not rename or remove this ! This is the logger object

#---- Do not change the variable names in above section ----#

class IMessage:
    def __init__(self, msg_id, handle_id, text, contact, direction, acc, date, date_read, date_delivered, is_from_me, is_read, att_path, att_name, att_size, user, source):
        self.msg_id = msg_id
        self.handle_id = handle_id
        self.text = text
        self.contact = contact
        self.direction= direction
        self.date_read = date_read
        self.date_delivered = date_delivered
        self.is_from_me = is_from_me
        self.is_read = is_read
        self.account = acc
        self.date = date
        self.att_path = att_path
        self.att_name = att_name
        self.att_size = att_size
        self.user = user
        self.source = source

def PrintAll(imessages, output_params, source_path):
    imessages_info = [ ('MsgID',DataType.INTEGER),('Text',DataType.TEXT),('Conversation',DataType.INTEGER),
                       ('Contact',DataType.TEXT),('Direction',DataType.TEXT), ('Account',DataType.TEXT),
                       ('Date',DataType.DATE),('AttachmentPath',DataType.TEXT),('AttachmentName',DataType.TEXT),
                       ('AttachmentSize', DataType.INTEGER),
                       ('User', DataType.TEXT),('Source',DataType.TEXT)
                     ]

    log.info(str(len(imessages)) + " iMessages found")
    imessages_list = []
    for imsg in imessages:
        imsg_items = [imsg.msg_id, imsg.text, imsg.handle_id, imsg.contact, 
                      u'\u27F6' if imsg.direction == '->' else u'\u27F5', 
                      imsg.account, imsg.date,
                      imsg.att_path, imsg.att_name, imsg.att_size, 
                      imsg.user, imsg.source
                     ]
        imessages_list.append(imsg_items)
    WriteList("iMessages", "IMessages", imessages_list, imessages_info, output_params, source_path)

def GetAttachments(mac_info, sourceDirectory, user):
    '''
        Walks through attachment directory of 3 randomely named subdirectories
        Attachments may be seen as an image and a movie, due to the nature of sending Apple's Live Photos
    '''
    files = []
    initial_folders = mac_info.ListItemsInFolder(sourceDirectory, EntryType.FOLDERS, True)
    if len(initial_folders) > 0:
        for folders in initial_folders:
            folder_names = folders['name'] + '/'
            raw_secondary_folder_names = mac_info.ListItemsInFolder(sourceDirectory + folder_names, EntryType.FOLDERS, True)
            for secondary_folders in raw_secondary_folder_names:
                secondary_folder_names = secondary_folders['name'] + '/'
                raw_tri_folder_names = mac_info.ListItemsInFolder(sourceDirectory + folder_names + secondary_folder_names, EntryType.FOLDERS, True)
                for tri_folders in raw_tri_folder_names:
                    tri_folder_names = tri_folders['name'] + '/'
                    items = mac_info.ListItemsInFolder(sourceDirectory + folder_names + secondary_folder_names + tri_folder_names, EntryType.FILES, True)
                    for attachments in items:
                        attachments = attachments['name']
                        files.append(sourceDirectory + folder_names + secondary_folder_names + tri_folder_names + attachments)
        for attachment_paths in files:
            mac_info.ExportFile(attachment_paths, os.path.join(__Plugin_Name, user), '', False)
    else:
        log.info('No attachment files found under {}'.format(sourceDirectory))

def OpenDbFromImage(mac_info, inputPath):
    '''Returns tuple of (connection, wrapper_obj)'''
    try:
        sqlite = SqliteWrapper(mac_info)
        conn = sqlite.connect(inputPath)
        log.debug ("Opened database successfully")
        return conn, sqlite
    except Exception as ex:
        log.exception ("Failed to open database, is it a valid iMessage DB?")
    return None

def OpenDb(inputPath):
    log.info ("Processing file " + inputPath)
    try:
        conn = sqlite3.connect(inputPath)
        log.debug ("Opened database successfully")
        return conn
    except:
        log.exception ("Failed to open database, is it a valid iMessage DB?")
    return None


def ReadiMessages(db, imessages, source, user):
    try:
        query = u"SELECT m.rowid as msg_id, m.handle_id, m.text ,c.chat_identifier as contact, "\
                " (case when m.is_from_me == 0 then '->' when m.is_from_me == 1 then '<-' end ) as direction, "\
                " m.account, m.date, m.date_read, m.date_delivered, m.is_from_me, m.is_read, "\
                " a.filename as att_path, a.transfer_name as att_name, a.total_bytes as att_size"\
                " from message as m "\
                " LEFT JOIN message_attachment_join as ma on ma.message_id = m.rowid "\
                " LEFT JOIN attachment as a on a.ROWID=ma.attachment_id "\
                " LEFT JOIN chat_message_join as cmj on cmj.message_id = m.rowid" \
                " LEFT JOIN chat as c on c.ROWID=cmj.chat_id"
        db.row_factory = sqlite3.Row
        cursor = db.execute(query)
        for row in cursor:
            try:
                att_path = row['att_path']
                if att_path != None:
                    pass
                imsg = IMessage(row['msg_id'], row['handle_id'], row['text'], row['contact'], row['direction'], row['account'],
                                CommonFunctions.ReadMacAbsoluteTime(row['date']),
                                CommonFunctions.ReadMacAbsoluteTime(row['date_read']),
                                CommonFunctions.ReadMacAbsoluteTime(row['date_delivered']),
                                row['is_from_me'], row['is_read'],
                                row['att_path'], row['att_name'], row['att_size'],
                                user, source)
                imessages.append(imsg)
            except:
                log.exception('Error fetching row data')
    except:
        log.exception('Query  execution failed. Query was: ' + query)

def ProcessChatDbFromPath(mac_info, imessages, source_path, user):
    mac_info.ExportFile(source_path, __Plugin_Name, user + "_")
    db, wrapper = OpenDbFromImage(mac_info, source_path)
    if db != None:
        ReadiMessages(db, imessages, source_path, user)
        db.close()


def Plugin_Start(mac_info):
    '''Main Entry point function for plugin'''
    chat_db_path = '{}/Library/Messages/chat.db'
    attachments_path = '{}/Library/Messages/Attachments/'
    processed_paths = []
    imessages = []
    for user in mac_info.users:
        user_name = user.user_name
        if user.home_dir == '/private/var': continue # Optimization, nothing should be here!
        elif user.home_dir == '/private/var/root': user_name = 'root' # Some other users use the same root folder, we will list such all users as 'root', as there is no way to tell
        if user.home_dir in processed_paths: continue # Avoid processing same folder twice (some users have same folder! (Eg: root & daemon))
        processed_paths.append(user.home_dir)
        chats_file_path = chat_db_path.format(user.home_dir)
        if mac_info.IsValidFilePath(chats_file_path):
            ProcessChatDbFromPath(mac_info, imessages, chats_file_path, user_name)
            user_attachments_path = attachments_path.format(user.home_dir)
            if mac_info.IsValidFolderPath(user_attachments_path):
                GetAttachments(mac_info, user_attachments_path, user_name)
    if imessages:
        PrintAll(imessages, mac_info.output_params, '')
    else:
        log.info("No imessages found.")

def Plugin_Start_Standalone(input_files_list, output_params):
    log.info("Module Started as standalone")
    for input_path in input_files_list:
        log.debug("Input file passed was: " + input_path)
        imessages = []
        db = OpenDb(input_path)
        if db != None:
            filename = os.path.basename(input_path)
            ReadiMessages(db, imessages, input_path, "")
        if imessages:
            PrintAll(imessages, output_params, '')
        else:
            log.info("No imessages found.")

if __name__ == '__main__':
    print ("This plugin is a part of a framework and does not run independently on its own!")