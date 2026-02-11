'''
   Copyright (c) 2017 Yogesh Khatri
   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the
   terms of the MIT License.

'''

import sqlite3
from plugins.helpers.macinfo import *
from plugins.helpers.writer import *
from plugins.helpers.common import *
import logging
import os

__Plugin_Name = "IMESSAGE"
__Plugin_Friendly_Name = "iMessage Info"
__Plugin_Version = "1.1"
__Plugin_Description = "Parses iMessage conversations, exports messages and attachments"
__Plugin_Author = "Jack Farley, Yogesh Khatri"
__Plugin_Author_Email = "jack.farley@mymail.champlain.edu, yogesh@swiftforensics.com"

__Plugin_Modes = "MACOS,ARTIFACTONLY"
__Plugin_ArtifactOnly_Usage = 'Provide one or more iMessage databases (chat.db) found at /Users/<USER>/Library/Messages/'

log = logging.getLogger('MAIN.' + __Plugin_Name) # Do not rename or remove this ! This is the logger object

#---- Do not change the variable names in above section ----#

class IMessage:
    def __init__(self, msg_id, chat_id, text, conversation, contact, direction, acc, date, date_read, date_delivered, is_from_me, is_read, att_path, att_name, att_size, service, user, source):
        self.msg_id = msg_id
        self.chat_id = chat_id
        self.text = text
        self.conversation = conversation
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
        self.service = service
        self.user = user
        self.source = source

def PrintAll(imessages, output_params, source_path):
    imessages_info = [ ('MsgID',DataType.INTEGER),('Text',DataType.TEXT),('ChatID',DataType.INTEGER),
                       ('ChatIdentifier',DataType.TEXT),
                       ('Contact',DataType.TEXT),('Direction',DataType.TEXT), ('Account',DataType.TEXT),
                       ('Date',DataType.DATE),('DateDelivered',DataType.DATE),('DateRead',DataType.DATE),
                       ('AttachmentPath',DataType.TEXT),('AttachmentName',DataType.TEXT),
                       ('AttachmentSize', DataType.INTEGER),('Service',DataType.TEXT),
                       ('User', DataType.TEXT),('Source',DataType.TEXT)
                     ]

    log.info(str(len(imessages)) + " iMessages found")
    imessages_list = []
    for imsg in imessages:
        imsg_items = [imsg.msg_id, imsg.text, imsg.chat_id, imsg.conversation, imsg.contact, 
                      u'\u27F6' if imsg.direction == '->' else u'\u27F5', 
                      imsg.account, imsg.date, imsg.date_delivered, imsg.date_read,
                      imsg.att_path, imsg.att_name, imsg.att_size, imsg.service,
                      imsg.user, imsg.source
                     ]
        imessages_list.append(imsg_items)
    WriteList("iMessages", "IMessages", imessages_list, imessages_info, output_params, source_path)

def OpenDbFromImage(mac_info, inputPath):
    '''Returns tuple of (connection, wrapper_obj)'''
    try:
        sqlite = SqliteWrapper(mac_info)
        conn = sqlite.connect(inputPath)
        if conn:
            log.debug ("Opened database successfully")
        return conn, sqlite
    except sqlite3.Error as ex:
        log.exception ("Failed to open database, is it a valid iMessage DB?")
    return None, None

def OpenDb(inputPath):
    log.info ("Processing file " + inputPath)
    try:
        conn = CommonFunctions.open_sqlite_db_readonly(inputPath)
        log.debug ("Opened database successfully")
        return conn
    except sqlite3.Error:
        log.exception ("Failed to open database, is it a valid iMessage DB?")
    return None


def ReadiMessages(db, imessages, source, user):
    try:
        dest_id_exists = CommonFunctions.ColumnExists(db, 'message', 'destination_caller_id')
        query = "SELECT m.rowid as msg_id, m.handle_id, m.text, c.ROWID as chat_id, c.chat_identifier as chat, h.id as contact, m.service, "\
                " (case when m.is_from_me == 0 then '->' when m.is_from_me == 1 then '<-' end ) as direction, "\
                " m.account, m.date, m.date_read, m.date_delivered, m.is_from_me, m.is_read, m.attributedBody, "\
                + ("m.destination_caller_id, " if dest_id_exists else "") + \
                " a.filename as att_path, a.transfer_name as att_name, a.total_bytes as att_size "\
                " from message as m "\
                " LEFT JOIN message_attachment_join as ma on ma.message_id = m.rowid "\
                " LEFT JOIN attachment as a on a.ROWID=ma.attachment_id "\
                " LEFT JOIN chat_message_join as cmj on cmj.message_id = m.rowid" \
                " LEFT JOIN chat as c on c.ROWID=cmj.chat_id" \
                " LEFT JOIN handle as h on h.ROWID=m.handle_id"
        db.row_factory = sqlite3.Row
        cursor = db.execute(query)
        for row in cursor:
            att_path = row['att_path']
            if att_path != None:
                pass
            account = row['account']
            if dest_id_exists and row['destination_caller_id']:
                if account is None:
                    account = row['destination_caller_id']
                elif account.find(row['destination_caller_id']) == -1:
                    account = row['destination_caller_id'] + "(" + account + ")"
            text = row['text']
            if text is None:
                # Often this field is blank and the data is stored as a serialized NSArchive (legacy format)
                # Below code just hacks the first NSString from this structure, it does not implement a full parser!
                attributed_body = row['attributedBody']
                if attributed_body:
                    string_pos = attributed_body.find(b'NSString', 0)
                    text = ''
                    count = 0
                    while string_pos > 0:
                        text_data = attributed_body[string_pos + 8:]
                        skip_bytes = 5
                        if text_data[skip_bytes] == 0x81:
                            str_len = struct.unpack("<H", text_data[6:8])[0]
                            skip_bytes += 3
                        else:
                            str_len = text_data[skip_bytes]
                            skip_bytes += 1
                        if str_len > len(text_data):
                            log.error(f'str_len ({str_len}) > len(text_data) ({len(text_data)})')
                        if text:
                            text += "\n"
                        text += text_data[skip_bytes:skip_bytes + min(len(text_data), str_len)].decode('utf8', 'ignore')
                        count += 1

                        string_pos += 11 + str_len
                        string_pos = attributed_body.find(b'NSString', string_pos)
                        
                    if count > 1:
                        log.debug(f"MULTIPLE NSStrings in msg {row['msg_id']}, {text}")

            imsg = IMessage(row['msg_id'], row['chat_id'], text, row['chat'], row['contact'], 
                            row['direction'], account,
                            CommonFunctions.ReadMacAbsoluteTime(row['date']),
                            CommonFunctions.ReadMacAbsoluteTime(row['date_read']),
                            CommonFunctions.ReadMacAbsoluteTime(row['date_delivered']),
                            row['is_from_me'], row['is_read'],
                            row['att_path'], row['att_name'], row['att_size'],
                            row['service'],
                            user, source)
            imessages.append(imsg)
    except sqlite3.Error:
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
                log.info('Exporting Attachments folder now, this might take some time (depending on size)...')
                mac_info.ExportFolder(user_attachments_path, os.path.join(__Plugin_Name, user_name), True)
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