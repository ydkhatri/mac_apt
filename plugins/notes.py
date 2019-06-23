'''
   Copyright (c) 2017 Yogesh Khatri 

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the 
   terms of the MIT License.

   notes.py
   ---------------
   This plugin will read databases from the built-in 'Notes' application.

   #TODO:
   Create better output, html in xl is not readable.
   Export attachments contained within individual notes.
'''

import os
from helpers.macinfo import *
from helpers.writer import *
import logging
from biplist import *
import binascii
import sqlite3
import zlib
import struct

__Plugin_Name = "NOTES"
__Plugin_Friendly_Name = "Notes"
__Plugin_Version = "1.1"
__Plugin_Description = "Reads Notes databases"
__Plugin_Author = "Yogesh Khatri"
__Plugin_Author_Email = "yogesh@swiftforensics.com"

__Plugin_Standalone = True
__Plugin_Standalone_Usage = 'Provide one or more Notes sqlite databases as input to process. These are typically '\
                            'located at ~/Library/Containers/com.apple.Notes/Data/Library/Notes/  or '\
                            '~/Library/Group Containers/group.com.apple.notes/'

log = logging.getLogger('MAIN.' + __Plugin_Name) # Do not rename or remove this ! This is the logger object

#---- Do not change the variable names in above section ----#

class Note:

    def __init__(self, id, folder, title, snippet, data, att_id, att_path, acc_desc, acc_identifier, acc_username, created, edited, version, user, source):
        self.note_id = id
        self.folder = folder
        self.title = title
        self.snippet = snippet
        self.data = data
        self.attachment_id = att_id
        self.attachment_path = att_path
        self.account = acc_desc
        self.account_identifier = acc_identifier
        self.account_username = acc_username
        self.date_created = created
        self.date_edited = edited
        self.version = version
        self.user = user
        self.source_file = source
        #self.folder_title_modified = folder_title_modified

def PrintAll(notes, output_params):

    note_info = [ ('ID',DataType.INTEGER),('Title',DataType.TEXT),('Snippet',DataType.TEXT),('Folder',DataType.TEXT),
                    ('Created',DataType.DATE),('LastModified',DataType.DATE),('Data', DataType.TEXT),
                    ('AttachmentID',DataType.TEXT),('AttachmentPath',DataType.TEXT),('AccountDescription',DataType.TEXT),
                    ('AccountIdentifier', DataType.TEXT),('AccountUsername', DataType.TEXT),
                    ('Version', DataType.TEXT),('User', DataType.TEXT),('Source',DataType.TEXT)
                ]

    log.info (str(len(notes)) + " note(s) found")
    notes_list = []
    for note in notes:
        note_items = [note.note_id, note.title, note.snippet, note.folder, 
                      note.date_created, note.date_edited, note.data,
                      note.attachment_id, note.attachment_path, note.account,
                      note.account_identifier, note.account_username, 
                      note.version, note.user, note.source_file
                     ]
        notes_list.append(note_items)
    WriteList("note information", "Notes", notes_list, note_info, output_params, '')

def ReadAttPathFromPlist(plist_blob):
    '''For NotesV2, read plist and get path'''
    try:
        plist = readPlistFromString(plist_blob)
        try:
            path = plist['$objects'][2]
            return path
        except (KeyError, IndexError):
            log.exception('Could not fetch attachment path from plist')
    except (InvalidPlistException, IOError) as e:
        log.error ("Invalid plist in table." + str(e) )
    return ''

def GetUncompressedData(compressed):
    if compressed == None:
        return None
    data = None
    try:
        data = zlib.decompress(compressed, 15 + 32)
    except zlib.error:
        log.exception('Zlib Decompression failed!')
    return data

def ReadNotesV2_V4_V6(db, notes, version, source, user):
    '''Reads NotesVx.storedata, where x= 2,4,6,7'''
    try:
        query = "SELECT n.Z_PK as note_id, n.ZDATECREATED as created, n.ZDATEEDITED as edited, n.ZTITLE as title, "\
                " (SELECT ZNAME from ZFOLDER where n.ZFOLDER=ZFOLDER.Z_PK) as folder, "\
                " (SELECT zf2.ZACCOUNT from ZFOLDER as zf1  LEFT JOIN ZFOLDER as zf2 on (zf1.ZPARENT=zf2.Z_PK) where n.ZFOLDER=zf1.Z_PK) as folder_parent_id, "\
                " ac.ZEMAILADDRESS as email, ac.ZACCOUNTDESCRIPTION as acc_desc, ac.ZUSERNAME as username, b.ZHTMLSTRING as data, "\
                " att.ZCONTENTID as att_id, att.ZFILEURL as file_url "\
                " FROM ZNOTE as n "\
                " LEFT JOIN ZNOTEBODY as b ON b.ZNOTE = n.Z_PK "\
                " LEFT JOIN ZATTACHMENT as att ON att.ZNOTE = n.Z_PK "\
                " LEFT JOIN ZACCOUNT as ac ON ac.Z_PK = folder_parent_id"
        db.row_factory = sqlite3.Row
        cursor = db.execute(query)
        for row in cursor:
            try:
                att_path = ''
                if row['file_url'] != None:
                    att_path = ReadAttPathFromPlist(row['file_url'])
                note = Note(row['note_id'], row['folder'], row['title'], '', row['data'], row['att_id'], att_path,
                            row['acc_desc'], row['email'], row['username'], 
                            CommonFunctions.ReadMacAbsoluteTime(row['created']), CommonFunctions.ReadMacAbsoluteTime(row['edited']),
                            version, user, source)
                notes.append(note)
            except (sqlite3.Error, KeyError):
                log.exception('Error fetching row data')
    except sqlite3.Error:
        log.exception('Query  execution failed. Query was: ' + query)

def ReadLengthField(blob):
    '''Returns a tuple (length, skip) where skip is number of bytes read'''
    length = 0
    skip = 0
    try:
        data_length = int(blob[0])
        length = data_length & 0x7F
        while data_length > 0x7F:
            skip += 1
            data_length = int(blob[skip])
            length = ((data_length & 0x7F) << (skip * 7)) + length
    except (IndexError, ValueError):
        log.exception('Error trying to read length field in note data blob')
    skip += 1
    return length, skip

def ProcessNoteBodyBlob(blob):
    data = b''
    if blob == None: return data
    try:
        pos = 0
        if blob[0:3] != b'\x08\x00\x12': # header
            log.error('Unexpected bytes in header pos 0 - ' + binascii.hexlify(blob[0:3]) + '  Expected 080012')
            return ''
        pos += 3
        length, skip = ReadLengthField(blob[pos:])
        pos += skip

        if blob[pos:pos+3] != b'\x08\x00\x10': # header 2
            log.error('Unexpected bytes in header pos {0}:{0}+3'.format(pos))
            return '' 
        pos += 3
        length, skip = ReadLengthField(blob[pos:])
        pos += skip

        # Now text data begins
        if blob[pos] != 0x1A:
            log.error('Unexpected byte in text header pos {} - byte is 0x{:X}'.format(pos, blob[pos]))
            return ''
        pos += 1
        length, skip = ReadLengthField(blob[pos:])
        pos += skip
        # Read text tag next
        if blob[pos] != 0x12:
            log.error('Unexpected byte in pos {} - byte is 0x{:X}'.format(pos, blob[pos]))
            return ''
        pos += 1
        length, skip = ReadLengthField(blob[pos:])
        pos += skip
        data = blob[pos : pos + length].decode('utf-8')
        # Skipping the formatting Tags
    except (IndexError, ValueError):
        log.exception('Error processing note data blob')
    return data

def ReadNotesHighSierra(db, notes, source, user):
    '''Read Notestore.sqlite'''
    try:
        query = " SELECT n.Z_PK, n.ZNOTE as note_id, n.ZDATA as data, " \
                " c3.ZFILESIZE, "\
                " c4.ZFILENAME, c4.ZIDENTIFIER as att_uuid,  "\
                " c1.ZTITLE1 as title, c1.ZSNIPPET as snippet, c1.ZIDENTIFIER as noteID, "\
                " c1.ZCREATIONDATE1 as created, c1.ZLASTVIEWEDMODIFICATIONDATE, c1.ZMODIFICATIONDATE1 as modified, "\
                " c2.ZACCOUNT3, c2.ZTITLE2 as folderName, c2.ZIDENTIFIER as folderID, "\
                " c5.ZNAME as acc_name, c5.ZIDENTIFIER as acc_identifier, c5.ZACCOUNTTYPE "\
                " FROM ZICNOTEDATA as n "\
                " LEFT JOIN ZICCLOUDSYNCINGOBJECT as c1 ON c1.ZNOTEDATA = n.Z_PK  "\
                " LEFT JOIN ZICCLOUDSYNCINGOBJECT as c2 ON c2.Z_PK = c1.ZFOLDER "\
                " LEFT JOIN ZICCLOUDSYNCINGOBJECT as c3 ON c3.ZNOTE= n.ZNOTE "\
                " LEFT JOIN ZICCLOUDSYNCINGOBJECT as c4 ON c4.ZATTACHMENT1= c3.Z_PK "\
                " LEFT JOIN ZICCLOUDSYNCINGOBJECT as c5 ON c5.Z_PK = c1.ZACCOUNT2  "\
                " ORDER BY note_id  "
        db.row_factory = sqlite3.Row
        cursor = db.execute(query)
        for row in cursor:
            try:
                att_path = ''
                if row['att_uuid'] != None:
                    if user:
                        att_path = '/Users/' + user + '/Library/Group Containers/group.com.apple.notes/Media/' + row['att_uuid'] + '/' + row['ZFILENAME']
                    else:
                        att_path = 'Media/' + row['att_uuid'] + '/' + row['ZFILENAME']
                data = GetUncompressedData(row['data'])
                text_content = ProcessNoteBodyBlob(data)
                note = Note(row['note_id'], row['folderName'], row['title'], row['snippet'], text_content, row['att_uuid'], att_path,
                            row['acc_name'], row['acc_identifier'], '', 
                            CommonFunctions.ReadMacAbsoluteTime(row['created']), CommonFunctions.ReadMacAbsoluteTime(row['modified']),
                            'NoteStore', user, source)
                notes.append(note)
            except sqlite3.Error:
                log.exception('Error fetching row data')
    except sqlite3.Error:
        log.exception('Query  execution failed. Query was: ' + query)

def IsHighSierraDb(db):
    '''Returns false if Z_xxNOTE is a table where xx is a number'''
    try:
        cursor = db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE '%NOTE%'")
        for row in cursor:
            if row[0].startswith('Z_') and row[0].endswith('NOTES'):
                return False
    except sqlite3.Error as ex:
        log.error ("Failed to list tables of db. Error Details:{}".format(str(ex)) )
    return True

def ExecuteQuery(db, query):
    '''Run query, return tuple (cursor, error_message)'''
    try:
        db.row_factory = sqlite3.Row
        cursor = db.execute(query)
        return cursor, ""
    except sqlite3.Error as ex:
        error = str(ex)
        #log.debug('Exception:{}'.format(error))
    return None, error

def ReadNotes(db, notes, source, user):
    '''Read Notestore.sqlite'''
    if IsHighSierraDb(db):
        ReadNotesHighSierra(db, notes, source, user)
        return

    query1 = " SELECT n.Z_12FOLDERS as folder_id , n.Z_9NOTES as note_id, d.ZDATA as data, " \
            " c2.ZTITLE2 as folder, c2.ZDATEFORLASTTITLEMODIFICATION as folder_title_modified, " \
            " c1.ZCREATIONDATE as created, c1.ZMODIFICATIONDATE1 as modified, c1.ZSNIPPET as snippet, c1.ZTITLE1 as title, c1.ZACCOUNT2 as acc_id, " \
            " c5.ZACCOUNTTYPE as acc_type, c5.ZIDENTIFIER as acc_identifier, c5.ZNAME as acc_name, " \
            " c3.ZMEDIA as media_id, c3.ZFILESIZE as att_filesize, c3.ZMODIFICATIONDATE as att_modified, c3.ZPREVIEWUPDATEDATE as att_previewed, c3.ZTITLE as att_title, c3.ZTYPEUTI, c3.ZIDENTIFIER as att_uuid, " \
            " c4.ZFILENAME, c4.ZIDENTIFIER as media_uuid " \
            " FROM Z_12NOTES as n " \
            " LEFT JOIN ZICNOTEDATA as d ON d.ZNOTE = n.Z_9NOTES " \
            " LEFT JOIN ZICCLOUDSYNCINGOBJECT as c1 ON c1.Z_PK = n.Z_9NOTES " \
            " LEFT JOIN ZICCLOUDSYNCINGOBJECT as c2 ON c2.Z_PK = n.Z_12FOLDERS " \
            " LEFT JOIN ZICCLOUDSYNCINGOBJECT as c3 ON c3.ZNOTE = n.Z_9NOTES " \
            " LEFT JOIN ZICCLOUDSYNCINGOBJECT as c4 ON c3.ZMEDIA = c4.Z_PK " \
            " LEFT JOIN ZICCLOUDSYNCINGOBJECT as c5 ON c5.Z_PK = c1.ZACCOUNT2 " \
            " ORDER BY note_id "
    query2 = " SELECT n.Z_11FOLDERS as folder_id , n.Z_8NOTES as note_id, d.ZDATA as data, " \
            " c2.ZTITLE2 as folder, c2.ZDATEFORLASTTITLEMODIFICATION as folder_title_modified, " \
            " c1.ZCREATIONDATE as created, c1.ZMODIFICATIONDATE1 as modified, c1.ZSNIPPET as snippet, c1.ZTITLE1 as title, c1.ZACCOUNT2 as acc_id, " \
            " c5.ZACCOUNTTYPE as acc_type, c5.ZIDENTIFIER as acc_identifier, c5.ZNAME as acc_name, " \
            " c3.ZMEDIA as media_id, c3.ZFILESIZE as att_filesize, c3.ZMODIFICATIONDATE as att_modified, c3.ZPREVIEWUPDATEDATE as att_previewed, c3.ZTITLE as att_title, c3.ZTYPEUTI, c3.ZIDENTIFIER as att_uuid, " \
            " c4.ZFILENAME, c4.ZIDENTIFIER as media_uuid " \
            " FROM Z_11NOTES as n " \
            " LEFT JOIN ZICNOTEDATA as d ON d.ZNOTE = n.Z_8NOTES " \
            " LEFT JOIN ZICCLOUDSYNCINGOBJECT as c1 ON c1.Z_PK = n.Z_8NOTES " \
            " LEFT JOIN ZICCLOUDSYNCINGOBJECT as c2 ON c2.Z_PK = n.Z_11FOLDERS " \
            " LEFT JOIN ZICCLOUDSYNCINGOBJECT as c3 ON c3.ZNOTE = n.Z_8NOTES " \
            " LEFT JOIN ZICCLOUDSYNCINGOBJECT as c4 ON c3.ZMEDIA = c4.Z_PK " \
            " LEFT JOIN ZICCLOUDSYNCINGOBJECT as c5 ON c5.Z_PK = c1.ZACCOUNT2 " \
            " ORDER BY note_id "
    cursor, error1 = ExecuteQuery(db, query1)
    if cursor:
        ReadQueryResults(cursor, notes, user, source)
    else: # Try query2
        cursor, error2 = ExecuteQuery(db, query2)
        if cursor:
            ReadQueryResults(cursor, notes, user, source)
        else:
            log.error('Query execution failed.\n Query 1 error: {}\n Query 2 error: {}'.format(error1, error2))

def ReadQueryResults(cursor, notes, user, source):
    for row in cursor:
        try:
            att_path = ''
            if row['media_id'] != None:
                att_path = row['ZFILENAME']
            data = GetUncompressedData(row['data'])
            text_content = ProcessNoteBodyBlob(data)
            note = Note(row['note_id'], row['folder'], row['title'], row['snippet'], text_content, row['att_uuid'], att_path,
                        row['acc_name'], row['acc_identifier'], '', 
                        CommonFunctions.ReadMacAbsoluteTime(row['created']), CommonFunctions.ReadMacAbsoluteTime(row['modified']),
                        'NoteStore', user, source)
            notes.append(note)
        except sqlite3.Error:
            log.exception('Error fetching row data')

def OpenDb(inputPath):
    log.info ("Processing file " + inputPath)
    try:
        conn = sqlite3.connect(inputPath)
        log.debug ("Opened database successfully")
        return conn
    except sqlite3.Error:
        log.exception ("Failed to open database, is it a valid Notes DB?")
    return None

def OpenDbFromImage(mac_info, inputPath, user):
    '''Returns tuple of (connection, wrapper_obj)'''
    log.info ("Processing notes for user '{}' from file {}".format(user, inputPath))
    try:
        sqlite = SqliteWrapper(mac_info)
        conn = sqlite.connect(inputPath)
        log.debug ("Opened database successfully")
        return conn, sqlite
    except sqlite3.Error:
        log.exception ("Failed to open database, is it a valid Notes DB?")
    return None

def ProcessNotesDbFromPath(mac_info, notes, source_path, user, version=''):
    if mac_info.IsValidFilePath(source_path):
        mac_info.ExportFile(source_path, __Plugin_Name, user + "_")
        db, wrapper = OpenDbFromImage(mac_info, source_path, user)
        if db != None:
            if version:
                ReadNotesV2_V4_V6(db, notes, version, source_path, user)
            else:
                ReadNotes(db, notes, source_path, user)
            db.close()

def Plugin_Start(mac_info):
    '''Main Entry point function for plugin'''
    notes = []
    notes_v1_path = '{}/Library/Containers/com.apple.Notes/Data/Library/Notes/NotesV1.storedata' # Mountain Lion
    notes_v2_path = '{}/Library/Containers/com.apple.Notes/Data/Library/Notes/NotesV2.storedata' # Mavericks
    notes_v4_path = '{}/Library/Containers/com.apple.Notes/Data/Library/Notes/NotesV4.storedata' # Yosemite
    notes_v6_path = '{}/Library/Containers/com.apple.Notes/Data/Library/Notes/NotesV6.storedata' # Elcapitan & Sierra
    notes_v7_path = '{}/Library/Containers/com.apple.Notes/Data/Library/Notes/NotesV7.storedata' # HighSierra
    notes_path    = '{}/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite'         # Elcapitan+ has this too!

    for user in mac_info.users:
        if user.home_dir == '/private/var/empty': continue # Optimization, nothing should be here!
        source_path = notes_v1_path.format(user.home_dir)
        ProcessNotesDbFromPath(mac_info, notes, source_path, user.user_name, 'V1')

        source_path = notes_v2_path.format(user.home_dir)
        ProcessNotesDbFromPath(mac_info, notes, source_path, user.user_name, 'V2')

        source_path = notes_v4_path.format(user.home_dir)
        ProcessNotesDbFromPath(mac_info, notes, source_path, user.user_name, 'V4')

        source_path = notes_v6_path.format(user.home_dir)
        ProcessNotesDbFromPath(mac_info, notes, source_path, user.user_name, 'V6')

        source_path = notes_v7_path.format(user.home_dir)
        ProcessNotesDbFromPath(mac_info, notes, source_path, user.user_name, 'V7')

        source_path = notes_path.format(user.home_dir)
        ProcessNotesDbFromPath(mac_info, notes, source_path, user.user_name)

    if len(notes) > 0:
        PrintAll(notes, mac_info.output_params)
    else:
        log.info('No notes found')

def Plugin_Start_Standalone(input_files_list, output_params):
    log.info("Module Started as standalone")
    for input_path in input_files_list:
        log.debug("Input file passed was: " + input_path)
        notes = []
        db = OpenDb(input_path)
        if db != None:
            filename = os.path.basename(input_path)
            if filename.find('V2') > 0:
                ReadNotesV2_V4_V6(db, notes, 'V2', input_path, '')
            elif filename.find('V1') > 0:
                ReadNotesV2_V4_V6(db, notes, 'V1', input_path, '')
            elif filename.find('V4') > 0:
                ReadNotesV2_V4_V6(db, notes, 'V4', input_path, '')
            elif filename.find('V6') > 0:
                ReadNotesV2_V4_V6(db, notes, 'V6', input_path, '')
            elif filename.find('V7') > 0:
                ReadNotesV2_V4_V6(db, notes, 'V7', input_path, '')
            elif filename.find('NoteStore') >= 0:
                ReadNotes(db, notes, input_path, '')
            else:
                log.info('Unknown database type, not a recognized file name')
            db.close()
        if len(notes) > 0:
            PrintAll(notes, output_params)
        else:
            log.info('No notes found in {}'.format(input_path))

if __name__ == '__main__':
    print ("This plugin is a part of a framework and does not run independently on its own!")
