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

import binascii
import logging
import os
import sqlite3
import zlib

from io import BytesIO
from plugins.helpers.common import CommonFunctions
from plugins.helpers.macinfo import *
from plugins.helpers.writer import *

__Plugin_Name = "NOTES"
__Plugin_Friendly_Name = "Notes"
__Plugin_Version = "1.3"
__Plugin_Description = "Reads Notes databases"
__Plugin_Author = "Yogesh Khatri"
__Plugin_Author_Email = "yogesh@swiftforensics.com"

__Plugin_Modes = "MACOS,ARTIFACTONLY,IOS"
__Plugin_ArtifactOnly_Usage = 'Provide one or more Notes sqlite databases as input to process. These are typically '\
                            'located at ~/Library/Containers/com.apple.Notes/Data/Library/Notes/  or '\
                            '~/Library/Group Containers/group.com.apple.notes/'

log = logging.getLogger('MAIN.' + __Plugin_Name) # Do not rename or remove this ! This is the logger object

#---- Do not change the variable names in above section ----#

class Note:

    def __init__(self, id, folder, title, snippet, data, att_id, att_path, acc_desc, acc_identifier, acc_username, \
                created, edited, version, encrypted, pw_hint, user, source, embed_type='', embed_summary='', embed_url='', embed_title=''):
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
        self.encrypted = encrypted
        self.password_hint = pw_hint
        self.user = user
        self.source_file = source
        #self.folder_title_modified = folder_title_modified
        self.embed_type = embed_type
        self.embed_summary = embed_summary
        self.embed_url = embed_url
        self.embed_title = embed_title

def PrintAll(notes, output_params):

    note_info = [ ('ID',DataType.INTEGER),('Title',DataType.TEXT),('Snippet',DataType.TEXT),('Folder',DataType.TEXT),
                    ('Created',DataType.DATE),('LastModified',DataType.DATE),
                    ('Encrypted',DataType.INTEGER),('Password Hint', DataType.TEXT),('Data', DataType.TEXT),
                    ('AttachmentID',DataType.TEXT),('AttachmentPath',DataType.TEXT),
                    ('EmbedType',DataType.TEXT),('EmbedSummary',DataType.TEXT),('EmbedURL',DataType.TEXT),('EmbedTitle',DataType.TEXT),
                    ('AccountDescription',DataType.TEXT),('AccountIdentifier', DataType.TEXT),('AccountUsername', DataType.TEXT),
                    ('Version', DataType.TEXT),('User', DataType.TEXT),('Source',DataType.TEXT)
                ]

    log.info (str(len(notes)) + " note(s) found")
    notes_list = []
    for note in notes:
        note_items = [note.note_id, note.title, note.snippet, note.folder, 
                      note.date_created, note.date_edited, 
                      note.encrypted, note.password_hint, note.data,
                      note.attachment_id, note.attachment_path, 
                      note.embed_type, note.embed_summary, note.embed_url, note.embed_title,
                      note.account, note.account_identifier, note.account_username, 
                      note.version, note.user, note.source_file
                     ]
        notes_list.append(note_items)
    WriteList("note information", "Notes", notes_list, note_info, output_params, '')

def ReadAttPathFromPlist(plist_blob):
    '''For NotesV2, read plist and get path'''
    f = BytesIO(plist_blob)
    success, plist, error = CommonFunctions.ReadPlist(f)
    if success:
        try:
            path = plist['$objects'][2]
            return CommonFunctions.url_decode(path)
        except (KeyError, IndexError):
            log.exception('Could not fetch attachment path from plist')
    else:
        log.error("Invalid plist in table. " + error)
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
                            version, 0, '', user, source)
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
        data = blob[pos : pos + length].decode('utf-8', 'backslashreplace')
        # Skipping the formatting Tags
    except (IndexError, ValueError):
        log.exception('Error processing note data blob')
    return data

def ReadNotesHighSierraAndAbove(db, notes, source, user, is_ios):
    '''Read Notestore.sqlite'''
    
    try:
        query_1 = \
        """
        SELECT n.Z_PK, n.ZNOTE as note_id, n.ZDATA as data, c1.ZISPASSWORDPROTECTED as encrypted, c1.ZPASSWORDHINT, 
        c3.ZFILESIZE, c4.ZFILENAME, c4.ZIDENTIFIER as att_uuid, c4.ZGENERATION1,
        c1.ZTITLE1 as title, c1.ZSNIPPET as snippet, c1.ZIDENTIFIER as noteID, 
        c1.ZCREATIONDATE1 as created, c1.ZLASTVIEWEDMODIFICATIONDATE, c1.ZMODIFICATIONDATE1 as modified,
        c2.ZACCOUNT3, c2.ZTITLE2 as folderName, c2.ZIDENTIFIER as folderID, 
        c5.ZNAME as acc_name, c5.ZIDENTIFIER as acc_identifier, c5.ZACCOUNTTYPE, 
        c3.ZSUMMARY, c3.ZTITLE, c3.ZURLSTRING, c3.ZTYPEUTI  FROM ZICNOTEDATA as n 
        LEFT JOIN ZICCLOUDSYNCINGOBJECT as c1 ON c1.ZNOTEDATA = n.Z_PK 
        LEFT JOIN ZICCLOUDSYNCINGOBJECT as c2 ON c2.Z_PK = c1.ZFOLDER 
        LEFT JOIN ZICCLOUDSYNCINGOBJECT as c3 ON c3.ZNOTE= n.ZNOTE 
        LEFT JOIN ZICCLOUDSYNCINGOBJECT as c4 ON c4.ZATTACHMENT1= c3.Z_PK 
        LEFT JOIN ZICCLOUDSYNCINGOBJECT as c5 ON c5.Z_PK = c1.ZACCOUNT2 
        ORDER BY note_id
        """
        query_2 = \
        """
        SELECT n.Z_PK, n.ZNOTE as note_id, n.ZDATA as data, c1.ZISPASSWORDPROTECTED as encrypted, c1.ZPASSWORDHINT, 
        c3.ZFILESIZE, c4.ZFILENAME, c4.ZIDENTIFIER as att_uuid, c4.ZGENERATION1,
        c1.ZTITLE1 as title, c1.ZSNIPPET as snippet, c1.ZIDENTIFIER as noteID, 
        c1.ZCREATIONDATE1 as created, c1.ZLASTVIEWEDMODIFICATIONDATE, c1.ZMODIFICATIONDATE1 as modified,
        c2.ZACCOUNT4, c2.ZTITLE2 as folderName, c2.ZIDENTIFIER as folderID, 
        c5.ZNAME as acc_name, c5.ZIDENTIFIER as acc_identifier, c5.ZACCOUNTTYPE,  
        c3.ZSUMMARY, c3.ZTITLE, c3.ZURLSTRING, c3.ZTYPEUTI  FROM ZICNOTEDATA as n 
        LEFT JOIN ZICCLOUDSYNCINGOBJECT as c1 ON c1.ZNOTEDATA = n.Z_PK 
        LEFT JOIN ZICCLOUDSYNCINGOBJECT as c2 ON c2.Z_PK = c1.ZFOLDER 
        LEFT JOIN ZICCLOUDSYNCINGOBJECT as c3 ON c3.ZNOTE= n.ZNOTE 
        LEFT JOIN ZICCLOUDSYNCINGOBJECT as c4 ON c4.ZATTACHMENT1= c3.Z_PK 
        LEFT JOIN ZICCLOUDSYNCINGOBJECT as c5 ON c5.Z_PK = c1.ZACCOUNT3   
        ORDER BY note_id
        """
        if CommonFunctions.ColumnExists(db, 'ZICCLOUDSYNCINGOBJECT', 'ZACCOUNT4'):
            query = query_2
        else:
            query = query_1

        # ZACCOUNTTYPE - 1=iCloud, 3=local
        db.row_factory = sqlite3.Row
        cursor = db.execute(query)
        for row in cursor:
            try:
                att_path = ''
                if row['encrypted']:
                    text_content = ''
                    pw_hint = row['ZPASSWORDHINT']
                else:
                    pw_hint = ''
                    data = GetUncompressedData(row['data'])
                    text_content = ProcessNoteBodyBlob(data)
                if row['att_uuid'] != None:
                    try:
                        filename = row['ZFILENAME'] if row['ZFILENAME'] is not None else row['att_uuid']
                        if is_ios:
                            base_path, _ = os.path.split(source)
                            att_path = f'{base_path}/Accounts/{row['acc_identifier']}/Media/{row['att_uuid']}/{row['ZGENERATION1']}/{filename}'
                        elif user:
                            att_path = f'/Users/{user}/Library/Group Containers/group.com.apple.notes/Accounts/LocalAccount/Media/{row['att_uuid']}/{row['ZGENERATION1']}/{filename}'
                        else:
                            att_path = f'Accounts/LocalAccount/Media/{row['att_uuid']}/{row['ZGENERATION1']}/{filename}'
                    except TypeError as ex:
                        log.error('Error computing att path for row ' + str(row['note_id']) + ' Error was ' + str(ex))

                note = Note(row['note_id'], row['folderName'], row['title'], row['snippet'], text_content, row['att_uuid'], att_path,
                            row['acc_name'], row['acc_identifier'], '', 
                            CommonFunctions.ReadMacAbsoluteTime(row['created']), CommonFunctions.ReadMacAbsoluteTime(row['modified']),
                            'NoteStore', row['encrypted'], pw_hint, user, source, row['ZTYPEUTI'], row['ZSUMMARY'], row['ZURLSTRING'], row['ZTITLE'])
                notes.append(note)
            except sqlite3.Error:
                log.exception('Error fetching row data')
    except sqlite3.Error:
        log.exception('Query  execution failed. Query was: ' + query)

def IsHighSierraOrAboveDb(db):
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

def ReadNotes(db, notes, source, user, is_ios):
    '''Read Notestore.sqlite'''
    if IsHighSierraOrAboveDb(db):
        ReadNotesHighSierraAndAbove(db, notes, source, user, is_ios)
        return

    if CommonFunctions.ColumnExists(db, 'ZICCLOUDSYNCINGOBJECT', 'ZISPASSWORDPROTECTED'):
        enc_possible = True
    else:
        enc_possible = False

    query1 = " SELECT n.Z_12FOLDERS as folder_id , n.Z_9NOTES as note_id, d.ZDATA as data, " + ("c1.ZISPASSWORDPROTECTED as encrypted, c1.ZPASSWORDHINT, " if enc_possible else "") + \
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
    query2 = " SELECT n.Z_11FOLDERS as folder_id , n.Z_8NOTES as note_id, d.ZDATA as data, "  + ("c1.ZISPASSWORDPROTECTED as encrypted, c1.ZPASSWORDHINT, " if enc_possible else "") + \
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
        ReadQueryResults(cursor, notes, enc_possible, user, source)
    else: # Try query2
        cursor, error2 = ExecuteQuery(db, query2)
        if cursor:
            ReadQueryResults(cursor, notes, enc_possible, user, source)
        else:
            log.error('Query execution failed.\n Query 1 error: {}\n Query 2 error: {}'.format(error1, error2))

def ReadQueryResults(cursor, notes, enc_possible, user, source):
    for row in cursor:
        try:
            att_path = ''
            if row['media_id'] != None:
                att_path = row['ZFILENAME']
            if enc_possible and row['encrypted'] == 1:
                text_content = ''
                pw_hint = row['ZPASSWORDHINT']
            else:
                pw_hint = ''
                data = GetUncompressedData(row['data'])
                text_content = ProcessNoteBodyBlob(data)
            note = Note(row['note_id'], row['folder'], row['title'], row['snippet'], text_content, row['att_uuid'], att_path,
                        row['acc_name'], row['acc_identifier'], '', 
                        CommonFunctions.ReadMacAbsoluteTime(row['created']), CommonFunctions.ReadMacAbsoluteTime(row['modified']),
                        'NoteStore', row['encrypted'] if enc_possible else 0, pw_hint, user, source)
            notes.append(note)
        except sqlite3.Error:
            log.exception('Error fetching row data')

def OpenDb(inputPath):
    log.info ("Processing file " + inputPath)
    try:
        conn = CommonFunctions.open_sqlite_db_readonly(inputPath)
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
        if conn:
            log.debug ("Opened database successfully")
        return conn, sqlite
    except sqlite3.Error:
        log.exception ("Failed to open database, is it a valid Notes DB?")
    return None, None

def ProcessNotesDbFromPath(mac_info, notes, source_path, user, version='', is_ios=False):
    if mac_info.IsValidFilePath(source_path):
        mac_info.ExportFile(source_path, __Plugin_Name, user + "_")
        db, wrapper = OpenDbFromImage(mac_info, source_path, user)
        if db != None:
            if version:
                ReadNotesV2_V4_V6(db, notes, version, source_path, user)
            else:
                ReadNotes(db, notes, source_path, user, is_ios)
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
        ProcessNotesDbFromPath(mac_info, notes, source_path, user.user_name, '', False)

    if len(notes) > 0:
        PrintAll(notes, mac_info.output_params)
    else:
        log.info('No notes found')

def find_notes_folder(apps):
    for app in apps:
        if app.bundle_identifier == 'com.apple.mobilenotes':
            for container in app.app_group_containers:
                if container.id == 'group.com.apple.notes':
                    return container.path
    return ''

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
                ReadNotes(db, notes, input_path, '', False)
            else:
                log.info('Unknown database type, not a recognized file name')
            db.close()
        if len(notes) > 0:
            PrintAll(notes, output_params)
        else:
            log.info('No notes found in {}'.format(input_path))

def Plugin_Start_Ios(ios_info):
    '''Entry point for ios_apt plugin'''
    notes = []
    notes_folder = find_notes_folder(ios_info.apps)
    if notes_folder:
        source_path = notes_folder + '/NoteStore.sqlite'
        if ios_info.IsValidFilePath(source_path):
            ios_info.ExportFile(source_path, __Plugin_Name, '')
            ProcessNotesDbFromPath(ios_info, notes, source_path, 'mobile', '', True)
        else:
            log.error(f'DB not found - {source_path}')
    else:
        log.error('Could not find notes folder :(')

    if len(notes) > 0:
        PrintAll(notes, ios_info.output_params)
    else:
        log.info('No notes found')

if __name__ == '__main__':
    print ("This plugin is a part of a framework and does not run independently on its own!")
