'''
   Copyright (c) 2017 Yogesh Khatri 

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the 
   terms of the MIT License.

   notes.py
   ---------------
   This plugin will read the 'Notes' databases from osx.

   #TODO:
   Create better output, html in xl is not readable.
'''
from __future__ import print_function
#from __future__ import unicode_literals # Must disable for sqlite.row_factory

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
__Plugin_Version = "1.0"
__Plugin_Description = "Reads Notes databases"
__Plugin_Author = "Yogesh Khatri"
__Plugin_Author_Email = "yogesh@swiftforensics.com"

__Plugin_Standalone = True
__Plugin_Standalone_Usage = 'Read Notes databases'

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
        except:
            log.exception('Could not fetch attachment path from plist')
    except (InvalidPlistException, NotBinaryPlistException, Exception) as e:
        log.error ("Invalid plist in table." + str(e) )
    return ''

def GetUncompressedData(compressed):
    if compressed == None:
        return None
    data = None
    try:
        data = zlib.decompress(compressed, 15 + 32)
    except:
        log.exception('Zlib Decompression failed!')
    return data

def ReadNotesV2_V4_V6(db, notes, version, source, user):
    '''Reads NotesV2.storedata, NotesV4.storedata, NotesV6.storedata'''
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
            except:
                log.exception('Error fetching row data')
    except:
        log.exception('Query  execution failed. Query was: ' + query)

def ReadLengthField(blob):
    '''Returns a tuple (length, skip) where skip is number of bytes read'''
    length = 0
    skip = 0
    try:
        data_length = int(struct.unpack('<B', blob[0])[0])
        if data_length > 0x7F: # -ve number for signed byte
            skip = 2
            length = (int(struct.unpack('<B', blob[1])[0]) << 7) + (data_length & 0x7F)
        else:
            skip = 1
            length = data_length
    except:
        log.exception('Error trying to read length field in note data blob')    
    return length, skip

def ProcessNoteBodyBlob(blob):
    data = ''
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
        if blob[pos] != b'\x1A':
            log.error('Unexpected byte in text header pos {} - byte is {}'.format(pos, binascii.hexlify(blob[pos])))
            return ''
        pos += 1
        length, skip = ReadLengthField(blob[pos:])
        pos += skip
        # Read text tag next
        if blob[pos] != b'\x12':
            log.error('Unexpected byte in pos {} - byte is {}'.format(pos, binascii.hexlify(blob[pos])))
            return ''
        pos += 1
        length, skip = ReadLengthField(blob[pos:])
        pos += skip
        data = blob[pos : pos + length].decode('utf-8')
        # Skipping the formatting Tags
    except:
        log.exception('Error processing note data blob')
    return data

def ReadNotes(db, notes, source, user):
    '''Read Notestore.sqlite'''
    try:
        query = " SELECT n.Z_12FOLDERS as folder_id , n.Z_9NOTES as note_id, d.ZDATA as data, " \
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
        db.row_factory = sqlite3.Row
        cursor = db.execute(query)
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
            except:
                log.exception('Error fetching row data')
    except:
        log.exception('Query  execution failed. Query was: ' + query)

def OpenDb(inputPath):
    log.info ("Processing file " + inputPath)
    try:
        conn = sqlite3.connect(inputPath)
        log.debug ("Opened database successfully")
        return conn
    except Exception as ex:
        log.error ("Failed to open database, is it a valid Notification DB? \nError details: " + str(ex.args))
    return None

def OpenDbFromImage(mac_info, inputPath, user):
    log.info ("Processing notifications for user '{}' from file {}".format(user, inputPath))
    try:
        sqlite = SqliteWrapper(mac_info)
        conn = sqlite.connect(inputPath)
        log.debug ("Opened database successfully")
        return conn
    except Exception as ex:
        log.error ("Failed to open database, is it a valid Notification DB? Error details: " + str(ex)) 
    return None

def ProcessNotesDbFromPath(mac_info, notes, source_path, user, version=''):
    if mac_info.IsValidFilePath(source_path):
        mac_info.ExportFile(source_path, __Plugin_Name, user + "_")
        db = OpenDbFromImage(mac_info, source_path, user)
        if db != None:
            if version:
                ReadNotesV2_V4_V6(db, notes, version, source_path, user)
            else:
                ReadNotes(db, notes, source_path, user)
            db.close()

def Plugin_Start(mac_info):
    '''Main Entry point function for plugin'''
    notes = []
    notes_v2_path = '{}/Library/Containers/com.apple.Notes/Data/Library/Notes/NotesV2.storedata' # Mavericks
    notes_v4_path = '{}/Library/Containers/com.apple.Notes/Data/Library/Notes/NotesV4.storedata' # Yosemite
    notes_v6_path = '{}/Library/Containers/com.apple.Notes/Data/Library/Notes/NotesV6.storedata' # Elcapitan
    notes_path    = '{}/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite'         # Elcapitan has this too!

    for user in mac_info.users:
        if user.home_dir == '/private/var/empty': continue # Optimization, nothing should be here!
        source_path = notes_v2_path.format(user.home_dir)
        ProcessNotesDbFromPath(mac_info, notes, source_path, user.user_name, 'V2')

        source_path = notes_v4_path.format(user.home_dir)
        ProcessNotesDbFromPath(mac_info, notes, source_path, user.user_name, 'V4')

        source_path = notes_v6_path.format(user.home_dir)
        ProcessNotesDbFromPath(mac_info, notes, source_path, user.user_name, 'V6')

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
            elif filename.find('V4') > 0:
                ReadNotesV2_V4_V6(db, notes, 'V4', input_path, '')
            elif filename.find('V6') > 0:
                ReadNotesV2_V4_V6(db, notes, 'V6', input_path, '')
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