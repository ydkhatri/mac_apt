'''
   Copyright (c) 2019 Yogesh Khatri

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the
   terms of the MIT License.

'''

from plugins.helpers.macinfo import *
from plugins.helpers.writer import *
from plugins.helpers.common import *
import os
import sqlite3
import logging

__Plugin_Name = "EVERNOTE"
__Plugin_Friendly_Name = "EverNote Data"
__Plugin_Version = "1.0"
__Plugin_Description = "Parses EverNote data"
__Plugin_Author = "Jack Farley"
__Plugin_Author_Email = "jfarley248@gmail.com"

__Plugin_Modes = "IOS,MACOS,ARTIFACTONLY"
__Plugin_ArtifactOnly_Usage = 'Provide the folder coming from: /Users/USER/Library/Group Containers/' \
                              'Q79WDW8YH9.com.evernote.Evernote/CoreNote/accounts/www.evernote.com/XXXXXXX' \
                              '' \
                              'The XXXXX Folder is the folder you will pass to mac apt. This folder contains folders such as:' \
                              'content, chunks, localNoteStore, etc'

log = logging.getLogger('MAIN.' + __Plugin_Name) # Do not rename or remove this ! This is the logger object

#---- Do not change the variable names in above section ----#


EVERNOTE_QUERY = "SELECT " \
        "zn.ZTITLE as note_name, " \
        "datetime(strftime(zn.ZDATECREATED + 978307200), 'unixepoch') as creation_date, " \
        "datetime(strftime(zn.ZDATEUPDATED + 978307200), 'unixepoch') as update_date, " \
        "zn.ZAUTHOR as author, " \
        "zn.ZOSXGEOLOCATIONNAME as location, " \
        "zn.ZSOURCE as source_machine, " \
        "zn.ZLOCALUUID as note_folder_uuid, " \
        "zn.ZSOURCEURL as source_url, " \
        "znb.ZNAME as parent_notebook " \
        "FROM " \
        "ZENNOTE as zn " \
        "LEFT JOIN ZENNOTEBOOK as znb WHERE znb.Z_PK = zn.ZNOTEBOOK " \



class EverNote:
    def __init__(self, note_name, creation_date, update_date, author, location, note_snippet, source_machine, note_folder_uuid,
                 source_url, parent_notebook, user, source):
        self.note_name = note_name
        self.creation_date = creation_date
        self.update_date = update_date
        self.author = author
        self.location = location
        self.note_snippet = note_snippet
        self.source_machine = source_machine
        self.note_folder_uuid = note_folder_uuid
        self.source_url= source_url
        self.parent_notebook = parent_notebook
        self.user = user
        self.source = source

def PrintAllEverNote(evernote_data, output_params, source_path):
    evernote_info = [ ('Note_Name',DataType.TEXT),('Creation_Date',DataType.TEXT),('Update_Date',DataType.TEXT),
                       ('Author',DataType.TEXT),('Location',DataType.INTEGER), ('Note_Snippet',DataType.TEXT),
                      ('Source_Machine',DataType.INTEGER), ('Note_Folder_UUID',DataType.INTEGER),('Source_URL',DataType.TEXT),
                       ('Parent_Notebook', DataType.TEXT), ('User', DataType.TEXT),('Source',DataType.TEXT)
                     ]

    evernote_list = []
    for en in evernote_data:
        en_items = [en.note_name, en.creation_date, en.update_date,
                      en.author,
                      en.location, en.note_snippet,
                      en.source_machine, en.note_folder_uuid, en.source_url,
                      en.parent_notebook, en.user, en.source
                     ]
        evernote_list.append(en_items)
    WriteList("EverNote Notes", "EverNote", evernote_list, evernote_info, output_params, source_path)


class EverNoteNotebook:
    def __init__(self, notebook_name, notes_in_notebook, creation_date,  last_updated_note, location, user, source):
        self.notebook_name = notebook_name
        self.notes_in_notebook = notes_in_notebook
        self.creation_date = creation_date
        self.last_updated_note = last_updated_note
        self.location = location
        self.user = user
        self.source = source



def PrintAllEverNoteNotebook(evernote_data, output_params, source_path):
    evernote_info = [ ('Notebook_Name',DataType.TEXT),('Notes_in_Notebook',DataType.TEXT),('Creation_Date',DataType.TEXT),
                       ('Last_Updated_Note',DataType.TEXT),('Location',DataType.INTEGER), ('User',DataType.INTEGER),
                       ('Source',DataType.INTEGER)
                     ]

    evernote_list = []
    for en in evernote_data:
        en_items = [en.notebook_name, en.creation_date, en.creation_date,
                      en.last_updated_note,
                      en.location, en.user, en.source
                     ]
        evernote_list.append(en_items)
    WriteList("EverNote Notebooks", "EverNote", evernote_list, evernote_info, output_params, source_path)

def OpenDbFromImage(mac_info, inputPath):
    '''Returns tuple of (connection, wrapper_obj)'''
    try:
        sqlite = SqliteWrapper(mac_info)
        conn = sqlite.connect(inputPath)
        log.debug ("Opened database successfully")
        return conn, sqlite
    except sqlite3.Error as ex:
        log.exception ("Failed to open database, is it a valid Screen Time DB?")
    return None

def OpenDb(inputPath):
    log.info ("Processing file " + inputPath)
    try:
        conn = sqlite3.connect(inputPath)
        log.debug ("Opened database successfully")
        return conn
    except sqlite3.Error:
        log.exception ("Failed to open database, is it a valid Screen Time DB?")
    return None


def findEverNoteDir(mac_info, evernote_folder_user):
    """

    :param mac_info: mac_info object
    :param evernote_folder_user: User folder to search for the evernote folder in: /Users/USER/Library/Group Containers/
    :return: evernote_folder_user attached with subfolder of evernote
    """

    evernote_folder = ''

    sub_dirs = mac_info.ListItemsInFolder(evernote_folder_user)
    for sub_dir in sub_dirs:
        if "com.evernote.Evernote" in sub_dir['name']:

            evernote_folder += evernote_folder_user + sub_dir['name'] + "/CoreNote/accounts/www.evernote.com"
            sub_dirs = mac_info.ListItemsInFolder(evernote_folder)
            for item in sub_dirs:
                if mac_info.IsValidFolderPath(evernote_folder + "/" + item["name"]):
                    evernote_folder += "/" + item["name"]

                    if mac_info.IsValidFolderPath(evernote_folder):
                        return evernote_folder
    else:
        return None

def ExtractNoteFiles(mac_info, note_name, note_dir):
    pass

def FindNoteSnippet(mac_info, evernote_dir, note_folder_uuid):
    """

    :param mac_info: mac_info object
    :param evernote_dir: The directory that conatins evernote data
    :return: Text data containing the evernote note snippet
    """

    specific_note_folder = evernote_dir + "/content/" + note_folder_uuid
    if not mac_info.IsValidFolderPath(specific_note_folder):
        log.info("No note snippet found for note with UUID: " + note_folder_uuid)
        return ""


    snippet_file_path = specific_note_folder + "/snippet.txt"
    snippet_text = mac_info.open(snippet_file_path).read()
    return snippet_text


def process_evernotes_standalone(db, evernotes, evernote_dir, user, source):
    pass


def process_evernotes(mac_info, evernotes, evernote_dir, user_name):
    """

    :param mac_info: mac_info object
    :param evernotes: Empty array for putting in Evernote objects
    :param evernote_dir: Directory containing the database
    :param user_name: The username of the user for data output
    :return:
    """




    evernote_db = evernote_dir  + "/localNoteStore/LocalNoteStore.sqlite"
    if not mac_info.IsValidFilePath(evernote_db):
        log.info("No EverNote database found")
        return
    log.debug("EverNote database found")

    db, wrapper = OpenDbFromImage(mac_info, evernote_db)
    if db is None:
        return
    db.row_factory = sqlite3.Row
    cursor = db.execute(EVERNOTE_QUERY)

    for row in cursor:

        note_folder_uuid = row['note_folder_uuid']
        note_snippet = FindNoteSnippet(mac_info, evernote_dir, note_folder_uuid)

        note_name = row['note_name']
        creation_date = row['creation_date']
        update_date = row['update_date']
        author = row['author']
        location = row['location']
        source_machine = row['source_machine']
        note_folder_uuid = note_folder_uuid
        source_url = row['source_url']
        parent_notebook = row['parent_notebook']


        en = EverNote(note_name,
                      creation_date,
                      update_date,
                      author,
                      location,
                      note_snippet,
                      source_machine,
                      note_folder_uuid,
                      source_url,
                      parent_notebook,
                      user_name,
                      evernote_db)

        evernotes.append(en)

    db.close()

def process_evernote_notebooks(mac_info, evernote_notebooks, evernote_root_dir, user_name):
    pass

def Plugin_Start(mac_info):
    '''Main Entry point function for plugin'''
    evernote_folder = '{}/Library/Group Containers/'
    processed_paths = []
    evernotes = []
    evernote_notebooks = []
    for user in mac_info.users:
        user_name = user.user_name
        if user.home_dir == '/private/var': continue # Optimization, nothing should be here!
        elif user.home_dir == '/private/var/root': user_name = 'root' # Some other users use the same root folder, we will list such all users as 'root', as there is no way to tell
        if user.home_dir in processed_paths: continue # Avoid processing same folder twice (some users have same folder! (Eg: root & daemon))
        processed_paths.append(user.home_dir)
        evernote_folder_user = evernote_folder.format(user.home_dir)
        evernote_root_dir = findEverNoteDir(mac_info, evernote_folder_user)
        if evernote_root_dir is not None and mac_info.IsValidFolderPath(evernote_root_dir):
            process_evernotes(mac_info, evernotes, evernote_root_dir, user_name)
            process_evernote_notebooks(mac_info, evernote_notebooks, evernote_root_dir, user_name)
    if evernotes:
        PrintAllEverNote(evernotes, mac_info.output_params, '')

    if evernote_notebooks:
        PrintAllEverNoteNotebook(evernote_notebooks, mac_info.output_params, '')
    else:
        log.info("No EverNote data found.")



def Plugin_Start_Standalone(input_folder, output_params):
    log.info("Module Started as standalone")

    log.debug("Input folder passed was: " + input_folder)
    evernotes = []
    evernote_notebooks = []
    db_file = input_folder + "\\localNoteStore\\LocalNoteStore.sqlite"
    db = OpenDb(db_file)
    if db != None:
        process_evernotes_standalone(db, evernotes, input_folder, "", db_file)
    if evernotes:
        PrintAllEverNote(evernotes, output_params, '')
    else:
        log.info("No imessages found.")