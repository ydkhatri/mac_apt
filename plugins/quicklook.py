'''
   Copyright (c) 2019 Yogesh Khatri

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the
   terms of the MIT License.

'''

from plugins.helpers.macinfo import *
from plugins.helpers.writer import *
from plugins.helpers.common import *
import sqlite3
import logging
import os
from PIL import Image

__Plugin_Name = "QUICKLOOK" # Cannot have spaces, and must be all caps!
__Plugin_Friendly_Name = "QuickLook Thumbnail Cache"
__Plugin_Version = "1.0"
__Plugin_Description = "Parses QuickLook Thumbnail Cache data"
__Plugin_Author = "Jack Farley"
__Plugin_Author_Email = "jfarley248@gmail.com"

__Plugin_Standalone = True
__Plugin_Standalone_Usage = 'Provide QuickLook database found at:' \
                            '/private/var/folders/XX/XXXXXXXXXXXXXXXXXXX_XXXXXXXXX/' \
                            'C/com.apple.QuickLook.thumbnailcache/index.sqlite AS WELL AS: '\
                            '/private/var/folders/XX/XXXXXXXXXXXXXXXXXXX_XXXXXXXXX/thumbnails.data' \

log = logging.getLogger('MAIN.' + __Plugin_Name) # Do not rename or remove this ! This is the logger object

#---- Do not change the variable names in above section ----#

"""
This plugin was made using previously conducted research and scripting from Mari Degrazia and Dave:
https://github.com/mdegrazia/OSX-QuickLook-Parser
http://www.easymetadata.com/2015/01/sqlite-analysing-the-quicklook-database-in-macos/
"""

class QuickLook:
    def __init__(self, folder, file_name, hit_count, last_hit_date, version, bits_per_pixel, bitmapdata_location,
                 bitmapdata_length, width, height, fs_id, row_id, source):
        self.folder = folder
        self.file_name= file_name
        self.hit_count = hit_count
        self.last_hit_date = last_hit_date
        self.version = version
        self.bits_per_pixel = bits_per_pixel
        self.bitmapdata_location = bitmapdata_location
        self.bitmapdata_length = bitmapdata_length
        self.width = width
        self.height = height
        self.fs_id = fs_id
        self.row_id = row_id
        self.source = source


def PrintAll(quicklook_data, output_params, source_path):
    quicklook_info = [ ('Folder',DataType.TEXT),('File_Name',DataType.TEXT),('Hit_Count',DataType.TEXT),
                       ('Last_Hit_Date',DataType.TEXT), ('version',DataType.BLOB), ('Bits_per_Pixel',DataType.INTEGER), ('bitmap_data_location',DataType.INTEGER),
                       ('bitmap_data_length',DataType.INTEGER), ('Width',DataType.INTEGER), ('Height',DataType.INTEGER),
                       ('fs_id',DataType.TEXT), ('row_id',DataType.INTEGER), ('Source',DataType.TEXT)
                     ]

    quicklook_list = []
    for ql in quicklook_data:
        ql_items = [ql.folder, ql.file_name, ql.hit_count,
                      ql.last_hit_date, ql.version, ql.bits_per_pixel, ql.bitmapdata_location, ql.bitmapdata_length, ql.width,
                      ql.height, ql.fs_id, ql.row_id, ql.source
                     ]
        quicklook_list.append(ql_items)
    WriteList("QuickLook Info", "QuickLook", quicklook_list, quicklook_info, output_params, source_path)


def OpenDbFromImage(mac_info, inputPath):
    '''Returns tuple of (connection, wrapper_obj)'''
    try:
        sqlite = SqliteWrapper(mac_info)
        conn = sqlite.connect(inputPath)
        log.debug ("Opened database successfully")
        return conn, sqlite
    except sqlite3.Error as ex:
        log.exception ("Failed to open database, is it a valid QuickLook DB?")
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


def openSingle(path):
    """

    :param path: Path of file to open, use in standalone mode
    :return: handle to file
    """
    handle = open(path, "rb")
    return handle

def openDeadbox(path, mac_info):
    """

    :param path: Path in image to file
    :param mac_info: mac_info object
    :return: handle to file
    """
    handle = mac_info.OpenSmallFile(path)
    return handle

def carveThumbs(offset, length, thumbfile, thumbname, width, height, export):
    """

    :param offset: Offset in thumbnails.data for thumbnail
    :param length: Lenght of data to carve for thumbnail in thumbnails.data
    :param thumbfile: Source thumbnails.data file to carve from
    :param thumbname: Name of the file that has the thumbnail
    :param export: Either output directory in single plugin mode or mac_info object
    :return: Nothing
    """



    if length is not None:

        # Parse via mac_info
        if type(export) is not str:
            handle = openDeadbox(thumbfile, export)

        # Parse via single plugin
        else:
            handle = openSingle(thumbfile)

        # Seek and read thumbnails.data from offsets and lengths found in the index.sqlite
        handle.seek(offset)
        thumb = handle.read(length)
        handle.close()

        # Use the Pillow Library Image to parse and export files as images
        imgSize = (width, height)
        img = Image.frombytes('RGBA', imgSize, thumb, decoder_name='raw')

        # Parse via mac_info
        if type(export) is not str:
            export_folder = os.path.join(export.output_params.export_path, __Plugin_Name, "Thumbnails")

        # Parse via single plugin
        else:
            export_folder = os.path.join(export, __Plugin_Name, "Thumbnails")

        # Create output directory if doesn't exist
        if not os.path.exists(export_folder):
            os.makedirs(export_folder)

        # Set up output file with png extension attached
        export_file = os.path.join(export_folder, thumbname + ".png")

        img.save(export_file)


def parseDb(c, quicklook_array, source, path_to_thumbnails, export):
    """
    :param c: Connection to index.sqlite
    :param quicklook_array: Empty quicklook array to store QuickLook objects
    :param source: The source file being used, the full path to the index.sqlite
    :return: Nothing, fills the quicklook array
    """

    #Query from: https://github.com/mdegrazia/OSX-QuickLook-Parser
    thumbnail_query = """
    select distinct f_rowid,k.folder,k.file_name,k.version,t.hit_count,t.last_hit_date, t.bitsperpixel,
    t.bitmapdata_location,bitmapdata_length,t.width,t.height,datetime(t.last_hit_date + strftime("%s", "2001-01-01 00:00:00"), 
    "unixepoch") As [decoded-last_hit_date],fs_id from (select rowid as f_rowid,folder,file_name,fs_id,version from files) 
    k left join thumbnails t on t.file_id = k.f_rowid order by t.hit_count DESC
    """

    try:
        c.execute(thumbnail_query)
        data = c.fetchall()

        # Iterate through the rows returned by the above SQL statment and create QuickLook object based off it,
        # then appends to array
        for item in data:
            folder = item[1]
            file_name = item[2]
            hit_count = item[4]
            last_hit_date = item[11]
            version = item[3]
            bits_per_pixel = item[6]
            bitmapdata_location = item[7]
            bitmapdata_length = item[8]
            width = item[9]
            height = item[10]
            fs_id = item[12]
            row_id = item[0]


            ql = QuickLook(folder, file_name, hit_count, last_hit_date, version, bits_per_pixel, bitmapdata_location,
                           bitmapdata_length, width, height, fs_id, row_id, source)
            quicklook_array.append(ql)

            # Carve out thumbnails
            carveThumbs(bitmapdata_location, bitmapdata_length, path_to_thumbnails, file_name, width, height, export)

    # Catch SQLite3 exceptions
    except sqlite3.Error as e:
        log.exception("Exception while executing query for QuickLook cache. Exception was: " + str(e))


def findDb(mac_info):

    users_dir = mac_info.ListItemsInFolder('/private/var/folders', EntryType.FOLDERS)
    # In /private/var/folders/  --> Look for --> xx/yyyyyy/C/C/com.apple.QuickLook.thumbnailcache
    for unknown1 in users_dir:
        unknown1_name = unknown1['name']
        unknown1_dir = mac_info.ListItemsInFolder('/private/var/folders/' + unknown1_name, EntryType.FOLDERS)
        for unknown2 in unknown1_dir:
            unknown2_name = unknown2['name']
            found_home = False
            found_user = False
            home = ''
            # This is yyyyyy folder
            path_to_quicklook_db = '/private/var/folders/' + unknown1_name + '/' + unknown2_name + '/C/com.apple.QuickLook.thumbnailcache/index.sqlite'
            path_to_thumbnails = '/private/var/folders/' + unknown1_name + '/' + unknown2_name + '/C/com.apple.QuickLook.thumbnailcache/thumbnails.data'
            if mac_info.IsValidFilePath(path_to_quicklook_db) and mac_info.GetFileSize(path_to_quicklook_db) and mac_info.IsValidFilePath(path_to_thumbnails) and mac_info.GetFileSize(path_to_thumbnails):  # This does not always exist or it may be zero in size!
                return path_to_quicklook_db, path_to_thumbnails
            else:
                log.error("Quicklook DB or Thumbnail database not found")




def Plugin_Start(mac_info):
    '''Main Entry point function for plugin'''

    # Check for Mac OS version because QuickLook changes structure in 10.15
    os_minor_version = int(mac_info.osx_version[3:])
    if os_minor_version <= 14:

        # Array to store QuickLook objects
        quicklook_array = []

        # Finds QuickLook index.sqlite and the thumbnails.data
        path_to_quicklook_db, path_to_thumbnails = findDb(mac_info)

        # Export thumbnails.data file
        mac_info.ExportFile(path_to_thumbnails, __Plugin_Name)

        # If the index.sqlite exists, we then start parsing
        if path_to_quicklook_db:
            log.info("QuickLook Cache data found!")
            mac_info.ExportFile(path_to_quicklook_db, __Plugin_Name)

            # Opens index.sqlite
            quicklook_db, quicklook_wrapper = OpenDbFromImage(mac_info, path_to_quicklook_db)

            c = quicklook_db.cursor()

            # Calls parseDB to execute SQL statement
            parseDb(c, quicklook_array, path_to_quicklook_db, path_to_thumbnails, mac_info)

            # Close the index.sqlite
            quicklook_db.close()

            # If the QuickLook array is not empty, we print the information out
            if quicklook_array:
                PrintAll(quicklook_array, mac_info.output_params, '')

        else:
            log.info("No Screen Time artifacts found.")

    # Exit plugin due to unsupported Mac OS version
    else:
        log.warning("Parsing Quicklook Cache on Mac OS 10.15 & Higher is not yet supported")


def Plugin_Start_Standalone(input_files_list, output_params):
    log.info("Module Started as standalone")

    quicklook_db = os.path.join(input_files_list[0], "index.sqlite")
    thumbnails = os.path.join(input_files_list[0], "thumbnails.data")
    quicklook_array = []

    if os.path.isfile(quicklook_db) and os.path.isfile(thumbnails):
        log.info("index.sqlite and thumbnails.data files found!")

        db = OpenDb(quicklook_db)
        c = db.cursor()
        parseDb(c, quicklook_array, quicklook_db, thumbnails, output_params.output_path)
        db.close()

        if quicklook_array:
            PrintAll(quicklook_array, output_params, '')

    else:
        log.error("index.sqlite or thumbnails.data not found in input directory.\n"
                  "Remember to use a folder containing the index.sqlite AND the thumbnails.data as your input!")



if __name__ == '__main__':
    print ("This plugin is a part of a framework and does not run independently on its own!")