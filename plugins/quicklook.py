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
from itertools import chain, zip_longest
from PIL import Image

__Plugin_Name = "QUICKLOOK" # Cannot have spaces, and must be all caps!
__Plugin_Friendly_Name = "QuickLook Thumbnail Cache"
__Plugin_Version = "1.0"
__Plugin_Description = "Parses QuickLook Thumbnail Cache data"
__Plugin_Author = "Jack Farley - BlackStone Discovery"
__Plugin_Author_Email = "jfarley@blackstonediscovery.com - jfarley248@gmail.com"

__Plugin_Modes = "MACOS,ARTIFACTONLY"
__Plugin_ArtifactOnly_Usage = 'Provide QuickLook database folder, found at:' \
                            '/private/var/folders/XX/XXXXXXXXXXXXXXXXXXX_XXXXXXXXX/' \
                            'C/com.apple.QuickLook.thumbnailcache/index.sqlite' \

log = logging.getLogger('MAIN.' + __Plugin_Name) # Do not rename or remove this ! This is the logger object

#---- Do not change the variable names in above section ----#

"""
This plugin was made using previously conducted research and scripting from Mari Degrazia and Dave:
https://github.com/mdegrazia/OSX-QuickLook-Parser
http://www.easymetadata.com/2015/01/sqlite-analysing-the-quicklook-database-in-macos/
"""

class QuickLook:
    def __init__(self, folder, file_name, hit_count, last_hit_date, version, bitmapdata_location,
                 bitmapdata_length, width, height, fs_id, inode, row_id, source):
        self.folder = folder
        self.file_name= file_name
        self.hit_count = hit_count
        self.last_hit_date = last_hit_date
        self.version = version
        self.bitmapdata_location = bitmapdata_location
        self.bitmapdata_length = bitmapdata_length
        self.width = width
        self.height = height
        self.fs_id = fs_id
        self.inode = inode
        self.row_id = row_id
        self.source = source


def PrintAll(quicklook_data, output_params, source_path):
    quicklook_info = [ ('Folder',DataType.TEXT),('File_Name',DataType.TEXT),('Hit_Count',DataType.TEXT),
                       ('Last_Hit_Date',DataType.TEXT), ('version',DataType.BLOB), ('bitmap_data_location',DataType.INTEGER),
                       ('bitmap_data_length',DataType.INTEGER), ('Width',DataType.INTEGER), ('Height',DataType.INTEGER),
                       ('fs_id',DataType.TEXT),('inode',DataType.TEXT), ('row_id',DataType.TEXT), ('Source',DataType.TEXT)
                     ]

    quicklook_list = []
    for ql in quicklook_data:
        ql_items = [ql.folder, ql.file_name, ql.hit_count,
                      ql.last_hit_date, ql.version, ql.bitmapdata_location, ql.bitmapdata_length, ql.width,
                      ql.height, ql.fs_id, ql.inode, ql.row_id, ql.source
                     ]
        quicklook_list.append(ql_items)
    WriteList("QuickLook Info", "QuickLook", quicklook_list, quicklook_info, output_params, source_path)


def OpenDbFromImage(mac_info, inputPath):
    '''Returns tuple of (connection, wrapper_obj)'''
    try:
        sqlite = SqliteWrapper(mac_info)
        conn = sqlite.connect(inputPath)
        if conn:
            log.debug ("Opened database successfully")
        return conn, sqlite
    except sqlite3.Error as ex:
        log.exception ("Failed to open database, is it a valid QuickLook DB?")
    return None, None

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
    handle = mac_info.Open(path)
    return handle

def carveThumb(offset, length, thumbfile, thumbname, width, height, export, user_name, is_BGRA=False):
    """

    :param offset: Offset in thumbnails.data for thumbnail
    :param length: Lenght of data to carve for thumbnail in thumbnails.data
    :param thumbfile: Source thumbnails.data file to carve from
    :param thumbname: Name of the file that has the thumbnail
    :param export: Either output directory in single plugin mode or mac_info object
    :return: Nothing
    """

    if length is not None:

        # Seek and read thumbnails.data from offsets and lengths found in the index.sqlite
        thumbfile.seek(offset)
        thumb = thumbfile.read(length)

        if is_BGRA:
            thumb = convertBGRA_to_RGBA(thumb)

        # Use the Pillow Library Image to parse and export files as images
        imgSize = (width, height)
        img = Image.frombytes('RGBA', imgSize, thumb, decoder_name='raw')

        # Parse via mac_info
        if type(export) is not str:
            export_folder = os.path.join(export.output_params.export_path, __Plugin_Name, "Thumbnails", user_name)

        # Parse via single plugin
        else:
            export_folder = os.path.join(export, __Plugin_Name, "Thumbnails")

        # Create output directory if doesn't exist
        if not os.path.exists(export_folder):
            os.makedirs(export_folder)

        thumbname = CommonFunctions.SanitizeName(thumbname) # remove illegal characters which might cause issues!

        # Set up output file with png extension attached
        try:
            # Some of the names may have illegal characters in them, filter those out
            thumbname = CommonFunctions.SanitizeName(thumbname) + " - " + str(width) +  "x" + str(height) + ".png"
            export_file = os.path.join(export_folder, thumbname)
            export_file = CommonFunctions.GetNextAvailableFileName(export_file)
            log.debug("Attempting to copy out thumbnail to file: " + export_file)

            img.save(export_file)
        except (ValueError, OSError) as ex:
            log.exception('Failed to write out thumbnail ' + thumbname)

def parseDb(c, quicklook_array, source, path_to_thumbnails, export, user_name):
    """
    :param c: Connection to index.sqlite
    :param quicklook_array: Empty quicklook array to store QuickLook objects
    :param source: The source file being used, the full path to the index.sqlite
    :return: Nothing, fills the quicklook array
    """

    # Query only gets the largest render for a file, ignoring smaller thumbnails
    # TODO - Identify deleted files based on null thumbnails with non-existing inode numbers
    thumbnail_query = """
    select files.rowid , folder, file_name, fs_id, version, max(size) as size, hit_count,
        datetime(last_hit_date + strftime('%s', '2001-01-01 00:00:00'), 'unixepoch') as last_hit_date, 
        width, (bytesperrow / (bitsperpixel/bitspercomponent)) as computed_width, height, 
        bitmapdata_location, bitmapdata_length 
    from files left join thumbnails on files.ROWID = thumbnails.file_id
    where size is not null 
    group by files.ROWID
    """

    try:
        c.execute(thumbnail_query)
        data = c.fetchall()
        thumbfile = None
        if len(data):
            # Export the thumbnails.data file via mac_info
            if type(export) is not str:
                thumbfile = openDeadbox(path_to_thumbnails, export)

            # Export thumbnails.data via single plugin
            else:
                thumbfile = openSingle(path_to_thumbnails)

        # Iterate through the rows returned by the above SQL statment and create QuickLook object based off it,
        # then appends to array
        for item in data:
            row_id = item[0]
            folder = item[1]
            file_name = item[2]
            hit_count = item[6]
            last_hit_date = item[7]
            bitmapdata_location = item[11]
            bitmapdata_length = item[12]
            width = item[8]
            computed_width = item[9]
            height = item[10]
            fs_id = item[3]
            if fs_id and len(fs_id) > 10:
                try:
                    inode = fs_id[10:].split('.')[1]
                    inode = inode.rstrip('/')
                except IndexError as ex:
                    inode = ''
            else:
                inode = ''
            version = item[4] #plist

            ql = QuickLook(folder, file_name, hit_count, last_hit_date, version, bitmapdata_location,
                           bitmapdata_length, computed_width, height, fs_id, inode, row_id, source)
            quicklook_array.append(ql)

            # Carve out thumbnail
            carveThumb(bitmapdata_location, bitmapdata_length, thumbfile, file_name, computed_width, height, export, user_name)
        
        if thumbfile:
            thumbfile.close()

    # Catch SQLite3 exceptions
    except sqlite3.Error as e:
        log.exception("Exception while executing query for QuickLook cache. Exception was: " + str(e))


def findParents(c, CNID, full_path):
    inode_query_unformat = """
    SELECT Parent_CNID from Combined_Inodes where Combined_Inodes.CNID == {}
    """
    inode_query = inode_query_unformat.format(CNID)

    name_query_unformat = """
    SELECT Name from Combined_Inodes where Combined_Inodes.CNID == {}
    """

    if CNID == 2:
        return
    else:
        c.execute(inode_query)
        parent_CNID = c.fetchone()[0]
        name_query = name_query_unformat.format(parent_CNID)
        c.execute(name_query)
        parent_folder = c.fetchone()[0]
        full_path[0] =   parent_folder + "/" + full_path[0]
        findParents(c, parent_CNID, full_path)

def parseDbNewSinglePlug(c, quicklook_array, source, path_to_thumbnails, export):
    """
            :param c: Connection to index.sqlite
            :param quicklook_array: Empty quicklook array to store QuickLook objects
            :param source: The source file being used, the full path to the index.sqlite
            :return: Nothing, fills the quicklook array
        """


    combined_query = """
        SELECT fileId, version, MAX(size), hit_count, 
        datetime(last_hit_date + strftime('%s', '2001-01-01 00:00:00'), 'unixepoch') as last_hit_date, 
        width, (bytesperrow / (bitsperpixel/bitspercomponent)) as computed_width, height,
        bitmapdata_location, bitmapdata_length
        FROM thumbnails LEFT JOIN basic_files 
        ON (basic_files.fileId | -9223372036854775808) == thumbnails.file_id
        group by fileId
        """

    c.execute(combined_query)
    combined_files = c.fetchall()

    # If the statement returned anything, lets parse it further
    if combined_files:
        # Export thumbnails.data via mac_info
        if type(export) is not str:
            thumbfile = openDeadbox(path_to_thumbnails, export)
        # Export thumbnails.data via single plugin
        else:
            thumbfile = openSingle(path_to_thumbnails)
        unknown_count = 0
        for entries in combined_files:
            # Carve out thumbnails with no iNode
            bitmapdata_location = entries[8]
            bitmapdata_length = entries[9]
            computed_width = entries[6]
            height = entries[7]
            name = "Unknown" + str(unknown_count)
            hit_count = entries[3]
            last_hit_date = entries[4]
            version = b"" # Not writing this out
            fs_id = "N/A"
            inode = entries[0]
            row_id = "N/A"
            carveThumb(bitmapdata_location, bitmapdata_length, thumbfile, name, computed_width, height, export, '', True)
            unknown_count += 1
            ql = QuickLook("UNKNOWN", "UNKNOWN", hit_count, last_hit_date, version,
                            bitmapdata_location, bitmapdata_length, computed_width, height, fs_id, inode, row_id, source)
            quicklook_array.append(ql)
        if thumbfile:
            thumbfile.close()

def convertBGRA_to_RGBA(data):
    if len(data)%4 != 0:
        print("Problem, got a remainder, trying to pad..!")
        data += b'\0' * (4 - len(data)%4)

    ret = tuple(chain(*((R,G,B,A) for B,G,R,A in zip_longest(*[iter(data)]*4))))
    return bytes(ret)


def parseDbNew(c, quicklook_array, source, path_to_thumbnails, export, user_name):
    """
        :param c: Connection to index.sqlite
        :param quicklook_array: Empty quicklook array to store QuickLook objects
        :param source: The source file being used, the full path to the index.sqlite
        :return: Nothing, fills the quicklook array
    """

    inode_query = """
    SELECT Name from Combined_Inodes where Combined_Inodes.CNID == {}
    """

    combined_query = """
        SELECT fileId, version, MAX(size), hit_count, 
        datetime(last_hit_date + strftime('%s', '2001-01-01 00:00:00'), 'unixepoch') as last_hit_date, 
        width, (bytesperrow / (bitsperpixel/bitspercomponent)) as computed_width, height,
        bitmapdata_location, bitmapdata_length
        FROM thumbnails LEFT JOIN basic_files 
        ON (basic_files.fileId | -9223372036854775808) == thumbnails.file_id
        group by fileId
    """

    c.execute(combined_query)
    combined_files = c.fetchall()

    # If the statement returned anything, lets parse it further
    if combined_files:
        # Export the thumbnails.data file via mac_info
        thumbfile = openDeadbox(path_to_thumbnails, export)
        unknown_count = 0
        for entries in combined_files:
            bitmapdata_location = entries[8]
            bitmapdata_length = entries[9]
            width = entries[6]
            height = entries[7]
            hit_count = entries[3]
            last_hit_date = entries[4]
            version = b""
            fs_id = "N/A"
            inode = entries[0]
            row_id = "N/A"

            # Format the inode_query for our specific iNode number so we can find the filename
            apfs_query = inode_query.format(entries[0])

            # Create cursor to the APFS db created by mac_apt
            apfs_c = export.apfs_db.conn.cursor()

            apfs_c.row_factory = sqlite3.Row
            cursor = apfs_c.execute(apfs_query)
            test_row = cursor.fetchone()
            if test_row is None:
                log.warning("No file matches iNode: " + str(inode) + "!!")
                log.warning("This file will be outputted as Unknown" + str(unknown_count))

                # Carve out thumbnails with no iNode

                name = "Unknown" + str(unknown_count)

                log.debug("Carving an unknown thumbnail, this is unknown number: " + str(unknown_count))
                carveThumb(bitmapdata_location, bitmapdata_length, thumbfile, name, width, height, export, user_name, True)
                unknown_count += 1
                ql = QuickLook("UNKNOWN", "UNKNOWN", hit_count, last_hit_date, version, bitmapdata_location,
                                bitmapdata_length, width, height, fs_id, inode, row_id, source)
                quicklook_array.append(ql)

            else:
                for row in test_row:
                    log.debug("File matching iNode: " + str(inode) + " is: " + row)
                    full_path = [""]
                    findParents(apfs_c, inode, full_path)

                    ql = QuickLook(full_path[0], row, hit_count, last_hit_date, version, bitmapdata_location,
                                    bitmapdata_length, width, height, fs_id, inode, row_id, source)
                    quicklook_array.append(ql)

                    # Carve out thumbnails
                    log.debug("Carving thumbnail: " + str(full_path[0]) + row + " from thumbnails.data file")
                    carveThumb(bitmapdata_location, bitmapdata_length, thumbfile, row, width, height, export, user_name, True)
        if thumbfile:
            thumbfile.close()

def findDb(mac_info):
    log.debug("Finding QuickLook databases and caches now in user cache dirs")
    db_path_arr = []
    thumbnail_path_array = []
    users = []
    is_big_sur_or_higher = mac_info.GetVersionDictionary()['major'] >= 11

    for user in mac_info.users:
        if not user.DARWIN_USER_CACHE_DIR or not user.user_name:
            continue  # TODO: revisit this later!
        else:

            darwin_user_folders = user.DARWIN_USER_CACHE_DIR.split(',')

            for darwin_user_cache_dir in darwin_user_folders:
                if is_big_sur_or_higher:
                    db_path = darwin_user_cache_dir + '/com.apple.quicklook.ThumbnailsAgent/com.apple.QuickLook.thumbnailcache/index.sqlite'
                    thumbnail_path = darwin_user_cache_dir + '/com.apple.quicklook.ThumbnailsAgent/com.apple.QuickLook.thumbnailcache/thumbnails.data'
                else:
                    db_path = darwin_user_cache_dir + '/com.apple.QuickLook.thumbnailcache/index.sqlite'
                    thumbnail_path = darwin_user_cache_dir + '/com.apple.QuickLook.thumbnailcache/thumbnails.data'
                if not mac_info.IsValidFilePath(db_path) or not mac_info.IsValidFilePath(thumbnail_path):
                    continue
                
                log.debug(f"Found valid thumbnail database for user '{user.user_name}' at {db_path}")
                log.debug(f"Found valid thumbnail data for user '{user.user_name}' at {thumbnail_path}")
                db_path_arr.append(db_path)
                thumbnail_path_array.append(thumbnail_path)
                users.append(user.user_name)

    return db_path_arr, thumbnail_path_array, users


def Plugin_Start(mac_info):
    '''Main Entry point function for plugin'''

    # Array to store QuickLook objects
    quicklook_array = []

    # Finds QuickLook index.sqlite and the thumbnails.data
    paths_to_quicklook_db, paths_to_thumbnails, users = findDb(mac_info)

    # Iterate through returned array of paths and pair each index.sqlite with their thumbnails.data
    for quicklook_db_path, thumbnail_file, user in zip(paths_to_quicklook_db, paths_to_thumbnails, users):
        log.info("QuickLook Cache data found!")

        # Export index.sqlite and thumbnails.data file
        mac_info.ExportFile(quicklook_db_path, __Plugin_Name, user + "_")
        mac_info.ExportFile(thumbnail_file, __Plugin_Name, user + "_")

        # Opens index.sqlite
        quicklook_db, quicklook_wrapper = OpenDbFromImage(mac_info, quicklook_db_path)
        if quicklook_db == None:
            continue

        c = quicklook_db.cursor()
        query = "PRAGMA table_info('files');"
        c.execute(query)
        row = c.fetchone()
        if row is not None:
            log.debug("QuickLook data from Mac OS below 10.15 found... Processing")
            parseDb(c, quicklook_array, quicklook_db_path, thumbnail_file, mac_info, user)
        else:
            log.debug("QuickLook data from Mac OS 10.15+ found... Processing")
            parseDbNew(c, quicklook_array, quicklook_db_path, thumbnail_file, mac_info, user)

        # Close the index.sqlite
        quicklook_db.close()

    # If the QuickLook array is not empty, we print the information out
    if quicklook_array:
        PrintAll(quicklook_array, mac_info.output_params, '')
    else:
        log.info("No QuickLook artifacts found.")


def Plugin_Start_Standalone(input_files_list, output_params):

    query = "PRAGMA table_info('files');"

    log.info("Module Started as standalone")

    quicklook_db = os.path.join(input_files_list[0], "index.sqlite")
    thumbnails = os.path.join(input_files_list[0], "thumbnails.data")
    quicklook_array = []

    if os.path.isfile(quicklook_db) and os.path.isfile(thumbnails):
        log.info("index.sqlite and thumbnails.data files found!")

        db = OpenDb(quicklook_db)
        c = db.cursor()
        c.execute(query)
        row = c.fetchone()
        if row is not None:
            log.debug("QuickLook data from Mac OS below 10.15 found... Processing")
            parseDb(c, quicklook_array, quicklook_db, thumbnails, output_params.output_path, '')
        else:
            log.debug("QuickLook data from Mac OS 10.15+ found... Processing")
            parseDbNewSinglePlug(c, quicklook_array, quicklook_db, thumbnails, output_params.output_path)
        db.close()
    else:
        log.error("index.sqlite or thumbnails.data not found in input directory.\n"
                  "Remember to use a folder containing the index.sqlite AND the thumbnails.data as your input!")
                  
    if quicklook_array:
        log.info("QuickLook data processed. Printing out now")
        PrintAll(quicklook_array, output_params, '')


if __name__ == '__main__':
    print ("This plugin is a part of a framework and does not run independently on its own!")