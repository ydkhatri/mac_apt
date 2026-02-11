'''
   Copyright (c) 2020-2025 Yogesh Khatri 

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the 
   terms of the MIT License.

   documentrevisions.py
   ---------------
   Reads the DocumentRevisions database. The database contains information
   about files that users have opened and edited, including the full path to
   the original file, the date a generated revision was made, date last seen, 
   and the full path to the generated file revision.

   Also reads the ChunkStorage database that stores the data referenced in the
   DocumentRevisions database. All stored data is extracted out, which 
   may be quite large! Extracted files may contain some deleted data that 
   is no longer referenced in the database and files that no longer reside on
   disk.

   Prior research:
   https://eclecticlight.co/2025/09/08/managing-macos-versioning-and-the-documentrevisions-v100-folder/
   https://versprite.com/vs-labs/file-versioning-mac-os-x/

'''
from plugins.helpers.common import CommonFunctions
from plugins.helpers.macinfo import *
from plugins.helpers.writer import *

import binascii
import logging
import sqlite3

__Plugin_Name = "DOCUMENTREVISIONS"
__Plugin_Friendly_Name = "DocumentRevisions"
__Plugin_Version = "2.1"
__Plugin_Description = "Read DocumentRevisions data and extract stored versions"
__Plugin_Author = "Yogesh Khatri, Nicole Ibrahim"
__Plugin_Author_Email = "yogesh@swiftforensics.com, nicoleibrahim.us@gmail.com"

__Plugin_Modes = "MACOS,ARTIFACTONLY,IOS"
__Plugin_ArtifactOnly_Usage = 'Provide the location of the full extracted .DocumentRevisions folder. '\
                            'This is located at /System/Volumes/Data/.DocumentRevisions-V100/ '

log = logging.getLogger('MAIN.' + __Plugin_Name) # Do not rename or remove this ! This is the logger object

#---- Do not change the variable names in above section ----#


class Revisions:

    def __init__(self, gen_id, file_inode, storage_id, path, exists, last_seen, generation_added, generation_path, 
                 generation_size, genstore_orig_display_name, genstore_orig_posix_name, source):
        self.gen_id = gen_id
        self.inode = file_inode
        self.storage_id = storage_id
        self.path = path
        self.exists = exists
        self.last_seen = last_seen
        self.generation_added = generation_added
        self.generation_path = generation_path
        self.generation_size = generation_size
        self.genstore_orig_display_name = genstore_orig_display_name
        self.genstore_orig_posix_name = genstore_orig_posix_name
        self.rev_storage_inode = 0
        self.rev_storage_extension = ''
        self.source_file = source
        self.extracted_path = ''

def PrintAll(revisions, output_params):

    revisions_info = [ ('File_Inode',DataType.INTEGER),('Rev_Inode',DataType.INTEGER),
                        ('Generation_ID',DataType.INTEGER),
                        ('Storage_ID',DataType.INTEGER),('File_Path',DataType.TEXT),
                        ('Rev_Exists_On_Disk',DataType.TEXT),('Extracted_Path',DataType.TEXT),
                        ('File_Last_Seen_UTC',DataType.DATE),('Generation_Added_UTC',DataType.DATE),
                        ('Generation_Path',DataType.TEXT),
                        ('Genstore_Orig_Display_Name', DataType.TEXT), ('Genstore_Orig_Posix_Name', DataType.TEXT),
                        ('Source',DataType.TEXT)
                      ]

    log.info (str(len(revisions)) + " revision item(s) found")
    revisions_list = []
    for q in revisions:
        q_item =  [ q.inode, q.rev_storage_inode, q.gen_id, q.storage_id, q.path, q.exists, q.extracted_path,
                    CommonFunctions.ReadUnixTime(q.last_seen), CommonFunctions.ReadUnixTime(q.generation_added), 
                    q.generation_path, q.genstore_orig_display_name, q.genstore_orig_posix_name, q.source_file
                  ]
        revisions_list.append(q_item)
    WriteList("revisions information", "DocumentRevisions", revisions_list, revisions_info, output_params, '')

def ReadChunkStorageDb(db, chunk_info, source):
    '''Reads ChunkStorage db, parses allocated chunk info into chunk_info, returns all chunk metadata'''
    # Get CSStorageChunkListTable data
    try:
        db.row_factory = sqlite3.Row
        query = "SELECT clt_rowid, clt_inode, clt_count, clt_chunkRowIDs FROM CSStorageChunkListTable"
        cursor = db.execute(query)
        for row in cursor:
            ids_bin = row['clt_chunkRowIDs']
            if len(ids_bin) == 0:
                log.error(f"error, {len(ids_bin)} was zero! for clt_rowid={row['clt_rowid']} clt_inode={row['clt_inode']} Skipping!")
                continue
            if len(ids_bin) > 8:
                num = len(ids_bin) // 8
                if len(ids_bin) % 8 != 0:
                    log.error(f"error, len(ids_bin) is not divisible by 8! len(ids_bin)={len(ids_bin)}, for clt_rowid={row['clt_rowid']} clt_inode={row['clt_inode']} Skipping!")
                    continue
            else:
                num = 1
            ids = struct.unpack(f'<{num}Q', ids_bin)
            chunk_info[row['clt_inode']] = [ids,]

        cursor.close()
    except sqlite3.Error:
        log.exception('Query  execution failed. Query was: ' + query)
    
    # Get CSChunkTable data
    chunk_table_info = {} # {row_id: (file_name, hex_cid, offset, dataLen), .. }
    try:
        query = "SELECT ct_rowid, ft_rowid, offset, dataLen, hex(cid) as hex_cid, timeStamp from CSChunkTable"
        cursor = db.execute(query)
        for row in cursor:
            chunk_table_info[row['ct_rowid']] = (row['ft_rowid'], row['hex_cid'], row['offset'], row['dataLen'])
        cursor.close()
    except sqlite3.Error:
        log.exception('Query  execution failed. Query was: ' + query)
    
    for clt_inode, row_data in chunk_info.items():
        row_ids = row_data[0]
        chunks = []
        for row_id in row_ids:
            chunk = chunk_table_info.get(row_id, None)
            chunks.append(chunk)
        row_data.append(chunks)

    return chunk_table_info

def ReadRevisionsdB(db, revisions, source):
    '''Reads db.sqlite db'''
    try:
        query = """SELECT generations.generation_id as gen_id, files.file_inode as inode, 
                generations.generation_storage_id as storage_id, files.file_path as path,
                files.file_last_seen as file_last_seen_utc,
                generations.generation_add_time as generation_add_time_utc,
                generations.generation_path as generation_path,
                generations.generation_size
                FROM generations left join files ON generations.generation_storage_id = files.file_storage_id"""
        db.row_factory = sqlite3.Row
        cursor = db.execute(query)
        for row in cursor:
            try:
                rev = Revisions(row['gen_id'], row['inode'], row['storage_id'], row['path'], '', row['file_last_seen_utc'], 
                                    row['generation_add_time_utc'], row['generation_path'], row['generation_size'], '', '', source)
                revisions.append(rev)
            except (sqlite3.Error, KeyError):
                log.exception('Error fetching row data')
    except sqlite3.Error:
        log.exception('Query  execution failed. Query was: ' + query)

def OpenDb(inputPath):
    log.info ("Processing file " + inputPath)
    try:
        conn = CommonFunctions.open_sqlite_db_readonly(inputPath)
        log.debug ("Opened database successfully")
        return conn
    except sqlite3.Error:
        log.exception ("Failed to open database, is it a valid DB?")
    return None

def OpenDbFromImage(mac_info, inputPath):
    '''Returns tuple of (connection, wrapper_obj)'''
    log.info ("Processing revisions events from file {}".format(inputPath))
    try:
        sqlite = SqliteWrapper(mac_info)
        conn = sqlite.connect(inputPath)
        if conn:
            log.debug ("Opened database successfully")
        return conn, sqlite
    except sqlite3.Error as ex:
        log.exception ("Failed to open database, is it a valid DB?")
    return None, None

def ProcessDbsFromPath(mac_info, revisions, chunk_info, rev_source_path, cs_source_path):
    chunk_table_info = {}
    if mac_info.IsValidFilePath(rev_source_path):
        mac_info.ExportFile(rev_source_path, __Plugin_Name)
        db, wrapper = OpenDbFromImage(mac_info, rev_source_path)
        if db != None:
            ReadRevisionsdB(db, revisions, rev_source_path)
            db.close()
    if mac_info.IsValidFilePath(cs_source_path):
        mac_info.ExportFile(cs_source_path, __Plugin_Name)
        db, wrapper = OpenDbFromImage(mac_info, cs_source_path)
        if db != None:
            chunk_table_info = ReadChunkStorageDb(db, chunk_info, cs_source_path)
            db.close()
    return chunk_table_info
    
def CheckForRevisionExistence(mac_info, revisions, root):
    try_alternate_path = False
    if not hasattr(mac_info, 'apfs_db') or \
           isinstance(mac_info, ZipMacInfo) or \
           isinstance(mac_info, MountedVRZip):
        log.warning("This is MOUNTED or ZIP or VR mode, will try searching paths with /System/Volumes/Data first")
        try_alternate_path = True

    if not root.endswith('/'):
        root += '/'
    for rev in revisions:
        path = root + rev.generation_path
        paths = [path]
        if try_alternate_path:
            alternate_path = "/System/Volumes/Data" + path
            paths.insert(0, alternate_path)
        found = False
        for path in paths:
            if mac_info.IsValidFilePath(path) or \
                mac_info.IsValidFolderPath(path):
                rev.exists = 'Yes'
                found = True
                xattrs = mac_info.GetExtendedAttributes(path)
                rev.genstore_orig_display_name = xattrs.get('com.apple.genstore.origdisplayname', b'').decode('utf8', 'ignore')
                rev.genstore_orig_posix_name = xattrs.get('com.apple.genstore.origposixname', b'').decode('utf8', 'ignore')
                if path.endswith(':QLThumbnailAdditionName'):
                    # Older macOS versions store thumbnail as a .jpeg file, newer as .png
                    if mac_info.IsValidFilePath(path + "/thumbnail.png"):
                        rev.rev_storage_inode = mac_info.GetFileInodeNumber(path + "/thumbnail.png")
                        rev.rev_storage_extension = '.png'
                    elif mac_info.IsValidFilePath(path + "/thumbnail.jpeg"):
                        rev.rev_storage_inode = mac_info.GetFileInodeNumber(path + "/thumbnail.jpeg")
                        rev.rev_storage_extension = '.jpeg'
                    else:
                        # get first child in folder and its inode number
                        items = mac_info.ListItemsInFolder(path, EntryType.FILES)
                        if items:
                            log.info(f'Did not find .jpeg or .png thumbnail file in {path}, using first file {items[0]["name"]}')
                            thumb_path = os.path.join(path, items[0]['name'])
                            rev.rev_storage_inode = mac_info.GetFileInodeNumber(thumb_path)
                else:
                    rev.rev_storage_inode = mac_info.GetFileInodeNumber(path)
                continue
        if found == False:
            log.debug(f'Did not FIND -> {path}')
            rev.exists = 'No'

def GetChunkFileInfo(mac_info, chunk_path):
    '''Retrieve chunk storage file paths and also export them'''
    files_info = {} # { name1: (path1, size1), name2: (path2, size2), ..}
    # Files will be in chunk_path\xx\yy\zz\ folder at 4th level
    # first layer
    items_1 = mac_info.ListItemsInFolder(chunk_path, EntryType.FOLDERS)
    for x in items_1:
        # second layer
        items_2 = mac_info.ListItemsInFolder(f'{chunk_path}/{x["name"]}', EntryType.FOLDERS)
        for y in items_2:
            # third layer
            items_3 = mac_info.ListItemsInFolder(f'{chunk_path}/{x["name"]}/{y["name"]}', EntryType.FOLDERS)
            for z in items_3:
                # fourth layer
                items_4 = mac_info.ListItemsInFolder(f'{chunk_path}/{x["name"]}/{y["name"]}/{z["name"]}', EntryType.FILES)
                for item in items_4:
                    file_name = item['name']
                    file_size = item['size']
                    file_path = f'{chunk_path}/{x["name"]}/{y["name"]}/{z["name"]}/{file_name}'
                    # file name should be an integer
                    int_filename = CommonFunctions.IntFromStr(file_name, 10, -1, True)
                    if int_filename != -1:
                        files_info[int_filename] = (file_path, file_size)
                        mac_info.ExportFile(file_path, __Plugin_Name)
    return files_info

def GetChunkFileInfoStandalone(chunk_path):
    files_info = {} # { name1: (path1, size1), name2: (path2, size2), ..}

    for root, dirs, files in os.walk(chunk_path, topdown=True):
        current_depth = root[len(chunk_path):].count(os.sep)
        if current_depth < 3:
            pass
        elif current_depth == 3:
            for file_name in files:
                file_path = os.path.join(root, file_name)
                file_size = os.path.getsize(file_path)
                
                # file name should be an integer
                int_filename = CommonFunctions.IntFromStr(file_name, 10, -1, True)
                if int_filename != -1:
                    files_info[int_filename] = (file_path, file_size)
            break
        else:
            # Prevent descending deeper
            dirs[:] = []
    return files_info

def ExtractChunksReconstructFile(mac_info, export_path, files_info, chunk_meta_info, used_cids):
    '''Returns file size written
       Format of chunk_meta_info is [(row['ft_rowid'], row['hex_cid'], row['offset'], row['dataLen']), ..]
    '''
    size_written = 0
    with open(export_path, 'wb') as f:
        log.debug(f'Writing {export_path}')
        for chunk_meta in chunk_meta_info:
            if chunk_meta is not None:
                chunk_file_name = chunk_meta[0]
                hex_cid = chunk_meta[1]
                offset = chunk_meta[2]
                data_len = chunk_meta[3]
                if chunk_file_name in files_info:
                    file_path, file_size = files_info[chunk_meta[0]]
                    if file_size > 0:
                        if mac_info is None:
                            cf = open(file_path, 'rb')
                        else:
                            cf = mac_info.Open(file_path)
                        cf.seek(offset)
                        data = cf.read(data_len)
                        cf_cid = binascii.hexlify(data[4:25]).decode('utf8').upper()
                        if cf_cid != hex_cid:
                            log.error(f'cid did not match {cf_cid} != {hex_cid}')
                            continue
                        else:
                            size_written += f.write(data[25:])
                            used_cids.add(hex_cid)
                        if mac_info is None and cf is not None:
                            cf.close()
                else:
                    log.error('File size was zero, writing zeroes!')
                    size_written += f.write(b'\x00'*data_len)
            else:
                log.error('Chunk data info missing, skipping this, file will be out of sync!')
    return size_written

def ExtractOrphanChunksToFiles(mac_info, used_cids, files_info, export_path):
    log.info('Extracting any orphan chunks now...')
    num_extracted = 0
    for file_name, (file_path, file_size) in files_info.items():
        if file_size == 0:
            continue
        file = None
        if mac_info is not None:
            file = mac_info.Open(file_path)
        else:
            file = open(file_path, 'rb')
        data_avail_size = file_size
        while True:
            header = file.read(25)
            if len(header) == 0:
                break
            elif len(header) < 25:
                log.error(f'Could not read chunk header only {len(header)} bytes returned')
                break
            else:
                size = struct.unpack('>I', header[0:4])[0]
                size -= 25
                cid = header[4:]
                if size < 0:
                    log.error(f'size ({size}) < 0 , data_avail_size={data_avail_size}')
                    break
                elif size > data_avail_size:
                    log.error(f'size ({size}) > data_avail_size ({data_avail_size})')
                    break
                hex_cid = cid.hex().upper()
                if hex_cid in used_cids:
                    file.seek(size, os.SEEK_CUR)
                else:
                    data = file.read(size)
                    path = os.path.join(export_path, f'ORPHAN_{file_name}_{hex_cid}.jpg')
                    log.debug(f'Found an orphaned chunk, writing out {path}')
                    with open (path, 'wb') as f:
                        f.write(data)
                        num_extracted += 1
                data_avail_size -= size
        if mac_info is None and file is not None:
            file.close()
    log.info(f"{num_extracted} orphan file(s) written")

def ProcessRevisionsAndExtract(mac_info, revisions, chunk_info, chunk_files, export_path):
    used_cids = set()

    if revisions:
        if mac_info is not None:
            CheckForRevisionExistence(mac_info, revisions, '/.DocumentRevisions-V100')
        
        for rev in revisions:
            out_file_name = ''
            if  rev.rev_storage_inode is not None and \
                rev.rev_storage_inode > 0 and \
                rev.rev_storage_inode in chunk_info:
                # extract chunk
                chunks_meta_info = chunk_info[rev.rev_storage_inode][1]
                # sanity check , skip if all elements are none
                if all(x == None for x in chunks_meta_info):
                    continue
                if rev.path is None:
                    # try to get path from inode
                    if mac_info is not None:
                        rev.path = mac_info.GetFilePathFromInodeNumber(rev.inode)
                    if rev.path is None or rev.path == '':
                        rev.path = "UNKNOWN"
                        if rev.genstore_orig_display_name:
                            out_file_name = f'{rev.path}_{rev.genstore_orig_display_name}'
                        else:
                            out_file_name = rev.path
                    else:
                        out_file_name = os.path.basename(rev.path)
                else:
                    out_file_name = os.path.basename(rev.path)
                if rev.generation_path.endswith('QLThumbnailAdditionName'):
                    if rev.rev_storage_extension:
                        out_file_name += rev.rev_storage_extension
                    else:
                        out_file_name += ".jpg"
                out_file_path = CommonFunctions.GetNextAvailableFileName(os.path.join(export_path, f'{rev.gen_id}_{out_file_name}'))
                rev.extracted_path = out_file_path
                size_written = ExtractChunksReconstructFile(mac_info, out_file_path, chunk_files, chunks_meta_info, used_cids)
                if size_written != rev.generation_size:
                    log.warning(f'Size mismatch occurred. Expected {rev.generation_size} Got {size_written}')
            else:
                log.warning(f'Did not find rev_storage_inode={rev.rev_storage_inode} in chunk db')
    ExtractOrphanChunksToFiles(mac_info, used_cids, chunk_files, export_path)

def Plugin_Start(mac_info):
    '''Main Entry point function for plugin'''
    revisions = []
    chunk_info = {}

    doc_rev_paths = ('/.DocumentRevisions-V100', 
                     '/System/Volumes/Data/.DocumentRevisions-V100')
    chunk_table_info = {}

    for doc_rev_path in doc_rev_paths:
        if mac_info.IsValidFolderPath(doc_rev_path):
            rev_path   = f'{doc_rev_path}/db-V1/db.sqlite'
            csdb_path  = f'{doc_rev_path}/.cs/ChunkStoreDatabase'
            chunk_path = f'{doc_rev_path}/.cs/ChunkStorage'
            chunk_table_info = ProcessDbsFromPath(mac_info, revisions, chunk_info, rev_path, csdb_path)
            chunk_files = GetChunkFileInfo(mac_info, chunk_path)
            export_path = os.path.join(mac_info.output_params.output_path, "DocRevisionsExtracted")
            os.makedirs(export_path, exist_ok=True)
            ProcessRevisionsAndExtract(mac_info, revisions, chunk_info, chunk_files, export_path)
            break
    
    if len(revisions) > 0:
        PrintAll(revisions, mac_info.output_params)
    else:
        log.info('No revisions item found')

def Plugin_Start_Standalone(input_files_list, output_params):
    log.info("Module Started as standalone")
    for input_path in input_files_list:
        log.debug("Input file passed was: " + input_path)
        if os.path.isdir(input_path):
            doc_rev_path = input_path.strip('\\').strip('/')
            rev_path   = os.path.join(doc_rev_path, 'db-V1', 'db.sqlite')
            csdb_path  = os.path.join(doc_rev_path, '.cs', 'ChunkStoreDatabase')
            chunk_path = os.path.join(doc_rev_path, '.cs', 'ChunkStorage')
            chunk_files = GetChunkFileInfoStandalone(chunk_path)
            revisions = []
            chunk_info = {}
            chunk_table_info = {}
            export_path = os.path.join(output_params.output_path, "DocRevisionsExtracted")
            os.makedirs(export_path, exist_ok=True)

            db = OpenDb(rev_path)
            if db != None:
                filename = os.path.basename(rev_path)
                ReadRevisionsdB(db, revisions, rev_path)
                db.close()
            else:
                log.error(f'Failed to open database {rev_path}')

            db = OpenDb(csdb_path)
            if db != None:
                #filename = os.path.basename(csdb_path)
                chunk_table_info = ReadChunkStorageDb(db, chunk_info, csdb_path)
                db.close()
            else:
                log.error(f'Failed to open database {csdb_path}')
            
            ProcessRevisionsAndExtract(None, revisions, chunk_info, chunk_files, export_path)

            if len(revisions) > 0:
                PrintAll(revisions, output_params)
            else:
                log.info('No revisions item found in {}'.format(input_path))
        else:
            log.info(f'Input path is not a folder: {input_path}')

def Plugin_Start_Ios(ios_info):
    '''Main Entry point function for plugin'''
    revisions = []
    chunk_info = {}
    revisions_path = '/private/var/mobile/.DocumentRevisions-V100/db-V1/db.sqlite'
    ProcessDbsFromPath(ios_info, revisions, chunk_info, revisions_path, '')
    CheckForRevisionExistence(ios_info, revisions, '/private/var/mobile/.DocumentRevisions-V100')

    if len(revisions) > 0:
        PrintAll(revisions, ios_info.output_params)
    else:
        log.info('No revisions item found')

if __name__ == '__main__':
    print ("This plugin is a part of a framework and does not run independently on its own!")
