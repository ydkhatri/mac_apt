'''
   Copyright (c) 2017 Yogesh Khatri 

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the 
   terms of the MIT License.

'''

from plugins.helpers.macinfo import *
from plugins.helpers.writer import *
import logging
import zlib
import struct

__Plugin_Name = "FSEVENTS"
__Plugin_Friendly_Name = "Fsevents"
__Plugin_Version = "1.0"
__Plugin_Description = "Reads file system event logs (from .fseventsd)"
__Plugin_Author = "Yogesh Khatri"
__Plugin_Author_Email = "yogesh@swiftforensics.com"

__Plugin_Modes = "IOS,MACOS,ARTIFACTONLY"
__Plugin_ArtifactOnly_Usage = 'Provide the ".fseventsd" folder as input to process. This is '\
                            'located at the root of any disk'

log = logging.getLogger('MAIN.' + __Plugin_Name) # Do not rename or remove this ! This is the logger object

#---- Do not change the variable names in above section ----#

# According to Apple - https://web.archive.org/web/20140812143008/https://developer.apple.com/library/mac/documentation/Darwin/Reference/FSEvents_Ref/Reference/reference.html
# FSEventStreamEventFlags
# enum {
#    kFSEventStreamEventFlagNone = 0x00000000,
#    kFSEventStreamEventFlagMustScanSubDirs = 0x00000001,
#    kFSEventStreamEventFlagUserDropped = 0x00000002,
#    kFSEventStreamEventFlagKernelDropped = 0x00000004,
#    kFSEventStreamEventFlagEventIdsWrapped = 0x00000008,
#    kFSEventStreamEventFlagHistoryDone = 0x00000010,
#    kFSEventStreamEventFlagRootChanged = 0x00000020,
#    kFSEventStreamEventFlagMount = 0x00000040,
#    kFSEventStreamEventFlagUnmount = 0x00000080, /* These flags are only set if you specified the FileEvents*/
#    /* flags when creating the stream.*/
#    kFSEventStreamEventFlagItemCreated = 0x00000100,
#    kFSEventStreamEventFlagItemRemoved = 0x00000200,
#    kFSEventStreamEventFlagItemInodeMetaMod = 0x00000400,
#    kFSEventStreamEventFlagItemRenamed = 0x00000800,
#    kFSEventStreamEventFlagItemModified = 0x00001000,
#    kFSEventStreamEventFlagItemFinderInfoMod = 0x00002000,
#    kFSEventStreamEventFlagItemChangeOwner = 0x00004000,
#    kFSEventStreamEventFlagItemXattrMod = 0x00008000,
#    kFSEventStreamEventFlagItemIsFile = 0x00010000,
#    kFSEventStreamEventFlagItemIsDir = 0x00020000,
#    kFSEventStreamEventFlagItemIsSymlink = 0x00040000
# };
# These flags don't match the actual values! Also noted by Nicole Ibrahim http://www.osdfcon.org/presentations/2017/Ibrahim-Understanding-MacOS-File-Ststem-Events-with-FSEvents-Parser.pdf
# The flag values below taken from https://github.com/dlcowen/FSEventsParser/blob/master/FSEParser_V3.3.py
# 

TypeValues = {
    0x00800000: 'File',
    0x01000000: 'Folder',
    0x00100000: 'HardLink',
    0x00400000: 'SymbolicLink'
}

FlagValues = {
    0x00000000: 'None',
    0x00000001: 'Created',
    0x00000002: 'Removed',
    0x00000004: 'InodeMetaMod',
    0x00000008: 'RenamedOrMoved',
    0x00000010: 'Modified',
    0x00000020: 'Exchange',
    0x00000040: 'FinderInfoMod',
    0x00000080: 'FolderCreated',
    0x00000100: 'PermissionChange',
    0x00000200: 'XAttrModified',
    0x00000400: 'XAttrRemoved',
    0x00000800: '0x00000800',
    0x00001000: 'DocumentRevision',
    0x00002000: '0x00002000',
    0x00004000: 'ItemCloned',
    0x00008000: '0x00008000',
    0x00010000: '0x00010000',
    0x00020000: '0x00020000',
    0x00040000: '0x00040000',
    0x00080000: 'LastHardLinkRemoved',
    #0x00100000: 'HardLink',
    0x00200000: '0x00200000',
    #0x00400000: 'SymbolicLink',
    #0x00800000: 'FileEvent',
    #0x01000000: 'FolderEvent',
    0x02000000: 'Mount',
    0x04000000: 'Unmount',
    0x08000000: '0x08000000',
    0x10000000: '0x10000000',
    0x20000000: 'EndOfTransaction',
    0x40000000: '0x40000000',
    0x80000000: '0x80000000'
}

data_writer = ChunkedDataWriter()
out_params = None
total_logs_processed = 0

# [log_id, log_event_flag, log_filepath, log_file_id, source_date, source]
def PrintAll(logs):
    global FlagValues
    global TypeValues
    global data_writer
    global out_params
    fsevent_info = [ ('LogID',DataType.TEXT),
                     ('EventFlagsHex',DataType.TEXT),('EventType',DataType.TEXT),('EventFlags',DataType.TEXT),
                     ('Filepath',DataType.TEXT),
                     ('File_ID',DataType.INTEGER),('SourceModDate',DataType.DATE),('Source',DataType.TEXT)
                   ]

    log.info ("Writing " + str(len(logs)) + " fsevent(s)")
    fsevent_list = []
    for x in logs:
        e_item =  [ "{:016X}".format(x[0]), 
                    "{:08X}".format(x[1]), GetEventFlagsString(x[1], TypeValues), GetEventFlagsString(x[1], FlagValues), 
                    x[2],
                    x[3], x[4], x[5]
                  ]
        fsevent_list.append(e_item)
    data_writer.WriteListPartial("fsevents information", "FsEvents", fsevent_list, fsevent_info, out_params, '')

def GetEventFlagsString(flags, flag_values):
    '''Get string names of all flags set'''
    list_flags = []
    for k, v in list(flag_values.items()):
        if (k & flags) != 0:
            list_flags.append(v)
    return '|'.join(list_flags)

def ReadCString(buffer, buffer_size, start_pos):
    '''
    Reads null-terminated string starting at start_pos in buffer.
    Returns tuple (string, end_pos)
    '''
    string = ""
    end_pos = buffer[start_pos:].find(b'\0')
    if end_pos == -1: # Null not found
        end_pos = len(buffer)
        string = buffer[start_pos:].decode("utf-8", "backslashreplace")
    else:
        string = buffer[start_pos:start_pos + end_pos].decode("utf-8", "backslashreplace")
    end_pos += start_pos

    return string, end_pos + 1

def ParseData(buffer, logs, source_date, source):
    '''Process buffer to extract log data and return number of logs processed'''
    global total_logs_processed
    num_logs_processed = 0
    buffer_size = len(buffer)
    if buffer_size < 12:
        log.error("Error, too small buffer (size={})".format(len(buffer)))
        return 0
    
    header_sig, unknown, file_size = struct.unpack("<4sII", buffer[0:12])
    #Changed header_sig encoding so that it would actually match true against a string
    is_version2 = (str(header_sig, 'utf-8') == '2SLD')
    is_version_unknown = (not is_version2) and (str(header_sig, 'utf-8') != '1SLD')

    if is_version_unknown:
        log.error("Unsupported version, header = {}".format(str(header_sig)))
        return 0
    
    pos = 12

    try:
        if is_version2:
            while pos < min(buffer_size, file_size): # buffer size is always larger, this skips the junk data at its end
                log_filepath, pos = ReadCString(buffer, buffer_size, pos)
                if not log_filepath: break # end of stream, rest are zeroes
                log_id, log_event_flag, log_file_id = struct.unpack("<QIq", buffer[pos:pos+20])
                pos += 20
                num_logs_processed += 1
                logs.append([log_id, log_event_flag, log_filepath, log_file_id, source_date, source])
        else:
            while pos < min(buffer_size, file_size):
                log_filepath, pos = ReadCString(buffer, buffer_size, pos)
                if not log_filepath: break # end of stream, rest are zeroes
                log_id, log_event_flag = struct.unpack("<QI", buffer[pos:pos+12])
                pos += 12
                num_logs_processed += 1
                logs.append([log_id, log_event_flag, log_filepath, None, source_date, source])
    except (ValueError, IndexError, struct.error):
        log.exception('Error processing stream from file {}, stream pos was {}'.format(source, pos))
    if len(logs) > 500000:
        PrintAll(logs)
        logs.clear()
    total_logs_processed += num_logs_processed
    return num_logs_processed

def ProcessFile(file_name, f, logs, source_date, source):
    num_logs_processed_this_file = 0
    z = zlib.decompressobj(31)
    uncompressed_count = 0
    uncompressed_data = b''
    gzip_start = 0

    try:
        while True:
            if z.unused_data == b"":
                buf = f.read(65536)
                if buf == b"":
                    break
            else:
                buf = z.unused_data
                log.debug("decompressed={} bytes from gzip ({}) at pos={}".format(uncompressed_count, file_name, gzip_start))
                num_logs_processed_this_file += ParseData(uncompressed_data, logs, source_date, source)

                uncompressed_data = b''
                uncompressed_count = 0
                gzip_start = f.tell() - len(buf)
                z = zlib.decompressobj(31)
            uncompressed_data_temp = z.decompress(buf)
            uncompressed_data  += uncompressed_data_temp
            uncompressed_count += len(uncompressed_data_temp)
        log.debug ("decompressed={} bytes from gzip ({}) at pos={}".format(uncompressed_count, file_name, gzip_start))
    except zlib.error:
        log.exception("Error trying to decompress file {}".format(source))
    if uncompressed_data:
        num_logs_processed_this_file += ParseData(uncompressed_data, logs, source_date, source)

    log.debug( "num_logs_processed from {} = {}".format(file_name, num_logs_processed_this_file))

def ReadUuid(f):
    uuid = ''
    try:
        uuid = f.read().decode('utf-8', 'backslashreplace')
    except (ValueError, AttributeError):
        log.exception('Error trying to read UUID')
    return uuid

def ProcessFsevents(logs, folder_path, file_list, mac_info):
    ''' Process Fsevents from files
        Args:
            logs - list to be populated
            file_list - list returned from mac_info.ListItemsInFolder
            mac_info - MacInfo object
    '''
    for item in file_list:
        file_name = item['name']
        path = folder_path + '/' + file_name
        mac_info.ExportFile(path, __Plugin_Name, '', False)
        f = mac_info.Open(path)
        if f != None:
            if file_name == 'fseventsd-uuid':
                uuid = ReadUuid(f)
                log.info("fseventsd-uuid={}".format(uuid))
            else:
                ProcessFile(file_name, f, logs, item['dates']['m_time'], path)
        else:
            log.error('Could not open file {}'.format(path))

def Plugin_Start(mac_info):
    '''Main Entry point function for plugin'''
    global data_writer
    global total_logs_processed
    global out_params
    out_params = mac_info.output_params
    logs = []

    file_list = mac_info.ListItemsInFolder('/.fseventsd', EntryType.FILES, True)
    ProcessFsevents(logs, '/.fseventsd', file_list, mac_info)

    #if hasattr(mac_info, 'BuildFullPath') or isinstance(mac_info, ZipMacInfo): # its a MOUNTED or live image
    os_ver = mac_info.GetVersionDictionary()
    if (os_ver['major'] == 10 and os_ver['minor'] >= 15) or os_ver['major'] == 11:
        # Then also get DATA volume's FSEVENTS from /System/Volumes/Data
        file_list = mac_info.ListItemsInFolder('/System/Volumes/Data/.fseventsd', EntryType.FILES, True)
        ProcessFsevents(logs, '/System/Volumes/Data/.fseventsd', file_list, mac_info)
    
    if len(logs) > 0:
        PrintAll(logs)
    if total_logs_processed > 0:
        log.info(f'{total_logs_processed} logs found')
        data_writer.FinishWrites()
    else:
        log.info('No fsevents found')


def Plugin_Start_Standalone(input_files_list, output_params):
    global data_writer
    global out_params
    global total_logs_processed
    out_params = output_params
    log.info("Module Started as standalone")
    for input_path in input_files_list:
        log.debug("Input folder passed was: " + input_path)
        logs = []
        data_writer = ChunkedDataWriter()
        total_logs_processed = 0
        files_list = os.listdir(input_path)
        for file_name in files_list:
            if file_name == 'fseventsd-uuid':
                pass
            else:
                path = os.path.join(input_path, file_name)
                try:
                    with open(path, 'rb') as f:
                        ProcessFile(file_name, f, logs, CommonFunctions.ReadUnixTime(os.path.getmtime(path)), path)
                except (OSError):
                    log.exception('Failed to open file for reading: ' + path)
        if len(logs) > 0:
            PrintAll(logs, output_params)
            log.info("The source_date field on the fsevents are from the individual file modified date "\
                     "(metadata not data)! This may have changed if you are not on a live or read-only image.")
        if total_logs_processed > 0:
            log.info(f'{total_logs_processed} logs found')
            data_writer.FinishWrites()
        else:
            log.info('No fsevents found')

def Plugin_Start_Ios(ios_info):
    '''Entry point for ios_apt plugin'''
    global out_params
    global total_logs_processed
    global data_writer

    out_params = ios_info.output_params
    logs = []
 
    file_list = ios_info.ListItemsInFolder('/.fseventsd', EntryType.FILES, True)
    ProcessFsevents(logs, '/.fseventsd', file_list, ios_info)

    file_list = ios_info.ListItemsInFolder('/private/var/.fseventsd', EntryType.FILES, True)
    ProcessFsevents(logs, '/private/var/.fseventsd', file_list, ios_info)

    if len(logs) > 0:
        PrintAll(logs)
    if total_logs_processed > 0:
        log.info(f'{total_logs_processed} logs found')
        data_writer.FinishWrites()
    else:
        log.info('No fsevents found')

if __name__ == '__main__':
    print ("This plugin is a part of a framework and does not run independently on its own!")
