import zlib
import struct

## Eventmask from 
EVENTMASK = {
    0x00000000: 'None',
    0x00000001: 'FolderEvent',
    0x00000002: 'Mount',
    0x00000004: 'Unmount',
    0x00000008: '0x00000008',
    0x00000010: '0x00000010',
    0x00000020: 'EndOfTransaction',
    0x00000040: '0x00000040',
    0x00000080: '0x00000080',
    0x00000100: '0x00000100',
    0x00000200: '0x00000200',
    0x00000400: '0x00000400',
    0x00000800: 'LastHardLinkRemoved',
    0x00001000: 'HardLink',
    0x00002000: '0x00002000',
    0x00004000: 'SymbolicLink',
    0x00008000: 'FileEvent',
    0x00010000: 'PermissionChange',
    0x00020000: 'ExtendedAttrModified',
    0x00040000: 'ExtendedAttrRemoved',
    0x00080000: '0x00080000',
    0x00100000: 'DocumentRevisioning',
    0x00200000: '0x00200000',
    0x00400000: 'ItemCloned',           # macOS HighSierra
    0x00800000: '0x00800000',
    0x01000000: 'Created',
    0x02000000: 'Removed',
    0x04000000: 'InodeMetaMod',
    0x08000000: 'Renamed',
    0x10000000: 'Modified',
    0x20000000: 'Exchange',
    0x40000000: 'FinderInfoMod',
    0x80000000: 'FolderCreated'
}

#for x, y in EVENTMASK.items():
#    #print y, "%.8X"%x
#    print '  {} = 0x{:08X},'.format (y.rstrip(";"), x)

def ReadCString(buffer, buffer_size, start_pos):
    '''
    Reads null-terminated string starting at start_pos in buffer.
    Returns tuple (string, end_pos)
    '''
    end_pos = start_pos
    string = ""
    ch = ''
    while end_pos < buffer_size:
        ch = buffer[end_pos]
        if ch == '\x00':
            break
        else:
            end_pos += 1
            string += ch
    return string, end_pos + 1

def ParseData(buffer, out_file):
    global total_logs_processed
    buffer_size = len(buffer)
    if buffer_size < 12:
        print "Error, too small buffer ( < 12)"
        return
    
    header_sig, unknown, file_size = struct.unpack("<4sII", buffer[0:12])
    is_version2 = (header_sig == '2SLD') 
    is_version_unknown = (not is_version2) and (header_sig != '1SLD')

    if is_version_unknown:
        print "Unsupported version, header = {}".format(header_sig)
        return
    
    pos = 12

    if is_version2:
        while pos < buffer_size:
            log_filepath, pos = ReadCString(buffer, buffer_size, pos)
            log_id, log_event_flag, log_file_id = struct.unpack("<QIQ", buffer[pos:pos+20])
            pos += 20
            total_logs_processed += 1
            out_file.write("{:016X}\t{:08X}\t{}\t{}\r\n".format(log_id, log_event_flag, log_filepath, log_file_id))
    else:
        while pos < buffer_size:
            log_filepath, pos = ReadCString(buffer, buffer_size, pos)
            log_id, log_event_flag = struct.unpack("<QI", buffer[pos:pos+12])
            pos += 12
            log_file_id = None
            total_logs_processed += 1
            out_file.write("{:016X}\t{:08X}\t{}\t{}\r\n".format(log_id, log_event_flag, log_filepath, log_file_id))

total_logs_processed = 0

print "DONT RUN ME !!!!"
import sys
sys.exit()

with open ("G:\\temp\\fsevts\\hs\\.fseventsd\\0000000000641196", 'rb') as f:
    with open ("C:\\temp\\fsevt\\hs.0000000000641196.txt", 'wb') as csv:
        csv.write("log_id\tlog_event_flag\tlog_filepath\tlog_file_id\r\n")
        z = zlib.decompressobj(31)
        uncompressed_count = 0
        uncompressed_data = b''
        gzip_start = 0
        #out_file = open("C:\\temp\\0.out", 'wb')
        while True:
            if z.unused_data == "":
                buf = f.read(65536)
                if buf == "":
                    break
            else:
                buf = z.unused_data
                print "decompressed={} bytes from gzip at pos={}".format(uncompressed_count, gzip_start)
                #out_file.write(uncompressed_data)
                #out_file.close()
                ParseData(uncompressed_data, csv)

                uncompressed_data = b''
                uncompressed_count = 0
                gzip_start = f.tell() - len(buf)
                #out_file = open("C:\\temp\\{}.out".format(gzip_start), 'wb')
                z = zlib.decompressobj(31)
            uncompressed_data_temp = z.decompress(buf)
            uncompressed_data  += uncompressed_data_temp
            uncompressed_count += len(uncompressed_data_temp)
        print "decompressed={} bytes from gzip at pos={}".format(uncompressed_count, gzip_start)
        #out_file.write(uncompressed_data)
        #out_file.close()
        ParseData(uncompressed_data, csv)

    print "total_logs_processed={}".format(total_logs_processed)