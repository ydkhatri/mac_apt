'''
   Copyright (c) 2024 Yuya Hashimoto

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the
   terms of the MIT License.

'''

import os
import struct
import datetime

from plugins.helpers.macinfo import *
from plugins.helpers.writer import *

import logging

__Plugin_Name = "ASL"
__Plugin_Friendly_Name = "Asl"
__Plugin_Version = "1.1"
__Plugin_Description = 'Reads macOS ASL (Apple System Log) from asl.log, asl.db, and ".asl" files.'
__Plugin_Author = "Yuya Hashimoto"
__Plugin_Author_Email = "yhashimoto0707@gmail.com"

__Plugin_Modes = "MACOS,ARTIFACTONLY"
__Plugin_ArtifactOnly_Usage = "Provide the path to folder containing asl files"

log = logging.getLogger('MAIN.' + __Plugin_Name) # Do not rename or remove this ! This is the logger object

#---- Do not change the variable names in above section ----#

#  Processes ASL files
#      /private/var/log/asl.log (macOS 10.4)
#      /private/var/log/asl.db (macOS 10.5 - 10.5.5)
#      /private/var/log/asl/*.asl (macOS 10.5.6 -)

#_ASL_DB_COOKIE = b"ASL DB\x00\x00\x00\x00\x00\x00"
_ASL_DB_COOKIE = b"ASL DB"
_ASL_DB_COOKIE_LEN = 6
_DB_HEADER_VERS_OFFSET = 12
_DB_VERSION_TXT = 0
_DB_VERSION_LEGACY_1 = 1
_DB_VERSION_2 = 2

_DB_TYPE_MESSAGE= 2
_DB_TYPE_KVLIST = 3
_DB_TYPE_STRING = 4
_DB_TYPE_STRCONT = 5
_ASL_FILE_TYPE_STR = 1

_ASL_LEVEL = ["Emergency", "Alert", "Critical", "Error", "Warning", "Notice", "Info", "Debug"]

data_name_text = "asl_text"
data_description_text = "asl.log (in text format) entries"
data_type_info_text = [ ("Time",DataType.TEXT), ("Facility",DataType.TEXT), ("Sender",DataType.TEXT),
                   ("PID", DataType.INTEGER), ("Message",DataType.TEXT), ("Level", DataType.TEXT),
                   ("UID", DataType.INTEGER), ("GID", DataType.INTEGER), ("Host",DataType.TEXT),
                   ("Source",DataType.TEXT)]

data_name_legacy = "asl_legacy"
data_description_legacy = "asl.db (legacy) entries"
data_type_info_legacy = [ ("Time",DataType.DATE), ("Host",DataType.TEXT), ("Sender",DataType.TEXT),
                          ("Facility",DataType.TEXT), ("Level", DataType.TEXT), ("PID", DataType.INTEGER),
                          ("UID", DataType.INTEGER), ("GID", DataType.INTEGER), ("ID", DataType.INTEGER),
                          ("Message",DataType.TEXT), ("Key_Value",DataType.TEXT), ("Source",DataType.TEXT) ]

data_name_ver2 = "asl_ver2"
data_description_ver2 = "asl (version 2) entries"
data_type_info_ver2 = [ ("Timestamp",DataType.DATE), ("Nano",DataType.INTEGER), ("ID", DataType.INTEGER),
                        ("Flags", DataType.INTEGER), ("Host", DataType.TEXT), ("Sender", DataType.TEXT),
                        ("Facility", DataType.TEXT), ("Level", DataType.TEXT), ("PID", DataType.INTEGER),
                        ("UID", DataType.INTEGER), ("GID", DataType.INTEGER), ("RefProc", DataType.TEXT),
                        ("RefPID", DataType.INTEGER), ("Message", DataType.TEXT), ("Session", DataType.TEXT),
                        ("Key_Value", DataType.TEXT), ("Source", DataType.TEXT) ]

class AslText:

    def get_msg(self):
        _file = self.file
        _time = self.kvs["Time"] if "Time" in self.kvs else ""
        _facility = self.kvs["Facility"] if "Facility" in self.kvs else ""
        _sender = self.kvs["Sender"] if "Sender" in self.kvs else ""
        _pid = self.kvs["PID"] if "PID" in self.kvs else ""
        _message = self.kvs["Message"] if "Message" in self.kvs else ""
        _level = _ASL_LEVEL[int(self.kvs["Level"])] if "Level" in self.kvs and int(self.kvs["Level"]) < len(_ASL_LEVEL) else ""
        _uid = self.kvs["UID"] if "UID" in self.kvs else ""
        _gid = self.kvs["GID"] if "GID" in self.kvs else ""
        _host = self.kvs["Host"] if "Host" in self.kvs else ""
        return [_time, _facility, _sender, int(_pid), _message, _level, int(_uid), int(_gid), _host, _file]

    def __init__(self, file, line):
        self.file = file
        line = line.decode(errors="ignore")
        elements = line.split("] [")
        kvs = {}
        for element in elements:
            kv = element.strip("] [\n")
            pos = kv.find(" ")
            if pos != -1:
                key = kv[:pos]
                val = kv[pos:]
                kvs[key] = val.strip()
        self.kvs = kvs

class AslLegacy:
#  The file format is based on the description in asl_legacy1.h.
#  (https://github.com/apple-oss-distributions/Libc/blob/Libc-825.25/gen/asl_legacy1.h)

    def get_msg(self):

        _file = self.file
        _time = self.time
        _host = self.host
        _sender = self.sender
        _facility = self.facility
        _level = self.level
        _pid = self.pid
        _uid = self.uid
        _gid = self.gid
        _message = self.message
        _id = self.id
        if len(self.kvs) > 0:
            _kvs = str(self.kvs)
        else:
            _kvs = ""
        _type_of_rec = self.type_of_rec
        _next_rec = self.next_rec
        _ruid = self.ruid
        _rgid = self.rgid

        return [_time, _host, _sender, _facility, _level, int(_pid), int(_uid), int(_gid), int(_id), _message, _kvs, _file]
        
    def _get_asl_kvs(self, rec, kvs):

        _pos = rec * 80
        self.fd.seek(_pos)

        _type_of_rec, _next_rec, _count = struct.unpack(">B2I", self.fd.read(9))
        _kvs = kvs
        if _type_of_rec == _DB_TYPE_KVLIST:
            for i in range(_count):
                self.fd.seek(_pos + 9 + 8 * 2 * i)
                _k, _v = struct.unpack(">2Q", self.fd.read(16))
                _kvs[self._get_asl_str(_k)] = self._get_asl_str(_v)

        if _next_rec != 0:
            _kvs = self._get_asl_kvs(_next_rec, _kvs)
            
        return _kvs

    def _get_str_cont(self, rec, len):

        _str = ""
        _pos = rec * 80
        self.fd.seek(_pos)
        _type_of_rec, _next_rec = struct.unpack(">BI", self.fd.read(5))

        if len > 75:
            _str = self.fd.read(75).decode(errors="ignore")
            len = len - 75
        else:
            _str = self.fd.read(len -1).decode(errors="ignore")
            len = 0

        if _next_rec != 0:
            _str = _str + self._get_str_cont(_next_rec, len)
        
        return _str

    def _get_asl_str(self, val):
        _str = ""
        if val not in self.str_ids:
            if val & 0x8000000000000000 != 0:
                _bytes = struct.pack(">Q", val)
                _len = _bytes[0] & 0x7F
                _str = _bytes[1:1+_len].decode(errors="ignore")
        else:
            _pos = self.str_ids[val]
            self.fd.seek(_pos)
            _type_of_rec, _next_rec, _id, _refcount = struct.unpack(">BIQI", self.fd.read(17))

            if _type_of_rec == _DB_TYPE_STRING and _id == val:
                _hash = self.fd.read(4).hex()
                _length, = struct.unpack(">I", self.fd.read(4))

                self.fd.seek(_pos+25)
                if _length > 55:
                    _str = self.fd.read(55).decode(errors="ignore")
                    _length = _length - 55
                else:
                    _str = self.fd.read(_length-1).decode(errors="ignore")
                    _length = 0

                if _next_rec != 0:
                    _str = _str + self._get_str_cont(_next_rec, _length)
            else:
                log.error('Type or ID Not Match')

        return _str

    def __init__(self, file, fd, str_ids, id, pos):

        self.file = file
        self.fd = fd
        self.str_ids = str_ids
        self.pos = pos
        self.fd.seek(self.pos)

        _type_of_rec, _next_rec, _id, _ruid, \
        _rgid, _time, _host, _sender, _facility, \
        _level, _pid, _uid, _gid, _message, _flags = struct.unpack(">BIQ2I4Q4IQH", self.fd.read(79))

        _host = self._get_asl_str(_host)
        _sender = self._get_asl_str(_sender)
        _facility = self._get_asl_str(_facility)
        _message = self._get_asl_str(_message)

        self.type_of_rec = _type_of_rec
        self.id = id
        self.next_rec = _next_rec
        self.ruid = _ruid
        self.rgid = _rgid
        self.time = datetime.datetime.fromtimestamp(0) + datetime.timedelta(seconds=_time)
        self.host = _host
        self.sender = _sender
        self.facility = _facility
        self.message = _message
        self.level = _ASL_LEVEL[_level] if int(_level) < len(_ASL_LEVEL) else ""
        self.pid = _pid
        self.uid = _uid
        self.gid = _gid
        self.flags = _flags

        self.kvs = {}
        if self.next_rec != 0:
            self.kvs = self._get_asl_kvs(self.next_rec, {})


class AslVer2:
#  The file format is based on the description in asl_file.h.
#  (https://github.com/apple-oss-distributions/Libc/blob/Libc-825.25/gen/asl_file.h)

    def get_msg(self):

        _file = self.file
        _timestamp = self.timestamp
        _nano = self.nano
        _host = self.host
        _sender = self.sender
        _facility = self.facility
        _level = self.level
        _pid = self.pid
        _uid = self.uid
        _gid = self.gid
        _refpid = self.refpid
        _message = self.message
        _flags = self.flags
        _id = self.id
        _session = self.session
        _refproc = self.refproc

        if len(self.kvs) > 0:
            _kvs = str(self.kvs)
        else:
            _kvs = ""

        _ruid = self.ruid
        _rgid = self.rgid
        return [_timestamp, int(_nano), int(_id), int(_flags), _host,
                _sender, _facility, _level, int(_pid), int(_uid), int(_gid),
                _refproc, int(_refpid), _message, _session, _kvs, _file]

    def _get_asl_str(self, val):
        _str = ""
        if val == 0:
            return _str

        if val & 0x8000000000000000 == 0:
            self.fd.seek(val)
            _type_of_rec, = struct.unpack(">H",self.fd.read(2))
            if _type_of_rec != _ASL_FILE_TYPE_STR:
                log.error('Type Not Match')
            else:
                _len, = struct.unpack(">I", self.fd.read(4))
                _str = self.fd.read(_len - 1).decode(errors="ignore")
        else:
            _bytes = struct.pack(">Q", val)
            _len = _bytes[0] & 0x7F
            _str = _bytes[1:1+_len].decode(errors="ignore")
        return _str

    def __init__(self, file, fd, pos):

        self.file = file
        self.pos = pos
        self.fd = fd

        self.fd.seek(self.pos+2)
        _len, _next_rec, _id, _time, _nano, \
        _level, _flags, _pid, _uid, _gid, _ruid, \
        _rgid, _refpid, _kv_count, _host, _sender, \
        _facility, _message, _refproc, _session = struct.unpack(">I3QI2H7I6Q", self.fd.read(112))

        _kvs = {}
        for i in range(_kv_count//2):
            self.fd.seek(pos+114 + 16 *i)
            _k, _v = struct.unpack(">2Q", self.fd.read(16))
            _kvs[self._get_asl_str(_k)] = self._get_asl_str(_v)

        _host = self._get_asl_str(_host)
        _sender = self._get_asl_str(_sender)
        _refproc = self._get_asl_str(_refproc)
        _facility = self._get_asl_str(_facility)
        _message = self._get_asl_str(_message)
        _session = self._get_asl_str(_session)

        self.id = _id
        self.timestamp = datetime.datetime.fromtimestamp(0) + datetime.timedelta(seconds=_time)
        self.nano = _nano
        self.level = _ASL_LEVEL[_level] if int(_level) < len(_ASL_LEVEL) else ""
        self.flags = _flags
        self.pid = _pid
        self.uid = _uid
        self.gid = _gid
        self.ruid = _ruid
        self.rgid = _rgid
        self.refpid = _refpid
        self.host = _host
        self.sender = _sender
        self.facility = _facility
        self.message = _message
        self.refproc = _refproc
        self.session = _session
        self.kvs = _kvs

class Asl:

    def get_version(self):
        return self.version

    def __init__(self, fd, size, file):
        self.version = -1
        try:
            _fd = fd
            _size = size
        except Exception as ex:
            log.exception("Could not open file '{0}' ({1})".format(file, ex))
            return

        self.file = file
        self.fd = _fd
        self.size = _size

        _cookie = self.fd.read(_ASL_DB_COOKIE_LEN)
        if _cookie == _ASL_DB_COOKIE:
            self.fd.seek(_DB_HEADER_VERS_OFFSET)
            self.version, = struct.unpack(">I", self.fd.read(4))

            if self.version == _DB_VERSION_LEGACY_1:
                self.max_id, = struct.unpack(">Q", self.fd.read(8))
                self.fd.read(56)

                self.msg_ids = {}
                self.str_ids = {}
                _pos = self.fd.tell()
                while _pos < self.size:
                    self.fd.seek(_pos)
                    _type_of_rec, = struct.unpack(">B",self.fd.read(1))
                    if _type_of_rec == _DB_TYPE_MESSAGE:
                        self.fd.seek(_pos + 5)
                        _id, = struct.unpack(">Q", self.fd.read(8))
                        self.msg_ids[_id] = _pos
                    elif _type_of_rec == _DB_TYPE_STRING:
                        self.fd.seek(_pos + 5)
                        _id, = struct.unpack(">Q", self.fd.read(8))
                        self.str_ids[_id] = _pos
                    _pos += 80
                self.msg_ids = dict(sorted(self.msg_ids.items()))

            elif self.version == _DB_VERSION_2:
                self.first_rec, td = struct.unpack(">Qq", self.fd.read(16))
                try:
                    timedelta = datetime.timedelta(seconds=td)
                    self.time = datetime.datetime.fromtimestamp(0) + timedelta
                except:
                    log.exception('Time exception')
                self.string_cache_size, = struct.unpack(">I", self.fd.read(4))
                self.fd.read(1)
                self.last_rec, = struct.unpack(">Q", self.fd.read(8))
                self.fd.read(35)
                self.msg_pos = []
                self.msg_pos.append(self.first_rec)
                _current_rec = self.first_rec

                while _current_rec != self.last_rec:
                    self.fd.seek(_current_rec + 6)
                    _next_rec, = struct.unpack(">Q", self.fd.read(8))
                    self.msg_pos.append(_next_rec)
                    _current_rec = _next_rec

        else:
            self.fd.seek(0)
            if self.fd.read(5).decode(errors="ignore") == "[Time":
                self.version = _DB_VERSION_TXT
            self.fd.seek(0)

    def __iter__(self):
        if self.version == _DB_VERSION_TXT:
            for l in self.fd: # BUG? won't work as file is opened in 'b' mode
                yield AslText(self.file, l)
        if self.version == _DB_VERSION_LEGACY_1:
            for id, pos in self.msg_ids.items():
                yield AslLegacy(self.file, self.fd, self.str_ids, id, pos)
        elif self.version == _DB_VERSION_2:
            for pos in self.msg_pos:
                yield AslVer2(self.file, self.fd, pos)

def CreateXlsxFile(output_path):

    try:
        xlsx_path = os.path.join(output_path, "ASL.xlsx")
        log.info("Creating xlsx file for asl @ {}".format(xlsx_path))
        xlsx_writer = ExcelWriter()
        xlsx_writer.CreateXlsxFile(xlsx_path)
        return xlsx_writer
    except (xlsxwriter.exceptions.XlsxWriterException, OSError) as ex:
        log.error('xlsx file could not be created at : ' + xlsx_path)
        log.exception('Exception occurred when trying to create xlsx file')
        return None

def CopyOutputParams(output_params):

    op_copy = OutputParams()
    op_copy.output_path = output_params.output_path
    op_copy.write_csv = output_params.write_csv
    op_copy.write_tsv = output_params.write_tsv
    op_copy.write_sql = output_params.write_sql
    op_copy.write_xlsx = output_params.write_xlsx
    op_copy.write_jsonl = output_params.write_jsonl
    if op_copy.write_xlsx:
        op_copy.xlsx_writer = CreateXlsxFile(op_copy.output_path)
    else:
        op_copy.write_xlsx = False
        op_copy.xlsx_writer = output_params.write_xlsx
    op_copy.output_db_path = output_params.output_db_path
    op_copy.export_path = output_params.export_path
    op_copy.export_log_sqlite = output_params.export_log_sqlite
    op_copy.timezone = output_params.timezone
    return op_copy

def CreateSqliteDb(output_path, out_params):

    try:
        sqlite_writer = SqliteWriter()
        sqlite_path = os.path.join(output_path, "ASL.db")
        out_params.output_db_path = sqlite_writer.CreateSqliteDb(sqlite_path)
        log.info("Creating sqlite db for asl @ {}".format(out_params.output_db_path))
        return True
    except sqlite3.Error as ex:
        log.error('Sqlite db could not be created at : ' + sqlite_path)
        log.exception('Exception occurred when trying to create Sqlite db')
        return False

def Process_Asl_File(mac_info, out_params, asl_file, writer, data_description, data_name, data_type_info):

    msgs = []
    if mac_info is None: # for artifact_only
        try:
            size = os.path.getsize(asl_file)
            fd = open(asl_file, 'rb')
            asl = Asl(fd, size, asl_file)
        except Exception as e:
            log.exception("Could not read file as ASL DB '{0}' ({1}): Skipping this file".format(asl_file, e))
            return
    else:
        try:
            size = mac_info.GetFileSize(asl_file)
            fd = mac_info.Open(asl_file)
            asl = Asl(fd, size, asl_file)
        except Exception as e:
            log.exception("Could not read file as ASL DB '{0}' ({1}): Skipping this file".format(asl_file, e))
            return

    _v = asl.get_version()
    if _v == _DB_VERSION_TXT or _v == _DB_VERSION_LEGACY_1 or _v == _DB_VERSION_2:
        for msg in asl:
            msgs.append(msg.get_msg())
        writer.WriteListPartial(data_description, data_name, msgs, data_type_info, out_params)

def Recurse_Process_Asl_Files(mac_info, out_params, asl_files):

    if _DB_VERSION_TXT in asl_files:
        writer = ChunkedDataWriter()
        for _f in asl_files[_DB_VERSION_TXT]:
            Process_Asl_File(mac_info, out_params, _f, writer, data_description_text, data_name_text, data_type_info_text)
        writer.FinishWrites()

    if _DB_VERSION_LEGACY_1 in asl_files:
        writer = ChunkedDataWriter()
        for _f in asl_files[_DB_VERSION_LEGACY_1]:
            Process_Asl_File(mac_info, out_params, _f, writer, data_description_legacy, data_name_legacy, data_type_info_legacy)
        writer.FinishWrites()

    if _DB_VERSION_2 in asl_files:
        writer = ChunkedDataWriter()
        for _f in asl_files[_DB_VERSION_2]:
            Process_Asl_File(mac_info, out_params, _f, writer, data_description_ver2, data_name_ver2, data_type_info_ver2)
        writer.FinishWrites()

    if out_params.write_xlsx:
        out_params.xlsx_writer.CommitAndCloseFile()


def Plugin_Start(mac_info):
    '''Main Entry point function for plugin'''

    # asl path
    asl_text_path = "/private/var/log/asl.log"
    asl_legacy_path = "/private/var/log/asl.db"
    asl_ver2_folder_paths = ("/private/var/log/asl/", "/private/var/log/DiagnosticMessages/")
    asl_files = {}

    if mac_info.IsValidFilePath(asl_text_path):
        mac_info.ExportFile(asl_text_path, __Plugin_Name, "", False, False)
        asl_files[_DB_VERSION_TXT] = [asl_text_path]
    
    if mac_info.IsValidFilePath(asl_legacy_path):
        mac_info.ExportFile(asl_legacy_path, __Plugin_Name, "", False, False)
        asl_files[_DB_VERSION_LEGACY_1] = [asl_legacy_path]

    asl_ver2_files = []
    for asl_ver2_folder_path in asl_ver2_folder_paths:    
        if mac_info.IsValidFolderPath(asl_ver2_folder_path):
            _items = mac_info.ListItemsInFolder(asl_ver2_folder_path, EntryType.FILES)
            for _i in _items:
                if _i['name'].endswith(".asl"):
                    mac_info.ExportFile(asl_ver2_folder_path + _i['name'], __Plugin_Name, "", False, False)
                    asl_ver2_files.append(asl_ver2_folder_path + _i['name'])
    if asl_ver2_files:
        asl_files[_DB_VERSION_2] = asl_ver2_files

    try:
        output_path = mac_info.output_params.output_path
        out_params = CopyOutputParams(mac_info.output_params)
        if CreateSqliteDb(output_path, out_params):
            Recurse_Process_Asl_Files(mac_info, out_params, asl_files)
    except:
        log.exception('')

def Plugin_Start_Standalone(input_files_list, output_params):
    log.info("Module Started as standalone")
    asl_files = {}
    asl_ver2_files = []
    asl_text_files = []
    for input_path in input_files_list:
        if not os.path.isdir(input_path):
            log.error(f'Input path is not a folder: {input_path}')
            continue
        log.debug("Input folder passed was: " + input_path)
        for name in os.listdir(input_path):
            file_path = os.path.join(input_path, name)
            if name.lower().endswith(".asl"):
                asl_ver2_files.append(file_path)
            elif name.lower().endswith("asl.log"):
                asl_text_files.append(file_path)
            if asl_text_files:
                asl_files[_DB_VERSION_TXT] = asl_text_files
            if asl_ver2_files:
                asl_files[_DB_VERSION_2] = asl_ver2_files
    if asl_files:
        try:
            output_path = output_params.output_path
            out_params = CopyOutputParams(output_params)
            if CreateSqliteDb(output_path, out_params):
                Recurse_Process_Asl_Files(None, out_params, asl_files)
        except:
            log.exception('')
    else:
        log.info('Nothing to process, no suitable asl files found.')

if __name__ == '__main__':
    print ("This plugin is a part of a framework and does not run independently on its own!")