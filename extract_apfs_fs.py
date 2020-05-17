'''
   Copyright (c) 2020 Yogesh Khatri

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the 
   terms of the MIT License.
   
   extract_apfs_fs.py
   ------------------
   This script only parses the APFS containers from a given disk image,
   it does not perform any other forensic processing. The output is 
   an sqlite database representing the APFS containers on disk.
   
   For usage information, run: 
     python extract_apfs_fs.py -h

   NOTE: This currently works only on Python3.7 or higher.
   
'''

import argparse
import logging
import os
import plugins.helpers.macinfo as macinfo
import pyewf
import pytsk3
import pyvmdk
import sys
import textwrap
import time
import traceback
from plugins.helpers.apfs_reader import ApfsContainer, ApfsDbInfo
from plugins.helpers.writer import *
from plugins.helpers.disk_report import *
from plugin import *
from pyaff4 import container
from uuid import UUID

__VERSION = "0.5"
__PROGRAMNAME = "APFS metadata extract Tool"
__EMAIL = "yogesh@swiftforensics.com"

def CheckInputType(input_type):
    input_type = input_type.upper()
    return input_type in ['AFF4','E01','DD','DMG','VMDK','MOUNTED']

######### FOR HANDLING E01 file ###############
class ewf_Img_Info(pytsk3.Img_Info):
  def __init__(self, ewf_handle):
    self._ewf_handle = ewf_handle
    super(ewf_Img_Info, self).__init__(
        url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

  def close(self):
    self._ewf_handle.close()

  def read(self, offset, size):
    self._ewf_handle.seek(offset)
    return self._ewf_handle.read(size)

  def get_size(self):
    return self._ewf_handle.get_media_size()

def PrintAttributes(obj, useTypeName=False):
    for attr in dir(obj):
        if str(attr).endswith("__"): continue
        if hasattr( obj, attr ):
            if useTypeName:
                log.info( "%s.%s = %s" % (type(obj).__name__, attr, getattr(obj, attr)))
            else:
                log.info( "%s = %s" % (attr, getattr(obj, attr)))

# Call this function instead of pytsk3.Img_Info() for E01 files
def GetImgInfoObjectForE01(path):
    filenames = pyewf.glob(path) # Must be path to E01
    ewf_handle = pyewf.handle()
    ewf_handle.open(filenames)
    img_info = ewf_Img_Info(ewf_handle)
    return img_info

####### End special handling for E01 #########

######### FOR HANDLING VMDK file ###############
class vmdk_Img_Info(pytsk3.Img_Info):
  def __init__(self, vmdk_handle):
    self._vmdk_handle = vmdk_handle
    super(vmdk_Img_Info, self).__init__(
        url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

  def close(self):
    self._vmdk_handle.close()

  def read(self, offset, size):
    self._vmdk_handle.seek(offset)
    return self._vmdk_handle.read(size)

  def get_size(self):
    return self._vmdk_handle.get_media_size()

def OpenExtentDataFiles(vmdk_handle, base_directory):
    '''Because vmdk_handle.open_extent_data_files() is broken in 20170226'''
    extent_data_files = []
    for extent_descriptor in vmdk_handle.extent_descriptors:
        extent_data_filename = extent_descriptor.filename

        _, path_separator, filename = extent_data_filename.rpartition("/")
        if not path_separator:
            _, path_separator, filename = extent_data_filename.rpartition("\\")

        if not path_separator:
            filename = extent_data_filename

        extent_data_file_path = os.path.join(base_directory, filename)

        if not os.path.exists(extent_data_file_path):
            break

        extent_data_files.append(extent_data_file_path)

    if len(extent_data_files) != vmdk_handle.number_of_extents:
        raise RuntimeError("Unable to locate all extent data files.")

    file_objects = []
    for extent_data_file_path in extent_data_files:
        file_object = open(extent_data_file_path, "rb")
        file_objects.append(file_object)

    vmdk_handle.open_extent_data_files_file_objects(file_objects)

def GetImgInfoObjectForVMDK(path):
    vmdk_handle = pyvmdk.handle()
    vmdk_handle.open(path)
    base_directory = os.path.dirname(path)
    #vmdk_handle.open_extent_data_files() Broken in current version #20170226
    OpenExtentDataFiles(vmdk_handle, base_directory)
    img_info = vmdk_Img_Info(vmdk_handle)
    return img_info
####### End special handling for VMDK #########

######### FOR HANDLING AFF4 file ###############
class aff4_Img_Info(pytsk3.Img_Info):
  def __init__(self, aff4_stream):
    self._aff4_stream = aff4_stream
    super(aff4_Img_Info, self).__init__(
        url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

  def close(self):
    self._aff4_stream.Close()

  def read(self, offset, size):
    self._aff4_stream.SeekRead(offset)
    return self._aff4_stream.Read(size)

  def get_size(self):
    return self._aff4_stream.Size()

# Call this function instead of pytsk3.Img_Info() for AFF4 files
def GetImgInfoObjectForAff4(path):
    aff4_map_stream = container.Container.open(path)
    img_info = aff4_Img_Info(aff4_map_stream)
    return img_info

####### End special handling for AFF4 #########

def IsApfsContainer(img, partition_start_offset):
    '''Checks if this is an APFS container'''
    try:
        if img.read(partition_start_offset + 0x20, 4) == b'NXSB':
            return True
    except:
        raise ValueError('Cannot seek into image @ offset {}'.format(partition_start_offset + 0x20))
    return False

def GetApfsContainerUuid(img, container_start_offset):
    '''Returns a UUID object'''
    uuid_bytes = img.read(container_start_offset + 72, 16)
    uuid = UUID(bytes=uuid_bytes)
    return uuid

def IsHFSVolume(img, partition_start_offset):
    '''Checks if this is an HFS volume'''
    try:
        if img.read(partition_start_offset + 0x400, 2) in (b'\x48\x58', b'\x48\x2B'):
            return True
    except:
        raise ValueError('Cannot seek into image @ offset {}'.format(partition_start_offset + 0x400))
    return False

def IsHFSPartition(img, partition_start_offset):
    '''Determines if the partition is HFS by mounting it'''
    try:
        fs = pytsk3.FS_Info(img, offset=partition_start_offset)    
        fs_info = fs.info # TSK_FS_INFO
        return fs_info.ftype == pytsk3.TSK_FS_TYPE_HFS_DETECT
    except Exception as ex:
        log.exception("Exception")
    return False

def ParseVolumesInApfsContainer(img, vol_info, container_size, container_start_offset, container_uuid):
    global mac_info
    mac_info = macinfo.ApfsMacInfo(mac_info.output_params, mac_info.password)
    mac_info.pytsk_image = img   # Must be populated
    mac_info.vol_info = vol_info # Must be populated
    mac_info.is_apfs = True
    mac_info.macos_partition_start_offset = container_start_offset # apfs container offset
    mac_info.apfs_container = ApfsContainer(img, container_size, container_start_offset)
    # Check if this is 10.15 style System + Data volume?
    for vol in mac_info.apfs_container.volumes:
        #if vol.is_encrypted: continue
        if vol.role == vol.container.apfs.VolumeRoleType.system.value:
            log.debug("{} is SYSTEM volume type".format(vol.volume_name))
            mac_info.apfs_sys_volume = vol
        elif vol.role == vol.container.apfs.VolumeRoleType.data.value:
            log.debug("{} is DATA volume type".format(vol.volume_name))
            mac_info.apfs_data_volume = vol
    try:
        # start db
        use_existing_db = False
        apfs_sqlite_path = os.path.join(mac_info.output_params.output_path, "APFS_Volumes_" + str(container_uuid).upper() + ".db")
        if os.path.exists(apfs_sqlite_path): # Check if db already exists
            existing_db = SqliteWriter()     # open & check if it has the correct data
            existing_db.OpenSqliteDb(apfs_sqlite_path)
            apfs_db_info = ApfsDbInfo(existing_db)
            if apfs_db_info.CheckVerInfo() and apfs_db_info.CheckVolInfoAndGetVolEncKey(mac_info.apfs_container.volumes):
                # all good, db is up to date, use it
                use_existing_db = True
                mac_info.apfs_db = existing_db
                if mac_info.apfs_sys_volume:
                    mac_info.apfs_data_volume.dbo = mac_info.apfs_db
                    mac_info.apfs_sys_volume.dbo = mac_info.apfs_db
                    mac_info.UseCombinedVolume()
                log.info('Found an existing APFS_Volumes.db in the output folder, looks good, will not create a new one!')
            else:
                # db does not seem up to date, create a new one and read info
                existing_db.CloseDb()
                log.info('Found an existing APFS_Volumes.db in the output folder, but it is STALE, creating a new one!')
                os.remove(apfs_sqlite_path)
        if not use_existing_db:
            apfs_sqlite_path = SqliteWriter.CreateSqliteDb(apfs_sqlite_path) # Will create with next avail file name
            mac_info.apfs_db = SqliteWriter()
            mac_info.apfs_db.OpenSqliteDb(apfs_sqlite_path)
            try:
                log.info('Reading APFS volumes from container, this may take a few minutes ...')
                mac_info.ReadApfsVolumes()
                apfs_db_info = ApfsDbInfo(mac_info.apfs_db)
                apfs_db_info.WriteVolInfo(mac_info.apfs_container.volumes)
                if mac_info.apfs_sys_volume:
                    mac_info.apfs_data_volume.dbo = mac_info.apfs_db
                    mac_info.apfs_sys_volume.dbo = mac_info.apfs_db
                    if not mac_info.CreateCombinedVolume():
                        return False
                apfs_db_info.WriteVersionInfo()
            except:
                log.exception('Error while reading APFS volumes')
                return False
        mac_info.output_params.apfs_db_path = apfs_sqlite_path
        if mac_info.apfs_db != None:
            mac_info.apfs_db.CloseDb()
            mac_info.apfs_db = None

        return True
    except Exception as ex:
        log.info('Sqlite db could not be created at : ' + apfs_sqlite_path)
        log.exception('Exception occurred when trying to create APFS_Volumes Sqlite db')
    return False

def ParsePartitionTables(img, vol_info, vs_info):
    for part in vol_info:
        if (int(part.flags) & pytsk3.TSK_VS_PART_FLAG_ALLOC):
            partition_start_offset = vs_info.block_size * part.start
            if part.desc.decode('utf-8').upper() == "EFI SYSTEM PARTITION":
                log.debug ("Skipping EFI System Partition @ offset {}".format(partition_start_offset))
                continue # skip this
            elif part.desc.decode('utf-8').upper() == "APPLE_PARTITION_MAP":
                log.debug ("Skipping Apple_partition_map @ offset {}".format(partition_start_offset))
                continue # skip this
            else:
                log.info ("Looking at FS with volume label '{}'  @ offset {}".format(part.desc.decode('utf-8'), partition_start_offset)) 
            
            if IsApfsContainer(img, partition_start_offset):
                uuid = GetApfsContainerUuid(img, partition_start_offset)
                log.info('Found an APFS container with uuid: {}'.format(str(uuid).upper()))
                return ParseVolumesInApfsContainer(img, vol_info, vs_info.block_size * part.len, partition_start_offset, uuid)

            elif IsHFSVolume(img, partition_start_offset):
                log.info('Found HFS partition, skipping..')
            else:
                log.info("Found unknown partition, skipping..")
                
    return False

def Exit(message=''):
    if log and (len(message) > 0):
        log.info(message)
        sys.exit()
    else:
        sys.exit(message)

## Main program ##

log = None

arg_parser = argparse.ArgumentParser(description='extract_apfs_fs is a script to read APFS metadata from an image\n'\
                                                 'You are running {} version {}'.format(__PROGRAMNAME, __VERSION),
                                    epilog='', formatter_class=argparse.RawTextHelpFormatter)
arg_parser.add_argument('input_type', help='Specify Input type as either E01, DD, DMG, VMDK, AFF4')
arg_parser.add_argument('input_path', help='Path to disk image/volume')
arg_parser.add_argument('-o', '--output_path', help='Path where output files will be created')
arg_parser.add_argument('-l', '--log_level', help='Log levels: INFO, DEBUG, WARNING, ERROR, CRITICAL (Default is INFO)')#, choices=['INFO','DEBUG','WARNING','ERROR','CRITICAL'])
arg_parser.add_argument('-p', '--password', help='Password for any user (for decrypting encrypted volume)')
args = arg_parser.parse_args()

if args.output_path:
    if (os.name != 'nt'):
        if args.output_path.startswith('~/') or args.output_path == '~': # for linux/mac, translate ~ to user profile folder
            args.output_path = os.path.expanduser(args.output_path)

    args.output_path = os.path.abspath(args.output_path)
    print ("Output path was : {}".format(args.output_path))
    if not CheckOutputPath(args.output_path):
        Exit()
else:
    args.output_path = os.path.abspath('.') # output to same folder as script.

if args.log_level:
    args.log_level = args.log_level.upper()
    if not args.log_level in ['INFO','DEBUG','WARNING','ERROR','CRITICAL']: # TODO: change to just [info, debug, error]
        Exit("Invalid input type for log level. Valid values are INFO, DEBUG, WARNING, ERROR, CRITICAL")
    else:
        if args.log_level == "INFO": args.log_level = logging.INFO
        elif args.log_level == "DEBUG": args.log_level = logging.DEBUG
        elif args.log_level == "WARNING": args.log_level = logging.WARNING
        elif args.log_level == "ERROR": args.log_level = logging.ERROR
        elif args.log_level == "CRITICAL": args.log_level = logging.CRITICAL
else:
    args.log_level = logging.INFO
log = CreateLogger(os.path.join(args.output_path, "Log." + str(time.strftime("%Y%m%d-%H%M%S")) + ".txt"), args.log_level, args.log_level) # Create logging infrastructure
log.setLevel(args.log_level)
log.info("Started {}, version {}".format(__PROGRAMNAME, __VERSION))
log.info("Dates and times are in UTC unless the specific artifact being parsed saves it as local time!")
log.debug(' '.join(sys.argv))
LogLibraryVersions(log)

# Check inputs
if not CheckInputType(args.input_type): 
    Exit("Exiting -> 'input_type' " + args.input_type + " not recognized")

# Check outputs, create output files
output_params = macinfo.OutputParams()
output_params.output_path = args.output_path
try:
    sqlite_path = os.path.join(output_params.output_path, "disk_info.db")
    output_params.output_db_path = SqliteWriter.CreateSqliteDb(sqlite_path)
    output_params.write_sql = True
except Exception as ex:
    log.info('Sqlite db could not be created at : ' + sqlite_path)
    log.exception('Exception occurred when trying to create Sqlite db')
    Exit()

try:
    xlsx_path = os.path.join(output_params.output_path, "disk_info.xlsx")
    output_params.xlsx_writer = ExcelWriter()
    output_params.xlsx_writer.CreateXlsxFile(xlsx_path)
    output_params.write_xlsx = True
except Exception as ex:
    log.info('XLSX file could not be created at : ' + xlsx_path)
    log.exception('Exception occurred when trying to create XLSX file')


# At this point, all looks good, lets mount the image
img = None
found_macos = False
mac_info = None
time_processing_started = time.time()
try:
    if args.input_type.upper() == 'E01':
        img = GetImgInfoObjectForE01(args.input_path)
        mac_info = macinfo.MacInfo(output_params)
    elif args.input_type.upper() == 'VMDK':
        img = GetImgInfoObjectForVMDK(args.input_path)
        mac_info = macinfo.MacInfo(output_params)
    elif args.input_type.upper() == 'AFF4':
        img = GetImgInfoObjectForAff4(args.input_path)
        mac_info = macinfo.MacInfo(output_params)
    elif args.input_type.upper() in ('DD', 'DMG'):
        img = pytsk3.Img_Info(args.input_path) # Works for split dd images too! Works for DMG too, if no compression/encryption is used!
        mac_info = macinfo.MacInfo(output_params)

    log.info("Opened image " + args.input_path)
except Exception as ex:
    log.error("Failed to load image. Error Details are: " + str(ex))
    Exit()

if args.password:
    mac_info.password = args.password
mac_info.use_native_hfs_parser = True #False if args.use_tsk else True

mac_info.pytsk_image = img
if IsApfsContainer(img, 0):
    uuid = GetApfsContainerUuid(img, 0)
    log.info('Found an APFS container with uuid: {}'.format(str(uuid).upper()))
    ParseVolumesInApfsContainer(img, None, img.get_size(), 0, uuid)
elif IsHFSVolume(img, 0):
    log.info('Found an HFS partition, skipping it..')
else: # perhaps this is a full disk image
    try:
        vol_info = pytsk3.Volume_Info(img)
        vs_info = vol_info.info # TSK_VS_INFO object
        mac_info.vol_info = vol_info
        # Try as a partition/container first
        ParsePartitionTables(img, vol_info, vs_info)
        Disk_Info(mac_info, args.input_path).Write()
    except Exception as ex:
        log.exception("Error while trying to read partitions on disk")

log.info("-"*50)

# Final cleanup
if img != None: img.close()

output_params.xlsx_writer.CommitAndCloseFile()
if mac_info.is_apfs and mac_info.apfs_db != None:
    mac_info.apfs_db.CloseDb()

time_processing_ended = time.time()
run_time = time_processing_ended - time_processing_started
log.info("Finished in time = {}".format(time.strftime('%H:%M:%S', time.gmtime(run_time))))
log.info("Review the Log file and report any ERRORs or EXCEPTIONS to the developers")