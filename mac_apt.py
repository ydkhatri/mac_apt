'''
   Copyright (c) 2017 Yogesh Khatri

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the 
   terms of the MIT License.
   
   mac_apt.py
   ----------
   This is the main launcher script, which loads evidence, loads user
   preferences, loads plugins and starts processing. 
   
   For usage information, run: 
     python mac_apt.py -h

   NOTE: This currently works only on Python2.
   
'''
from __future__ import print_function
from __future__ import unicode_literals

import sys
import os
import argparse
import pyewf
import pytsk3
import traceback
import plugins.helpers.macinfo as macinfo
from plugins.helpers.apfs_reader import ApfsContainer, ApfsDbInfo
from plugins.helpers.writer import *
from plugins.helpers.disk_report import *
import logging
import time
import textwrap
from plugin import *

__VERSION = "0.1"
__PROGRAMNAME = "macOS Artifact Parsing Tool"
__EMAIL = "yogesh@swiftforensics.com"


def IsItemPresentInList(collection, item):
    try:
        collection.index(item)
        return True
    except Exception:
        pass
    return False

def CheckInputType(input_type):
    input_type = input_type.upper()
    return input_type in ['E01','DD','MOUNTED']

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

def FindOsxFiles(mac_info):
    if mac_info.IsValidFilePath('/System/Library/CoreServices/SystemVersion.plist'):
        if mac_info.IsValidFilePath("/System/Library/Kernels/kernel") or \
            mac_info.IsValidFilePath( "/mach_kernel"):
            log.info ("Found valid OSX/macOS kernel")
        else:
            log.info ("Could not find OSX/macOS kernel!")# On partial/corrupted images, this may not be found
        mac_info._GetSystemInfo()
        mac_info._GetUserInfo()
        #PrintAttributes(fs_info)
        return True
    else:
        log.info ("Could not find OSX/macOS installation!")
    return False

def IsOsxPartition(img, partition_start_offset, mac_info):
    '''Determines if the partition contains OSX installation'''
    try:
        fs = pytsk3.FS_Info(img, offset=partition_start_offset)    
        fs_info = fs.info # TSK_FS_INFO
        if (fs_info.ftype != pytsk3.TSK_FS_TYPE_HFS_DETECT):
            log.info (" Skipping non-HFS partition")
            return False

        # Found HFS partition, now look for osx files & folders
        try: 
            folders = fs.open_dir("/")
            mac_info.osx_FS = fs
            mac_info.osx_partition_start_offset = partition_start_offset
            return FindOsxFiles(mac_info)
        except Exception:
            log.error ("Could not open / (root folder on partition)")
            log.debug ("Exception info", exc_info=True)
    except Exception as ex:
        log.info(" Error: Failed to detect/parse file system!" + str(ex))
        log.exception("Exception") #traceback.print_exc(
    return False

def IsApfsContainer(img, partition_start_offset):
    '''Checks if this is an APFS container'''
    try:
        if img.read(partition_start_offset + 0x20, 4) == b'NXSB':
            return True
    except:
        raise 'Cannot seek into image @ offset {}'.format(partition_start_offset + 0x20)
    return False

def FindOsxPartitionInApfsContainer(img, vol_info, vs_info, part, partition_start_offset):
    global mac_info
    mac_info = macinfo.ApfsMacInfo(mac_info.output_params)
    mac_info.pytsk_image = img   # Must be populated
    mac_info.vol_info = vol_info # Must be populated
    mac_info.is_apfs = True
    mac_info.osx_partition_start_offset = partition_start_offset # apfs container offset
    mac_info.apfs_container = ApfsContainer(img, vs_info.block_size * part.len, partition_start_offset)
    try:
        # start db
        use_existing_db = False
        apfs_sqlite_path = os.path.join(mac_info.output_params.output_path, "APFS_Volumes.db")
        if os.path.exists(apfs_sqlite_path): # Check if db already exists
            existing_db = SqliteWriter()     # open & check if it has the correct data
            existing_db.OpenSqliteDb(apfs_sqlite_path)
            apfs_db_info = ApfsDbInfo(existing_db)
            if apfs_db_info.CheckVerInfo() and apfs_db_info.CheckVolInfo(mac_info.apfs_container.volumes):
                # all good, db is up to date, use it
                use_existing_db = True
                mac_info.apfs_db = existing_db
                log.info('Found an existing APFS_Volumes.db in the output folder, looks good, will not create a new one!')
            else:
                # db does not seem up to date, create a new one and read info
                existing_db.CloseDb()
        if not use_existing_db:
            apfs_sqlite_path = SqliteWriter.CreateSqliteDb(apfs_sqlite_path) # Will create with next avail file name
            mac_info.apfs_db = SqliteWriter()
            mac_info.apfs_db.OpenSqliteDb(apfs_sqlite_path)
            try:
                log.info('Reading APFS volumes from container, this may take a few minutes ...')
                mac_info.ReadApfsVolumes()
                apfs_db_info = ApfsDbInfo(mac_info.apfs_db)
                apfs_db_info.WriteVolInfo(mac_info.apfs_container.volumes)
                apfs_db_info.WriteVersionInfo()
            except:
                log.exception('Error while reading APFS volumes')
                return False
        mac_info.output_params.apfs_db_path = apfs_sqlite_path
        # Now search for osx partition in volumes
        for vol in mac_info.apfs_container.volumes:
            if vol.num_blocks_used * vol.container.block_size < 10000000000: # < 10 GB, cannot be a macOS installation volume
                continue
            mac_info.osx_FS = vol
            if FindOsxFiles(mac_info):
                return True
        # Did not find macOS installation
        mac_info.osx_FS = None

    except Exception as ex:
        log.info('Sqlite db could not be created at : ' + apfs_sqlite_path)
        log.exception('Exception occurred when trying to create APFS_Volumes Sqlite db')
    return False

def FindOsxPartition(img, vol_info, vs_info):
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
                log.debug('Found an APFS container')
                return FindOsxPartitionInApfsContainer(img, vol_info, vs_info, part, partition_start_offset)

            elif IsOsxPartition(img, partition_start_offset, mac_info): # Assumes there is only one single OSX installation partition
                return True
                
    return False

def Exit(message=''):
    if log and (len(message) > 0):
        log.info(message)
        sys.exit()
    else:
        sys.exit(message)

def SetupExportLogger(output_params):
    '''Creates the csv writer for logging files exported'''
    output_params.export_path = os.path.join(output_params.output_path, "Export")
    if not os.path.exists(output_params.export_path):
        try:
            os.makedirs(output_params.export_path)
        except Exception as ex:
            log.error("Exception while creating Export folder: " + output_params.export_path + "\n Is the location Writeable?" +
                    "Is drive full? Perhaps the drive is disconnected? Exception Details: " + str(ex))
            Exit()

    output_params.export_log_csv = CsvWriter()
    output_params.export_log_csv.CreateCsvFile(os.path.join(output_params.export_path, "Exported_Files_Log.csv"))
    column_info = collections.OrderedDict([ ('SourcePath',DataType.TEXT), ('ExportPath',DataType.TEXT),
                                            ('InodeModifiedTime',DataType.DATE),('ModifiedTime',DataType.DATE),
                                            ('CreatedTime',DataType.DATE),('AccessedTime',DataType.DATE) ])
    output_params.export_log_csv.WriteRow(column_info)

## Main program ##

plugins = []
log = None
plugin_count = ImportPlugins(plugins)
if plugin_count == 0:
    Exit ("No plugins could be added ! Exiting..")

plugin_name_list = ['ALL']
plugins_info = "The following plugins are available:\n" + " "*4 + "ALL" + " "*17 + "Processes all plugins" 
for plugin in plugins:
    plugins_info += "\n    {:<20}{}".format(plugin.__Plugin_Name, textwrap.fill(plugin.__Plugin_Description, subsequent_indent=' '*24, initial_indent=' '*24, width=80)[24:])
    plugin_name_list.append(plugin.__Plugin_Name)

arg_parser = argparse.ArgumentParser(description='mac_apt is a framework to process forensic artifacts on a Mac OSX system\n'\
                                                 'You are running {} version {}'.format(__PROGRAMNAME, __VERSION),
                                    epilog=plugins_info, formatter_class=argparse.RawTextHelpFormatter)
arg_parser.add_argument('input_type', help='Specify Input type as either E01, DD or MOUNTED')
arg_parser.add_argument('input_path', help='Path to OSX image/volume')
arg_parser.add_argument('-o', '--output_path', help='Path where output files will be created')
arg_parser.add_argument('-x', '--xlsx', action="store_true", help='Save output in excel spreadsheet(s)')
arg_parser.add_argument('-c', '--csv', action="store_true", help='Save output as CSV files (Default option if no output type selected)')
arg_parser.add_argument('-s', '--sqlite', action="store_true", help='Save output in an sqlite database')
arg_parser.add_argument('-l', '--log_level', help='Log levels: INFO, DEBUG, WARNING, ERROR, CRITICAL (Default is INFO)')#, choices=['INFO','DEBUG','WARNING','ERROR','CRITICAL'])
arg_parser.add_argument('plugin', nargs="+", help="Plugins to run (space seperated). 'ALL' will process every available plugin")
args = arg_parser.parse_args()

if args.output_path:
    print ("Output path was : {}".format(args.output_path))
    if not CheckOutputPath(args.output_path):
        Exit()
else:
    args.output_path = '.' # output to same folder as script.

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
log.info("Started {} program".format(__PROGRAMNAME))
log.info("Dates and times are in UTC unless the specific artifact being parsed saves it as local time!")
log.debug(' '.join(sys.argv))

# Check inputs
if not CheckInputType(args.input_type): 
    Exit("Exiting -> 'input_type' " + args.input_type + " not recognized")

plugins_to_run = [x.upper() for x in args.plugin]  # convert all plugin names entered by user to uppercase
process_all = IsItemPresentInList(plugins_to_run, 'ALL')
if not process_all:
    #Check for invalid plugin names or ones not Found
    if not CheckUserEnteredPluginNames(plugins_to_run, plugins):
        Exit("Exiting -> Invalid plugin name entered.")

# Check outputs, create output files
output_params = macinfo.OutputParams()
output_params.output_path = args.output_path
SetupExportLogger(output_params)
if args.xlsx: 
    try:
        xlsx_path = os.path.join(output_params.output_path, "mac_apt.xlsx")
        output_params.xlsx_writer = ExcelWriter()
        output_params.xlsx_writer.CreateXlsxFile(xlsx_path)
        output_params.write_xlsx = True
    except Exception as ex:
        log.info('XLSX file could not be created at : ' + xlsx_path)
        log.exception('Exception occurred when trying to create XLSX file')

if args.sqlite: 
    try:
        sqlite_path = os.path.join(output_params.output_path, "mac_apt.db")
        output_params.output_db_path = SqliteWriter.CreateSqliteDb(sqlite_path)
        output_params.write_sql = True
    except Exception as ex:
        log.info('Sqlite db could not be created at : ' + sqlite_path)
        log.exception('Exception occurred when trying to create Sqlite db')
    
if args.csv or not (output_params.write_sql or output_params.write_xlsx):
    output_params.write_csv  = True

# At this point, all looks good, lets mount the image
img = None
found_osx = False
mac_info = None
time_processing_started = time.time()
try:
    if args.input_type.upper() == 'E01':
        img = GetImgInfoObjectForE01(args.input_path) # Use this function instead of pytsk3.Img_Info()
        mac_info = macinfo.MacInfo(output_params)
    elif args.input_type.upper() == 'DD':
        img = pytsk3.Img_Info(args.input_path) # Works for split dd images too! Works for DMG too, if no compression/encryption is used!
        mac_info = macinfo.MacInfo(output_params)
    elif args.input_type.upper() == 'MOUNTED':
        if os.path.isdir(args.input_path):
            mac_info = macinfo.MountedMacInfo(args.input_path, output_params)
            found_osx = FindOsxFiles(mac_info)
        else:
            Exit("Exiting -> Cannot browse mounted image at " + args.input_path)
    log.info("Opened image " + args.input_path)
except Exception as ex:
    log.error("Failed to load image. Error Details are: " + str(ex))
    Exit()

if args.input_type.upper() != 'MOUNTED':
    try:
        vol_info = pytsk3.Volume_Info(img) 
        vs_info = vol_info.info # TSK_VS_INFO object
        mac_info.pytsk_image = img
        mac_info.vol_info = vol_info
        found_osx = FindOsxPartition(img, vol_info, vs_info)
    except Exception as ex:
        if str(ex).find("Cannot determine partition type") > 0 :
            log.info(" Info: Probably not a disk image, trying to parse as a File system")
            found_osx = IsOsxPartition(img, 0, mac_info)
        else:
            log.error("Unknown error while trying to determine partition")
            log.exception("Exception") #traceback.print_exc()

# Write out disk & vol information
Disk_Info(mac_info, args.input_path).Write()
if not mac_info.is_apfs:
    mac_info.hfs_native.Initialize(mac_info.pytsk_image, mac_info.osx_partition_start_offset)

# Start processing plugins now!
if found_osx:
    #print ("Found the partition having OSX on it!")
    for plugin in plugins:
        if process_all or IsItemPresentInList(plugins_to_run, plugin.__Plugin_Name):
            log.info("-"*50)
            log.info("Running plugin " + plugin.__Plugin_Name)
            try:
                plugin.Plugin_Start(mac_info)
            except Exception as ex:
                log.exception ("An exception occurred while running plugin - {}".format(plugin.__Plugin_Name))
else:
    log.warning (":( Could not find a partition having an OSX installation on it")

# Final cleanup
if img != None: img.close()
if args.xlsx:
    output_params.xlsx_writer.CommitAndCloseFile()
if mac_info.is_apfs:
    mac_info.apfs_db.CloseDb()

time_processing_ended = time.time()
run_time = time_processing_ended - time_processing_started
log.info("Finished in time = {}".format(time.strftime('%H:%M:%S', time.gmtime(run_time))))
