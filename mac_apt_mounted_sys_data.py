'''
   Copyright (c) 2020 Yogesh Khatri

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the 
   terms of the MIT License.
   
   mac_apt_mounted_sys_data.py
   ----------
   This is a special version of the mac_apt.py script which is 
   specifically created for processing macOS 10.15 (Catalina) or
   above images in MOUNTED mode. Here you will have two seperate
   volumes mounted for SYSTEM and DATA. Provide both to this 
   script.
   
   For usage information, run: 
     python mac_apt_mounted_sys_data.py -h

   NOTE: This currently works only on Python3.7 or higher.
   
'''

import argparse
import logging
import os
import plugins.helpers.macinfo as macinfo
import sys
import textwrap
import time
import traceback
from plugins.helpers.writer import *
from plugins.helpers.disk_report import *
from plugin import *

__VERSION = "1.4.2"
__PROGRAMNAME = "macOS Artifact Parsing Tool - SYS DATA Mounted mode"
__EMAIL = "yogesh@swiftforensics.com"


def IsItemPresentInList(collection, item):
    try:
        collection.index(item)
        return True
    except ValueError:
        pass
    return False

def FindMacOsFiles(mac_info):
    if mac_info.IsValidFilePath('/System/Library/CoreServices/SystemVersion.plist'):
        if mac_info.IsValidFilePath("/System/Library/Kernels/kernel") or \
            mac_info.IsValidFilePath( "/mach_kernel"):
            log.info ("Found valid OSX/macOS kernel")
        else:
            log.info ("Could not find OSX/macOS kernel!")# On partial/corrupted images, this may not be found
        mac_info._GetSystemInfo()
        mac_info._GetUserInfo()
        return True
    else:
        log.info ("Could not find OSX/macOS installation!")
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

    export_sqlite_path = SqliteWriter.CreateSqliteDb(os.path.join(output_params.export_path, "Exported_Files_Log.db"))
    writer = SqliteWriter(asynchronous=True)
    writer.OpenSqliteDb(export_sqlite_path)
    column_info = collections.OrderedDict([ ('SourcePath',DataType.TEXT), ('ExportPath',DataType.TEXT),
                                            ('InodeModifiedTime',DataType.DATE),('ModifiedTime',DataType.DATE),
                                            ('CreatedTime',DataType.DATE),('AccessedTime',DataType.DATE) ])
    writer.CreateTable(column_info, 'ExportedFileInfo')
    output_params.export_log_sqlite = writer

## Main program ##

plugins = []
log = None
plugin_count = ImportPlugins(plugins, 'MACOS')
if plugin_count == 0:
    Exit ("No plugins could be added ! Exiting..")

plugin_name_list = ['ALL', 'FAST']
plugins_info = f"The following {len(plugins)} plugins are available:"

for plugin in plugins:
    plugins_info += "\n    {:<20}{}".format(plugin.__Plugin_Name, textwrap.fill(plugin.__Plugin_Description, subsequent_indent=' '*24, initial_indent=' '*24, width=80)[24:])
    plugin_name_list.append(plugin.__Plugin_Name)

plugins_info += "\n    " + "-"*76 + "\n" +\
                 " "*4 + "FAST" + " "*16 + "Runs all plugins except IDEVICEBACKUPS, SPOTLIGHT, UNIFIEDLOGS\n" + \
                 " "*4 + "ALL" + " "*17 + "Runs all plugins"
arg_parser = argparse.ArgumentParser(description='mac_apt is a framework to process macOS forensic artifacts\n'\
                                                 f'You are running {__PROGRAMNAME} version {__VERSION}\n\n'\
                                                 'Note: The default output is now sqlite, no need to specify it now',
                                    epilog=plugins_info, formatter_class=argparse.RawTextHelpFormatter)
arg_parser.add_argument('input_sys_path', help='Path to root folder of mounted SYSTEM image/volume')
arg_parser.add_argument('input_data_path', help='Path to root folder of mounted DATA image/volume')
arg_parser.add_argument('-o', '--output_path', help='Path where output files will be created')
arg_parser.add_argument('-x', '--xlsx', action="store_true", help='Save output in Excel spreadsheet')
arg_parser.add_argument('-c', '--csv', action="store_true", help='Save output as CSV files')
#arg_parser.add_argument('-s', '--sqlite', action="store_true", help='Save output in an sqlite database')
arg_parser.add_argument('-l', '--log_level', help='Log levels: INFO, DEBUG, WARNING, ERROR, CRITICAL (Default is INFO)')#, choices=['INFO','DEBUG','WARNING','ERROR','CRITICAL'])
arg_parser.add_argument('plugin', nargs="+", help="Plugins to run (space separated). 'FAST' will run most plugins")
args = arg_parser.parse_args()

if args.output_path:
    if (os.name != 'nt'):
        if args.output_path.startswith('~/') or args.output_path == '~': # for linux/mac, translate ~ to user profile folder
            args.output_path = os.path.expanduser(args.output_path)
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
#LogLibraryVersions(log)

# Check inputs
if not os.path.isdir(args.input_sys_path):
    Exit('Exiting -> Invalid SYSTEM volume path entered -  {}'.format(args.input_sys_path))
if not os.path.isdir(args.input_data_path):
    Exit('Exiting -> Invalid DATA volume path entered -  {}'.format(args.input_data_path))

plugins_to_run = [x.upper() for x in args.plugin]  # convert all plugin names entered by user to uppercase
process_all = IsItemPresentInList(plugins_to_run, 'ALL')
if not process_all:
    if IsItemPresentInList(plugins_to_run, 'FAST'): # check for FAST
        plugins_to_run = plugin_name_list
        plugins_to_run.remove('ALL')
        plugins_to_run.remove('FAST')
        plugins_to_run.remove('IDEVICEBACKUPS')
        plugins_to_run.remove('SPOTLIGHT')
        plugins_to_run.remove('UNIFIEDLOGS')
    else:
        #Check for invalid plugin names or ones not Found
        if not CheckUserEnteredPluginNames(plugins_to_run, plugins):
            Exit("Exiting -> Invalid plugin name entered.")

# Check outputs, create output files
output_params = macinfo.OutputParams()
output_params.output_path = args.output_path
SetupExportLogger(output_params)

try:
    sqlite_path = os.path.join(output_params.output_path, "mac_apt.db")
    output_params.output_db_path = SqliteWriter.CreateSqliteDb(sqlite_path)
    output_params.write_sql = True
except Exception as ex:
    log.info('Sqlite db could not be created at : ' + sqlite_path)
    log.exception('Exception occurred when trying to create Sqlite db')
    Exit()

if args.xlsx: 
    try:
        xlsx_path = os.path.join(output_params.output_path, "mac_apt.xlsx")
        output_params.xlsx_writer = ExcelWriter()
        output_params.xlsx_writer.CreateXlsxFile(xlsx_path)
        output_params.write_xlsx = True
    except Exception as ex:
        log.info('XLSX file could not be created at : ' + xlsx_path)
        log.exception('Exception occurred when trying to create XLSX file')
    
if args.csv:
    output_params.write_csv  = True

# At this point, all looks good, lets mount the image
found_macos = False
mac_info = None
time_processing_started = time.time()
try:
    log.info("Opened images ")
    mac_info = macinfo.MountedMacInfoSeperateSysData(args.input_sys_path, args.input_data_path, output_params)
    found_macos = FindMacOsFiles(mac_info)
except Exception as ex:
    log.exception("Failed to browse image. Error Details are: " + str(ex))
    Exit()

# Start processing plugins now!
if found_macos:
    for plugin in plugins:
        if process_all or IsItemPresentInList(plugins_to_run, plugin.__Plugin_Name):
            log.info("-"*50)
            log.info("Running plugin " + plugin.__Plugin_Name)
            try:
                plugin.Plugin_Start(mac_info)
            except Exception as ex:
                log.exception ("An exception occurred while running plugin - {}".format(plugin.__Plugin_Name))
else:
    log.warning (":( Could not find a partition having a macOS installation on it")

log.info("-"*50)

# Final cleanup
if args.xlsx:
    output_params.xlsx_writer.CommitAndCloseFile()
if mac_info.is_apfs and mac_info.apfs_db != None:
    mac_info.apfs_db.CloseDb()

time_processing_ended = time.time()
run_time = time_processing_ended - time_processing_started
log.info("Finished in time = {}".format(time.strftime('%H:%M:%S', time.gmtime(run_time))))
log.info("Review the Log file and report any ERRORs or EXCEPTIONS to the developers")