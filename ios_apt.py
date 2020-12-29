'''
   Copyright (c) 2020 Yogesh Khatri 

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the 
   terms of the MIT License.
   
   ios_apt.py
   ------------------------
   This is the ios artifact parser tool.

   For usage information, run: 
     python ios_apt.py -h
  
   NOTE: This currently works only on Python3.7 or higher.
'''

import sys
import os
import argparse
import traceback
import plugins.helpers.macinfo as macinfo
from plugins.helpers.writer import *
import logging
import time
import textwrap
from plugin import *

__VERSION = "0.9.dev"
__PROGRAMNAME = "iOS Artifact Parsing Tool"
__EMAIL = "yogesh@swiftforensics.com"

def IsItemPresentInList(collection, item):
    try:
        collection.index(item)
        return True
    except ValueError:
        pass
    return False

def GetPlugin(name):
    for plugin in plugins:
        if plugin.__Plugin_Name == name: return plugin
    return None

def FindIosFiles(ios_info):
    if ios_info.IsValidFilePath('/System/Library/CoreServices/SystemVersion.plist'):
        return ios_info._GetSystemInfo()
    else:
        log.error("Could not find iOS system version!")
    return False

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
plugin_count = ImportPlugins(plugins, 'IOS')
if plugin_count == 0:
    sys.exit ("No plugins could be added ! Exiting..")

plugin_name_list = ['ALL']
plugins_info = f"The following {len(plugins)} plugins are available:"
for plugin in plugins:
    plugins_info += "\n    {:<20}{}".format(plugin.__Plugin_Name, textwrap.fill(plugin.__Plugin_Description, subsequent_indent=' '*24, initial_indent=' '*24, width=80)[24:])
    plugin_name_list.append(plugin.__Plugin_Name)

plugins_info += "\n    " + "-"*76 + "\n" +\
                 " "*4 + "ALL" + " "*17 + "Runs all plugins"
arg_parser = argparse.ArgumentParser(description='ios_apt is a framework to process forensic artifacts on a mounted iOS full file system image\n'\
                                                 'You are running {} version {}'.format(__PROGRAMNAME, __VERSION),
                                    epilog=plugins_info, formatter_class=argparse.RawTextHelpFormatter)
arg_parser.add_argument('-i', '--input_path', help='Path to root folder of ios image') # Not optional !
arg_parser.add_argument('-o', '--output_path', help='Path where output files will be created') # Not optional !
arg_parser.add_argument('-x', '--xlsx', action="store_true", help='Save output in excel spreadsheet(s)')
arg_parser.add_argument('-c', '--csv', action="store_true", help='Save output as CSV files (Default option if no output type selected)')
arg_parser.add_argument('-l', '--log_level', help='Log levels: INFO, DEBUG, WARNING, ERROR, CRITICAL (Default is INFO)')
arg_parser.add_argument('plugin', nargs="+", help="Plugins to run (space separated). 'ALL' will process every available plugin")
args = arg_parser.parse_args()

plugins_to_run = [x.upper() for x in args.plugin]  # convert all plugin names entered by user to uppercase
process_all = IsItemPresentInList(plugins_to_run, 'ALL')
if not process_all:
    #Check for invalid plugin names or ones not Found
    if not CheckUserEnteredPluginNames(plugins_to_run, plugins):
        sys.exit("Exiting -> Invalid plugin name entered.")

# Check outputs, create output files
if args.output_path:
    if (os.name != 'nt'):
        if args.output_path.startswith('~/') or args.output_path == '~': # for linux/mac, translate ~ to user profile folder
            args.output_path = os.path.expanduser(args.output_path)
    print ("Output path was : {}".format(args.output_path))
    if not CheckOutputPath(args.output_path):
        sys.exit("Exiting -> Output path not valid!")
else:
    sys.exit("Exiting -> No output_path provided, the -o option is mandatory!")

output_params = macinfo.OutputParams()
output_params.output_path = args.output_path
SetupExportLogger(output_params)

if args.log_level:
    args.log_level = args.log_level.upper()
    if not args.log_level in ['INFO','DEBUG','WARNING','ERROR','CRITICAL']: # TODO: change to just [info, debug, error]
        sys.exit("Exiting -> Invalid input type for log level. Valid values are INFO, DEBUG, WARNING, ERROR, CRITICAL")
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

if args.input_path:
    if os.path.isdir(args.input_path):
        ios_info = macinfo.MountedIosInfo(args.input_path, output_params)
        if not FindIosFiles(ios_info):
            sys.exit(":( Could not find an iOS installation on path provided. Make sure you provide the path to the root folder."
                        " This folder should contain folders 'bin', 'System', 'private', 'Library' and others. ")
        ios_info._GetAppDetails()
    else:
        sys.exit("Exiting -> Provided input path is not a folder! - " + args.input_path)
else:
    sys.exit("Exiting -> No input file provided, the -i option is mandatory. Please provide a file to process!")

try:
    log.debug("Trying to create db @ " + os.path.join(output_params.output_path, "ios_apt.db"))
    output_params.output_db_path = SqliteWriter.CreateSqliteDb(os.path.join(output_params.output_path, "ios_apt.db"))
    output_params.write_sql = True
except Exception as ex:
    log.exception('Exception occurred when tried to create Sqlite db')
    sys.exit('Exiting -> Cannot create sqlite db!')

if args.xlsx: 
    try:
        xlsx_path = os.path.join(output_params.output_path, "mac_apt.xlsx")
        output_params.xlsx_writer = ExcelWriter()
        log.debug("Trying to create xlsx file @ " + xlsx_path)
        output_params.xlsx_writer.CreateXlsxFile(xlsx_path)
        output_params.write_xlsx = True
    except Exception as ex:
        log.info('XLSX file could not be created at : ' + xlsx_path)
        log.exception('Exception occurred when trying to create XLSX file')

if args.csv or not (output_params.write_sql or output_params.write_xlsx):
    output_params.write_csv  = True

# At this point, all looks good, lets process the input file
# Start processing plugin now!

time_processing_started = time.time()

for plugin in plugins:
    if process_all or IsItemPresentInList(plugins_to_run, plugin.__Plugin_Name):
        log.info("-"*50)
        log.info("Running plugin " + plugin.__Plugin_Name)
        try:
            plugin.Plugin_Start_Ios(ios_info)
        except Exception as ex:
            log.exception ("An exception occurred while running plugin - {}".format(plugin.__Plugin_Name))
log.info("-"*50)

if args.xlsx:
    output_params.xlsx_writer.CommitAndCloseFile()
if output_params.export_log_sqlite:
    output_params.export_log_sqlite.CloseDb()

time_processing_ended = time.time()
run_time = time_processing_ended - time_processing_started
log.info("Finished in time = {}".format(time.strftime('%H:%M:%S', time.gmtime(run_time))))
log.info("Review the Log file and report any ERRORs or EXCEPTIONS to the developers")