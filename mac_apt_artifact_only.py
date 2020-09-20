'''
   Copyright (c) 2018 Yogesh Khatri 

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the 
   terms of the MIT License.
   
   mac_apt_artifact_only.py
   ------------------------
   This is intended for situations where you don't have a full 
   disk/volume image, but just have artifact plist files or databases
   to examine. This script allows a single plugin to run and process
   multiple artifact files. Not all plugins support this option!

   For usage information, run: 
     python mac_apt_artifact_only.py -h
  
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

__VERSION = "0.8.dev"
__PROGRAMNAME = "macOS Artifact Parsing Tool - Artifact Only mode"
__EMAIL = "yogesh@swiftforensics.com"

def GetPlugin(name):
    for plugin in plugins:
        if plugin.__Plugin_Name == name: return plugin
    return None

## Main program ##
plugins = []
plugin_count = ImportPlugins(plugins, 'ARTIFACTONLY')
if plugin_count == 0:
    sys.exit ("No plugins could be added ! Exiting..")

plugin_name_list = []
plugins_info = f"The following {len(plugins)} plugins are available:"
for plugin in plugins:
    plugins_info += "\n    {:<20}{}".format(plugin.__Plugin_Name, textwrap.fill(plugin.__Plugin_Description, subsequent_indent=' '*24, initial_indent=' '*24, width=80)[24:])
    plugin_name_list.append(plugin.__Plugin_Name)

arg_parser = argparse.ArgumentParser(description='mac_apt is a framework to process forensic artifacts on a Mac OSX system\n'\
                                                 f'You are running {__PROGRAMNAME} version {__VERSION}\n\n'\
                                                 'Note: The default output is now sqlite, no need to specify it now',
                                    epilog=plugins_info, formatter_class=argparse.RawTextHelpFormatter)
arg_parser.add_argument('-i', '--input_path', nargs='+', help='Path to input file(s)') # Not optional !
arg_parser.add_argument('-o', '--output_path', help='Path where output files will be created') # Not optional !
arg_parser.add_argument('-x', '--xlsx', action="store_true", help='Save output in excel spreadsheet(s)')
arg_parser.add_argument('-c', '--csv', action="store_true", help='Save output as CSV files')
arg_parser.add_argument('-l', '--log_level', help='Log levels: INFO, DEBUG, WARNING, ERROR, CRITICAL (Default is INFO)')
arg_parser.add_argument('plugin', help="Plugin to run")
arg_parser.add_argument('--plugin_help', action="store_true", help="Plugin usage info")
args = arg_parser.parse_args()

plugin_to_run = args.plugin.upper()  # convert plugin name entered by user to uppercase
if plugin_to_run in plugin_name_list:
    plugin = GetPlugin(plugin_to_run)
    if args.plugin_help:
        # Display help for Module
        print("\nHelp for Module {} ({})\n".format(plugin.__Plugin_Name, plugin.__Plugin_Friendly_Name))
        print("-"*50 + "\n{}\n".format( textwrap.fill(plugin.__Plugin_ArtifactOnly_Usage, width=80, drop_whitespace=False)))
        sys.exit()
else:
    sys.exit("Exiting -> Plugin '" + args.plugin + "' is not a valid plugin name.")

if args.output_path:
    if (os.name != 'nt'):
        if args.output_path.startswith('~/') or args.output_path == '~': # for linux/mac, translate ~ to user profile folder
            args.output_path = os.path.expanduser(args.output_path)
    print ("Output path was : {}".format(args.output_path))
    if not CheckOutputPath(args.output_path):
        sys.exit("Exiting -> Output path not valid!")
else:
    sys.exit("Exiting -> No output_path provided, the -o option is mandatory!")

if args.input_path:
    try:
        for in_file in args.input_path:
            if not os.path.exists(in_file):
                sys.exit("Exiting -> Input path '{}' does not exist!".format(in_file))
    except Exception as ex:
        sys.exit("Exiting -> Error while checking input_path\n" + str(ex))
else:
    sys.exit("Exiting -> No input file provided, the -i option is mandatory. Please provide a file to process!")

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

output_params = macinfo.OutputParams()
output_params.output_path = args.output_path

try:
    log.debug("Trying to create db @ " + os.path.join(output_params.output_path, "mac_apt.db"))
    output_params.output_db_path = SqliteWriter.CreateSqliteDb(os.path.join(output_params.output_path, "mac_apt.db"))
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

if args.csv:
    output_params.write_csv  = True

# At this point, all looks good, lets process the input file
# Start processing plugin now!

time_processing_started = time.time()
log.info("-"*50)
log.info("Running plugin " + plugin_to_run)
log.info("-"*50)
try:
    plugin = GetPlugin(plugin_to_run)
    plugin.Plugin_Start_Standalone(args.input_path, output_params)
except Exception as ex:
    log.exception ("An exception occurred while running plugin - " + plugin_to_run)

log.info("-"*50)

if args.xlsx:
    output_params.xlsx_writer.CommitAndCloseFile()

time_processing_ended = time.time()
run_time = time_processing_ended - time_processing_started
log.info("Finished in time = {}".format(time.strftime('%H:%M:%S', time.gmtime(run_time))))
log.info("Review the Log file and report any ERRORs or EXCEPTIONS to the developers")
