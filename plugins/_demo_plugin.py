'''
   Copyright (c) 2017 Yogesh Khatri

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the
   terms of the MIT License.

   _demo_plugin.py
   ---------------
   This demonstrates how to write a simple plugin for use with mac_apt.
   Any plugin that starts with underscore '_' will not be included, so
   remember to remove the underscore to include it into mac_apt.
'''

import os

from plugins.helpers.macinfo import *
from plugins.helpers.writer import *

import logging
import biplist

__Plugin_Name = "DEMOPLUGIN1" # Cannot have spaces, and must be all caps!
__Plugin_Friendly_Name = "Demo Plugin 1"
__Plugin_Version = "1.0"
__Plugin_Description = "Demonstrates logging, reading plist and writing out information"
__Plugin_Author = "Yogesh Khatri"
__Plugin_Author_Email = "yogesh@swiftforensics.com"

__Plugin_Modes = "MACOS,ARTIFACTONLY" # Valid values are 'MACOS', 'IOS, 'ARTIFACTONLY' 
__Plugin_ArtifactOnly_Usage = 'Provide SystemVersion.plist to read macOS version'

log = logging.getLogger('MAIN.' + __Plugin_Name) # Do not rename or remove this ! This is the logger object

#---- Do not change the variable names in above section ----#

def Plugin_Start(mac_info):
    '''Main Entry point function for plugin'''

    # Lets print the macOS name and version that the framework has already retrieved. (Utilizing MacInfo)
    log.info("Current OS is: " + os.name)
    log.info("Mac version is : {}".format(mac_info.os_version))

    # Now lets try to get it ourselves manually.
    file_path = '/System/Library/CoreServices/SystemVersion.plist'
    version = Process_File(mac_info, file_path)
    log.info("Mac version retrieved = {}".format(version))

    # Lets export our file into the Export folder, as most plugins should.
    mac_info.ExportFile(file_path, __Plugin_Name)

    # Let's write it out now
    WriteMe(version, mac_info.output_params, file_path)


def Process_File(mac_info, file_path):
    version = ''
    log.debug("Inside Process_File")
    try:
        log.info("Trying to get version from {}".format(file_path))
        success, plist, error = mac_info.ReadPlist(file_path)
        if success:
            version = GetMacOsVersion(plist)
    except Exception:
        log.exception(error)
    return version

def GetMacOsVersion(plist):
    ''' Gets macOS version number from plist, input here is the plist itself.'''
    try:
        os_version = plist['ProductVersion']
    except Exception:
        log.error("Error fetching ProductVersion from plist. Is it a valid xml plist?")
    return os_version


def WriteMe(version, output_params, file_path):
    col_info = [ ('Version info', DataType.TEXT),('Major', DataType.INTEGER) ] # Define your columns
    major_ver = int(version.split('.')[0])
    data = [version, major_ver] # Data as a list (or dictionary)

    ## The following demonstrates use of the writer class.
    writer = DataWriter(output_params, 'macOS Info', col_info, file_path)
    try:
        writer.WriteRow(data)
    except:
        log.exception('WriteMe() exception')
    finally:
        writer.FinishWrites()

    # Alternately, you could do it in one line as shown below:
    WriteList('OSX version info', 'OSX Info', [data], col_info, output_params, file_path)

def Plugin_Start_Standalone(input_files_list, output_params):
    '''Main entry point function when used on single artifacts (mac_apt_singleplugin), not on a full disk image'''
    log.info("Module Started as standalone")
    for input_path in input_files_list:
        log.debug("Input file passed was: " + input_path)
        ## Process the input file here ##
        if input_path.endswith('SystemVersion.plist'):
            success, plist, error = CommonFunctions.ReadPlist(input_path)
            if success:
                os_version = plist.get('ProductVersion', None)
                if os_version == None:
                    log.error('Could not find ProductVersion in plist!')
                else:
                    WriteMe(os_version, output_params, input_path)
            else:
                log.error('Input file "{}" is not a valid plist. Error opening file was: {}'.format(input_path, error))

def Plugin_Start_Ios(ios_info):
    '''Entry point for ios_apt plugin'''
    pass

if __name__ == '__main__':
    print ("This plugin is a part of a framework and does not run independently on its own!")