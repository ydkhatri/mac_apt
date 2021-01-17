'''
   Copyright (c) 2017 Yogesh Khatri 

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the 
   terms of the MIT License.
   
'''

import os
import logging
from plugins.helpers.common import CommonFunctions
from plugins.helpers.macinfo import *
from plugins.helpers.writer import *

__Plugin_Name = "INSTALLHISTORY"
__Plugin_Friendly_Name = "Install History"
__Plugin_Version = "1.0"
__Plugin_Description = "Parses the InstallHistory.plist to get software installation history"
__Plugin_Author = "Noah Siddall, Yogesh Khatri"
__Plugin_Author_Email = "noah.sidall@mymail.champlain.edu, yogesh@swiftforensics.com"

__Plugin_Modes = "MACOS,ARTIFACTONLY"
__Plugin_ArtifactOnly_Usage = "Provide path to InstallHistory.plist to process"

log = logging.getLogger('MAIN.' + __Plugin_Name) # Do not rename or remove this ! This is the logger object


#---- Do not change the variable names in above section ----#

    
class InstalledItem: 
    
    def __init__(self):
        self.ContentType = ""
        self.Date = None
        self.DisplayName = ""
        self.DisplayVersion = ""
        self.PackageIdentifiers = ""
        self.ProcessName = ""

    def ReadParam(self, dict, param):
        return dict.get(param, None)
    
    def ReadInstallHistory(self, dict):
        self.ContentType = self.ReadParam(dict, 'contentType')
        self.Date = self.ReadParam(dict, 'date')
        self.DisplayName = self.ReadParam(dict, 'displayName')
        self.DisplayVersion = self.ReadParam(dict, 'displayVersion')
        self.PackageIdentifiers = self.ReadParam(dict, 'packageIdentifiers')
        self.ProcessName = self.ReadParam(dict, 'processName')

def ReadInstallHistoryPlist(plist, history):
    try:
        for item in plist:
            inst = InstalledItem()
            inst.ReadInstallHistory(item)
            history.append(inst)
    except ValueError as ex:
        log.info('Error reading plist, error was: {}'.format(str(ex)))

def ParseInstallHistoryFile(input_file):
    history = []
    success, plist, error = CommonFunctions.ReadPlist(input_path)
    if success:
        ReadInstallHistoryPlist(plist, history)
    else:
        log.error("Could not open plist, error was : " + error)
    return history

def PrintAll(history, output_params, source_path):
    install_info = [ ('ContentType',DataType.TEXT),('Date',DataType.DATE),('DisplayName',DataType.TEXT),
                     ('DisplayVersion',DataType.TEXT),('PackageIdentifiers',DataType.TEXT),('ProcessName',DataType.TEXT),
                     ('Source',DataType.TEXT)
                   ]

    data_list = []
    for entry in history:
        data_list.append( [ entry.ContentType, entry.Date, entry.DisplayName, entry.DisplayVersion, 
                            ', '.join(entry.PackageIdentifiers) if entry.PackageIdentifiers else '',
                            entry.ProcessName, source_path
                          ] )

    WriteList("Installation history", "InstallHistory", data_list, install_info, output_params, source_path)
    
def Plugin_Start(mac_info):
    '''Main Entry point function for plugin'''
    installhistory_plist_path = '/Library/Receipts/InstallHistory.plist'
    if mac_info.IsValidFilePath(installhistory_plist_path):
        mac_info.ExportFile(installhistory_plist_path, __Plugin_Name, '', False)
        success, plist, error = mac_info.ReadPlist(installhistory_plist_path)
        if success:
            history = []
            ReadInstallHistoryPlist(plist, history)
            if len(history) > 0:
                PrintAll(history, mac_info.output_params, installhistory_plist_path)
            else:
                log.info('No install history records found')
        else:
            log.error('Could not open plist ' + installhistory_plist_path)
            log.error('Error was: ' + error)
    else:
        log.info('InstallHistory.plist not found')
        
def Plugin_Start_Standalone(input_files_list, output_params):
    log.info("Module Started as standalone")
    for input_path in input_files_list:
        log.debug("Input file passed was: " + input_path)
        history = ParseInstallHistoryFile(input_path)
        if len(history) > 0:
            PrintAll(history, output_params, input_path)
        else:
            log.info('No install history records found in {}'.format(input_path))

if __name__ == '__main__':
    print("This plugin is a part of a framework and does not run independently on its own!")
