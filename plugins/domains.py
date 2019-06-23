'''
   Copyright (c) 2017 Yogesh Khatri 

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the 
   terms of the MIT License.
   
'''

import os
import logging
import biplist
from helpers.macinfo import *
from helpers.writer import *


__Plugin_Name = "DOMAINS" # Cannot have spaces, and must be all caps!
__Plugin_Friendly_Name = "Domains connected"
__Plugin_Version = "0.1"
__Plugin_Description = "Get information about ActiveDirectory Domain(s) that this mac is connected to"
__Plugin_Author = "Yogesh Khatri"
__Plugin_Author_Email = "yogesh@swiftforensics.com"

__Plugin_Standalone = True
__Plugin_Standalone_Usage = "Processes ActiveDirectory plist files under /Library/Preferences/OpenDirectory/Configurations/Active Directory"

log = logging.getLogger('MAIN.' + __Plugin_Name) # Do not rename or remove this ! This is the logger object


#---- Do not change the variable names in above section ----#

ad_info = [ ('node name',DataType.TEXT),('trustaccount',DataType.TEXT),('trustkerberosprincipal',DataType.TEXT),
              ('trusttype',DataType.TEXT),('allow multi-domain',DataType.INTEGER),('cache last user logon',DataType.INTEGER),
              ('domain',DataType.TEXT),('forest',DataType.TEXT),('trust domain',DataType.TEXT),('source',DataType.TEXT)
          ]
ad_details = []

def Plugin_Start(mac_info):
    ad_folder = '/Library/Preferences/OpenDirectory/Configurations/Active Directory'
    if mac_info.IsValidFolderPath(ad_folder):
        ad_list = mac_info.ListItemsInFolder(ad_folder, EntryType.FILES)
        if len(ad_list) == 0:
            log.debug("No files found under " + ad_folder)
            return
        for ad in ad_list:
            if ad['size'] == 0: continue
            ad_name = ad['name']
            log.info("Trying to read " + ad_name)
            mac_info.ExportFile(ad_folder + '/' + ad_name, __Plugin_Name, '', False)
            plist_path = ad_folder + '/' + ad_name
            success, plist, error_message = mac_info.ReadPlist(plist_path)
            if success:
                ProcessActiveDirectoryPlist(plist_path, plist)
            else:
                log.error('Failed to read plist ' + plist_path + " Error was : " + error_message)
        
        WriteList('domain details', 'Domain_ActiveDirectory', ad_details, ad_info, mac_info.output_params, '/Library/Preferences/OpenDirectory/Configurations/Active Directory/')
    else:
        log.info("Folder " + ad_folder + " not found!")

def ProcessActiveDirectoryPlist(plist_path, plist):
    active_directory = {'source': plist_path}
    try:
        for item, value in plist.items():
            if item in ['node name','trustaccount','trustkerberosprincipal','trusttype']:
                active_directory[item] = value
        ad_dict = plist['module options']['ActiveDirectory']
        for item, value in ad_dict.items():
            if item in ['allow multi-domain','cache last user logon','domain','forest','trust domain']:
                active_directory[item] = value
    except (KeyError, ValueError) as ex:
        log.error('Error reading plist ' + plist_path + ' Exception details: ' + str(ex))
    ad_details.append(active_directory)

        
def Plugin_Start_Standalone(input_files_list, output_params):
    log.info("Module Started as standalone")
    for input_path in input_files_list:
        log.debug("Trying to read plist : " + input_path)
        success, plist, error = CommonFunctions.ReadPlist.readPlist(input_path)
        if success:
            ProcessActiveDirectoryPlist(input_path, plist)
            WriteList('domain details', 'Domain_ActiveDirectory', ad_details, ad_info, mac_info.output_params, input_path)
        else:
            log.error("Failed to read plist " + input_path + " Error was: " + error)

    

if __name__ == '__main__':
    print("This plugin is a part of a framework and does not run independently on its own!")
