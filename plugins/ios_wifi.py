'''
   Copyright (c) 2020 Yogesh Khatri 

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the 
   terms of the MIT License.
   
'''

import os
import logging
from plugins.helpers.macinfo import *
from plugins.helpers.writer import *

__Plugin_Name = "WIFI"
__Plugin_Friendly_Name = "Wifi"
__Plugin_Version = "1.0"
__Plugin_Description = "Information about connected/stored wifi access points"
__Plugin_Author = "Yogesh Khatri"
__Plugin_Author_Email = "yogesh@swiftforensics.com"

__Plugin_Modes = "IOS,ARTIFACTONLY"
__Plugin_ArtifactOnly_Usage = ""

log = logging.getLogger('MAIN.' + __Plugin_Name) # Do not rename or remove this ! This is the logger object


#---- Do not change the variable names in above section ----#

wifi_info = [ ('SSID',DataType.TEXT),('BSSID',DataType.TEXT),('Enabled', DataType.TEXT),
              ('Profile_User_Name',DataType.TEXT),('Last_Auto_Joined',DataType.DATE),
              ('Last_Joined',DataType.DATE),('Last_Updated',DataType.DATE),
              ('Network_Usage',DataType.REAL),('Source',DataType.TEXT)
             ]

def Plugin_Start(mac_info):
    pass

def Plugin_Start_Standalone(input_files_list, output_params):
    log.info("This cannot be used as a standalone plugin")

def Plugin_Start_Ios(ios_info):
    '''Entry point for ios_apt plugin'''
    networks = []
    wifi_plist_path = '/private/var/preferences/SystemConfiguration/com.apple.wifi.plist'
    if ios_info.IsValidFilePath(wifi_plist_path):
        ios_info.ExportFile(wifi_plist_path, __Plugin_Name, '', False)
        success, plist, error = ios_info.ReadPlist(wifi_plist_path)
        if success:
            known_networks = plist.get('List of known networks', [])
            for network in known_networks:
                ssid = network.get('SSID', b'').decode('utf8', 'ignore')
                bssid = network.get('BSSID', '')
                enabled = network.get('enabled', '')
                last_join = network.get('lastJoined', '')
                last_auto_join = network.get('lastAutoJoined', '')
                last_update = network.get('lastUpdated', '')
                usage = network.get('networkUsage', 0)
                user = ''
                try:
                    user = network['EnterpriseProfile']['EAPClientConfiguration']['UserName']
                except (KeyError, ValueError):
                    pass
                networks.append( [ssid, bssid, enabled, user, last_auto_join, last_join, last_update, usage, wifi_plist_path] )
        else:
            log.error(f'Error reading {plist_path} : {error}')
    else:
        log.info(f'Did not find wifi plist at {wifi_plist_path}')

    log.info('Found {} wifi access points'.format(len(networks)))

    WriteList("wifi information", "Wifi", networks, wifi_info, ios_info.output_params, '')

if __name__ == '__main__':
    print("This plugin is a part of a framework and does not run independently on its own!")
