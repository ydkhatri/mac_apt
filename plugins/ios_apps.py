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

__Plugin_Name = "APPS"
__Plugin_Friendly_Name = "App Information"
__Plugin_Version = "1.0"
__Plugin_Description = "Extract App information"
__Plugin_Author = "Yogesh Khatri"
__Plugin_Author_Email = "yogesh@swiftforensics.com"

__Plugin_Modes = "IOS"
__Plugin_ArtifactOnly_Usage = ""

log = logging.getLogger('MAIN.' + __Plugin_Name) # Do not rename or remove this ! This is the logger object


#---- Do not change the variable names in above section ----#

app_info = [ ('App_Name',DataType.TEXT),('Hidden',DataType.TEXT),('Bundle_Identifier',DataType.TEXT),
              ('Bundle_Path',DataType.TEXT),('Data_Path',DataType.TEXT),
              ('Uninstall_Date',DataType.DATE),('Version',DataType.INTEGER),
              ('Icon_Path',DataType.TEXT),('Source',DataType.TEXT)
             ]

def Plugin_Start(mac_info):
    pass

def Plugin_Start_Standalone(input_files_list, output_params):
    log.info("This cannot be used as a standalone plugin")

def Plugin_Start_Ios(ios_info):
    '''Entry point for ios_apt plugin'''
    apps = []
    for app in ios_info.apps:

        apps.append([app.bundle_display_name, app.hidden, app.bundle_identifier,
                     app.bundle_path, app.sandbox_path,
                     app.uninstall_date, app.bundle_version, 
                     app.main_icon_path, app.source])

    log.info('Found {} apps'.format(len(apps)))

    WriteList("app information", "Apps", apps, app_info, ios_info.output_params, '')

if __name__ == '__main__':
    print("This plugin is a part of a framework and does not run independently on its own!")
