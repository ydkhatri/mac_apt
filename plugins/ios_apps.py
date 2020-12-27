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
__Plugin_Description = "Gets App listing, install dates, sandbox locations"
__Plugin_Author = "Yogesh Khatri"
__Plugin_Author_Email = "yogesh@swiftforensics.com"

__Plugin_Modes = "IOS"
__Plugin_ArtifactOnly_Usage = ""

log = logging.getLogger('MAIN.' + __Plugin_Name) # Do not rename or remove this ! This is the logger object


#---- Do not change the variable names in above section ----#

app_info = [ ('App_Name',DataType.TEXT),('Hidden',DataType.TEXT),('Bundle_Identifier',DataType.TEXT),
              ('Bundle_Path',DataType.TEXT),('Data_Path',DataType.TEXT),
              ('Install_Date',DataType.DATE),('Uninstall_Date',DataType.DATE),('Version',DataType.TEXT),
              ('App Groups',DataType.TEXT),('Sys Groups',DataType.TEXT),('Extensions',DataType.TEXT),
              ('Icon_Path',DataType.TEXT),('Source',DataType.TEXT)
             ]

app_group_info = [ ('App_Name',DataType.TEXT),('GroupType',DataType.TEXT),
                    ('Group Name',DataType.TEXT),('UUID',DataType.TEXT),('Path',DataType.TEXT) ]

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
                     app.install_date, app.uninstall_date, app.bundle_version, 
                     ', '.join(app.app_groups),
                     ', '.join(app.sys_groups),
                     ', '.join(app.extensions),
                     app.main_icon_path, app.source])

    log.info('Found {} apps'.format(len(apps)))
    WriteList("app information", "Apps", apps, app_info, ios_info.output_params, '')

    app_groups = []
    for app in ios_info.apps:
        if app.app_group_containers:
            app_name = app.bundle_display_name
            if not app_name:
                app_name = app.bundle_identifier
            for group in app.app_group_containers:
                app_groups.append( [app_name, 'AppGroup', group.id, group.uuid, group.path] )
            for group in app.sys_group_containers:
                app_groups.append( [app_name, 'SystemGroup', group.id, group.uuid, group.path] )

    WriteList("app group information", "AppGroupInfo", app_groups, app_group_info, ios_info.output_params, '')

    app_plugins = []
    for app in ios_info.apps:
        if app.ext_group_containers:
            app_name = app.bundle_display_name
            if not app_name:
                app_name = app.bundle_identifier
            for group in app.ext_group_containers:
                app_plugins.append( [app_name, 'PluginKitPlugin', group.id, group.uuid, group.path] )
    
    WriteList("app extension information", "AppExtensionInfo", app_plugins, app_group_info, ios_info.output_params, '')

if __name__ == '__main__':
    print("This plugin is a part of a framework and does not run independently on its own!")
