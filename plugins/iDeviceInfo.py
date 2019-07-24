'''
   Copyright (c) 2018 Yogesh Khatri

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the
   terms of the MIT License.

   iDeviceInfo.py
   ------------
   This plugin will scan for connected iDevices from /Users/<USER>/Library/Preferences/com.apple.iPod.plist
'''

from __future__ import print_function
from __future__ import unicode_literals

from plugins.helpers.macinfo import *
from plugins.helpers.writer import *
from plugins.helpers.common import *
from biplist import *
import logging
import os
from enum import Enum

__Plugin_Name = "IDEVICEINFO" # Cannot have spaces, and must be all caps!
__Plugin_Friendly_Name = "iDevice Info"
__Plugin_Version = "1.0"
__Plugin_Description = "Reads and exports connected iDevice details"
__Plugin_Author = "Jack Farley"
__Plugin_Author_Email = "jack.farley@mymail.champlain.edu"

__Plugin_Standalone = True
__Plugin_Standalone_Usage = 'Reads iDevice Info found at /Users/<USER>/Library/Preferences/com.apple.iPod.plist'\
                            'Provide the path to this file as input for this plugin'

log = logging.getLogger('MAIN.' + __Plugin_Name) # Do not rename or remove this ! This is the logger object

#---- Do not change the variable names in above section ----#



'''Enum to convert country codes'''
class Country(Enum):
    Egypt_OR_United_Arab_Emirates_OR_Jordan_OR_Saudi_Arabia = "AB"
    Ireland_OR_UK = "B"
    Canada = "C"
    China = "CH"
    Czech_Republic = "CZ"
    Austria_OR_Germany_OR_Netherlands = "DN"
    Mexico = "E"
    Estonia = "EE"
    Luxembourg = "FB"
    Austria_OR_Liechtenstein_OR_Switzerland = "FD"
    Greece = "GN"
    India = "HN"
    Japan = "J"
    Norway = "KN"
    Finland_OR_Sweeded = "KS"
    Colombia_OR_Ecuador_OR_El_Salvador_OR_Guatamela_OR_Honduras_OR_Peru = "LA"
    Argentina = "LE"
    United_States = "LL"
    Chile_OR_Uruguay_OR_Paraguay = "LZ"
    Hungary = "MG"
    Belgium_OR_Luxembourg_OR_France = "NF"
    Poland = "PL"
    Portugal = "PO"
    Philippines = "PP"
    Romania = "RO"
    Russia = "RS"
    Slovakia = "SL"
    South_Africa = "SO"
    Italy = "T"
    Taiwan = "TA"
    Turkey = "TU"
    Australia_OR_New_Zealand = "X"
    Spain = "Y"
    Singapore = "ZA"
    Hong_Kong_OR_Macao = "ZP"


class iDeviceInfo:
    def __init__(self, Username, Device_Class, Serial_Num, Use_Count, Last_Connected, Firmware_Ver_String, Product_Type, ID, IMEI, Build_Version,
                 MEID, Region, Firmware_Version, source):

        self.Username = Username
        self.Device_Class = Device_Class
        self.Serial_Num= Serial_Num
        self.Use_Count = Use_Count
        self.Last_Connected= Last_Connected
        self.Firmware_Ver_String = Firmware_Ver_String
        self.Product_Type = Product_Type
        self.ID = ID
        self.IMEI = IMEI
        self.Build_Version = Build_Version
        self.MEID = MEID
        self.Region = Region
        self.Firmware_Version = Firmware_Version
        self.source = source

def PrintAll(output_params, source_path, devices):
    device_labels = [('Username',DataType.TEXT),('Device_Class',DataType.TEXT),('Serial_Num',DataType.TEXT),
                    ('Use_Count',DataType.INTEGER),('Last_Connected',DataType.DATE), ('Firmware_Ver_String',DataType.TEXT),
                    ('Product_Type',DataType.TEXT),('ID',DataType.TEXT),('IMEI',DataType.TEXT),
                    ('Build_Version',DataType.TEXT),('MEID',DataType.TEXT),('Region',DataType.TEXT),
                    ('Firmware_Version', DataType.TEXT), ('Source',DataType.TEXT)
                    ]

    device_list = []
    for dvc in devices:
        dvcs_item = [ dvc.Username, dvc.Device_Class, dvc.Serial_Num, dvc.Use_Count,
                      dvc.Last_Connected, dvc.Firmware_Ver_String, dvc.Product_Type, dvc.ID,
                      dvc.IMEI, dvc.Build_Version, dvc.MEID, dvc.Region,
                      dvc.Firmware_Version, dvc.source
                     ]
        device_list.append(dvcs_item)

    WriteList("iDevice Info", "iDevice_Info", device_list, device_labels, output_params, source_path)

'''Gets all neccessary data from each individual device in the plist'''
def deviceReader(devicePlist, userDevicePath, user_name, devices):

    '''Converts country code'''
    rawCode = devicePlist.get('Region Info', '')
    if rawCode:
        if "/" in rawCode:
            parsedCode = rawCode[0:rawCode.find("/")]
        else:
            parsedCode = rawCode
        try:
            parsedCode = str(Country(parsedCode))
            parsedCode= parsedCode[8:]
        except ValueError: # The country code is not present in our list
            pass
    else:
        parsedCode = rawCode

    '''Reads all data and appends to device'''
    dvcs = iDeviceInfo(
        user_name,
        devicePlist.get('Device Class', ''),
        devicePlist.get('Serial Number', ''),
        devicePlist.get('Use Count', ''),
        devicePlist.get('Connected', ''),
        devicePlist.get('Firmware Version String', ''),
        devicePlist.get('Product Type', ''),
        devicePlist.get('ID', ''),
        devicePlist.get('IMEI', ''),
        devicePlist.get('Build Version', ''),
        devicePlist.get('MEID', ''),
        parsedCode,
        devicePlist.get('Firmware Version', ''),
        userDevicePath
    )
    devices.append(dvcs)

'''Function to return the data from the plist'''
def deviceFinder(userDevicePath, user_name, devices, standalone, mac_info = None):
    '''Opens com.apple.iPod.plist dependant on standalone flag'''
    if standalone:
        try:
            devicePlist = readPlist(userDevicePath)
        except InvalidPlistException as ex:
            log.exception("Could not read plist: " + userDevicePath + " Exception was: " + str(ex))
    else:
        success, devicePlist, error = mac_info.ReadPlist(userDevicePath)
        if not success:
            devicePlist = {}
            log.error('Error reading Info.plist - ' + error)

    allDevices = devicePlist.get('Devices', {})
    for d in allDevices:
        singleDevice = allDevices.get(d, {})
        if standalone:
            deviceReader(singleDevice, userDevicePath, user_name, devices)
        else:
            deviceReader(singleDevice, userDevicePath, user_name, devices)

def Plugin_Start(mac_info):
    '''Main Entry point function for plugin'''
    devicePath = '{}/Library/Preferences/com.apple.iPod.plist'
    processed_paths = []
    devices = []
    for user in mac_info.users:
        for user in mac_info.users:
            user_name = user.user_name
            if user.home_dir == '/private/var':
                continue  # Optimization, nothing should be here!
            elif user.home_dir == '/private/var/root':
                user_name = 'root'  # Some other users use the same root folder, we will list such all users as 'root', as there is no way to tell
            if user.home_dir in processed_paths: continue  # Avoid processing same folder twice (some users have same folder! (Eg: root & daemon))
            processed_paths.append(user.home_dir)
            userDevicePath = devicePath.format(user.home_dir)
            export_folder_path = os.path.join(__Plugin_Name, user_name + "_iDeviceInfo")  # Should create folder EXPORT/IDEVICEBACKUPS/user_BackupUUID/
            if mac_info.IsValidFilePath(userDevicePath):
                log.info("Found iDevice Info for user: " + user_name)
                mac_info.ExportFile(userDevicePath, export_folder_path)
                deviceFinder(userDevicePath, user_name, devices, 0, mac_info)

    if devices:
        PrintAll(mac_info.output_params, '', devices)
    else:
        log.info('No iDevice Info found')

def Plugin_Start_Standalone(input_files_list, output_params):
    log.info("Module Started as standalone")
    devices = []
    inputFile = str(input_files_list[0])
    if os.path.isfile(inputFile):
        deviceFinder(input_files_list[0], "", devices, 1)
        if devices:
            PrintAll(output_params, '', devices)
        else:
            log.info('No iDevice Info found')
    else:
        log.error("Input must be the com.apple.iPod.plist plist")

if __name__ == '__main__':
    print ("This plugin is a part of a framework and does not run independently on its own!")