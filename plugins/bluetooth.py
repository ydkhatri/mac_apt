'''
   Copyright (c) 2018 Yogesh Khatri

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the
   terms of the MIT License.

   bluetooth.py
   ---------------
   Parses system Bluetooth artifacts from com.apple.Bluetooth.plist. 
   
   This file also uses code from https://github.com/mikeryan/btclassify 
   written by Mike Ryan to parse ClassOfDevice. 

'''

import logging
import re
import yaml

from importlib.resources import files
from plugins.helpers.common import CommonFunctions
from plugins.helpers.macinfo import *
from plugins.helpers.writer import *

__Plugin_Name = "BLUETOOTH"
__Plugin_Friendly_Name = "Bluetooth Parser"
__Plugin_Version = "1.2"
__Plugin_Description = "Parses System Bluetooth Artifacts"
__Plugin_Author = "Adam Ferrante, Yogesh Khatri"
__Plugin_Author_Email = "adam@ferrante.io, yogesh@swiftforensics.com"
__Plugin_Modes = "MACOS,ARTIFACTONLY"
__Plugin_ArtifactOnly_Usage = 'Provide the plist files located at /Library/Preferences/com.apple.Bluetooth.plist or /Library/Bluetooth/Library/Preferences/com.apple.MobileBluetooth.devices.plist'

log = logging.getLogger('MAIN.' + __Plugin_Name) # Do not rename or remove this ! This is the logger object

#---- Do not change the variable names in above section ----#

def ParseClassOfDevice(cod_number):
    '''
    Parses a cod and returns tuple (device, service) where
    device and service are strings.
    Code courtesy of https://github.com/mikeryan/btclassify
    '''
    if cod_number == None: return ('', '')
    try:
        class_string = '0x{:06X}'.format(cod_number)
        m = re.match('(0x)?([0-9A-Fa-f]{6})', class_string)
        if m is None:
            log.error("Invalid class, skipping (%s)" % class_string)
            return ('Invalid', 'Invalid')

        hex_string = m.group(2)

        # "class" is a reserved word in Python, so CoD is class
        CoD = int(hex_string, 16)

        # Class of Device: 0x38010c (Computer - services: Audio, Object transfer, Capturing)

        # Major Device Classes
        classes = ['Miscellaneous', 'Computer', 'Phone', 'LAN/Network Access Point',
                'Audio/Video', 'Peripheral', 'Imaging', 'Wearable', 'Toy',
                'Health']
        major_number = (CoD >> 8) & 0x1f
        if major_number < len(classes):
            major = classes[major_number]
        elif major_number == 31:
            major = 'Uncategorized'
        else:
            major = 'Reserved'

        # Minor - varies depending on major
        minor_number = (CoD >> 2) & 0x3f
        minor = None

        # computer
        if major_number == 1:
            classes = [
                'Uncategorized', 'Desktop workstation', 'Server-class computer',
                'Laptop', 'Handheld PC/PDA (clamshell)', 'Palm-size PC/PDA',
                'Wearable computer (watch size)', 'Tablet']
            if minor_number < len(classes):
                minor = classes[minor_number]
            else:
                minor = 'reserved'

        # phone
        elif major_number == 2:
            classes = [
                'Uncategorized', 'Cellular', 'Cordless', 'Smartphone',
                'Wired modem or voice gateway', 'Common ISDN access']
            if minor_number < len(classes):
                minor = classes[minor_number]
            else:
                minor = 'reserved'

        # network access point
        elif major_number == 3:
            minor_number >> 3
            classes = [
                'Fully available', '1% to 17% utilized', '17% to 33% utilized',
                '33% to 50% utilized', '50% to 67% utilized',
                '67% to 83% utilized', '83% to 99% utilized',
                'No service available']
            if minor_number < len(classes):
                minor = classes[minor_number]
            else:
                minor = 'reserved'

        # audio/video
        elif major_number == 4:
            classes = [
                'Uncategorized', 'Wearable Headset Device', 'Hands-free Device',
                '(Reserved)', 'Microphone', 'Loudspeaker', 'Headphones',
                'Portable Audio', 'Car audio', 'Set-top box', 'HiFi Audio Device',
                'VCR', 'Video Camera', 'Camcorder', 'Video Monitor',
                'Video Display and Loudspeaker', 'Video Conferencing',
                '(Reserved)', 'Gaming/Toy']
            if minor_number < len(classes):
                minor = classes[minor_number]
            else:
                minor = 'reserved'

        # peripheral, this one's gross
        elif major_number == 5:
            feel_number = minor_number >> 4
            classes = [
                'Not Keyboard / Not Pointing Device', 'Keyboard',
                'Pointing device', 'Combo keyboard/pointing device']
            feel = classes[feel_number]

            classes = [
                'Uncategorized', 'Joystick', 'Gamepad', 'Remote control',
                'Sensing device', 'Digitizer tablet', 'Card Reader', 'Digital Pen',
                'Handheld scanner for bar-codes, RFID, etc.',
                'Handheld gestural input device' ]
            if minor_number < len(classes):
                minor_low = classes[minor_number]
            else:
                minor_low = 'reserved'
            
            minor = '%s, %s' % (feel, minor_low)

        # imaging
        elif major_number == 6:
            minors = []
            if minor_number & (1 << 2):
                minors.append('Display')
            if minor_number & (1 << 3):
                minors.append('Camera')
            if minor_number & (1 << 4):
                minors.append('Scanner')
            if minor_number & (1 << 5):
                minors.append('Printer')
            if len(minors) > 0:
                minors = ', '.join(minors)

        # wearable
        elif major_number == 7:
            classes = ['Wristwatch', 'Pager', 'Jacket', 'Helmet', 'Glasses']
            if minor_number < len(classes):
                minor = classes[minor_number]
            else:
                minor = 'reserved'

        # toy
        elif major_number == 8:
            classes = ['Robot', 'Vehicle', 'Doll / Action figure', 'Controller',
                    'Game']
            if minor_number < len(classes):
                minor = classes[minor_number]
            else:
                minor = 'reserved'

        # health
        elif major_number == 9:
            classes = [
                'Undefined', 'Blood Pressure Monitor', 'Thermometer',
                'Weighing Scale', 'Glucose Meter', 'Pulse Oximeter',
                'Heart/Pulse Rate Monitor', 'Health Data Display', 'Step Counter',
                'Body Composition Analyzer', 'Peak Flow Monitor',
                'Medication Monitor', 'Knee Prosthesis', 'Ankle Prosthesis',
                'Generic Health Manager', 'Personal Mobility Device']
            if minor_number < len(classes):
                minor = classes[minor_number]
            else:
                minor = 'reserved'

        # Major Service Class (can by multiple)
        services = []
        if CoD & (1 << 23):
            services.append('Information')
        if CoD & (1 << 22):
            services.append('Telephony')
        if CoD & (1 << 21):
            services.append('Audio')
        if CoD & (1 << 20):
            services.append('Object Transfer')
        if CoD & (1 << 19):
            services.append('Capturing')
        if CoD & (1 << 18):
            services.append('Rendering')
        if CoD & (1 << 17):
            services.append('Networking')
        if CoD & (1 << 16):
            services.append('Positioning')
        if CoD & (1 << 15):
            services.append('(reserved)')
        if CoD & (1 << 14):
            services.append('(reserved)')
        if CoD & (1 << 13):
            services.append('Limited Discoverable Mode')
        device = major + (('[' + minor + ']') if minor else '')
        return (device, ', '.join(services))
    except (KeyError, ValueError):
        log.exception("")
    return ('', '')


class BluetoothCacheItem:
    def __init__(self, bluetooth_address, name, usernamekey, displayname, manufacturer, batterypercent, connected, vendorid, productid, cod, lastnameupdate, services, supportfeatures, lastservicesupdate, last_seen, source):

        self.bluetooth_address = bluetooth_address
        self.name = name
        self.usernamekey = usernamekey
        self.displayname = displayname
        self.manufacturer = manufacturer
        self.batterypercent = batterypercent
        self.connected = connected # rename to Paired??
        self.vendorid = vendorid
        self.productid = productid
        self.classofdevice = cod
        self.lastnameupdate = lastnameupdate
        self.services = services
        self.supportfeatures = supportfeatures
        self.lastservicesupdate = lastservicesupdate
        self.last_seen = last_seen
        self.source = source

def PrintAll(bluetooth_devices, output_params, input_path=''):
    # read vendor list from yaml
    # https://bitbucket.org/bluetooth-SIG/public/raw/95d7e6796256035562dbf2485d418338cb79f395/assigned_numbers/company_identifiers/company_identifiers.yaml
    log.debug('Trying to parse vendor list')
    vendors = {}
    try:
        package_files = files('plugins.helpers')
        yaml_file = package_files.joinpath('bluetooth_company_identifiers.yaml')
        yaml_text = yaml_file.read_text(encoding='utf-8')

        vendor_data = yaml.safe_load(yaml_text)
        for c in vendor_data['company_identifiers']:
            vendors[c['value']] = c['name']

    except (ModuleNotFoundError, FileNotFoundError, yaml.error.YAMLError, KeyError) as ex:
        log.exception('Error trying to read embedded vendor yaml file')
    log.debug(f'{len(vendors)} vendor ids read.')
    
    bluetooth_info = [   ('Bluetooth Address',DataType.TEXT),('Name',DataType.TEXT),('UserNameKey',DataType.TEXT),
                    ('Display Name',DataType.TEXT),('Manufacturer', DataType.TEXT),('Battery Percent',DataType.REAL),
                    ('Connected',DataType.TEXT), ('Vendor',DataType.TEXT), ('Vendor ID',DataType.INTEGER), ('Product ID',DataType.INTEGER),
                    ('Class of Device',DataType.INTEGER), ('CoD_Device',DataType.TEXT), ('CoD_Service',DataType.TEXT),
                    ('Last Name Update',DataType.DATE), ('Services',DataType.BLOB),
                    ('Support Features',DataType.BLOB), ('Last Services Update',DataType.DATE),
                    ('Last Seen',DataType.DATE),
                    ('Source',DataType.TEXT)
                ]

    log.info (str(len(bluetooth_devices)) + " Bluetooth device(s) found")

    bluetooth_devices_list = []

    for device in bluetooth_devices:
        cod_device, cod_service = ParseClassOfDevice(device.classofdevice)
        vendor_name = vendors.get(device.vendorid, f"Unknown {device.vendorid}")
        single_bt_instance = [device.bluetooth_address, device.name, device.usernamekey,
                            device.displayname, device.manufacturer, device.batterypercent,
                            device.connected, vendor_name, device.vendorid, device.productid, 
                            device.classofdevice, cod_device, cod_service, device.lastnameupdate,
                            device.services, device.supportfeatures, device.lastservicesupdate,
                            device.last_seen,
                            device.source
                            ]

        bluetooth_devices_list.append(single_bt_instance)

    WriteList("Bluetooth Devices", "BT Devices", bluetooth_devices_list, bluetooth_info, output_params, input_path)


def ReadBluetoothPlist(plist, source_path):
    '''Reads the com.apple.Bluetooth.plist and gets connected device info'''
    # Check to see what devices were paired first for later comparison.
    try:
        connected_devices = plist['PairedDevices']
    except KeyError:
        log.debug("Paired devices missing, did this device ever touch/use another Bluetooth device?")
        connected_devices = []

    # Gather the data from the DeviceCache key, and put it into an object.
    cache_list = []
    device_cache = plist.get('DeviceCache', None)
    if device_cache:
        for cached_device in device_cache.keys():
            cache_data = device_cache.get(cached_device, None)
            if cache_data:
                cache_item = BluetoothCacheItem(
                    cached_device,
                    cache_data.get('Name', '').upper(),
                    cache_data.get('UserNameKey', ''),
                    cache_data.get('displayName', ''),
                    cache_data.get('Manufacturer', ''),
                    cache_data.get('BatteryPercent', None), 
                    'Yes' if cached_device in connected_devices else 'No',
                    cache_data.get('VendorID', None),
                    cache_data.get('ProductID', None),
                    cache_data.get('ClassOfDevice', None),
                    cache_data.get('LastNameUpdate', None),
                    cache_data.get('Services', None),
                    cache_data.get('SupportedFeatures', None),
                    cache_data.get('LastServicesUpdate', None),
                    None,
                    source_path
                )
                cache_list.append(cache_item)
    return cache_list

def FindCachedItem(cache_list, mac_address):
    '''Return BluetoothCacheItem that matches mac_address'''
    mac_address = mac_address.upper()
    for item in cache_list:
        if item.bluetooth_address == mac_address:
            return item
    return None

def ReadMobileBluetoothPlist(plist, mobile_bluetooth_path, cache_list):
    for device_mac_address, device_details in plist.items():
        cached_item = FindCachedItem(cache_list, device_mac_address)
        device_class = struct.unpack('<i', device_details.get('DeviceClass', b'\0'*4))[0]

        if cached_item is None:
            cached_item = BluetoothCacheItem(
                device_mac_address.upper(), 
                device_details.get('DefaultName', ''),
                device_details.get('Name', ''),
                device_details.get('UserNameKey', ''),
                '',
                '',
                'Yes',
                device_details.get('DeviceIdVendor', ''),
                device_details.get('DeviceIdProduct', ''),
                device_class,
                None,
                None,
                None,
                None,
                CommonFunctions.ReadUnixTime(device_details.get('LastSeenTime', '')),
                mobile_bluetooth_path
                )
            cache_list.append(cached_item)
        else:
            cached_item.last_seen = CommonFunctions.ReadUnixTime(device_details.get('LastSeenTime', ''))

def Plugin_Start(mac_info):
    '''Main Entry point function for plugin'''
    bluetooth_path = '/Library/Preferences/com.apple.Bluetooth.plist'
    mobile_bluetooth_path = '/Library/Bluetooth/Library/Preferences/com.apple.MobileBluetooth.devices.plist'
    cache_list = []

    if mac_info.IsValidFilePath(bluetooth_path):
        mac_info.ExportFile(bluetooth_path, __Plugin_Name)
        success, plist, error = mac_info.ReadPlist(bluetooth_path)
        if success:
            cache_list = ReadBluetoothPlist(plist, bluetooth_path)
    else:
        log.warning(f'{bluetooth_path} not found')

    if mac_info.IsValidFilePath(mobile_bluetooth_path):
        mac_info.ExportFile(mobile_bluetooth_path, __Plugin_Name)
        success, plist, error = mac_info.ReadPlist(mobile_bluetooth_path)
        if success:
            ReadMobileBluetoothPlist(plist, mobile_bluetooth_path, cache_list)
    else:
        log.warning(f'{mobile_bluetooth_path} not found')

    # Write it all out.
    if len(cache_list) > 0:
        PrintAll(cache_list, mac_info.output_params, bluetooth_path)
    else:
        log.debug("No bluetooth devices found")

def Plugin_Start_Standalone(input_files_list, output_params):
    for input_file in input_files_list:
        cache_list = []
        success, plist, error = CommonFunctions.ReadPlist(input_file)
        if success:
            if input_file.endswith('com.apple.Bluetooth.plist'):
                cache_list = ReadBluetoothPlist(plist, input_file)
            elif input_file.endswith('com.apple.MobileBluetooth.devices.plist'):
                ReadMobileBluetoothPlist(plist, input_file, cache_list)
        else:
            log.error(error)

        if len(cache_list) > 0:
            PrintAll(cache_list, output_params, input_file)
        else:
            log.debug("No bluetooth devices found")

if __name__ == '__main__':
    print ("This plugin is a part of a framework and does not run independently on its own!")