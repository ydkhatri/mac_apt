'''
   Copyright (c) 2017 Yogesh Khatri 

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the 
   terms of the MIT License.
   
'''

import os
import biplist
import sys
import logging

from biplist import *
from enum import IntEnum
from binascii import unhexlify
from plugins.helpers.macinfo import *
from plugins.helpers.writer import *


__Plugin_Name = "WIFI"
__Plugin_Friendly_Name = "Wifi-Airport Preferences"
__Plugin_Version = "1.1"
__Plugin_Description = "Gets wifi network information from the com.apple.airport.preferences.plist file"
__Plugin_Author = "Michael Geyer, Yogesh Khatri"
__Plugin_Author_Email = "michael.geyer@mymail.champlain.edu, yogesh@swiftforensics.com"
__Plugin_Modes = "MACOS,ARTIFACTONLY"
__Plugin_ArtifactOnly_Usage = 'Provide the airport wifi plist file found at /Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist'

log = logging.getLogger('MAIN.' + __Plugin_Name) # Do not rename or remove this ! This is the logger object

#---- Do not change the variable names in above section ----#

class NetType(IntEnum):
    UNKNOWN = 0
    KNOWN = 1
    PREVIOUSREMEMBERED = 2 # After an update ?

    def __str__(self):
        return self.name # This returns 'KNOWN' instead of 'NetType.KNOWN'

class Network: 
    
    def __init__(self, version):
        self.Name = ''
        self.Order = None
        self.Type = NetType.UNKNOWN
        self.Version = version
        self.Disabled = False
        self.SystemMode = False
        self.PossiblyHiddenNetwork = False
        self.TemporarilyDisabled = False
        self.Closed = False
        self.SecurityType = ""
        self.SSIDString = ""
        self.SPRoaming = False
        self.Passpoint = False
        self.AutoLogin = False
        self.Captive = False
        self.LastConnected = None
        self.PersonalHotspot = False
        self.CollocatedGroup = ""
        self.RoamingProfileType = ""
        self.lastChannelHistory = ""
        self.ChannelHistory = ""
        self.BSSIDHistory = None
    
    def ReadNetworkInfo(self, dictionary, net_type):
        self.Type = net_type
        self.AutoLogin = dictionary.get('AutoLogin', '')
        self.Captive = dictionary.get('Captive', '')
        self.Closed = dictionary.get('Closed', '')
        self.CollocatedGroup = dictionary.get('CollocatedGroup', '')
        self.Disabled = dictionary.get('Disabled', '')
        self.LastConnected = dictionary.get('LastConnected', '')
        self.Passpoint = dictionary.get('Passpoint', '')
        self.PersonalHotspot = dictionary.get('PersonalHotspot', '')
        self.PossiblyHiddenNetwork = dictionary.get('PossiblyHiddenNetwork', '')
        self.RoamingProfileType = dictionary.get('RoamingProfileType', '')
        self.SPRoaming = dictionary.get('SPRoaming', '')
        #self.SSID = dictionary.get('SSID')
        self.SSIDString = dictionary.get('SSIDString', '')
        self.SecurityType = dictionary.get('SecurityType', '')
        self.SystemMode = dictionary.get('SystemMode', '')
        self.TemporarilyDisabled = dictionary.get('TemporarilyDisabled')
        self.ChannelHistory = dictionary.get('ChannelHistory')
        bssid_history = dictionary.get('BSSIDHistory', None) # Present if version=1900
        if bssid_history and len(bssid_history) > 0:
            self.BSSIDHistory = ''
            for history_item in bssid_history:
                self.BSSIDHistory += '[MAC={}, {}]'.format(
                                        history_item.get('BSSID',''), 
                                        str(history_item.get('Timestamp', '')) )

def GetReadableSSID(ssid, wifi_plist_ver):
    try:
        if (wifi_plist_ver >= 2500):
            ssid = ssid[10:]
        else:
            ssid = ssid[11:-1]
        ssid = ssid.replace(" ", "").replace("<", "").replace(">", "")
        ssid = unhexlify(ssid).decode('utf-8', 'backslashreplace')
    except (ValueError, IndexError) as e:
        log.error ('Error in GetReadableSSID() Details: ' + str(e))
    return ssid
    
def GetSSIDs(ssids, wifi_plist_ver):
    list = []
    for ssid in ssids:
        ssid_readable = GetReadableSSID(ssid, wifi_plist_ver)
        if ssid_readable:
            list.append(ssid_readable)
    return list

def PrintAll(networks, output_params, source_path):
    #Removed SSID (redundant and problematic sometimes because of binary data)
    network_info = [ ('Name',DataType.TEXT),('SSIDString',DataType.TEXT),('Preferred order',DataType.INTEGER),('Version',DataType.TEXT),
                     ('Type',DataType.TEXT),('Security Type',DataType.TEXT),('Auto login',DataType.TEXT),
                     ('Captive',DataType.TEXT),('Closed',DataType.TEXT),('Collocated group', DataType.TEXT),
                     ('Disabled', DataType.TEXT),('Last connected', DataType.DATE),('Passpoint', DataType.TEXT),
                     ('Personal Hotspot',DataType.TEXT),('Possibly hidden network',DataType.TEXT),('Roaming profile type',DataType.TEXT),
                     ('SPRoaming',DataType.TEXT),('System mode',DataType.TEXT),('Temporarily disabled',DataType.TEXT),
                     ('Last connected channel',DataType.TEXT),('Other channel history',DataType.TEXT),
                     ('BSSIDHistory',DataType.TEXT)
                   ]

    log.info ("Found " + str(len(networks)) + " network(s)")
    data_list = []
    for wifi in networks:
        data_list.append( [ wifi.Name, wifi.SSIDString, wifi.Order, wifi.Version, 
                            str(wifi.Type), wifi.SecurityType, wifi.AutoLogin, 
                            wifi.Captive, wifi.Closed, 
                            '' if wifi.CollocatedGroup == None else ','.join(wifi.CollocatedGroup), 
                            wifi.Disabled, wifi.LastConnected, wifi.Passpoint, wifi.PersonalHotspot, wifi.PossiblyHiddenNetwork, 
                            wifi.RoamingProfileType,wifi.SPRoaming, wifi.SystemMode, wifi.TemporarilyDisabled, 
                            str(wifi.lastChannelHistory), 
                            str(wifi.ChannelHistory) if (wifi.ChannelHistory and len(wifi.ChannelHistory) > 0) else '',
                            wifi.BSSIDHistory
                          ] )

    WriteList("wifi network information", "Wifi", data_list, network_info, output_params, source_path)
    
    
# # # MAIN PROGRAM BELOW # # # 

def ParseWifi(input_file):
    networks = []
    try:
        plist = readPlist(input_file)
        ReadAirportPrefPlist(plist, networks)
    except (OSError, InvalidPlistException) as e:
        log.error ("Could not open plist, error was : " + str(e) )
    return networks

def ProcessOlderAirportPrefPlist(plist, networks, version):
    try:
        rememberedNetworks = plist['RememberedNetworks']
        for network in rememberedNetworks:
            net = Network(version)
            net.ReadNetworkInfo(network, NetType.KNOWN)
            networks.append(net)
    except KeyError:
        log.debug ('RememberedNetworks not found in plist')

def ParseKnownNetworksAndPreferredOrder(known_networks, networks, preferred_order, version, net_type=NetType.KNOWN):
    #Puts the list of Preferred order into a list and decode the names
    try:
        for network in known_networks:
            net = Network(version)
            net.Name = GetReadableSSID(network, version)
            for name in preferred_order:
                if name == net.Name:
                    net.Order = preferred_order.index(name) + 1 #add one to preferred order so start is 1 and not 0
                    
            net.ReadNetworkInfo(known_networks[network], net_type)
            
            SSIDNames = net.CollocatedGroup
            if SSIDNames != None:
                net.CollocatedGroup = GetSSIDs(SSIDNames, version)
                
            #pulls the most recently used timestamp and channel and puts it into a separate list
            #also parses Channel history to a format that is more standard and readable
            try:
                if net.ChannelHistory != []:
                    history = net.ChannelHistory
                    net.ChannelHistory = []
                    
                    high = 0
                    for i in range(len(history) - 1):
                        if history[i]['Timestamp'] < history[i + 1]['Timestamp']:
                            high = i + 1
                    time = history[high]['Timestamp'].strftime('%Y/%m/%d %H:%M:%S')
                    net.lastChannelHistory = [time, str(history[high]['Channel'])]
                    for i in range(len(history) - 1):
                        if i != high:
                            string = '(' + history[high]['Timestamp'].strftime('%Y/%m/%d %H:%M:%S') + ', ' + str(history[high]['Channel']) + ')'
                            net.ChannelHistory.append(string)
            except (KeyError, ValueError) as e:
                log.exception ("Error could not parse channel history: " + str(e))
            networks.append(net)
    except Exception as e:
        log.exception('Error parsing and adding a known network to the final known network list')

def ReadAirportPrefPlist(plist, networks):
    # Read version info (12=10.8, 14=10.9, 2200=10.10 & higher) Also seen 1900 and 2100
    # Version 1900 has BSSIDHistory (MAC address of AP & timestamp)
    # No version info in SnowLeopard (10.6) !

    wifi_plist_ver = plist.get('Version', 0)
    log.debug ("com.apple.airport.preferences.plist version is {}".format(wifi_plist_ver))
    if wifi_plist_ver == 0:
        log.error ('Could not find com.apple.airport.preferences.plist version number')
    if wifi_plist_ver <= 14:
        ProcessOlderAirportPrefPlist(plist, networks, wifi_plist_ver)
        return
    
    #parses known networks first
    preferred_order = [GetReadableSSID(x, wifi_plist_ver) for x in plist.get('PreferredOrder', [])]
    known_networks = plist.get('KnownNetworks', {})
    ParseKnownNetworksAndPreferredOrder(known_networks, networks, preferred_order, wifi_plist_ver)

    # UpdateHistory is a list, can have multiple elements
    for history_item in plist.get('UpdateHistory', []):
        log.debug("UpdateHistory timestamp is " + str(history_item.get('Timestamp', ''))) # time when this plist was created with new format, and old data archived here?
        previous = history_item.get('Previous', None) # Will exist but may be blank too
        if not previous:
            continue
        prev_version = previous.get('Version', 0)
        log.info("UpdateHistory version is {}".format(prev_version))
        # Prev Remembered Networks
        prevRemembered = previous.get('RememberedNetworks', [])
        for network in prevRemembered:
            net = Network(prev_version)
            net.ReadNetworkInfo(network, NetType.PREVIOUSREMEMBERED)
            networks.append(net)
        
        prev_networks = []
        prev_preferred_order = [GetReadableSSID(x, prev_version) for x in previous.get('PreferredOrder', [])]
        prev_known_networks = previous.get('KnownNetworks', {})
        ParseKnownNetworksAndPreferredOrder(prev_known_networks, prev_networks, prev_preferred_order, prev_version, NetType.PREVIOUSREMEMBERED)
        for network in prev_networks:
            networks.append(network)

def Plugin_Start(mac_info):
    '''Main Entry point function for plugin'''
    airport_pref_plist_path = '/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist'
    mac_info.ExportFile(airport_pref_plist_path, __Plugin_Name, '', False)
    success, plist, error = mac_info.ReadPlist(airport_pref_plist_path)
    if success:
        networks = []
        ReadAirportPrefPlist(plist, networks)
        if len(networks) > 0:
            PrintAll(networks, mac_info.output_params, airport_pref_plist_path)
        else:
            log.info('No wifi networks found')
    else:
        log.error('Could not open plist ' + airport_pref_plist_path)
        log.error('Error was: ' + error)
    
def Plugin_Start_Standalone(input_files_list, output_params):
    log.info("Module Started as standalone")
    for input_path in input_files_list:
        log.debug("Input file passed was: " + input_path)
        networks = ParseWifi(input_path)
        if len(networks) > 0:
            PrintAll(networks, output_params, input_path)
        else:
            log.info('No wifi networks found')

if __name__ == '__main__':
    print ("This plugin is a part of a framework and does not run independently on its own!")