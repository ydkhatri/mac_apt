'''
   Copyright (c) 2017 Yogesh Khatri 

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the 
   terms of the MIT License.
   
'''
from __future__ import print_function
from __future__ import unicode_literals
import os
import biplist
import sys
import logging

from biplist import *
from enum import IntEnum
from binascii import unhexlify
from helpers.macinfo import *
from helpers.writer import *


__Plugin_Name = "WIFI"
__Plugin_Friendly_Name = "Wifi-Airport Preferences"
__Plugin_Version = "1.0"
__Plugin_Description = "Gets wifi network information from the com.apple.airport.preferences.plist file"
__Plugin_Author = "Michael Geyer, Yogesh Khatri"
__Plugin_Author_Email = "michael.geyer@mymail.champlain.edu, yogesh@swiftforensics.com"

__Plugin_Standalone = True
__Plugin_Standalone_Usage = 'Provide the airport wifi plist file found at /Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist'

log = logging.getLogger('MAIN.' + __Plugin_Name) # Do not rename or remove this ! This is the logger object

#---- Do not change the variable names in above section ----#

class NetType(IntEnum):
    UNKNOWN = 0
    KNOWN = 1
    PREVIOUSREMEMBERED = 2 # Perhaps after an update ?

    def __str__(self):
        return self.name # This return 'KNOWN' instead of 'NetType.KNOWN'

class Network: 
    
    def __init__(self):
        self.Name = ''
        self.Order = None
        self.Type = NetType.UNKNOWN
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

    # Not all parameters are present always, so reading them needs
    # to be in a try except block
    def ReadParam(self, dictionary, param):
        return dictionary.get(param, '') # <-- returning empty string is better than None 
    
    def ReadNetworkInfo(self, dictionary, net_type): # Changed var names as they clash with common 'dict' class and reserved keyword 'type'
        self.Type = net_type
        self.AutoLogin = self.ReadParam(dictionary, 'AutoLogin')
        self.Captive = self.ReadParam(dictionary, 'Captive')
        self.Closed = self.ReadParam(dictionary, 'Closed')
        self.CollocatedGroup = self.ReadParam(dictionary, 'CollocatedGroup')        
        self.Disabled = self.ReadParam(dictionary, 'Disabled')        
        self.LastConnected = self.ReadParam(dictionary, 'LastConnected')        
        self.Passpoint = self.ReadParam(dictionary, 'Passpoint')    
        self.PersonalHotspot = self.ReadParam(dictionary, 'PersonalHotspot')        
        self.PossiblyHiddenNetwork = self.ReadParam(dictionary, 'PossiblyHiddenNetwork')
        self.RoamingProfileType = self.ReadParam(dictionary, 'RoamingProfileType')        
        self.SPRoaming = self.ReadParam(dictionary, 'SPRoaming')    
        #self.SSID = self.ReadParam(dictionary, 'SSID')
        self.SSIDString = self.ReadParam(dictionary, 'SSIDString')
        self.SecurityType = self.ReadParam(dictionary, 'SecurityType')        
        self.SystemMode = self.ReadParam(dictionary, 'SystemMode')
        self.TemporarilyDisabled = self.ReadParam(dictionary, 'TemporarilyDisabled')
        self.ChannelHistory = self.ReadParam(dictionary, 'ChannelHistory')

def GetReadableSSID(ssid):
    global wifi_plist_ver
    
    try:
        if (wifi_plist_ver == 2500):
            ssid = ssid[10:]
        else:
            ssid = ssid[11:-1]
            ssid = ssid.replace(" ", "")
        ssid = unhexlify(ssid).decode('utf-8')
    except Exception as e:
        log.error ('Error in GetReadableSSID() Details: ' + str(e))
    return ssid
    
def GetSSIDs(ssids):
    list = []
    for ssid in ssids:
        ssid_readable = GetReadableSSID(ssid)
        if ssid_readable:
            list.append(ssid_readable)
    return list

def PrintAll(networks, output_params, source_path):
    #Removed SSID (redundant and problematic sometimes because of binary data)
    network_info = [ ('Name',DataType.TEXT),('SSIDString',DataType.TEXT),('Preferred order',DataType.INTEGER),
                     ('Type',DataType.TEXT),('Security Type',DataType.TEXT),('Auto login',DataType.TEXT),
                     ('Captive',DataType.TEXT),('Closed',DataType.TEXT),('Collocated group', DataType.TEXT),
                     ('Disabled', DataType.TEXT),('Last connected', DataType.DATE),('Passpoint', DataType.TEXT),
                     ('Personal Hotspot',DataType.TEXT),('Possibly hidden network',DataType.TEXT),('Roaming profile type',DataType.TEXT),
                     ('SPRoaming',DataType.TEXT),('System mode',DataType.TEXT),('Temporarily disabled',DataType.TEXT),
                     ('Last connected channel',DataType.TEXT),('Other channel history',DataType.TEXT)
                   ]

    log.info ("Found " + str(len(networks)) + " network(s)")
    data_list = []
    for wifi in networks:
        data_list.append( [ wifi.Name, wifi.SSIDString, wifi.Order, str(wifi.Type), wifi.SecurityType, wifi.AutoLogin, 
                            wifi.Captive, wifi.Closed, 
                            '' if wifi.CollocatedGroup == None else ','.join(wifi.CollocatedGroup), 
                            wifi.Disabled, wifi.LastConnected, wifi.Passpoint, wifi.PersonalHotspot, wifi.PossiblyHiddenNetwork, 
                            wifi.RoamingProfileType,wifi.SPRoaming, wifi.SystemMode, wifi.TemporarilyDisabled, 
                            str(wifi.lastChannelHistory), 
                            str(wifi.ChannelHistory) if (wifi.ChannelHistory and len(wifi.ChannelHistory) > 0) else ''
                          ] )

    WriteList("wifi network information", "Wifi", data_list, network_info, output_params, source_path)
    
    
# # # MAIN PROGRAM BELOW # # # 

wifi_plist_ver = 0

def ParseWifi(input_file):
    networks = []
    try:
        plist = readPlist(input_file)
        ReadAirportPrefPlist(plist, networks)
    except (InvalidPlistException, NotBinaryPlistException) as e:
        log.error ("Could not open plist, error was : " + str(e) )
    return networks

def ProcessOlderAirportPrefPlist(plist, networks):
    try:
        rememberedNetworks = plist['RememberedNetworks']
        for network in rememberedNetworks:
            try:
                net = Network()
                net.ReadNetworkInfo(network, NetType.KNOWN)
                networks.append(net)
            except Exception as e:
                log.error ('Error reading RememberedNetworks: ' + str(e))    
    except:
        log.debug ('RememberedNetworks not found in plist')

def ReadAirportPrefPlist(plist, networks):
    #Read version info (12=10.8, 14=10.9, 2200=10.10 & higher)
    # No version info in SnowLeopard (10.6) !
    global wifi_plist_ver
    wifi_plist_ver = 0
    try:
        wifi_plist_ver = plist['Version']
        log.debug ("com.apple.airport.preferences.plist version is {}".format(wifi_plist_ver))
    except Exception as e:
        log.info ('Error reading version number: ' + str(e))
    if wifi_plist_ver <= 14:
        ProcessOlderAirportPrefPlist(plist, networks)
        return
    try:
        # Is this UTC or local? Seems to be converted to local time due 
        # This might be a creation time of the plist, not last updated.  More research is needed
        log.debug ("UpdateHistory timestamp is " + str(plist['UpdateHistory'][0]['Timestamp']))
        
    except Exception as e:
        log.debug ('Could not read UpdateHistory Timestamp ' + str(e))
        
    #Puts the list of Preferred order into a list and decode the names
    try:
        PreferedList = plist['PreferredOrder']
        PreferredOrder = []
        for prefered in PreferedList:
            PreferredOrder.append(GetReadableSSID(prefered))
    except Exception as e:
        log.error ('Error parsing order of known networks: ' + str(e))
    
    #parses known networks first
    try:
        knownNetworks = plist['KnownNetworks']
        try:
            for network in knownNetworks:
                net = Network()
                net.Name = GetReadableSSID(network)
                for name in PreferredOrder:
                    if name == net.Name:
                        net.Order = PreferredOrder.index(name) + 1 #add one to preferred order so start is 1 and not 0
                        
                net.ReadNetworkInfo(knownNetworks[network], NetType.KNOWN)
                
                SSIDNames = net.CollocatedGroup
                if SSIDNames != None:
                    net.CollocatedGroup = GetSSIDs(SSIDNames)
                    
                #pulls the most recently used timestamp and channel and puts it into a separate list
                #also parses Channel history to a format that is more standard and readable
                try:
                    if net.ChannelHistory != []:
                        history = net.ChannelHistory
                        net.ChannelHistory = []
                        
                        high = 0
                        for i in xrange(len(history) - 1):
                            if history[i]['Timestamp'] < history[i + 1]['Timestamp']:
                                high = i + 1
                        time = history[high]['Timestamp'].strftime('%Y/%m/%d %H:%M:%S')
                        net.lastChannelHistory = [time, str(history[high]['Channel'])]
                        for i in xrange(len(history) - 1):
                            if i != high:
                                string = '(' + history[high]['Timestamp'].strftime('%Y/%m/%d %H:%M:%S') + ', ' + str(history[high]['Channel']) + ')'
                                net.ChannelHistory.append(string)
                except Exception as e:
                    log.error ("Error could not parse channel history: " + str(e))
                    
                networks.append(net)
        except Exception as e:
            print ('Error parsing and adding a known network to the final known network list: ', str(e))
    except Exception as e:
        log.error ('Error reading known networks: ' + str(e))

    #Note: some plists don't have any information.  look for check here
    try:
        # Prev Remembered Networks
        prevRemembered = plist['UpdateHistory'][0]['Previous']['RememberedNetworks']
        try:
            log.debug ("UpdateHistory Previous RememberedNetworks version is " + str(plist['UpdateHistory'][0]['Previous']['Version']))
        except Exception as e:
            pass
        for network in prevRemembered:
            net = Network()
            net.ReadNetworkInfo(network, NetType.PREVIOUSREMEMBERED)
            networks.append(net)
    except Exception as e:
        pass
        #fix pass for e if nothing exists within remembered networks
        # if e.con == ' \'RememberedNetworks\' ':
            # pass
        # else:
            # print ('Error could not parse previously remembered networks: ', e)

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