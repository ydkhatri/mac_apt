'''
   Copyright (c) 2017 Yogesh Khatri 

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the 
   terms of the MIT License.
   
'''


import os
from plugins.helpers.macinfo import *
from plugins.helpers.writer import *
import logging
import biplist
import binascii
import sys


__Plugin_Name = "NETWORKING" # Cannot have spaces, and must be all caps!
__Plugin_Friendly_Name = "Networking"
__Plugin_Version = "1.0"
__Plugin_Description = 'Gets network related information - Interfaces, last IP addresses, MAC address, etc..'
__Plugin_Author = "Yogesh Khatri"
__Plugin_Author_Email = "yogesh@swiftforensics.com"

__Plugin_Standalone = False
__Plugin_Standalone_Usage = ''

log = logging.getLogger('MAIN.' + __Plugin_Name) # Do not rename or remove this ! This is the logger object

#---- Do not change the variable names in above section ----#

PYTHON_VER = sys.version_info.major
dhcp_interfaces = []
dhcp_data_info =  [ ('Interface',DataType.TEXT),('MAC_Address',DataType.TEXT),('IPAddress',DataType.TEXT),
                    ('LeaseLength',DataType.INTEGER),('LeaseStartDate',DataType.DATE),('PacketData',DataType.BLOB),
                    ('RouterHardwareAddress',DataType.TEXT),('RouterIPAddress',DataType.TEXT),
                    ('SSID', DataType.TEXT),('Source', DataType.TEXT)
                  ]
resolv_conf = []
etc_hosts = []
net_interfaces = []
net_interface_info = [  ('Category',DataType.TEXT),('Active',DataType.TEXT),('BSD Name',DataType.TEXT),
                        ('IOBuiltin',DataType.TEXT),('IOInterfaceNamePrefix', DataType.TEXT),('IOInterfaceType',DataType.INTEGER),
                        ('IOInterfaceUnit', DataType.INTEGER),('IOMACAddress',DataType.TEXT),('IOPathMatch',DataType.TEXT),
                        ('SCNetworkInterfaceInfo',DataType.TEXT),('SCNetworkInterfaceType',DataType.TEXT),('Source', DataType.TEXT)
                    ]

net_interface_details = []
net_interface_detail_info = [ ('UUID',DataType.TEXT),('IPv4.ConfigMethod',DataType.TEXT),('IPv6.ConfigMethod',DataType.TEXT),
                              ('DeviceName',DataType.TEXT),('Hardware',DataType.TEXT),('Type',DataType.TEXT),
                              ('SubType',DataType.TEXT),('UserDefinedName',DataType.TEXT),('Proxies.ExceptionsList',DataType.TEXT),
                              ('SMB.NetBIOSName',DataType.TEXT),('SMB.Workgroup',DataType.TEXT),
                              ('PPP',DataType.TEXT),('Modem',DataType.TEXT),('Source', DataType.TEXT) #,('VirtualInterfaces',DataType.TEXT)
                            ]

def GetNetworkInterface2Info(mac_info):
    '''Read interface info from /Library/Preferences/SystemConfiguration/preferences.plist'''
    preference_plist_path = '/Library/Preferences/SystemConfiguration/preferences.plist'
    mac_info.ExportFile(preference_plist_path, __Plugin_Name, '', False)
    success, plist, error_message = mac_info.ReadPlist(preference_plist_path)
    if success:
        try:
            for uuid, interface in list(plist['NetworkServices'].items()):
                interface_info = { 'UUID': uuid, 'Source': preference_plist_path }
                for item, value in list(interface.items()):
                    if item == 'DNS' and value: log.info('Interface {} has DNS info as : {}'.format(uuid, value))
                    elif item == 'UserDefinedName' or item == 'Modem' or item == 'PPP': interface_info[item] = str(value)
                    elif item == 'Proxies':
                        try:
                            exceptions = value['ExceptionsList']
                            interface_info['Proxies.ExceptionsList'] = ",".join(exceptions)
                        except:
                            log.debug('/NetworkServices/' + uuid + '/Proxies/ExceptionsList not found in plist ' + preference_plist_path)
                    elif item == 'IPv4': 
                        try:
                            method = value['ConfigMethod']
                            interface_info['IPv4.ConfigMethod'] = method
                        except Exception: log.error('/NetworkServices/' + uuid + '/IPv4/ConfigMethod not found in plist ' + preference_plist_path)
                    elif item == 'IPv6': 
                        try:
                            method = value['ConfigMethod']
                            interface_info['IPv6.ConfigMethod'] = method
                        except Exception: log.error('/NetworkServices/' + uuid + '/IPv6/ConfigMethod not found in plist ' + preference_plist_path)                        
                    elif item == 'Interface':
                        for k, v in list(value.items()):
                            if k in ['DeviceName', 'Hardware', 'Type', 'UserDefinedName']:  interface_info[k] = v
                            else:
                                log.info('Found unknown data in plist at /NetworkServices/' + uuid + '/Interface/' + k + ' Value=' + str(v))
                    elif item == 'SMB':
                        for k, v in list(value.items()):
                            if k in ['NetBIOSName', 'Workgroup', 'Type', 'UserDefinedName']:  interface_info['SMB.'+ k] = v
                            else:
                                log.info('Found unknown data in plist at /NetworkServices/' + uuid + '/SMB/' + k + ' Value=' + v)
                net_interface_details.append(interface_info)
                '''try:
                    for item, bridge in plist['VirtualNetworkInterfaces']['Bridge'].items():
                            try:
                                for if_name in bridge['Interfaces']:
                                    for interface in net_interface_details:
                                        if if_name == interface['DeviceName']: 
                                            interface['IsVirtualInterface'] = True
                                            break
                            except:
                                log.debug('/VirtualNetworkInterfaces/Bridge/' + bridge + '/Interfaces not found!')
                except Exception:
                    log.debug('/VirtualNetworkInterfaces/Bridge not found!')'''
        except Exception:
            log.exception('/NetworkServices not found or other error from ' + preference_plist_path)
    else:
        log.error('Failed to read plist ' + preference_plist_path + " Error was : " + error_message)

def GetNetworkInterfaceInfo(mac_info):
    '''Read interface info from NetworkInterfaces.plist'''
    path = '/Library/Preferences/SystemConfiguration/NetworkInterfaces.plist'
    mac_info.ExportFile(path, __Plugin_Name, '', False)
    log.debug("Trying to read {}".format(path))
    success, plist, error = mac_info.ReadPlist(path)
    if success:
        try:
            log.info("Model = " + plist['Model'])
        except Exception: pass
        for category, cat_array in plist.items(): #value is another array in this dict
            if not category.startswith('Interface'): 
                if category != 'Model': log.debug('Skipping ' + category)
                continue
            for interface in cat_array:
                interface_info = {'Category':category, 'Source':path }
                for item, value in interface.items():
                    if item in ['Active','BSD Name','IOBuiltin','IOInterfaceNamePrefix','IOInterfaceType',
                                'IOInterfaceUnit','IOPathMatch','SCNetworkInterfaceType']:
                        interface_info[item] = value
                    elif item == 'IOMACAddress':  # convert binary blob to MAC address
                        data = ':'.join(value.hex()[i:i + 2] for i in range(0, len(value.hex()), 2))
                        interface_info[item] = data.upper()

                    elif item == 'SCNetworkInterfaceInfo':
                        try: interface_info['SCNetworkInterfaceInfo'] = value['UserDefinedName']
                        except Exception: pass
                    else:
                        log.info("Found unknown item in plist: ITEM=" + item + " VALUE=" + str(value))
                net_interfaces.append(interface_info)
    else:
        log.error("Could not open plist to get interface info for " + path + " Error was " + error)


def GetDhcpInfo(mac_info):
    '''Read dhcp leases & interface entries'''
    try:
        interfaces = mac_info.ListItemsInFolder('/private/var/db/dhcpclient/leases', EntryType.FILES)
        for interface in interfaces:
            name = interface['name']
            if name.find(",") > 0:
                #Process plist
                mac_info.ExportFile('/private/var/db/dhcpclient/leases/' + name, __Plugin_Name, '', False)
                name_no_ext = os.path.splitext(name)[0] # not needed as there is no .plist extension on these files
                if_name, mac_address = name_no_ext.split(",")
                log.info("Found mac address = " + mac_address + " on interface " + if_name)

                log.debug("Trying to read {}".format(name))
                path = '/private/var/db/dhcpclient/leases/' + name
                success, plist, error = mac_info.ReadPlist(path)
                if success:
                    interface_info = {  'Source':'/private/var/db/dhcpclient/leases/' + name,
                                        'Interface':if_name,
                                        'MAC_Address':mac_address }

                    for item, value in list(plist.items()):
                        if item in ['IPAddress','LeaseLength','LeaseStartDate','PacketData','RouterIPAddress','SSID']:
                            interface_info[item] = value
                        elif item == 'RouterHardwareAddress':  # convert binary blob to MAC address
                            data = ':'.join(value.hex()[i:i+2] for i in range(0,len(value.hex()),2))
                            interface_info[item] = data.upper()
                        else:
                            log.info("Found unknown item in plist: ITEM=" + item + " VALUE=" + str(value))
                    dhcp_interfaces.append(interface_info)
                else:
                    log.error("Could not open plist to get interface info for " + path + " Error was " + error)
            else:
                log.info("Found unexpected file, not processing /private/var/db/dhcpclient/leases/" + name + " size=" + str(interface['size']))
        # Done processing interfaces!
    except Exception as ex:
        log.error("Could not list files for folder /private/var/db/dhcpclient/leases")
        log.exception("Exception from GetDhcpInterfaces()")

def GetFileContents(mac_info, path):
    lines = []
    log.debug("Trying to read {}".format(path))
    f = mac_info.OpenSmallFile(path)
    if f != None:
        try:
            for line in f:
                if not line.startswith(b'#'):
                    line = line.rstrip(b' \t\n\r')
                    #log.debug("Content --> " + line)
                    lines.append(line.decode('utf-8'))
        except Exception as ex:
            log.error("Unknown error while reading file " + path + " : " + str(ex))
    else:
        log.error("Could not open file " + path)
    return lines

def GetResolvConf(mac_info):
    '''Reads last domain and nameserver data from resolv.conf'''
    resolv_conf_path = '/private/var/run/resolv.conf'
    if mac_info.IsValidFilePath(resolv_conf_path):
        resolv_conf = GetFileContents(mac_info, resolv_conf_path)
        mac_info.ExportFile(resolv_conf_path, __Plugin_Name, '', False)
        for line in resolv_conf:
            log.info("resolve.conf Content --> " + line)
    else:
        log.info("{} does not exist!".format(resolv_conf_path))

def GetEtcHosts(mac_info):
    '''Reads hosts file'''
    etc_hosts = GetFileContents(mac_info, '/private/etc/hosts')
    mac_info.ExportFile('/private/etc/hosts', __Plugin_Name, '', False)
    for line in etc_hosts:
        log.info("/etc/hosts Content --> " + line)

def Plugin_Start(mac_info):
    '''Main Entry point function for plugin'''  
    dchp_duid_plist = '/private/var/db/dhcpclient/DUID_IA.plist'
    # TODO: Read duid plist and display..
    #
    GetDhcpInfo(mac_info)
    GetResolvConf(mac_info) # Not writing to file yet!
    GetEtcHosts(mac_info) # Not writing to file yet!
    GetNetworkInterfaceInfo(mac_info)
    GetNetworkInterface2Info(mac_info)
    WriteList('dhcp data', 'Network_DHCP', dhcp_interfaces, dhcp_data_info, mac_info.output_params)
    WriteList('network interface data', 'Network_Interfaces', net_interfaces, net_interface_info, mac_info.output_params, '/Library/Preferences/SystemConfiguration/NetworkInterfaces.plist')
    WriteList('network interface details', 'Network_Details', net_interface_details, net_interface_detail_info, mac_info.output_params, '/Library/Preferences/SystemConfiguration/preferences.plist')

def Plugin_Start_Standalone(input_files_list, output_params):
    log.info("This plugin cannot be run as standalone")
    

if __name__ == '__main__':
    print ("This plugin is a part of a framework and does not run independently on its own!")