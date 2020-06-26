# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # 
# Sample implementation of Darwin_USER_ folders path generation
# Copyright (c) 2017  Yogesh Khatri <yogesh@swiftforensics.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You can get a copy of the complete license here:
#  <http://www.gnu.org/licenses/>.
#
# Script Name  : darwin_path_generator.py
# Author       : Yogesh Khatri
# Last Updated : 4/25/2017
# Purpose/Usage: This script will generate the DARWIN_USER_ folder path
#                given a user's UUID and UID. These are the folders found
#                under /var/folders/
#


def GetDarwinPath(uuid, uid):
    '''Returns DARWIN_USER_FOLDER path constructed from UUID and UID for 
       osx older than Mavericks(10.9)'''
    charset ='+-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
    uuid = uuid.replace('-', '') # strip '-' if present
    uid = int(uid)
    if uid < 0:
        # convert to unsigned num
        uid = struct.unpack('<I', struct.pack('<i', uid))[0]
    #Convert uid to hex 8 byte string
    uid = '{:08x}'.format(uid) # input uid may be int or string (decimal)
    hex_string = uuid + uid
    binary_string = ''.join('{0:04b}'.format(int(c, 16)) for c in hex_string) # get binary string
    
    size = len(binary_string)
    darwin_path = ''
    for x in range(0, size, 6):
        index = binary_string[x:x+6]
        darwin_path += charset[int(index, 2)]
        if x == 6:
            darwin_path += '/' + darwin_path
    return darwin_path

def GetDarwinPath2(uuid, uid):
    '''Returns DARWIN_USER_FOLDER path constructed from UUID and UID.
       This is the algorithm for newer osx - Mavericks(10.9) thru Sierra(10.12)'''
    charset ='0123456789_bcdfghjklmnpqrstvwxyz'
    uuid = uuid.replace('-', '') # strip '-' if present
    uid = int(uid)
    if uid < 0:
        # convert to unsigned num
        uid = struct.unpack('<I', struct.pack('<i', uid))[0]
    #Convert uid to hex 8 byte string
    uid = '{:08x}'.format(uid) # input uid may be int or string (decimal)
    hex_string = uuid + uid
    binary_string = ''.join('{0:04b}'.format(int(c, 16)) for c in hex_string) # get binary string
    
    size = len(binary_string)
    darwin_path = ''
    for x in range(0, size, 5):
        index = binary_string[x:x+5]
        darwin_path += charset[int(index, 2)]
        if x == 5:
            darwin_path += '/'
    return darwin_path

#print(GetDarwinPath2('3CEEF7A5-A3D9-47DC-82C1-8E386A1EA83B', 502))

# Computing path for root user
# root_uuid='FFFFEEEEDDDDCCCCBBBBAAAA00000000'
# root_uid = 0

# path_on_older_mac = GetDarwinPath(root_uuid, root_uid)
# path_on_newer_mac = GetDarwinPath2(root_uuid, root_uid)

# print('Darwin folder path for root on older macs is /var/folders/' + path_on_older_mac)
# print('Darwin folder path for root on newer macs is /var/folders/' + path_on_newer_mac)