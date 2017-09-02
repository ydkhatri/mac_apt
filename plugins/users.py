'''
   Copyright (c) 2017 Yogesh Khatri 

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the 
   terms of the MIT License.
   
'''
from __future__ import print_function
from __future__ import unicode_literals
import os
import logging
from helpers.macinfo import *
from helpers.writer import *

__Plugin_Name = "USERS" # Cannot have spaces, and must be all caps!
__Plugin_Friendly_Name = "User Information"
__Plugin_Version = "1.0"
__Plugin_Description = "Gets local and domain user information like name, UID, UUID, GID, homedir & Darwin paths"
__Plugin_Author = "Yogesh Khatri"
__Plugin_Author_Email = "yogesh@swiftforensics.com"

__Plugin_Standalone = False
__Plugin_Standalone_Usage = ""

log = logging.getLogger('MAIN.' + __Plugin_Name) # Do not rename or remove this ! This is the logger object


#---- Do not change the variable names in above section ----#

user_info = [ ('Username',DataType.TEXT),('Realname',DataType.TEXT),('Homedir',DataType.TEXT),
              ('UID',DataType.TEXT),('GID',DataType.TEXT),('UUID',DataType.TEXT),('CreationDate',DataType.DATE),
              ('FailedLoginCount',DataType.INTEGER),('FailedLoginTime',DataType.DATE),('LastLoginTime',DataType.DATE),
              ('PasswordLastSetTime',DataType.DATE),('PasswordHint',DataType.TEXT),
              ('DARWIN_USER_DIR',DataType.TEXT),('DARWIN_USER_TEMP_DIR',DataType.TEXT),('DARWIN_USER_CACHE_DIR',DataType.TEXT)
             ]

def Plugin_Start(mac_info):
    users = []
    for user in mac_info.users:
        users.append([user.user_name, user.real_name, user.home_dir, user.UID, user.GID, user.UUID,user.creation_time,
                     user.failed_login_count, user.failed_login_timestamp, user.last_login_timestamp, 
                     user.password_last_set_time, user.pw_hint,
                     user.DARWIN_USER_DIR, user.DARWIN_USER_TEMP_DIR, user.DARWIN_USER_CACHE_DIR])
    WriteList("user information", "Users", users, user_info, mac_info.output_params, '')

def Plugin_Start_Standalone(input_files_list, output_params):
    log.info("This cannot be used as a standalone plugin")

if __name__ == '__main__':
    print("This plugin is a part of a framework and does not run independently on its own!")
