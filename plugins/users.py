'''
   Copyright (c) 2017 Yogesh Khatri 

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the 
   terms of the MIT License.
   
'''

import os
import logging
from plugins.helpers.macinfo import *
from plugins.helpers.writer import *

__Plugin_Name = "USERS"
__Plugin_Friendly_Name = "User Information"
__Plugin_Version = "1.0"
__Plugin_Description = "Gets local and domain user information like name, UID, UUID, GID, homedir & Darwin paths. Also extracts auto-login stored passwords and deleted user info"
__Plugin_Author = "Yogesh Khatri"
__Plugin_Author_Email = "yogesh@swiftforensics.com"

__Plugin_Modes = "MACOS"
__Plugin_ArtifactOnly_Usage = ""

log = logging.getLogger('MAIN.' + __Plugin_Name) # Do not rename or remove this ! This is the logger object


#---- Do not change the variable names in above section ----#

user_info = [ ('Username',DataType.TEXT),('Realname',DataType.TEXT),('Homedir',DataType.TEXT),
              ('UID',DataType.TEXT),('GID',DataType.TEXT),('UUID',DataType.TEXT),
              ('CreationDate',DataType.DATE),('DeletedDate',DataType.DATE),
              ('FailedLoginCount',DataType.INTEGER),('FailedLoginTime',DataType.DATE),('LastLoginTime',DataType.DATE),
              ('PasswordLastSetTime',DataType.DATE),('PasswordHint',DataType.TEXT),('Password',DataType.TEXT),
              ('DARWIN_USER_DIR',DataType.TEXT),('DARWIN_USER_TEMP_DIR',DataType.TEXT),('DARWIN_USER_CACHE_DIR',DataType.TEXT),
              ('Source',DataType.TEXT)
             ]

# Decryption XOR key from http://www.brock-family.org/gavin/perl/kcpassword.html
def decrypt_kcpassword(enc_bytes):
    '''Decrypt the password stored in /etc/kcpassword'''
    password = ''
    key_list = [0x7D, 0x89, 0x52, 0x23, 0xD2, 0xBC, 0xDD, 0xEA, 0xA3, 0xB9, 0x1F] # size = 11
    size = len(enc_bytes)
    counter = 0
    decrypted = b''
    for byte in enc_bytes:
        decoded_byte = byte ^ key_list[counter]
        if decoded_byte == 0: break
        decrypted += bytes([decoded_byte])
        counter += 1
        if counter == 11:
            counter = 0

    password = decrypted.decode('utf-8', 'backslashreplace')
    return password

def GetAutoLoginPass(mac_info):
    '''Retrieves the user and password for user that is set for auto-logon'''
    kc_path = '/private/etc/kcpassword'
    mac_info.ExportFile(kc_path, __Plugin_Name, '', False)
    dec_data = ''
    try:
        f = mac_info.Open(kc_path)
        if f:
            enc_data = f.read()            
            dec_data = decrypt_kcpassword(enc_data)
        else:
            log.error('Could not open file ' + kc_path)
    except (OSError):
        log.exception('Error while trying to open {}'.format(kc_path))
    return dec_data

def GetAutoLoginUser(mac_info):
    user = ''
    loginwindow_plist_path = '/Library/Preferences/com.apple.loginwindow.plist'
    if mac_info.IsValidFilePath(loginwindow_plist_path):
        mac_info.ExportFile(loginwindow_plist_path, __Plugin_Name, '', False)
        success, plist, error_message = mac_info.ReadPlist(loginwindow_plist_path)
        if success:
            user = plist.get('autoLoginUser', '')
        else:
            log.error('Failed to read plist ' + loginwindow_plist_path + " Error was : " + error_message)
    return user

#Not sure if this still exists post 10.9
def GetDeletedUsers(mac_info):
    deleted_users = []
    plist_path = '/Library/Preferences/com.apple.preferences.accounts.plist'
    if mac_info.IsValidFilePath(plist_path):
        mac_info.ExportFile(plist_path, __Plugin_Name, '', False)
        success, plist, error_message = mac_info.ReadPlist(plist_path)
        if success:
            users = plist.get('deletedUsers', None)
            if users:
                log.debug('Found {} deleted users'.format(len(users)))
                for user in users:
                    deleted_user = UserInfo()
                    deleted_users.append(deleted_user)
                    deleted_user.user_name = user.get('name','')
                    deleted_user.real_name = user.get('dsAttrTypeStandard:RealName','')
                    deleted_user.UID = str(user.get('dsAttrTypeStandard:UniqueID',''))
                    deleted_user.deletion_time = user.get('date', None)
                    deleted_user._source = plist_path
            else:
                log.debug('Could not find deletedUsers in com.apple.preferences.accounts.plist')
        else:
            log.error('Failed to read plist ' + plist_path + " Error was : " + error_message)    
    return deleted_users

def Plugin_Start(mac_info):

    auto_login = False
    auto_username = ''
    auto_password = ''

    if mac_info.IsValidFilePath('/private/etc/kcpassword'):
        auto_password = GetAutoLoginPass(mac_info)
        auto_username = GetAutoLoginUser(mac_info)
        auto_login = True

    users = []
    for user in mac_info.users:
        source = user._source
        if auto_login and (auto_username == user.user_name):
            user.password = auto_password
            source += ', /private/etc/kcpassword'

        users.append([user.user_name, user.real_name, user.home_dir, user.UID, user.GID, user.UUID,
                     user.creation_time, user.deletion_time,
                     user.failed_login_count, user.failed_login_timestamp, user.last_login_timestamp, 
                     user.password_last_set_time, user.pw_hint, user.password,
                     user.DARWIN_USER_DIR, user.DARWIN_USER_TEMP_DIR, user.DARWIN_USER_CACHE_DIR,
                     source])

    deleted_users = GetDeletedUsers(mac_info)
    log.info('Found {} users and {} deleted user(s)'.format(len(users), len(deleted_users)))

    if len(deleted_users) > 0:
        for user in deleted_users:
            users.append([user.user_name, user.real_name, user.home_dir, user.UID, user.GID, user.UUID,
                     user.creation_time, user.deletion_time,
                     user.failed_login_count, user.failed_login_timestamp, user.last_login_timestamp, 
                     user.password_last_set_time, user.pw_hint, user.password,
                     user.DARWIN_USER_DIR, user.DARWIN_USER_TEMP_DIR, user.DARWIN_USER_CACHE_DIR,
                     user._source])
    WriteList("user information", "Users", users, user_info, mac_info.output_params, '')

def Plugin_Start_Standalone(input_files_list, output_params):
    log.info("This cannot be used as a standalone plugin")

if __name__ == '__main__':
    print("This plugin is a part of a framework and does not run independently on its own!")
