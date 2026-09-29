'''
   Copyright (c) 2026 Yogesh Khatri

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the
   terms of the MIT License.

   akd.py
   ---------------
   Reads app, device info and private email replay information 
   from ~Library/Application Support/com.apple.akd/*.db files:
        authorization.db
        devicelist.db
        privateEmails.db
'''

import os

from plugins.helpers.common import CommonFunctions
from plugins.helpers.macinfo import *
from plugins.helpers.writer import *

import logging

__Plugin_Name = "AKD" # Cannot have spaces, and must be all caps!
__Plugin_Friendly_Name = "AuthKit daemon"
__Plugin_Version = "1.0"
__Plugin_Description = "Reads device and email alias info from Authkit daemon (com.apple.akd) databases"
__Plugin_Author = "Yogesh Khatri"
__Plugin_Author_Email = "yogesh@swiftforensics.com"

__Plugin_Modes = "MACOS,ARTIFACTONLY" # Valid values are 'MACOS', 'IOS, 'ARTIFACTONLY' 
__Plugin_ArtifactOnly_Usage = 'Provide path to ~Library/Application Support/com.apple.akd/ folder'

log = logging.getLogger('MAIN.' + __Plugin_Name) # Do not rename or remove this ! This is the logger object

#---- Do not change the variable names in above section ----#

def OpenDb(inputPath):
    log.info ("Processing file " + inputPath)
    try:
        conn = CommonFunctions.open_sqlite_db_readonly(inputPath)
        log.debug ("Opened database successfully")
        return conn
    except sqlite3.Error:
        log.exception ("Failed to open database, is it a valid DB?")
    return None

def OpenDbFromImage(mac_info, inputPath):
    '''Returns tuple of (connection, wrapper_obj)'''
    try:
        sqlite = SqliteWrapper(mac_info)
        conn = sqlite.connect(inputPath)
        if conn:
            log.debug ("Opened database successfully")
        return conn, sqlite
    except sqlite3.Error as ex:
        log.exception ("Failed to open database, is it a valid DB?")
    return None, None

def ExtractAndReadDb(mac_info, artifacts, user, file_path, parser_function):
    if mac_info.IsValidFilePath(file_path):
        mac_info.ExportFile(file_path, __Plugin_Name, user + '_')
        db, wrapper = OpenDbFromImage(mac_info, file_path)
        if db:
            parser_function(artifacts, db, user, file_path)
            db.close()

def OpenLocalDbAndRead(artifacts, user, file_path, parser_function):
    conn = OpenDb(file_path)
    if conn:
        parser_function(artifacts, conn, '', file_path)
        conn.close()

def process_auth(artifacts, db, user, file_path):
    '''Process the authorization.db database'''
    try:
        db.row_factory = sqlite3.Row
        cursor = db.cursor()
        cursor.execute('SELECT version.db_version, version.authorizedAppListVersion FROM version')
        for row in cursor.fetchall():
            log.debug(f"authorization.db -> DB Version: {row['db_version']}, Authorized App List Version: {row['authorizedAppListVersion']}")
    except sqlite3.Error:
        log.exception("Failed to read version info for authorization.db")

    query = '''
        SELECT authorized_teams.team_id, private_email, 
            authorized_primary_applications.app_name, authorized_primary_applications.app_developer_name,
            authorized_applications.creation_date
        FROM authorized_teams LEFT JOIN authorized_applications ON authorized_applications.team_id=authorized_teams.team_id
            LEFT JOIN authorized_primary_applications ON authorized_primary_applications.client_id=authorized_applications.client_id
        WHERE --(NOT (authorized_teams.private_email is NULL)) AND 
            (NOT (authorized_primary_applications.client_id is NULL))
        ORDER BY app_name
    '''
    try:
        db.row_factory = sqlite3.Row
        cursor = db.cursor()
        cursor.execute(query)
        for row in cursor.fetchall():
            artifacts.append({
                'Private Email': row['private_email'],
                'App Name': row['app_name'],
                'App Developer Name': row['app_developer_name'],
                'Creation Date': CommonFunctions.ReadUnixTime(row['creation_date']),
                'User': user,
                'Source': file_path
            })
    except sqlite3.Error:
        log.exception("Failed to process authorization.db")

def PrintAllAuths(auths_dict, output_params):

    auth_info = [ ('Private Email',DataType.TEXT),('App Name',DataType.TEXT),
                 ('App Developer Name',DataType.TEXT),('Creation Date',DataType.DATE),
                 ('User', DataType.TEXT),('Source',DataType.TEXT) ]

    log.info (f"{len(auths_dict)} authorization artifact(s) found")
    WriteList("AKD_Auths", "AKD_Auths", auths_dict, auth_info, output_params, '')

def process_private_emails(artifacts, db, user, file_path):
    '''Process the privateEmails.db database'''
    try:
        db.row_factory = sqlite3.Row
        cursor = db.cursor()
        cursor.execute('SELECT privateEmailListVersion, db_version, protocol_version FROM version')
        for row in cursor.fetchall():
            log.debug(f"privateEmails.db -> DB Version: {row['db_version']}, Private Email List Version: {CommonFunctions.ReadUnixMillisecondsTime(row['privateEmailListVersion'])}, Protocol Version: {row['protocol_version']}")
    except sqlite3.Error:
        log.exception("Failed to read version info for privateEmails.db")
    try:
        db.row_factory = sqlite3.Row
        cursor = db.cursor()
        cursor.execute('SELECT email FROM emails')
        for row in cursor.fetchall():
            artifacts.append({
                'Email': row['email'],
                'User': user,
                'Source': file_path
            })
    except sqlite3.Error:
        log.exception("Failed to process privateEmails.db")

def PrintAllEmails(emails_dict, output_params):

    email_info = [ ('Email',DataType.TEXT),('User', DataType.TEXT),('Source',DataType.TEXT) ]
    log.info (f"{len(emails_dict)} email artifact(s) found")
    WriteList("AKD_Emails", "AKD_Emails", emails_dict, email_info, output_params, '')

def process_devices(artifacts, db, user, file_path):
    '''Process the devicelist.db database'''
    try:
        db.row_factory = sqlite3.Row
        cursor = db.cursor()
        cursor.execute('SELECT db_version FROM version')
        for row in cursor.fetchall():
            log.debug(f"devicelist.db -> DB Version: {row['db_version']}")
    except sqlite3.Error:
        log.exception("Failed to read version info for devicelist.db")

    try:
        db.row_factory = sqlite3.Row
        cursor = db.cursor()
        query = '''
            SELECT name, serial_number, model, os, os_version, build_number, 
                trusted, last_updated_date, additional_info, services
            FROM device_list
        '''
        cursor.execute(query)
        for row in cursor.fetchall():
            artifacts.append({
                'Name': row['name'],
                'Serial Number': row['serial_number'],
                'Model': row['model'],
                'OS': row['os'],
                'OS Version': row['os_version'],
                'Build Number': row['build_number'],
                'Trusted': row['trusted'],
                'Last Updated Date': CommonFunctions.ReadUnixTime(row['last_updated_date']),
                'Additional Info': row['additional_info'],
                'Services': row['services'],
                'User': user,
                'Source': file_path
            })
    except sqlite3.Error:
        log.exception("Failed to process devicelist.db")

def PrintAllDevices(devices_dict, output_params):

    device_info = [ ('Name',DataType.TEXT),('Serial Number', DataType.TEXT),('Model',DataType.TEXT),
                    ('OS',DataType.TEXT),('OS Version',DataType.TEXT),('Build Number',DataType.TEXT),
                    ('Trusted',DataType.TEXT),('Last Updated Date',DataType.DATE),('Additional Info',DataType.TEXT),
                    ('Services',DataType.TEXT),('User', DataType.TEXT),('Source',DataType.TEXT) ]
    data_list = []
    log.info (f"{len(devices_dict)} device artifact(s) found")
    #for item in devices_dict.values():
    #    data_list.append( [ item['name'], item['serial_number'], item['model'], item['os'], item['os_version'],
    #                       item['build_number'], item['trusted'], item['last_updated_date'], item['additional_info'],
    #                       item['services'], item['user'], item['source'] ] )
    WriteList("AKD_Devices", "AKD_Devices", devices_dict, device_info, output_params, '')

def Plugin_Start(mac_info):
    '''Main Entry point function for plugin'''

    emails = []
    devices = []
    auths = []
    auth_db_path = '{}/Library/Application Support/com.apple.akd/authorization.db'
    email_db_path = '{}/Library/Application Support/com.apple.akd/privateEmails.db'
    device_db_path = '{}/Library/Application Support/com.apple.akd/devicelist.db'
    processed_paths = []
    for user in mac_info.users:
        user_name = user.user_name
        if user.home_dir == '/private/var/empty': continue # Optimization, nothing should be here!
        elif user.home_dir == '/private/var/root': user_name = 'root' # Some other users use the same root folder, we will list such all users as 'root', as there is no way to tell
        if user.home_dir in processed_paths: continue # Avoid processing same folder twice (some users have same folder! (Eg: root & daemon))
        processed_paths.append(user.home_dir)
        akd_path = os.path.join(user.home_dir, 'Library', 'Application Support', 'com.apple.akd')
        if mac_info.IsValidFilePath(email_db_path.format(user.home_dir)):
            ExtractAndReadDb(mac_info, emails, user_name, email_db_path.format(user.home_dir), process_private_emails)
        if mac_info.IsValidFilePath(device_db_path.format(user.home_dir)):
            ExtractAndReadDb(mac_info, devices, user_name, device_db_path.format(user.home_dir), process_devices)
        if mac_info.IsValidFilePath(auth_db_path.format(user.home_dir)):
            ExtractAndReadDb(mac_info, auths, user_name, auth_db_path.format(user.home_dir), process_auth)

    if len(emails) > 0:
        PrintAllEmails(emails, mac_info.output_params)
    else:
        log.info(f'No email aliases found in AKD!')

    if len(devices) > 0:
        PrintAllDevices(devices, mac_info.output_params)
    else:
        log.info(f'No devices found in AKD!')

    if len(auths) > 0:
        PrintAllAuths(auths, mac_info.output_params)
    else:
        log.info(f'No authorization entries found in AKD!')

def Plugin_Start_Standalone(input_files_list, output_params):
    '''Main entry point function when used on single artifacts (mac_apt_singleplugin), not on a full disk image'''
    log.info("Module Started as standalone")
    for input_path in input_files_list:
        log.debug("Input path passed was: " + input_path)
        if not os.path.isdir(input_path):
            log.error(f'Input path "{input_path}" is not a valid directory!')
            return
        emails = []
        devices = []
        auths = []
        for file_name in os.listdir(input_path):
            full_path = os.path.join(input_path, file_name)
            if file_name.lower() == 'authorization.db':
                OpenLocalDbAndRead(auths, '', full_path, process_auth)
                if len(auths) > 0:
                    PrintAllAuths(auths, output_params)
                else:
                    log.info('No authorization entries found in {}'.format(input_path))
            elif file_name.lower() == 'device.db':
                OpenLocalDbAndRead(devices, '', full_path, process_devices)
                if len(devices) > 0:
                    PrintAllDevices(devices, output_params)
                else:
                    log.info('No devices found in {}'.format(input_path))
            elif file_name.lower() == 'email.db':
                OpenLocalDbAndRead(emails, '', full_path, process_private_emails)
                if len(emails) > 0:
                    PrintAllEmails(emails, output_params)
                else:
                    log.info('No email aliases found in {}'.format(input_path))

def Plugin_Start_Ios(ios_info):
    '''Entry point for ios_apt plugin'''
    pass

if __name__ == '__main__':
    print ("This plugin is a part of a framework and does not run independently on its own!")