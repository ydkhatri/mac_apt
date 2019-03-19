'''
   Copyright (c) 2017 Yogesh Khatri 

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the 
   terms of the MIT License.
   
'''
from __future__ import print_function
#from __future__ import unicode_literals
import os
import logging
import struct

from biplist import *
from helpers.macinfo import *
from helpers.writer import *

__Plugin_Name = "INETACCOUNTS"
__Plugin_Friendly_Name = "Internet Accounts"
__Plugin_Version = "1.0"
__Plugin_Description = "Reads configured internet account (iCloud, Google, Linkedin, facebook..) settings used by Mail, Contacts, Calendar and other apps"
__Plugin_Author = "Yogesh Khatri"
__Plugin_Author_Email = "yogesh@swiftforensics.com"

__Plugin_Standalone = True
__Plugin_Standalone_Usage = 'This module parses configured internet accounts such as iCloud, Google, Linkedin, facebook, Twitter used by Mail, Contacts, Calendar and other apps. Data is retreived from the database file found at: /Users/$USER/Library/Preferences/MobileMeAccounts.plist or since Mavericks: /Users/$USER/Library/Accounts/AccountsX.sqlite where X = 3 or 4\r\nPlease provide the plist file(s) or the sqlite database(s) to process'

log = logging.getLogger('MAIN.' + __Plugin_Name) # Do not rename or remove this ! This is the logger object

#---- Do not change the variable names in above section ----#

class Account:
    def __init__(self, id, type, name, username, display_name, date, parent_id, uuid, bundle, user, source):
        self.id = id
        self.type = type
        self.username = username
        self.display_name = display_name
        self.name = name
        self.date = date
        self.parent_id = parent_id
        self.uuid = uuid
        self.bundle = bundle
        self.user = user
        self.source = source

def PrintAll(accounts, output_params, source_path):
    account_info = [ ('ID',DataType.INTEGER),('Type',DataType.TEXT),('Name',DataType.TEXT),
                      ('Date',DataType.DATE),('UserDisplayName',DataType.TEXT),('Username',DataType.TEXT),
                      ('Parent_ID',DataType.INTEGER),('Bundle',DataType.TEXT),
                      ('UUID_or_AccountDSID',DataType.TEXT),
                      ('User',DataType.TEXT),('Source',DataType.TEXT)
                   ]
    log.info (str(len(accounts)) + " account(s) found")
    account_items = []
    for account in accounts:
        account_item = [ account.id, account.type, account.name, account.date, account.display_name,
                         account.username, account.parent_id,
                         account.bundle, account.uuid, account.user, account.source ]
        account_items.append(account_item)
    WriteList("internet account information", "InternetAccounts", account_items, account_info, output_params, source_path)
    
def ParseAccountFile(input_file, accounts):
    try:
        plist = readPlist(input_file)
        ReadMobileMeAccountPlist(plist, accounts, input_file)
    except (InvalidPlistException, NotBinaryPlistException) as e:
        log.error ("Could not open plist, error was : " + str(e) )

def ReadMobileMeAccountPlist(plist, accounts, source='', user=''):
    try:
        user_accounts = plist.get('Accounts', None)
        for item in user_accounts:
            display_name = item.get('DisplayName','') # John Doe
            user_name = item.get('AccountID','') # usually email
            description = item.get('AccountDescription','') # iCloud
            dsid = item.get('AccountDSID','')
            services = item.get('Services', None)
            if services:
                for service in services:
                    if service.get('Enabled', None) == True: # Only getting enabled ones
                        account = Account(None, service.get('Name',''), description, user_name, display_name,
                                          None, None, dsid, service.get('ServiceID', ''), user, source)
                        accounts.append(account)
            else:
                account = Account(None, '', description, user_name, display_name,
                                  None, None, dsid, '', user, source)
                accounts.append(account) 

    except Exception as ex:
        log.exception('Error reading MobileMeAccounts plist')   

def OpenDb(inputPath):
    log.info ("Processing file " + inputPath)
    try:
        conn = sqlite3.connect(inputPath)
        log.debug ("Opened database successfully")
        return conn
    except Exception as ex:
        log.exeption ("Failed to open database, is it a valid Accounts DB?")
    return None

def OpenDbFromImage(mac_info, inputPath, user):
    '''Returns tuple of (connection, wrapper_obj)'''
    log.info ("Processing internet accounts for user '{}' from file {}".format(user, inputPath))
    try:
        sqlite = SqliteWrapper(mac_info)
        conn = sqlite.connect(inputPath)
        log.debug ("Opened database successfully")
        return conn, sqlite
    except Exception as ex:
        log.exception ("Failed to open database, is it a valid Accounts DB?")
    return None

def ProcessDbFromPath(mac_info, accounts, source_path, user):
    db, wrapper = OpenDbFromImage(mac_info, source_path, user)
    if db != None:
        ReadAccountsDb(db, accounts, source_path, user)
        db.close()

def ReadAccountsDb(db, accounts, source_path, user):
    '''Parses Accounts3.sqlite & Accounts4.sqlite files'''
    try:
        query = " SELECT Z_PK as acc_id, "\
                " (SELECT ZACCOUNTTYPEDESCRIPTION from ZACCOUNTTYPE where ZACCOUNTTYPE.Z_PK=a.ZACCOUNTTYPE) as acc_type, "\
                " a.ZACCOUNTDESCRIPTION as acc_name, a.ZUSERNAME as acc_user, a.ZDATE as acc_date, "\
                " a.ZPARENTACCOUNT as acc_parent_id, a.ZIDENTIFIER as acc_uuid, a.ZOWNINGBUNDLEID as acc_bundle "\
                " FROM ZACCOUNT as a "\
                " WHERE a.Z_ENT = (SELECT Z_ENT FROM Z_PRIMARYKEY WHERE Z_NAME LIKE 'Account')"
        db.row_factory = sqlite3.Row
        cursor = db.execute(query)
        for row in cursor:
            try: # id, type, name, username, date, parent_id, uuid, bundle, user, source)
                account = Account(row['acc_id'], row['acc_type'], row['acc_name'], row['acc_user'], '',
                            CommonFunctions.ReadMacAbsoluteTime(row['acc_date']), 
                            row['acc_parent_id'], row['acc_uuid'], row['acc_bundle'], user, source_path)
                accounts.append(account)
            except:
                log.exception('Error fetching row data')
    except:
        log.exception('Query  execution failed. Query was: ' + query)


def Plugin_Start(mac_info):
    '''Main Entry point function for plugin'''
    accounts = []
    account_plist_rel_path = '{}/Library/Preferences/MobileMeAccounts.plist' # older
    account_sqlite_rel_path = '{0}/Library/Accounts/Accounts{1}.sqlite' # Accounts3 Seen in Mavericks and above, Accounts4 in High Sierra
    version = mac_info.GetVersionDictionary()
    for user in mac_info.users:
        if user.home_dir == '/private/var/empty': continue # Optimization, nothing should be here!
        plist_path = account_plist_rel_path.format(user.home_dir)
        if mac_info.IsValidFilePath(plist_path):
            mac_info.ExportFile(plist_path, __Plugin_Name, user.user_name + "_", False)
            success, plist, error = mac_info.ReadPlist(plist_path)
            if success:
                ReadMobileMeAccountPlist(plist, accounts, plist_path, user.user_name)
        
        # Process Sqlite db
        for version in xrange(1, 5):
            sqlite_path = account_sqlite_rel_path.format(user.home_dir, version)
            if mac_info.IsValidFilePath(sqlite_path):
                mac_info.ExportFile(sqlite_path, __Plugin_Name, user.user_name + "_")
                ProcessDbFromPath(mac_info, accounts, sqlite_path, user.user_name)

    if len(accounts) > 0:
        PrintAll(accounts, mac_info.output_params, '')
    else:
        log.info('No accounts found')

def Plugin_Start_Standalone(input_files_list, output_params):
    log.info("Module Started as standalone")
    for input_path in input_files_list:
        log.debug("Input file passed was: " + input_path)
        accounts = []
        if os.path.basename(input_path).upper() == 'MOBILEMEACCOUNTS.PLIST':
            success, plist, error = CommonFunctions.ReadPlist(input_path)
            if success:
                ReadMobileMeAccountPlist(plist, accounts, input_path, '')
            else:
                log.error('Failed to read plist - {}  Error was {}'.format(input_path, error))
        elif os.path.basename(input_path).upper() in ('ACCOUNTS1.SQLITE','ACCOUNTS2.SQLITE','ACCOUNTS3.SQLITE','ACCOUNTS4.SQLITE'):
            db = OpenDb(input_path)
            if db != None:
                ReadAccountsDb(db, accounts, input_path, '')
                db.close()
        else:
            log.info("Unknown file type: {}".format(os.path.basename(input_path)))

        if len(accounts) > 0:
            PrintAll(accounts, output_params, input_path)
        else:
            log.info('No accounts found in {}'.format(input_path))

if __name__ == '__main__':
    print ("This plugin is a part of a framework and does not run independently on its own!")