'''
   Copyright (c) 2018 Yogesh Khatri

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the
   terms of the MIT License.

   keychains.py
   ---------------
   Reads the Encrypted Keychain files for System.

'''

import logging
import os
import plugins.helpers.chainbreaker as chainbreaker
import sys

from collections import namedtuple
from plugins.helpers.macinfo import *
from plugins.helpers.writer import *

__Plugin_Name = "KEYCHAINS"
__Plugin_Friendly_Name = "Keychains"
__Plugin_Version = "1.0"
__Plugin_Description = "Reads the System keychain"
__Plugin_Author = "Yogesh Khatri"
__Plugin_Author_Email = "yogesh@swiftforensics.com"

__Plugin_Modes = "MACOS"
__Plugin_ArtifactOnly_Usage = ''

log = logging.getLogger('MAIN.' + __Plugin_Name) # Do not rename or remove this ! This is the logger object

#---- Do not change the variable names in above section ----#

class ChainbreakerArgs:
    def __init__(self, output_dir):
        self.dump_keychain_password_hash = False
        self.export_keychain_password_hash = False
        self.dump_generic_passwords = True
        self.export_generic_passwords = True
        self.dump_internet_passwords = True
        self.export_internet_passwords = True
        self.dump_appleshare_passwords = True
        self.export_appleshare_passwords = False
        self.dump_private_keys = True
        self.export_private_keys = False
        self.dump_public_keys = True
        self.export_public_keys = False
        self.dump_x509_certificates = True
        self.export_x509_certificates = False
        # output dir
        self.output = output_dir

class PasswordRecord:
    def __init__(self, record_type, created, modified, desc, creator, type, print_name, alias,
                 account, service, password, user, source_path):
        
        self.record_type = PasswordRecord.to_str(record_type)
        self.created = created
        self.modified = modified
        self.desc = PasswordRecord.to_str(desc)
        self.type = PasswordRecord.to_str(type)
        self.creator = PasswordRecord.to_str(creator)
        self.print_name = PasswordRecord.to_str(print_name)
        self.alias = PasswordRecord.to_str(alias)
        self.account = PasswordRecord.to_str(account)
        self.service = PasswordRecord.to_str(service)
        self.password = PasswordRecord.to_str(password)
        self.user = user
        self.source_path = source_path
    
    @staticmethod
    def to_str(record):
        if isinstance(record, bytes):
            return record.decode('utf8', 'ignore')
        elif record in ('', None):
            return ''
        return str(record)

def PrintAll(passwords:list, output_params, input_path=''):
    password_info = [   ('Record Type',DataType.TEXT),
                    ('Created',DataType.DATE),
                    ('Last Modified',DataType.DATE),
                    ('Description',DataType.TEXT),
                    ('Creator',DataType.TEXT),
                    ('Type',DataType.TEXT),
                    ('Print Name',DataType.TEXT),
                    ('Alias',DataType.TEXT),
                    ('Account',DataType.TEXT),
                    ('Service',DataType.TEXT),
                    ('Password',DataType.TEXT),
                    ('User',DataType.TEXT),
                    ('Source',DataType.TEXT)
                ]

    log.info (str(len(passwords)) + " password records(s) found")

    password_list = []
    for p in passwords:
        password_list.append([p.record_type, p.created, p.modified, p.desc, 
                              p.creator, p.type, 
                              p.print_name, p.alias, p.account, p.service, 
                              p.password, p.user, p.source_path])

    WriteList("Keychain Passwords", "KeychainPasswords", password_list, password_info, output_params, input_path)

def Plugin_Start(mac_info):
    '''Main Entry point function for plugin'''
    sys_keychain_path = '/Library/Keychains/System.keychain'
    systemkey_path = '/private/var/db/SystemKey'
    user_keychain_path = '{}/Library/Keychains/'

    passwords = []

    if mac_info.IsValidFilePath(systemkey_path):
        mac_info.ExportFile(systemkey_path, __Plugin_Name, '', False)
        f = mac_info.Open(systemkey_path)
        if f != None:
            unlock_contents = f.read()
            if mac_info.IsValidFilePath(sys_keychain_path):
                mac_info.ExportFile(sys_keychain_path, __Plugin_Name, '', False)
                s = mac_info.Open(sys_keychain_path)
                if s != None:
                    keychain_contents = s.read()
                    keychain = chainbreaker.Chainbreaker(sys_keychain_path, keychain_file_contents=keychain_contents, unlock_file_contents=unlock_contents)
                    output_folder = os.path.join(mac_info.output_params.output_path, 'Chainbreaker_output', 'System')
                    args = ChainbreakerArgs(output_folder)
                    output = chainbreaker.results.resolve(args, keychain)

                    log.info(f'Running Chainbreaker {chainbreaker.__version__}, https://github.com/n0fate/chainbreaker')
                    for record_collection in output:
                        if 'records' in record_collection:
                            collection_summary = "Found %s %s" % (len(record_collection['records']), record_collection['header'])
                            log.info(collection_summary)

                            for record in record_collection['records']:
                                if record_collection.get('write_to_console', False):
                                    if isinstance(record, chainbreaker.Chainbreaker.GenericPasswordRecord):
                                        p = PasswordRecord("Generic Password", record.Created, record.LastModified, 
                                                           record.Description, record.Creator, record.Type, record.PrintName, 
                                                           record.Alias, record.Account, record.Service, record.password, '', sys_keychain_path)
                                        passwords.append(p)
                                    #TODO other types
                                if record_collection.get('write_to_disk', False):
                                    record.write_to_disk(record_collection.get('write_directory', args.output))
                                #log.info("")

                    #summary_output.append("Dump End: %s" % datetime.datetime.now())

                    # if any(x.get('write_to_disk', False) for x in output):
                    #     with open(os.path.join(args.output, "summary.txt"), 'w') as summary_fp:
                    #         for line in summary_output:
                    #             summary_fp.write("%s\n" % line)
                    #             log.info(line)
                    # else:
                    #     for line in summary_output:
                    #         log.info(line)
                    s.close()
                else:
                    log.error('Could not open file {}'.format(sys_keychain_path))
            f.close()
        else:
            log.error('Could not open file {}'.format(systemkey_path))
    else:
        log.error(f'Could not find {systemkey_path}')

    if len(passwords) > 0:
        PrintAll(passwords, mac_info.output_params, '')
    else:
        log.info('No passwords found in keychains.')

if __name__ == '__main__':
    print ("This plugin is a part of a framework and does not run independently on its own!")