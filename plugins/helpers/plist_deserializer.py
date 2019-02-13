'''
   Copyright (c) 2018 Yogesh Khatri 

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the 
   terms of the MIT License.
   
'''

#
#  This module deserializes an NSKeyedArchive plist 
#

import ccl_bplist

def recurseCreatePlist(plist, root):
    if isinstance(root, dict):
        for key, value in root.items():
            if key == '$class': 
                continue
            v = None
            if isinstance(value, list):
                v = []
                recurseCreatePlist(v, value)
            elif isinstance(value, dict):
                v = {}
                recurseCreatePlist(v, value)
            else:
                v = value
            plist[key] = v
    else: # must be list
        for value in root:
            v = None
            if isinstance(value, list):
                v = []
                recurseCreatePlist(v, value)
            elif isinstance(value, dict):
                v = {}
                recurseCreatePlist(v, value)
            else:
                v = value
            plist.append(v)

def DeserializeNSKeyedArchive(file_pointer):
    '''Pass an open file pointer (file must be opened as rb) and get a dict or list representation
       of the plist returned back
    '''
    ccl_bplist.set_object_converter(ccl_bplist.NSKeyedArchiver_common_objects_convertor)
    plist = ccl_bplist.load(file_pointer)
    ns_keyed_archiver_obj = ccl_bplist.deserialise_NsKeyedArchiver(plist, parse_whole_structure=True)
    root = ns_keyed_archiver_obj['root']

    if isinstance(root, dict):
        plist = {}
    else:
        plist = []

    recurseCreatePlist(plist, root)
    return plist