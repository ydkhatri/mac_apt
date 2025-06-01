'''
   Copyright (c) 2025 Yogesh Khatri

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the 
   terms of the MIT License.
   
   version_info_builder.py
   ------------------
   This script generates the version info files for Pyinstaller needed
   when compiling mac_apt, mac_apt_artifact_only and ios_apt.
   
'''
import importlib.util
import os
from datetime import datetime

def get_version_dict(v_str):
    """
        v_str will always be of form "1.55.4 (20250903)"
        Returns dict of form { 'major'='1', 'minor'='55', 'micro'='4', 'builddate'='(20250903)' }
    """
    ret = {}
    parts = v_str.split('.')
    ret['major'] = parts[0]
    ret['minor'] = parts[1]
    ret['micro'] = parts[2].split(" ")[0]
    ret['builddate'] = parts[2].split(" ")[1]
    return ret

def create_version_file(output_filename, companyname, productname, internalname, 
                        origfilename, filedescription):
    version_info = ""
    base_path = os.path.dirname(os.path.abspath(__file__))
    mod_path = os.path.join(base_path, "..", "version.py")

    spec = importlib.util.spec_from_file_location("version", mod_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    version_info = module.__VERSION
    version_info = get_version_dict(version_info)

    year = datetime.now().strftime("%Y")

    with open(os.path.join(base_path, 'version_info_template.txt'), 'rb') as f:
        content = f.read().decode()
        content = content.replace('_major_', version_info['major'])
        content = content.replace('_minor_', version_info['minor'])
        content = content.replace('_micro_', version_info['micro'])
        content = content.replace('_builddate_', version_info['builddate'])
        content = content.replace('_companyname_', companyname)
        content = content.replace('_productname_', productname)
        content = content.replace('_internalname_', internalname)
        content = content.replace('_origfilename_', origfilename)
        content = content.replace('_filedescription_', filedescription)
        content = content.replace('_year_', year)
        with open(os.path.join(base_path, output_filename), 'w', newline='') as out:
            out.write(content)

create_version_file('mac_apt_version_info.txt', 
    "", 
    "mac_apt - macOS Artifact Parsing Tool", 
    "mac_apt", 
    "mac_apt.exe", 
    "mac_apt standalone executable")

create_version_file('ios_apt_version_info.txt', 
    "", 
    "ios_apt - iOS Artifact Parsing Tool", 
    "ios_apt", 
    "ios_apt.exe", 
    "ios_apt standalone executable")

create_version_file('mac_apt_artifact_only_version_info.txt', 
    "", 
    "mac_apt_artifact_only - macOS Artifact Parsing Tool", 
    "mac_apt_artifact_only", 
    "mac_apt_artifact_only.exe", 
    "mac_apt_artifact_only standalone executable")