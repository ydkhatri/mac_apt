'''
   Copyright (c) 2017 Yogesh Khatri 

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the 
   terms of the MIT License.
   
'''

import logging
import os
import plistlib
import posixpath
import re

from plistutils.alias import AliasParser

from plugins.helpers.bookmark import *
from plugins.helpers.codesign_offline import get_bundle_info
from plugins.helpers.macinfo import *
from plugins.helpers.shared_file_list import parse_shared_file_list, parse_shared_file_list_path
from plugins.helpers.writer import *

__Plugin_Name = "AUTOSTART" # Cannot have spaces, and must be all caps!
__Plugin_Friendly_Name = "Auto start"
__Plugin_Version = "2.0"
__Plugin_Description = "Retrieves persistent and auto-start programs, daemons, services"
__Plugin_Author = "Brandon Mignini, Yogesh Khatri, Minoru Kobayashi"
__Plugin_Author_Email = "brandon.mignini@mymail.champlain.edu, khatri@champlain.edu, unknownbit@gmail.com"
__Plugin_Modes = "MACOS,ARTIFACTONLY"
__Plugin_Standalone = False
__Plugin_ArtifactOnly_Usage = "Provide a .btm file, launchd plist, StartupItems directory, legacy login-item .sfl/.sfl2/.sfl3, or a .kext bundle"

log = logging.getLogger('MAIN.' + __Plugin_Name) # Do not rename or remove this ! This is the logger object

#---- Do not change the variable names in above section ----#

# TODO: Old deprecated methods:
#     /private/var/at/jobs/  <--- CRONTAB
#  Login & Logout hooks- https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CustomLogin.html
# Good resource -> https://www.launchd.info/
# For explanation on StartupTypes, see https://keith.github.io/xcode-man-pages/launchd.plist.5.html

DispositionValues = {
    0x01: 'Enabled',
    0x02: 'Allowed',
    0x04: 'Hidden',
    0x08: 'Notified'
}

# Types as per sfltool dumpbtm output
TypeValues = {
    0x01: 'user item',
    0x02: 'app',
    0x04: 'login item',
    0x08: 'agent',
    0x10: 'daemon',
    0x20: 'developer',
    0x40: 'spotlight',
    0x800: 'quicklook',
    0x80000: 'curated',
    0x10000: 'legacy'
}

class PersistentProgram:
    def __init__(self, source, name, full_name, persistence_type, user, uid, disabled, app_path,
                 app_args='', btm_disp='', btm_type='', btm_flags='', btm_developer='', btm_container='',
                 btm_exec_mod_date='', btm_dev_identifier=''):
        self.source = source
        self.name = name
        self.full_name = full_name
        self.persistence_type = persistence_type
        self.user = user
        self.uid = uid
        self.disabled = disabled
        self.start_when = ''
        self.app_path = app_path
        self.app_args = app_args
        self.btm_disposition = btm_disp
        self.btm_type = btm_type
        self.btm_flags = btm_flags
        self.btm_developer = btm_developer
        self.btm_container = btm_container
        self.btm_exec_mod_date = btm_exec_mod_date
        self.btm_dev_identifier = btm_dev_identifier

def process_loginitems_plist(mac_info, plist_path, user, uid, persistent_programs):
    mac_info.ExportFile(plist_path, __Plugin_Name, user + "_", False)
    success, plist, error = mac_info.ReadPlist(plist_path)
    if success:
        try:
            items = plist['SessionItems']['CustomListItems']
            for item in items:
                try:
                    name = item.get('Name', '')
                    path = ''
                    alias_data = item.get('Alias', None)
                    if alias_data:
                        try:
                            alias_properties = next(AliasParser.parse(plist_path, 0, alias_data))
                            path = alias_properties.get('path', '')
                        except (IndexError, ValueError, KeyError, TypeError):
                            log.exception('')
                    program = PersistentProgram(plist_path, name, name, 'Login Item', user, uid, '', path)
                    program.start_when = 'Run at Login'
                    persistent_programs.append(program)
                except (ValueError, TypeError):
                    log.exception('')
        except KeyError:
            pass # SessionItems or CustomListItems not present
            log.warning('Possibly a newer version of com.apple.loginitems.plist Filepath was {}'.format(plist_path))
                    #Look for legacy LoginHook LogoutHook
        login_hook = plist.get('LoginHook', '')
        if login_hook:
            program = PersistentProgram(plist_path, os.path.basename(login_hook), name, 'Login Hook', user, uid, '', login_hook)
            program.start_when = 'Run at Login'
            persistent_programs.append(program)
        logout_hook = plist.get('LogoutHook', '')
        if logout_hook:
            program = PersistentProgram(plist_path, os.path.basename(logout_hook), name, 'Logout Hook', user, uid, '', logout_hook)
            program.start_when = 'Run at Logout'
            persistent_programs.append(program)
    else:
        log.error("Problem reading plist for {} - {}".format(plist_path, error))

def process_loginwindow_plist(mac_info, plist_path, user, uid, persistent_programs):
    '''Reads LoginHook and LogoutHook from com.apple.loginwindow.plist at the correct paths'''
    mac_info.ExportFile(plist_path, __Plugin_Name, user + "_", False)
    success, plist, error = mac_info.ReadPlist(plist_path)
    if success:
        login_hook = plist.get('LoginHook', '')
        if login_hook:
            program = PersistentProgram(plist_path, os.path.basename(login_hook), login_hook,
                                        'Login Hook', user, uid, '', login_hook)
            program.start_when = 'Run at Login'
            persistent_programs.append(program)
        logout_hook = plist.get('LogoutHook', '')
        if logout_hook:
            program = PersistentProgram(plist_path, os.path.basename(logout_hook), logout_hook,
                                        'Logout Hook', user, uid, '', logout_hook)
            program.start_when = 'Run at Logout'
            persistent_programs.append(program)
    else:
        log.error("Problem reading plist for {} - {}".format(plist_path, error))

def process_backgrounditems_btm(mac_info, btm_path, user, uid, persistent_programs):
    global DispositionValues
    global TypeValues

    if mac_info:
        mac_info.ExportFile(btm_path, __Plugin_Name, user + "_", False)
        success, plist, error = mac_info.ReadPlist(btm_path, deserialize=True)
    else:
        success, plist, error = CommonFunctions.ReadPlist(btm_path, deserialize=True)
    if success:
        # >= macOS 10.13 and <= macOS 12
        if isinstance(plist, dict) and plist['version'] == 2:
            all_containers = plist.get('backgroundItems', {}).get('allContainers', {})
            for container in all_containers:
                try:
                    bm = container['internalItems'][0]['bookmark']['data']
                except (KeyError, ValueError, TypeError) as ex:
                    log.error('Error fetching bookmark data ' + str(ex))
                    continue
                if isinstance(bm, bytes):
                    bm = Bookmark.from_bytes(bm)
                elif isinstance(bm, dict):
                    try:
                        bm = Bookmark.from_bytes(bm['NS.data'])
                    except (KeyError, ValueError, TypeError):
                        log.exception("Failed to read NS.data as bookmark")
                        continue
                try:
                    # record type 0xf017 means an item name
                    name = bm.tocs[0][1].get(0xf017, '')

                    # Get full file path
                    vol_path = bm.tocs[0][1].get(BookmarkKey.VolumePath, '')
                    file_path = bm.tocs[0][1].get(BookmarkKey.Path, [])
                    file_path = '/' + '/'.join(file_path)
                    if vol_path and (not file_path.startswith(vol_path)):
                        file_path = vol_path + file_path

                    # If file is on a mounted volume (dmg), get the dmg file details too
                    orig_vol_bm = bm.tocs[0][1].get(BookmarkKey.VolumeBookmark, None)
                    if orig_vol_bm:
                        filtered = list(filter(lambda x: x[0]==orig_vol_bm, bm.tocs))
                        if filtered:
                            orig_vol_toc = filtered[0][1]
                            orig_vol_path = orig_vol_toc.get(BookmarkKey.Path, '')
                            orig_vol_creation_date = orig_vol_toc.get(BookmarkKey.VolumeCreationDate, '')
                            if orig_vol_path:
                                orig_vol_path = '/' + '/'.join(orig_vol_path)
                                log.info
                        else:
                            print ("Error, tid {} not found ".format(orig_vol_bm))
                except (TypeError, KeyError, ValueError) as ex:
                    log.exception('Problem reading btm bookmark')
                    continue

                if not name:
                    name = os.path.basename(file_path)
                program = PersistentProgram(btm_path, name, file_path, 'Background Task Management Agent', user, uid, '', file_path)
                program.start_when = 'Run at Login'
                persistent_programs.append(program)

        # >= macOS 13
        elif isinstance(plist, list) and plist[0].get('version', 0) >= 3:
            log.info(f'BTM version is {plist[0]["version"]}')
            for uuid in plist[1]['store']['itemsByUserIdentifier'].keys():
                user_name = ''
                if mac_info:
                    for user_info in mac_info.users:
                        if uuid == user_info.UUID:
                            user_name = user_info.user_name
                            user_uid = user_info.UID
                            break

                if not user_name:
                    user_name = 'unknown (' + uuid + ')'
                    user_uid = ''

                for item_number in list(range(len(plist[1]['store']['itemsByUserIdentifier'][uuid]))):
                    entry = plist[1]['store']['itemsByUserIdentifier'][uuid][item_number]
                    if entry.get('url', ''):
                        url_relative = entry['url'].get('NS.relative', '')
                    else:
                        url_relative = ''
                    app_arguments = ' '.join(entry.get('programArguments', []))
                    btm_disp = entry.get('disposition', 0)
                    btm_type = entry.get('type', 0)
                    btm_flags = entry.get('flags', 0)
                    btm_dev = entry.get('developerName', '')
                    btm_container = entry.get('container', '')
                    btm_exec_mod_date = entry.get('executableModificationDate', '')
                    btm_team_identifier = entry.get('teamIdentifier', '')
                    name = entry.get('name', '')

                    if btm_type & 0x20 == 0x20:
                        continue # We don't care about 0x20:'developer', these aren't autostart entries
                    
                    executable_path = entry.get('executablePath', '')
                    items = entry.get('items', '')

                    start_when = ''
                    if url_relative.endswith('.plist'):
                        file_path = executable_path
                        if '/LaunchAgents/' in url_relative:
                            start_when = 'Run at Login'
                        elif '/LaunchDaemons/' in url_relative:
                            start_when = 'Run at Boot'
                    elif url_relative:
                        file_path = url_relative
                        start_when = 'Run at Login'
                    elif items:
                        file_path = items[0]
                    else:
                        file_path = 'unknown'

                    disp_str = GetEventFlagsString(btm_disp, DispositionValues)
                    if disp_str.find('Allowed') < 0:
                        disp_str = '|'.join(('NOT Allowed', disp_str))
                    program = PersistentProgram(btm_path, name, file_path, 'Background Task Management Agent', user_name, user_uid, 
                                                '' if btm_disp & 0x1 == 1 else '1', file_path, app_arguments, 
                                                disp_str, GetEventFlagsString(btm_type, TypeValues), 
                                                btm_flags, btm_dev, btm_container, btm_exec_mod_date, btm_team_identifier)
                    program.start_when = start_when
                    persistent_programs.append(program)

        else:
            log.error('Unsupported btm file: {}'.format(btm_path))

    else:
        log.error('Failed to read btm file, Error was ' + error)

def process_kernel_extensions(mac_info, path, persistent_programs):
    try:
        folder_list = mac_info.ListItemsInFolder(path, EntryType.FOLDERS, False)
    except Exception:
        folder_list = []
    if len(folder_list):
        for folder in folder_list:
            full_name = folder['name']
            full_path = path + '/' + full_name
            if not full_name.endswith('.kext'):
                continue
            _process_single_kext_bundle(mac_info, full_path, persistent_programs)
    else:
        log.info('No kernel extensions found under {}'.format(path))

def _process_single_kext_bundle(mac_info, full_path, persistent_programs):
    full_name = os.path.basename(full_path)
    name = os.path.splitext(full_name)[0]
    source = full_path
    info_plist_path = full_path + '/Contents/Info.plist'
    bundle_id = ''
    bundle_version = ''
    executable_name = ''
    team_id = ''
    sha256 = ''
    executable_path = ''

    if mac_info.IsValidFilePath(info_plist_path):
        source = info_plist_path
        success, plist, error = mac_info.ReadPlist(info_plist_path)
        if success and isinstance(plist, dict):
            name = plist.get('CFBundleName', name)
            if isinstance(name, str):
                name = name.lstrip('"').rstrip('"')
            bundle_id = plist.get('CFBundleIdentifier', '')
            bundle_version = plist.get('CFBundleVersion', '') or plist.get('CFBundleShortVersionString', '')
            executable_name = plist.get('CFBundleExecutable', '')
        else:
            log.error("Problem reading plist for {} - {}".format(info_plist_path, error))
        mac_info.ExportFile(info_plist_path, __Plugin_Name, "kext_" + name + "_", False)

    cs = get_bundle_info(mac_info, full_path)
    executable_path = cs.main_binary_path
    team_id = cs.team_id
    sha256 = cs.sha256
    if executable_path and mac_info.IsValidFilePath(executable_path):
        mac_info.ExportFile(executable_path, __Plugin_Name, "kextbin_" + name + "_", False)

    metadata_parts = []
    _append_startup_item_metadata(metadata_parts, 'BundleID', bundle_id)
    _append_startup_item_metadata(metadata_parts, 'Version', bundle_version)
    _append_startup_item_metadata(metadata_parts, 'Executable', executable_name or os.path.basename(executable_path))
    _append_startup_item_metadata(metadata_parts, 'SHA256', sha256)

    program = PersistentProgram(source, name, os.path.splitext(full_name)[0], 'Kernel Extension', 'root', 0, '', executable_path)
    program.start_when = 'Run at Boot'
    program.app_args = '; '.join(metadata_parts)
    program.btm_dev_identifier = team_id
    persistent_programs.append(program)

def _is_loginitems_shared_file_list_name(name):
    lowered = name.lower()
    return ('loginitems' in lowered or 'sessionloginitems' in lowered) and \
           (lowered.endswith('.sfl') or lowered.endswith('.sfl2') or lowered.endswith('.sfl3'))

def _add_shared_file_list_loginitems(entries, source_path, user, uid, persistent_programs):
    for entry in entries:
        target_path = entry.resolved_path or entry.url
        name = entry.name or os.path.basename(target_path or source_path)
        program = PersistentProgram(source_path, name, name, 'Legacy Login Item', user, uid, '', target_path)
        program.start_when = 'Run at Login'
        metadata_parts = ['SharedFileList={}'.format(os.path.basename(source_path))]
        if entry.info:
            metadata_parts.append(entry.info)
        program.app_args = '; '.join(metadata_parts)
        persistent_programs.append(program)

def process_shared_file_list_loginitems(mac_info, root_path, user, uid, persistent_programs, max_depth=3):
    if not mac_info.IsValidFolderPath(root_path):
        return
    queue = [(root_path, 0)]
    seen = set()
    while queue:
        directory, depth = queue.pop(0)
        if directory in seen:
            continue
        seen.add(directory)
        try:
            items = mac_info.ListItemsInFolder(directory, EntryType.FILES_AND_FOLDERS, False)
        except Exception:
            continue
        for item in sorted(items, key=lambda x: x['name'].lower()):
            name = item['name']
            if name.startswith('._') or name == '.DS_Store':
                continue
            item_path = directory + '/' + name
            if mac_info.IsValidFolderPath(item_path):
                if depth < max_depth:
                    queue.append((item_path, depth + 1))
                continue
            if not _is_loginitems_shared_file_list_name(name):
                continue
            mac_info.ExportFile(item_path, __Plugin_Name, user + "_", False)
            handle = mac_info.Open(item_path)
            if not handle:
                continue
            try:
                entries = parse_shared_file_list(handle, item_path)
            finally:
                try:
                    handle.close()
                except Exception:
                    pass
            _add_shared_file_list_loginitems(entries, item_path, user, uid, persistent_programs)

def _summarize_collection_for_startup(name, value, max_items=4):
    '''Return a compact summary string for list/dict launchd values.'''
    if not value:
        return ''
    entries = []
    if isinstance(value, dict):
        for k, v in value.items():
            if v in ('', None):
                entries.append(str(k))
            elif isinstance(v, bool):
                entries.append('{}={}'.format(k, 'true' if v else 'false'))
            else:
                entries.append('{}={}'.format(k, str(v)))
    elif isinstance(value, (list, tuple, set)):
        entries = [str(x) for x in value if x not in ('', None)]
    else:
        entries = [str(value)]
    if not entries:
        return ''
    summary = ','.join(entries[:max_items])
    if len(entries) > max_items:
        summary += ',+{} more'.format(len(entries) - max_items)
    return '{}={}'.format(name, summary)

def _append_startup_item_metadata(parts, key, value):
    '''Append one startup-item metadata field to parts if populated.'''
    if value in ('', None, [], {}):
        return
    if isinstance(value, (list, tuple, set)):
        text = ','.join(str(x) for x in value if x not in ('', None))
    else:
        text = str(value)
    if text:
        parts.append('{}={}'.format(key, text))

def _file_has_shebang(mac_info, path):
    '''Return True if the first bytes of a file look like a script shebang.'''
    try:
        f = mac_info.Open(path)
        if f is None:
            return False
        head = f.read(8)
        return head.startswith(b'#!')
    except Exception:
        return False

def _get_startup_item_target(mac_info, item_dir, item_name):
    '''Pick the most likely startup script inside a StartupItems item folder.'''
    same_name_path = item_dir + '/' + item_name
    if mac_info.IsValidFilePath(same_name_path):
        return same_name_path

    try:
        files = mac_info.ListItemsInFolder(item_dir, EntryType.FILES, False)
    except Exception:
        files = []

    candidates = []
    for item in sorted(files, key=lambda x: x['name'].lower()):
        name = item['name']
        if name in ('.DS_Store', 'StartupParameters.plist') or name.startswith('._'):
            continue
        if name.lower().endswith('.plist'):
            continue
        candidates.append(item_dir + '/' + name)

    for candidate in candidates:
        if _file_has_shebang(mac_info, candidate):
            return candidate
    return candidates[0] if candidates else ''

def process_startup_items(mac_info, path, persistent_programs, user_name, uid):
    '''Parse legacy /Library/StartupItems/<Item>/ directories.'''
    try:
        folder_list = mac_info.ListItemsInFolder(path, EntryType.FOLDERS, False)
    except Exception:
        folder_list = []

    if not folder_list:
        log.info('No startup items found under {}'.format(path))
        return

    for folder in sorted(folder_list, key=lambda x: x['name'].lower()):
        item_name = folder['name']
        item_dir = path + '/' + item_name
        plist_path = item_dir + '/StartupParameters.plist'
        name = item_name
        source = plist_path if mac_info.IsValidFilePath(plist_path) else item_dir
        metadata_parts = []

        if mac_info.IsValidFilePath(plist_path):
            mac_info.ExportFile(plist_path, __Plugin_Name, user_name + "_", False)
            success, plist, error = mac_info.ReadPlist(plist_path)
            if success and isinstance(plist, dict):
                name = plist.get('Description', '') or plist.get('Provides', '')
                if isinstance(name, list):
                    name = ','.join(str(x) for x in name)
                name = name or item_name
                for key in ('Description', 'Provides', 'Requires', 'Uses', 'OrderPreference'):
                    _append_startup_item_metadata(metadata_parts, key, plist.get(key, ''))
            else:
                log.error("Problem reading plist for {} - {}".format(plist_path, error))

        target_path = _get_startup_item_target(mac_info, item_dir, item_name)
        if target_path:
            mac_info.ExportFile(target_path, __Plugin_Name, user_name + "_", False)

        program = PersistentProgram(
            source, name, item_name, 'Startup Item', user_name, uid, '', target_path
        )
        program.start_when = 'Run at Boot'
        program.app_args = '; '.join(metadata_parts)
        persistent_programs.append(program)

def process_dir(mac_info, path, persistent_programs, method, user_name, uid):
    '''Description'''
    if method == 'Startup Item':
        process_startup_items(mac_info, path, persistent_programs, user_name, uid)
        return

    files_list = mac_info.ListItemsInFolder(path, EntryType.FILES, False)
    if len(files_list):
        for file in files_list:
            file_name = file['name']
            full_path = path + '/' + file_name
            if file_name.lower().endswith('.plist') and not file_name.startswith('._'):
                common_name = file_name.split('.')
                if len(common_name) >= 4:
                    del common_name[0]
                    del common_name[0]
                    del common_name[-1]
                    common_name = '.'.join(common_name)
                else:
                    common_name = common_name[len(common_name)-2]
            else:
                common_name = file_name
            full_name = os.path.splitext(file_name)[0]
            disabled = ''
            program = PersistentProgram(full_path, common_name, full_name, method, user_name, uid, disabled, '')

            if mac_info.IsSymbolicLink(full_path):
                target_path = mac_info.ReadSymLinkTargetPath(full_path)
                log.debug('SYMLINK {} <==> {}'.format(full_path, target_path))
                if target_path.startswith('../') or target_path.startswith('./'):
                    full_path = mac_info.GetAbsolutePath(posixpath.split(full_path)[0], target_path)
                else:
                    full_path = target_path
            if full_path.startswith('/System/Cryptexes/App/'):
                # This is a sym link to /../../System/Volumes/Preboot/Cryptexes/App   
                # Read from mac_info.apfs_preboot_volume.
                
                # If this is from a uac collection or other collection where it MAY have 
                # been collected, we'll try to still read it first.
                if not mac_info.IsValidFilePath(full_path):
                    log.warning(f'Path {full_path} is a symlink to Preboot volume. Currently unsupported, skipping')
                    continue

                # TODO - change ExportFile and some other functions to accept a volume, or perhaps better to 
                #        add Preboot volume to the Combined_Volume after reading the 

            mac_info.ExportFile(full_path, __Plugin_Name, user_name + "_", False)

            if method == 'Daemon' or method == 'Agents':
                success, plist, error = mac_info.ReadPlist(full_path)
                if success:
                    disabled_param = plist.get('Disabled', '')
                    if isinstance(disabled_param, dict):
                        feature_flag_enabled = disabled_param.get('#IfFeatureFlagEnabled', '')
                        feature_flag_disabled = disabled_param.get('#IfFeatureFlagDisabled', '')
                        _disabled = disabled_param.get('#Then', '')
                        msg = ''
                        if feature_flag_enabled:
                            msg = 'IfFeatureFlagEnabled {} Then {}'.format(feature_flag_enabled, _disabled)
                        elif feature_flag_disabled:
                            msg = 'IfFeatureFlagDisabled {} Then {}'.format(feature_flag_disabled, _disabled)
                        else:
                            log.error('Unsupported plist Disabled parameter: {}'.format(disabled_param))
                            for k, v in disabled_param.items():
                                if msg:
                                    msg += ', {}:{}'.format(k, v)
                                else:
                                    msg = '{}:{}'.format(k, v)
                        program.disabled = msg
                    else:
                        program.disabled = disabled_param

                    program_path = plist.get('Program', '')
                    program_args = plist.get('ProgramArguments', [])
                    if not program_path:
                        if program_args:
                            program_path = program_args[0]
                    program.app_path = program_path
                    program.app_args = ' '.join(program_args)
                    persistent_programs.append(program)
                    program.start_when = get_run_when(plist, method)
                    program.user = plist.get('UserName', program.user) # plist can override this, so get that value
                else:
                    log.error("Problem reading plist for {} - {}".format(full_path, error))
            else:
                persistent_programs.append(program)

def get_run_when(plist, method):
    run_when = []
    run_at_load = plist.get('RunAtLoad', False)
    keep_alive = plist.get('KeepAlive', False)
    # This can be a dictionary. If AfterInitialDemand is True in this dict, then it is loaded but not started, ie, manual start.
    if isinstance(keep_alive, dict):
        after_initial_demand = keep_alive.get('AfterInitialDemand', False)
        if after_initial_demand == True:
            keep_alive = False
        else:
            keep_alive = True
    if run_at_load or keep_alive:
        #run_when.append('RunAtLoad') # if run_at_load else '') # 'DontRunAtLoad'
        #For daemons this means execution at boot time, for agents execution at login.
        if method == 'Daemon':
            run_when.append('Run at Boot')
        elif method == 'Agents':
            run_when.append('Run at Login')
    for item in ('StartInterval', 'StartCalendarInterval', 'StartOnMount', 'WatchPaths', 'QueueDirectories'):
        val = plist.get(item, '')
        if val:
            run_when.append(f'{item}={str(val)}')
    path_state = plist.get('PathState', '')
    if path_state:
        summary = _summarize_collection_for_startup('PathState', path_state, max_items=3)
        if summary:
            run_when.append(summary)
    mach_services = plist.get('MachServices', '')
    if mach_services:
        summary = _summarize_collection_for_startup('MachServices', mach_services, max_items=3)
        if summary:
            run_when.append(summary)
    sockets = plist.get('Sockets', '')
    if sockets:
        summary = _summarize_collection_for_startup('Sockets', sockets, max_items=3)
        if summary:
            run_when.append(summary)
    session_type = plist.get('LimitLoadToSessionType', '')
    if session_type:
        summary = _summarize_collection_for_startup('LimitLoadToSessionType', session_type, max_items=4)
        if summary:
            run_when.append(summary)
    return ', '.join(run_when)

def process_file(mac_info, file_path, persistent_programs, file_name):
    full_path = file_path + '/' + file_name
    mac_info.ExportFile(full_path, __Plugin_Name, '', False)
    program = PersistentProgram(full_path, file_name, file_name, "Launch Script", 'root', 0, '', '')
    persistent_programs.append(program)

def process_periodic_conf(mac_info, file_path, persistent_programs):
    '''Read periodic.conf to detect local_periodic overrides and non-default periodic trees.
    Emits one row for the config file itself, then scans any custom local_periodic dirs found.'''
    mac_info.ExportFile(file_path, __Plugin_Name, '', False)
    program = PersistentProgram(file_path, os.path.basename(file_path), file_path,
                                'Periodic Config', 'root', 0, '', file_path)
    program.start_when = 'daily/weekly/monthly'
    persistent_programs.append(program)
    f = mac_info.Open(file_path)
    if f is None:
        return
    local_dirs = []
    try:
        for line in f:
            if isinstance(line, bytes):
                line = line.decode('utf-8', errors='replace')
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            # e.g. local_periodic="/usr/local/etc/periodic"
            m = re.match(r'^local_periodic\s*=\s*["\']?([^"\'#\s]+)["\']?', line)
            if m:
                local_dirs.append(m.group(1))
    except Exception:
        log.exception('Error reading {}'.format(file_path))
    for local_dir in local_dirs:
        for sub in ('daily', 'weekly', 'monthly'):
            full_dir = local_dir.rstrip('/') + '/' + sub
            if mac_info.IsValidFolderPath(full_dir):
                process_dir(mac_info, full_dir, persistent_programs, 'Periodic', 'root', 0)

def process_overrides(mac_info, file_path, user, uid, persistent_programs):
    mac_info.ExportFile(file_path, __Plugin_Name, user + "_", False)
    success, plist, error = mac_info.ReadPlist(file_path)
    if success:
        uid_text = str(uid)
        for k, v in plist.items():
            disabled_value = v.get('Disabled', None)
            if disabled_value != None:
                for prog in persistent_programs:
                    if (prog.full_name == k) and (str(prog.uid) == uid_text):
                        prog.disabled = disabled_value
                        log.debug("Override applied to {}".format(k))
                        break
            else:
                log.error('Did not find "Disabled" in override for {}'.format(k))
    else:
        log.error("Problem reading plist for {} - {}".format(file_path, error))

def ProcessLoginRestartApps(mac_info, persistent_programs):
    '''Gets apps/windows set to relaunch upon re-login (after logout)'''
    processed_paths = set()
    plist_folder_path = '{}/Library/Preferences/ByHost' # /com.apple.loginwindow.<UUID>.plist'

    for user in mac_info.users:
        user_name = user.user_name
        if user.home_dir == '/private/var/empty': continue # Optimization, nothing should be here!
        elif user.home_dir == '/private/var/root': user_name = 'root' # Some other users use the same root folder, we will list such all users as 'root', as there is no way to tell
        if user.home_dir in processed_paths: continue # Avoid processing same folder twice (some users have same folder! (Eg: root & daemon))
        processed_paths.add(user.home_dir)
        folder_path = plist_folder_path.format(user.home_dir)
        if mac_info.IsValidFolderPath(folder_path):
            files_list = mac_info.ListItemsInFolder(folder_path, EntryType.FILES, False)
            for file in files_list:
                file_name = file['name']
                full_path = folder_path + '/' + file_name
                if file_name.startswith('com.apple.loginwindow.') and len(file_name) == 64 and file_name.endswith('.plist') and file['size'] > 85:
                    mac_info.ExportFile(full_path, __Plugin_Name, user_name + "_", False)
                    success, plist, error = mac_info.ReadPlist(full_path)
                    if success:
                        items = plist.get('TALAppsToRelaunchAtLogin', [])
                        for item in items:
                            bundle_id = item.get('BundleID', '')
                            bundle_path = item.get('Path', '')
                            program = PersistentProgram(full_path, bundle_id, file_name, "Apps To Relaunch At Login", user_name, user.UID, '', bundle_path)
                            program.start_when = 'Run at Login'
                            persistent_programs.append(program)
                    else:
                        log.error("Problem reading plist {} - {}".format(full_path, error))

def GetEventFlagsString(flags, flag_values):
    '''Get string names of all flags set'''
    list_flags = []
    for k, v in list(flag_values.items()):
        if (k & flags) != 0:
            list_flags.append(v)
    return '|'.join(list_flags)

def print_all(programs, output_params, source_path):
    program_info = [ ('Type',DataType.TEXT),('Name',DataType.TEXT),
                     ('User',DataType.TEXT),('StartupType',DataType.TEXT),('Disabled',DataType.TEXT),
                     ('AppPath',DataType.TEXT),('AppArguments',DataType.TEXT),
                     ('BTM_Disposition',DataType.TEXT),('BTM_Type',DataType.TEXT),
                     #('BTM_Flags',DataType.TEXT),
                     ('BTM_Developer',DataType.TEXT),('BTM_TeamIdentifier',DataType.TEXT),
                     ('BTM_Container',DataType.TEXT),('BTM_ExecutableModDate',DataType.DATE),
                     ('Source',DataType.TEXT) ]
    data_list = []
    log.info("Found {} autostart item(s)".format(len(programs)))
    for program in programs:
        data_list.append([program.persistence_type, program.name, str(program.user), program.start_when, 
                          program.disabled, program.app_path, program.app_args,
                          program.btm_disposition, program.btm_type,
                          program.btm_developer, program.btm_dev_identifier, program.btm_container, 
                          CommonFunctions.ReadMacAbsoluteTime(program.btm_exec_mod_date), 
                          #program.flags,
                          program.source])
    WriteList("autostart information", "AutoStart", data_list, program_info, output_params, source_path)

def Plugin_Start(mac_info):
    '''Main Entry point function for plugin'''
    kext_paths = ('/System/Library/Extensions', '/Library/Extensions')
    persistent_system_paths = { 'Daemon': ['/System/Library/LaunchDaemons', '/Library/LaunchDaemons'], 
                                'Agents': ['/System/Library/LaunchAgents', '/Library/LaunchAgents'], 
                                'Startup Item': ['/System/Library/StartupItems', '/Library/StartupItems'], 
                                'Periodic': ['/private/etc/periodic/daily','/private/etc/periodic/monthly','/private/etc/periodic/weekly',
                                         '/usr/local/etc/periodic/daily','/usr/local/etc/periodic/weekly','/usr/local/etc/periodic/monthly']
                              }
    persistent_file_paths = { '/private/etc' : ['rc.common', 'rc.local', 'launchd.conf']}
    persistent_usr_paths = {'Agents' : ['/Library/LaunchAgents'] }
    processed_paths = set()
    persistent_programs = []

    ### process kernel extensions ###
    for path in kext_paths:
        process_kernel_extensions(mac_info, path, persistent_programs)

    ### process system directories  ###
    for method in persistent_system_paths:
        for path in persistent_system_paths[method]:
            if path in processed_paths: continue
            if mac_info.IsValidFolderPath(path):
                processed_paths.add(path)
                process_dir(mac_info, path, persistent_programs, method, 'root', 0)

    ### process system files ###
    for file_path in persistent_file_paths:
        for file_name in persistent_file_paths[file_path]:
            if file_name in processed_paths: continue
            if mac_info.IsValidFilePath(file_path + '/' + file_name):
                processed_paths.add(file_name)
                process_file(mac_info, file_path, persistent_programs, file_name)

    # Sweep /private/etc/rc* for rc scripts beyond the fixed list above
    _handled_rc = {'rc.common', 'rc.local', 'launchd.conf'}
    if mac_info.IsValidFolderPath('/private/etc'):
        for file_entry in mac_info.ListItemsInFolder('/private/etc', EntryType.FILES, False):
            fname = file_entry['name']
            if fname.startswith('rc') and fname not in _handled_rc:
                full_path = '/private/etc/' + fname
                if full_path not in processed_paths:
                    processed_paths.add(full_path)
                    process_file(mac_info, '/private/etc', persistent_programs, fname)

    # Parse periodic.conf files for local_periodic overrides
    for conf_path in ('/private/etc/defaults/periodic.conf', '/private/etc/periodic.conf'):
        if mac_info.IsValidFilePath(conf_path):
            process_periodic_conf(mac_info, conf_path, persistent_programs)

    # Login hooks from system-wide com.apple.loginwindow.plist
    loginwindow_system_plist = '/Library/Preferences/com.apple.loginwindow.plist'
    if mac_info.IsValidFilePath(loginwindow_system_plist):
        process_loginwindow_plist(mac_info, loginwindow_system_plist, 'root', 0, persistent_programs)

    ### process user dirs ###
    for user in mac_info.users:
        user_name = user.user_name
        if user.home_dir == '/private/var/empty': continue # Optimization, nothing should be here!
        elif user.home_dir == '/private/var/root': user_name = 'root' # Some other users use the same root folder, we will list such all users as 'root', as there is no way to tell
        if user.home_dir in processed_paths: continue # Avoid processing same folder twice (some users have same folder! (Eg: root & daemon))
        processed_paths.add(user.home_dir)
        for method in persistent_usr_paths:
            for path in persistent_usr_paths[method]:
                full_path = "{0}{1}".format(user.home_dir, path)
                if mac_info.IsValidFolderPath(full_path):
                    process_dir(mac_info, full_path, persistent_programs, method, user_name, user.UID)
                else:
                    log.debug("Folder not found {}".format(full_path))

        # process loginitems plist
        loginitems_plist_path = '{}/Library/Preferences/com.apple.loginitems.plist'.format(user.home_dir)
        if mac_info.IsValidFilePath(loginitems_plist_path) and mac_info.GetFileSize(loginitems_plist_path) > 70:
            process_loginitems_plist(mac_info, loginitems_plist_path, user_name, user.UID, persistent_programs)

        # process per-user com.apple.loginwindow.plist for LoginHook / LogoutHook
        loginwindow_plist_path = '{}/Library/Preferences/com.apple.loginwindow.plist'.format(user.home_dir)
        if mac_info.IsValidFilePath(loginwindow_plist_path):
            process_loginwindow_plist(mac_info, loginwindow_plist_path, user_name, user.UID, persistent_programs)

        # process backgrounditems.btm
        backgrounditems_btm_path = '{}/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm'.format(user.home_dir)
        if mac_info.IsValidFilePath(backgrounditems_btm_path):
            process_backgrounditems_btm(mac_info, backgrounditems_btm_path, user_name, user.UID, persistent_programs)

        legacy_loginitems_root = '{}/Library/Application Support/com.apple.sharedfilelist'.format(user.home_dir)
        process_shared_file_list_loginitems(mac_info, legacy_loginitems_root, user_name, user.UID, persistent_programs)

    # process BackgroundItems-v*.btm
    backgrounditems_btm_base_path = '/private/var/db/com.apple.backgroundtaskmanagement'
    if mac_info.IsValidFolderPath(backgrounditems_btm_base_path):
        files_list = mac_info.ListItemsInFolder(backgrounditems_btm_base_path, EntryType.FILES, include_dates=False)
        for file_entry in files_list:
                backgrounditems_btm_path = backgrounditems_btm_base_path + '/' + file_entry['name']
                process_backgrounditems_btm(mac_info, backgrounditems_btm_path, 'root', 0, persistent_programs)

    # system overrides
    override_plist_path = '/private/var/db/launchd.db/com.apple.launchd/overrides.plist'
    if mac_info.IsValidFilePath(override_plist_path) and mac_info.GetFileSize(override_plist_path):
        process_overrides(mac_info, override_plist_path, 'root', 0, persistent_programs)

    # user overrides
    user_override_folder = '/private/var/db/launchd.db'
    if mac_info.IsValidFolderPath(user_override_folder):
        folder_list = mac_info.ListItemsInFolder(user_override_folder, EntryType.FOLDERS, False)
        if len(folder_list):
            for folder in folder_list:
                full_name = folder['name']
                if len(full_name) > 26 and full_name.startswith('com.apple.launchd.peruser.'):
                    uid_str = full_name[26:]
                    uid = CommonFunctions.IntFromStr(uid_str, error_val=None)
                    if uid != None:
                        uid = CommonFunctions.convert_32bit_num_to_signed(uid)
                        uid_str = str(uid)
                        user_name = ''
                        for user in mac_info.users:
                            if user.UID == uid_str:
                                user_name = user.user_name
                                break
                        if user_name != '':
                            override_plist_path = '/private/var/db/launchd.db/com.apple.launchd.peruser.{}/overrides.plist'.format(uid_str)
                            if mac_info.IsValidFilePath(override_plist_path) and mac_info.GetFileSize(override_plist_path):
                                process_overrides(mac_info, override_plist_path, user_name, uid_str, persistent_programs)
                        else:
                            log.error("Failed to get username for UID={}. This was found in filename {}".format(uid, full_name))
                    else:
                        log.error("Failed to get uid from filename {}".format(full_name))
    else:
        log.info('User overrides not present as folder {} not present'.format(user_override_folder))
    # user apps/windows to restart after logon/restart
    ### process user dirs ###
    ProcessLoginRestartApps(mac_info, persistent_programs)

    print_all(persistent_programs, mac_info.output_params, '')

def Plugin_Start_Standalone(input_files_list, output_params):
    '''Main entry point function when used on single artifacts (mac_apt_singleplugin), not on a full disk image'''
    log.info("Module Started as standalone")
    all_persistent_programs = []
    for input_path in input_files_list:
        log.debug("Input path passed was: " + input_path)
        persistent_programs = []
        if input_path.lower().endswith('.btm'):
            process_backgrounditems_btm(None, input_path, '', 0, persistent_programs)
        elif input_path.lower().endswith('.sfl') or input_path.lower().endswith('.sfl2') or input_path.lower().endswith('.sfl3'):
            entries = parse_shared_file_list_path(input_path)
            _add_shared_file_list_loginitems(entries, input_path, '', 0, persistent_programs)
        elif os.path.isdir(input_path):
            if input_path.endswith('.kext'):
                _standalone_process_kext_bundle(input_path, persistent_programs)
            else:
                _standalone_process_startup_items(input_path, persistent_programs)
        elif input_path.lower().endswith('.plist'):
            _standalone_process_launchd_plist(input_path, persistent_programs)
        else:
            log.error('Did not process artifact: {}'.format(input_path))

        if len(persistent_programs) > 0:
            all_persistent_programs.extend(persistent_programs)
        else:
            log.info('No autostart artifacts found in {}'.format(input_path))

    if all_persistent_programs:
        print_all(all_persistent_programs, output_params, '')

def _standalone_process_launchd_plist(plist_path, persistent_programs):
    '''Process a launchd plist in artifact-only mode.'''
    try:
        with open(plist_path, 'rb') as f:
            plist = plistlib.load(f)
    except Exception as ex:
        log.error('Could not read {}: {}'.format(plist_path, ex))
        return

    file_name = os.path.basename(plist_path)
    common_name = file_name.split('.')
    if len(common_name) >= 4:
        del common_name[0]
        del common_name[0]
        del common_name[-1]
        common_name = '.'.join(common_name)
    else:
        common_name = common_name[len(common_name)-2] if len(common_name) >= 2 else file_name
    full_name = os.path.splitext(file_name)[0]
    method = 'Daemon' if 'daemon' in file_name.lower() else 'Agents'
    program = PersistentProgram(plist_path, common_name, full_name, method, '', 0, '', '')
    disabled = plist.get('Disabled', '')
    if isinstance(disabled, dict):
        program.disabled = _summarize_collection_for_startup('Disabled', disabled, max_items=4)
    else:
        program.disabled = disabled
    program_path = plist.get('Program', '')
    program_args = plist.get('ProgramArguments', [])
    if not program_path and program_args:
        program_path = program_args[0]
    program.app_path = program_path
    program.app_args = ' '.join(program_args)
    program.start_when = get_run_when(plist, method)
    program.user = plist.get('UserName', '')
    persistent_programs.append(program)

def _standalone_file_has_shebang(path):
    try:
        with open(path, 'rb') as f:
            return f.read(8).startswith(b'#!')
    except OSError:
        return False

def _standalone_pick_startup_item_target(item_dir, item_name):
    same_name_path = os.path.join(item_dir, item_name)
    if os.path.isfile(same_name_path):
        return same_name_path
    candidates = []
    try:
        for name in sorted(os.listdir(item_dir)):
            candidate = os.path.join(item_dir, name)
            if not os.path.isfile(candidate):
                continue
            if name in ('.DS_Store', 'StartupParameters.plist') or name.startswith('._'):
                continue
            if name.lower().endswith('.plist'):
                continue
            candidates.append(candidate)
    except OSError:
        return ''
    for candidate in candidates:
        if _standalone_file_has_shebang(candidate):
            return candidate
    return candidates[0] if candidates else ''

def _standalone_process_startup_items(path, persistent_programs):
    '''Process a StartupItems root or individual item directory in artifact-only mode.'''
    item_dirs = []
    if os.path.isfile(os.path.join(path, 'StartupParameters.plist')):
        item_dirs = [path]
    else:
        try:
            for name in sorted(os.listdir(path)):
                candidate = os.path.join(path, name)
                if os.path.isdir(candidate):
                    item_dirs.append(candidate)
        except OSError as ex:
            log.error('Could not list {}: {}'.format(path, ex))
            return

    for item_dir in item_dirs:
        item_name = os.path.basename(item_dir.rstrip('/'))
        plist_path = os.path.join(item_dir, 'StartupParameters.plist')
        name = item_name
        metadata_parts = []
        source = plist_path if os.path.isfile(plist_path) else item_dir

        if os.path.isfile(plist_path):
            try:
                with open(plist_path, 'rb') as f:
                    plist = plistlib.load(f)
                name = plist.get('Description', '') or plist.get('Provides', '')
                if isinstance(name, list):
                    name = ','.join(str(x) for x in name)
                name = name or item_name
                for key in ('Description', 'Provides', 'Requires', 'Uses', 'OrderPreference'):
                    _append_startup_item_metadata(metadata_parts, key, plist.get(key, ''))
            except Exception as ex:
                log.error('Could not read {}: {}'.format(plist_path, ex))

        target_path = _standalone_pick_startup_item_target(item_dir, item_name)
        program = PersistentProgram(
            source, name, item_name, 'Startup Item', '', 0, '', target_path
        )
        program.start_when = 'Run at Boot'
        program.app_args = '; '.join(metadata_parts)
        persistent_programs.append(program)

def _standalone_process_kext_bundle(path, persistent_programs):
    info_plist_path = os.path.join(path, 'Contents', 'Info.plist')
    name = os.path.splitext(os.path.basename(path))[0]
    bundle_id = ''
    bundle_version = ''
    executable_name = ''
    executable_path = ''
    source = info_plist_path if os.path.isfile(info_plist_path) else path

    if os.path.isfile(info_plist_path):
        try:
            with open(info_plist_path, 'rb') as handle:
                plist = plistlib.load(handle)
            name = plist.get('CFBundleName', name) or name
            bundle_id = plist.get('CFBundleIdentifier', '')
            bundle_version = plist.get('CFBundleVersion', '') or plist.get('CFBundleShortVersionString', '')
            executable_name = plist.get('CFBundleExecutable', '')
        except Exception as ex:
            log.error('Could not read {}: {}'.format(info_plist_path, ex))

    if executable_name:
        candidate = os.path.join(path, 'Contents', 'MacOS', executable_name)
        if os.path.isfile(candidate):
            executable_path = candidate
    if not executable_path:
        macos_dir = os.path.join(path, 'Contents', 'MacOS')
        if os.path.isdir(macos_dir):
            try:
                names = sorted(os.listdir(macos_dir))
                if names:
                    executable_path = os.path.join(macos_dir, names[0])
            except OSError:
                pass

    metadata_parts = []
    _append_startup_item_metadata(metadata_parts, 'BundleID', bundle_id)
    _append_startup_item_metadata(metadata_parts, 'Version', bundle_version)
    _append_startup_item_metadata(metadata_parts, 'Executable', executable_name or os.path.basename(executable_path))
    program = PersistentProgram(source, name, os.path.splitext(os.path.basename(path))[0], 'Kernel Extension', 'root', 0, '', executable_path)
    program.start_when = 'Run at Boot'
    program.app_args = '; '.join(metadata_parts)
    persistent_programs.append(program)
