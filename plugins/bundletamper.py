'''
   Copyright (c) 2026 jaybird1291

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the
   terms of the MIT License.

   bundletamper.py
   ---------------
   Detects signs of app bundle tampering used for persistence.

   Sub-mechanisms:
     extra_binary             : extra executables in Contents/MacOS/ beyond
                                the declared CFBundleExecutable; or executable
                                files directly under Contents/ root
     dylib_unexpected_location: .dylib placed in Contents/ or Contents/MacOS/
                                rather than Contents/Frameworks/ (unusual location
                                used to shadow search-path resolution)
     reexport_proxy_bundle    : .dylib in Contents/Frameworks/ with
                                LC_REEXPORT_DYLIB pointing to a suspicious or
                                unusual path (proxy dylib hijack pattern)
     unsigned_main            : main bundle executable lacks a code signature
                                (macho_offline reports has_code_signature=False)
                                while the bundle has a declared CFBundleIdentifier,
                                suggesting the binary may have been replaced or
                                built without signing

   App bundles scanned:
     /Applications/  /Library/Applications/  ~/Applications/

   Design notes:
     - Only suspicious/unusual dylib paths (per classify_dylib_path) are flagged
       for reexport_proxy_bundle, suppressing @rpath / @executable_path chaining.
     - extra_binary excludes files whose name starts with a dot (hidden helpers
       placed by some legitimate apps).  Both regular files AND symlinks are
       included since symlinks pointing outside the bundle are a known attack.
     - unsigned_main is informational - unsigned helpers are common in legitimate
       bundles; treat as low-signal unless combined with other indicators.

   Output tables:
     BUNDLETAMPER        - one row per finding
     BUNDLETAMPER_DETAIL - path, dylib refs, codesign context
'''

import logging
import os

from plugins.helpers.macinfo import *
from plugins.helpers.writer import *
from plugins.helpers.app_bundle_discovery import list_curated_app_bundles
from plugins.helpers.codesign_offline import get_bundle_info, get_binary_codesign_info
from plugins.helpers.macho_offline import (
    parse_macho_from_mac_info, classify_dylib_path,
    LC_REEXPORT_DYLIB,
)
from plugins.helpers.persistence_common import (
    MAIN_TABLE_COLUMNS, DETAIL_TABLE_COLUMNS,
    make_main_row, make_detail_row,
    get_file_mtime, safe_user_label,
)

__Plugin_Name = "BUNDLETAMPER"
__Plugin_Friendly_Name = "Bundle Tamper Persistence"
__Plugin_Version = "1.0"
__Plugin_Description = (
    "Detects app bundle tampering used for persistence: extra executables, "
    "unexpected dylib placement, proxy reexport hijack, and unsigned main binaries"
)
__Plugin_Author = "jaybird1291"
__Plugin_Author_Email = ""
__Plugin_Modes = "MACOS,ARTIFACTONLY"
__Plugin_ArtifactOnly_Usage = "Provide an .app bundle path"

log = logging.getLogger('MAIN.' + __Plugin_Name)

#---- Do not change the variable names in above section ----#

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

SYSTEM_APP_DIRS = ['/Applications', '/Library/Applications']


# ---------------------------------------------------------------------------
# Per-bundle checks
# ---------------------------------------------------------------------------

def _list_files_in_dir(mac_info, directory):
    '''Return list of item dicts from ListItemsInFolder, or [] on failure.'''
    if not mac_info.IsValidFolderPath(directory):
        return []
    try:
        return mac_info.ListItemsInFolder(directory, EntryType.FILES, False)
    except Exception:
        return []


def _list_folders_in_dir(mac_info, directory):
    if not mac_info.IsValidFolderPath(directory):
        return []
    try:
        return mac_info.ListItemsInFolder(directory, EntryType.FOLDERS, False)
    except Exception:
        return []


def check_extra_binaries(mac_info, bundle_path, main_binary_name,
                          owner_bundle_id, main_rows, detail_rows):
    '''Flag executables in Contents/MacOS/ beyond the declared main binary.
    Also flags executables placed directly in Contents/ (unusual).'''
    macos_dir   = bundle_path + '/Contents/MacOS'
    contents_dir = bundle_path + '/Contents'

    for search_dir, label in ((macos_dir, 'Contents/MacOS'),
                               (contents_dir, 'Contents')):
        for item in _list_files_in_dir(mac_info, search_dir):
            name = item['name']
            if name.startswith('.'):
                continue
            if name.endswith('.dylib') or name.endswith('.framework'):
                continue
            # In Contents/, only flag executables (not plists, resources, etc.)
            if search_dir == contents_dir:
                # Heuristic: files without extension or .sh/.py/.rb/.pl/.lua
                ext = os.path.splitext(name)[1].lower()
                if ext not in ('', '.sh', '.py', '.rb', '.pl', '.lua', '.zsh',
                               '.bash', '.fish', '.js'):
                    continue
            # Skip the declared main binary when in MacOS/
            if search_dir == macos_dir and name == main_binary_name:
                continue

            item_path = search_dir + '/' + name
            cs = get_binary_codesign_info(mac_info, item_path)
            artifact_mtime = get_file_mtime(mac_info, item_path)
            mac_info.ExportFile(item_path, __Plugin_Name, 'extra_binary_', False)

            main_rows.append(make_main_row(
                mechanism='Bundle Tamper Persistence',
                sub_mechanism='extra_binary',
                scope='system',
                artifact_path=item_path,
                artifact_type='extra_executable',
                target_path=item_path,
                trigger='host app execution / code injection',
                owner_app_path=bundle_path,
                owner_bundle_id=owner_bundle_id,
                label_or_name=name,
                team_id=cs.team_id,
                codesign_status=cs.codesign_status,
                sha256=cs.sha256,
                artifact_mtime=artifact_mtime,
                source=item_path,
            ))
            detail_rows.append(make_detail_row(
                artifact_path=item_path,
                evidence_type='extra_executable_in_bundle',
                key_or_line=label,
                value=name,
                resolved_path=item_path,
            ))


def check_dylib_unexpected_location(mac_info, bundle_path, owner_bundle_id,
                                     main_rows, detail_rows):
    '''Flag .dylib files placed in Contents/ or Contents/MacOS/ (not Frameworks/).'''
    for search_dir in (bundle_path + '/Contents', bundle_path + '/Contents/MacOS'):
        for item in _list_files_in_dir(mac_info, search_dir):
            name = item['name']
            if not name.endswith('.dylib'):
                continue

            item_path = search_dir + '/' + name
            cs = get_binary_codesign_info(mac_info, item_path)
            artifact_mtime = get_file_mtime(mac_info, item_path)
            mac_info.ExportFile(item_path, __Plugin_Name, 'dylib_unexp_', False)

            main_rows.append(make_main_row(
                mechanism='Bundle Tamper Persistence',
                sub_mechanism='dylib_unexpected_location',
                scope='system',
                artifact_path=item_path,
                artifact_type='dylib_unexpected_location',
                target_path=item_path,
                trigger='host app execution / dynamic loader',
                owner_app_path=bundle_path,
                owner_bundle_id=owner_bundle_id,
                label_or_name=name,
                team_id=cs.team_id,
                codesign_status=cs.codesign_status,
                sha256=cs.sha256,
                artifact_mtime=artifact_mtime,
                source=item_path,
            ))
            detail_rows.append(make_detail_row(
                artifact_path=item_path,
                evidence_type='dylib_in_unexpected_bundle_location',
                key_or_line=search_dir.replace(bundle_path, ''),
                value=name,
                resolved_path=item_path,
            ))


def check_reexport_proxy_in_frameworks(mac_info, bundle_path, owner_bundle_id,
                                        main_rows, detail_rows):
    '''Scan Contents/Frameworks/ for .dylib files with LC_REEXPORT_DYLIB
    pointing to suspicious/unusual paths (proxy hijack pattern).'''
    fw_dir = bundle_path + '/Contents/Frameworks'
    for item in _list_files_in_dir(mac_info, fw_dir):
        name = item['name']
        if not name.endswith('.dylib'):
            continue

        item_path = fw_dir + '/' + name
        macho = parse_macho_from_mac_info(mac_info, item_path)
        if macho.parse_error or not macho.arches:
            continue

        for dylib_ref in macho.dylibs:
            if dylib_ref.load_type != 'reexport':
                continue
            classification = classify_dylib_path(dylib_ref.path)
            if classification == 'standard':
                continue
            # Flag: reexport target outside standard locations
            cs = get_binary_codesign_info(mac_info, item_path)
            artifact_mtime = get_file_mtime(mac_info, item_path)
            mac_info.ExportFile(item_path, __Plugin_Name, 'reexport_proxy_', False)

            main_rows.append(make_main_row(
                mechanism='Bundle Tamper Persistence',
                sub_mechanism='reexport_proxy_bundle',
                scope='system',
                artifact_path=item_path,
                artifact_type='proxy_dylib_in_frameworks',
                target_path=dylib_ref.path,
                trigger='host app execution / dylib proxy load',
                owner_app_path=bundle_path,
                owner_bundle_id=owner_bundle_id,
                label_or_name=name,
                team_id=cs.team_id,
                codesign_status=cs.codesign_status,
                sha256=cs.sha256,
                artifact_mtime=artifact_mtime,
                source=item_path,
            ))
            detail_rows.append(make_detail_row(
                artifact_path=item_path,
                evidence_type='reexport_dylib_target',
                key_or_line='LC_REEXPORT_DYLIB',
                value=dylib_ref.path,
                resolved_path=dylib_ref.path if dylib_ref.path.startswith('/') else '',
            ))


def check_unsigned_main(mac_info, bundle_path, main_binary_path, bundle_id,
                         main_rows, detail_rows):
    '''Flag main binary that lacks a code signature when the bundle has a
    bundle ID (suggesting it was expected to be signed).'''
    if not main_binary_path or not bundle_id:
        return

    macho = parse_macho_from_mac_info(mac_info, main_binary_path)
    if macho.parse_error or not macho.arches:
        return
    if macho.has_code_signature:
        return  # signed - nothing to flag

    artifact_mtime = get_file_mtime(mac_info, main_binary_path)

    main_rows.append(make_main_row(
        mechanism='Bundle Tamper Persistence',
        sub_mechanism='unsigned_main',
        scope='system',
        artifact_path=main_binary_path,
        artifact_type='unsigned_main_binary',
        target_path=main_binary_path,
        trigger='host app execution',
        owner_app_path=bundle_path,
        owner_bundle_id=bundle_id,
        label_or_name=os.path.basename(main_binary_path),
        codesign_status='unsigned',
        artifact_mtime=artifact_mtime,
        source=main_binary_path,
    ))
    detail_rows.append(make_detail_row(
        artifact_path=main_binary_path,
        evidence_type='unsigned_mach_o',
        key_or_line='has_code_signature',
        value='False',
        resolved_path=main_binary_path,
    ))


def process_app_bundle(mac_info, bundle_path, main_rows, detail_rows):
    '''Run all BUNDLETAMPER checks on a single .app bundle.'''
    cs = get_bundle_info(mac_info, bundle_path)

    main_binary_name = (os.path.basename(cs.main_binary_path)
                        if cs.main_binary_path else '')

    check_extra_binaries(mac_info, bundle_path, main_binary_name,
                          cs.bundle_id, main_rows, detail_rows)
    check_dylib_unexpected_location(mac_info, bundle_path,
                                     cs.bundle_id, main_rows, detail_rows)
    check_reexport_proxy_in_frameworks(mac_info, bundle_path,
                                        cs.bundle_id, main_rows, detail_rows)
    check_unsigned_main(mac_info, bundle_path, cs.main_binary_path,
                         cs.bundle_id, main_rows, detail_rows)


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def write_output(main_rows, detail_rows, output_params):
    main_col_info = [(c, DataType.TEXT) for c in MAIN_TABLE_COLUMNS]
    for i, (name, _) in enumerate(main_col_info):
        if name in ('ArtifactMTime', 'TargetMTime'):
            main_col_info[i] = (name, DataType.DATE)
    detail_col_info = [(c, DataType.TEXT) for c in DETAIL_TABLE_COLUMNS]

    log.info('Found {} bundle tamper persistence item(s)'.format(len(main_rows)))
    if main_rows:
        WriteList('bundle tamper persistence', 'BUNDLETAMPER', main_rows,
                  main_col_info, output_params, '')
    if detail_rows:
        WriteList('bundle tamper persistence detail', 'BUNDLETAMPER_DETAIL',
                  detail_rows, detail_col_info, output_params, '')


# ---------------------------------------------------------------------------
# Plugin entry points
# ---------------------------------------------------------------------------

def Plugin_Start(mac_info):
    main_rows   = []
    detail_rows = []
    for bundle_path in list_curated_app_bundles(mac_info):
        process_app_bundle(mac_info, bundle_path, main_rows, detail_rows)

    if main_rows or detail_rows:
        write_output(main_rows, detail_rows, mac_info.output_params)
    else:
        log.info('No bundle tamper persistence artifacts found')


def Plugin_Start_Standalone(input_files_list, output_params):
    log.info('Module started as standalone')
    main_rows   = []
    detail_rows = []

    for input_path in input_files_list:
        log.debug('Input path: ' + input_path)
        if not input_path.endswith('.app'):
            log.warning('Expected a .app bundle path, got: {}'.format(input_path))
            continue

        # Minimal standalone check: parse Mach-O of provided binary directly
        import os as _os
        # Walk for executables + dylibs
        main_binary_name = _os.path.basename(input_path).replace('.app', '')
        macos_dir = input_path + '/Contents/MacOS'
        fw_dir    = input_path + '/Contents/Frameworks'

        # Extra binaries
        if _os.path.isdir(macos_dir):
            for fname in _os.listdir(macos_dir):
                if fname.startswith('.') or fname == main_binary_name:
                    continue
                fpath = macos_dir + '/' + fname
                if _os.path.isfile(fpath):
                    main_rows.append(make_main_row(
                        mechanism='Bundle Tamper Persistence',
                        sub_mechanism='extra_binary',
                        artifact_path=fpath,
                        artifact_type='extra_executable',
                        target_path=fpath,
                        trigger='host app execution / code injection',
                        owner_app_path=input_path,
                        label_or_name=fname,
                        source=fpath,
                    ))

        # Reexport proxies in Frameworks/
        if _os.path.isdir(fw_dir):
            from plugins.helpers.macho_offline import parse_macho, classify_dylib_path
            for fname in _os.listdir(fw_dir):
                if not fname.endswith('.dylib'):
                    continue
                fpath = fw_dir + '/' + fname
                try:
                    with open(fpath, 'rb') as f:
                        data = f.read(512 * 1024)
                    macho = parse_macho(data, path=fpath)
                    for dylib_ref in macho.dylibs:
                        if dylib_ref.load_type == 'reexport' and \
                                classify_dylib_path(dylib_ref.path) != 'standard':
                            main_rows.append(make_main_row(
                                mechanism='Bundle Tamper Persistence',
                                sub_mechanism='reexport_proxy_bundle',
                                artifact_path=fpath,
                                artifact_type='proxy_dylib_in_frameworks',
                                target_path=dylib_ref.path,
                                trigger='host app execution / dylib proxy load',
                                owner_app_path=input_path,
                                label_or_name=fname,
                                source=fpath,
                            ))
                except OSError:
                    log.exception('Could not read {}'.format(fpath))

    if main_rows or detail_rows:
        write_output(main_rows, detail_rows, output_params)
    else:
        log.info('No bundle tamper artifacts found in provided paths')


if __name__ == '__main__':
    print('This plugin is part of a framework and does not run independently.')
