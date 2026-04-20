'''
   Copyright (c) 2026 jaybird1291

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the
   terms of the MIT License.

   codesign_offline.py
   -------------------
   Offline code-signature enrichment for persistence plugins.

   Provides:
     get_bundle_info(mac_info, bundle_path)      -> BundleInfo
     get_binary_codesign_info(mac_info, path)    -> BundleInfo
     compute_sha256(mac_info, path)              -> str (hex)

   What is extracted offline:
     - CFBundleIdentifier  (from Contents/Info.plist or Info.plist)
     - Team ID             (from CodeDirectory blob in the Mach-O binary)
     - SHA-256             (of the main executable)
     - CodeSign status     ('signed' | 'adhoc' | 'unsigned' | 'unknown')

   What requires live tools (not implemented here):
     - Signer common name   (codesign -dvvv / certificate chain)
     - Entitlement details  (available via LC_CODE_SIGNATURE → CSSLOT_ENTITLEMENTS,
                             but full Mach-O parsing is deferred to macho_offline.py)
     - Revocation status

   Team ID extraction strategy:
     The CodeDirectory blob (magic 0xfade0c02) embeds a null-terminated Team ID
     string at `teamOffset` (present when CodeDirectory version >= 0x20200).
     We scan the last MAX_SCAN_BYTES of the binary for this blob.
     Code signatures are always appended at the end of Mach-O files, so
     restricting the scan to the tail is both correct and efficient.
'''

import hashlib
import logging
import struct

log = logging.getLogger('MAIN.HELPERS.CODESIGN_OFFLINE')

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# CodeDirectory magic (big-endian uint32)
CSMAGIC_CODEDIRECTORY  = 0xfade0c02
CD_MAGIC_BYTES         = b'\xfa\xde\x0c\x02'

# Minimum CodeDirectory version that carries a teamOffset field
# (field added in 0x20200; present in all modern macOS binaries)
CD_VERSION_TEAM_OFFSET = 0x20200

# Byte offset of fields within a CodeDirectory struct (all big-endian uint32):
#   magic(4) length(4) version(4) flags(4) hashOffset(4) identOffset(4)
#   nSpecialSlots(4) nCodeSlots(4) codeLimit(4) hashSize(1) hashType(1)
#   platform(1) pageSize(1) spare2(4) scatterOffset(4) → teamOffset at byte 48
CD_FLAGS_FIELD_POS       = 12   # offset of flags within CodeDirectory struct
CD_TEAM_OFFSET_FIELD_POS = 48   # offset of teamOffset field

# CS_ADHOC flag: set when the binary is signed without a certificate (self-signed)
CS_ADHOC = 0x2

# Maximum bytes read from the end of a binary when scanning for Team ID.
# Code signatures are always at the end of a Mach-O; 4 MB is generous.
MAX_SCAN_BYTES = 4 * 1024 * 1024

# Team IDs are always exactly 10 upper-case alphanumeric characters
TEAM_ID_LEN = 10


# ---------------------------------------------------------------------------
# Data class
# ---------------------------------------------------------------------------

class BundleInfo:
    '''Lightweight container for offline codesign enrichment results.'''
    __slots__ = ('bundle_id', 'team_id', 'codesign_status', 'sha256',
                 'main_binary_path')

    def __init__(self):
        self.bundle_id        = ''
        self.team_id          = ''
        self.codesign_status  = 'unknown'  # signed | adhoc | unsigned | unknown
        self.sha256           = ''
        self.main_binary_path = ''

    def __repr__(self):
        return ('BundleInfo(bundle_id={!r}, team_id={!r}, '
                'status={!r}, sha256={!r:.16})'.format(
                    self.bundle_id, self.team_id,
                    self.codesign_status, self.sha256))


# ---------------------------------------------------------------------------
# SHA-256 computation
# ---------------------------------------------------------------------------

def compute_sha256(mac_info, file_path):
    '''Return lowercase hex SHA-256 of the file, or empty string on error.'''
    try:
        f = mac_info.Open(file_path)
        if f is None:
            return ''
        h = hashlib.sha256()
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            if isinstance(chunk, str):
                chunk = chunk.encode('latin-1')
            h.update(chunk)
        return h.hexdigest()
    except Exception:
        log.debug('SHA-256 failed for {}'.format(file_path))
        return ''


# ---------------------------------------------------------------------------
# Team ID extraction
# ---------------------------------------------------------------------------

def _scan_bytes_for_team_id(data):
    '''Scan a bytes buffer for a CodeDirectory blob.
    Returns (team_id, is_adhoc) where:
      team_id  - 10-char alphanumeric string or empty string
      is_adhoc - True when CS_ADHOC flag is set in any valid CodeDirectory found
    '''
    offset = 0
    found_is_adhoc = False

    while True:
        idx = data.find(CD_MAGIC_BYTES, offset)
        if idx < 0:
            break

        # Need at least 16 bytes to verify magic and read flags
        if len(data) - idx < CD_FLAGS_FIELD_POS + 4:
            break

        try:
            magic, _length, version = struct.unpack_from('>III', data, idx)
            if magic != CSMAGIC_CODEDIRECTORY:
                offset = idx + 4
                continue

            # Read CS flags — present in all CodeDirectory versions
            flags = struct.unpack_from('>I', data, idx + CD_FLAGS_FIELD_POS)[0]
            if flags & CS_ADHOC:
                found_is_adhoc = True

            if version < CD_VERSION_TEAM_OFFSET:
                offset = idx + 4
                continue

            # Need 52 bytes to read the teamOffset field
            if len(data) - idx < CD_TEAM_OFFSET_FIELD_POS + 4:
                offset = idx + 4
                continue

            team_field_off = struct.unpack_from('>I', data,
                                                idx + CD_TEAM_OFFSET_FIELD_POS)[0]
            if team_field_off == 0:
                offset = idx + 4
                continue

            abs_off = idx + team_field_off
            if abs_off >= len(data):
                offset = idx + 4
                continue

            # Team ID is null-terminated; cap search to avoid runaway reads
            end = data.find(b'\x00', abs_off, abs_off + TEAM_ID_LEN + 2)
            if end < 0:
                offset = idx + 4
                continue

            raw = data[abs_off:end]
            if len(raw) != TEAM_ID_LEN:
                offset = idx + 4
                continue

            try:
                candidate = raw.decode('ascii')
            except UnicodeDecodeError:
                offset = idx + 4
                continue

            if candidate.isalnum() and candidate.isupper():
                return candidate, found_is_adhoc
            # Some Team IDs mix upper and digit only - accept alphanumeric
            if candidate.isalnum():
                return candidate, found_is_adhoc

        except struct.error:
            pass

        offset = idx + 4

    return '', found_is_adhoc


def get_team_id_from_binary(mac_info, binary_path):
    '''Extract Team ID and adhoc flag from a Mach-O binary by scanning for a
    CodeDirectory. Reads only the last MAX_SCAN_BYTES of the file for performance.
    Returns (team_id, is_adhoc) tuple.'''
    try:
        file_size = mac_info.GetFileSize(binary_path)
        if not file_size:
            return '', False
        f = mac_info.Open(binary_path)
        if f is None:
            return '', False

        if file_size > MAX_SCAN_BYTES:
            f.seek(file_size - MAX_SCAN_BYTES)
            data = f.read(MAX_SCAN_BYTES)
        else:
            data = f.read(file_size)

        if isinstance(data, str):
            data = data.encode('latin-1')

        return _scan_bytes_for_team_id(data)

    except Exception:
        log.debug('Team ID binary scan failed for {}'.format(binary_path))
        return '', False


# ---------------------------------------------------------------------------
# Bundle-level helpers
# ---------------------------------------------------------------------------

def _find_main_binary(mac_info, bundle_path, plist):
    '''Resolve the path to the main executable inside a bundle.
    Tries CFBundleExecutable first, then falls back to listing Contents/MacOS.'''
    exec_name = plist.get('CFBundleExecutable', '') if plist else ''

    candidates = []
    if exec_name:
        for subdir in ('Contents/MacOS', 'MacOS', 'Contents'):
            candidates.append(bundle_path + '/' + subdir + '/' + exec_name)

    for c in candidates:
        if mac_info.IsValidFilePath(c):
            return c

    # Fallback: first file in Contents/MacOS
    from plugins.helpers.macinfo import EntryType
    for macos_dir in (bundle_path + '/Contents/MacOS', bundle_path + '/MacOS'):
        if mac_info.IsValidFolderPath(macos_dir):
            try:
                items = mac_info.ListItemsInFolder(macos_dir,
                                                   EntryType.FILES, False)
                if items:
                    return macos_dir + '/' + items[0]['name']
            except Exception:
                pass
    return ''


def _has_code_signature_dir(mac_info, bundle_path):
    for sig_dir in (bundle_path + '/Contents/_CodeSignature',
                    bundle_path + '/_CodeSignature'):
        if mac_info.IsValidFolderPath(sig_dir):
            return True
    return False


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_bundle_info(mac_info, bundle_path):
    '''Offline codesign enrichment for an app bundle (.app / .framework / etc.)
    Returns a BundleInfo instance.  Never raises - errors are logged at DEBUG.'''
    info = BundleInfo()

    # --- Bundle ID from Info.plist ---
    plist = None
    for plist_path in (bundle_path + '/Contents/Info.plist',
                       bundle_path + '/Info.plist'):
        if mac_info.IsValidFilePath(plist_path):
            success, plist_data, _ = mac_info.ReadPlist(plist_path)
            if success and isinstance(plist_data, dict):
                info.bundle_id = plist_data.get('CFBundleIdentifier', '')
                plist = plist_data
                break

    # --- Main binary path ---
    info.main_binary_path = _find_main_binary(mac_info, bundle_path, plist)

    # --- Team ID + SHA-256 ---
    is_adhoc = False
    if info.main_binary_path:
        info.team_id, is_adhoc = get_team_id_from_binary(mac_info, info.main_binary_path)
        info.sha256  = compute_sha256(mac_info, info.main_binary_path)

    # --- CodeSign status ---
    has_sig_dir = _has_code_signature_dir(mac_info, bundle_path)
    if is_adhoc:
        info.codesign_status = 'adhoc'
    elif info.team_id:
        info.codesign_status = 'signed'
    elif has_sig_dir:
        # Signature directory present but Team ID not readable
        info.codesign_status = 'signed'
    elif info.main_binary_path:
        info.codesign_status = 'unsigned'
    # else: bundle without binary - leave as 'unknown'

    return info


def get_binary_codesign_info(mac_info, binary_path):
    '''Offline codesign enrichment for a standalone Mach-O binary (not a bundle).
    Returns a BundleInfo instance (bundle_id will be empty).'''
    info = BundleInfo()
    info.main_binary_path = binary_path
    info.team_id, is_adhoc = get_team_id_from_binary(mac_info, binary_path)
    info.sha256  = compute_sha256(mac_info, binary_path)

    if is_adhoc:
        info.codesign_status = 'adhoc'
    elif info.team_id:
        info.codesign_status = 'signed'
    else:
        info.codesign_status = 'unknown'

    return info
