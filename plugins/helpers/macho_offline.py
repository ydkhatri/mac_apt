'''
   Copyright (c) 2026 jaybird1291

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the
   terms of the MIT License.

   macho_offline.py
   ----------------
   Lightweight offline Mach-O / fat Mach-O parser focused on load commands
   relevant to persistence hunting.

   Extracts:
     LC_LOAD_DYLIB         - required dylib dependency
     LC_LOAD_WEAK_DYLIB    - optional (weak) dylib dependency
     LC_REEXPORT_DYLIB     - re-exported dylib (proxy injection pattern)
     LC_LOAD_UPWARD_DYLIB  - upward dylib link
     LC_LAZY_LOAD_DYLIB    - lazily-loaded dylib
     LC_CODE_SIGNATURE     - presence flag + offset/size

   Also detects fat (universal) binaries and iterates all contained arches.

   Performance design:
     Only the first MAX_LOAD_CMD_READ_BYTES of each arch are read for
     load command parsing.  Code signatures are at the END of the binary,
     so LC_CODE_SIGNATURE is flagged from the load command table (cheap)
     without reading the signature blob itself.

   Public API:
     parse_macho(data_or_reader, path='')  -> MachOInfo
     parse_macho_from_mac_info(mac_info, binary_path, max_bytes=...) -> MachOInfo
'''

import logging
import struct

log = logging.getLogger('MAIN.HELPERS.MACHO_OFFLINE')

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Mach-O magic values
MH_MAGIC_32 = 0xFEEDFACE   # 32-bit little-endian
MH_MAGIC_64 = 0xFEEDFACF   # 64-bit little-endian
MH_CIGAM_32 = 0xCEFAEDFE   # 32-bit big-endian (byte-swapped)
MH_CIGAM_64 = 0xCFFAEDFE   # 64-bit big-endian
FAT_MAGIC   = 0xCAFEBABE   # fat/universal (fat header always big-endian)
FAT_MAGIC_64 = 0xCAFEBABF  # fat 64-bit

MACHO_MAGICS = {MH_MAGIC_32, MH_MAGIC_64, MH_CIGAM_32, MH_CIGAM_64}

# Load command types
LC_LOAD_DYLIB        = 0x0000000C
LC_LOAD_WEAK_DYLIB   = 0x00000018
LC_REEXPORT_DYLIB    = 0x8000001F
LC_LOAD_UPWARD_DYLIB = 0x80000023
LC_LAZY_LOAD_DYLIB   = 0x00000020
LC_CODE_SIGNATURE    = 0x0000001D

DYLIB_CMD_MAP = {
    LC_LOAD_DYLIB:        'required',
    LC_LOAD_WEAK_DYLIB:   'weak',
    LC_REEXPORT_DYLIB:    'reexport',
    LC_LOAD_UPWARD_DYLIB: 'upward',
    LC_LAZY_LOAD_DYLIB:   'lazy',
}

# Mach-O file types
_FILE_TYPE_MAP = {
    0x1: 'object',
    0x2: 'executable',
    0x4: 'core',
    0x5: 'preload',
    0x6: 'dylib',
    0x7: 'dylinker',
    0x8: 'bundle',
    0x9: 'dylib_stub',
    0xa: 'dsym',
}

# CPU type → human name (masking off ABI bits)
_CPU_TYPE_MAP = {
    0x07: 'x86',
    0x0C: 'arm',
    0x01000007: 'x86_64',
    0x0100000C: 'arm64',
}

# Maximum bytes read from the start of a binary (covers all load commands
# for essentially any real-world macOS binary)
MAX_LOAD_CMD_READ_BYTES = 512 * 1024   # 512 KB


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

class DylibRef:
    '''A single dylib referenced by a load command.'''
    __slots__ = ('path', 'load_type')

    def __init__(self, path, load_type):
        self.path      = path       # str: dylib path as stored in binary
        self.load_type = load_type  # 'required'|'weak'|'reexport'|'upward'|'lazy'

    def __repr__(self):
        return 'DylibRef({!r}, {!r})'.format(self.path, self.load_type)


class ArchInfo:
    '''Parsed info for one Mach-O arch (slice of a fat binary, or the whole binary).'''
    __slots__ = ('cpu_type', 'file_type', 'dylibs', 'has_code_signature')

    def __init__(self):
        self.cpu_type          = 'unknown'
        self.file_type         = 'unknown'
        self.dylibs            = []        # list[DylibRef]
        self.has_code_signature = False

    def __repr__(self):
        return 'ArchInfo(cpu={!r}, type={!r}, dylibs={}, cs={})'.format(
            self.cpu_type, self.file_type, len(self.dylibs),
            self.has_code_signature)


class MachOInfo:
    '''Top-level result of parse_macho().'''
    __slots__ = ('is_fat', 'arches', 'parse_error')

    def __init__(self):
        self.is_fat      = False
        self.arches      = []     # list[ArchInfo]
        self.parse_error = ''

    @property
    def dylibs(self):
        '''Deduplicated DylibRef list across all arches.'''
        seen   = set()
        result = []
        for arch in self.arches:
            for d in arch.dylibs:
                if d.path not in seen:
                    seen.add(d.path)
                    result.append(d)
        return result

    @property
    def has_code_signature(self):
        return any(a.has_code_signature for a in self.arches)

    def __repr__(self):
        return 'MachOInfo(fat={}, arches={}, dylibs={}, cs={})'.format(
            self.is_fat, len(self.arches), len(self.dylibs),
            self.has_code_signature)


# ---------------------------------------------------------------------------
# Low-level struct helpers
# ---------------------------------------------------------------------------

def _u32(data, offset, big_endian=False):
    fmt = '>I' if big_endian else '<I'
    return struct.unpack_from(fmt, data, offset)[0]


def _read_cstring(data, offset):
    '''Read null-terminated string from data at offset.'''
    end = data.find(b'\x00', offset)
    if end < 0:
        end = len(data)
    try:
        return data[offset:end].decode('utf-8', errors='replace')
    except Exception:
        return ''


# ---------------------------------------------------------------------------
# Single-arch Mach-O parser
# ---------------------------------------------------------------------------

def _parse_single_arch(data, base_offset=0):
    '''Parse one Mach-O slice starting at base_offset.
    Returns ArchInfo or None on failure.'''
    if base_offset + 4 > len(data):
        return None

    magic = _u32(data, base_offset, big_endian=True)  # read as BE to detect
    if magic not in MACHO_MAGICS:
        return None

    # The first 4 bytes are read in big-endian form only to identify the
    # on-disk byte pattern. FE ED FA CE/CF are big-endian Mach-O files,
    # while CE/CF FA ED FE are little-endian ones.
    big_endian = magic in (MH_MAGIC_32, MH_MAGIC_64)
    is_64      = magic in (MH_MAGIC_64, MH_CIGAM_64)
    hdr_size   = 32 if is_64 else 28

    if base_offset + hdr_size > len(data):
        return None

    # Parse mach_header
    endian = '>' if big_endian else '<'
    try:
        if is_64:
            (_, cputype, _, filetype, ncmds, sizeofcmds, _, _) = struct.unpack_from(
                endian + '8I', data, base_offset)
        else:
            (_, cputype, _, filetype, ncmds, sizeofcmds, _) = struct.unpack_from(
                endian + '7I', data, base_offset)
    except struct.error:
        return None

    arch = ArchInfo()
    arch.cpu_type  = _CPU_TYPE_MAP.get(cputype, 'cpu:{:#010x}'.format(cputype))
    arch.file_type = _FILE_TYPE_MAP.get(filetype, 'type:{:#x}'.format(filetype))

    # Parse load commands
    lc_offset = base_offset + hdr_size
    lc_end    = lc_offset + sizeofcmds-

    if lc_end > len(data):
        # We may have a truncated read — process as much as available
        lc_end = len(data)

    pos = lc_offset
    for _ in range(ncmds):
        if pos + 8 > lc_end:
            break
        try:
            cmd, cmdsize = struct.unpack_from(endian + 'II', data, pos)
        except struct.error:
            break
        if cmdsize < 8:
            break

        if cmd == LC_CODE_SIGNATURE:
            arch.has_code_signature = True

        elif cmd in DYLIB_CMD_MAP:
            # dylib_command: cmd(4) + cmdsize(4) + name_offset(4) + ...
            if pos + 12 <= lc_end:
                try:
                    name_off = struct.unpack_from(endian + 'I', data, pos + 8)[0]
                    abs_name = pos + name_off
                    if abs_name < lc_end:
                        dylib_path = _read_cstring(data, abs_name)
                        if dylib_path:
                            arch.dylibs.append(
                                DylibRef(dylib_path, DYLIB_CMD_MAP[cmd]))
                except struct.error:
                    pass

        pos += cmdsize

    return arch


# ---------------------------------------------------------------------------
# Fat / universal binary parser
# ---------------------------------------------------------------------------

def _parse_fat(data, is_fat64=False):
    '''Parse a fat/universal binary. Returns list[ArchInfo].'''
    # Fat header is always big-endian
    if len(data) < 8:
        return []
    nfat_arch = _u32(data, 4, big_endian=True)
    if nfat_arch > 64:  # sanity check
        return []

    arches = []
    fat_arch_offset = 8
    arch_entry_size = 32 if is_fat64 else 20
    for i in range(nfat_arch):
        arch_entry_start = fat_arch_offset + i * arch_entry_size
        if arch_entry_start + arch_entry_size > len(data):
            break
        try:
            if is_fat64:
                arch_offset, arch_size = struct.unpack_from('>QQ', data, arch_entry_start + 8)
            else:
                arch_offset = _u32(data, arch_entry_start + 8, big_endian=True)
                arch_size   = _u32(data, arch_entry_start + 12, big_endian=True)
        except struct.error:
            break

        # Slice the arch data (capped at what we have)
        slice_end = min(arch_offset + arch_size, len(data))
        if slice_end <= arch_offset:
            continue
        arch_info = _parse_single_arch(data[:slice_end], arch_offset)
        if arch_info:
            arches.append(arch_info)

    return arches-


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parse_macho(data, path=''):
    '''Parse Mach-O / fat Mach-O from bytes.
    Returns MachOInfo.  Never raises — errors are logged at DEBUG.

    Args:
        data: bytes (the binary or first MAX_LOAD_CMD_READ_BYTES of it)
        path: optional str for log messages
    '''
    info = MachOInfo()
    if not data or len(data) < 4:
        info.parse_error = 'too small'
        return info

    if isinstance(data, str):
        data = data.encode('latin-1')

    # Peek at magic (big-endian read to normalise byte-order detection)
    magic = _u32(data, 0, big_endian=True)

    if magic in (FAT_MAGIC, FAT_MAGIC_64):
        info.is_fat = True
        info.arches = _parse_fat(data, is_fat64=(magic == FAT_MAGIC_64))
        if not info.arches:
            info.parse_error = 'empty fat binary'

    elif magic in MACHO_MAGICS:
        arch = _parse_single_arch(data)
        if arch:
            info.arches = [arch]
        else:
            info.parse_error = 'single-arch parse failed'

    else:
        info.parse_error = 'not a Mach-O file (magic={:#010x})'.format(magic)

    return info


def parse_macho_from_mac_info(mac_info, binary_path,
                               max_bytes=MAX_LOAD_CMD_READ_BYTES):
    '''Read a binary from a mac_info filesystem and parse its Mach-O structure.
    Reads at most max_bytes from the start of the file (sufficient for all
    load commands in practice).
    Returns MachOInfo.'''
    info = MachOInfo()
    try:
        file_size = mac_info.GetFileSize(binary_path)
        if not file_size:
            info.parse_error = 'empty or missing file'
            return info
        f = mac_info.Open(binary_path)
        if f is None:
            info.parse_error = 'could not open'
            return info
        data = f.read(min(file_size, max_bytes))
        if isinstance(data, str):
            data = data.encode('latin-1')
    except Exception as e:
        info.parse_error = str(e)
        log.debug('macho_offline: read error for {}: {}'.format(binary_path, e))
        return info-

    return parse_macho(data, path=binary_path)


# ---------------------------------------------------------------------------
# Convenience: dylib path classification
# ---------------------------------------------------------------------------

# Path prefixes considered "standard" — not flagged as suspicious
STANDARD_DYLIB_PREFIXES = (
    '/usr/lib/',
    '/usr/local/lib/',
    '/System/Library/',
    '/Library/Frameworks/',
    '/opt/homebrew/lib/',
    '/opt/homebrew/opt/',
    '@rpath/',
    '@executable_path/',
    '@executable_path/../Frameworks/',
    '@executable_path/../PlugIns/',
    '@loader_path/',
    '@loader_path/../Frameworks/',
    '@loader_path/../PlugIns/',
)

# Prefixes/substrings that are always suspicious regardless of other factors
SUSPICIOUS_DYLIB_PATTERNS = (
    '/tmp/',
    '/private/tmp/',
    '/var/folders/',
    '/private/var/folders/',
    '/Users/',
    '/home/',
)


def classify_dylib_path(path):
    '''Return "standard" | "suspicious" | "unusual" for a dylib path.

    standard : well-known system or framework location
    suspicious: writable / temporary directory
    unusual   : absolute or relative path not matching either category
    '''
    if not path:
        return 'unusual'
    for prefix in STANDARD_DYLIB_PREFIXES:
        if path.startswith(prefix):
            return 'standard'
    for pat in SUSPICIOUS_DYLIB_PATTERNS:
        if path.startswith(pat):
            return 'suspicious'
    return 'unusual'
