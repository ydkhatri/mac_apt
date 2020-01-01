# Copyright 2018 Arun Prasannan <arun.prasannan@cclgroupltd.com>. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not
# use this file except in compliance with the License.  You may obtain a copy of
# the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
# License for the specific language governing permissions and limitations under
# the License.

import os
import ctypes
import platform


# https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/uapi/linux/stat.h?h=v4.19#n46
class StatxTimestamp(ctypes.Structure):
    _fields_ = [("tv_sec", ctypes.c_longlong),
                ("tv_nsec", ctypes.c_uint),
                ("__reserved", ctypes.c_int)]


# https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/uapi/linux/stat.h?h=v4.19#n62
class Statx(ctypes.Structure):
    _fields_ = [("stx_mask", ctypes.c_uint),
                ("stx_blksize", ctypes.c_uint),
                ("stx_attributes", ctypes.c_ulonglong),

                ("stx_nlink", ctypes.c_uint),
                ("stx_uid", ctypes.c_uint),
                ("stx_gid", ctypes.c_uint),
                ("stx_mode", ctypes.c_ushort),
                ("__spare0", ctypes.c_ushort * 1),

                ("stx_ino", ctypes.c_ulonglong),
                ("stx_size", ctypes.c_ulonglong),
                ("stx_blocks", ctypes.c_ulonglong),
                ("stx_attributes_mask", ctypes.c_ulonglong),

                ("stx_atime", StatxTimestamp),
                ("stx_btime", StatxTimestamp),
                ("stx_ctime", StatxTimestamp),
                ("stx_mtime", StatxTimestamp),

                ("stx_rdev_major", ctypes.c_uint),
                ("stx_rdev_minor", ctypes.c_uint),
                ("stx_dev_major", ctypes.c_uint),
                ("stx_dev_minor", ctypes.c_uint),

                ("__spare2", ctypes.c_ulonglong * 14)]

    def get_btime(self):
        return self.stx_btime.tv_sec + (self.stx_btime.tv_nsec / 1000000000)


# https://github.com/hrw/syscalls-table
SYSCALLS = {
    "alpha": 522,
    "arc": 291,
    "arm": 397,
    "arm64": 291,
    "armoabi": 9437581,
    "c6x": 291,
    "csky": 291,
    "h8300": 291,
    "hexagon": 291,
    "i386": 383,
    "m68k": 379,
    "metag": 291,
    "microblaze": 398,
    "mips64": 5326,
    "mips64n32": 6330,
    "mipso32": 4366,
    "nds32": 291,
    "nios2": 291,
    "openrisc": 291,
    "parisc": 349,
    "powerpc": 383,
    "powerpc64": 383,
    "riscv": 291,
    "s390": 379,
    "s390x": 379,
    "score": 291,
    "sparc": 360,
    "sparc64": 360,
    "tile": 291,
    "tile64": 291,
    "unicore32": 291,
    "x32": 1073742156,
    "x86_64": 332,
    "xtensa": 351,
}


# https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/uapi/linux/fcntl.h?h=v4.19
AT_FDCWD = -100 # fcntl.h
AT_SYMLINK_NOFOLLOW = 0x100 # fcntl.h
STATX_ALL = 0xfff # stat.h
SYS_STATX = SYSCALLS[platform.machine()]


def statx(path):
    pathname = path.encode('utf8')
    statxbuf = ctypes.create_string_buffer(ctypes.sizeof(Statx))

    lib = ctypes.CDLL(None, use_errno=True)
    syscall = lib.syscall

    # int statx(int dirfd, const char *pathname, int flags, unsigned int mask, struct statx *statxbuf);
    syscall.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_uint, ctypes.c_char_p]
    syscall.restype = ctypes.c_int

    if syscall(SYS_STATX, AT_FDCWD, pathname, AT_SYMLINK_NOFOLLOW, STATX_ALL, statxbuf):
        e = ctypes.get_errno()
        raise OSError(e, os.strerror(e), path)
    return Statx.from_buffer(statxbuf)
