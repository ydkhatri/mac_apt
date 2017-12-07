'''
   Copyright (c) 2017 Yogesh Khatri 

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the 
   terms of the MIT License.
   
'''
from __future__ import print_function
from __future__ import unicode_literals
from __future__ import division

import pytsk3
from writer import *
import macinfo
import logging
import textwrap

log = logging.getLogger('MAIN.DISK_REPORT')

class Vol_Info:
    def __init__(self, name, size, file_sys_type, offset, has_os):
        self.name = name
        self.size_bytes = size
        self.file_system = file_sys_type
        self.offset = offset
        self.size_str = Disk_Info.GetSizeStr(size)
        self.has_os = has_os

class Disk_Info:

    @staticmethod
    def GetSizeStr(size_bytes):
        size_str = ''
        if size_bytes < 1024:
            size_str = str(size_bytes) + " bytes"
        elif size_bytes >= 1024 and size_bytes < 1024 * 1024:
            size_str = '{0:.2f} KB'.format(size_bytes / 1024)
        elif size_bytes >= 1024 * 1024 and size_bytes < 1024 * 1024 * 1024:
            size_str = '{0:.2f} MB'.format(size_bytes / (1024 * 1024))
        elif size_bytes >= 1024 * 1024 * 1024 and size_bytes < 1024 * 1024 * 1024 * 1024:
            size_str = '{0:.2f} GB'.format(size_bytes / (1024 * 1024 * 1024))
        else: 
            size_str = '{0:.2f} TB'.format(size_bytes / (1024 * 1024 * 1024 * 1024))
        return size_str

    def __init__(self, mac_info, source_image_path):
        self.mac_info = mac_info
        self.image_path = source_image_path
        self.block_size = mac_info.vol_info.info.block_size
        self.apfs_block_size = 0
        if mac_info.is_apfs:
            self.apfs_block_size = mac_info.apfs_container.block_size
        self.img = mac_info.pytsk_image
        self.volumes = []
        self.total_disk_size_in_bytes = self.img.get_size()
        self.total_MB = self.total_disk_size_in_bytes / (1024 * 1024)
        self.total_GB = self.total_disk_size_in_bytes / (1024 * 1024 * 1024)
    
    def Write(self):
        log.info('Disk info')
        log.info('Disk Size   = {:.2f} GB ({} bytes)'.format(self.total_GB, self.total_disk_size_in_bytes))
        log.info('Part Scheme = {}'.format(str(self.mac_info.vol_info.info.vstype)[12:]))
        log.info('Block size  = {} bytes'.format(self.block_size))
        log.info('Num Sectors = {} '.format(self.total_disk_size_in_bytes/self.block_size))

        self.ReadVolumesFromPartTable()

        data_info = [ ('Type',DataType.TEXT),('Scheme_or_FS-Type',DataType.TEXT),('Name',DataType.TEXT),
                      ('Offset',DataType.INTEGER),('Size',DataType.TEXT), ('Size_in_bytes',DataType.INTEGER),
                      ('macOS_Installed',DataType.TEXT) ]
        info = [ ['Partition', x.file_system, x.name, x.offset, x.size_str, x.size_bytes, 
                    '*' if x.has_os else ''] for x in self.volumes]
        info.insert(0, ['Disk', str(self.mac_info.vol_info.info.vstype)[12:], '', 0, Disk_Info.GetSizeStr(self.total_disk_size_in_bytes), self.total_disk_size_in_bytes, ''])
        WriteList("disk, partition & volume information", "Disk_Info", info, data_info, self.mac_info.output_params,'')

    def ReadVolumesFromPartTable(self): 
        for part in self.mac_info.vol_info:
            if (int(part.flags) & pytsk3.TSK_VS_PART_FLAG_ALLOC):
                partition_start_offset = self.block_size * part.start
                partition_size_in_sectors = part.len
                file_system = 'Unknown'
                part_is_apfs = False
                try:
                    fs = pytsk3.FS_Info(self.img, offset=partition_start_offset)
                    fs_info = fs.info # TSK_FS_INFO
                    fs_type = str(fs_info.ftype)[12:]
                    if fs_type.find("_") > 0: fs_type = fs_type[0:fs_type.find("_")]
                    file_system = fs_type
                except Exception as ex:
                    if self.mac_info.is_apfs and partition_start_offset == self.mac_info.osx_partition_start_offset:
                        part_is_apfs = True
                        for volume in self.mac_info.apfs_container.volumes:
                            vol = Vol_Info(volume.volume_name, 
                                partition_size_in_sectors * self.block_size, 
                                'APFS', 
                                partition_start_offset,
                                self.mac_info.osx_FS == volume)
                            self.volumes.append(vol)
                    else:
                        log.debug(" Error: Failed to detect/parse file system!")
                if not part_is_apfs:
                    vol = Vol_Info(part.desc.decode('utf-8'), 
                                partition_size_in_sectors * self.block_size, 
                                file_system, partition_start_offset, self.mac_info.osx_partition_start_offset==partition_start_offset)
                    self.volumes.append(vol)

            