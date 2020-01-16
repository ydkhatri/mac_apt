'''
   Copyright (c) 2017 Yogesh Khatri 

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the 
   terms of the MIT License.
   
'''

import pytsk3
from plugins.helpers.apfs_reader import ApfsSysDataLinkedVolume
import plugins.helpers.macinfo as macinfo
from plugins.helpers.writer import *
import logging
import textwrap

log = logging.getLogger('MAIN.DISK_REPORT')

class Vol_Info:
    def __init__(self, name, size, used, file_sys_type, offset, has_os):
        self.name = name
        self.size_bytes = size
        self.size_used = used
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

    def __init__(self, mac_info, source_image_path, apfs_container_only=False):
        self.mac_info = mac_info
        self.image_path = source_image_path
        self.apfs_block_size = 0
        if mac_info.is_apfs:
            self.apfs_block_size = mac_info.apfs_container.block_size
        self.apfs_container_only = apfs_container_only
        if apfs_container_only:
            self.block_size = 0
        else:
            self.block_size = mac_info.vol_info.info.block_size
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
                      ('Size_Used',DataType.TEXT),('macOS_Installed',DataType.TEXT) ]
        info = [ ['Partition', x.file_system, x.name, x.offset, x.size_str, x.size_bytes, x.size_used,
                    '*' if x.has_os else ''] for x in self.volumes]
        info.insert(0, ['Disk', str(self.mac_info.vol_info.info.vstype)[12:], '', 0, Disk_Info.GetSizeStr(self.total_disk_size_in_bytes), self.total_disk_size_in_bytes, '', ''])
        WriteList("disk, partition & volume information", "Disk_Info", info, data_info, self.mac_info.output_params,'')

    def IsApfsBootVolume(self, volume):
        '''Checks if this is the boot volume. For Catalina (10.15), it will return True for
           both SYSTEM and DATA volumes
        '''
        if self.mac_info.macos_FS == volume:
            return True
        elif isinstance(self.mac_info.macos_FS, ApfsSysDataLinkedVolume):
            if volume == self.mac_info.macos_FS.sys_vol or volume == self.mac_info.macos_FS.data_vol:
                return True
        return False

    def ReadVolumesFromPartTable(self):
        if self.apfs_container_only:
            size = self.mac_info.apfs_container_size
            for volume in self.mac_info.apfs_container.volumes:
                used_space = '{:.2f} GB'.format(float(volume.container.block_size * volume.num_blocks_used / (1024*1024*1024.0)))
                vol = Vol_Info(volume.volume_name, size, used_space, 'APFS', 0, self.IsApfsBootVolume(volume))
                self.volumes.append(vol)
        else:
            for part in self.mac_info.vol_info:
                if (int(part.flags) & pytsk3.TSK_VS_PART_FLAG_ALLOC):
                    partition_start_offset = self.block_size * part.start
                    partition_size_in_sectors = part.len
                    file_system = 'Unknown'
                    part_is_apfs = False
                    used_space = ''
                    try:
                        fs = pytsk3.FS_Info(self.img, offset=partition_start_offset)
                        fs_info = fs.info # TSK_FS_INFO
                        fs_type = str(fs_info.ftype)[12:]
                        if fs_type.find("_") > 0: fs_type = fs_type[0:fs_type.find("_")]
                        file_system = fs_type
                        if file_system == 'HFS' and self.mac_info.macos_partition_start_offset == partition_start_offset: # For macOS partition only
                            hfs_info = self.mac_info.hfs_native.GetVolumeInfo()
                            used_space = '{:.2f} GB'.format(float(hfs_info.block_size * (hfs_info.total_blocks - hfs_info.free_blocks) / (1024*1024*1024.0)))
                    except Exception as ex:
                        if self.mac_info.is_apfs and partition_start_offset == self.mac_info.macos_partition_start_offset:
                            part_is_apfs = True
                            for volume in self.mac_info.apfs_container.volumes:
                                used_space = '{:.2f} GB'.format(float(volume.container.block_size * volume.num_blocks_used / (1024*1024*1024.0)))
                                vol = Vol_Info(volume.volume_name, 
                                    partition_size_in_sectors * self.block_size, 
                                    used_space, 'APFS', 
                                    partition_start_offset,
                                    self.IsApfsBootVolume(volume))
                                self.volumes.append(vol)
                        elif part.desc.decode('utf-8').upper() in ("EFI SYSTEM PARTITION", "APPLE_PARTITION_MAP"):
                            log.debug(" Skipping {}".format(part.desc.decode('utf-8')))
                        else:
                            log.debug(" Error: Failed to detect/parse file system!")
                    if not part_is_apfs:
                        vol = Vol_Info(part.desc.decode('utf-8'), 
                                    partition_size_in_sectors * self.block_size, used_space,
                                    file_system, partition_start_offset, self.mac_info.macos_partition_start_offset==partition_start_offset)
                        self.volumes.append(vol)
