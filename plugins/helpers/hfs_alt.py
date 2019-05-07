
'''
Copyright 2011 Jean-Baptiste B'edrune, Jean Sigwald

Using New BSD License:
Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
'''

#
# This code has since been edited to improve HFS parsing, add lzvn/lzfse support
# and is now a part of the mac_apt framework
#

#from __future__ import unicode_literals
from __future__ import print_function
import os
import sys
import struct
import zlib
import pytsk3
import logging
from plugins.helpers.common import CommonFunctions
from plugins.helpers.btree import AttributesTree, CatalogTree, ExtentsOverflowTree
from plugins.helpers.structs import *

log = logging.getLogger('MAIN.HELPERS.HFS_ALT')
lzfse_capable = False

try:
    import lzfse
    lzfse_capable = True
except (ImportError, Exception):
    print("lzfse not found. Won't decompress lzfse/lzvn streams")

def write_file(filename,data):
    f = open(filename, "wb")
    f.write(data)
    f.close()

def lzvn_decompress(compressed_stream, compressed_size, uncompressed_size): #TODO: Move to a class!
    '''Adds Prefix and Postfix bytes as required by decompressor, 
        then decompresses and returns uncompressed bytes buffer
    '''
    header = 'bvxn' + struct.pack('<I', uncompressed_size) + struct.pack('<I', compressed_size)
    footer = 'bvx$'
    return lzfse.decompress(header + compressed_stream + footer)

class HFSFile(object):
    def __init__(self, volume, hfsplusfork, fileID, deleted=False):
        self.volume = volume
        self.blockSize = volume.blockSize
        self.fileID = fileID
        self.totalBlocks = hfsplusfork.totalBlocks
        self.logicalSize = hfsplusfork.logicalSize
        self.extents = []
        self.deleted = deleted
        b = 0
        for extent in hfsplusfork.HFSPlusExtentDescriptor:
            self.extents.append(extent)
            b += extent.blockCount
        while b != hfsplusfork.totalBlocks:
            #log.debug("extents overflow {}".format(b))
            k,v = volume.getExtentsOverflowForFile(fileID, b)
            if not v:
                log.debug("extents overflow missing, startblock={}".format(b))
                break
            for extent in v:
                self.extents.append(extent)
                b += extent.blockCount

    def copyOutFile(self, outputfile, truncate=True):
        f = open(outputfile, "wb")
        for i in range(self.totalBlocks):
            f.write(self.readBlock(i))
        if truncate:
            f.truncate(self.logicalSize)
        f.close()

    '''def readAllBuffer(self, truncate=True):
        r = b""
        for i in xrange(self.totalBlocks):
            r += self.readBlock(i)
        if truncate:
            r = r[:self.logicalSize]
        return r
    '''
    def readAllBuffer(self, truncate=True, output_file=None):
        '''Write to output_file if valid, else return a buffer of data'''
        r = b""
        bs = self.volume.blockSize
        blocks_max = 52428800 / bs  # 50MB
        for extent in self.extents:
            if extent.blockCount == 0: continue
            #if not self.deleted and self.fileID != kHFSAllocationFileID and not self.volume.isBlockInUse(lba):
            #    log.debug("FAIL, block "0x{:x}" not marked as used".format(n))
            if extent.blockCount > blocks_max:
                counter = blocks_max
                remaining_blocks = extent.blockCount
                while remaining_blocks > 0:
                    num_blocks_to_read = min(blocks_max, remaining_blocks)
                    data = self.volume.read(extent.startBlock * bs, num_blocks_to_read * bs)
                    if output_file:
                        output_file.write(data)
                    else:
                        r += data
                    remaining_blocks -= num_blocks_to_read
            else:
                data = self.volume.read(extent.startBlock * bs, bs * extent.blockCount)
                if output_file:
                    output_file.write(data)
                else:
                    r += data
        if truncate:
            if output_file:
                output_file.truncate(self.logicalSize)
            else:
                r = r[:self.logicalSize]
        return r

    def processBlock(self, block, lba):
        return block

    def readBlock(self, n):
        bs = self.volume.blockSize
        if n*bs > self.logicalSize:
            raise Exception("BLOCK OUT OF BOUNDS" + "\xFF" * (bs - len("BLOCK OUT OF BOUNDS")))
        bc = 0
        for extent in self.extents:
            bc += extent.blockCount
            if n < bc:
                lba = extent.startBlock+(n-(bc-extent.blockCount))
                if not self.deleted and self.fileID != kHFSAllocationFileID and  not self.volume.isBlockInUse(lba):
                    raise Exception("FAIL, block %x not marked as used" % n)
                return self.processBlock(self.volume.read(lba*bs, bs), lba)
        return b""

class HFSCompressedResourceFork(HFSFile):
    def __init__(self, volume, hfsplusfork, fileID, compression_type, uncompressed_size):
        super(HFSCompressedResourceFork,self).__init__(volume, hfsplusfork, fileID)
        block0 = self.readBlock(0)
        self.compression_type = compression_type
        self.uncompressed_size = uncompressed_size
        if compression_type in [8, 12]: # 8 is lzvn, 12 is lzfse
            #only tested for 8
            self.header = HFSPlusCmpfLZVNRsrcHead.parse(block0)
            #print(self.header)
        else:
            self.header = HFSPlusCmpfRsrcHead.parse(block0)
            #print(self.header)
            self.blocks = HFSPlusCmpfRsrcBlockHead.parse(block0[self.header.headerSize:])
            log.debug("HFSCompressedResourceFork numBlocks:{}".format(self.blocks.numBlocks))

    #HAX, readblock not implemented
    def readAllBuffer(self, truncate=True, output_file=None):
        if self.compression_type in [7, 8, 11, 12] and not lzfse_capable:
            raise ValueError('LZFSE/LZVN compression detected, no decompressor available!')
        buff = super(HFSCompressedResourceFork, self).readAllBuffer()
        r = b""
        if self.compression_type in [7, 11]: # lzvn or lzfse # Does it ever go here????
            raise Exception("Did not expect type " + str(self.compression_type) + " in resource fork")
            try:
                # The following is only for lzvn, not encountered lzfse yet!
                data_start = self.header.headerSize
                compressed_stream = buff[data_start:self.header.totalSize]
                decompressed = lzvn_decompress(compressed_stream, self.header.totalSize - self.header.headerSize, self.uncompressed_size)
                if output_file: output_file.write(decompressed)
                else: r += decompressed
            except Exception as ex:
                raise Exception("Exception from lzfse_lzvn decompressor")
        elif self.compression_type in [8, 12]: # lzvn or lzfse in 64k chunks
            try:
                # The following is only for lzvn, not encountered lzfse yet!
                full_uncomp = self.uncompressed_size
                chunk_uncomp = 65536
                i = 0
                src_offset = self.header.headerSize
                for offset in self.header.chunkOffsets:
                    compressed_size = offset - src_offset
                    data = buff[src_offset:offset] #input_file.read(compressed_size)
                    src_offset = offset
                    if full_uncomp <= 65536:
                        chunk_uncomp = full_uncomp
                    else:
                        chunk_uncomp = 65536
                        if len(self.header.chunkOffsets) == i + 1: # last chunk
                            chunk_uncomp = full_uncomp - (65536 * i)
                    if chunk_uncomp < compressed_size and data[0] == b'\x06':
                        decompressed = data[1:]
                    else:
                        decompressed = lzvn_decompress(data, compressed_size, chunk_uncomp)
                    if output_file: output_file.write(decompressed)
                    else: r += decompressed
                    i += 1
            except Exception as ex:
                raise Exception("Exception from lzfse_lzvn decompressor")
        else:
            base = self.header.headerSize + 4
            for b in self.blocks.HFSPlusCmpfRsrcBlock:
                decompressed = zlib.decompress(buff[base+b.offset:base+b.offset+b.size])
                if output_file: output_file.write(decompressed)
                else: r += decompressed
        return r

class HFSVolume(object):
    def __init__(self, pytsk_image, offset=0):
        self.img = pytsk_image
        self.offset = offset

        try:
            data = self.read(0, 0x1000)
            self.header = HFSPlusVolumeHeader.parse(data[0x400:0x800])
            assert self.header.signature == 0x4858 or self.header.signature == 0x482B
        except:
            raise Exception("Not an HFS+ image")
        #self.is_hfsx = self.header.signature == 0x4858
        self.blockSize = self.header.blockSize
        self.allocationFile = HFSFile(self, self.header.allocationFile, kHFSAllocationFileID)
        self.allocationBitmap = self.allocationFile.readAllBuffer()
        self.extentsFile = HFSFile(self, self.header.extentsFile, kHFSExtentsFileID)
        self.extentsTree = ExtentsOverflowTree(self.extentsFile)
        self.catalogFile = HFSFile(self, self.header.catalogFile, kHFSCatalogFileID)
        self.xattrFile = HFSFile(self, self.header.attributesFile, kHFSAttributesFileID)
        self.catalogTree = CatalogTree(self.catalogFile)
        self.xattrTree = AttributesTree(self.xattrFile)

        self.hasJournal = self.header.attributes & (1 << kHFSVolumeJournaledBit)

    def read(self, offset, size):
        return self.img.read(self.offset + offset, size)

    def volumeID(self):
        return struct.pack(">LL", self.header.finderInfo[6], self.header.finderInfo[7])

    def isBlockInUse(self, block):
        block = int(block)
        thisByte = self.allocationBitmap[block // 8]
        return (thisByte & (1 << (7 - (block % 8)))) != 0

    def unallocatedBlocks(self):
        for i in range(self.header.totalBlocks):
            if not self.isBlockInUse(i):
                yield i, self.read(i*self.blockSize, self.blockSize)

    def getExtentsOverflowForFile(self, fileID, startBlock, forkType=kForkTypeData):
        return self.extentsTree.searchExtents(fileID, forkType, startBlock)

    def getXattr(self, fileID, name):
        return self.xattrTree.searchXattr(fileID, name)

    def getFileByPath(self, path):
        return self.catalogTree.getRecordFromPath(path)

    def getFinderDateAdded(self, path):
        k,v = self.catalogTree.getRecordFromPath(path)
        if k and v.recordType == kHFSPlusFileRecord:
            return v.data.ExtendedFileInfo.finderDateAdded
        elif k and v.recordType == kHFSPlusFolderRecord:
            return v.data.ExtendedFolderInfo.finderDateAdded
        return 0

    def listFolderContents(self, path):
        k,v = self.catalogTree.getRecordFromPath(path)
        if not k or v.recordType != kHFSPlusFolderRecord:
            return
        for k,v in self.catalogTree.getFolderContents(v.data.folderID):
            if v.recordType == kHFSPlusFolderRecord:
                print(v.data.folderID, getString(k) + "/")
            elif v.recordType == kHFSPlusFileRecord:
                print(v.data.fileID, getString(k))
    
    def listFinderData(self, path):
        '''Returns finder data'''
        finder_data = {}
        k,v = self.catalogTree.getRecordFromPath(path)
        date_added = 0
        if k and v.recordType == kHFSPlusFileRecord:
            date_added = v.data.ExtendedFileInfo.finderDateAdded
            if v.data.FileInfo.fileType: finder_data['fileType'] = v.data.FileInfo.fileType
            if v.data.FileInfo.fileCreator: finder_data['fileCreator'] = v.data.FileInfo.fileCreator
            if v.data.FileInfo.finderFlags: finder_data['finderFlags'] = v.data.FileInfo.finderFlags
            if v.data.ExtendedFileInfo.extendedFinderFlags: finder_data['extendedFinderFlags'] = v.data.ExtendedFileInfo.extendedFinderFlags
        elif k and v.recordType == kHFSPlusFolderRecord:
            date_added = v.data.ExtendedFolderInfo.finderDateAdded
            if v.data.FolderInfo.finderFlags: finder_data['FinderFlags'] = v.data.FolderInfo.finderFlags
            if v.data.ExtendedFolderInfo.extendedFinderFlags: finder_data['extendedFinderFlags'] = v.data.ExtendedFolderInfo.extendedFinderFlags
        if date_added: finder_data['DateAdded'] = date_added

        return finder_data

    def listXattrs(self, path):
        k,v = self.catalogTree.getRecordFromPath(path)
        if k and v.recordType == kHFSPlusFileRecord:
            return self.xattrTree.getAllXattrs(v.data.fileID)
        elif k and v.recordType == kHFSPlusFolderThreadRecord:
            return self.xattrTree.getAllXattrs(v.data.folderID)

    '''	Compression type in Xattr as per apple:
        Source: https://opensource.apple.com/source/copyfile/copyfile-138/copyfile.c.auto.html
        case 3:  /* zlib-compressed data in xattr */
        case 4:  /* 64k chunked zlib-compressed data in resource fork */
        case 7:  /* LZVN-compressed data in xattr */
        case 8:  /* 64k chunked LZVN-compressed data in resource fork */
        case 9:  /* uncompressed data in xattr (similar to but not identical to CMP_Type1) */
        case 10: /* 64k chunked uncompressed data in resource fork */
        case 11: /* LZFSE-compressed data in xattr */
        case 12: /* 64k chunked LZFSE-compressed data in resource fork */
            /* valid compression type, we want to copy. */
            break;
        case 5: /* specifies de-dup within the generation store. Don't copy decmpfs xattr. */
            copyfile_debug(3, "compression_type <5> on attribute com.apple.decmpfs for src file %s is not copied.",
                    s->src ? s->src : "(null string)");
            continue;
        case 6: /* unused */
    '''

    def readFile(self, path, output_file=None):
        '''Reads file specified by 'path' and copies it out into output_file if valid, else returns as string'''
        k,v = self.catalogTree.getRecordFromPath(path)
        if not v:
            raise ValueError("File not found")
        data = b''
        assert v.recordType == kHFSPlusFileRecord
        xattr = self.getXattr(v.data.fileID, "com.apple.decmpfs")
        if xattr:
            decmpfs = HFSPlusDecmpfs.parse(xattr)
            log.debug("decmpfs.compression_type={}".format(str(decmpfs.compression_type)))
            if decmpfs.compression_type == 1:
                data = xattr[16:]
                if output_file: output_file.write(data)
            elif decmpfs.compression_type == 3:
                if decmpfs.uncompressed_size == len(xattr) - 16:
                    data = xattr[16:]
                else:
                    data = zlib.decompress(xattr[16:])
                if output_file: output_file.write(data)
            elif decmpfs.compression_type == 4:
                f = HFSCompressedResourceFork(self, v.data.resourceFork, v.data.fileID, decmpfs.compression_type, decmpfs.uncompressed_size)
                data = f.readAllBuffer(True, output_file)
            elif decmpfs.compression_type in [7, 11]:
                if xattr[16] == b'\x06': # perhaps even 0xF?
                    data = xattr[17:] #tested OK
                else: #tested OK
                    uncompressed_size = struct.unpack('<I', xattr[8:12])[0]
                    compressed_size = len(xattr) - 16
                    compressed_stream = xattr[16:]
                    data = lzvn_decompress(compressed_stream, compressed_size, uncompressed_size)
                if output_file: output_file.write(data)
            elif decmpfs.compression_type in [8, 12]:
                # tested for type 8 , OK
                f = HFSCompressedResourceFork(self, v.data.resourceFork, v.data.fileID, decmpfs.compression_type, decmpfs.uncompressed_size)
                data = f.readAllBuffer(True, output_file)
                if output_file: output_file.write(data)
        else:
            f = HFSFile(self, v.data.dataFork, v.data.fileID)
            data = f.readAllBuffer(True, output_file)
        return data

    def readJournal(self):
        jb = self.read(self.header.journalInfoBlock * self.blockSize, self.blockSize)
        jib = JournalInfoBlock.parse(jb)
        return self.read(jib.offset,jib.size)

    def GetFileMACTimesFromFileRecord(self, v):
        times = { 'c_time':None, 'm_time':None, 'cr_time':None, 'a_time':None }
        catalog_file = v.data
        times['c_time'] = CommonFunctions.ReadMacHFSTime(catalog_file.attributeModDate)
        times['m_time'] = CommonFunctions.ReadMacHFSTime(catalog_file.contentModDate)
        times['cr_time'] = CommonFunctions.ReadMacHFSTime(catalog_file.createDate)
        times['a_time'] = CommonFunctions.ReadMacHFSTime(catalog_file.accessDate)
        return times

    def GetFileMACTimes(self, file_path):
        '''
           Returns dictionary {c_time, m_time, cr_time, a_time} 
           where cr_time = created time and c_time = Last time inode/mft modified
        '''
        k,v = self.catalogTree.getRecordFromPath(file_path)
        if k and v.recordType in (kHFSPlusFileRecord, kHFSPlusFolderRecord):
            return self.GetFileMACTimesFromFileRecord(v)
        raise Exception("Path not found or not file/folder!")

    def IsValidFilePath(self, path):
        '''Check if a file path is valid, does not check for folders!'''
        k,v = self.catalogTree.getRecordFromPath(path)
        if not v:
            return False
        return v.recordType == kHFSPlusFileRecord #TODO: Check for hard links , sym links?

    def IsValidFolderPath(self, path):
        '''Check if a folder path is valid'''
        k,v = self.catalogTree.getRecordFromPath(path)
        if not v:
            return False
        return v.recordType == kHFSPlusFolderRecord #TODO: Check for hard links , sym links?

    def GetFileSizeFromFileRecord(self, v):
        xattr = self.getXattr(v.data.fileID, "com.apple.decmpfs")
        if xattr:
            decmpfs = HFSPlusDecmpfs.parse(xattr)
            return decmpfs.uncompressed_size #TODO verify for all cases!
        else:
            return v.data.dataFork.logicalSize

    def GetFileSize(self, path):
        '''For a given file path, gets logical file size'''
        k,v = self.catalogTree.getRecordFromPath(path)
        if k and v.recordType == kHFSPlusFileRecord:
            return self.GetFileSizeFromFileRecord(v)
        else:
            raise Exception("Path not found")

    def GetUserAndGroupID(self, path):
        k,v = self.catalogTree.getRecordFromPath(path)
        if k and v.recordType in (kHFSPlusFileRecord, kHFSPlusFolderRecord):
            return (v.data.HFSPlusBSDInfo.ownerID, v.data.HFSPlusBSDInfo.groupID)
        else:
            raise Exception("Path not found") 
