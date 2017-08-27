
'''
Copyright 2011 Jean-Baptiste B'edrune, Jean Sigwald

Using New BSD License:
Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
'''

"""
HFS+:
http://developer.apple.com/library/mac/#technotes/tn/tn1150.html

Finder flags:
http://mirror.informatimago.com/next/developer.apple.com/documentation/Carbon/Reference/Finder_Interface/finder_interface/constant_1.html
   kIsOnDesk = 0x0001,
   kColor = 0x000E,
   kIsShared = 0x0040,
   kHasNoINITs = 0x0080,
   kHasBeenInited = 0x0100,
   kHasCustomIcon = 0x0400,
   kIsStationery = 0x0800,
   kNameLocked = 0x1000,
   kHasBundle = 0x2000,
   kIsInvisible = 0x4000,
   kIsAlias = 0x8000
"""

from construct import *

def getString(obj):
    return obj.HFSUniStr255.unicode

kHFSRootParentID            = 1
kHFSRootFolderID            = 2
kHFSExtentsFileID           = 3
kHFSCatalogFileID           = 4
kHFSBadBlockFileID          = 5
kHFSAllocationFileID        = 6
kHFSStartupFileID           = 7
kHFSAttributesFileID        = 8
kHFSRepairCatalogFileID     = 14
kHFSBogusExtentFileID       = 15
kHFSFirstUserCatalogNodeID  = 16

kBTLeafNode       = -1
kBTIndexNode      =  0
kBTHeaderNode     =  1
kBTMapNode        =  2

kHFSPlusFolderRecord        = 0x0001
kHFSPlusFileRecord          = 0x0002
kHFSPlusFolderThreadRecord  = 0x0003
kHFSPlusFileThreadRecord    = 0x0004

kHFSPlusAttrInlineData  = 0x10
kHFSPlusAttrForkData    = 0x20
kHFSPlusAttrExtents     = 0x30

kForkTypeData = 0
kForkTypeRsrc = 0xFF

kHFSVolumeHardwareLockBit       =  7
kHFSVolumeUnmountedBit          =  8
kHFSVolumeSparedBlocksBit       =  9
kHFSVolumeNoCacheRequiredBit    = 10
kHFSBootVolumeInconsistentBit   = 11
kHFSCatalogNodeIDsReusedBit     = 12
kHFSVolumeJournaledBit          = 13
kHFSVolumeSoftwareLockBit       = 15

kHFSCaseFolding   = 0xCF	#Case folding (case-insensitive) # For HFSX only
kHFSBinaryCompare = 0xBC	#Binary compare (case-sensitive) # For HFSX only

DECMPFS_MAGIC = 0x636d7066  #cmpf

HFSPlusExtentDescriptor = "HFSPlusExtentDescriptor" / Struct(
    "startBlock" / Int32ub,
    "blockCount" / Int32ub
)
HFSPlusExtentRecord = Array(8, "HFSPlusExtentDescriptor" / HFSPlusExtentDescriptor)

HFSPlusForkData = "HFSPlusForkData" / Struct(
    "logicalSize" / Int64ub,
    "clumpSize" / Int32ub,
    "totalBlocks" / Int32ub,
    Array(8, "HFSPlusExtentDescriptor" / HFSPlusExtentDescriptor)
)

HFSPlusVolumeHeader= "HFSPlusVolumeHeader" / Struct(
    "signature" / Int16ub,
    "version" / Int16ub,
    "attributes" / Int32ub,
    "lastMountedVersion" / Int32ub,
    "journalInfoBlock" / Int32ub,
    "createDate" / Int32ub,
    "modifyDate" / Int32ub,
    "backupDate" / Int32ub,
    "checkedDate" / Int32ub,
    "fileCount" / Int32ub,
    "folderCount" / Int32ub,
    "blockSize" / Int32ub,
    "totalBlocks" / Int32ub,
    "freeBlocks" / Int32ub,
    "nextAllocation" / Int32ub,
    "rsrcClumpSize" / Int32ub,
    "dataClumpSize" / Int32ub,
    "nextCatalogID" / Int32ub,
    "writeCount" / Int32ub,
    "encodingsBitmap" / Int64ub,
    Array(8, "finderInfo" / Int32ub),
    "allocationFile" / HFSPlusForkData,
    "extentsFile" / HFSPlusForkData,
    "catalogFile" / HFSPlusForkData,
    "attributesFile" / HFSPlusForkData,
    "startupFile" / HFSPlusForkData
)

BTNodeDescriptor = "BTNodeDescriptor" / Struct(
    "fLink" / Int32ub,
    "bLink" / Int32ub,
    "kind" / Int8sb,
    "height" / Int8ub,
    "numRecords" / Int16ub,
    "reserved" / Int16ub
)

BTHeaderRec = "BTHeaderRec" / Struct(
    "treeDepth" / Int16ub,
    "rootNode" / Int32ub,
    "leafRecords" / Int32ub,
    "firstLeafNode" / Int32ub,
    "lastLeafNode" / Int32ub,
    "nodeSize" / Int16ub,
    "maxKeyLength" / Int16ub,
    "totalNodes" / Int32ub,
    "freeNodes" / Int32ub,
    "reserved1" / Int16ub,
    "clumpSize" / Int32ub,
    "btreeType" / Int8ub,
    "keyCompareType" / Int8ub,
    "attributes" / Int32ub,
    Array(16, "reserved3" / Int32ub)
)

HFSUniStr255 = "HFSUniStr255" / Struct(
    "length" / Int16ub,
    "unicode" / String(lambda ctx: ctx["length"] * 2, encoding="utf-16-be") # "unicode", 
)

HFSPlusAttrKey = "HFSPlusAttrKey" / Struct(
    "keyLength" / Int16ub,
    "pad" / Int16ub,
    "fileID" / Int32ub,
    "startBlock" / Int32ub,
    "HFSUniStr255" / HFSUniStr255,
    #Int32ub("nodeNumber")
)

HFSPlusAttrData = "HFSPlusAttrData" / Struct(
    "recordType" / Int32ub,
    Array(2, "reserved" / Int32ub),
    "size" / Int32ub,
    "data" / Bytes(lambda ctx: ctx["size"])
)

HFSPlusCatalogKey = "HFSPlusCatalogKey" / Struct(
    "keyLength" / Int16ub,
    "parentID" / Int32ub,
    "HFSUniStr255" / HFSUniStr255
)

HFSPlusBSDInfo = "HFSPlusBSDInfo" / Struct(
    "ownerID" / Int32ub,
    "groupID" / Int32ub,
    "adminFlags" / Int8ub,
    "ownerFlags" / Int8ub,
    "fileMode" / Int16ub,
    "union_special" / Int32ub  
)

Point = "Point" / Struct(
    "v" / Int16sb,
    "h" / Int16sb
)
Rect = "Rect" / Struct(
    "top" / Int16sb,
    "left" / Int16sb,
    "bottom" / Int16sb,
    "right" / Int16sb
)
FileInfo = "FileInfo" / Struct(
    "fileType" / String(4), #Int32ub,
    "fileCreator" / String(4), #Int32ub,
    "finderFlags" / Int16ub,
    Point,
    "reservedField" / Int16ub
)
ExtendedFileInfo = "ExtendedFileInfo" / Struct(
    Array(2, "reserved1" / Int16sb),
    "finderDateAdded" / Int32ub, # 4 bytes stores Finder.DateAdded as unix timestamp
    "extendedFinderFlags" / Int16ub,
    "reserved2" / Int16sb,
    "putAwayFolderID" / Int32sb
)

FolderInfo = "FolderInfo" / Struct(
    Rect,
    "finderFlags" / Int16ub,
    Point,
    "reservedField" / Int16ub
)

ExtendedFolderInfo = "ExtendedFolderInfo" / Struct(
    Point,
    "finderDateAdded" / Int32sb,
    "extendedFinderFlags" / Int16ub,
    "reserved2" / Int16sb,
    "putAwayFolderID" / Int32sb
)

HFSPlusCatalogFolder = "HFSPlusCatalogFolder" / Struct(
    "flags" / Int16ub,
    "valence" / Int32ub,
    "folderID" / Int32ub,
    "createDate" / Int32ub,
    "contentModDate" / Int32ub,
    "attributeModDate" / Int32ub,
    "accessDate" / Int32ub,
    "backupDate" / Int32ub,
    HFSPlusBSDInfo,
    FolderInfo,
    ExtendedFolderInfo,
    "textEncoding" / Int32ub,
    "reserved" / Int32ub
)

HFSPlusCatalogFile = "HFSPlusCatalogFile" / Struct(
    "flags" / Int16ub,
    "reserved1" / Int32ub,
    "fileID" / Int32ub,
    "createDate" / Int32ub,
    "contentModDate" / Int32ub,
    "attributeModDate" / Int32ub,
    "accessDate" / Int32ub,
    "backupDate" / Int32ub,
    HFSPlusBSDInfo,
    FileInfo,
    ExtendedFileInfo,
    "textEncoding" / Int32ub,
    "reserved2" / Int32ub,
    "dataFork" / HFSPlusForkData,
    "resourceFork" / HFSPlusForkData
)

HFSPlusCatalogThread = "HFSPlusCatalogThread" / Struct(
    "reserved" / Int16sb,
    "parentID" / Int32ub,
    "HFSUniStr255" / HFSUniStr255,
)

HFSPlusCatalogData = "HFSPlusCatalogData" / Struct(
    "recordType" / Int16ub,
    "data" / Switch(lambda ctx: ctx["recordType"], 
    {
        kHFSPlusFolderRecord : HFSPlusCatalogFolder,
        kHFSPlusFileRecord : HFSPlusCatalogFile,
        kHFSPlusFolderThreadRecord: HFSPlusCatalogThread,
        kHFSPlusFileThreadRecord: HFSPlusCatalogThread
    },
    #default=HFSPlusCatalogFolder #XXX: should not reach
    )
)

HFSPlusExtentKey = "HFSPlusExtentKey" / Struct(
    "keyLength" / Int16ub,
    "forkType" / Int8ub,
    "pad" / Int8ub,
    "fileID" / Int32ub,
    "startBlock" / Int32ub
)

HFSPlusDecmpfs  = "HFSPlusDecmpfs" / Struct(
   "compression_magic" / Int32ul,
   "compression_type" / Int32ul,
   "uncompressed_size" / Int64ul,
)

HFSPlusCmpfRsrcHead = "HFSPlusCmpfRsrcHead" / Struct(
    "headerSize" / Int32ub,
    "totalSize" / Int32ub,
    "dataSize" / Int32ub,
    "flags" / Int32ub
)

HFSPlusCmpfLZVNRsrcHead = "HFSPlusCmpfLZVNRsrcHead" / Struct(
    "headerSize" / Int32ul,
    "chunkOffsets" / Array(lambda ctx:ctx["headerSize"]/4 - 1, Int32ul)
)

HFSPlusCmpfRsrcBlock = "HFSPlusCmpfRsrcBlock" / Struct(
    "offset" / Int32ul,
    "size" / Int32ul
)

HFSPlusCmpfRsrcBlockHead = "HFSPlusCmpfRsrcBlockHead" / Struct(
    "dataSize" / Int32ub,
    "numBlocks" / Int32ul,
    Array(lambda ctx:ctx["numBlocks"], HFSPlusCmpfRsrcBlock)
)

HFSPlusCmpfEnd = "HFSPlusCmpfEnd" / Struct(
    Array(6, "pad" / Int32ub),
    "unk1" / Int16ub,
    "unk2" / Int16ub,
    "unk3" / Int16ub,
    "magic" / Int32ub,
    "flags" / Int32ub,
    "size" / Int64ub,
    "unk4" / Int32ub
)


"""
Journal stuff
"""
JournalInfoBlock = "JournalInfoBlock" / Struct(
    "flags" / Int32ub,
    Array(8, "device_signature" / Int32ub),
    "offset" / Int64ub,
    "size" / Int64ub,
    Array(32, "reserved" / Int32ub)
)

journal_header = "journal_header" / Struct(
    "magic" / Int32ul,
    "endian" / Int32ul,
    "start" / Int64ul,
    "end" / Int64ul,
    "size" / Int64ul,
    "blhdr_size" / Int32ul,
    "checksum" / Int32ul,
    "jhdr_size" / Int32ul
)

block_info = "block_info" / Struct(
    "bnum" / Int64ul,
    "bsize" / Int32ul,
    "next" / Int32ul
)

block_list_header = "block_list_header" / Struct(
    "max_blocks" / Int16ul,
    "num_blocks" / Int16ul,
    "bytes_used" / Int32ul,
    "checksum" / Int8sl,
    "pad" / Int32ub,
    Array(lambda ctx:ctx["num_blocks"], block_info)
)
