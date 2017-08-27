 
'''
Copyright 2011 Jean-Baptiste B'edrune, Jean Sigwald

Using New BSD License:
Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
'''

from __future__ import print_function
from __future__ import unicode_literals
from structs import *

"""
Probably buggy
"""

class BTree(object):
    def __init__(self, file, keyStruct, dataStruct):
        self.file = file
        self.keyStruct = keyStruct
        self.dataStruct = dataStruct
        block0 = self.file.readBlock(0)
        btnode = BTNodeDescriptor.parse(block0)
        assert btnode.kind == kBTHeaderNode
        self.header = BTHeaderRec.parse(block0[BTNodeDescriptor.sizeof():])
        #TODO: do more testing when nodeSize != blockSize
        self.nodeSize = self.header.nodeSize
        self.nodesInBlock = file.blockSize / self.header.nodeSize
        self.blocksForNode = self.header.nodeSize / file.blockSize
        #print (file.blockSize , self.header.nodeSize)
        self.lastRecordNumber = 0
        type, (hdr, maprec) = self.readBtreeNode(0)
        self.maprec = maprec
        self.compare_case_sensitive = self.header.keyCompareType == kHFSBinaryCompare # 0xBC

    def isNodeInUse(self, nodeNumber):
        thisByte = ord(self.maprec[nodeNumber / 8])
        return (thisByte & (1 << (7 - (nodeNumber % 8)))) != 0
    
    def readEmptySpace(self):
        res = ""
        z = 0
        for i in xrange(self.header.totalNodes):
            if not self.isNodeInUse(i):
                z += 1
                res += self.readNode(i)
        assert z == self.header.freeNodes
        return res
    
    #convert construct structure to tuple
    def getComparableKey(self, k):
        raise "implement in subclass"
    
    def compare_operation_insensitive(self, k1, operation, k2):
        '''Case Insensitive compare operation 
           TODO: Fix issues: There are 2 problems-
           1. Nulls (empty strings) end up first in sort, but should be last in HFS implementation
           2. Unicode handling is not addressed (Need to port Apple's FastUnicodeCompare())
        '''
        k1_ci = [(item.lower() if (type(item)==unicode or type(item)==str) else item) for item in k1]
        k2_ci = [(item.lower() if (type(item)==unicode or type(item)==str) else item) for item in k2]
        if operation == '==':
            return k1_ci == k2_ci
        elif operation == '<':
            return k1_ci < k2_ci
        elif operation == '>':
            return k1_ci > k2_ci

    def compareKeys(self, k1, k2):
        k2 = self.getComparableKey(k2) 
        if self.compare_case_sensitive:
            #print ('Comparing k1=' + str(k1) + ' k2=' + str(k2) + ' ' + str(k1 > k2))
            if k1 == k2:
                return 0
            return -1 if k1 < k2 else 1
        else:
            #print ('Comparing k1=' + str(k1) + ' k2=' + str(k2) + ' ' + str(self.compare_operation_insensitive(k1, ">", k2)))
            if self.compare_operation_insensitive(k1, "==", k2):
                return 0
            return -1 if self.compare_operation_insensitive(k1, "<", k2) else 1
    
    def printLeaf(self, key, data):
        print (key, data)

    def readNode(self, nodeNumber):
        node = b""
        for i in xrange(self.blocksForNode):
            node += self.file.readBlock(nodeNumber * self.blocksForNode + i)
        return node
    
    def readBtreeNode(self, nodeNumber):
        self.lastnodeNumber = nodeNumber
        node = memoryview(self.readNode(nodeNumber))
        #node = self.readNode(nodeNumber)
        self.lastbtnode = btnode = BTNodeDescriptor.parse(node)

        if btnode.kind == kBTHeaderNode:
            #XXX
            offsets = Array(btnode.numRecords, "off" / Int16ub).parse(node[-2*btnode.numRecords:])
            hdr = BTHeaderRec.parse(node[BTNodeDescriptor.sizeof():])
            maprec = node[offsets[-3]:]
            return kBTHeaderNode, [hdr, maprec]
        elif btnode.kind == kBTIndexNode:
            recs = []
            offsets = Array(btnode.numRecords, "off" / Int16ub).parse(node[-2*btnode.numRecords:])
            for i in xrange(btnode.numRecords):
                off = offsets[btnode.numRecords-i-1]
                k = self.keyStruct.parse(node[off:])
                off += 2 + k.keyLength
                k.childNode = Int32ub.parse(node[off:off+4]) # ("nodeNumber")
                recs.append(k)
            return kBTIndexNode, recs
        elif btnode.kind == kBTLeafNode:
            recs = []
            offsets = Array(btnode.numRecords, "off" / Int16ub).parse(node[-2*btnode.numRecords:])
            for i in xrange(btnode.numRecords):
                off = offsets[btnode.numRecords-i-1]
                k = self.keyStruct.parse(node[off:])
                off += 2 + k.keyLength
                d = self.dataStruct.parse(node[off:])
                recs.append((k,d))
            return kBTLeafNode, recs
        else:
            raise Exception("Invalid node type " + str(btnode)) 

    def search(self, searchKey, node=None):
        if node == None:
            node = self.header.rootNode
            
        type, stuff = self.readBtreeNode(node)
        
        if type == kBTIndexNode: 
            for i in xrange(len(stuff)):
                if self.compareKeys(searchKey, stuff[i]) < 0:
                    if i > 0:
                        i = i - 1
                    return self.search(searchKey, stuff[i].childNode)
            return self.search(searchKey, stuff[len(stuff)-1].childNode)
        elif type == kBTLeafNode:
            self.lastRecordNumber = 0
            for k,v in stuff:
                res = self.compareKeys(searchKey, k)
                if res == 0:
                    return k, v
                if res < 0:
                    break
                self.lastRecordNumber += 1
        return None, None

    def traverse(self, node=None, count=0, callback=None):
        if node == None:
            node = self.header.rootNode
   
        type, stuff = self.readBtreeNode(node)
        
        if type == kBTIndexNode: 
            for i in xrange(len(stuff)):
                count += self.traverse(stuff[i].childNode, callback=callback)
        elif type == kBTLeafNode:
            for k,v in stuff:
                if callback:
                    callback(k,v)
                else:
                    self.printLeaf(k, v)
                count += 1
        return count
    
    def traverseLeafNodes(self, callback=None):
        nodeNumber = self.header.firstLeafNode
        count = 0
        while nodeNumber != 0:
            _, stuff = self.readBtreeNode(nodeNumber)
            count += len(stuff)
            for k,v in stuff:
                if callback:
                    callback(k,v)
                else:
                    self.printLeaf(k, v)
            nodeNumber = self.lastbtnode.fLink
        return count
    
    #XXX
    def searchMultiple(self, searchKey, filterKeyFunction=lambda x:False):
        self.search(searchKey)
        nodeNumber = self.lastnodeNumber
        recordNumber = self.lastRecordNumber
        kv = []
        while nodeNumber != 0:
            _, stuff = self.readBtreeNode(nodeNumber)
            for k,v in stuff[recordNumber:]:
                if filterKeyFunction(k):
                    kv.append((k,v))
                else:
                    return kv
            nodeNumber = self.lastbtnode.fLink
            recordNumber = 0
        return kv

class CatalogTree(BTree):
    def __init__(self, file):
        super(CatalogTree,self).__init__(file, HFSPlusCatalogKey, HFSPlusCatalogData)
    
    def printLeaf(self, k, d):
        if d.recordType == kHFSPlusFolderRecord or d.recordType == kHFSPlusFileRecord:
            print (getString(k))

    def getComparableKey(self, k2):
        return (k2. parentID, getString(k2))
    
    def searchByCNID(self, cnid):
        threadk, threadd = self.search((cnid, ""))
        return self.search((threadd.data.parentID, getString(threadd.data))) if threadd else (None, None)
    
    def getFolderContents(self, cnid):
        return self.searchMultiple((cnid, ""), lambda k:k.parentID == cnid)
    
    def getRecordFromPath(self, path):
        if not path.startswith("/"):
            return None, None
        if path == "/":
            return self.searchByCNID(kHFSRootFolderID)
        parentId=kHFSRootFolderID
        for p in path.split("/")[1:]:
            if p == "":
                break
            k,v  = self.search((parentId, p))
            if (k,v) == (None, None):
                return None, None

            if v.recordType == kHFSPlusFolderRecord:
                parentId = v.data.folderID
            else:
                break
        return k,v
    
class ExtentsOverflowTree(BTree):
    def __init__(self, file):
        super(ExtentsOverflowTree,self).__init__(file, HFSPlusExtentKey, HFSPlusExtentRecord)
    
    def getComparableKey(self, k2):
        return (k2.fileID, k2.forkType, k2.startBlock)
    
    def searchExtents(self, fileID, forkType, startBlock):
        return self.search((fileID, forkType, startBlock))

class AttributesTree(BTree):
    def __init__(self, file):
        super(AttributesTree,self).__init__(file, HFSPlusAttrKey, HFSPlusAttrData)
    
    def printLeaf(self, k, d):
        print (k.fileID, getString(k), d.data.encode("hex"))
    
    def getComparableKey(self, k2):
        return (k2.fileID, getString(k2))
    
    def searchXattr(self, fileID, name):
        k,v = self.search((fileID, name))
        return v.data if v else None
    
    def getAllXattrs(self, fileID):
        res = {}
        for k,v in self.searchMultiple((fileID, ""), lambda k:k.fileID == fileID):
            res[getString(k)] = v.data
        return res
