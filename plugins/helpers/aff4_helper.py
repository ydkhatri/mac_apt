'''
   Copyright (c) 2020 Yogesh Khatri 

   This file is part of mac_apt (macOS Artifact Parsing Tool).
   Usage or distribution of this software/code is subject to the 
   terms of the MIT License.
   
'''

from pyaff4 import container
import hashlib
from pyaff4 import lexicon
from pyaff4 import rdfvalue

class EvidenceImageStream():
    def __init__(self, path_to_aff4_file):
        self.image_path = path_to_aff4_file
        self.size = 0
        self.position = 0
        self.init()
    
    def init(self):
        self.urn = rdfvalue.URN.FromFileName(self.image_path)
        self.c = container.Container.openURNtoContainer(self.urn)
        self.size = int(self.getMetadata(self.c, 'size')[0]) # aff4:size
        self.mapStream = self.c.image.dataStream

    def getMetadata(self, c, item_name):
        "Returns list or None"
        try:
            return c.resolver.Get(lexicon.AFF4_TYPE, str(c.image.urn), c.lexicon.of(item_name))
        except Exception as ex:
            print (ex)
        return None
            
    def get_sha1_hash(self):
        '''Calculate SHA1 of evidence image'''
        hasher = hashlib.sha1()
        self.seek(0)
        unit = 50*1024*1024  # 50MiB
        data = self.read(unit)
        pos = self.tell()

        while data:
            hasher.update(data)
            data = img.read(unit)
            if data:
                pos += len(data)
                print(f'Read {pos/(1024*1024)} MB, {pos} bytes')
        return hasher.hexdigest()

    def read(self, length=1024*1024):
        self.mapStream.SeekRead(self.position)
        buf = self.mapStream.Read(length)
        if buf is None:
            buf = b''
        buf_len = len(buf)
        if buf_len == length:
            self.position += buf_len
            return buf
        elif buf_len < length:
            #check if EOF reached
            if self.position + length > self.size:
                buf += b'\0'*(self.size - self.position - buf_len)
                self.position = self.size
                return buf
            else:
                #EOF not reached, buf gave less data, fill with zeroes
                buf += b'\0'*(length - buf_len)
                self.position += length
                return buf

    def seek(self, offset):
        self.position = offset
        if offset > self.size:
            self.position = self.size

    def tell(self):
        return self.position

    def close(self):
        pass