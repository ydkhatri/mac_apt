# -*- coding: utf-8 -*-
'''The virtual file system.'''

from __future__ import unicode_literals

import os

class VirtualFileSystem(object):
    '''
        This class implements the file system functions that the library relies on.
        In this base class, they default to the local OS ones such as os.path.exits(),
        os.listdir() and a few others. To make them do something else, inherit the 
        class and override its methods.
    '''
    def __init__(self, virtual_file_class):
        super(VirtualFileSystem, self).__init__()
        self.virtual_file_class = virtual_file_class
    
    def path_exists(self, path):
        '''Return True if file/folder specified by 'path' exists'''
        return os.path.exists(path)
    
    def listdir(self, path):
        '''Return a list of all files/folders contained at given path'''
        return os.listdir(path)

    def is_dir(self, path):
        '''Return True if path is a directory'''
        return os.path.isdir(path)

    def path_join(self, path, *paths):
        '''Return the joined path, similar to os.path.join(path, *paths)'''
        return os.path.join(path, *paths)

    def get_virtual_file(self, path, filetype=''):
        '''Return a VirtualFile object'''
        return self.virtual_file_class(path, filetype)
