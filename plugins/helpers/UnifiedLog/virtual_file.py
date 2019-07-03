# -*- coding: utf-8 -*-
'''The virtual file object.'''

from __future__ import unicode_literals

import os

import plugins.helpers.UnifiedLog.logger as logger

class VirtualFile(object):
    '''
        This is a virtual file object. Its purpose is to enable the same parsing code to be used
        regardless of whether your file is local or in-memory or remote accessed via your custom
        API. This base implementation operates on local files. You can inherit and override these
        functions to implement accessing files or other data stores.
    '''
    def __init__(self, path, filetype=''):
        super(VirtualFile, self).__init__()
        self.path = path
        self.filename = os.path.basename(path)
        self.file_type = filetype
        self.file_pointer = None # This will be set to file or file-like object on successful open
        self.is_valid = True     # Set for corrupted or missing files
        self.file_not_found = False

    def open(self, mode='rb'):
        '''Opens a file for reading/writing, returns file pointer or None'''
        try:
            logger.debug('Trying to read {} file {}'.format(self.file_type, self.path))
            self.file_pointer = open(self.path, mode)
            return self.file_pointer
        except Exception as ex:
            if str(ex).find('No such file') == -1:
                logger.exception('Failed to open file {}'.format(self.path))
            else:
                logger.error('Failed to open as file not found {}'.format(self.path))
                self.file_not_found = True
            self.is_valid = False
        return None

    def get_file_size(self):
        '''Returns file logical size. Must be called after file is opened'''
        if not self.is_valid: 
            return 0
        if not self.file_pointer:
            raise ValueError('File pointer was invalid. File must be opened before calling get_file_size()')
        original_pos = self.file_pointer.tell()
        self.file_pointer.seek(0, 2) # seek to end
        size = self.file_pointer.tell()
        self.file_pointer.seek(original_pos)
        return size

    def close(self):
        if self.file_pointer:
            self.file_pointer.close()
