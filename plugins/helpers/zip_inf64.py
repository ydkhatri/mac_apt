"""
This code is from the project:
https://codeberg.org/miurahr/zipfile-inflate64

A slight modification has been made to fix a bug.

Copyright (C) 2022 Hiroshi Miura

"""
import inflate64
import functools
import zipfile

from typing import Any, Callable, Dict

#from zipfile_inflate64.version import __version__
# Has the side effect of applying patches

__copyright__ = 'Copyright (C) 2022 Hiroshi Miura'

class Decompressor:
    def __init__(self):
        self._decompressor = inflate64.Inflater()

    def decompress(self, data):
        return self._decompressor.inflate(data)

    @property
    def eof(self):
        return self._decompressor.eof

class Compressor:
    def __init__(self):
        self._eof = False
        self._compressor = inflate64.Deflater()

    def compress(self, data):
        return self._compressor.deflate(data)

    def flush(self):
        self._eof = True
        return self._compressor.flush()

    @property
    def eof(self):
        return self._eof

class patch:  # noqa: N801
    originals: Dict[str, Any] = {}

    def __init__(self, host: Any, name: str):
        self.host = host
        self.name = name

    def __call__(self, func: Callable):
        original = getattr(self.host, self.name)
        self.originals[self.name] = original

        functools.update_wrapper(func, original)

        setattr(self.host, self.name, func)

        return func


# Since none of the public API of zipfile needs to be patched, we don't have to worry about
# ensuring that this is prior to other code importing things from zipfile.

# This is already defined in zipfile.compressor_names, for error-handling purposes
zipfile.ZIP_DEFLATED64 = 9  # type: ignore[attr-defined]

@patch(zipfile, '_check_compression')
def deflate64_check_compression(compression: int) -> None:
    if compression == zipfile.ZIP_DEFLATED64:  # type: ignore[attr-defined]
        pass
    else:
        patch.originals['_check_compression'](compression)

@patch(zipfile, '_get_compressor')
def deflate64_get_compressor(compress_type: int, compresslevel=None):
    if compress_type == zipfile.ZIP_DEFLATED64:  # type: ignore[attr-defined]
        return Compressor()
    else:
        return patch.originals['_get_compressor'](compress_type, compresslevel)

@patch(zipfile, '_get_decompressor')
def deflate64_get_decompressor(compress_type: int):
    if compress_type == zipfile.ZIP_DEFLATED64:  # type: ignore[attr-defined]
        return Decompressor()
    else:
        return patch.originals['_get_decompressor'](compress_type)

@patch(zipfile.ZipExtFile, '__init__')
def deflate64_ZipExtFile_init(self, *args, **kwarg):  # noqa: N802
    patch.originals['__init__'](self, *args, **kwarg)
    if self._compress_type == zipfile.ZIP_DEFLATED64:
        self.MIN_READ_SIZE = 64 << 10

# isort: skip_file

from zipfile import (
    BadZipFile,
    BadZipfile,
    error,
    ZIP_STORED,
    ZIP_DEFLATED,
    ZIP_BZIP2,
    ZIP_LZMA,
    is_zipfile,
    ZipInfo,
    ZipFile,
    PyZipFile,
    LargeZipFile,
    Path,
)

__all__ = [
    'BadZipFile',
    'BadZipfile',
    'error',
    'ZIP_STORED',
    'ZIP_DEFLATED',
    'ZIP_BZIP2',
    'ZIP_LZMA',
    'ZIP_DEFLATED64',
    'is_zipfile',
    'ZipInfo',
    'ZipFile',
    'PyZipFile',
    'LargeZipFile',
    'Path',
    #'__version__',
    '__copyright__',
]
