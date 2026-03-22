"""
Copyright (c) 2026 Andrea Lazzarotto

UDIF compressed DMG read support (AppleDiskImage). Most of the logic here is a
Python rewrite of the dmgwiz project, which extracts filesystem data from DMG
files (chunk types, koly/BLKX layout, decompression, plist handling):
https://github.com/citruz/dmgwiz/

Semantics match dmgwiz: ``extract_all`` concatenates each plist ``blkx``
resource in order, each produced by the same steps as ``extract_partition``
(padding between sector runs, then decompress). Random ``read`` serves bytes
from that concatenated raw stream, while ``size`` is the total length of
that stream.

Limitations in this port:
- ADC-compressed chunks are not supported
- Encrypted DMGs are not supported

The original dmgwiz source code is licensed under the MIT License:

Copyright (c) 2020 Felix Seele

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

from __future__ import annotations

import bisect
import bz2
import io
import logging
import plistlib
import struct
from collections import OrderedDict
from typing import BinaryIO, List, Optional, Tuple
import zlib

import liblzfse

log = logging.getLogger("MAIN.HELPERS.APPLE_DISK_IMAGE")

SECTOR_SIZE = 512

# Chunk type constants (UDIF / dmgwiz)
CHUNK_ZERO = 0x00000000
CHUNK_RAW = 0x00000001
CHUNK_IGNORE = 0x00000002
CHUNK_COMMENT = 0x7FFFFFFE
CHUNK_ADC = 0x80000004
CHUNK_ZLIB = 0x80000005
CHUNK_BZLIB = 0x80000006
CHUNK_LZFSE = 0x80000007
CHUNK_TERM = 0xFFFFFFFF


class AppleDiskImageError(Exception):
    pass


def _unpack_koly(data: bytes) -> dict:
    """
    Parse koly trailer. Same field order as dmgwiz KolyHeader after the signature.
    Supports either 4-byte ASCII 'koly' (on-disk UDIF) or 16-byte bincode-style chars (dmgwiz).
    """
    if len(data) != 512:
        raise AppleDiskImageError("koly block must be 512 bytes")
    if data[0:4] == b"koly":
        off = 4
    else:
        quads = struct.unpack_from(">IIII", data, 0)
        if "".join(chr(c) for c in quads) != "koly":
            raise AppleDiskImageError("invalid koly signature")
        off = 16
    version, header_size, flags = struct.unpack_from(">III", data, off)
    off += 12
    running_df, data_fork_off, data_fork_len, rsrc_off, rsrc_len = struct.unpack_from(
        ">QQQQQ", data, off
    )
    off += 40
    seg_num, seg_cnt = struct.unpack_from(">II", data, off)
    off += 8
    seg_id = struct.unpack_from(">IIII", data, off)
    off += 16
    df_ck_type, df_ck_size = struct.unpack_from(">II", data, off)
    off += 8
    struct.unpack_from(">32I", data, off)
    off += 128
    xml_off, xml_len = struct.unpack_from(">QQ", data, off)
    off += 16
    struct.unpack_from(">QQQQQQQQQQQQQQQ", data, off)
    off += 120
    struct.unpack_from(">II", data, off)
    off += 8
    struct.unpack_from(">32I", data, off)
    off += 128
    (image_variant,) = struct.unpack_from(">I", data, off)
    off += 4
    (sector_count,) = struct.unpack_from(">Q", data, off)
    off += 8
    struct.unpack_from(">III", data, off)
    return {
        "signature": "koly",
        "version": version,
        "header_size": header_size,
        "flags": flags,
        "data_fork_offset": data_fork_off,
        "data_fork_length": data_fork_len,
        "xml_offset": xml_off,
        "xml_length": xml_len,
        "sector_count": sector_count,
    }


def _unpack_blkx_table(data: bytes) -> Tuple[dict, List[dict]]:
    """
    Parse BLKXTable + chunks. Same layout as dmgwiz BLKXTable::from after signature.
    Supports 4-byte 'mish' or 16-byte bincode-style signature.
    """
    if len(data) < 4:
        raise AppleDiskImageError("BLKX table too short")
    if data[0:4] == b"mish":
        off = 4
    else:
        quads = struct.unpack_from(">IIII", data, 0)
        if "".join(chr(c) for c in quads) != "mish":
            raise AppleDiskImageError("invalid mish signature")
        off = 16
    (version,) = struct.unpack_from(">I", data, off)
    off += 4
    sector_number, sector_count, table_data_offset = struct.unpack_from(
        ">QQQ", data, off
    )
    off += 24
    buffers_needed, block_descriptors = struct.unpack_from(">II", data, off)
    off += 8
    reserved = struct.unpack_from(">IIIIII", data, off)
    off += 24
    ck_type, ck_size = struct.unpack_from(">II", data, off)
    off += 8
    struct.unpack_from(">32I", data, off)
    off += 128
    (num_chunks,) = struct.unpack_from(">I", data, off)
    off += 4
    header = {
        "signature": "mish",
        "version": version,
        "sector_number": sector_number,
        "sector_count": sector_count,
        "data_offset": table_data_offset,
        "buffers_needed": buffers_needed,
        "block_descriptors": block_descriptors,
        "reserved": reserved,
        "checksum_type": ck_type,
        "checksum_size": ck_size,
        "num_chunks": num_chunks,
    }
    chunks = []
    for _ in range(num_chunks):
        if off + 40 > len(data):
            raise AppleDiskImageError("truncated BLKX chunk table")
        ctype, comment, sn, sc, coff, clen = struct.unpack_from(">IIQQQQ", data, off)
        off += 40
        chunks.append(
            {
                "type": ctype,
                "comment": comment,
                "sector_number": sn,
                "sector_count": sc,
                "compressed_offset": coff,
                "compressed_length": clen,
            }
        )
    return header, chunks


def _find_valid_xml_end(data: bytes) -> int:
    """Trim trailing garbage after plist (dmgwiz find_valid_xml_offset semantics, simplified)."""
    end = data.rfind(b"</plist>")
    if end < 0:
        raise AppleDiskImageError("no closing </plist> in DMG XML resource")
    return end + len(b"</plist>")


def _decompress_chunk(
    chunk_type: int, compressed: bytes, out_len: int, partition_num: int, chunk_num: int
) -> bytes:
    if chunk_type in (CHUNK_IGNORE, CHUNK_ZERO, CHUNK_COMMENT):
        if out_len < 0:
            raise AppleDiskImageError("invalid output length")
        return b"\x00" * out_len
    if chunk_type == CHUNK_RAW:
        if len(compressed) != out_len:
            raise AppleDiskImageError(
                f"raw chunk size mismatch (partition={partition_num} chunk={chunk_num})"
            )
        return compressed
    if chunk_type == CHUNK_ADC:
        raise AppleDiskImageError(
            "ADC-compressed DMG chunks are not supported (partition=%d chunk=%d)"
            % (partition_num, chunk_num)
        )
    if chunk_type == CHUNK_ZLIB:
        try:
            out = zlib.decompress(compressed)
        except zlib.error as e:
            raise AppleDiskImageError("zlib decompress failed: %s" % e) from e
        if len(out) != out_len:
            raise AppleDiskImageError(
                f"zlib length mismatch (partition={partition_num} chunk={chunk_num})"
            )
        return out
    if chunk_type == CHUNK_BZLIB:
        try:
            out = bz2.decompress(compressed)
        except OSError as e:
            raise AppleDiskImageError("bzip2 decompress failed: %s" % e) from e
        if len(out) != out_len:
            raise AppleDiskImageError(
                f"bzip2 length mismatch (partition={partition_num} chunk={chunk_num})"
            )
        return out
    if chunk_type == CHUNK_LZFSE:
        try:
            out = liblzfse.decompress(compressed)
        except Exception as e:
            raise AppleDiskImageError("lzfse decompress failed: %s" % e) from e
        if len(out) != out_len:
            raise AppleDiskImageError(
                f"lzfse length mismatch (partition={partition_num} chunk={chunk_num})"
            )
        return out
    raise AppleDiskImageError("unknown chunk type %#010x" % chunk_type)


class AppleDiskImage:
    """
    Exposes the same raw byte stream dmgwiz would write with ``extract_all``:
    partition 0 output, then partition 1, … (plist ``blkx`` order).
    """

    def __init__(self):
        self._fp: Optional[BinaryIO] = None
        self._path: Optional[str] = None
        self.size = 0
        self._data_fork_offset = 0
        self._koly: dict = {}
        self._partitions: List[Tuple[dict, List[dict], str]] = []
        # _partition_byte_offsets[i] = start of partition i in concatenated stream; len = n+1
        self._partition_byte_offsets: List[int] = []
        # Per-partition non-overlapping spans: (byte_start, byte_end_exclusive, chunk_index_or_-1).
        # chunk_index -1 = zero padding (dmgwiz extract_partition padding before next sector_number).
        self._part_spans: List[List[Tuple[int, int, int]]] = []
        self._part_span_starts: List[List[int]] = []
        self._chunk_cache: OrderedDict[Tuple[int, int], bytes] = OrderedDict()
        self._chunk_cache_max = 64

    def __del__(self):
        self.close()

    def close(self):
        if self._fp:
            self._fp.close()
            self._fp = None

    @staticmethod
    def _is_udif_trailer(path: str) -> bool:
        try:
            with open(path, "rb") as f:
                f.seek(-512, io.SEEK_END)
                block = f.read(512)
            if len(block) != 512:
                return False
            k = _unpack_koly(block)
            return k["signature"] == "koly" and k["version"] == 4
        except (OSError, AppleDiskImageError, struct.error):
            return False

    @staticmethod
    def is_compressed(path: str) -> bool:
        return AppleDiskImage._is_udif_trailer(path)

    def open(self, filepath: str) -> None:
        self.close()
        self._path = filepath
        self._fp = open(filepath, "rb")
        fp = self._fp
        fp.seek(-512, io.SEEK_END)
        koly_raw = fp.read(512)
        if len(koly_raw) != 512:
            raise AppleDiskImageError("file too small for koly trailer")
        try:
            self._koly = _unpack_koly(koly_raw)
        except struct.error as e:
            raise AppleDiskImageError("invalid koly structure") from e
        if self._koly["signature"] != "koly":
            raise AppleDiskImageError(
                "not a UDIF koly trailer (signature=%r)" % self._koly["signature"]
            )
        if self._koly["data_fork_length"] == 0:
            raise AppleDiskImageError("data fork length is 0")
        self._data_fork_offset = self._koly["data_fork_offset"]
        xml_off = self._koly["xml_offset"]
        xml_len = self._koly["xml_length"]
        fp.seek(xml_off)
        xml_blob = fp.read(xml_len)
        if len(xml_blob) != xml_len:
            raise AppleDiskImageError("short read on plist XML")
        valid_len = _find_valid_xml_end(xml_blob)
        try:
            plist = plistlib.loads(xml_blob[:valid_len])
        except Exception as e:
            raise AppleDiskImageError("plist parse failed: %s" % e) from e
        try:
            blkx_arr = plist["resource-fork"]["blkx"]
        except (KeyError, TypeError) as e:
            raise AppleDiskImageError(
                "invalid plist structure (missing resource-fork/blkx)"
            ) from e
        self._partitions = []
        for part in blkx_arr:
            if not isinstance(part, dict):
                continue
            raw = part.get("Data")
            if raw is None:
                continue
            if not isinstance(raw, bytes):
                continue
            try:
                hdr, chunks = _unpack_blkx_table(raw)
            except (struct.error, AppleDiskImageError) as e:
                raise AppleDiskImageError("invalid BLKX table: %s" % e) from e
            if hdr["signature"] != "mish":
                raise AppleDiskImageError(
                    "invalid BLKX signature %r" % hdr["signature"]
                )
            name = (part.get("Name") or part.get("CFName") or "").strip()
            self._partitions.append((hdr, chunks, name))

        if not self._partitions:
            raise AppleDiskImageError("no blkx resources in plist")

        self._partition_byte_offsets = [0]
        self._part_spans = []
        self._part_span_starts = []
        for pi in range(len(self._partitions)):
            total, spans = self._build_partition_spans(pi)
            self._part_spans.append(spans)
            self._part_span_starts.append([s[0] for s in spans])
            self._partition_byte_offsets.append(
                self._partition_byte_offsets[-1] + total
            )
        self.size = self._partition_byte_offsets[-1]
        log.debug(
            "AppleDiskImage extract_all-equivalent size=%s bytes, blkx_resources=%d",
            self.size,
            len(self._partitions),
        )

    def _build_partition_spans(self, pi: int) -> Tuple[int, List[Tuple[int, int, int]]]:
        """
        Single pass: dmgwiz extract_partition byte layout as contiguous spans.
        Returns (total_bytes, spans). Spans are (start, end, ci) with ci=-1 for padding.
        """
        _hdr, chunks, _ = self._partitions[pi]
        stream_pos = 0
        sectors_written = 0
        spans: List[Tuple[int, int, int]] = []
        for ci, ch in enumerate(chunks):
            if ch["type"] == CHUNK_TERM:
                break
            sn = ch["sector_number"]
            sc = ch["sector_count"]
            if sn < sectors_written:
                raise AppleDiskImageError(
                    "invalid sector number %s (partition=%s chunk=%s)" % (sn, pi, ci)
                )
            if sn > sectors_written:
                pad_len = (sn - sectors_written) * SECTOR_SIZE
                if pad_len:
                    pad_end = stream_pos + pad_len
                    spans.append((stream_pos, pad_end, -1))
                    stream_pos = pad_end
            out_len = int(sc) * SECTOR_SIZE
            data_end = stream_pos + out_len
            spans.append((stream_pos, data_end, ci))
            stream_pos = data_end
            sectors_written += sc
        return stream_pos, spans

    def _load_chunk(self, pi: int, ci: int) -> bytes:
        key = (pi, ci)
        if key in self._chunk_cache:
            self._chunk_cache.move_to_end(key)
            return self._chunk_cache[key]
        hdr, chunks, _ = self._partitions[pi]
        ch = chunks[ci]
        ctype = ch["type"]
        if ctype == CHUNK_TERM:
            return b""
        out_len = int(ch["sector_count"]) * SECTOR_SIZE
        in_len = int(ch["compressed_length"])
        abs_off = (
            self._data_fork_offset
            + int(hdr["data_offset"])
            + int(ch["compressed_offset"])
        )
        self._fp.seek(abs_off)
        compressed = self._fp.read(in_len)
        if len(compressed) != in_len:
            raise AppleDiskImageError("short read on compressed chunk data")
        out = _decompress_chunk(ctype, compressed, out_len, pi, ci)
        if len(out) <= 16 * 1024 * 1024:
            self._chunk_cache[key] = out
            self._chunk_cache.move_to_end(key)
            while len(self._chunk_cache) > self._chunk_cache_max:
                self._chunk_cache.popitem(last=False)
        return out

    def _read_partition_slice(self, pi: int, start: int, length: int) -> bytes:
        """Bytes [start, start+length) within dmgwiz ``extract_partition(pi)`` output only."""
        if length <= 0:
            return b""
        total = self._partition_byte_offsets[pi + 1] - self._partition_byte_offsets[pi]
        if start < 0 or start >= total:
            return b"\x00" * length
        target_end = min(start + length, total)
        length = target_end - start
        spans = self._part_spans[pi]
        span_starts = self._part_span_starts[pi]
        out = bytearray(length)  # zero-filled; padding spans need no explicit writes
        if not spans:
            return bytes(out)
        # First span overlapping [start, target_end): bisect on span starts, then skip
        # spans that end at or before start (e.g. start on next span's first byte).
        i = bisect.bisect_right(span_starts, start) - 1
        if i < 0:
            i = 0
        while i < len(spans) and spans[i][1] <= start:
            i += 1
        while i < len(spans) and spans[i][0] < target_end:
            a, b, ci = spans[i]
            overlap_lo = max(a, start)
            overlap_hi = min(b, target_end)
            if overlap_hi > overlap_lo and ci >= 0:
                chunk_data = self._load_chunk(pi, ci)
                out_len = b - a
                if len(chunk_data) != out_len:
                    raise AppleDiskImageError("chunk length mismatch")
                src_a = overlap_lo - a
                src_b = overlap_hi - a
                dst_a = overlap_lo - start
                out[dst_a : dst_a + (src_b - src_a)] = chunk_data[src_a:src_b]
            i += 1
        return bytes(out)

    def read(self, offset: int, size: int) -> bytes:
        if self._fp is None:
            raise AppleDiskImageError("image not open")
        if offset < 0 or size < 0:
            raise ValueError("invalid offset/size")
        if offset >= self.size or size == 0:
            return b""
        end = min(offset + size, self.size)
        size = end - offset
        result = bytearray(size)
        pos = 0
        offs = self._partition_byte_offsets
        while pos < size:
            g = offset + pos
            pi = bisect.bisect_right(offs, g) - 1
            base = self._partition_byte_offsets[pi]
            local = g - base
            part_end = self._partition_byte_offsets[pi + 1]
            take = min(size - pos, part_end - g)
            result[pos : pos + take] = self._read_partition_slice(pi, local, take)
            pos += take
        return bytes(result)
