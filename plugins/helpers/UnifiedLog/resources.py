# -*- coding: utf-8 -*-
'''Several resource objects.'''

from __future__ import unicode_literals

import plugins.helpers.UnifiedLog.logger as logger


class Catalog(object):
    def __init__(self):
        super(Catalog, self).__init__()
        self.ContinuousTime = 0
        self.FileObjects = []
        self.Strings = ''
        self.ProcInfos = []
        self.ChunkMetaInfo = []

    def GetProcInfoById(self, id):
        for proc_info in self.ProcInfos:
            if proc_info.id == id:
                return proc_info
        # Not found!
        logger.error("ProcInfo with id={} not found".format(id))
        return None


class ChunkMeta(object):
    def __init__(self, continuous_time_first, continuous_time_last, chunk_len, compression_alg):
        super(ChunkMeta, self).__init__()
        self.continuous_time_first = continuous_time_first
        self.continuous_time_last = continuous_time_last
        self.length_of_chunk = chunk_len # Chunk to follow
        self.compression_alg = compression_alg # 0x100 (256) = lz4
        self.ProcInfo_Ids = []
        self.StringIndexes = []
        self.ProcInfos = {}   # key = pid
        self.Strings = {} # key = string offset


class ExtraFileReference(object):
    '''Extra file reference object. Some ProcInfos have messages in more than one uuidtext file'''
    def __init__(self, data_size, uuid_file_index, u2, v_offset, id):
        super(ExtraFileReference, self).__init__()
        self.data_size = data_size # data size
        self.uuid_file_index = uuid_file_index
        self.unknown2 = u2
        self.v_offset = v_offset # virtual offset
        self.id = id


class ProcInfo(object):
    def __init__(self, id, flags, uuid_file_index, dsc_file_index, proc_id1, proc_id2, pid, euid, u6, num_extra_uuid_refs, u8, num_subsys_cat_elements, u9, extra_file_refs):
        super(ProcInfo, self).__init__()
        self.id = id
        self.flags = flags
        self.uuid_file_index = uuid_file_index
        self.dsc_file_index = dsc_file_index
        self.proc_id1 = proc_id1 # usually same as pid (but not always!)
        self.proc_id2 = proc_id2 # secondary pid like unique value for getting unique entries when 2 proc_info have same pid
        self.pid = pid
        self.euid = euid
        self.unk_val6 = u6
        self.num_extra_uuid_refs = num_extra_uuid_refs
        self.unk_val8 = u8
        self.num_subsys_cat_elements = num_subsys_cat_elements
        self.unk_val9 = u9

        self.items = {}    #  key = item_id, val = (subsystem, category)
        self.extra_file_refs = extra_file_refs # In addition to self.uuid_file_index

    def GetSubSystemAndCategory(self, sc_id):
        sc = self.items.get(sc_id, None)
        if sc:
            return (sc[0], sc[1])
        # Not found!
        logger.error("Could not find subsystem_category_id={}".format(sc_id))
        return ('','')


class Timesync(object):
    def __init__(self, header):
        super(Timesync, self).__init__()
        self.header = header
        self.items = []
        #self.items_dict = {} # unused , use later for optimization


class TimesyncHeader(object):

    def __init__(self, sig, unk1, boot_uuid, ts_numer, ts_denom, ts, bias, is_dst):
        super(TimesyncHeader, self).__init__()
        self.signature = sig
        self.unknown1  = unk1
        self.boot_uuid = boot_uuid
        self.ts_numerator   = ts_numer
        self.ts_denominator = ts_denom
        self.time_stamp = ts
        self.bias_minutes   = bias
        self.is_dst = (is_dst == 1) # 1 = DST


class TimesyncItem(object):
    '''Timesync item object'''
    def __init__(self, ts_unknown, cont_time, ts, bias, is_dst):
        super(TimesyncItem, self).__init__()
        #self.signature = sig # "Ts  " = sig?
        self.ts_unknown = ts_unknown
        self.continuousTime = cont_time
        self.time_stamp = ts
        self.bias_minutes = bias
        self.is_dst = (is_dst == 1) # 1 = DST
