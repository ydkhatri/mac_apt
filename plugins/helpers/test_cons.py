from construct import *

HFSPlusCatalogKey = "HFSPlusCatalogKey" / Struct(
    "keyLength" / Int16ub,
    "parentID" / Int32ub,
    "HFSUniStr255" / HFSUniStr255
)

