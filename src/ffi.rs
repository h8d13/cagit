use std::ffi::c_int;

// emhash8 index node layout is value-type-independent; reused across maps.
#[repr(C)]
pub struct MapIndexNode { pub next: u32, pub slot: u32 }

// offset_map: u64 (pack byte offset) -> u32 (slab index)
#[repr(C)]
pub struct OffsetMapPair { pub first: u64, pub second: u32 }

#[repr(C)]
pub struct OffsetMap {
    pub _index:          *mut MapIndexNode,
    pub _pairs:          *mut OffsetMapPair,
    pub _ctrl:           *mut u8,
    pub _mlf:            u32,
    pub _mask:           u32,
    pub _num_buckets:    u32,
    pub _num_filled:     u32,
    pub _last:           u32,
    pub _etail:          u32,
    pub _pairs_capacity: u32,
}

unsafe extern "C" {
    pub fn dhasht_om_init(m: *mut OffsetMap, bucket: usize);
    pub fn dhasht_om_deinit(m: *mut OffsetMap);
    pub fn dhasht_om_set(m: *mut OffsetMap, key: u64, val: u32) -> c_int;
    pub fn dhasht_om_get(m: *const OffsetMap, key: u64, out: *mut u32) -> c_int;
    pub fn dhasht_om_reserve(m: *mut OffsetMap, n: u64, force: c_int) -> c_int;
}
