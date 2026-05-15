use std::ffi::c_int;

#[repr(C)]
pub struct ShaMapIndex { pub next: u32, pub slot: u32 }
#[repr(C)]
pub struct ShaMapPair  { pub first: u64, pub second: u64 }

#[repr(C)]
pub struct ShaMap {
    pub _index:          *mut ShaMapIndex,
    pub _pairs:          *mut ShaMapPair,
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
    pub fn dhasht_sm_init(m: *mut ShaMap, bucket: usize);
    pub fn dhasht_sm_deinit(m: *mut ShaMap);
    pub fn dhasht_sm_set(m: *mut ShaMap, key: u64, val: u64) -> c_int;
    pub fn dhasht_sm_get(m: *const ShaMap, key: u64, out: *mut u64) -> c_int;
    pub fn dhasht_sm_contains(m: *const ShaMap, key: u64) -> c_int;
    pub fn dhasht_sm_reserve(m: *mut ShaMap, n: u64, force: c_int) -> c_int;
}

// offset_map: u64 (pack byte offset) -> u32 (slab index)
#[repr(C)]
pub struct OffsetMapPair { pub first: u64, pub second: u32 }

#[repr(C)]
pub struct OffsetMap {
    pub _index:          *mut ShaMapIndex,  // index node layout is type-independent
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
