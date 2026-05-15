use std::mem::MaybeUninit;
use crate::ffi::{self, ShaMap as Raw};

pub struct ShaMap { inner: Raw }
unsafe impl Send for ShaMap {}
unsafe impl Sync for ShaMap {}

impl ShaMap {
    pub fn new(cap: usize) -> Self {
        unsafe {
            let mut m = MaybeUninit::<Raw>::uninit();
            ffi::dhasht_sm_init(m.as_mut_ptr(), cap);
            ShaMap { inner: m.assume_init() }
        }
    }
    pub fn set(&mut self, k: u64, v: u64) {
        unsafe { ffi::dhasht_sm_set(&mut self.inner, k, v); }
    }
    pub fn get(&self, k: u64) -> Option<u64> {
        let mut out = 0u64;
        if unsafe { ffi::dhasht_sm_get(&self.inner, k, &mut out) } != 0 { Some(out) } else { None }
    }
    pub fn contains(&self, k: u64) -> bool {
        unsafe { ffi::dhasht_sm_contains(&self.inner, k) != 0 }
    }
    pub fn reserve(&mut self, n: u64) {
        unsafe { ffi::dhasht_sm_reserve(&mut self.inner, n, 0); }
    }
    pub fn len(&self) -> usize { self.inner._num_filled as usize }
}

impl Drop for ShaMap {
    fn drop(&mut self) { unsafe { ffi::dhasht_sm_deinit(&mut self.inner); } }
}

pub fn sha1_key(sha: &[u8; 20]) -> u64 {
    let mut h = 0x9e3779b97f4a7c15u64;
    for chunk in sha.chunks(8) {
        let mut v = 0u64;
        for (i, &b) in chunk.iter().enumerate() { v |= (b as u64) << (i * 8); }
        h ^= v;
        h = h.wrapping_mul(0x517cc1b727220a95);
        h ^= h >> 33;
    }
    h
}
