use std::mem::MaybeUninit;
use crate::ffi::{self, OffsetMap as Raw};

pub struct OffsetMap { inner: Raw }
unsafe impl Send for OffsetMap {}
unsafe impl Sync for OffsetMap {}

impl OffsetMap {
    pub fn new(cap: usize) -> Self {
        unsafe {
            let mut m = MaybeUninit::<Raw>::uninit();
            ffi::dhasht_om_init(m.as_mut_ptr(), cap);
            OffsetMap { inner: m.assume_init() }
        }
    }
    pub fn set(&mut self, k: u64, v: u32) {
        unsafe { ffi::dhasht_om_set(&mut self.inner, k, v); }
    }
    pub fn get(&self, k: u64) -> Option<u32> {
        let mut out = 0u32;
        if unsafe { ffi::dhasht_om_get(&self.inner, k, &mut out) } != 0 { Some(out) } else { None }
    }
    pub fn reserve(&mut self, n: u64) {
        unsafe { ffi::dhasht_om_reserve(&mut self.inner, n, 0); }
    }
}

impl Drop for OffsetMap {
    fn drop(&mut self) { unsafe { ffi::dhasht_om_deinit(&mut self.inner); } }
}
