use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::sha_map::{sha1_key, ShaMap};

const IDX_MAGIC: [u8; 4] = [0xff, 0x74, 0x4f, 0x63];
const IDX_V2:    [u8; 4] = [0x00, 0x00, 0x00, 0x02];

// value layout: top 8 bits = pack_id, low 56 bits = byte offset in .pack file
// supports 255 pack files and offsets up to 72 PB
fn encode(pack_id: u8, offset: u64) -> u64 {
    ((pack_id as u64) << 56) | (offset & 0x00ff_ffff_ffff_ffff)
}

fn decode(v: u64) -> (u8, u64) {
    ((v >> 56) as u8, v & 0x00ff_ffff_ffff_ffff)
}

pub struct PackIndex {
    pub map: ShaMap,
}

impl PackIndex {
    /// Load all .idx files from `<git_dir>/objects/pack/` into a single ShaMap.
    pub fn load(git_dir: &Path) -> io::Result<Self> {
        Ok(Self::load_with_paths(git_dir)?.0)
    }

    /// Like `load`, but also returns the ordered list of .pack paths (index = pack_id).
    pub fn load_with_paths(git_dir: &Path) -> io::Result<(Self, Vec<PathBuf>)> {
        let pack_dir = git_dir.join("objects/pack");
        let mut map = ShaMap::new(4096);
        let mut pack_id: u8 = 0;
        let mut pack_paths: Vec<PathBuf> = Vec::new();

        let mut idx_paths: Vec<PathBuf> = match fs::read_dir(&pack_dir) {
            Ok(rd) => rd.filter_map(|e| e.ok()).map(|e| e.path())
                        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("idx"))
                        .collect(),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(e),
        };
        idx_paths.sort();

        for idx_path in idx_paths {
            load_idx(&idx_path, pack_id, &mut map)?;
            pack_paths.push(idx_path.with_extension("pack"));
            pack_id = pack_id.checked_add(1).ok_or_else(|| {
                io::Error::new(io::ErrorKind::Other, "too many pack files (>255)")
            })?;
        }

        Ok((PackIndex { map }, pack_paths))
    }

    /// Returns `(pack_id, offset_in_pack)` or `None` if the object is not in any pack.
    pub fn lookup(&self, sha: &[u8; 20]) -> Option<(u8, u64)> {
        self.map.get(sha1_key(sha)).map(decode)
    }

    pub fn contains(&self, sha: &[u8; 20]) -> bool {
        self.map.contains(sha1_key(sha))
    }
}

fn load_idx(path: &Path, pack_id: u8, map: &mut ShaMap) -> io::Result<()> {
    let data = fs::read(path)?;

    if data.len() < 8 + 256 * 4 {
        return Err(bad("idx too short"));
    }
    if data[0..4] != IDX_MAGIC {
        return Err(bad("not a v2 pack index (bad magic)"));
    }
    if data[4..8] != IDX_V2 {
        return Err(bad("only pack index v2 is supported"));
    }

    // fan_out[255] = total object count
    let n = u32_be(&data, 8 + 255 * 4) as usize;

    let sha_base   = 8 + 256 * 4;
    let crc_base   = sha_base + n * 20;
    let soff_base  = crc_base + n * 4;   // small (32-bit) offsets
    let loff_base  = soff_base + n * 4;  // large (64-bit) offsets, may be empty

    if data.len() < loff_base {
        return Err(bad("idx truncated before offset table"));
    }

    map.reserve(n as u64);

    for i in 0..n {
        let sha: &[u8; 20] = data[sha_base + i * 20..sha_base + i * 20 + 20]
            .try_into()
            .unwrap();

        let raw = u32_be(&data, soff_base + i * 4);
        let offset: u64 = if raw & 0x8000_0000 != 0 {
            let li = (raw & 0x7fff_ffff) as usize;
            let lo = loff_base + li * 8;
            if data.len() < lo + 8 {
                return Err(bad("large offset out of bounds"));
            }
            u64_be(&data, lo)
        } else {
            raw as u64
        };

        map.set(sha1_key(sha), encode(pack_id, offset));
    }

    Ok(())
}

#[inline]
fn u32_be(data: &[u8], off: usize) -> u32 {
    u32::from_be_bytes(data[off..off + 4].try_into().unwrap())
}

#[inline]
fn u64_be(data: &[u8], off: usize) -> u64 {
    u64::from_be_bytes(data[off..off + 8].try_into().unwrap())
}

fn bad(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}
