use std::fmt::Write as FmtWrite;
use std::fs;
use std::io::{self, Read as _};
use std::path::{Path, PathBuf};

use flate2::read::ZlibDecoder;
use memmap2::Mmap;

use crate::pack_index::PackIndex;

const PACK_MAGIC: &[u8; 4] = b"PACK";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectKind { Commit, Tree, Blob, Tag }

pub struct GitObject {
    pub kind: ObjectKind,
    pub data: Vec<u8>,
}

pub struct PackStore {
    index: PackIndex,
    packs: Vec<Mmap>,
}

impl PackStore {
    pub fn load(git_dir: &Path) -> io::Result<Self> {
        let (index, pack_paths) = PackIndex::load_with_paths(git_dir)?;
        let packs = pack_paths.iter()
            .map(|p| {
                let f = fs::File::open(p)?;
                // SAFETY: pack files are write-once; git never modifies or truncates them
                unsafe { Mmap::map(&f) }
            })
            .collect::<io::Result<Vec<_>>>()?;
        for pack in &packs { check_header(pack)?; }
        Ok(PackStore { index, packs })
    }

    pub fn read(&self, sha: &[u8; 20]) -> io::Result<Option<GitObject>> {
        match self.index.lookup(sha) {
            None => Ok(None),
            Some((pack_id, offset)) => {
                read_object(&self.packs[pack_id as usize], offset as usize, self).map(Some)
            }
        }
    }

    pub fn contains(&self, sha: &[u8; 20]) -> bool {
        self.index.contains(sha)
    }
}

fn check_header(data: &[u8]) -> io::Result<()> {
    if data.len() < 12 { return Err(bad("pack too short")); }
    if &data[0..4] != PACK_MAGIC { return Err(bad("not a pack file")); }
    let ver = u32::from_be_bytes(data[4..8].try_into().unwrap());
    if ver != 2 { return Err(bad("only pack version 2 supported")); }
    Ok(())
}

fn read_object(pack: &[u8], offset: usize, store: &PackStore) -> io::Result<GitObject> {
    let mut pos = offset;
    let (obj_type, _size) = read_obj_header(pack, &mut pos);

    match obj_type {
        1..=4 => {
            let kind = match obj_type {
                1 => ObjectKind::Commit,
                2 => ObjectKind::Tree,
                3 => ObjectKind::Blob,
                _ => ObjectKind::Tag,
            };
            Ok(GitObject { kind, data: zlib_inflate(&pack[pos..])? })
        }
        6 => {
            // OFS_DELTA: base at negative offset in same pack
            let neg = read_ofs_offset(pack, &mut pos);
            let base_off = offset.checked_sub(neg as usize)
                .ok_or_else(|| bad("OFS_DELTA offset underflow"))?;
            let base = read_object(pack, base_off, store)?;
            let data = apply_delta(&base.data, &zlib_inflate(&pack[pos..])?)?;
            Ok(GitObject { kind: base.kind, data })
        }
        7 => {
            // REF_DELTA: base referenced by 20-byte SHA
            if pack.len() < pos + 20 { return Err(bad("REF_DELTA SHA truncated")); }
            let sha: &[u8; 20] = pack[pos..pos + 20].try_into().unwrap();
            pos += 20;
            let base = store.read(sha)?.ok_or_else(|| bad("REF_DELTA base not found"))?;
            let data = apply_delta(&base.data, &zlib_inflate(&pack[pos..])?)?;
            Ok(GitObject { kind: base.kind, data })
        }
        t => Err(io::Error::new(io::ErrorKind::InvalidData, format!("unknown object type {t}"))),
    }
}

// Returns (type_id 1-7, uncompressed size). Advances pos past the variable-length header.
pub(crate) fn read_obj_header(data: &[u8], pos: &mut usize) -> (u8, u64) {
    let b = data[*pos]; *pos += 1;
    let obj_type = (b >> 4) & 0x7;
    let mut size = (b & 0x0f) as u64;
    let mut shift = 4u32;
    let mut cont = b & 0x80;
    while cont != 0 {
        let b = data[*pos]; *pos += 1;
        size |= ((b & 0x7f) as u64) << shift;
        shift += 7;
        cont = b & 0x80;
    }
    (obj_type, size)
}

// OFS_DELTA negative-offset encoding: MSB continuation with +1 bias per byte after the first.
pub(crate) fn read_ofs_offset(data: &[u8], pos: &mut usize) -> u64 {
    let mut b = data[*pos] as u64; *pos += 1;
    let mut val = b & 0x7f;
    while b & 0x80 != 0 {
        b = data[*pos] as u64; *pos += 1;
        val = ((val + 1) << 7) | (b & 0x7f);
    }
    val
}

fn zlib_inflate(src: &[u8]) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    ZlibDecoder::new(src).read_to_end(&mut out)?;
    Ok(out)
}

pub(crate) fn apply_delta(base: &[u8], delta: &[u8]) -> io::Result<Vec<u8>> {
    let mut pos = 0usize;

    let src_size = read_varint(delta, &mut pos);
    if src_size != base.len() as u64 { return Err(bad("delta source size mismatch")); }
    let tgt_size = read_varint(delta, &mut pos) as usize;
    let mut out = Vec::with_capacity(tgt_size);

    while pos < delta.len() {
        let cmd = delta[pos]; pos += 1;
        if cmd & 0x80 != 0 {
            // copy [off, off+sz) from base
            let (mut off, mut sz) = (0u64, 0u64);
            for i in 0..4u64 {
                if cmd & (1 << i) != 0 { off |= (delta[pos] as u64) << (i * 8); pos += 1; }
            }
            for i in 0..3u64 {
                if cmd & (1 << (4 + i)) != 0 { sz |= (delta[pos] as u64) << (i * 8); pos += 1; }
            }
            if sz == 0 { sz = 0x10000; }
            let (off, sz) = (off as usize, sz as usize);
            if off + sz > base.len() { return Err(bad("delta copy out of bounds")); }
            out.extend_from_slice(&base[off..off + sz]);
        } else if cmd != 0 {
            let sz = cmd as usize;
            if pos + sz > delta.len() { return Err(bad("delta insert out of bounds")); }
            out.extend_from_slice(&delta[pos..pos + sz]);
            pos += sz;
        } else {
            return Err(bad("delta instruction 0x00 reserved"));
        }
    }

    Ok(out)
}

fn read_varint(data: &[u8], pos: &mut usize) -> u64 {
    let mut val = 0u64;
    let mut shift = 0u32;
    loop {
        let b = data[*pos]; *pos += 1;
        val |= ((b & 0x7f) as u64) << shift;
        shift += 7;
        if b & 0x80 == 0 { break; }
    }
    val
}

fn bad(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

// ---- loose objects -------------------------------------------------------

fn read_loose(git_dir: &Path, sha: &[u8; 20]) -> io::Result<Option<GitObject>> {
    let hex = sha_to_hex(sha);
    let path = git_dir.join("objects").join(&hex[..2]).join(&hex[2..]);
    let compressed = match fs::read(&path) {
        Ok(d) => d,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let raw = zlib_inflate(&compressed)?;
    let nul = raw.iter().position(|&b| b == 0)
        .ok_or_else(|| bad("loose: missing nul in header"))?;
    let header = std::str::from_utf8(&raw[..nul])
        .map_err(|_| bad("loose: non-utf8 header"))?;
    let kind = match header.split_once(' ').map(|(t, _)| t) {
        Some("commit") => ObjectKind::Commit,
        Some("tree")   => ObjectKind::Tree,
        Some("blob")   => ObjectKind::Blob,
        Some("tag")    => ObjectKind::Tag,
        _              => return Err(bad("loose: unknown type")),
    };
    Ok(Some(GitObject { kind, data: raw[nul + 1..].to_vec() }))
}

fn sha_to_hex(sha: &[u8; 20]) -> String {
    let mut s = String::with_capacity(40);
    for b in sha { write!(s, "{b:02x}").unwrap(); }
    s
}

// ---- unified store -------------------------------------------------------

/// Reads objects from packs first (O(1) ShaMap probe), falls through to loose files.
pub struct ObjectStore {
    packs: PackStore,
    git_dir: PathBuf,
}

impl ObjectStore {
    pub fn load(git_dir: &Path) -> io::Result<Self> {
        Ok(ObjectStore { packs: PackStore::load(git_dir)?, git_dir: git_dir.to_path_buf() })
    }

    pub fn read(&self, sha: &[u8; 20]) -> io::Result<Option<GitObject>> {
        if let Some(obj) = self.packs.read(sha)? { return Ok(Some(obj)); }
        read_loose(&self.git_dir, sha)
    }

    /// O(1) ShaMap probe: does not check loose objects.
    pub fn contains_packed(&self, sha: &[u8; 20]) -> bool {
        self.packs.contains(sha)
    }
}
