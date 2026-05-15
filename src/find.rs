// PoC: git log --find-object equivalent for a local pack, leaning on FFI
// offset_map for O(1) sha->offset lookups.
//
// Walks all commits in pack, sorts by author_ts oldest first, for each does a
// memoized contains-check on its root tree. First match = introducing commit.

use std::io::{self, Read as _};

use flate2::read::ZlibDecoder;

use crate::offset_map::OffsetMap;
use crate::pack_reader::{apply_delta, read_obj_header, read_ofs_offset};

const NO_NEXT: u32 = u32::MAX;

pub struct ShaEntry {
    pub sha: [u8; 20],
    pub offset: u64,
    next: u32,
}

pub struct ShaIndex {
    slab: Vec<ShaEntry>,
    // u64 = first 8 bytes of sha; chain via slab.next for prefix collisions.
    map: OffsetMap,
}

fn sha_key(sha: &[u8; 20]) -> u64 {
    u64::from_le_bytes(sha[..8].try_into().unwrap())
}

fn u32_be(d: &[u8], o: usize) -> u32 { u32::from_be_bytes(d[o..o+4].try_into().unwrap()) }
fn u64_be(d: &[u8], o: usize) -> u64 { u64::from_be_bytes(d[o..o+8].try_into().unwrap()) }

impl ShaIndex {
    pub fn from_idx(idx: &[u8]) -> Self {
        let n = u32_be(idx, 8 + 255 * 4) as usize;
        let sha_base  = 8 + 256 * 4;
        let soff_base = sha_base + n * 20 + n * 4;
        let loff_base = soff_base + n * 4;
        let mut slab: Vec<ShaEntry> = Vec::with_capacity(n);
        let mut map = OffsetMap::new(n.next_power_of_two().max(16));
        map.reserve(n as u64);
        for i in 0..n {
            let raw = u32_be(idx, soff_base + i * 4);
            let offset = if raw & 0x8000_0000 != 0 {
                u64_be(idx, loff_base + (raw & 0x7fff_ffff) as usize * 8)
            } else {
                raw as u64
            };
            let sha: [u8; 20] = idx[sha_base + i*20..sha_base + i*20 + 20].try_into().unwrap();
            let k = sha_key(&sha);
            let prev = map.get(k).unwrap_or(NO_NEXT);
            map.set(k, slab.len() as u32);
            slab.push(ShaEntry { sha, offset, next: prev });
        }
        Self { slab, map }
    }

    /// Build from (sha, offset) pairs (e.g. emitted during a no-idx pack walk).
    pub fn from_pairs(pairs: &[([u8; 20], u64)]) -> Self {
        let n = pairs.len();
        let mut slab: Vec<ShaEntry> = Vec::with_capacity(n);
        let mut map = OffsetMap::new(n.next_power_of_two().max(16));
        map.reserve(n as u64);
        for &(sha, offset) in pairs {
            let k = sha_key(&sha);
            let prev = map.get(k).unwrap_or(NO_NEXT);
            map.set(k, slab.len() as u32);
            slab.push(ShaEntry { sha, offset, next: prev });
        }
        Self { slab, map }
    }

    pub fn lookup(&self, sha: &[u8; 20]) -> Option<u64> {
        let mut idx = self.map.get(sha_key(sha))?;
        loop {
            let entry = &self.slab[idx as usize];
            if entry.sha == *sha { return Some(entry.offset); }
            if entry.next == NO_NEXT { return None; }
            idx = entry.next;
        }
    }

    pub fn slab(&self) -> &[ShaEntry] { &self.slab }
}

pub fn inflate_at(pack: &[u8], offset: u64) -> io::Result<(u8, Vec<u8>)> {
    let mut pos = offset as usize;
    let (obj_type, size) = read_obj_header(pack, &mut pos);
    match obj_type {
        1..=4 => {
            let mut out = Vec::with_capacity(size as usize);
            ZlibDecoder::new(&pack[pos..]).read_to_end(&mut out)?;
            Ok((obj_type, out))
        }
        6 => {
            let neg = read_ofs_offset(pack, &mut pos);
            let base_off = offset.checked_sub(neg)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "ofs underflow"))?;
            let (base_kind, base_data) = inflate_at(pack, base_off)?;
            let mut delta = Vec::new();
            ZlibDecoder::new(&pack[pos..]).read_to_end(&mut delta)?;
            let out = apply_delta(&base_data, &delta)?;
            Ok((base_kind, out))
        }
        _ => Err(io::Error::new(io::ErrorKind::InvalidData,
                                format!("type {obj_type}"))),
    }
}

// Resolve final object type by walking the delta chain without zlib.
pub fn resolve_type(pack: &[u8], mut offset: u64) -> u8 {
    loop {
        let mut pos = offset as usize;
        let (t, _) = read_obj_header(pack, &mut pos);
        if t != 6 { return t; }
        let neg = read_ofs_offset(pack, &mut pos);
        match offset.checked_sub(neg) {
            Some(o) => offset = o,
            None => return 0,
        }
    }
}

// Memo encoding for tree_contains: missing = unvisited, 1 = false, 2 = true.
const MEMO_FALSE: u32 = 1;
const MEMO_TRUE:  u32 = 2;

fn tree_contains(
    pack: &[u8],
    sha_idx: &ShaIndex,
    tree_offset: u64,
    target: &[u8; 20],
    memo: &mut OffsetMap,
) -> io::Result<bool> {
    if let Some(v) = memo.get(tree_offset) {
        return Ok(v == MEMO_TRUE);
    }
    let (_kind, data) = inflate_at(pack, tree_offset)?;

    let mut pos = 0;
    let mut found = false;
    while pos < data.len() {
        // entry: <mode_ascii> ' ' <name> '\0' <sha20>
        let Some(sp) = data[pos..].iter().position(|&b| b == b' ') else { break };
        let mode_start = pos;
        let name_start = pos + sp + 1;
        let Some(nul_rel) = data[name_start..].iter().position(|&b| b == 0) else { break };
        let sha_start = name_start + nul_rel + 1;
        if sha_start + 20 > data.len() { break; }
        let entry_sha: &[u8; 20] = (&data[sha_start..sha_start+20]).try_into().unwrap();

        if entry_sha == target {
            found = true;
            break;
        }

        // Subtree mode is "40000" (ascii). Gitlinks ("160000") and others not recursed.
        let mode = &data[mode_start..mode_start + sp];
        if mode == b"40000" {
            if let Some(child_off) = sha_idx.lookup(entry_sha) {
                if tree_contains(pack, sha_idx, child_off, target, memo)? {
                    found = true;
                    break;
                }
            }
        }

        pos = sha_start + 20;
    }
    memo.set(tree_offset, if found { MEMO_TRUE } else { MEMO_FALSE });
    Ok(found)
}

#[derive(Clone)]
pub struct CommitInfo {
    pub offset: u64,
    pub commit_sha: [u8; 20],
    pub root_tree: [u8; 20],
    pub author_ts: i64,
}

fn parse_commit(data: &[u8]) -> Option<([u8; 20], i64)> {
    let mut tree_sha: Option<[u8; 20]> = None;
    let mut author_ts: i64 = 0;
    let mut linestart = 0;
    for i in 0..data.len() {
        if data[i] == b'\n' {
            let line = &data[linestart..i];
            if line.is_empty() { break; }
            if line.len() >= 45 && line.starts_with(b"tree ") {
                if let Ok(h) = std::str::from_utf8(&line[5..45]) {
                    tree_sha = hex_to_sha(h);
                }
            } else if line.starts_with(b"author ") {
                if let Ok(s) = std::str::from_utf8(line) {
                    let parts: Vec<&str> = s.split_ascii_whitespace().collect();
                    if parts.len() >= 2 {
                        author_ts = parts[parts.len() - 2].parse().unwrap_or(0);
                    }
                }
            }
            linestart = i + 1;
        }
    }
    tree_sha.map(|t| (t, author_ts))
}

pub fn hex_to_sha(hex: &str) -> Option<[u8; 20]> {
    if hex.len() != 40 { return None; }
    let mut sha = [0u8; 20];
    for (i, b) in sha.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[i*2..i*2+2], 16).ok()?;
    }
    Some(sha)
}

/// Up to `limit` oldest commits (by author_ts) whose root tree (recursively)
/// contains `target`. Early-exits as soon as `limit` matches are collected.
pub fn find_oldest(
    pack: &[u8],
    sha_idx: &ShaIndex,
    target: &[u8; 20],
    limit: usize,
) -> io::Result<Vec<CommitInfo>> {
    let mut commits: Vec<CommitInfo> = Vec::new();
    for entry in sha_idx.slab() {
        if resolve_type(pack, entry.offset) != 1 { continue; }
        let (_, data) = inflate_at(pack, entry.offset)?;
        if let Some((root_tree, author_ts)) = parse_commit(&data) {
            commits.push(CommitInfo {
                offset: entry.offset,
                commit_sha: entry.sha,
                root_tree,
                author_ts,
            });
        }
    }
    commits.sort_unstable_by_key(|c| c.author_ts);

    let mut memo = OffsetMap::new(1024);
    let mut out: Vec<CommitInfo> = Vec::new();
    for c in &commits {
        if out.len() >= limit { break; }
        let Some(tree_off) = sha_idx.lookup(&c.root_tree) else { continue };
        if tree_contains(pack, sha_idx, tree_off, target, &mut memo)? {
            out.push(c.clone());
        }
    }
    Ok(out)
}
