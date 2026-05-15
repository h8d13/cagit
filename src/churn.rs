// Per-file change counts across a range of commits.
// Walks tree-pair diffs commit-by-commit (vs first parent) and accumulates
// path -> change_count in an FFI-backed PathCounter.

use std::io;

use crate::find::{resolve_sha_multi, LooseStore, ShaIndex};
use crate::offset_map::OffsetMap;

const NO_NEXT: u32 = u32::MAX;

// FNV-1a u64 for variable-length path keys; collisions handled by slab chaining.
fn path_key(path: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in path {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

pub struct PathCounter {
    slab: Vec<PathCounterEntry>,
    map: OffsetMap,
}

struct PathCounterEntry {
    path: Vec<u8>,
    count: u32,
    next: u32,
}

impl PathCounter {
    pub fn with_capacity(cap: usize) -> Self {
        let mut map = OffsetMap::new(cap.next_power_of_two().max(16));
        map.reserve(cap as u64);
        Self { slab: Vec::with_capacity(cap), map }
    }

    pub fn increment(&mut self, path: &[u8]) {
        let k = path_key(path);
        let head = self.map.get(k);
        // Walk chain to find exact path; if found, increment in place.
        let mut idx_opt = head;
        while let Some(idx) = idx_opt {
            if self.slab[idx as usize].path == path {
                self.slab[idx as usize].count += 1;
                return;
            }
            let n = self.slab[idx as usize].next;
            idx_opt = if n == NO_NEXT { None } else { Some(n) };
        }
        // New entry: prepend to chain.
        let prev = head.unwrap_or(NO_NEXT);
        self.map.set(k, self.slab.len() as u32);
        self.slab.push(PathCounterEntry { path: path.to_vec(), count: 1, next: prev });
    }

    pub fn into_sorted_desc(self) -> Vec<(Vec<u8>, u32)> {
        let mut v: Vec<(Vec<u8>, u32)> = self.slab.into_iter()
            .map(|e| (e.path, e.count))
            .collect();
        v.sort_by(|a, b| b.1.cmp(&a.1));
        v
    }

    pub fn len(&self) -> usize { self.slab.len() }
}

struct Entry<'a> {
    name: &'a [u8],
    is_tree: bool,
    sha: [u8; 20],
}

fn parse_entries(data: &[u8]) -> Vec<Entry<'_>> {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < data.len() {
        let Some(sp) = data[pos..].iter().position(|&b| b == b' ') else { break };
        let mode_start = pos;
        let name_start = pos + sp + 1;
        let Some(nul_rel) = data[name_start..].iter().position(|&b| b == 0) else { break };
        let name_end = name_start + nul_rel;
        let sha_start = name_end + 1;
        if sha_start + 20 > data.len() { break; }
        let mode = &data[mode_start..mode_start + sp];
        let is_tree = mode == b"40000";
        let sha: [u8; 20] = data[sha_start..sha_start+20].try_into().unwrap();
        out.push(Entry { name: &data[name_start..name_end], is_tree, sha });
        pos = sha_start + 20;
    }
    out
}

fn count_path(prefix: &[u8], name: &[u8], counts: &mut PathCounter) {
    let mut path = Vec::with_capacity(prefix.len() + 1 + name.len());
    path.extend_from_slice(prefix);
    if !prefix.is_empty() { path.push(b'/'); }
    path.extend_from_slice(name);
    counts.increment(&path);
}

// Recurse into a one-sided tree, counting each blob leaf path.
fn count_leaves(
    packs: &[&[u8]],
    sha_idxs: &[ShaIndex],
    loose: &LooseStore,
    tree_sha: &[u8; 20],
    prefix: &mut Vec<u8>,
    counts: &mut PathCounter,
) -> io::Result<()> {
    let Some((_, data)) = resolve_sha_multi(packs, sha_idxs, loose, tree_sha) else { return Ok(()); };
    for entry in parse_entries(&data) {
        if entry.is_tree {
            let saved = prefix.len();
            if !prefix.is_empty() { prefix.push(b'/'); }
            prefix.extend_from_slice(entry.name);
            count_leaves(packs, sha_idxs, loose, &entry.sha, prefix, counts)?;
            prefix.truncate(saved);
        } else {
            count_path(prefix, entry.name, counts);
        }
    }
    Ok(())
}

/// Diff two trees in lockstep on entry names; accumulate per-path change counts.
pub fn diff_trees(
    packs: &[&[u8]],
    sha_idxs: &[ShaIndex],
    loose: &LooseStore,
    tree_sha_a: &[u8; 20],
    tree_sha_b: &[u8; 20],
    prefix: &mut Vec<u8>,
    counts: &mut PathCounter,
) -> io::Result<()> {
    if tree_sha_a == tree_sha_b { return Ok(()); }
    let Some((_, data_a)) = resolve_sha_multi(packs, sha_idxs, loose, tree_sha_a) else { return Ok(()); };
    let Some((_, data_b)) = resolve_sha_multi(packs, sha_idxs, loose, tree_sha_b) else { return Ok(()); };
    let ents_a = parse_entries(&data_a);
    let ents_b = parse_entries(&data_b);

    let mut i = 0usize;
    let mut j = 0usize;
    while i < ents_a.len() || j < ents_b.len() {
        let a = ents_a.get(i);
        let b = ents_b.get(j);
        match (a, b) {
            (None, None) => break,
            (Some(a), None) => {
                if a.is_tree {
                    let saved = prefix.len();
                    if !prefix.is_empty() { prefix.push(b'/'); }
                    prefix.extend_from_slice(a.name);
                    count_leaves(packs, sha_idxs, loose, &a.sha, prefix, counts)?;
                    prefix.truncate(saved);
                } else {
                    count_path(prefix, a.name, counts);
                }
                i += 1;
            }
            (None, Some(b)) => {
                if b.is_tree {
                    let saved = prefix.len();
                    if !prefix.is_empty() { prefix.push(b'/'); }
                    prefix.extend_from_slice(b.name);
                    count_leaves(packs, sha_idxs, loose, &b.sha, prefix, counts)?;
                    prefix.truncate(saved);
                } else {
                    count_path(prefix, b.name, counts);
                }
                j += 1;
            }
            (Some(a), Some(b)) => {
                match a.name.cmp(b.name) {
                    std::cmp::Ordering::Less => {
                        if a.is_tree {
                            let saved = prefix.len();
                            if !prefix.is_empty() { prefix.push(b'/'); }
                            prefix.extend_from_slice(a.name);
                            count_leaves(packs, sha_idxs, loose, &a.sha, prefix, counts)?;
                            prefix.truncate(saved);
                        } else {
                            count_path(prefix, a.name, counts);
                        }
                        i += 1;
                    }
                    std::cmp::Ordering::Greater => {
                        if b.is_tree {
                            let saved = prefix.len();
                            if !prefix.is_empty() { prefix.push(b'/'); }
                            prefix.extend_from_slice(b.name);
                            count_leaves(packs, sha_idxs, loose, &b.sha, prefix, counts)?;
                            prefix.truncate(saved);
                        } else {
                            count_path(prefix, b.name, counts);
                        }
                        j += 1;
                    }
                    std::cmp::Ordering::Equal => {
                        if a.sha != b.sha {
                            if a.is_tree && b.is_tree {
                                let saved = prefix.len();
                                if !prefix.is_empty() { prefix.push(b'/'); }
                                prefix.extend_from_slice(a.name);
                                diff_trees(packs, sha_idxs, loose, &a.sha, &b.sha, prefix, counts)?;
                                prefix.truncate(saved);
                            } else {
                                count_path(prefix, a.name, counts);
                            }
                        }
                        i += 1; j += 1;
                    }
                }
            }
        }
    }
    Ok(())
}
