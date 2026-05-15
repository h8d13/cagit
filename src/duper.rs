// Duplicate-code detector running over a git tree (typically HEAD's).
//   walk_tree -> collect blob (path, sha) -> for each blob:
//     inflate -> reject binary -> strip comments -> normalize (trim) ->
//     sliding window of MIN_LINES -> hash -> FFI map bucketing.
// Groups with >=2 occurrences are reported, ranked by wasted lines.

use std::io;

use crate::find::{resolve_sha_multi, LooseStore, ShaIndex};
use crate::offset_map::OffsetMap;

const NO_NEXT: u32 = u32::MAX;
pub const MIN_LINES: usize = 3;

const SKIP_STEMS: &[&[u8]] = &[
    b"LICENSE", b"LICENCE", b"CHANGELOG", b"NOTICE", b"AUTHORS", b"COPYING",
];

const CODE_EXTENSIONS: &[&[u8]] = &[
    b".py", b".js", b".ts", b".jsx", b".tsx",
    b".java", b".c", b".cpp", b".h", b".hpp", b".cc", b".cxx",
    b".go", b".rs", b".rb", b".php", b".cs",
    b".sh", b".bash", b".zsh", b".fish",
    b".lua", b".pl", b".swift", b".kt", b".scala",
    b".md", b".rst", b".txt", b".html", b".xml", b".css", b".scss", b".sass",
    b".yaml", b".yml", b".toml", b".json",
];

pub struct FileEntry {
    pub path: Vec<u8>,
    pub blob_sha: [u8; 20],
}

pub struct Group {
    pub line_count: u32,
    pub occurrences: Vec<(u32, u32)>, // (file_idx, start_line, 1-based)
}

impl Group {
    pub fn wasted_lines(&self) -> u32 {
        self.line_count * (self.occurrences.len() as u32 - 1)
    }
}

pub struct DuperOutput {
    pub files: Vec<FileEntry>,
    pub groups: Vec<Group>, // sorted by wasted_lines desc
    pub stats: Stats,
}

#[derive(Default)]
pub struct Stats {
    pub files_scanned: usize,
    pub files_skipped_binary: usize,
    pub windows_hashed: usize,
    pub unique_windows: usize,
}

fn stem(name: &[u8]) -> &[u8] {
    if let Some(dot) = name.iter().rposition(|&b| b == b'.') {
        &name[..dot]
    } else {
        name
    }
}

fn ends_with_extension(name: &[u8], exts: &[&[u8]]) -> bool {
    for ext in exts {
        if name.len() >= ext.len() && &name[name.len() - ext.len()..] == *ext {
            return true;
        }
    }
    false
}

fn is_binary(content: &[u8]) -> bool {
    content.iter().take(8192).any(|&b| b == 0)
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() { return Some(0); }
    if needle.len() > haystack.len() { return None; }
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn trim(s: &[u8]) -> &[u8] {
    let start = s.iter().position(|&b| !b.is_ascii_whitespace()).unwrap_or(s.len());
    let end = s.iter().rposition(|&b| !b.is_ascii_whitespace()).map(|i| i + 1).unwrap_or(start);
    &s[start..end]
}

// Walk tree recursively (sha-based, multi-pack + loose), collecting code-like blobs.
fn walk_tree(
    packs: &[&[u8]],
    sha_idxs: &[ShaIndex],
    loose: &LooseStore,
    tree_sha: &[u8; 20],
    prefix: &[u8],
    out: &mut Vec<FileEntry>,
) -> io::Result<()> {
    let Some((_kind, data)) = resolve_sha_multi(packs, sha_idxs, loose, tree_sha) else {
        return Ok(());
    };
    let mut pos = 0;
    while pos < data.len() {
        let Some(sp) = data[pos..].iter().position(|&b| b == b' ') else { break };
        let mode = &data[pos..pos + sp];
        let name_start = pos + sp + 1;
        let Some(nul_rel) = data[name_start..].iter().position(|&b| b == 0) else { break };
        let name_end = name_start + nul_rel;
        let sha_start = name_end + 1;
        if sha_start + 20 > data.len() { break; }
        let name = &data[name_start..name_end];
        let sha: [u8; 20] = data[sha_start..sha_start + 20].try_into().unwrap();
        let is_tree = mode == b"40000";

        if is_tree {
            let mut new_prefix = prefix.to_vec();
            if !prefix.is_empty() { new_prefix.push(b'/'); }
            new_prefix.extend_from_slice(name);
            walk_tree(packs, sha_idxs, loose, &sha, &new_prefix, out)?;
        } else {
            // blob filtering
            if SKIP_STEMS.contains(&stem(name)) {
                pos = sha_start + 20;
                continue;
            }
            let has_dot = name.iter().any(|&b| b == b'.');
            let starts_dot = name.first() == Some(&b'.');
            let include = if has_dot {
                ends_with_extension(name, CODE_EXTENSIONS)
            } else {
                !starts_dot
            };
            if include {
                let mut full = prefix.to_vec();
                if !prefix.is_empty() { full.push(b'/'); }
                full.extend_from_slice(name);
                out.push(FileEntry { path: full, blob_sha: sha });
            }
        }
        pos = sha_start + 20;
    }
    Ok(())
}

// Port of DUPER strip_comments. Operates per-line, with cross-line block state.
fn strip_comments(raw_lines: &[&[u8]]) -> Vec<Vec<u8>> {
    let line_prefixes: &[&[u8]] = &[b"//", b"#", b"--", b";", b"%"];
    let block_markers: &[(&[u8], &[u8])] = &[
        (b"/*", b"*/"),
        (b"<!--", b"-->"),
        (b"--[[", b"]]"),
        (b"{-", b"-}"),
        (b"\"\"\"", b"\"\"\""),
        (b"'''", b"'''"),
    ];

    let mut result: Vec<Vec<u8>> = Vec::with_capacity(raw_lines.len());
    let mut in_block: Option<&[u8]> = None;

    for &line in raw_lines {
        let mut s: &[u8] = line;
        if let Some(close) = in_block {
            if let Some(idx) = find_subslice(s, close) {
                s = &s[idx + close.len()..];
                in_block = None;
            } else {
                result.push(Vec::new());
                continue;
            }
        }
        let mut clean: Vec<u8> = s.to_vec();
        loop {
            let mut earliest_pos = clean.len();
            let mut earliest_open: Option<&[u8]> = None;
            let mut earliest_close: Option<&[u8]> = None;
            for (open_m, close_m) in block_markers {
                if let Some(p) = find_subslice(&clean, open_m) {
                    if p < earliest_pos {
                        earliest_pos = p;
                        earliest_open = Some(open_m);
                        earliest_close = Some(close_m);
                    }
                }
            }
            let mut line_pos = clean.len();
            let mut line_marker_found = false;
            for prefix in line_prefixes {
                if let Some(p) = find_subslice(&clean, prefix) {
                    if p < line_pos {
                        line_pos = p;
                        line_marker_found = true;
                    }
                }
            }
            if earliest_open.is_none() && !line_marker_found {
                break;
            }
            if line_marker_found && line_pos <= earliest_pos {
                clean.truncate(line_pos);
                break;
            }
            // earliest_open present and earlier than any line marker
            let open_m = earliest_open.unwrap();
            let close_m = earliest_close.unwrap();
            let after_open_start = earliest_pos + open_m.len();
            let after_open = &clean[after_open_start..];
            if let Some(close_idx) = find_subslice(after_open, close_m) {
                let end = after_open_start + close_idx + close_m.len();
                clean.drain(earliest_pos..end);
            } else {
                clean.truncate(earliest_pos);
                in_block = Some(close_m);
                break;
            }
        }
        result.push(clean);
    }
    result
}

fn hash_window(lines: &[Vec<u8>], start: usize, count: usize) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for i in start..start + count {
        for &b in &lines[i] {
            h ^= b as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
        h ^= b'\n' as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

#[derive(Clone, Copy)]
struct SlabEntry {
    hash: u64,
    file_idx: u32,
    start_line: u32,
    next: u32,
}

pub fn run(
    packs: &[&[u8]],
    sha_idxs: &[ShaIndex],
    loose: &LooseStore,
    head_tree_sha: &[u8; 20],
    min_lines: usize,
) -> io::Result<DuperOutput> {
    let mut files: Vec<FileEntry> = Vec::new();
    walk_tree(packs, sha_idxs, loose, head_tree_sha, b"", &mut files)?;

    let mut slab: Vec<SlabEntry> = Vec::new();
    let mut map = OffsetMap::new(1 << 16);
    map.reserve(1 << 16);
    let mut stats = Stats::default();

    for (file_idx, file) in files.iter().enumerate() {
        let Some((kind, body)) = resolve_sha_multi(packs, sha_idxs, loose, &file.blob_sha) else { continue };
        if kind != 3 { continue; }
        if is_binary(&body) {
            stats.files_skipped_binary += 1;
            continue;
        }
        stats.files_scanned += 1;

        let raw_lines: Vec<&[u8]> = body.split(|&b| b == b'\n').collect();
        let stripped = strip_comments(&raw_lines);
        let normalized: Vec<Vec<u8>> = stripped.iter().map(|l| trim(l).to_vec()).collect();

        let n = normalized.len();
        if n < min_lines { continue; }

        for start in 0..=(n - min_lines) {
            // skip empty-leading or mostly-blank windows
            if normalized[start].is_empty() { continue; }
            let non_empty = (0..min_lines)
                .filter(|i| !normalized[start + *i].is_empty())
                .count();
            if non_empty * 10 < min_lines * 6 { continue; }
            // skip trivial windows (closing braces, etc): require >= 25 bytes
            // of total non-whitespace content across the window.
            let total_chars: usize = (0..min_lines)
                .map(|i| normalized[start + i].iter().filter(|&&b| !b.is_ascii_whitespace()).count())
                .sum();
            if total_chars < 25 { continue; }

            let h = hash_window(&normalized, start, min_lines);
            let prev_head = map.get(h).unwrap_or(NO_NEXT);
            let new_idx = slab.len() as u32;
            slab.push(SlabEntry {
                hash: h,
                file_idx: file_idx as u32,
                start_line: start as u32 + 1,
                next: prev_head,
            });
            map.set(h, new_idx);
            stats.windows_hashed += 1;
        }
    }

    // Build groups: for each slab entry that's a chain head (map[hash] == its idx),
    // walk the chain and emit a group if it has >1 occurrence.
    let mut groups: Vec<Group> = Vec::new();
    let mut unique = 0usize;
    for (i, entry) in slab.iter().enumerate() {
        let head = match map.get(entry.hash) { Some(h) => h, None => continue };
        if head as usize != i { continue; }
        unique += 1;
        let mut occs: Vec<(u32, u32)> = vec![(entry.file_idx, entry.start_line)];
        let mut cur = entry.next;
        while cur != NO_NEXT {
            let e = &slab[cur as usize];
            occs.push((e.file_idx, e.start_line));
            cur = e.next;
        }
        if occs.len() >= 2 {
            groups.push(Group {
                line_count: min_lines as u32,
                occurrences: occs,
            });
        }
    }
    stats.unique_windows = unique;
    groups.sort_by(|a, b| b.wasted_lines().cmp(&a.wasted_lines()));

    Ok(DuperOutput { files, groups, stats })
}
