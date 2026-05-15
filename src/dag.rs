// Commit DAG with parent map, child map, and generation numbers.
// Built in one pass over all commits in the pack.
// See: git/Documentation/technical/commit-graph.adoc

use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::io::{self, BufWriter, Read as _, Write as _};
use std::path::Path;

use flate2::read::ZlibDecoder;

use crate::find::{hex_to_sha, inflate_at, resolve_type, CommitInfo, ShaIndex};
use crate::offset_map::OffsetMap;

const CACHE_MAGIC: &[u8; 4] = b"CDAG";
const CACHE_VERSION: u8 = 3; // multi-pack + loose-commit support
const LOOSE_OFFSET_MARK: u64 = 1u64 << 63;
const OFFSET_MASK: u64 = (1u64 << 56) - 1;

fn encode_offset(pack_id: u8, off: u64) -> u64 {
    ((pack_id as u64) << 56) | (off & OFFSET_MASK)
}

fn decode_offset(o: u64) -> (u8, u64) {
    (((o >> 56) & 0x7f) as u8, o & OFFSET_MASK)
}

pub struct CommitDag {
    pub commits: Vec<CommitInfo>,
    offset_to_index: OffsetMap,
    // sha -> index in `commits`. Covers both packed and loose. Rebuilt on load.
    sha_to_index: HashMap<[u8; 20], u32>,
    // Loose commit bodies, keyed by index in `commits` (so we can inflate for summary).
    pub loose_bodies: HashMap<u32, Vec<u8>>,
    pub parents: Vec<Vec<u32>>,
    pub children: Vec<Vec<u32>>,
    pub generation: Vec<u32>,
}

// Walk <git_dir>/objects/<2>/<38> and return (sha, inflated commit body) for
// every loose commit. Other object types (blob, tree, tag) are skipped.
pub fn scan_loose_commits(git_dir: &Path) -> io::Result<Vec<([u8; 20], Vec<u8>)>> {
    let mut out = Vec::new();
    let objects = git_dir.join("objects");
    let Ok(rd) = objects.read_dir() else { return Ok(out); };
    for e in rd.filter_map(|e| e.ok()) {
        let name = e.file_name();
        let s = name.to_string_lossy();
        if s.len() != 2 || !s.chars().all(|c| c.is_ascii_hexdigit()) { continue; }
        let sub = e.path();
        let Ok(rd2) = sub.read_dir() else { continue; };
        for f in rd2.filter_map(|e| e.ok()) {
            let fname = f.file_name();
            let fs = fname.to_string_lossy();
            if fs.len() != 38 || !fs.chars().all(|c| c.is_ascii_hexdigit()) { continue; }
            let full_hex = format!("{}{}", s, fs);
            let Some(sha) = hex_to_sha(&full_hex) else { continue; };
            let compressed = match std::fs::read(f.path()) { Ok(b) => b, Err(_) => continue };
            let mut decompressed = Vec::new();
            if ZlibDecoder::new(&compressed[..]).read_to_end(&mut decompressed).is_err() { continue; }
            // header: "<type> <size>\0"
            if let Some(nul) = decompressed.iter().position(|&b| b == 0) {
                if decompressed[..nul].starts_with(b"commit ") {
                    out.push((sha, decompressed[nul + 1..].to_vec()));
                }
            }
        }
    }
    Ok(out)
}

fn parse_commit_full(data: &[u8]) -> Option<([u8; 20], i64, Vec<[u8; 20]>)> {
    let mut tree_sha: Option<[u8; 20]> = None;
    let mut author_ts = 0i64;
    let mut parents: Vec<[u8; 20]> = Vec::new();
    let mut linestart = 0;
    for i in 0..data.len() {
        if data[i] == b'\n' {
            let line = &data[linestart..i];
            if line.is_empty() { break; }
            if line.len() >= 45 && line.starts_with(b"tree ") {
                if let Ok(h) = std::str::from_utf8(&line[5..45]) {
                    tree_sha = hex_to_sha(h);
                }
            } else if line.len() >= 47 && line.starts_with(b"parent ") {
                if let Ok(h) = std::str::from_utf8(&line[7..47]) {
                    if let Some(s) = hex_to_sha(h) { parents.push(s); }
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
    tree_sha.map(|t| (t, author_ts, parents))
}

impl CommitDag {
    pub fn build(packs: &[(&[u8], &ShaIndex)], git_dir: Option<&Path>) -> io::Result<Self> {
        if packs.len() > 127 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "too many packs (>127)"));
        }
        let mut commits: Vec<CommitInfo> = Vec::new();
        let mut parent_shas: Vec<Vec<[u8; 20]>> = Vec::new();
        let mut offset_to_index = OffsetMap::new(1024);
        let mut sha_to_index: HashMap<[u8; 20], u32> = HashMap::new();
        let mut loose_bodies: HashMap<u32, Vec<u8>> = HashMap::new();

        // Pass 1a: packed commits across all packs. Encode pack_id in offset.
        for (pack_id, (pack, sha_idx)) in packs.iter().enumerate() {
            for entry in sha_idx.slab() {
                if resolve_type(pack, entry.offset) != 1 { continue; }
                let (_, data) = inflate_at(pack, entry.offset)?;
                if let Some((root_tree, author_ts, parents)) = parse_commit_full(&data) {
                    if sha_to_index.contains_key(&entry.sha) { continue; }
                    let idx = commits.len() as u32;
                    let encoded = encode_offset(pack_id as u8, entry.offset);
                    offset_to_index.set(encoded, idx);
                    sha_to_index.insert(entry.sha, idx);
                    commits.push(CommitInfo {
                        offset: encoded,
                        commit_sha: entry.sha,
                        root_tree,
                        author_ts,
                    });
                    parent_shas.push(parents);
                }
            }
        }

        // Pass 1b: loose commits (if git_dir is available).
        if let Some(dir) = git_dir {
            for (sha, body) in scan_loose_commits(dir)? {
                if sha_to_index.contains_key(&sha) { continue; }
                if let Some((root_tree, author_ts, parents)) = parse_commit_full(&body) {
                    let idx = commits.len() as u32;
                    let synth_offset = LOOSE_OFFSET_MARK | idx as u64;
                    sha_to_index.insert(sha, idx);
                    commits.push(CommitInfo {
                        offset: synth_offset,
                        commit_sha: sha,
                        root_tree,
                        author_ts,
                    });
                    parent_shas.push(parents);
                    loose_bodies.insert(idx, body);
                }
            }
        }

        let n = commits.len();

        // Resolve parent shas to commit indices; build children as the inverse.
        // Lookup via unified sha_to_index handles both packed and loose parents.
        let mut parents: Vec<Vec<u32>> = Vec::with_capacity(n);
        let mut children: Vec<Vec<u32>> = vec![Vec::new(); n];
        for i in 0..n {
            let mut p_indices: Vec<u32> = Vec::new();
            for psha in &parent_shas[i] {
                if let Some(&pidx) = sha_to_index.get(psha) {
                    p_indices.push(pidx);
                    children[pidx as usize].push(i as u32);
                }
            }
            parents.push(p_indices);
        }

        // Kahn's: topological generation (v1: 1 for roots, 1 + max(parents) otherwise).
        let mut in_degree: Vec<u32> = parents.iter().map(|p| p.len() as u32).collect();
        let mut queue: VecDeque<usize> = (0..n).filter(|&i| in_degree[i] == 0).collect();
        let mut generation: Vec<u32> = vec![0; n];
        while let Some(i) = queue.pop_front() {
            let max_parent_gen = parents[i].iter()
                .map(|&p| generation[p as usize])
                .max()
                .unwrap_or(0);
            generation[i] = max_parent_gen + 1;
            for &c in &children[i] {
                in_degree[c as usize] -= 1;
                if in_degree[c as usize] == 0 {
                    queue.push_back(c as usize);
                }
            }
        }

        Ok(Self { commits, offset_to_index, sha_to_index, loose_bodies, parents, children, generation })
    }

    pub fn index_by_sha(&self, sha: &[u8; 20]) -> Option<usize> {
        self.sha_to_index.get(sha).map(|&v| v as usize)
    }

    pub fn index_from_offset(&self, offset: u64) -> Option<usize> {
        self.offset_to_index.get(offset).map(|v| v as usize)
    }

    /// True if this commit's content lives in a loose object (no pack offset).
    pub fn is_loose(&self, idx: usize) -> bool {
        self.commits[idx].offset & LOOSE_OFFSET_MARK != 0
    }

    /// Get the inflated commit body, transparently handling packed (decoded
    /// pack_id picks the right slice) and loose (via the stored body) commits.
    pub fn commit_body(&self, packs: &[&[u8]], idx: usize) -> Vec<u8> {
        if self.is_loose(idx) {
            self.loose_bodies.get(&(idx as u32)).cloned().unwrap_or_default()
        } else {
            let (pack_id, off) = decode_offset(self.commits[idx].offset);
            packs.get(pack_id as usize)
                .and_then(|p| inflate_at(p, off).ok())
                .map(|(_, d)| d)
                .unwrap_or_default()
        }
    }

    /// BFS via parents from `idx`. Inclusive of `idx`.
    pub fn ancestors(&self, idx: usize) -> Vec<usize> {
        let mut visited = vec![false; self.commits.len()];
        let mut queue = VecDeque::new();
        let mut out = Vec::new();
        queue.push_back(idx);
        visited[idx] = true;
        while let Some(i) = queue.pop_front() {
            out.push(i);
            for &p in &self.parents[i] {
                if !visited[p as usize] {
                    visited[p as usize] = true;
                    queue.push_back(p as usize);
                }
            }
        }
        out
    }

    /// BFS via children from `idx`. Inclusive of `idx`.
    pub fn descendants(&self, idx: usize) -> Vec<usize> {
        let mut visited = vec![false; self.commits.len()];
        let mut queue = VecDeque::new();
        let mut out = Vec::new();
        queue.push_back(idx);
        visited[idx] = true;
        while let Some(i) = queue.pop_front() {
            out.push(i);
            for &c in &self.children[i] {
                if !visited[c as usize] {
                    visited[c as usize] = true;
                    queue.push_back(c as usize);
                }
            }
        }
        out
    }

    /// Find the merge commit (parents.len() > 1) that first integrated
    /// `commit_idx` into `head_idx`'s ancestry. "First" = lowest generation
    /// among merges that are both descendants of `commit_idx` AND ancestors
    /// of `head_idx`.
    ///
    /// Useful for "when did this commit land in main?".
    pub fn integration_merge(&self, commit_idx: usize, head_idx: usize) -> Option<usize> {
        let n = self.commits.len();

        // Pass 1: bitset of HEAD's ancestors.
        let mut head_anc = vec![false; n];
        let mut queue = VecDeque::new();
        queue.push_back(head_idx);
        head_anc[head_idx] = true;
        while let Some(i) = queue.pop_front() {
            for &p in &self.parents[i] {
                if !head_anc[p as usize] {
                    head_anc[p as usize] = true;
                    queue.push_back(p as usize);
                }
            }
        }

        // If commit isn't in HEAD's ancestry, no merge integrates it.
        if !head_anc[commit_idx] { return None; }

        // Pass 2: BFS descendants of commit. Candidates = in head_anc AND merge.
        // Among candidates, pick the one with the lowest generation.
        let mut visited = vec![false; n];
        let mut queue = VecDeque::new();
        queue.push_back(commit_idx);
        visited[commit_idx] = true;
        let mut best: Option<(usize, u32)> = None;
        while let Some(i) = queue.pop_front() {
            if i != commit_idx && head_anc[i] && self.parents[i].len() > 1 {
                let g_new = self.generation[i];
                if best.map_or(true, |(_, g)| g_new < g) {
                    best = Some((i, g_new));
                }
            }
            for &c in &self.children[i] {
                if !visited[c as usize] {
                    visited[c as usize] = true;
                    queue.push_back(c as usize);
                }
            }
        }
        best.map(|(i, _)| i)
    }

    pub fn save(&self, path: &Path) -> io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut f = BufWriter::new(File::create(path)?);
        f.write_all(CACHE_MAGIC)?;
        f.write_all(&[CACHE_VERSION])?;
        let n = self.commits.len() as u32;
        f.write_all(&n.to_le_bytes())?;
        for i in 0..self.commits.len() {
            let c = &self.commits[i];
            f.write_all(&c.offset.to_le_bytes())?;
            f.write_all(&c.commit_sha)?;
            f.write_all(&c.root_tree)?;
            f.write_all(&c.author_ts.to_le_bytes())?;
            f.write_all(&self.generation[i].to_le_bytes())?;
            f.write_all(&(self.parents[i].len() as u32).to_le_bytes())?;
            for p in &self.parents[i] { f.write_all(&p.to_le_bytes())?; }
            f.write_all(&(self.children[i].len() as u32).to_le_bytes())?;
            for c in &self.children[i] { f.write_all(&c.to_le_bytes())?; }
            // loose body (length-prefixed; 0 = packed, no body).
            let body = self.loose_bodies.get(&(i as u32));
            let blen = body.map(|b| b.len() as u32).unwrap_or(0);
            f.write_all(&blen.to_le_bytes())?;
            if let Some(b) = body { f.write_all(b)?; }
        }
        Ok(())
    }

    pub fn load(path: &Path) -> io::Result<Self> {
        let mut buf = Vec::new();
        File::open(path)?.read_to_end(&mut buf)?;
        let bad = |m: &'static str| io::Error::new(io::ErrorKind::InvalidData, m);
        if buf.len() < 9 || &buf[0..4] != CACHE_MAGIC { return Err(bad("not a CDAG cache")); }
        if buf[4] != CACHE_VERSION { return Err(bad("CDAG version mismatch")); }
        let n = u32::from_le_bytes(buf[5..9].try_into().unwrap()) as usize;

        let mut commits = Vec::with_capacity(n);
        let mut generation = Vec::with_capacity(n);
        let mut parents: Vec<Vec<u32>> = Vec::with_capacity(n);
        let mut children: Vec<Vec<u32>> = Vec::with_capacity(n);
        let mut offset_to_index = OffsetMap::new(n.next_power_of_two().max(16));
        offset_to_index.reserve(n as u64);
        let mut sha_to_index: HashMap<[u8; 20], u32> = HashMap::with_capacity(n);
        let mut loose_bodies: HashMap<u32, Vec<u8>> = HashMap::new();

        let mut pos = 9usize;
        for i in 0..n {
            let offset = u64::from_le_bytes(buf[pos..pos+8].try_into().unwrap()); pos += 8;
            let sha: [u8;20] = buf[pos..pos+20].try_into().unwrap(); pos += 20;
            let root_tree: [u8;20] = buf[pos..pos+20].try_into().unwrap(); pos += 20;
            let author_ts = i64::from_le_bytes(buf[pos..pos+8].try_into().unwrap()); pos += 8;
            let g = u32::from_le_bytes(buf[pos..pos+4].try_into().unwrap()); pos += 4;
            let pcount = u32::from_le_bytes(buf[pos..pos+4].try_into().unwrap()) as usize; pos += 4;
            let mut p = Vec::with_capacity(pcount);
            for _ in 0..pcount {
                p.push(u32::from_le_bytes(buf[pos..pos+4].try_into().unwrap()));
                pos += 4;
            }
            let ccount = u32::from_le_bytes(buf[pos..pos+4].try_into().unwrap()) as usize; pos += 4;
            let mut c = Vec::with_capacity(ccount);
            for _ in 0..ccount {
                c.push(u32::from_le_bytes(buf[pos..pos+4].try_into().unwrap()));
                pos += 4;
            }
            let blen = u32::from_le_bytes(buf[pos..pos+4].try_into().unwrap()) as usize; pos += 4;
            if blen > 0 {
                loose_bodies.insert(i as u32, buf[pos..pos+blen].to_vec());
                pos += blen;
            }
            if offset & LOOSE_OFFSET_MARK == 0 {
                offset_to_index.set(offset, i as u32);
            }
            sha_to_index.insert(sha, i as u32);
            commits.push(CommitInfo { offset, commit_sha: sha, root_tree, author_ts });
            generation.push(g);
            parents.push(p);
            children.push(c);
        }

        Ok(Self { commits, offset_to_index, sha_to_index, loose_bodies, parents, children, generation })
    }

    /// Is `to` an ancestor of `from`? Uses generation number for fast negative.
    pub fn reaches(&self, from: usize, to: usize) -> bool {
        if self.generation[to] > self.generation[from] { return false; }
        let mut visited = vec![false; self.commits.len()];
        let mut queue = VecDeque::new();
        queue.push_back(from);
        visited[from] = true;
        while let Some(i) = queue.pop_front() {
            if i == to { return true; }
            for &p in &self.parents[i] {
                let p = p as usize;
                if visited[p] || self.generation[p] < self.generation[to] { continue; }
                visited[p] = true;
                queue.push_back(p);
            }
        }
        false
    }
}
