// Commit DAG with parent map, child map, and generation numbers.
// Built in one pass over all commits in the pack.
// See: git/Documentation/technical/commit-graph.adoc

use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::io::{self, BufWriter, Read as _, Write as _};
use std::path::{Path, PathBuf};

use flate2::read::ZlibDecoder;

use crate::find::{hex_to_sha, inflate_at, resolve_type, CommitInfo, ShaIndex};

/// Derive a stable cache dir for a repo arg (URL or local path).
/// Layout: <base>/<repo>/. Override base via CAGIT_CACHE_DIR.
pub fn cache_dir_for(repo_arg: &str) -> PathBuf {
    let base = std::env::var("CAGIT_CACHE_DIR").unwrap_or_else(|_| "/tmp/cagit-cache".to_string());
    let repo = if repo_arg.starts_with("http://") || repo_arg.starts_with("https://") {
        let after_scheme = repo_arg.split("://").nth(1).unwrap_or("");
        let parts: Vec<&str> = after_scheme.trim_end_matches('/').split('/').collect();
        parts.last().map(|s| s.trim_end_matches(".git").to_string()).unwrap_or_else(|| "repo".to_string())
    } else {
        let p = PathBuf::from(repo_arg);
        let canon = p.canonicalize().unwrap_or(p);
        let stripped = if canon.file_name().and_then(|s| s.to_str()) == Some(".git") {
            canon.parent().unwrap_or(canon.as_path()).to_path_buf()
        } else {
            canon
        };
        stripped.file_name().and_then(|s| s.to_str()).unwrap_or("repo").to_string()
    };
    PathBuf::from(base).join(repo)
}

/// Pack's trailing 20-byte sha = stable content fingerprint.
pub fn pack_fingerprint(pack: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(40);
    for b in &pack[pack.len() - 20..] {
        write!(s, "{b:02x}").unwrap();
    }
    s
}

/// Cache key for a multi-pack repo: concatenate sorted pack fingerprints (each
/// shortened to 16 hex chars).
pub fn multi_pack_fingerprint(packs: &[&[u8]]) -> String {
    let mut parts: Vec<String> = packs.iter().map(|p| pack_fingerprint(p)[..16].to_string()).collect();
    parts.sort();
    parts.join("-")
}

/// Load DAG from cache if present and matching the packs' combined fingerprint;
/// else build fresh and persist for next time.
pub fn load_or_build_dag(
    packs: &[&[u8]],
    sha_idxs: &[ShaIndex],
    repo_arg: &str,
    git_dir: Option<&Path>,
) -> io::Result<(CommitDag, bool)> {
    let dir = cache_dir_for(repo_arg);
    let cache_path = dir.join(format!("{}.dag", multi_pack_fingerprint(packs)));
    if cache_path.exists() {
        if let Ok(dag) = CommitDag::load(&cache_path) {
            return Ok((dag, true));
        }
    }
    let pairs: Vec<(&[u8], &ShaIndex)> = packs.iter().copied()
        .zip(sha_idxs.iter())
        .collect();
    let dag = CommitDag::build(&pairs, git_dir)?;
    let _ = dag.save(&cache_path);
    Ok((dag, false))
}

const CACHE_MAGIC: &[u8; 4] = b"CDAG";
const CACHE_VERSION: u8 = 5; // CSR adjacency + sorted sha index (no hashmap rebuild on load)
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
    // Sorted (sha, index) pairs - binary search replaces hashmap rebuild on load.
    sha_sorted: Vec<([u8; 20], u32)>,
    // Loose commit bodies, keyed by index in `commits` (so we can inflate for summary).
    pub loose_bodies: HashMap<u32, Vec<u8>>,
    // CSR adjacency. parents_of(i) = parent_data[parent_offsets[i]..parent_offsets[i+1]]
    parent_data: Vec<u32>,
    parent_offsets: Vec<u32>, // len = commits.len() + 1
    child_data: Vec<u32>,
    child_offsets: Vec<u32>,  // len = commits.len() + 1
    pub generation: Vec<u32>,
}

fn vec_to_csr(adj: &[Vec<u32>]) -> (Vec<u32>, Vec<u32>) {
    let total: usize = adj.iter().map(|v| v.len()).sum();
    let mut offsets = Vec::with_capacity(adj.len() + 1);
    let mut data = Vec::with_capacity(total);
    offsets.push(0u32);
    for row in adj {
        data.extend_from_slice(row);
        offsets.push(data.len() as u32);
    }
    (data, offsets)
}

// Walk <git_dir>/objects/<2>/<38> and return (sha, kind, inflated body) for
// every loose object. Kind: 1=commit, 2=tree, 3=blob, 4=tag.
pub fn scan_all_loose(git_dir: &Path) -> io::Result<Vec<([u8; 20], u8, Vec<u8>)>> {
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
            if let Some(nul) = decompressed.iter().position(|&b| b == 0) {
                let header = &decompressed[..nul];
                let kind: u8 = if header.starts_with(b"commit ") { 1 }
                          else if header.starts_with(b"tree ")   { 2 }
                          else if header.starts_with(b"blob ")   { 3 }
                          else if header.starts_with(b"tag ")    { 4 }
                          else { continue };
                out.push((sha, kind, decompressed[nul + 1..].to_vec()));
            }
        }
    }
    Ok(out)
}

// Back-compat helper used by CommitDag::build: filter to commits only.
pub fn scan_loose_commits(git_dir: &Path) -> io::Result<Vec<([u8; 20], Vec<u8>)>> {
    Ok(scan_all_loose(git_dir)?.into_iter()
        .filter(|(_, k, _)| *k == 1)
        .map(|(s, _, b)| (s, b))
        .collect())
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
        let mut sha_sorted: Vec<([u8; 20], u32)> = Vec::new();
        let mut loose_bodies: HashMap<u32, Vec<u8>> = HashMap::new();
        // Temporary sha->index map used only during build for parent resolution.
        let mut sha_build_map = crate::find::ShaU32Map::with_capacity(1024);

        // Pass 1a: packed commits across all packs. Encode pack_id in offset.
        for (pack_id, (pack, sha_idx)) in packs.iter().enumerate() {
            for entry in sha_idx.slab() {
                if resolve_type(pack, entry.offset) != 1 { continue; }
                let (_, data) = inflate_at(pack, entry.offset)?;
                if let Some((root_tree, author_ts, parents)) = parse_commit_full(&data) {
                    if sha_build_map.get(&entry.sha).is_some() { continue; }
                    let idx = commits.len() as u32;
                    let encoded = encode_offset(pack_id as u8, entry.offset);
                    sha_build_map.insert(entry.sha, idx);
                    sha_sorted.push((entry.sha, idx));
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
                if sha_build_map.get(&sha).is_some() { continue; }
                if let Some((root_tree, author_ts, parents)) = parse_commit_full(&body) {
                    let idx = commits.len() as u32;
                    let synth_offset = LOOSE_OFFSET_MARK | idx as u64;
                    sha_build_map.insert(sha, idx);
                    sha_sorted.push((sha, idx));
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
        let mut adj_parents: Vec<Vec<u32>> = Vec::with_capacity(n);
        let mut adj_children: Vec<Vec<u32>> = vec![Vec::new(); n];
        for i in 0..n {
            let mut p_indices: Vec<u32> = Vec::new();
            for psha in &parent_shas[i] {
                if let Some(pidx) = sha_build_map.get(psha) {
                    p_indices.push(pidx);
                    adj_children[pidx as usize].push(i as u32);
                }
            }
            adj_parents.push(p_indices);
        }

        // Kahn's: topological generation.
        let mut in_degree: Vec<u32> = adj_parents.iter().map(|p| p.len() as u32).collect();
        let mut queue: VecDeque<usize> = (0..n).filter(|&i| in_degree[i] == 0).collect();
        let mut generation: Vec<u32> = vec![0; n];
        while let Some(i) = queue.pop_front() {
            let max_parent_gen = adj_parents[i].iter()
                .map(|&p| generation[p as usize])
                .max()
                .unwrap_or(0);
            generation[i] = max_parent_gen + 1;
            for &c in &adj_children[i] {
                in_degree[c as usize] -= 1;
                if in_degree[c as usize] == 0 {
                    queue.push_back(c as usize);
                }
            }
        }

        let (parent_data, parent_offsets) = vec_to_csr(&adj_parents);
        let (child_data, child_offsets)   = vec_to_csr(&adj_children);
        sha_sorted.sort_unstable_by_key(|(s, _)| *s);

        Ok(Self { commits, sha_sorted, loose_bodies,
                  parent_data, parent_offsets, child_data, child_offsets, generation })
    }

    pub fn index_by_sha(&self, sha: &[u8; 20]) -> Option<usize> {
        self.sha_sorted
            .binary_search_by_key(sha, |(s, _)| *s)
            .ok()
            .map(|pos| self.sha_sorted[pos].1 as usize)
    }

    /// True if this commit's content lives in a loose object (no pack offset).
    pub fn is_loose(&self, idx: usize) -> bool {
        self.commits[idx].offset & LOOSE_OFFSET_MARK != 0
    }

    pub fn parents_of(&self, i: usize) -> &[u32] {
        let s = self.parent_offsets[i] as usize;
        let e = self.parent_offsets[i + 1] as usize;
        &self.parent_data[s..e]
    }

    pub fn children_of(&self, i: usize) -> &[u32] {
        let s = self.child_offsets[i] as usize;
        let e = self.child_offsets[i + 1] as usize;
        &self.child_data[s..e]
    }

    pub fn parent_count(&self, i: usize) -> usize {
        (self.parent_offsets[i + 1] - self.parent_offsets[i]) as usize
    }

    pub fn child_count(&self, i: usize) -> usize {
        (self.child_offsets[i + 1] - self.child_offsets[i]) as usize
    }

    /// First-parent of `idx`, or None for root commits.
    pub fn first_parent(&self, idx: usize) -> Option<usize> {
        self.parents_of(idx).first().map(|&p| p as usize)
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
            for &p in self.parents_of(i) {
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
            for &c in self.children_of(i) {
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
            for &p in self.parents_of(i) {
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
            if i != commit_idx && head_anc[i] && self.parent_count(i) > 1 {
                let g_new = self.generation[i];
                if best.map_or(true, |(_, g)| g_new < g) {
                    best = Some((i, g_new));
                }
            }
            for &c in self.children_of(i) {
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
        let n = self.commits.len() as u32;
        let tp = self.parent_data.len() as u32;
        let tc = self.child_data.len() as u32;
        // Header
        f.write_all(CACHE_MAGIC)?;
        f.write_all(&[CACHE_VERSION])?;
        f.write_all(&n.to_le_bytes())?;
        f.write_all(&tp.to_le_bytes())?;
        f.write_all(&tc.to_le_bytes())?;
        // Commit array: offset(8) + sha(20) + tree(20) + ts(8) + gen(4) = 60 bytes each
        for i in 0..self.commits.len() {
            let c = &self.commits[i];
            f.write_all(&c.offset.to_le_bytes())?;
            f.write_all(&c.commit_sha)?;
            f.write_all(&c.root_tree)?;
            f.write_all(&c.author_ts.to_le_bytes())?;
            f.write_all(&self.generation[i].to_le_bytes())?;
        }
        // Parent CSR
        for &o in &self.parent_offsets { f.write_all(&o.to_le_bytes())?; }
        for &v in &self.parent_data    { f.write_all(&v.to_le_bytes())?; }
        // Child CSR
        for &o in &self.child_offsets  { f.write_all(&o.to_le_bytes())?; }
        for &v in &self.child_data     { f.write_all(&v.to_le_bytes())?; }
        // Sorted sha index: n * (sha20 + u32) = n * 24 bytes
        for (sha, idx) in &self.sha_sorted {
            f.write_all(sha)?;
            f.write_all(&idx.to_le_bytes())?;
        }
        // Loose bodies (sparse)
        let num_loose = self.loose_bodies.len() as u32;
        f.write_all(&num_loose.to_le_bytes())?;
        for (&idx, body) in &self.loose_bodies {
            f.write_all(&idx.to_le_bytes())?;
            f.write_all(&(body.len() as u32).to_le_bytes())?;
            f.write_all(body)?;
        }
        Ok(())
    }

    pub fn load(path: &Path) -> io::Result<Self> {
        let mut buf = Vec::new();
        File::open(path)?.read_to_end(&mut buf)?;
        let bad = |m: &'static str| io::Error::new(io::ErrorKind::InvalidData, m);
        // Header: magic(4) + version(1) + n(4) + total_parents(4) + total_children(4) = 17
        if buf.len() < 17 || &buf[0..4] != CACHE_MAGIC { return Err(bad("not a CDAG cache")); }
        if buf[4] != CACHE_VERSION { return Err(bad("CDAG version mismatch")); }
        let n  = u32::from_le_bytes(buf[5..9].try_into().unwrap())   as usize;
        let tp = u32::from_le_bytes(buf[9..13].try_into().unwrap())  as usize;
        let tc = u32::from_le_bytes(buf[13..17].try_into().unwrap()) as usize;

        // Pre-allocate everything in one shot - no per-commit allocs, no hashmap rebuilds.
        let mut commits        = Vec::with_capacity(n);
        let mut generation     = Vec::with_capacity(n);
        let mut parent_offsets = Vec::with_capacity(n + 1);
        let mut parent_data    = Vec::with_capacity(tp);
        let mut child_offsets  = Vec::with_capacity(n + 1);
        let mut child_data     = Vec::with_capacity(tc);
        let mut sha_sorted     = Vec::with_capacity(n);
        let mut loose_bodies: HashMap<u32, Vec<u8>> = HashMap::new();

        // Commit array: 60 bytes per commit.
        let mut pos = 17usize;
        for _ in 0..n {
            let offset    = u64::from_le_bytes(buf[pos..pos+8].try_into().unwrap());  pos += 8;
            let sha: [u8;20] = buf[pos..pos+20].try_into().unwrap();                  pos += 20;
            let root_tree: [u8;20] = buf[pos..pos+20].try_into().unwrap();            pos += 20;
            let author_ts = i64::from_le_bytes(buf[pos..pos+8].try_into().unwrap());  pos += 8;
            let g         = u32::from_le_bytes(buf[pos..pos+4].try_into().unwrap());  pos += 4;
            commits.push(CommitInfo { offset, commit_sha: sha, root_tree, author_ts });
            generation.push(g);
        }
        // Parent CSR
        for _ in 0..=n { parent_offsets.push(u32::from_le_bytes(buf[pos..pos+4].try_into().unwrap())); pos += 4; }
        for _ in 0..tp { parent_data.push(u32::from_le_bytes(buf[pos..pos+4].try_into().unwrap()));    pos += 4; }
        // Child CSR
        for _ in 0..=n { child_offsets.push(u32::from_le_bytes(buf[pos..pos+4].try_into().unwrap()));  pos += 4; }
        for _ in 0..tc { child_data.push(u32::from_le_bytes(buf[pos..pos+4].try_into().unwrap()));     pos += 4; }
        // SHA sorted index: n * 24 bytes, read directly, no sort or hashmap.
        for _ in 0..n {
            let sha: [u8;20] = buf[pos..pos+20].try_into().unwrap();                  pos += 20;
            let idx = u32::from_le_bytes(buf[pos..pos+4].try_into().unwrap());        pos += 4;
            sha_sorted.push((sha, idx));
        }
        // Loose bodies
        if pos + 4 <= buf.len() {
            let num_loose = u32::from_le_bytes(buf[pos..pos+4].try_into().unwrap()) as usize; pos += 4;
            for _ in 0..num_loose {
                let idx  = u32::from_le_bytes(buf[pos..pos+4].try_into().unwrap()); pos += 4;
                let blen = u32::from_le_bytes(buf[pos..pos+4].try_into().unwrap()) as usize; pos += 4;
                loose_bodies.insert(idx, buf[pos..pos+blen].to_vec()); pos += blen;
            }
        }

        Ok(Self { commits, sha_sorted, loose_bodies,
                  parent_data, parent_offsets, child_data, child_offsets, generation })
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
            for &p in self.parents_of(i) {
                let p = p as usize;
                if visited[p] || self.generation[p] < self.generation[to] { continue; }
                visited[p] = true;
                queue.push_back(p);
            }
        }
        false
    }
}
