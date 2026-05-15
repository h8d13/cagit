// Unified "open a repo" abstraction. Handles local (multi-pack + loose) and
// remote (single wire pack, blob:none filter) repos. Produces an OpenedRepo
// with everything downstream queries need: packs, sha indexes per pack, DAG,
// resolved HEAD, and loose-object store.

use std::io;
use std::path::{Path, PathBuf};

use memmap2::Mmap;

use crate::dag::{load_or_build_dag, scan_all_loose, CommitDag};
use crate::find::{hex_to_sha, LooseStore, ShaIndex};
use crate::pack_scan::scan_objects_no_idx;
use crate::remote::fetch_pack_with_head;
use crate::util::kind_name;

pub enum PackSource {
    Mapped(Mmap),
    Heap(Vec<u8>),
}

impl PackSource {
    pub fn as_slice(&self) -> &[u8] {
        match self {
            Self::Mapped(m) => m.as_ref(),
            Self::Heap(v)   => v.as_slice(),
        }
    }
}

pub struct OpenedRepo {
    pub packs: Vec<PackSource>,
    pub sha_idxs: Vec<ShaIndex>,
    pub dag: CommitDag,
    pub head_sha: [u8; 20],
    pub dag_cached: bool,
    pub loose: LooseStore,
}

impl OpenedRepo {
    /// Slice views of every pack — useful for passing to resolve_sha_multi.
    pub fn pack_slices(&self) -> Vec<&[u8]> {
        self.packs.iter().map(|p| p.as_slice()).collect()
    }
}

/// Read HEAD's sha (hex) by following .git/HEAD (and packed-refs if needed).
pub fn resolve_head(git_dir: &Path) -> Option<String> {
    let raw = std::fs::read_to_string(git_dir.join("HEAD")).ok()?;
    let trimmed = raw.trim();
    if let Some(refpath) = trimmed.strip_prefix("ref: ") {
        // Loose ref file.
        if let Ok(s) = std::fs::read_to_string(git_dir.join(refpath)) {
            let s = s.trim();
            if s.len() == 40 && s.chars().all(|c| c.is_ascii_hexdigit()) {
                return Some(s.to_string());
            }
        }
        // packed-refs fallback.
        if let Ok(packed) = std::fs::read_to_string(git_dir.join("packed-refs")) {
            for line in packed.lines() {
                if line.starts_with('#') || line.starts_with('^') { continue; }
                let mut parts = line.split_ascii_whitespace();
                let sha = parts.next()?;
                let r = parts.next()?;
                if r == refpath && sha.len() == 40 {
                    return Some(sha.to_string());
                }
            }
        }
        None
    } else if trimmed.len() == 40 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        Some(trimmed.to_string())
    } else {
        None
    }
}

/// Auto-dispatches: URL -> remote fetch with filter=blob:none (commits + trees),
/// else local clone (full pack on disk).
pub fn open_repo(repo_arg: &str) -> io::Result<OpenedRepo> {
    if repo_arg.starts_with("http://") || repo_arg.starts_with("https://") {
        open_remote_repo(repo_arg)
    } else {
        open_local_repo(repo_arg)
    }
}

/// Like `open_repo` but the remote variant fetches the full pack (no filter).
/// Use when blob content is needed (e.g., duper).
pub fn open_repo_full(repo_arg: &str) -> io::Result<OpenedRepo> {
    if repo_arg.starts_with("http://") || repo_arg.starts_with("https://") {
        open_remote_repo_with_mask(repo_arg, 0)
    } else {
        open_local_repo(repo_arg)
    }
}

pub fn open_local_repo(repo_arg: &str) -> io::Result<OpenedRepo> {
    let p = PathBuf::from(repo_arg);
    let git_dir = if p.join(".git").exists() { p.join(".git") } else { p };

    let pack_dir = git_dir.join("objects/pack");
    let mut pairs: Vec<(PathBuf, PathBuf)> = Vec::new();
    if let Ok(rd) = pack_dir.read_dir() {
        for e in rd.filter_map(|e| e.ok()) {
            let p = e.path();
            if p.extension().and_then(|s| s.to_str()) == Some("pack") {
                let ip = p.with_extension("idx");
                if ip.exists() { pairs.push((p, ip)); }
            }
        }
    }
    if pairs.is_empty() {
        return Err(io::Error::new(io::ErrorKind::NotFound,
            format!("no packs in {}", pack_dir.display())));
    }
    pairs.sort();

    let mut mmaps_pack: Vec<Mmap> = Vec::with_capacity(pairs.len());
    let mut mmaps_idx:  Vec<Mmap> = Vec::with_capacity(pairs.len());
    for (pp, ip) in &pairs {
        mmaps_pack.push(unsafe { Mmap::map(&std::fs::File::open(pp)?) }?);
        mmaps_idx.push (unsafe { Mmap::map(&std::fs::File::open(ip)?) }?);
    }
    let sha_idxs: Vec<ShaIndex> = mmaps_idx.iter()
        .map(|i| ShaIndex::from_idx(i))
        .collect();

    let pack_slices: Vec<&[u8]> = mmaps_pack.iter().map(|m| m.as_ref()).collect();
    let (dag, dag_cached) = load_or_build_dag(&pack_slices, &sha_idxs, repo_arg, Some(&git_dir))?;

    let head_sha = resolve_head(&git_dir)
        .and_then(|hex| hex_to_sha(&hex))
        .unwrap_or([0u8; 20]);

    let mut loose = LooseStore::with_capacity(256);
    for (sha, kind, body) in scan_all_loose(&git_dir).unwrap_or_default() {
        loose.insert(sha, kind, body);
    }

    let packs = mmaps_pack.into_iter().map(PackSource::Mapped).collect();
    Ok(OpenedRepo { packs, sha_idxs, dag, head_sha, dag_cached, loose })
}

/// Remote with default kind_mask=0b0001 (commits → filter=blob:none on the wire).
pub fn open_remote_repo(url: &str) -> io::Result<OpenedRepo> {
    open_remote_repo_with_mask(url, 0b0001)
}

/// Remote with arbitrary kind_mask. Pass 0 to disable filter and fetch full pack.
pub fn open_remote_repo_with_mask(url: &str, kind_mask: u8) -> io::Result<OpenedRepo> {
    let (head_sha, pack_bytes) = fetch_pack_with_head(url, kind_mask)?;

    let mut pairs: Vec<([u8; 20], u64)> = Vec::new();
    scan_objects_no_idx(&pack_bytes, 0, |kind, data, offset| {
        let header = format!("{} {}\0", kind_name(kind), data.len());
        let mut h = sha1_smol::Sha1::new();
        h.update(header.as_bytes());
        h.update(data);
        pairs.push((h.digest().bytes(), offset));
        true
    })?;
    let sha_idxs = vec![ShaIndex::from_pairs(&pairs)];

    let pack_slices: Vec<&[u8]> = vec![&pack_bytes];
    let (dag, dag_cached) = load_or_build_dag(&pack_slices, &sha_idxs, url, None)?;

    Ok(OpenedRepo {
        packs: vec![PackSource::Heap(pack_bytes)],
        sha_idxs,
        dag,
        head_sha,
        dag_cached,
        loose: LooseStore::with_capacity(0),
    })
}
