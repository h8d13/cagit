use std::fmt::Write as _;
use std::io;
use std::path::{Path, PathBuf};

use cagit::pack_scan::{idx_sha_map, scan_objects, scan_objects_no_idx};
use cagit::remote::fetch_pack;
use memmap2::Mmap;
use regex::bytes::Regex;

fn print_usage() {
    eprintln!("usage:");
    eprintln!("  cagit <repo> <type> <query> [-e] [-s] [oldest|newest|N]");
    eprintln!("    scan pack for objects of <type> matching regex <query>");
    eprintln!("    type:           blob | commit | tree | tag | all");
    eprintln!("");
    eprintln!("  cagit <repo> find <sha> [N]");
    eprintln!("    N oldest commits whose tree contains <sha> (default N=1)");
    eprintln!("");
    eprintln!("  cagit <repo> dag [<sha>]");
    eprintln!("    DAG stats; with sha: gen/ancestors/descendants for that commit");
    eprintln!("");
    eprintln!("  cagit <repo> integrated <commit_sha> [<head_sha>]");
    eprintln!("    merge commit that first integrated <commit_sha> into HEAD");
    eprintln!("");
    eprintln!("  cagit comp <base> <target1> [<target2> ...]");
    eprintln!("    N-way ancestor diff + LCA across repos (paths or URLs)");
    eprintln!("");
    eprintln!("  cagit comp-has <sha> <repo1> [<repo2> ...]");
    eprintln!("    yes/no presence of <sha> in each repo (with HEAD-reachability)");
    eprintln!("");
    eprintln!("flags:");
    eprintln!("  -e, --exact         exact word match (regex wrap \\b(?:...)\\b)");
    eprintln!("  -s, --summary       include commit author + first-line summary");
    eprintln!("  CAGIT_CACHE_DIR=    override /tmp/cagit-cache");
}

fn main() {
    let raw: Vec<String> = std::env::args().collect();

    let mut exact   = false;
    let mut summary = false;
    let mut args: Vec<&String> = Vec::with_capacity(raw.len());
    args.push(&raw[0]);
    for a in raw.iter().skip(1) {
        match a.as_str() {
            "--help" | "-h" => { print_usage(); return; }
            "--exact"       => exact = true,
            "--summary"     => summary = true,
            s if s.starts_with("--") => {
                eprintln!("unknown option '{s}' (try --help)");
                std::process::exit(1);
            }
            // combined short flags: -e, -s, -es, -se
            s if s.len() > 1 && s.starts_with('-')
                && s[1..].chars().all(|c| "es".contains(c)) =>
            {
                exact   |= s.contains('e');
                summary |= s.contains('s');
            }
            _ => args.push(a),
        }
    }

    // `cagit comp <base> <target1> [<target2> ...]` — N-way ancestor diff + LCA.
    if args.len() >= 2 && args[1].as_str() == "comp" {
        if args.len() < 4 {
            eprintln!("usage: cagit comp <base> <target1> [<target2> ...]");
            std::process::exit(1);
        }
        let repos: Vec<&str> = args[2..].iter().map(|s| s.as_str()).collect();
        run_compare(&repos, summary);
        return;
    }

    // `cagit comp-has <sha> <repo1> [<repo2> ...]` — for each repo, does this
    // commit sha exist anywhere in its DAG? Yes/no per repo.
    if args.len() >= 2 && args[1].as_str() == "comp-has" {
        if args.len() < 4 {
            eprintln!("usage: cagit comp-has <sha> <repo1> [<repo2> ...]");
            std::process::exit(1);
        }
        let sha_hex = args[2].as_str();
        let repos: Vec<&str> = args[3..].iter().map(|s| s.as_str()).collect();
        run_comp_has(sha_hex, &repos, summary);
        return;
    }

    // `dag` is the one subcommand that's valid with just `<repo> dag` (no extra args).
    let bare_dag = args.len() == 3 && args[2].as_str() == "dag";
    if args.len() < 4 && !bare_dag {
        print_usage();
        std::process::exit(1);
    }

    let repo_path = PathBuf::from(args[1].as_str());
    let is_remote = args[1].starts_with("https://") || args[1].starts_with("http://");
    let git_dir = if repo_path.join(".git").exists() {
        repo_path.join(".git")
    } else {
        repo_path.clone()
    };

    if args[2].as_str() == "find" {
        let limit: usize = args.get(4).and_then(|s| s.parse().ok()).unwrap_or(1);
        if is_remote {
            run_find_remote(args[1].as_str(), args[3].as_str(), limit, summary);
        } else {
            run_find(&git_dir, args[3].as_str(), limit, summary);
        }
        return;
    }

    if args[2].as_str() == "dag" {
        if is_remote {
            eprintln!("dag: local only for now");
            std::process::exit(1);
        }
        let sha_arg = args.get(3).map(|s| s.as_str());
        run_dag(&git_dir, args[1].as_str(), sha_arg);
        return;
    }

    if args[2].as_str() == "integrated" {
        if is_remote {
            eprintln!("integrated: local only for now");
            std::process::exit(1);
        }
        // `cagit <repo> integrated <commit_sha> [<head_sha>]`
        // If head_sha omitted, resolve from .git/HEAD.
        let commit_hex = args.get(3).map(|s| s.as_str()).unwrap_or_else(|| {
            print_usage();
            std::process::exit(1);
        });
        let head_hex_owned: Option<String> = match args.get(4) {
            Some(s) => Some(s.to_string()),
            None => resolve_head(&git_dir),
        };
        let Some(head_hex) = head_hex_owned else {
            eprintln!("could not resolve HEAD; pass <head_sha> explicitly");
            std::process::exit(1);
        };
        run_integrated(&git_dir, args[1].as_str(), commit_hex, &head_hex, summary);
        return;
    }

    let kind_mask: u8 = match args[2].as_str() {
        "commit" | "commits" => 0b0001,
        "tree"   | "trees"   => 0b0010,
        "blob"   | "blobs"   => 0b0100,
        "tag"    | "tags"    => 0b1000,
        "all"                => 0,
        other => {
            eprintln!("unknown type '{other}' - use: blob commit tree tag all");
            std::process::exit(1);
        }
    };

    let pattern = if exact {
        format!(r"\b(?:{})\b", args[3])
    } else {
        args[3].to_string()
    };
    let re = match Regex::new(&pattern) {
        Ok(r) => r,
        Err(e) => { eprintln!("invalid regex: {e}"); std::process::exit(1); }
    };

    enum Order { Scan(usize), Oldest(usize), Newest(usize) }
    let order = match args.get(4).map(|s| s.as_str()) {
        Some("oldest") => Order::Oldest(args.get(5).and_then(|s| s.parse().ok()).unwrap_or(10)),
        Some("newest") => Order::Newest(args.get(5).and_then(|s| s.parse().ok()).unwrap_or(10)),
        Some(n)        => Order::Scan(n.parse().unwrap_or(10)),
        None           => Order::Scan(10),
    };

    // for Scan mode, stop decompressing once we have enough hits
    let scan_limit = match order { Order::Scan(n) => n, _ => usize::MAX };

    // (sort_key, sha40, kind, summary)
    let mut results: Vec<(i64, String, u8, String)> = Vec::new();

    if is_remote {
        let pack = match fetch_pack(args[1], kind_mask) {
            Ok(p)  => p,
            Err(e) => { eprintln!("fetch: {e}"); std::process::exit(1); }
        };
        let _ = scan_objects_no_idx(&pack, kind_mask, |kind, data, _offset| {
            if !re.is_match(data) { return true; }
            let sha40 = object_sha(kind, data);
            let summ  = if summary { make_summary(kind, data, &re) } else { String::new() };
            let ts    = if kind == 1 { commit_timestamp(data) } else { 0 };
            results.push((ts, sha40, kind, summ));
            results.len() < scan_limit
        });
    } else {
        // for each .pack, find the sibling .idx by extension swap
        let pack_dir = git_dir.join("objects/pack");
        let mut pack_paths: Vec<PathBuf> = Vec::new();
        if let Ok(rd) = pack_dir.read_dir() {
            for e in rd.filter_map(|e| e.ok()) {
                let p = e.path();
                if p.extension().and_then(|s| s.to_str()) == Some("pack") {
                    pack_paths.push(p);
                }
            }
        }

        if pack_paths.is_empty() {
            eprintln!("no pack files found in {}", pack_dir.display());
            std::process::exit(1);
        }

        for pp in &pack_paths {
            if results.len() >= scan_limit { break; }
            let ip = pp.with_extension("idx");
            if !ip.exists() { continue; }
            let pack = match std::fs::File::open(pp).and_then(|f| unsafe { Mmap::map(&f) }) {
                Ok(m)  => m,
                Err(e) => { eprintln!("mmap {}: {e}", pp.display()); continue }
            };
            let idx = match std::fs::File::open(&ip).and_then(|f| unsafe { Mmap::map(&f) }) {
                Ok(m)  => m,
                Err(e) => { eprintln!("mmap {}: {e}", ip.display()); continue }
            };
            let (sha_slab, sha_index) = idx_sha_map(&idx);

            let _ = scan_objects(&pack, &idx, kind_mask, |kind, data, offset| {
                if !re.is_match(data) { return true; }
                let sha40 = sha_index.get(offset)
                    .map(|i| hex40(&sha_slab[i as usize]))
                    .unwrap_or_else(|| "?".repeat(40));
                let summ  = if summary { make_summary(kind, data, &re) } else { String::new() };
                let ts    = if kind == 1 { commit_timestamp(data) } else { 0 };
                results.push((ts, sha40, kind, summ));
                results.len() < scan_limit
            });
        }
    }

    match order {
        Order::Oldest(n) => { results.sort_unstable_by_key(|r| r.0);                        results.truncate(n); }
        Order::Newest(n) => { results.sort_unstable_by_key(|r| std::cmp::Reverse(r.0));     results.truncate(n); }
        Order::Scan(n)   => results.truncate(n),
    }

    if results.is_empty() {
        eprintln!("no matches");
        return;
    }

    for (_, sha40, kind, summ) in &results {
        if summary {
            println!("{sha40}  {}  {summ}", kind_name(*kind));
        } else {
            println!("{sha40}  {}", kind_name(*kind));
        }
    }
}

fn make_summary(kind: u8, data: &[u8], re: &Regex) -> String {
    match kind {
        1 => commit_summary(data),
        2 => tree_summary(data, re),
        3 => blob_summary(data, re),
        4 => tag_summary(data),
        _ => String::new(),
    }
}

fn commit_timestamp(data: &[u8]) -> i64 {
    let text = String::from_utf8_lossy(data);
    text.lines()
        .find(|l| l.starts_with("author "))
        .and_then(|l| l.split_ascii_whitespace().nth_back(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

fn commit_summary(data: &[u8]) -> String {
    let text = String::from_utf8_lossy(data);
    let author = text.lines()
        .find(|l| l.starts_with("author "))
        .and_then(|l| l.strip_prefix("author "))
        .and_then(|l| l.split('<').next())
        .map(|s| s.trim())
        .unwrap_or("?");
    let msg = text.find("\n\n")
        .map(|i| text[i + 2..].trim_start())
        .unwrap_or("");
    let first_line = msg.lines().next().unwrap_or("").trim();
    format!("{author}: {first_line}")
}

fn blob_summary(data: &[u8], re: &Regex) -> String {
    let Some(m) = re.find(data) else { return String::new() };
    let pos = m.start();
    let line_start = data[..pos].iter().rposition(|&b| b == b'\n').map(|p| p + 1).unwrap_or(0);
    let line_end = data[pos..].iter().position(|&b| b == b'\n').map(|p| p + pos).unwrap_or(data.len());
    let line = String::from_utf8_lossy(&data[line_start..line_end]);
    let t = line.trim();
    if t.len() > 100 { format!("{}…", &t[..100]) } else { t.to_string() }
}

fn tree_summary(data: &[u8], re: &Regex) -> String {
    // tree entry: "<mode> <name>\0<sha20>"
    let mut pos = 0;
    while pos < data.len() {
        let Some(sp)  = data[pos..].iter().position(|&b| b == b' ') else { break };
        let Some(nul) = data[pos + sp..].iter().position(|&b| b == 0) else { break };
        let name = &data[pos + sp + 1..pos + sp + nul];
        if re.is_match(name) {
            return String::from_utf8_lossy(name).into_owned();
        }
        pos += sp + nul + 1 + 20;
    }
    String::new()
}

fn tag_summary(data: &[u8]) -> String {
    String::from_utf8_lossy(data).lines().next().unwrap_or("").to_string()
}

fn kind_name(kind: u8) -> &'static str {
    match kind { 1 => "commit", 2 => "tree", 3 => "blob", 4 => "tag", _ => "?" }
}

fn hex40(sha: &[u8; 20]) -> String {
    let mut s = String::with_capacity(40);
    for b in sha { write!(s, "{b:02x}").unwrap(); }
    s
}

// Compute the git object SHA from kind + decompressed content.
// git SHA = sha1("<type> <size>\0<content>")
fn object_sha(kind: u8, data: &[u8]) -> String {
    let header = format!("{} {}\0", kind_name(kind), data.len());
    let mut h = sha1_smol::Sha1::new();
    h.update(header.as_bytes());
    h.update(data);
    let bytes = h.digest().bytes();
    hex40(&bytes)
}

// N oldest commits whose root tree (recursively) contains target. Distinct
// from `git log --find-object`, which only reports diff-add/remove commits.
// cagit reports historical containment.
fn run_find(
    git_dir: &Path,
    target_hex: &str,
    limit: usize,
    summary: bool,
) {
    let Some(target) = cagit::find::hex_to_sha(target_hex) else {
        eprintln!("invalid target sha: {target_hex}");
        std::process::exit(1);
    };

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
        eprintln!("no pack found in {}", pack_dir.display());
        std::process::exit(1);
    }

    // Per-pack: find up to `limit` matches in requested order. Inflate body
    // eagerly when -s is requested so we can drop the mmap before the next pack.
    let mut all: Vec<(cagit::find::CommitInfo, Vec<u8>)> = Vec::new();
    for (pp, ip) in &pairs {
        let pack = match std::fs::File::open(pp).and_then(|f| unsafe { Mmap::map(&f) }) {
            Ok(m)  => m,
            Err(e) => { eprintln!("mmap {}: {e}", pp.display()); continue }
        };
        let idx = match std::fs::File::open(ip).and_then(|f| unsafe { Mmap::map(&f) }) {
            Ok(m)  => m,
            Err(e) => { eprintln!("mmap {}: {e}", ip.display()); continue }
        };
        let sha_idx = cagit::find::ShaIndex::from_idx(&idx);
        match cagit::find::find_oldest(&pack, &sha_idx, &target, limit) {
            Ok(results) => for c in results {
                let body = if summary {
                    cagit::find::inflate_at(&pack, c.offset).map(|(_, d)| d).unwrap_or_default()
                } else { Vec::new() };
                all.push((c, body));
            },
            Err(e) => eprintln!("scan {}: {e}", pp.display()),
        }
    }

    // Merge across packs: sort oldest-first and truncate.
    all.sort_by_key(|(c, _)| c.author_ts);
    all.truncate(limit);

    if all.is_empty() {
        eprintln!("not found");
        std::process::exit(1);
    }
    for (c, body) in &all {
        let sha40 = hex40(&c.commit_sha);
        if summary {
            println!("{sha40}  commit  {}", commit_summary(body));
        } else {
            println!("{sha40}  commit");
        }
    }
}

// Derive a stable cache dir for a given repo arg (URL or local path).
// Layout: <base>/<repo>/. Override base via CAGIT_CACHE_DIR.
fn cache_dir_for(repo_arg: &str) -> PathBuf {
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

// Pack's trailing 20-byte sha = stable content fingerprint.
fn pack_fingerprint(pack: &[u8]) -> String {
    let mut s = String::with_capacity(40);
    use std::fmt::Write as _;
    for b in &pack[pack.len() - 20..] {
        write!(s, "{b:02x}").unwrap();
    }
    s
}

// Cache key for a multi-pack repo: concatenate sorted pack fingerprints (each
// shortened to 16 hex chars to keep filenames reasonable).
fn multi_pack_fingerprint(packs: &[&[u8]]) -> String {
    let mut parts: Vec<String> = packs.iter().map(|p| pack_fingerprint(p)[..16].to_string()).collect();
    parts.sort();
    parts.join("-")
}

// Load DAG from cache if present and matching the packs' combined fingerprint;
// else build fresh and persist for next time.
fn load_or_build_dag(
    packs: &[&[u8]],
    sha_idxs: &[cagit::find::ShaIndex],
    repo_arg: &str,
    git_dir: Option<&Path>,
) -> io::Result<(cagit::dag::CommitDag, bool)> {
    let dir = cache_dir_for(repo_arg);
    let cache_path = dir.join(format!("{}.dag", multi_pack_fingerprint(packs)));
    if cache_path.exists() {
        if let Ok(dag) = cagit::dag::CommitDag::load(&cache_path) {
            return Ok((dag, true));
        }
    }
    let pairs: Vec<(&[u8], &cagit::find::ShaIndex)> = packs.iter().copied()
        .zip(sha_idxs.iter())
        .collect();
    let dag = cagit::dag::CommitDag::build(&pairs, git_dir)?;
    let _ = dag.save(&cache_path);
    Ok((dag, false))
}

// Read HEAD's sha (hex) by following .git/HEAD (and packed-refs if needed).
fn resolve_head(git_dir: &Path) -> Option<String> {
    let raw = std::fs::read_to_string(git_dir.join("HEAD")).ok()?;
    let trimmed = raw.trim();
    if let Some(refpath) = trimmed.strip_prefix("ref: ") {
        // Loose ref.
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

enum PackSource {
    Mapped(Mmap),
    Heap(Vec<u8>),
}
impl PackSource {
    fn as_slice(&self) -> &[u8] {
        match self {
            Self::Mapped(m) => m.as_ref(),
            Self::Heap(v)   => v.as_slice(),
        }
    }
}

struct OpenedRepo {
    packs: Vec<PackSource>,
    dag: cagit::dag::CommitDag,
    head_sha: [u8; 20],
    dag_cached: bool,
}

fn open_repo(repo_arg: &str) -> io::Result<OpenedRepo> {
    if repo_arg.starts_with("http://") || repo_arg.starts_with("https://") {
        open_remote_repo(repo_arg)
    } else {
        open_local_repo(repo_arg)
    }
}

fn open_local_repo(repo_arg: &str) -> io::Result<OpenedRepo> {
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
    let sha_idxs: Vec<cagit::find::ShaIndex> = mmaps_idx.iter()
        .map(|i| cagit::find::ShaIndex::from_idx(i))
        .collect();

    let pack_slices: Vec<&[u8]> = mmaps_pack.iter().map(|m| m.as_ref()).collect();
    let (dag, dag_cached) = load_or_build_dag(&pack_slices, &sha_idxs, repo_arg, Some(&git_dir))?;

    let head_sha = resolve_head(&git_dir)
        .and_then(|hex| cagit::find::hex_to_sha(&hex))
        .unwrap_or([0u8; 20]);

    let packs = mmaps_pack.into_iter().map(PackSource::Mapped).collect();
    Ok(OpenedRepo { packs, dag, head_sha, dag_cached })
}

// Remote: one pack fetched over HTTP. kind_mask=0b0001 → just commits (filter=blob:none).
fn open_remote_repo(url: &str) -> io::Result<OpenedRepo> {
    let (head_sha, pack_bytes) = cagit::remote::fetch_pack_with_head(url, 0b0001)?;

    // Build ShaIndex by walking + hashing every object in the wire pack.
    let mut pairs: Vec<([u8; 20], u64)> = Vec::new();
    cagit::pack_scan::scan_objects_no_idx(&pack_bytes, 0, |kind, data, offset| {
        let header = format!("{} {}\0", kind_name(kind), data.len());
        let mut h = sha1_smol::Sha1::new();
        h.update(header.as_bytes());
        h.update(data);
        pairs.push((h.digest().bytes(), offset));
        true
    })?;
    let sha_idx = cagit::find::ShaIndex::from_pairs(&pairs);

    let pack_slices: Vec<&[u8]> = vec![&pack_bytes];
    let (dag, dag_cached) = load_or_build_dag(&pack_slices, &[sha_idx], url, None)?;

    Ok(OpenedRepo {
        packs: vec![PackSource::Heap(pack_bytes)],
        dag,
        head_sha,
        dag_cached,
    })
}

fn pack_slices(repo: &OpenedRepo) -> Vec<&[u8]> {
    repo.packs.iter().map(|p| p.as_slice()).collect()
}

// cagit comp-has <sha> <repo1> [<repo2> ...]: for each repo, report whether
// the commit sha exists in its DAG and if so, whether it's an ancestor of HEAD.
fn run_comp_has(sha_hex: &str, repos: &[&str], summary: bool) {
    let Some(target) = cagit::find::hex_to_sha(sha_hex) else {
        eprintln!("invalid sha: {sha_hex}");
        std::process::exit(1);
    };
    println!("sha: {sha_hex}");
    for repo_arg in repos {
        let t0 = std::time::Instant::now();
        let repo = match open_repo(repo_arg) {
            Ok(r) => r,
            Err(e) => { println!("  {repo_arg}  ERROR ({e})"); continue; }
        };
        let elapsed = t0.elapsed();

        match repo.dag.index_by_sha(&target) {
            None => {
                println!("  {repo_arg}  no  [{elapsed:?}]");
            }
            Some(idx) => {
                // Check if it's an ancestor of this repo's HEAD.
                let mut reachable_from_head = false;
                if let Some(head_idx) = repo.dag.index_by_sha(&repo.head_sha) {
                    reachable_from_head = repo.dag.reaches(head_idx, idx);
                }
                let scope = if reachable_from_head { "in HEAD" } else { "in pack" };
                let g = repo.dag.generation[idx];
                let summ = if summary {
                    let body = repo.dag.commit_body(&pack_slices(&repo), idx);
                    format!("  {}", commit_summary(&body))
                } else { String::new() };
                println!("  {repo_arg}  yes  ({scope}, gen {g}){summ}  [{elapsed:?}]");
            }
        }
    }
}

// cagit compare <base> <target1> [<target2> ...]: ancestor-set diff and LCA
// of each target against the base.
fn run_compare(repos: &[&str], summary: bool) {
    let t0 = std::time::Instant::now();
    let base = match open_repo(repos[0]) {
        Ok(r) => r, Err(e) => { eprintln!("base: {e}"); std::process::exit(1); }
    };
    let Some(base_head_idx) = base.dag.index_by_sha(&base.head_sha) else {
        eprintln!("HEAD of base not in DAG");
        std::process::exit(1);
    };
    let base_anc = base.dag.ancestors(base_head_idx);
    let mut base_in: Vec<bool> = vec![false; base.dag.commits.len()];
    for &i in &base_anc { base_in[i] = true; }
    let t_base = t0.elapsed();

    eprintln!("base opened:   {:?}", t_base);
    eprintln!();
    println!("base   {}", repos[0]);
    println!("  HEAD:        {}", hex40(&base.head_sha));
    println!("  ancestors:   {}", base_anc.len());

    for target_arg in &repos[1..] {
        let t1 = std::time::Instant::now();
        let t = match open_repo(target_arg) {
            Ok(r) => r,
            Err(e) => { eprintln!("target {target_arg}: {e}"); continue; }
        };
        let Some(t_head_idx) = t.dag.index_by_sha(&t.head_sha) else {
            eprintln!("target {target_arg}: HEAD not in DAG");
            continue;
        };
        let t_anc = t.dag.ancestors(t_head_idx);
        let mut t_in: Vec<bool> = vec![false; t.dag.commits.len()];
        for &i in &t_anc { t_in[i] = true; }
        let t_open = t1.elapsed();

        // Common (in both base.ancestors AND target.ancestors), ahead (target only),
        // behind (base only). LCA = highest-gen among common.
        let t2 = std::time::Instant::now();
        let mut common_count = 0usize;
        let mut behind = 0usize;
        let mut lca_idx: Option<usize> = None;
        let mut lca_gen: u32 = 0;
        for &bi in &base_anc {
            let sha = base.dag.commits[bi].commit_sha;
            let in_target = t.dag.index_by_sha(&sha).map(|ti| t_in[ti]).unwrap_or(false);
            if in_target {
                common_count += 1;
                let g = base.dag.generation[bi];
                if lca_idx.is_none() || g > lca_gen {
                    lca_idx = Some(bi);
                    lca_gen = g;
                }
            } else {
                behind += 1;
            }
        }
        let ahead = t_anc.iter().filter(|&&ti| {
            let sha = t.dag.commits[ti].commit_sha;
            base.dag.index_by_sha(&sha)
                .map(|bi| !base_in[bi])
                .unwrap_or(true)
        }).count();
        let t_compute = t2.elapsed();

        println!();
        println!("vs     {target_arg}");
        println!("  HEAD:        {}", hex40(&t.head_sha));
        println!("  ancestors:   {}", t_anc.len());
        println!("  common:      {common_count}");
        println!("  ahead:       {ahead}        (in target, not base)");
        println!("  behind:      {behind}        (in base, not target)");
        match lca_idx {
            Some(i) => {
                let c = &base.dag.commits[i];
                let sha40 = hex40(&c.commit_sha);
                if summary {
                    let body = base.dag.commit_body(&pack_slices(&base), i);
                    println!("  LCA:         {sha40}  (gen {lca_gen})  {}", commit_summary(&body));
                } else {
                    println!("  LCA:         {sha40}  (gen {lca_gen})");
                }
            }
            None => println!("  LCA:         none (no shared history)"),
        }
        eprintln!("  [opened {t_open:?}, compute {t_compute:?}]");
    }
}

// Find the merge commit that first integrated <commit_sha> into <head_sha>'s
// ancestry. Builds the DAG once, then does two BFS (microseconds).
fn run_integrated(_git_dir: &Path, repo_arg: &str, commit_hex: &str, head_hex: &str, summary: bool) {
    let Some(commit_sha) = cagit::find::hex_to_sha(commit_hex) else {
        eprintln!("invalid commit sha: {commit_hex}");
        std::process::exit(1);
    };
    let Some(head_sha) = cagit::find::hex_to_sha(head_hex) else {
        eprintln!("invalid head sha: {head_hex}");
        std::process::exit(1);
    };

    let t0 = std::time::Instant::now();
    let repo = match open_repo(repo_arg) {
        Ok(r) => r, Err(e) => { eprintln!("{e}"); std::process::exit(1); }
    };
    eprintln!("dag {}: {:?}", if repo.dag_cached { "loaded" } else { "built" }, t0.elapsed());

    let Some(commit_i) = repo.dag.index_by_sha(&commit_sha) else {
        eprintln!("commit not in DAG: {commit_hex}");
        std::process::exit(1);
    };
    let Some(head_i) = repo.dag.index_by_sha(&head_sha) else {
        eprintln!("head not in DAG: {head_hex}");
        std::process::exit(1);
    };

    let t1 = std::time::Instant::now();
    let result = repo.dag.integration_merge(commit_i, head_i);
    eprintln!("query:     {:?}", t1.elapsed());

    match result {
        Some(merge_i) => {
            let c = &repo.dag.commits[merge_i];
            let sha40 = hex40(&c.commit_sha);
            if summary {
                let body = repo.dag.commit_body(&pack_slices(&repo), merge_i);
                println!("{sha40}  merge  {}  (gen {})", commit_summary(&body), repo.dag.generation[merge_i]);
            } else {
                println!("{sha40}  merge  (gen {})", repo.dag.generation[merge_i]);
            }
        }
        None => {
            eprintln!("commit not reachable to HEAD, or reached without a merge (direct first-parent)");
            std::process::exit(1);
        }
    }
}

// Build the commit DAG and print stats. If a sha is given, also print
// per-commit info (generation, ancestor count, descendant count).
fn run_dag(_git_dir: &Path, repo_arg: &str, sha_arg: Option<&str>) {
    let t0 = std::time::Instant::now();
    let repo = match open_repo(repo_arg) {
        Ok(r) => r, Err(e) => { eprintln!("{e}"); std::process::exit(1); }
    };
    let t_dag = t0.elapsed();
    let dag = &repo.dag;

    let n = dag.commits.len();
    let roots = dag.parents.iter().filter(|p| p.is_empty()).count();
    let leaves = dag.children.iter().filter(|c| c.is_empty()).count();
    let max_gen = dag.generation.iter().copied().max().unwrap_or(0);
    let merges = dag.parents.iter().filter(|p| p.len() > 1).count();
    let loose = dag.loose_bodies.len();

    eprintln!("dag {}: {:?}", if repo.dag_cached { "loaded" } else { "built " }, t_dag);
    eprintln!("packs:           {}", repo.packs.len());
    eprintln!("commits:         {n} ({loose} loose)");
    eprintln!("roots:           {roots}");
    eprintln!("leaves:          {leaves}");
    eprintln!("merge commits:   {merges}");
    eprintln!("max generation:  {max_gen}");

    if let Some(hex) = sha_arg {
        let Some(target) = cagit::find::hex_to_sha(hex) else {
            eprintln!("invalid sha: {hex}");
            std::process::exit(1);
        };
        let Some(idx) = dag.index_by_sha(&target) else {
            eprintln!("sha not in DAG (not a commit?)");
            std::process::exit(1);
        };
        let c = &dag.commits[idx];
        let t2 = std::time::Instant::now();
        let ancestors = dag.ancestors(idx);
        let t_anc = t2.elapsed();
        let t3 = std::time::Instant::now();
        let descendants = dag.descendants(idx);
        let t_desc = t3.elapsed();
        eprintln!("---");
        eprintln!("commit:          {}", hex);
        eprintln!("generation:      {}", dag.generation[idx]);
        eprintln!("parents:         {}", dag.parents[idx].len());
        eprintln!("children:        {}", dag.children[idx].len());
        eprintln!("ancestors:       {} ({:?})", ancestors.len(), t_anc);
        eprintln!("descendants:     {} ({:?})", descendants.len(), t_desc);
        eprintln!("author_ts:       {}", c.author_ts);
    }
}

// Remote variant: fetch full pack (no blob:none filter, since we need to be
// able to resolve any sha), then build ShaIndex by hashing each object during
// the walk. Slower upfront than local but otherwise identical logic.
fn run_find_remote(
    url: &str,
    target_hex: &str,
    limit: usize,
    summary: bool,
) {
    let Some(target) = cagit::find::hex_to_sha(target_hex) else {
        eprintln!("invalid target sha: {target_hex}");
        std::process::exit(1);
    };

    let pack = match fetch_pack(url, 0) { // kind_mask=0 = all, no filter
        Ok(p)  => p,
        Err(e) => { eprintln!("fetch: {e}"); std::process::exit(1); }
    };

    // Walk pack, accumulating (sha, offset) for every object so we can build a
    // sha->offset index identical to what idx_sha_map gives us locally.
    let mut pairs: Vec<([u8; 20], u64)> = Vec::new();
    let mut last_offset: u64 = 0;
    let mut last_kind: u8 = 0;
    let res = scan_objects_no_idx(&pack, 0, |kind, data, offset| {
        let header = format!("{} {}\0", kind_name(kind), data.len());
        let mut h = sha1_smol::Sha1::new();
        h.update(header.as_bytes());
        h.update(data);
        pairs.push((h.digest().bytes(), offset));
        last_offset = offset;
        last_kind = kind;
        true
    });
    if let Err(e) = res {
        eprintln!("scan: {e} (processed {} objects, last kind={} offset={}, pack {} bytes)",
                 pairs.len(), last_kind, last_offset, pack.len());
        std::process::exit(1);
    }

    let sha_idx = cagit::find::ShaIndex::from_pairs(&pairs);
    match cagit::find::find_oldest(&pack, &sha_idx, &target, limit) {
        Ok(results) => {
            if results.is_empty() { eprintln!("not found"); std::process::exit(1); }
            for c in &results {
                let sha40 = hex40(&c.commit_sha);
                if summary {
                    let body = cagit::find::inflate_at(&pack, c.offset)
                        .map(|(_, d)| d).unwrap_or_default();
                    println!("{sha40}  commit  {}", commit_summary(&body));
                } else {
                    println!("{sha40}  commit");
                }
            }
        }
        Err(e) => { eprintln!("find: {e}"); std::process::exit(1); }
    }
}
