use std::path::{Path, PathBuf};

use cagit::pack_scan::{idx_sha_map, scan_objects, scan_objects_no_idx};
use cagit::remote::fetch_pack;
use cagit::repo::{open_repo, resolve_head, OpenedRepo};
use cagit::util::{commit_summary, commit_timestamp, hex40, kind_name, object_sha, tag_summary};
use memmap2::Mmap;
use regex::bytes::Regex;

const USAGE: &str = r#"usage:

  -- git-aware queries --

  cagit <repo> <type> <query> [-e|--exact] [-s|--summary] [oldest|newest|N]
    scan pack for objects of <type> matching regex <query>
    type:               blob | commit | tree | tag | all
    -e, --exact:        wrap query in \b(?:...)\b for word-boundary match
    -s, --summary:      include commit/blob/tree/tag summary line

  cagit <repo> find <sha> [N] [-s|--summary]
    N oldest commits whose tree contains <sha> (default N=1)
    -s, --summary:      include commit author + first-line message

  cagit <repo> dag [<sha>]
    DAG stats; with sha: gen/ancestors/descendants for that commit

  cagit <repo> landed <commit_sha> [<head_sha>] [-s|--summary]
    merge commit that first landed <commit_sha> in HEAD's history
    -s, --summary:      include the landing merge's commit message

  cagit comp <base> <target1> [<target2> ...] [-s|--summary]
    N-way ancestor diff + LCA across repos (paths or URLs)
    -s, --summary:      include LCA commit's message

  cagit comp-has <sha> <repo1> [<repo2> ...] [-s|--summary]
    yes/no presence of <sha> in each repo (with HEAD-reachability)
    -s, --summary:      include commit message when found

  cagit churn <base> <fork> [N=20]
    top-N most-modified paths across commits in fork-not-base

  -- code-content analysis --

  cagit <repo> duper [N=15] [MIN_LINES=3]
    top-N duplicate code blocks in repo's HEAD tree
    higher MIN_LINES (5-8) filters out framework boilerplate

env:
  CAGIT_CACHE_DIR=    override default /tmp/cagit-cache location
"#;

fn print_usage() {
    eprint!("{USAGE}");
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

    // `cagit comp <base> <target1> [<target2> ...]`  N-way ancestor diff + LCA.
    if args.len() >= 2 && args[1].as_str() == "comp" {
        if args.len() < 4 {
            eprintln!("usage: cagit comp <base> <target1> [<target2> ...]");
            std::process::exit(1);
        }
        let repos: Vec<&str> = args[2..].iter().map(|s| s.as_str()).collect();
        run_compare(&repos, summary);
        return;
    }

    // `cagit churn <base> <fork> [N]`  top-N most-modified paths across
    // commits in fork-not-base (first-parent diff per commit).
    if args.len() >= 2 && args[1].as_str() == "churn" {
        if args.len() < 4 {
            eprintln!("usage: cagit churn <base> <fork> [N]");
            std::process::exit(1);
        }
        let n: usize = args.get(4).and_then(|s| s.parse().ok()).unwrap_or(20);
        run_churn(args[2].as_str(), args[3].as_str(), n);
        return;
    }

    // `cagit comp-has <sha> <repo1> [<repo2> ...]`  for each repo, does this
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
        let sha_arg = args.get(3).map(|s| s.as_str());
        run_dag(args[1].as_str(), sha_arg);
        return;
    }

    if args[2].as_str() == "duper" {
        let n: usize = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(15);
        let min_lines: usize = args.get(4).and_then(|s| s.parse().ok())
            .unwrap_or(cagit::duper::MIN_LINES).max(2);
        run_duper(args[1].as_str(), n, min_lines);
        return;
    }

    if args[2].as_str() == "landed" {
        // `cagit <repo> landed <commit_sha> [<head_sha>]`
        // If head_sha omitted: for local, resolve from .git/HEAD; for remote,
        // run_landed uses the fetched HEAD from open_repo.
        let commit_hex = args.get(3).map(|s| s.as_str()).unwrap_or_else(|| {
            print_usage();
            std::process::exit(1);
        });
        let head_hex_owned: Option<String> = match args.get(4) {
            Some(s) => Some(s.to_string()),
            None if !is_remote => resolve_head(&git_dir),
            None => None, // remote: resolved inside run_landed from repo.head_sha
        };
        run_landed(args[1].as_str(), commit_hex, head_hex_owned.as_deref(), summary);
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

// Regex-bound summary helpers (scan-only). Generic regex-free helpers live in
// `cagit::util`; these dispatch through there for commit/tag.
fn make_summary(kind: u8, data: &[u8], re: &Regex) -> String {
    match kind {
        1 => commit_summary(data),
        2 => tree_summary(data, re),
        3 => blob_summary(data, re),
        4 => tag_summary(data),
        _ => String::new(),
    }
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

// Wraps OpenedRepo::pack_slices for the existing run_* call sites.
fn pack_slices(repo: &OpenedRepo) -> Vec<&[u8]> { repo.pack_slices() }

// cagit <repo> duper [N] [MIN_LINES]: top-N duplicate code blocks of at least
// MIN_LINES (default 3) across HEAD's tree.
fn run_duper(repo_arg: &str, top_n: usize, min_lines: usize) {
    let t0 = std::time::Instant::now();
    // duper needs blob content; over the wire that means a full pack fetch
    // (no filter=blob:none).
    let repo = match cagit::repo::open_repo_full(repo_arg) {
        Ok(r) => r, Err(e) => { eprintln!("{e}"); std::process::exit(1); }
    };
    let t_setup = t0.elapsed();

    let Some(head_idx) = repo.dag.index_by_sha(&repo.head_sha) else {
        eprintln!("HEAD not in DAG"); std::process::exit(1);
    };
    let head_tree = repo.dag.commits[head_idx].root_tree;
    let packs_slices = pack_slices(&repo);

    let t1 = std::time::Instant::now();
    let out = match cagit::duper::run(&packs_slices, &repo.sha_idxs, &repo.loose, &head_tree, min_lines) {
        Ok(o) => o, Err(e) => { eprintln!("duper: {e}"); std::process::exit(1); }
    };
    let t_duper = t1.elapsed();

    eprintln!("setup:   {:?}", t_setup);
    eprintln!("scan:    {:?}", t_duper);
    eprintln!("files scanned: {} ({} skipped binary)",
              out.stats.files_scanned, out.stats.files_skipped_binary);
    eprintln!("windows hashed: {} ({} unique)",
              out.stats.windows_hashed, out.stats.unique_windows);
    eprintln!("duplicate groups: {}", out.groups.len());
    eprintln!();

    for (rank, g) in out.groups.iter().take(top_n).enumerate() {
        let (fi0, sl0) = g.occurrences[0];
        let file0 = &out.files[fi0 as usize];
        // Inflate first occurrence's blob to display the duplicated block.
        let snippet = cagit::find::resolve_sha_multi(&packs_slices, &repo.sha_idxs, &repo.loose, &file0.blob_sha)
            .map(|(_, body)| {
                let lines: Vec<&[u8]> = body.split(|&b| b == b'\n').collect();
                let start = (sl0 as usize).saturating_sub(1);
                let end = (start + g.line_count as usize).min(lines.len());
                lines[start..end].iter()
                    .map(|l| String::from_utf8_lossy(l).into_owned())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        println!("#{}  {} lines, {} occurrences, {} wasted",
                 rank + 1, g.line_count, g.occurrences.len(), g.wasted_lines());
        for line in &snippet {
            println!("    | {line}");
        }
        for (fi, sl) in &g.occurrences {
            let path = String::from_utf8_lossy(&out.files[*fi as usize].path);
            println!("    @ {path}:{sl}");
        }
        println!();
    }
}

// cagit churn <base> <fork> [N]: top-N most-modified paths across all commits
// in fork-not-base, diffed against each commit's first parent.
fn run_churn(base_arg: &str, fork_arg: &str, top_n: usize) {
    let t0 = std::time::Instant::now();
    let base = match open_repo(base_arg) {
        Ok(r) => r, Err(e) => { eprintln!("base: {e}"); std::process::exit(1); }
    };
    let fork = match open_repo(fork_arg) {
        Ok(r) => r, Err(e) => { eprintln!("fork: {e}"); std::process::exit(1); }
    };
    eprintln!("repos opened: {:?}", t0.elapsed());

    let Some(fork_head_idx) = fork.dag.index_by_sha(&fork.head_sha) else {
        eprintln!("fork HEAD not in DAG"); std::process::exit(1);
    };
    let fork_anc = fork.dag.ancestors(fork_head_idx);

    // Set of base's HEAD-ancestor shas  FFI-backed for membership probes.
    let mut base_set = cagit::find::ShaSet::with_capacity(8192);
    if let Some(bhi) = base.dag.index_by_sha(&base.head_sha) {
        for i in base.dag.ancestors(bhi) {
            base_set.insert(&base.dag.commits[i].commit_sha);
        }
    }

    let packs_slices = pack_slices(&fork);

    let t1 = std::time::Instant::now();
    let mut counts = cagit::churn::PathCounter::with_capacity(4096);
    let mut considered = 0usize;
    let mut prefix: Vec<u8> = Vec::new();
    for &ci in &fork_anc {
        let sha = fork.dag.commits[ci].commit_sha;
        if base_set.contains(&sha) { continue; }
        considered += 1;
        let Some(parent_idx) = fork.dag.first_parent(ci) else { continue };
        let child_tree = fork.dag.commits[ci].root_tree;
        let parent_tree = fork.dag.commits[parent_idx].root_tree;
        if child_tree == parent_tree { continue; }
        prefix.clear();
        let _ = cagit::churn::diff_trees(&packs_slices, &fork.sha_idxs, &fork.loose,
            &child_tree, &parent_tree, &mut prefix, &mut counts);
    }
    eprintln!("diffed {} commits in {:?}", considered, t1.elapsed());

    let ranked = counts.into_sorted_desc();

    eprintln!();
    println!("top {} paths by change count in fork-not-base ({} commits):",
             top_n.min(ranked.len()), considered);
    for (path, n) in ranked.iter().take(top_n) {
        println!("  {n:>5}  {}", String::from_utf8_lossy(path));
    }
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

// Find the merge commit that first landed <commit_sha> in <head_sha>'s
// ancestry. Builds the DAG once, then does two BFS (microseconds).
fn run_landed(repo_arg: &str, commit_hex: &str, head_hex_opt: Option<&str>, summary: bool) {
    let Some(commit_sha) = cagit::find::hex_to_sha(commit_hex) else {
        eprintln!("invalid commit sha: {commit_hex}");
        std::process::exit(1);
    };

    let t0 = std::time::Instant::now();
    let repo = match open_repo(repo_arg) {
        Ok(r) => r, Err(e) => { eprintln!("{e}"); std::process::exit(1); }
    };
    eprintln!("dag {}: {:?}", if repo.dag_cached { "loaded" } else { "built" }, t0.elapsed());

    // Resolve head: explicit arg wins; otherwise fall back to repo.head_sha
    // (works for both local resolved-from-.git/HEAD and remote fetched-HEAD).
    let head_sha: [u8; 20] = match head_hex_opt.and_then(cagit::find::hex_to_sha) {
        Some(s) => s,
        None if repo.head_sha != [0u8; 20] => repo.head_sha,
        None => {
            eprintln!("could not resolve HEAD; pass <head_sha> explicitly");
            std::process::exit(1);
        }
    };

    let Some(commit_i) = repo.dag.index_by_sha(&commit_sha) else {
        eprintln!("commit not in DAG: {commit_hex}");
        std::process::exit(1);
    };
    let Some(head_i) = repo.dag.index_by_sha(&head_sha) else {
        eprintln!("head not in DAG: {}", hex40(&head_sha));
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
fn run_dag(repo_arg: &str, sha_arg: Option<&str>) {
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
