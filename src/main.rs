use std::fmt::Write as _;
use std::path::PathBuf;

use cagit::pack_scan::{idx_sha_map, scan_objects, scan_objects_no_idx};
use cagit::remote::fetch_pack;
use memmap2::Mmap;
use regex::bytes::Regex;

fn print_usage() {
    eprintln!("usage: cagit <repo> <type> <query> [-e|--exact] [-s|--summary] [oldest|newest|N]");
    eprintln!("  type:               blob | commit | tree | tag | all");
    eprintln!("  -e, --exact:        exact word match (wraps query in \\b(?:...)\\b)");
    eprintln!("  -s, --summary:      show one-line summary (default: sha + kind only)");
    eprintln!("  oldest|newest:      sort commits by author date, show 10");
    eprintln!("  oldest N:           sort commits by author date, show N");
    eprintln!("  N:                  show first N results  (default: 10)");
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

    if args.len() < 4 {
        print_usage();
        std::process::exit(1);
    }

    let repo_path = PathBuf::from(args[1].as_str());
    let git_dir = if repo_path.join(".git").exists() {
        repo_path.join(".git")
    } else {
        repo_path.clone()
    };

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

    let is_remote = args[1].starts_with("https://") || args[1].starts_with("http://");

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
