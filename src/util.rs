// Small reusable helpers: kind names, hex, object sha, commit/tag summary.
// No CLI flavor; no regex dependencies (regex-bound helpers stay with the
// scan code in main.rs).

use std::fmt::Write as _;

pub fn kind_name(kind: u8) -> &'static str {
    match kind { 1 => "commit", 2 => "tree", 3 => "blob", 4 => "tag", _ => "?" }
}

pub fn hex40(sha: &[u8; 20]) -> String {
    let mut s = String::with_capacity(40);
    for b in sha { write!(s, "{b:02x}").unwrap(); }
    s
}

/// Compute the git object SHA from kind + decompressed content.
/// git SHA = sha1("<type> <size>\0<content>")
pub fn object_sha(kind: u8, data: &[u8]) -> String {
    let header = format!("{} {}\0", kind_name(kind), data.len());
    let mut h = sha1_smol::Sha1::new();
    h.update(header.as_bytes());
    h.update(data);
    let bytes = h.digest().bytes();
    hex40(&bytes)
}

/// Extract author timestamp from a commit body. 0 if unparseable.
pub fn commit_timestamp(data: &[u8]) -> i64 {
    let text = String::from_utf8_lossy(data);
    text.lines()
        .find(|l| l.starts_with("author "))
        .and_then(|l| l.split_ascii_whitespace().nth_back(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

/// "<author name>: <first line of message>" common terse commit line.
pub fn commit_summary(data: &[u8]) -> String {
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

/// First line of a tag object's body (the tag's metadata header line).
pub fn tag_summary(data: &[u8]) -> String {
    String::from_utf8_lossy(data).lines().next().unwrap_or("").to_string()
}
