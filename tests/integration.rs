use std::path::PathBuf;
use std::process::Command;

fn repo() -> PathBuf {
    match std::env::var("TEST_GIT_REPO") {
        Ok(p) => PathBuf::from(p),
        Err(_) => PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../git"),
    }
}

fn remote_url() -> String {
    std::env::var("TEST_GIT_URL")
        .unwrap_or_else(|_| "https://github.com/git/git.git".to_owned())
}

fn ghash(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_cagit"))
        .args(args)
        .output()
        .unwrap()
}

fn out_lines(o: &std::process::Output) -> Vec<String> {
    String::from_utf8_lossy(&o.stdout).lines().map(|l| l.to_owned()).collect()
}

fn err_str(o: &std::process::Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

// Default output line: "<sha40>  <kind>"
fn valid_line(line: &str) -> bool {
    let mut parts = line.splitn(3, "  ");
    let sha  = parts.next().unwrap_or("");
    let kind = parts.next().unwrap_or("");
    sha.len() == 40
        && sha.chars().all(|c| c.is_ascii_hexdigit())
        && ["commit", "tree", "blob", "tag"].contains(&kind)
}

// --- error cases ---

#[test]
fn missing_args_exits_nonzero() {
    let o = ghash(&[]);
    assert!(!o.status.success());
    assert!(err_str(&o).contains("usage:"));
}

#[test]
fn invalid_type_exits_nonzero() {
    let r = repo();
    let o = ghash(&[r.to_str().unwrap(), "blub", "cat"]);
    assert!(!o.status.success());
    assert!(err_str(&o).contains("unknown type"));
}

#[test]
fn invalid_regex_exits_nonzero() {
    let r = repo();
    let o = ghash(&[r.to_str().unwrap(), "blob", "[unclosed"]);
    assert!(!o.status.success());
    assert!(err_str(&o).contains("invalid regex"));
}

// --- output format ---

#[test]
fn output_lines_are_well_formed() {
    let r = repo();
    let o = ghash(&[r.to_str().unwrap(), "all", "cat", "10"]);
    assert!(o.status.success());
    let lines = out_lines(&o);
    assert!(!lines.is_empty());
    for line in &lines {
        assert!(valid_line(line), "malformed output line: {line:?}");
    }
}

// --- kind filtering ---

#[test]
fn blob_filter_returns_only_blobs() {
    let r = repo();
    let o = ghash(&[r.to_str().unwrap(), "blob", "cat", "10"]);
    assert!(o.status.success());
    let lines = out_lines(&o);
    assert!(!lines.is_empty());
    for line in &lines {
        assert!(line.contains("  blob"), "non-blob in blob results: {line:?}");
    }
}

#[test]
fn commit_filter_returns_only_commits() {
    let r = repo();
    let o = ghash(&[r.to_str().unwrap(), "commit", "cat", "10"]);
    assert!(o.status.success());
    let lines = out_lines(&o);
    assert!(!lines.is_empty());
    for line in &lines {
        assert!(line.contains("  commit"), "non-commit in commit results: {line:?}");
    }
}

#[test]
fn tree_filter_returns_only_trees() {
    let r = repo();
    let o = ghash(&[r.to_str().unwrap(), "tree", "cat", "5"]);
    assert!(o.status.success());
    for line in out_lines(&o) {
        assert!(line.contains("  tree"), "non-tree in tree results: {line:?}");
    }
}

#[test]
fn all_returns_results() {
    let r = repo();
    let o = ghash(&[r.to_str().unwrap(), "all", "cat", "10"]);
    assert!(o.status.success());
    assert!(!out_lines(&o).is_empty());
}

// --- limit ---

#[test]
fn limit_n_caps_output() {
    let r = repo();
    let o = ghash(&[r.to_str().unwrap(), "all", "cat", "3"]);
    assert!(o.status.success());
    assert!(out_lines(&o).len() <= 3);
}

// --- sort order ---

#[test]
fn oldest_and_newest_return_different_commits() {
    let r = repo();
    let r = r.to_str().unwrap();
    let old = ghash(&[r, "commit", "cat", "oldest", "1"]);
    let new = ghash(&[r, "commit", "cat", "newest", "1"]);
    assert!(old.status.success());
    assert!(new.status.success());
    let old_lines = out_lines(&old);
    let new_lines = out_lines(&new);
    assert_eq!(old_lines.len(), 1);
    assert_eq!(new_lines.len(), 1);
    assert_ne!(old_lines[0], new_lines[0], "oldest and newest should differ");
}

#[test]
fn oldest_limit_caps_and_returns_commits() {
    let r = repo();
    let o = ghash(&[r.to_str().unwrap(), "commit", "cat", "oldest", "5"]);
    assert!(o.status.success());
    let lines = out_lines(&o);
    assert!(lines.len() <= 5);
    for line in &lines {
        assert!(line.contains("  commit"));
    }
}

#[test]
fn newest_limit_caps_and_returns_commits() {
    let r = repo();
    let o = ghash(&[r.to_str().unwrap(), "commit", "cat", "newest", "5"]);
    assert!(o.status.success());
    let lines = out_lines(&o);
    assert!(lines.len() <= 5);
    for line in &lines {
        assert!(line.contains("  commit"));
    }
}

// --- regex ---

#[test]
fn regex_literal_works() {
    let r = repo();
    let o = ghash(&[r.to_str().unwrap(), "commit", "cat-file", "5"]);
    assert!(o.status.success());
    assert!(!out_lines(&o).is_empty());
}

#[test]
fn regex_alternation_works() {
    let r = repo();
    let o = ghash(&[r.to_str().unwrap(), "commit", "cat-file|read-tree", "10"]);
    assert!(o.status.success());
    assert!(!out_lines(&o).is_empty());
}

#[test]
fn regex_anchor_filters_correctly() {
    let r = repo();
    // anchored to start of line: only matches commits whose message begins with "cat"
    let anchored = ghash(&[r.to_str().unwrap(), "commit", "(?m)^cat", "10"]);
    let unanchored = ghash(&[r.to_str().unwrap(), "commit", "cat", "10"]);
    assert!(anchored.status.success());
    assert!(unanchored.status.success());
    // anchored should return fewer or equal results
    assert!(out_lines(&anchored).len() <= out_lines(&unanchored).len());
}

#[test]
fn exact_flag_returns_fewer_results_than_substring() {
    let r = repo();
    let r = r.to_str().unwrap();
    let substr = ghash(&[r, "commit", "cat", "100"]);
    let exact  = ghash(&[r, "commit", "cat", "-e", "100"]);
    assert!(substr.status.success());
    assert!(exact.status.success());
    assert!(!out_lines(&exact).is_empty());
    assert!(out_lines(&exact).len() <= out_lines(&substr).len());
}

#[test]
fn exact_flag_position_independent() {
    let r = repo();
    let r = r.to_str().unwrap();
    // -e before and after the limit should give identical results
    let before = ghash(&[r, "commit", "cat", "-e", "5"]);
    let after  = ghash(&[r, "commit", "cat", "5", "-e"]);
    assert!(before.status.success());
    assert!(after.status.success());
    assert_eq!(out_lines(&before), out_lines(&after));
}

// --- remote (network required, ignored by default) ---
// Run with: cargo test -- --ignored remote

/// Output format for remote matches local: sha40 + kind, well-formed lines.
#[test]
#[ignore]
fn remote_output_is_well_formed() {
    let u = remote_url();
    let o = ghash(&[&u, "commit", "cat", "5"]);
    assert!(o.status.success(), "stderr: {}", err_str(&o));
    let lines = out_lines(&o);
    assert!(!lines.is_empty());
    for line in &lines {
        assert!(valid_line(line), "malformed remote output line: {line:?}");
    }
}

/// Remote SHA for the oldest exact "cat" commit matches the known local SHA.
/// This is the gold-standard correctness test: same pack, same SHA algorithm,
/// same result regardless of whether the pack came from disk or the wire.
#[test]
#[ignore]
fn remote_sha_matches_local() {
    let u = remote_url();
    let r = repo();

    let remote = ghash(&[&u,                  "commit", "-se", "cat", "oldest", "1"]);
    let local  = ghash(&[r.to_str().unwrap(), "commit", "-se", "cat", "oldest", "1"]);

    assert!(remote.status.success(), "remote stderr: {}", err_str(&remote));
    assert!(local.status.success(),  "local stderr: {}",  err_str(&local));

    let remote_sha = out_lines(&remote).into_iter().next().unwrap();
    let local_sha  = out_lines(&local).into_iter().next().unwrap();

    assert_eq!(remote_sha, local_sha,
        "remote and local returned different SHAs for the same query");
}

/// Kind filter works over the wire: blob search returns only blobs.
#[test]
#[ignore]
fn remote_kind_filter_works() {
    let u = remote_url();
    let o = ghash(&[&u, "blob", "cat", "5"]);
    assert!(o.status.success(), "stderr: {}", err_str(&o));
    for line in out_lines(&o) {
        assert!(line.contains("  blob"), "non-blob in remote blob results: {line:?}");
    }
}
