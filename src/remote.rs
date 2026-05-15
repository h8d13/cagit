// Git smart HTTP protocol (v0): fetch a pack without cloning.
//
// Flow:
//   GET  <url>/info/refs?service=git-upload-pack  -> discover HEAD sha + capabilities
//   POST <url>/git-upload-pack                    -> want <sha>, receive pack
//
// Response is pkt-line framed with sideband-64k multiplexing.
// Strip framing, return raw PACK bytes for scan_objects_no_idx.
//
// If server advertises `filter` and caller doesn't need blobs, request
// filter=blob:none. For git/git: ~300MB -> ~108MB.
//
// Reference: git/Documentation/technical/pack-protocol.txt
//            git/Documentation/technical/http-protocol.txt

use std::io::{self, Read};
use std::time::Duration;

// kind_mask bit 2 = blob. If blob bit is unset and mask is non-zero, no blobs needed.
fn needs_blobs(kind_mask: u8) -> bool {
    kind_mask == 0 || (kind_mask & 0b0100 != 0)
}

// Per-socket-operation timeouts (not total): bound idle / hung-connection time,
// don't penalize legitimately-slow pack downloads.
fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(30))
        .timeout_read(Duration::from_secs(60))
        .timeout_write(Duration::from_secs(60))
        .build()
}

pub fn fetch_pack(url: &str, kind_mask: u8) -> io::Result<Vec<u8>> {
    fetch_pack_with_head(url, kind_mask).map(|(_, p)| p)
}

pub fn fetch_pack_with_head(url: &str, kind_mask: u8) -> io::Result<([u8; 20], Vec<u8>)> {
    let base = url.trim_end_matches('/');
    let agent = agent();

    let (head_sha, caps) = discover_head(&agent, base)?;
    eprintln!("HEAD {}", hex40(&head_sha));

    let use_filter = !needs_blobs(kind_mask) && caps.contains("filter");
    if use_filter {
        eprintln!("filter  blob:none");
    }

    let pack = request_pack(&agent, base, &head_sha, use_filter)?;
    eprintln!("pack  {} bytes", pack.len());
    Ok((head_sha, pack))
}

// GET info/refs: returns (HEAD sha, capabilities string).
fn discover_head(agent: &ureq::Agent, base: &str) -> io::Result<([u8; 20], String)> {
    let url = format!("{base}/info/refs?service=git-upload-pack");
    let resp = agent.get(&url)
        .call()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    let mut body = Vec::new();
    resp.into_reader().read_to_end(&mut body)?;
    parse_head_and_caps(&body)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no SHA found in info/refs"))
}

// POST git-upload-pack, demux sideband, return raw pack bytes.
fn request_pack(agent: &ureq::Agent, base: &str, sha: &[u8; 20], filter_blobs: bool) -> io::Result<Vec<u8>> {
    let caps = if filter_blobs {
        "side-band-64k ofs-delta no-progress filter"
    } else {
        "side-band-64k ofs-delta no-progress"
    };
    let want = format!("want {} {caps}\n", hex40(sha));

    let mut body = Vec::new();
    body.extend(pkt_encode(&want).as_bytes());
    if filter_blobs {
        body.extend(pkt_encode("filter blob:none\n").as_bytes());
    }
    body.extend(b"0000");
    body.extend(b"0009done\n");

    let url = format!("{base}/git-upload-pack");
    let resp = agent.post(&url)
        .set("Content-Type", "application/x-git-upload-pack-request")
        .set("Accept",       "application/x-git-upload-pack-result")
        .send_bytes(&body)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

    let mut raw = Vec::new();
    resp.into_reader().read_to_end(&mut raw)?;
    demux_sideband(&raw)
}

// Scan pkt-lines for the first line containing a 40-char hex SHA.
// That line has the format: "<sha40> HEAD\0<capabilities>" or "<sha40> <ref>".
// Capabilities (if present) follow the NUL byte on the first ref line.
fn parse_head_and_caps(data: &[u8]) -> Option<([u8; 20], String)> {
    let mut pos = 0;
    while pos < data.len() {
        let Some(pkt) = read_pkt_line(data, &mut pos) else { break };
        if pkt.len() < 40 { continue; }
        let Ok(hex) = std::str::from_utf8(&pkt[..40]) else { continue };
        if !hex.chars().all(|c| c.is_ascii_hexdigit()) { continue; }
        let sha = hex_to_sha(hex)?;
        // capabilities follow NUL on this same line
        let caps = pkt.iter().position(|&b| b == 0)
            .map(|nul| String::from_utf8_lossy(&pkt[nul + 1..]).into_owned())
            .unwrap_or_default();
        return Some((sha, caps));
    }
    None
}

// Strip sideband-64k framing, return concatenated pack data (channel 1).
fn demux_sideband(data: &[u8]) -> io::Result<Vec<u8>> {
    let mut pos = 0;
    let mut pack = Vec::new();
    loop {
        let pkt = match read_pkt_line(data, &mut pos) {
            Some(p) => p,
            None => {
                if pos < data.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        format!("truncated pkt-line at byte {pos}/{}", data.len()),
                    ));
                }
                break;
            }
        };
        if pkt.is_empty() { continue; }
        match pkt[0] {
            1 => pack.extend_from_slice(&pkt[1..]),
            2 => {}
            3 => {
                let msg = String::from_utf8_lossy(&pkt[1..]).into_owned();
                return Err(io::Error::new(io::ErrorKind::Other, msg));
            }
            _ => {}
        }
    }
    Ok(pack)
}

// Read one pkt-line from data[pos..], advance pos. Returns None on truncation.
// Returns Some(vec![]) for flush packets (len == 0).
fn read_pkt_line(data: &[u8], pos: &mut usize) -> Option<Vec<u8>> {
    if data.len() < *pos + 4 { return None; }
    let hex = std::str::from_utf8(&data[*pos..*pos + 4]).ok()?;
    let len = usize::from_str_radix(hex, 16).ok()?;
    *pos += 4;
    if len == 0 { return Some(vec![]); }
    if len < 4 { return None; }
    let payload = len - 4;
    if data.len() < *pos + payload { return None; }
    let pkt = data[*pos..*pos + payload].to_vec();
    *pos += payload;
    Some(pkt)
}

fn pkt_encode(s: &str) -> String {
    format!("{:04x}{s}", s.len() + 4)
}

fn hex_to_sha(hex: &str) -> Option<[u8; 20]> {
    if hex.len() != 40 { return None; }
    let mut sha = [0u8; 20];
    for (i, b) in sha.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(sha)
}

fn hex40(sha: &[u8; 20]) -> String {
    sha.iter().fold(String::with_capacity(40), |mut s, b| {
        use std::fmt::Write;
        write!(s, "{b:02x}").unwrap();
        s
    })
}
