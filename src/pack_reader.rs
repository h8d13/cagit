// Low-level pack helpers shared by pack_scan.
// See: git/Documentation/technical/pack-format.txt

use std::io;

fn bad(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

/// Returns (type_id 1..=7, uncompressed size). Advances pos past the
/// variable-length header.
pub(crate) fn read_obj_header(data: &[u8], pos: &mut usize) -> (u8, u64) {
    let b = data[*pos]; *pos += 1;
    let obj_type = (b >> 4) & 0x7;
    let mut size = (b & 0x0f) as u64;
    let mut shift = 4u32;
    let mut cont = b & 0x80;
    while cont != 0 {
        let b = data[*pos]; *pos += 1;
        size |= ((b & 0x7f) as u64) << shift;
        shift += 7;
        cont = b & 0x80;
    }
    (obj_type, size)
}

/// OFS_DELTA negative-offset encoding: MSB continuation with +1 bias per byte
/// after the first.
pub(crate) fn read_ofs_offset(data: &[u8], pos: &mut usize) -> u64 {
    let mut b = data[*pos] as u64; *pos += 1;
    let mut val = b & 0x7f;
    while b & 0x80 != 0 {
        b = data[*pos] as u64; *pos += 1;
        val = ((val + 1) << 7) | (b & 0x7f);
    }
    val
}

pub(crate) fn apply_delta(base: &[u8], delta: &[u8]) -> io::Result<Vec<u8>> {
    let mut pos = 0usize;

    let src_size = read_varint(delta, &mut pos);
    if src_size != base.len() as u64 { return Err(bad("delta source size mismatch")); }
    let tgt_size = read_varint(delta, &mut pos) as usize;
    let mut out = Vec::with_capacity(tgt_size);

    while pos < delta.len() {
        let cmd = delta[pos]; pos += 1;
        if cmd & 0x80 != 0 {
            // copy [off, off+sz) from base
            let (mut off, mut sz) = (0u64, 0u64);
            for i in 0..4u64 {
                if cmd & (1 << i) != 0 { off |= (delta[pos] as u64) << (i * 8); pos += 1; }
            }
            for i in 0..3u64 {
                if cmd & (1 << (4 + i)) != 0 { sz |= (delta[pos] as u64) << (i * 8); pos += 1; }
            }
            if sz == 0 { sz = 0x10000; }
            let (off, sz) = (off as usize, sz as usize);
            if off + sz > base.len() { return Err(bad("delta copy out of bounds")); }
            out.extend_from_slice(&base[off..off + sz]);
        } else if cmd != 0 {
            let sz = cmd as usize;
            if pos + sz > delta.len() { return Err(bad("delta insert out of bounds")); }
            out.extend_from_slice(&delta[pos..pos + sz]);
            pos += sz;
        } else {
            return Err(bad("delta instruction 0x00 reserved"));
        }
    }

    Ok(out)
}

fn read_varint(data: &[u8], pos: &mut usize) -> u64 {
    let mut val = 0u64;
    let mut shift = 0u32;
    loop {
        let b = data[*pos]; *pos += 1;
        val |= ((b & 0x7f) as u64) << shift;
        shift += 7;
        if b & 0x80 == 0 { break; }
    }
    val
}
