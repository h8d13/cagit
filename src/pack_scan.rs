// Covers: .pack + v2 .idx, all four object types, OFS_DELTA (type 6) chains.
// See: git/Documentation/technical/pack-format.txt
//
// Skipped:
//   REF_DELTA (type 7): base resolved by SHA, lives in another pack. git prefers
//     OFS_DELTA; skipping avoids cross-pack lookups with negligible coverage loss.
//   Loose objects: only recent commits before next gc; history is packed.
//   commit-graph, MIDX, bitmaps, .rev/.mtimes: no raw object content.
//   See: git/Documentation/technical/commit-graph-format.txt
//        git/Documentation/technical/bitmap-format.txt
//        git/Documentation/technical/pack-format.txt (MIDX section)

use std::collections::{HashMap, HashSet};
use std::io::{self, Read as _};

use flate2::read::ZlibDecoder;

use crate::offset_map::OffsetMap;
use crate::pack_reader::{apply_delta, read_obj_header, read_ofs_offset};

const PACK_MAGIC: &[u8; 4] = b"PACK";

/// Scan every object in a pack, calling `on_object(kind, data, offset)` for each.
///
/// `kind`: git type byte (1=commit 2=tree 3=blob 4=tag).
/// `kind_mask`: bitmask (bit 0=commit, 1=tree, 2=blob, 3=tag). 0 = all kinds.
/// Excluded-kind bases are not cached; their delta chains are skipped.
///
/// Pass 1: header-only scan via .idx offsets, collects OFS_DELTA base offsets.
/// Pass 2: sequential scan, each object decompressed exactly once.
///         Non-bases yielded then discarded. Bases kept in slab for delta apply.
pub fn idx_sha_map(idx: &[u8]) -> HashMap<u64, [u8; 20]> {
    let n = u32_be(idx, 8 + 255 * 4) as usize;
    let sha_base  = 8 + 256 * 4;
    let soff_base = sha_base + n * 20 + n * 4;
    let loff_base = soff_base + n * 4;
    let mut map = HashMap::with_capacity(n);
    for i in 0..n {
        let raw = u32_be(idx, soff_base + i * 4);
        let offset = if raw & 0x8000_0000 != 0 {
            u64_be(idx, loff_base + (raw & 0x7fff_ffff) as usize * 8)
        } else {
            raw as u64
        };
        let sha: [u8; 20] = idx[sha_base + i * 20..sha_base + i * 20 + 20].try_into().unwrap();
        map.insert(offset, sha);
    }
    map
}

/// Callback returns `true` to continue scanning, `false` to stop immediately.
pub fn scan_objects(pack: &[u8], idx: &[u8], kind_mask: u8, mut on_object: impl FnMut(u8, &[u8], u64) -> bool) -> io::Result<()> {
    if pack.len() < 12 || &pack[0..4] != PACK_MAGIC {
        return Err(bad("not a pack file"));
    }

    // collect all object offsets from .idx, sort into pack order, add sentinel
    let mut offsets = idx_offsets(idx);
    offsets.sort_unstable();
    offsets.push(pack.len() as u64 - 20); // sentinel: pack's trailing SHA checksum

    let n = offsets.len() - 1; // actual object count (sentinel excluded)

    let mask = if kind_mask == 0 { 0b1111u8 } else { kind_mask };

    let base_set = collect_bases(pack, &offsets[..n], mask);

    let mut cache = OffsetMap::new(base_set.len().next_power_of_two().max(16));
    cache.reserve(base_set.len() as u64);
    let mut slab:   Vec<Vec<u8>> = Vec::new();
    let mut kinds:  Vec<u8>      = Vec::new();
    let mut scratch: Vec<u8>     = Vec::new();

    'scan: for i in 0..n {
        let obj_off  = offsets[i];
        let is_base  = base_set.contains(&obj_off);
        let mut pos  = obj_off as usize;
        let (obj_type, size) = read_obj_header(pack, &mut pos);

        // Deltas are never cross-kind; kind is always inherited from the base.
        match obj_type {
            1..=4 => {
                let kind = obj_type as u8;
                let want = mask & (1 << (kind - 1)) != 0;
                if is_base {
                    let data = zlib_inflate_owned(pack, &mut pos, size as usize)?;
                    if want && !on_object(kind, &data, obj_off) { break 'scan; }
                    cache.set(obj_off, slab.len() as u32);
                    slab.push(data);
                    kinds.push(kind);
                } else if want {
                    zlib_inflate_scratch(pack, &mut pos, size as usize, &mut scratch)?;
                    if !on_object(kind, &scratch, obj_off) { break 'scan; }
                }
            }
            6 => {
                let neg      = read_ofs_offset(pack, &mut pos);
                let base_off = obj_off.checked_sub(neg)
                    .ok_or_else(|| bad("OFS_DELTA underflow"))?;

                let Some(base_idx) = cache.get(base_off) else {
                    continue;
                };
                let base_kind = kinds[base_idx as usize];
                zlib_inflate_scratch(pack, &mut pos, size as usize, &mut scratch)?;
                let data = apply_delta(&slab[base_idx as usize], &scratch)?;

                if !on_object(base_kind, &data, obj_off) { break 'scan; }
                if is_base {
                    cache.set(obj_off, slab.len() as u32);
                    slab.push(data);
                    kinds.push(base_kind);
                }
            }
            7 => continue,
            t => return Err(io::Error::new(io::ErrorKind::InvalidData,
                                           format!("unknown object type {t}"))),
        }
    }

    Ok(())
}

// Collect offsets that must be cached as OFS_DELTA bases.
// If the base is itself type 6 (kind unknown without chain walk), mark it conservatively.
fn collect_bases(pack: &[u8], offsets: &[u64], mask: u8) -> HashSet<u64> {
    let mut bases = HashSet::with_capacity(offsets.len() / 4);
    for &off in offsets {
        let mut pos = off as usize;
        let (obj_type, _) = read_obj_header(pack, &mut pos);
        if obj_type == 6 {
            let neg = read_ofs_offset(pack, &mut pos);
            if let Some(base_off) = off.checked_sub(neg) {
                let mut bpos = base_off as usize;
                let (base_type, _) = read_obj_header(pack, &mut bpos);
                let include = base_type == 6
                    || (base_type >= 1 && base_type <= 4 && mask & (1 << (base_type - 1)) != 0);
                if include {
                    bases.insert(base_off);
                }
            }
        }
    }
    bases
}

fn idx_offsets(idx: &[u8]) -> Vec<u64> {
    let n         = u32_be(idx, 8 + 255 * 4) as usize;
    let soff_base = 8 + 256 * 4 + n * 20 + n * 4;
    let loff_base = soff_base + n * 4;
    (0..n).map(|i| {
        let raw = u32_be(idx, soff_base + i * 4);
        if raw & 0x8000_0000 != 0 {
            u64_be(idx, loff_base + (raw & 0x7fff_ffff) as usize * 8)
        } else {
            raw as u64
        }
    }).collect()
}

// Allocate a fresh Vec with exact capacity; no realloc during decompression.
fn zlib_inflate_owned(data: &[u8], pos: &mut usize, size_hint: usize) -> io::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(size_hint);
    let mut dec = ZlibDecoder::new(&data[*pos..]);
    dec.read_to_end(&mut out)?;
    *pos += dec.total_in() as usize;
    Ok(out)
}

// Decompress into caller-supplied scratch buffer; clears but does not free it.
fn zlib_inflate_scratch(data: &[u8], pos: &mut usize, size_hint: usize, scratch: &mut Vec<u8>) -> io::Result<()> {
    scratch.clear();
    scratch.reserve(size_hint.saturating_sub(scratch.capacity()));
    let mut dec = ZlibDecoder::new(&data[*pos..]);
    dec.read_to_end(scratch)?;
    *pos += dec.total_in() as usize;
    Ok(())
}

fn u32_be(d: &[u8], o: usize) -> u32 { u32::from_be_bytes(d[o..o+4].try_into().unwrap()) }
fn u64_be(d: &[u8], o: usize) -> u64 { u64::from_be_bytes(d[o..o+8].try_into().unwrap()) }
fn bad(msg: &'static str) -> io::Error { io::Error::new(io::ErrorKind::InvalidData, msg) }

// Advance pos past a zlib stream without storing the output.
fn advance_zlib(data: &[u8], pos: &mut usize) -> io::Result<()> {
    let mut dec = ZlibDecoder::new(&data[*pos..]);
    io::copy(&mut dec, &mut io::sink())?;
    *pos += dec.total_in() as usize;
    Ok(())
}

/// Like `scan_objects` but without a `.idx` (e.g. pack received over the wire).
/// Single forward pass; git guarantees OFS_DELTA bases precede their dependents.
pub fn scan_objects_no_idx(
    pack: &[u8],
    kind_mask: u8,
    mut on_object: impl FnMut(u8, &[u8], u64) -> bool,
) -> io::Result<()> {
    if pack.len() < 12 || &pack[0..4] != PACK_MAGIC {
        return Err(bad("not a pack file"));
    }
    let count = u32_be(pack, 8) as usize;
    let mask  = if kind_mask == 0 { 0b1111u8 } else { kind_mask };

    let mut cache  = OffsetMap::new(count.next_power_of_two().max(16));
    cache.reserve(count as u64);
    let mut slab:    Vec<Vec<u8>> = Vec::new();
    let mut kinds:   Vec<u8>      = Vec::new();
    let mut scratch: Vec<u8>      = Vec::new();

    let mut pos = 12usize;
    let mut processed = 0usize;

    'scan: while processed < count && pos < pack.len().saturating_sub(20) {
        let obj_off = pos as u64;
        let (obj_type, size) = read_obj_header(pack, &mut pos);
        processed += 1;

        match obj_type {
            1..=4 => {
                let kind = obj_type as u8;
                let want = mask & (1 << (kind - 1)) != 0;
                if want {
                    let data = zlib_inflate_owned(pack, &mut pos, size as usize)?;
                    if !on_object(kind, &data, obj_off) { break 'scan; }
                    cache.set(obj_off, slab.len() as u32);
                    slab.push(data);
                    kinds.push(kind);
                } else {
                    advance_zlib(pack, &mut pos)?;
                }
            }
            6 => {
                let neg      = read_ofs_offset(pack, &mut pos);
                let base_off = obj_off.checked_sub(neg)
                    .ok_or_else(|| bad("OFS_DELTA underflow"))?;
                let Some(base_idx) = cache.get(base_off) else {
                    advance_zlib(pack, &mut pos)?;
                    continue;
                };
                let base_kind = kinds[base_idx as usize];
                zlib_inflate_scratch(pack, &mut pos, size as usize, &mut scratch)?;
                let data = apply_delta(&slab[base_idx as usize], &scratch)?;
                if !on_object(base_kind, &data, obj_off) { break 'scan; }
                cache.set(obj_off, slab.len() as u32);
                slab.push(data);
                kinds.push(base_kind);
            }
            7 => { pos += 20; advance_zlib(pack, &mut pos)?; }
            t => return Err(io::Error::new(io::ErrorKind::InvalidData,
                                           format!("unknown object type {t}"))),
        }
    }

    Ok(())
}
