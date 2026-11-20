//! `chunker/`: gear table and chunk boundaries (spec/wire.md §6). Generated. Chunk trees and
//! pages use osis-blob and osis-crdt (`chunker/tree.vec`, `chunker/pages.vec`).

use super::generated_header;
use crate::file::{Record, VecFile};
use crate::{hex, xof};
use osis_base::chunker::{GEAR, chunk_lengths};
use osis_base::{ChunkParams, format::CHUNK_MAX};

const SPEC: &str = "spec/wire.md §6";

pub fn gear() -> VecFile {
    let table: Vec<u8> = GEAR.iter().flat_map(|g| g.to_le_bytes()).collect();
    assert_eq!(table, xof("osis v1 gear table", 2048), "gear table per spec/wire.md §6");
    let mut cases = vec![
        Record::new()
            .with("case", "gear table")
            .with("spec", SPEC)
            .with("table-blake3", hex(&osis_base::hash::hash(&table)))
            .with("g0", hex(&table[..8]))
            .with("g255", hex(&table[2040..])),
    ];
    let inputs: [(&str, &str, Vec<u8>); 2] = [
        ("xof 4 MiB", "xof(\"osis test chunker\", 4194304)", xof("osis test chunker", 4 << 20)),
        ("zeros 1 MiB", "zeros(1048576)", vec![0; 1 << 20]),
    ];
    for (name, input, data) in inputs {
        let lens = chunk_lengths(&data, ChunkParams::FORMAT);
        if name.starts_with("zeros") {
            assert!(lens.iter().all(|&n| n == CHUNK_MAX), "zeros force CHUNK_MAX");
        }
        let lens: Vec<String> = lens.iter().map(usize::to_string).collect();
        cases.push(Record::new().with("case", name).with("spec", SPEC).with("input", input).with("lengths", lens.join(",")));
    }
    VecFile { header: generated_header("chunker", SPEC), cases }
}

/// `chunker/tree.vec`: chunk trees (spec/wire.md §6) by content hash alone (no encryption):
/// chunk count, per level the link counts of its nodes in order, root content hash. Dedup
/// secret `07`.
pub fn tree() -> VecFile {
    use osis_blob::{HashSink, write_tree};
    let dedup = osis_crypto::Secret32::from_bytes([0x07; 32]);
    let inputs: [(&str, &str, Vec<u8>); 2] =
        [("xof 64 MiB", "xof(\"osis test tree\", 67108864)", xof("osis test tree", 64 << 20)), ("zeros 1 MiB", "zeros(1048576)", vec![0; 1 << 20])];
    let mut cases = Vec::new();
    for (name, input, data) in inputs {
        let mut hs = HashSink::new(dedup.clone());
        let root = write_tree(&mut hs, ChunkParams::FORMAT, &data).unwrap();
        let mut r = Record::new().with("case", name).with("spec", SPEC).with("input", input).with("dedup", hex(dedup.expose())).with("chunks", hs.chunks.to_string());
        let top = hs.nodes.iter().map(|n| n.0).max().unwrap();
        for level in 1..=top {
            let sizes: Vec<String> = hs.nodes.iter().filter(|n| n.0 == level).map(|n| n.1.to_string()).collect();
            r = r.with(&format!("level-{level}"), sizes.join(","));
        }
        cases.push(r.with("root-hash", hex(&root.hash)));
    }
    VecFile { header: generated_header("chunker", SPEC), cases }
}

/// Records page plaintexts, links by keyed content hash only (blob ID and key zero).
struct PageRec {
    dedup: osis_crypto::Secret32,
    pages: Vec<Vec<u8>>,
    params: osis_crdt::PageParams,
}

impl osis_crdt::PageSink for PageRec {
    fn put(&mut self, plaintext: &[u8]) -> Result<osis_base::Link, osis_crdt::PageError> {
        self.pages.push(plaintext.to_vec());
        Ok(osis_base::Link { hash: osis_crypto::link_hash(&self.dedup, plaintext), blob: osis_base::BlobId([0; 32]), suite: 1, key: [0; 32], salt: [0; 16], del: osis_base::Del::NONE })
    }
    fn params(&self) -> osis_crdt::PageParams {
        self.params
    }
}

/// `chunker/pages.vec`: page split and link-page grouping of an element array (spec/crdt.md §8,
/// spec/wire.md §6) by content hash alone. Element `i` is the byte string of the 1024 bytes at
/// offset `1024 i` of the input (of 64 bytes, at small pages); dedup secret `07`. The format's
/// pages reach two levels only at about a gigabyte per level more, so a case at small pages
/// (stated parameters, the same rules) reaches four.
pub fn pages() -> VecFile {
    use osis_base::Value;
    const SPEC: &str = "spec/crdt.md §8, spec/wire.md §6";
    let dedup = osis_crypto::Secret32::from_bytes([0x07; 32]);
    let small = osis_crdt::PageParams { target: 600, cut: osis_base::ChunkParams { min: 128, max: 512, mask_bits: 6 }, fanout: 4, ..osis_crdt::PageParams::FORMAT };
    let format = osis_crdt::PageParams::FORMAT;
    let inputs: [(&str, usize, usize, osis_crdt::PageParams); 3] = [("pages 1 MiB", 1 << 20, 1024, format), ("link pages 64 MiB", 64 << 20, 1024, format), ("link levels at small pages 64 KiB", 64 << 10, 64, small)];
    let mut cases = Vec::new();
    for (name, n, size, params) in inputs {
        let data = xof("osis test pages", n);
        let items: Vec<Value> = data.chunks(size).map(|c| Value::Bytes(c.to_vec())).collect();
        let mut rec = PageRec { dedup: dedup.clone(), pages: Vec::new(), params };
        let top = osis_crdt::page_array(Some(&mut rec), &items).unwrap();
        let Value::List(top) = osis_base::decode(&top, &osis_base::Limits::DEFAULT).unwrap() else { panic!("array") };
        let mut elems = Vec::new();
        for p in &rec.pages {
            let Value::List(items) = osis_base::decode(p, &osis_base::Limits::new(4, osis_base::format::MAX_BLOB)).unwrap() else { panic!("page") };
            if !items.iter().all(|i| matches!(i, Value::Link(_))) {
                elems.push(items.len().to_string());
            }
        }
        let links: Vec<String> = link_levels(&rec.pages, &top).into_iter().rev().flatten().map(|n| n.to_string()).collect();
        assert_eq!(links.is_empty(), name.starts_with("pages"), "link pages only in the large cases");
        if params == format {
            assert_eq!(elems, naive_pages(&data).iter().map(usize::to_string).collect::<Vec<_>>(), "page rule re-derived");
        } else {
            assert!(levels(&rec.pages, &top) >= 4, "{name}: four page levels or more");
        }
        let top: Vec<String> = top.iter().map(|l| if let Value::Link(l) = l { hex(&l.hash) } else { panic!("link") }).collect();
        let mut r = Record::new()
            .with("case", name)
            .with("spec", SPEC)
            .with("input", format!("xof(\"osis test pages\", {n}) as byte strings of {size} bytes"));
        if params != format {
            r = r.with("params", format!("PAGE_TARGET {}, CHUNK_MIN {}, CHUNK_MAX {}, mask bits {}, fan-out {}", params.target, params.cut.min, params.cut.max, params.cut.mask_bits, params.fanout));
        }
        let mut r = r.with("dedup", hex(dedup.expose())).with("pages", elems.join(","));
        if !links.is_empty() {
            r = r.with("link-pages", links.join(","));
        }
        cases.push(r.with("top", top.join(",")));
    }
    VecFile { header: generated_header("chunker", SPEC), cases }
}

/// The link counts of the link pages under root list `top`, a level at a time from the top, each
/// in order.
fn link_levels(pages: &[Vec<u8>], top: &[osis_base::Value]) -> Vec<Vec<usize>> {
    use osis_base::Value;
    let dedup = osis_crypto::Secret32::from_bytes([0x07; 32]);
    let by: std::collections::HashMap<[u8; 32], &Vec<u8>> = pages.iter().map(|p| (osis_crypto::link_hash(&dedup, p), p)).collect();
    let (mut out, mut level) = (Vec::new(), top.to_vec());
    loop {
        let (mut counts, mut next) = (Vec::new(), Vec::new());
        for x in &level {
            let Value::Link(l) = x else { panic!("link") };
            if let Ok(Value::List(items)) = osis_base::decode(by[&l.hash], &osis_base::Limits::new(4, osis_base::format::MAX_BLOB))
                && items.iter().all(|i| matches!(i, Value::Link(_)))
            {
                counts.push(items.len());
                next.extend(items);
            }
        }
        if counts.is_empty() {
            return out;
        }
        out.push(counts);
        level = next;
    }
}

/// The page levels under root list `top`, leaves included: the first link followed down through
/// the recorded pages (by content hash).
fn levels(pages: &[Vec<u8>], top: &[osis_base::Value]) -> usize {
    use osis_base::Value;
    let dedup = osis_crypto::Secret32::from_bytes([0x07; 32]);
    let by: std::collections::HashMap<[u8; 32], &Vec<u8>> = pages.iter().map(|p| (osis_crypto::link_hash(&dedup, p), p)).collect();
    let first = |items: &[Value]| items.first().and_then(|x| if let Value::Link(l) = x { Some(l.hash) } else { None });
    let (mut at, mut d) = (first(top), 0);
    while let Some(p) = at.and_then(|h| by.get(&h)) {
        d += 1;
        at = match osis_base::decode(p, &osis_base::Limits::new(4, osis_base::format::MAX_BLOB)) {
            Ok(Value::List(items)) => first(&items),
            _ => None,
        };
    }
    d
}

/// The page rule of spec/wire.md §6 written out directly over the gear table: element counts.
fn naive_pages(data: &[u8]) -> Vec<usize> {
    use osis_base::format::{CHUNK_MAX, CHUNK_MIN};
    let (mut out, mut h, mut len, mut count) = (Vec::new(), 0u64, 0usize, 0usize);
    for e in data.chunks(1024) {
        let mut enc = vec![0x59, 0x04, 0x00];
        enc.extend_from_slice(e);
        let mut cut = false;
        for &b in &enc {
            h = (h << 1).wrapping_add(GEAR[usize::from(b)]);
            len += 1;
            cut |= len >= CHUNK_MIN && h >> 48 == 0;
        }
        count += 1;
        if cut || len >= CHUNK_MAX {
            out.push(count);
            (h, len, count) = (0, 0, 0);
        }
    }
    if count > 0 {
        out.push(count);
    }
    out
}
