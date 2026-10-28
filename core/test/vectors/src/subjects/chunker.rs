//! `chunker/`: gear table and chunk boundaries (spec/wire.md §6). Generated. Chunk trees and
//! pages use osis-label and osis-crdt (`chunker/tree.vec`, `chunker/pages.vec`).

use super::generated_header;
use crate::file::{Record, VecFile};
use crate::{hex, xof};
use osis_core::chunker::{GEAR, chunk_lengths};
use osis_core::{ChunkParams, format::CHUNK_MAX};

const SPEC: &str = "spec/wire.md §6";

pub fn gear() -> VecFile {
    let table: Vec<u8> = GEAR.iter().flat_map(|g| g.to_le_bytes()).collect();
    assert_eq!(table, xof("osis v1 gear table", 2048), "gear table per spec/wire.md §6");
    let mut cases = vec![
        Record::new()
            .with("case", "gear table")
            .with("spec", SPEC)
            .with("table-blake3", hex(&osis_core::hash::hash(&table)))
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
    use osis_label::{HashSink, write_tree};
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
}

impl osis_crdt::PageSink for PageRec {
    fn put(&mut self, plaintext: &[u8]) -> Result<osis_core::Link, osis_crdt::PageError> {
        self.pages.push(plaintext.to_vec());
        Ok(osis_core::Link { hash: osis_crypto::link_hash(&self.dedup, plaintext), blob: osis_core::BlobId([0; 32]), suite: 1, key: [0; 32] })
    }
}

/// `chunker/pages.vec`: page split and link-page grouping of an element array (spec/crdt.md §8,
/// spec/wire.md §6) by content hash alone. Element `i` is the byte string of the 1024 bytes at
/// offset `1024 i` of the input; dedup secret `07`.
pub fn pages() -> VecFile {
    use osis_core::Value;
    const SPEC: &str = "spec/crdt.md §8, spec/wire.md §6";
    let dedup = osis_crypto::Secret32::from_bytes([0x07; 32]);
    let inputs: [(&str, usize); 2] = [("pages 1 MiB", 1 << 20), ("link pages 64 MiB", 64 << 20)];
    let mut cases = Vec::new();
    for (name, n) in inputs {
        let data = xof("osis test pages", n);
        let items: Vec<Value> = data.chunks(1024).map(|c| Value::Bytes(c.to_vec())).collect();
        let mut rec = PageRec { dedup: dedup.clone(), pages: Vec::new() };
        let top = osis_crdt::page_array(Some(&mut rec), items).unwrap();
        let Value::List(top) = top else { panic!("array") };
        let (mut elems, mut links) = (Vec::new(), Vec::new());
        for p in &rec.pages {
            let Value::List(items) = osis_core::decode(p, &osis_core::Limits { max_depth: 4, max_bytes: osis_core::format::MAX_BLOB }).unwrap() else { panic!("page") };
            if items.iter().all(|i| matches!(i, Value::Link(_))) {
                links.push(items.len().to_string());
            } else {
                elems.push(items.len().to_string());
            }
        }
        assert_eq!(links.is_empty(), name.starts_with("pages"), "link pages only in the large case");
        assert_eq!(elems, naive_pages(&data).iter().map(usize::to_string).collect::<Vec<_>>(), "page rule re-derived");
        let top: Vec<String> = top.iter().map(|l| if let Value::Link(l) = l { hex(&l.hash) } else { panic!("link") }).collect();
        let mut r = Record::new()
            .with("case", name)
            .with("spec", SPEC)
            .with("input", format!("xof(\"osis test pages\", {n}) as byte strings of 1024 bytes"))
            .with("dedup", hex(dedup.expose()))
            .with("pages", elems.join(","));
        if !links.is_empty() {
            r = r.with("link-pages", links.join(","));
        }
        cases.push(r.with("top", top.join(",")));
    }
    VecFile { header: generated_header("chunker", SPEC), cases }
}

/// The page rule of spec/wire.md §6 written out directly over the gear table: element counts.
fn naive_pages(data: &[u8]) -> Vec<usize> {
    use osis_core::format::{CHUNK_MAX, CHUNK_MIN};
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
