//! `chunker/`: gear table and chunk boundaries (spec/wire.md §6). Generated. Chunk trees and
//! pages need osis-label and osis-crdt (`chunker/tree.vec`, `chunker/pages.vec`).

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
