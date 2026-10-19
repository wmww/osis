//! Fuzz seed corpora (fuzz/README.md), derived from the vector files so every parser starts from
//! valid and just-invalid inputs. `gen-vectors corpus` writes them to `fuzz/corpus/<target>/`,
//! one file per seed named by the first 16 hex digits of its BLAKE3.

use crate::file::VecFile;
use crate::{root, unhex, xof};

/// Cases of every present vector file of `subject` (all cases, pending included).
fn cases_of(subject: &str) -> Vec<crate::file::Record> {
    let dir = root().join(subject);
    let mut out = Vec::new();
    let mut paths: Vec<_> = std::fs::read_dir(dir).into_iter().flatten().flatten().map(|e| e.path()).collect();
    paths.sort();
    for p in paths {
        if let Ok(f) = std::fs::read_to_string(&p).map_err(|e| e.to_string()).and_then(|t| VecFile::parse(&t)) {
            out.extend(f.cases);
        }
    }
    out
}

fn field_bytes(subject: &str, field: &str) -> Vec<Vec<u8>> {
    cases_of(subject).iter().filter_map(|c| c.get(field)).filter_map(|h| unhex(h).ok()).collect()
}

fn field_text(subject: &str, field: &str) -> Vec<Vec<u8>> {
    cases_of(subject).iter().filter_map(|c| c.get(field)).map(|s| s.as_bytes().to_vec()).collect()
}

/// `(target, seeds)` for every fuzz target. A new target adds its line here.
pub fn seeds() -> Vec<(&'static str, Vec<Vec<u8>>)> {
    let cbor = field_bytes("cbor", "hex");
    let mut records = field_bytes("tid", "record");
    records.extend(cbor.iter().cloned());
    let mut tids = field_text("tid", "text");
    tids.extend(field_text("tid", "uri"));
    tids.push(b"AAAAAAAAAAAAAAAAAAAA".to_vec());
    tids.push(b"osis://_-_-_-_-_-_-_-_-_-_-".to_vec());
    let mut chunk = vec![3u8];
    chunk.extend(xof("osis fuzz chunker", 4000));
    // schema_dsl: a leading 0 byte means a schema value (CBOR), anything else DSL text.
    let mut schema: Vec<Vec<u8>> = field_bytes("schema", "value").into_iter().map(|v| [vec![0], v].concat()).collect();
    for src in [osis_schema::CORE_SRC, osis_schema::META_SRC] {
        schema.push([b"\x01".to_vec(), src.as_bytes().to_vec()].concat());
    }
    vec![
        ("cbor_decode", cbor),
        ("schema_dsl", schema),
        ("creation_record", records),
        ("tid_parse", tids),
        ("chunker", vec![vec![0], vec![1; 300], chunk]),
    ]
}

/// Replaces each target's seed directory with the seeds; returns how many files were written.
pub fn write() -> Result<usize, String> {
    let base = root().join("../fuzz/corpus");
    let mut n = 0;
    for (target, seeds) in seeds() {
        let dir = base.join(target);
        if dir.exists() {
            std::fs::remove_dir_all(&dir).map_err(|e| e.to_string())?;
        }
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        for s in seeds {
            let name = &crate::hex(&osis_core::hash::hash(&s))[..16];
            std::fs::write(dir.join(name), &s).map_err(|e| e.to_string())?;
            n += 1;
        }
    }
    Ok(n)
}
