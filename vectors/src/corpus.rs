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
    // proto_frame: message bodies, Hello, and framed bodies.
    let mut proto = field_bytes("proto", "hex");
    proto.extend(field_bytes("proto", "frame"));
    let mut prefixes = field_bytes("blob", "prefix");
    prefixes.extend(field_bytes("blob", "blob"));
    prefixes.extend(field_bytes("blob", "padded"));
    let mut steps = field_bytes("step", "step");
    steps.extend(field_bytes("step", "claim-set"));
    let mut signals = field_bytes("signal", "body");
    signals.extend(field_bytes("signal", "publish-auth"));
    let mut links = field_bytes("link", "bytes");
    links.extend(field_text("link", "text").into_iter().map(|t| [vec![0], t].concat()));
    vec![
        ("blob_prefix", prefixes),
        ("step", steps),
        ("inbox", field_bytes("inbox", "payload")),
        ("signal", signals),
        ("link_card", links),
        ("bundle", field_bytes("bundle", "bundle")),
        ("cbor_decode", cbor),
        ("proto_frame", proto),
        ("schema_dsl", schema),
        ("creation_record", records),
        ("tid_parse", tids),
        ("chunker", vec![vec![0], vec![1; 300], chunk]),
        ("commit_header", [field_bytes("commit", "header"), field_bytes("commit", "blob")].concat()),
        ("delta", delta_seeds()),
        ("box", [field_bytes("box", "sealed"), field_bytes("box", "wrap"), field_bytes("box", "box"), field_bytes("box", "padded"), field_bytes("box", "sealed-value")].concat()),
    ]
}

/// `delta`: a form byte (0 writer delta, 1 snapshot; fuzz/fuzz_targets/delta.rs fixes the
/// contexts) and an encoded delta of each encoding's typical values.
fn delta_seeds() -> Vec<Vec<u8>> {
    use osis_core::{Tid, Ts, Value};
    use osis_crdt::{AnyView, CounterRange, Delta, DeltaCtx, DeltaKind, Fragment, Frontiers, Snapshot, Source, Writer, create, encode_delta, encode_snapshot};
    let ts = Ts::from_u64(1_700_000_000_000 << 16).unwrap_or_default();
    let s = |x: &str| Value::Str(x.into());
    let values = [
        Value::Int(7),
        s("hello"),
        Value::Bytes(vec![1, 2, 3]),
        Value::List(vec![s("a"), s("b"), s("c")]),
        Value::Map([(s("x"), Value::Int(1)), (s("y"), Value::List(vec![Value::Int(2)]))].into_iter().collect()),
        Value::Set([Value::Int(1), Value::Int(2)].into_iter().collect()),
    ];
    let writer = Source::node(Tid::from_bytes([1; 15]));
    let mut out = Vec::new();
    for v in &values {
        let mut w = Writer::new(ts, writer.clone(), 1);
        let Ok(fragment) = create(&mut w, &AnyView, v) else { continue };
        let cx = DeltaCtx { ts, own: writer.clone(), range: CounterRange { lo: 1, hi: 1000 }, kind: DeltaKind::Writer };
        if let Ok(b) = encode_delta(&Delta { nonce: [1; 16], fragment: fragment.clone() }, &cx, None) {
            out.push([vec![0], b].concat());
        }
        let mut st = Fragment::default();
        st.join(fragment);
        let cx = DeltaCtx { ts, own: Source::node(Tid::from_bytes([9; 15])), range: CounterRange::EMPTY, kind: DeltaKind::Snapshot };
        let snap = Snapshot { nonce: [2; 16], fragment: st, frontiers: Frontiers::default(), authors: Default::default() };
        if let Ok(b) = encode_snapshot(&snap, &cx, None) {
            out.push([vec![1], b].concat());
        }
    }
    out
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
