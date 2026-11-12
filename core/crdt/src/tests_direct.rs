//! The direct codec (bytes read and written in place, no `Value` tree between) against the
//! `Value`-tree codec it replaced (`value_codec`): every encode writes the same root bytes and
//! puts the same pages in the same order; every decode, of valid inputs and of mutants of them
//! (root or page, bytewise or by one value node), decides alike with the same result or the
//! same error, whole, streamed, decode-only and through the whole-delta oracle.

use crate::codec::{decode_delta, decode_snapshot, encode_delta_in, encode_snapshot};
use crate::page::{PageSink, PageSource};
use crate::stamp::Interner;
use crate::tests_stream::{Blobs, Input, SMALL, TINY, mutant, per, types};
use crate::tests_wire::{snap_cx, writer_cx};
use crate::testutil::{frag, history_bulk, history_with, mapply};
use crate::value_codec as old;
use crate::wire::{Delta, DeltaCtx, Frontiers, Snapshot};
use crate::{Checked, Fragment};
use crdt_model::r#gen::Rng;
use crdt_model::stamp::Source as MSource;
use osis_base::Value;
use proptest::prelude::*;

type Out = Result<String, String>;
type Encode<'f> = dyn Fn(Option<&mut dyn PageSink>) -> Result<Vec<u8>, crate::Error> + 'f;

fn show<T: std::fmt::Debug>(r: Result<T, crate::Error>) -> Out {
    r.map(|x| format!("{x:?}")).map_err(|e| e.to_string())
}

/// Encodes with both codecs into fresh sinks: the same root and pages (in put order), or the
/// same error. The new encoding as an input.
fn encode_both(cx: &DeltaCtx, params: Option<crate::page::PageParams>, snapshot: bool, new: &Encode, old: &Encode) -> Result<Option<Input>, String> {
    let mut a = params.map(Blobs::new);
    let mut b = params.map(Blobs::new);
    let x = new(a.as_mut().map(|p| p as &mut dyn PageSink));
    let y = old(b.as_mut().map(|p| p as &mut dyn PageSink));
    let pages = |p: &Option<Blobs>| p.as_ref().map(|p| p.pages.clone());
    match (x, y) {
        (Ok(x), Ok(y)) if x == y && pages(&a) == pages(&b) => Ok(Some(Input { root: x, pages: a, cx: cx.clone(), snapshot })),
        (Ok(x), Ok(y)) => Err(format!("encodings differ: new {}, old {}", hex(&x), hex(&y))),
        (Err(x), Err(y)) if x.to_string() == y.to_string() => Ok(None),
        (x, y) => Err(format!("encode: new {x:?}, old {y:?}")),
    }
}

fn src(p: &mut Option<Blobs>) -> Option<&mut dyn PageSource> {
    p.as_mut().map(|p| p as &mut dyn PageSource)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Encodes a delta with both codecs (`encode_both`).
fn delta_both(d: &Delta, cx: &DeltaCtx, params: Option<crate::page::PageParams>) -> Result<Option<Input>, String> {
    encode_both(cx, params, false, &|p| encode_delta_in(d, cx, p), &|p| old::codec::encode_delta(d, cx, p))
}

/// Encodes a snapshot with both codecs (`encode_both`).
fn snapshot_both(s: &Snapshot, params: Option<crate::page::PageParams>) -> Result<Option<Input>, String> {
    let cx = snap_cx();
    encode_both(&cx, params, true, &|p| encode_snapshot(s, &cx, p), &|p| old::codec::encode_snapshot(s, &cx, p))
}

/// Every reading of `i` by both codecs: the whole decode, the streamed pieces, the whole-delta
/// oracle, and (accepted bytes) the decode-only readers. Whether it was accepted.
fn decode_both(i: &Input) -> Result<bool, String> {
    let pages = || i.pages.clone();
    let cx = &i.cx;
    let (mut p, mut q) = (pages(), pages());
    let (whole_new, whole_old) = if i.snapshot {
        (show(decode_snapshot(&i.root, cx, &mut Interner::new(), src(&mut p))), show(old::codec::decode_snapshot(&i.root, cx, &mut Interner::new(), src(&mut q))))
    } else {
        (show(decode_delta(&i.root, cx, &mut Interner::new(), src(&mut p))), show(old::codec::decode_delta(&i.root, cx, &mut Interner::new(), src(&mut q))))
    };
    let (mut p, mut q) = (pages(), pages());
    let (oracle_new, oracle_old) = if i.snapshot {
        (show(crate::codec::oracle::decode_snapshot(&i.root, cx, &mut Interner::new(), src(&mut p))), show(old::codec::oracle::decode_snapshot(&i.root, cx, &mut Interner::new(), src(&mut q))))
    } else {
        (show(crate::codec::oracle::decode_delta(&i.root, cx, &mut Interner::new(), src(&mut p))), show(old::codec::oracle::decode_delta(&i.root, cx, &mut Interner::new(), src(&mut q))))
    };
    let (mut p, mut q) = (pages(), pages());
    let (mut a, mut b) = (Vec::new(), Vec::new());
    let (stream_new, stream_old) = if i.snapshot {
        let x = crate::stream_snapshot(&i.root, cx, &mut Interner::new(), src(&mut p), &mut |x| { a.push(format!("{x:?}")); Ok(()) });
        let y = old::stream::stream_snapshot(&i.root, cx, &mut Interner::new(), src(&mut q), &mut |x| { b.push(format!("{x:?}")); Ok(()) });
        (show(x), show(y))
    } else {
        let x = crate::stream_delta(&i.root, cx, &mut Interner::new(), src(&mut p), &mut |x| { a.push(format!("{x:?}")); Ok(()) });
        let y = old::stream::stream_delta(&i.root, cx, &mut Interner::new(), src(&mut q), &mut |x| { b.push(format!("{x:?}")); Ok(()) });
        (show(x), show(y))
    };
    let all = [("whole", whole_new, whole_old), ("oracle", oracle_new, oracle_old), ("stream", stream_new.map(|h| format!("{h} {a:?}")), stream_old.map(|h| format!("{h} {b:?}")))];
    for (what, new, old) in &all {
        if new != old {
            return Err(format!("{what} decode differs on root {} pages {:?}: new {new:?}, old {old:?}", hex(&i.root), i.pages.as_ref().map(|p| p.pages.iter().map(|x| hex(x)).collect::<Vec<_>>())));
        }
    }
    let accepted = all[0].1.is_ok();
    if accepted {
        let (mut p, mut q) = (pages(), pages());
        let x = show(crate::decode_checked(Checked::verified(&i.root), cx, &mut Interner::new(), src(&mut p)));
        let y = show(old::stream::decode_checked(old::stream::Checked::verified(&i.root), cx, &mut Interner::new(), src(&mut q)));
        let (mut p, mut q) = (pages(), pages());
        let (mut a, mut b) = (Vec::new(), Vec::new());
        let xs = show(crate::stream_checked(Checked::verified(&i.root), cx, &mut Interner::new(), src(&mut p), &mut |x| { a.push(format!("{x:?}")); Ok(()) }));
        let ys = show(old::stream::stream_checked(old::stream::Checked::verified(&i.root), cx, &mut Interner::new(), src(&mut q), &mut |x| { b.push(format!("{x:?}")); Ok(()) }));
        if x != y || xs != ys || a != b {
            return Err(format!("decode-only reads differ on root {}", hex(&i.root)));
        }
    }
    Ok(accepted)
}

/// A random value of every kind a register or map key may hold (links and unknown tags too).
fn value(r: &mut Rng, depth: usize) -> Value {
    let leaf = depth == 0 || r.chance(1, 2);
    if leaf {
        return match r.below(9) {
            0 => Value::Int(r.below(600) as i64 - 300),
            1 => Value::Int([i64::MIN, i64::MAX, 23, 24, -25, 65536][r.below(6)]),
            2 => Value::float([0.5, -0.0, f64::NAN, f64::INFINITY, 1e300][r.below(5)]),
            3 => Value::Bool(r.chance(1, 2)),
            4 => Value::Str(["", "a", "ключ", "\u{1f600}x"][r.below(4)].repeat(1 + r.below(3))),
            5 => Value::Bytes(vec![r.below(256) as u8; r.below(40)]),
            6 => Value::Tid(osis_base::Tid::from_bytes([r.below(256) as u8; 15])),
            7 => Value::link(osis_base::Link { hash: [r.below(3) as u8; 32], blob: osis_base::BlobId([r.below(256) as u8; 32]), suite: 1, key: [7; 32] }),
            _ => Value::Enum(r.below(30) as u64, None),
        };
    }
    let n = r.below(4);
    match r.below(5) {
        0 => Value::List((0..n).map(|_| value(r, depth - 1)).collect()),
        1 => Value::Map((0..n).map(|_| (value(r, depth - 1), value(r, depth - 1))).collect()),
        2 => Value::Set((0..n).map(|_| value(r, depth - 1)).collect()),
        3 => Value::Enum(r.below(5) as u64, Some(Box::new(value(r, depth - 1)))),
        _ => Value::unknown(osis_base::Unknown::new(70_000 + r.below(3) as u64, osis_base::CanonicalBytes::from_value(&value(r, depth - 1))).unwrap_or_else(|| unreachable!())),
    }
}

/// A writer's delta creating a map of random keys and values, its context.
fn value_map(r: &mut Rng, n: usize) -> (Fragment, DeltaCtx) {
    use crdt_model::ops::Ty;
    let node = crate::testutil::sess(osis_base::Tid::from_bytes([1; 15]));
    let map = Value::Map((0..n).map(|_| (value(r, 3), value(r, 3))).collect());
    let mut w = crate::Writer::new(crate::testutil::ts(1 << 20), node.clone(), 1);
    let d = crate::create(&mut w, &crate::testutil::TyView(Ty::Map(Box::new(Ty::Register), Box::new(Ty::Register))), &map).unwrap_or_else(|e| panic!("create: {e}"));
    (d, DeltaCtx { ts: crate::testutil::ts(1 << 20), own: node, range: w.range(), kind: crate::DeltaKind::Writer })
}

/// One case: a random history's deltas and snapshot and a map of random values, encoded by
/// both codecs, then each input and `per()` mutants decoded by both. (accepted, rejected).
fn case(seed: u64) -> Result<(usize, usize), String> {
    let mut r = crate::testutil::rng(seed | 1);
    let params = [None, Some(TINY), Some(SMALL)][(seed / 3 % 3) as usize];
    let sources = (1..=3).map(|n| MSource::session(n, 0)).collect();
    let tys = types(seed);
    let commits = if params.is_some() { history_bulk(&mut r, &tys, sources, 12) } else { history_with(&mut r, &tys, sources, 3) };
    let mut ins = Vec::new();
    let mut state = None;
    for c in &commits {
        let d = Delta { nonce: [7; 16], fragment: frag(&c.delta) };
        ins.extend(delta_both(&d, &writer_cx(&c.w), params)?);
        mapply(&mut state, c.delta.clone());
    }
    if let Some(st) = &state {
        let s = Snapshot { absorbed: Default::default(), nonce: [3; 16], fragment: frag(st), frontiers: Frontiers::default(), facts: Default::default() };
        ins.extend(snapshot_both(&s, params)?);
    }
    let n = 1 + r.below(if params.is_some() { 60 } else { 8 });
    let (f, cx) = value_map(&mut r, n);
    ins.extend(delta_both(&Delta { nonce: [1; 16], fragment: f.clone() }, &cx, params)?);
    let facts = [((cx.ts, cx.own.clone()), crate::Fact { by: osis_base::PurgeBy::AuthorOrAdmin, actor: Some(osis_base::Tid::from_bytes([9; 15])) })].into();
    ins.extend(snapshot_both(&Snapshot { absorbed: [(osis_base::CommitId([4; 32]), osis_base::Tid::from_bytes([2; 15]))].into(), nonce: [2; 16], fragment: f, frontiers: Frontiers::default(), facts }, params)?);
    let mut n = (0, 0);
    let mut mr = crate::testutil::rng(seed ^ 0xd1ec);
    for i in &ins {
        if !decode_both(i)? {
            return Err(format!("an encoding rejected: root {}", hex(&i.root)));
        }
        for _ in 0..per() {
            if decode_both(&mutant(&mut mr, i))? {
                n.0 += 1;
            } else {
                n.1 += 1;
            }
        }
    }
    Ok(n)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(12))]

    /// The direct codec writes and reads exactly as the `Value`-tree codec did.
    #[test]
    fn direct_codec_matches_value_codec(seed in any::<u64>()) {
        if let Err(e) = case(seed) {
            prop_assert!(false, "{}", e);
        }
    }
}

/// The differential reaches both decisions often (else it tests nothing).
#[test]
fn direct_codec_differential_covers() {
    let mut n = (0, 0);
    for seed in 0..9u64 {
        let m = case(seed).unwrap_or_else(|e| panic!("seed {seed}: {e}"));
        n = (n.0 + m.0, n.1 + m.1);
    }
    assert!(n.0 > 20 && n.1 > 100, "accepted, rejected {n:?}");
}

/// `direct_codec_matches_value_codec` at size (a property).
#[test]
#[ignore = "property"]
fn direct_codec_matches_value_codec_large() {
    let seeds = osis_base::testenv::Seeds::from_env("OSIS_CRDT_START", "OSIS_CRDT_SEEDS", 0..600);
    let replay = |s: u64| format!("OSIS_CRDT_START={s} OSIS_CRDT_SEEDS=1 cargo test -p osis-crdt --lib -- --ignored --exact tests_direct::direct_codec_matches_value_codec_large");
    seeds.run("tests_direct::direct_codec_matches_value_codec_large", replay, |seed| {
        if let Err(e) = case(seed) {
            panic!("seed {seed}: {e}");
        }
    });
}
