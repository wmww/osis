//! Fixed inputs of the `seq_follow` fuzz target (core/test/fuzz/fuzz_targets/seq_follow.rs), shared with
//! its seeds (osis-vectors `corpus.rs`). Not part of the API.

use crate::{Batch, CounterRange, DeltaCtx, DeltaKind, Encoding, Fragment, Interner, Op, PathOp, Snapshot, Source, View, Writer, decode_snapshot, encode_snapshot};
use osis_base::{Tid, Ts, Value};
use std::borrow::Cow;

/// A text position's view.
pub struct TextView;

impl View for TextView {
    fn encoding(&self) -> Option<Encoding> {
        Some(Encoding::Text)
    }
    fn project<'a>(&self, v: &'a Value) -> Option<Cow<'a, Value>> {
        Some(Cow::Borrowed(v))
    }
    fn field(&self, _: u64) -> Option<TextView> {
        None
    }
    fn field_default(&self, _: u64) -> Option<Value> {
        None
    }
    fn case(&self, _: u64) -> Option<TextView> {
        None
    }
    fn element(&self) -> Option<TextView> {
        None
    }
    fn key(&self) -> Option<TextView> {
        None
    }
}

/// The context frame `frame` of an input decodes under: writer `source % 4` at a rising time,
/// with counters of its own (a writer never reuses a dot, §2.3).
pub fn seq_follow_cx(source: u8, frame: u64) -> DeltaCtx {
    let ts = Ts::from_u64((1_700_000_000_000 + frame) << 16).unwrap_or_default();
    let lo = 1 + frame * (1 << 16);
    DeltaCtx { ts, own: Source::node(Tid::from_bytes([source % 4 + 1; 15])), range: CounterRange { lo, hi: lo + (1 << 16) }, kind: DeltaKind::Writer }
}

/// The snapshot context of `seq_follow_state` and of the target's whole-pass check.
pub fn seq_follow_snap_cx() -> DeltaCtx {
    DeltaCtx { ts: Ts::from_u64(1_800_000_000_000 << 16).unwrap_or_default(), own: Source::node(Tid::from_bytes([9; 15])), range: CounterRange::EMPTY, kind: DeltaKind::Snapshot }
}

/// A text of a few hundred records typed and deleted in runs by two writers, through a
/// snapshot, so its deleted stretches are range records.
pub fn seq_follow_state() -> Fragment {
    let srcs = [Source::node(Tid::from_bytes([20; 15])), Source::node(Tid::from_bytes([21; 15]))];
    let mut lo = [1u64; 2];
    let mut st = Fragment::default();
    let mut x = 7u64;
    for k in 0..40u64 {
        x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let r = (x >> 33) as usize;
        let n = match st.read() {
            Some(Value::Str(s)) => s.chars().count(),
            _ => 0,
        };
        let op = if k % 3 == 2 && n > 10 { Op::Delete { at: r % (n - 8), len: 1 + r % 8 } } else { Op::Insert { at: r % (n + 1), items: vec![Value::Str("lorem ipsum ".into())] } };
        let i = (k % 2) as usize;
        let ts = Ts::from_u64((1_600_000_000_000 + k) << 16).unwrap_or_default();
        let (Some(src), Some(l)) = (srcs.get(i), lo.get_mut(i)) else { continue };
        let mut b = Batch::new(&st, Writer::new(ts, src.clone(), *l));
        if b.apply(&PathOp { path: vec![], op }, &TextView).is_err() {
            continue;
        }
        let Some((d, range)) = b.finish() else { continue };
        *l = range.hi;
        st.join(d);
    }
    let cx = seq_follow_snap_cx();
    let snap = Snapshot { absorbed: Default::default(), authors: Default::default(), nonce: [0; 16], fragment: st.clone(), frontiers: Default::default() };
    encode_snapshot(&snap, &cx, None).and_then(|b| decode_snapshot(&b, &cx, &mut Interner::new(), None)).map_or(st, |s| s.fragment)
}
