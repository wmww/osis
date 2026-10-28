//! Delta and snapshot decoders (spec/crdt.md §7–§8): never panic; the decoders check
//! canonicality themselves; a decoded fragment reads and joins (twice: idempotent) without
//! panicking. The first byte picks the form: 0 writer delta, 1 snapshot, 2 import. Pages are
//! absent (a paged input fails with `Missing`).
#![no_main]

use libfuzzer_sys::fuzz_target;
use osis_core::{Tid, Ts};
use osis_crdt::{CounterRange, DeltaCtx, DeltaKind, Fragment, Interner, MemoryPages, Source, decode_delta, decode_snapshot};

fuzz_target!(|data: &[u8]| {
    let Some((&form, bytes)) = data.split_first() else { return };
    let ts = Ts::from_u64(1_700_000_000_000 << 16).unwrap_or_default();
    let (kind, own, range) = match form % 3 {
        0 => (DeltaKind::Writer, [1; 15], CounterRange { lo: 1, hi: 1000 }),
        1 => (DeltaKind::Snapshot, [9; 15], CounterRange::EMPTY),
        _ => (DeltaKind::Import, [9; 15], CounterRange::EMPTY),
    };
    let cx = DeltaCtx { ts, own: Source::node(Tid::from_bytes(own)), range, kind };
    let mut pages = MemoryPages::new();
    let mut interner = Interner::new();
    let fragment = if kind == DeltaKind::Snapshot {
        decode_snapshot(bytes, &cx, &mut interner, Some(&mut pages)).map(|s| s.fragment)
    } else {
        decode_delta(bytes, &cx, &mut interner, Some(&mut pages)).map(|d| d.fragment)
    };
    if let Ok(f) = fragment {
        let read = f.read();
        let mut st = Fragment::default();
        st.join(f.clone());
        assert_eq!(st.read(), read);
        st.join(f);
        assert_eq!(st.read(), read);
    }
});
