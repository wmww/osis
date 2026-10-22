//! The cached sequence placement (spec/crdt.md §6) followed through joins: from a fixed text with
//! deleted stretches as range records, frames `[source, len lo, len hi, delta]` decode as text
//! writer deltas of up to four sources; before each join the placement is read (cached), and
//! after it the read equals that of the state rebuilt through a snapshot round trip (a whole
//! pass). A frame that does not decode or is not text is skipped.
#![no_main]

use libfuzzer_sys::fuzz_target;
use osis_crdt::fuzzing::{seq_follow_cx, seq_follow_snap_cx, seq_follow_state};
use osis_crdt::{Encoding, Fragment, Interner, Snapshot, decode_delta, decode_snapshot, encode_snapshot};
use std::sync::OnceLock;

static STATE: OnceLock<Fragment> = OnceLock::new();

fuzz_target!(|data: &[u8]| {
    let mut st = STATE.get_or_init(seq_follow_state).clone();
    let scx = seq_follow_snap_cx();
    let mut rest = data;
    let mut frame = 0u64;
    while let [src, l0, l1, tail @ ..] = rest {
        let n = usize::from(u16::from_le_bytes([*l0, *l1])).min(tail.len());
        let (bytes, more) = tail.split_at(n);
        rest = more;
        let cx = seq_follow_cx(*src, frame);
        frame += 1;
        let Ok(d) = decode_delta(bytes, &cx, &mut Interner::new(), None) else { continue };
        if d.fragment.encoding() != Encoding::Text {
            continue;
        }
        let _ = st.read();
        st.join(d.fragment);
        let read = st.read();
        let snap = Snapshot { absorbed: Default::default(), authors: Default::default(), nonce: [0; 16], fragment: st.clone(), frontiers: Default::default() };
        let Ok(b) = encode_snapshot(&snap, &scx, None) else { continue };
        let fresh = decode_snapshot(&b, &scx, &mut Interner::new(), None).expect("own snapshot decodes");
        assert_eq!(fresh.fragment.read(), read);
    }
});
