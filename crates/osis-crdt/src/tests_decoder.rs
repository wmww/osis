//! Decoder differential (spec/crdt.md §3.3 rule 7, §2.3): the implementation's decoder and the
//! model's accept and reject the same mutated writer deltas and snapshots, and decode what both
//! accept to the same fragment.

use crate::codec::{decode_delta, decode_snapshot, encode_delta, encode_snapshot};
use crate::stamp::Interner;
use crate::testutil::{MCommit, frag, history_with, mapply};
use crate::tests_wire::{snap_cx, writer_cx};
use crate::wire::{Delta, Frontiers, Snapshot};
use crdt_model::ops::Ty;
use crdt_model::r#gen::{Rng, kitchen_sink};
use crdt_model::stamp::Source as MSource;
use crdt_model::cbor::Error as MError;
use crdt_model::wire::{Ctx, decode_delta as m_decode_delta, decode_snapshot as m_decode_snapshot};
use proptest::prelude::*;

/// Bytes worth writing where a small CBOR item sits: small uints, empty and short arrays,
/// booleans, empty strings, a negative int, a one-byte uint head.
const SPECIAL: [u8; 12] = [0x00, 0x01, 0x02, 0x18, 0x20, 0x40, 0x60, 0x80, 0x81, 0x82, 0xf4, 0xf5];

/// One mutation of `b`: a byte moved by one, overwritten (often by a small item), inserted,
/// removed, or the tail cut.
fn mutate(r: &mut Rng, b: &mut Vec<u8>) {
    if b.is_empty() {
        return;
    }
    let p = r.below(b.len());
    let byte = |r: &mut Rng| if r.chance(2, 3) { SPECIAL[r.below(SPECIAL.len())] } else { r.below(256) as u8 };
    match r.below(8) {
        0..=2 => b[p] = if r.chance(1, 2) { b[p].wrapping_add(1) } else { b[p].wrapping_sub(1) },
        3 | 4 => b[p] = byte(r),
        5 => b.insert(p, byte(r)),
        6 => drop(b.remove(p)),
        _ => b.truncate(p),
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Accept/reject agreement on one writer delta.
fn same_delta(bytes: &[u8], c: &MCommit) -> Result<(), String> {
    let imp = decode_delta(bytes, &writer_cx(&c.w), &mut Interner::new(), None);
    let model = m_decode_delta(bytes, &mut Ctx::writer(c.w.ts, c.w.source.clone(), c.w.lo, c.w.hi()));
    match (imp, model) {
        (Ok(d), Ok(f)) if d.fragment == frag(&f) => Ok(()),
        (Err(_), Err(_)) => Ok(()),
        // value tags beyond set, tid and enum are not modeled (spec/data-model.md §5: unknown tags kept)
        (_, Err(MError::Bad("tag"))) => Ok(()),
        (i, m) => Err(format!("delta {}: implementation {:?}, model {:?}", hex(bytes), i.map(|d| d.fragment), m)),
    }
}

/// Accept/reject agreement on one snapshot.
fn same_snapshot(bytes: &[u8]) -> Result<(), String> {
    let imp = decode_snapshot(bytes, &snap_cx(), &mut Interner::new(), None);
    let model = m_decode_snapshot(bytes, &mut Ctx::new(1 << 40, MSource::node(250), 1));
    match (imp, model) {
        (Ok(s), Ok((f, _))) if s.fragment == frag(&f) => Ok(()),
        (Err(_), Err(_)) => Ok(()),
        (_, Err(MError::Bad("tag"))) => Ok(()),
        (i, m) => {
            let again = m.as_ref().ok().map(|(f, _)| hex(&crdt_model::wire::encode_snapshot(f, &[], [3; 16], &mut Ctx::new(1 << 40, MSource::node(250), 1))));
            Err(format!("snapshot {}: model re-encodes {:?}; implementation {:?}, model {:?}", hex(bytes), again, i.map(|s| s.fragment), m))
        }
    }
}

/// A random history's deltas and snapshots, each mutated `per` times; the first disagreement.
fn differential(seed: u64, types: &[Ty], per: usize) -> Result<(), String> {
    let mut r = Rng(seed | 1);
    let commits = history_with(&mut r, types, (1..=3).map(MSource::node).collect(), 3);
    let mut state = None;
    for c in &commits {
        let bytes = encode_delta(&Delta { nonce: [7; 16], fragment: frag(&c.delta) }, &writer_cx(&c.w), None).map_err(|e| e.to_string())?;
        same_delta(&bytes, c)?;
        for _ in 0..per {
            let mut b = bytes.clone();
            mutate(&mut r, &mut b);
            same_delta(&b, c)?;
        }
        mapply(&mut state, c.delta.clone());
    }
    if let Some(st) = &state {
        let s = Snapshot { nonce: [3; 16], fragment: frag(st), frontiers: Frontiers::default() };
        let bytes = encode_snapshot(&s, &snap_cx(), None).map_err(|e| e.to_string())?;
        same_snapshot(&bytes)?;
        for _ in 0..per * 4 {
            let mut b = bytes.clone();
            mutate(&mut r, &mut b);
            same_snapshot(&b)?;
        }
    }
    Ok(())
}

proptest! {
    /// §3.3 rule 7: text and list deltas and snapshots, mutated.
    #[test]
    fn seq_decoder_matches_model_spec_3_3(seed in any::<u64>()) {
        let inner = Ty::Struct([(1, Ty::Register), (2, Ty::Set(Box::new(Ty::Register)))].into_iter().collect());
        if let Err(e) = differential(seed, &[Ty::Text, Ty::List(Box::new(inner))], 40) {
            prop_assert!(false, "{}", e);
        }
    }

    /// §3.3 rule 7, §2.3: every encoding nested (registers, bags, struct, enum, set, map,
    /// sequences), and register and text at one position (snapshot `Slots`, §7), mutated.
    #[test]
    fn kitchen_sink_decoder_matches_model_spec_3_3(seed in any::<u64>()) {
        if let Err(e) = differential(seed, &[kitchen_sink(), Ty::Register, Ty::Text], 40) {
            prop_assert!(false, "{}", e);
        }
    }
}
