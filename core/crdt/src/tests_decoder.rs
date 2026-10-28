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
use osis_base::Value;
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

/// Every node of a value tree, pre-order.
fn count(v: &Value) -> usize {
    1 + match v {
        Value::List(l) => l.iter().map(count).sum(),
        Value::Map(m) => m.iter().map(|(k, x)| count(k) + count(x)).sum(),
        Value::Set(s) => s.iter().map(count).sum(),
        Value::Enum(_, Some(p)) => count(p),
        _ => 0,
    }
}

/// Mutates the `k`-th node (pre-order) of `v`: an int nudged or set to a boundary, an array
/// element dropped, duplicated or swapped with its neighbour, a map entry dropped, bytes or a
/// string changed, a bool flipped. `false` when that node cannot change.
fn mutate_at(r: &mut Rng, v: &mut Value, k: &mut usize) -> bool {
    if *k == 0 {
        return match v {
            Value::Int(i) => {
                *i = match r.below(5) {
                    0 => i.saturating_add(1),
                    1 => i.saturating_sub(1),
                    2 => 0,
                    3 => 1,
                    _ => 1 << 16,
                };
                true
            }
            Value::Bool(b) => {
                *b = !*b;
                true
            }
            Value::Bytes(b) if !b.is_empty() => {
                let p = r.below(b.len());
                if r.chance(1, 2) { b[p] ^= 1 } else { b.truncate(p) }
                true
            }
            Value::Str(x) => {
                if x.is_empty() || r.chance(1, 2) { x.push('x') } else { x.clear() }
                true
            }
            Value::List(l) if !l.is_empty() => {
                let p = r.below(l.len());
                match r.below(3) {
                    0 => drop(l.remove(p)),
                    1 => l.insert(p, l[p].clone()),
                    _ if p + 1 < l.len() => l.swap(p, p + 1),
                    _ => drop(l.remove(p)),
                }
                true
            }
            Value::Map(m) if !m.is_empty() => {
                let key = m.keys().nth(r.below(m.len())).cloned();
                key.map(|x| m.remove(&x)).is_some()
            }
            _ => false,
        };
    }
    *k -= 1;
    match v {
        Value::List(l) => l.iter_mut().any(|x| mutate_at(r, x, k)),
        Value::Map(m) => {
            // keys stay (a changed key would reorder the map); a pick inside a key changes nothing
            for (key, x) in m.iter_mut() {
                let n = count(key);
                if *k < n {
                    return false;
                }
                *k -= n;
                if mutate_at(r, x, k) {
                    return true;
                }
            }
            false
        }
        Value::Enum(_, Some(p)) => mutate_at(r, p, k),
        _ => false,
    }
}

/// A structural mutant of canonical bytes `b` (decoded to a value tree, one node changed,
/// re-encoded canonically), so it reaches the decoders' semantic checks; `None` if no node
/// changed.
fn mutate_tree(r: &mut Rng, b: &[u8]) -> Option<Vec<u8>> {
    let mut v = osis_base::decode(b, &osis_base::Limits { max_depth: 512, max_bytes: 1 << 24 }).ok()?;
    let n = count(&v);
    for _ in 0..8 {
        let mut w = v.clone();
        let mut k = r.below(n);
        if mutate_at(r, &mut w, &mut k) {
            v = w;
            return Some(osis_base::encode(&v));
        }
    }
    None
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The model knows the value tags set, tid and enum only: a fragment the implementation accepted
/// with an unknown tag (kept, spec/data-model.md §5) or a link is beyond it.
fn unmodeled_tag(f: &crate::fragment::Fragment) -> bool {
    let d = format!("{f:?}");
    d.contains("Unknown(") || d.contains("Link(")
}

/// Accept/reject agreement on one writer delta.
fn same_delta(bytes: &[u8], c: &MCommit) -> Result<(), String> {
    let imp = decode_delta(bytes, &writer_cx(&c.w), &mut Interner::new(), None);
    let model = m_decode_delta(bytes, &mut Ctx::writer(c.w.ts, c.w.source.clone(), c.w.lo, c.w.hi()));
    match (imp, model) {
        (Ok(d), Ok(f)) if d.fragment == frag(&f) => Ok(()),
        (Err(_), Err(_)) => Ok(()),
        (Ok(d), Err(MError::Bad("tag"))) if unmodeled_tag(&d.fragment) => Ok(()),
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
        (Ok(x), Err(MError::Bad("tag"))) if unmodeled_tag(&x.fragment) => Ok(()),
        (i, m) => {
            let again = m.as_ref().ok().map(|(f, _)| hex(&crdt_model::wire::encode_snapshot(f, &[], [3; 16], &mut Ctx::new(1 << 40, MSource::node(250), 1))));
            Err(format!("snapshot {}: model re-encodes {:?}; implementation {:?}, model {:?}", hex(bytes), again, i.map(|s| s.fragment), m))
        }
    }
}

/// A random history's deltas and snapshots, each mutated `per` times; the first disagreement.
fn differential(seed: u64, types: &[Ty], per: usize) -> Result<(), String> {
    let mut r = crate::testutil::rng(seed | 1);
    let commits = history_with(&mut r, types, (1..=3).map(MSource::node).collect(), 3);
    let mut state = None;
    for c in &commits {
        let bytes = encode_delta(&Delta { nonce: [7; 16], fragment: frag(&c.delta) }, &writer_cx(&c.w), None).map_err(|e| e.to_string())?;
        same_delta(&bytes, c)?;
        for _ in 0..per {
            let mut b = bytes.clone();
            mutate(&mut r, &mut b);
            same_delta(&b, c)?;
            if let Some(b) = mutate_tree(&mut r, &bytes) {
                same_delta(&b, c)?;
            }
        }
        mapply(&mut state, c.delta.clone());
    }
    if let Some(st) = &state {
        let s = Snapshot { absorbed: Default::default(), authors: Default::default(), nonce: [3; 16], fragment: frag(st), frontiers: Frontiers::default() };
        let bytes = encode_snapshot(&s, &snap_cx(), None).map_err(|e| e.to_string())?;
        same_snapshot(&bytes)?;
        for _ in 0..per * 4 {
            let mut b = bytes.clone();
            mutate(&mut r, &mut b);
            same_snapshot(&b)?;
            if let Some(b) = mutate_tree(&mut r, &bytes) {
                same_snapshot(&b)?;
            }
        }
    }
    Ok(())
}

// spec/crdt.md §2.3, §3.3 rule 7: every element of a writer's run is an own-source identity, so
// one past `hi` is out of range even when the run's first dot is not (shrunk from seed
// 2814254534854219504: the model checked only a run's first dot).
#[test]
fn run_past_counter_range_rejected_spec_2_3() {
    let w = crdt_model::ops::Writer::new(MSource::node(1), 3 << 16, 7); // range [7, 8)
    let l = |v: Vec<Value>| Value::List(v);
    let int = Value::Int;
    // a text delta deleting own elements first..first+n-1 at the delta stamp
    let delta = |first: i64, n: i64| {
        let flag = l(vec![int(0), int(n - 1), int(0), Value::Bool(true)]);
        let run = l(vec![int(first), int(n), l(vec![]), l(vec![]), l(vec![]), l(vec![flag])]);
        osis_base::encode(&l(vec![Value::Bytes(vec![7; 16]), l(vec![]), l(vec![]), l(vec![int(9), l(vec![]), l(vec![]), l(vec![run])])]))
    };
    let both = |b: &[u8]| {
        let imp = decode_delta(b, &writer_cx(&w), &mut Interner::new(), None).is_ok();
        let model = m_decode_delta(b, &mut Ctx::writer(w.ts, w.source.clone(), w.lo, w.hi())).is_ok();
        (imp, model)
    };
    assert_eq!(both(&delta(5, 2)), (true, true), "elements 5, 6 lie below lo");
    assert_eq!(both(&delta(5, 4)), (false, false), "element 8 lies at hi");
}

/// Mutations per commit of a differential history: 8 in tier 1, 40 with `OSIS_SLOW` (about
/// 1 s per case in debug at 40). The case count follows `PROPTEST_CASES`.
fn per() -> usize {
    if std::env::var_os("OSIS_SLOW").is_some() { 40 } else { 8 }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    /// §3.3 rule 7: text and list deltas and snapshots, mutated.
    #[test]
    fn seq_decoder_matches_model_spec_3_3(seed in any::<u64>()) {
        let inner = Ty::Struct([(1, Ty::Register), (2, Ty::Set(Box::new(Ty::Register)))].into_iter().collect());
        if let Err(e) = differential(seed, &[Ty::Text, Ty::List(Box::new(inner))], per()) {
            prop_assert!(false, "{}", e);
        }
    }

    /// §3.3 rule 7, §2.3: every encoding nested (registers, bags, struct, enum, set, map,
    /// sequences), and register and text at one position (snapshot `Slots`, §7), mutated.
    #[test]
    fn kitchen_sink_decoder_matches_model_spec_3_3(seed in any::<u64>()) {
        if let Err(e) = differential(seed, &[kitchen_sink(), Ty::Register, Ty::Text], per()) {
            prop_assert!(false, "{}", e);
        }
    }
}

/// §3.3 rule 7, §7: a mutated snapshot whose `Commits` give a register write a `Derived` stamp
/// (which no embedding could carry) is rejected by both decoders (pinned tier-2 seed).
#[test]
fn derived_register_write_rejected_spec_3_3() {
    differential(4077260943037867378, &[kitchen_sink(), Ty::Register, Ty::Text], 40).unwrap();
}
