//! spec/wire.md §11.3: fingerprints, the split rule, convergence.

use super::*;
use crate::msg::Message;
use osis_core::LabelId;
use proptest::prelude::*;

fn id_of(n: u64) -> BlobId {
    BlobId(osis_core::hash::hash(&n.to_le_bytes()))
}

fn set(ns: impl IntoIterator<Item = u64>) -> Vec<BlobId> {
    let mut v: Vec<BlobId> = ns.into_iter().map(id_of).collect();
    v.sort();
    v.dedup();
    v
}

/// Runs a full reconciliation through encoded messages; returns (need, have, rounds).
pub(crate) fn reconcile(a: &[BlobId], b: &[BlobId]) -> (BTreeSet<BlobId>, BTreeSet<BlobId>, usize) {
    let mut r = Reconciler::new(a);
    let mut rounds = 0;
    while r.has_queued() {
        rounds += 1;
        assert!(rounds < 64, "no convergence");
        let mut replies = Vec::new();
        while let Some((token, batch)) = r.next_batch() {
            let req = Message::Reconcile { id: 1, label: LabelId([0; 16]), ranges: batch };
            let Ok(Message::Reconcile { ranges, .. }) = Message::decode(&req.encode()) else { panic!("request did not decode") };
            let out = respond(b, &ranges).unwrap();
            let rep = Message::ReconcileReply { id: 1, ranges: out };
            let enc = rep.encode();
            assert!(enc.len() <= osis_core::format::MAX_MESSAGE);
            let Ok(Message::ReconcileReply { ranges, .. }) = Message::decode(&enc) else { panic!("reply did not decode") };
            replies.push((token, ranges));
        }
        for (token, rep) in replies {
            assert!(r.on_reply(token, a, &rep));
        }
    }
    assert!(r.is_done());
    (r.need, r.have, rounds)
}

fn diff(a: &[BlobId], b: &[BlobId]) -> BTreeSet<BlobId> {
    a.iter().filter(|x| b.binary_search(x).is_err()).copied().collect()
}

// spec/wire.md §11.3: fingerprint = BLAKE3(le256(sum mod 2^256) || le64(count)), first 16 bytes
#[test]
fn fingerprint_is_additive_and_wraps() {
    assert_eq!(fingerprint(&[]), {
        let h = osis_core::hash::hash(&[0u8; 40]);
        let mut f = [0; 16];
        f.copy_from_slice(&h[..16]);
        f
    });
    // 2^256 - 1 plus 1 wraps to 0, count 2
    let max = BlobId([0xff; 32]);
    let mut one = [0u8; 32];
    one[0] = 1;
    let mut zero_sum_two = [0u8; 40];
    zero_sum_two[32] = 2;
    let h = osis_core::hash::hash(&zero_sum_two);
    assert_eq!(fingerprint(&[BlobId(one), max]), h[..16]);
    // order-independent
    let s = set(0..50);
    let mut r = s.clone();
    r.reverse();
    assert_eq!(fingerprint(&s), fingerprint(&r));
}

// spec/wire.md §11.3: bounds compare right-padded with zeros; upper [] is the end
#[test]
fn bounds() {
    let id = BlobId([1; 32]);
    assert!(contains(&Bound::empty(), &Bound::empty(), &id));
    assert!(contains(&Bound::new(vec![1]).unwrap(), &Bound::new(vec![2]).unwrap(), &id));
    assert!(!contains(&Bound::new(vec![1, 2]).unwrap(), &Bound::empty(), &id));
    assert!(contains(&Bound::of(&id), &Bound::empty(), &id));
    assert!(!contains(&Bound::empty(), &Bound::of(&id), &id));
    assert_eq!(cmp_bounds(&Bound::new(vec![1]).unwrap(), &Bound::new(vec![1, 0, 0]).unwrap()), Ordering::Equal);
}

// spec/wire.md §11.3: split into 16 near-equal subranges, bounds the first own ID of each
#[test]
fn split_rule() {
    let s = set(0..100);
    let out = respond(&s, &[Range { lower: Bound::empty(), upper: Bound::empty(), mode: Mode::Fingerprint([0; 16]) }]).unwrap();
    assert_eq!(out.len(), 16);
    assert_eq!(out[0].lower, Bound::empty());
    assert_eq!(out[15].upper, Bound::empty());
    for (i, r) in out.iter().enumerate() {
        let (start, end) = (i * 100 / 16, (i + 1) * 100 / 16);
        if i > 0 {
            assert_eq!(r.lower, Bound::of(&s[start]));
        }
        assert_eq!(r.mode, Mode::Ids(s[start..end].to_vec()));
    }
    // over 32 own IDs answering a mismatched fingerprint, or over 1024 answering a list: split
    let big = set(0..2000);
    let out = respond(&big, &[Range { lower: Bound::empty(), upper: Bound::empty(), mode: Mode::Ids(vec![]) }]).unwrap();
    assert_eq!(out.len(), 16);
    assert!(out.iter().all(|r| matches!(r.mode, Mode::Fingerprint(_))));
    // at most 1024: mode 2
    let out = respond(&set(0..1024), &[Range { lower: Bound::empty(), upper: Bound::empty(), mode: Mode::Ids(set(5000..5003)) }]).unwrap();
    assert!(matches!(&out[..], [Range { mode: Mode::Diff { theirs, lacking }, .. }] if theirs.len() == 1024 && lacking.len() == 3));
    // equal fingerprint: nothing
    assert!(respond(&big, &[Range { lower: Bound::empty(), upper: Bound::empty(), mode: Mode::Fingerprint(fingerprint(&big)) }]).unwrap().is_empty());
}

// spec/wire.md §11.3: small and degenerate sets
#[test]
fn small_cases() {
    for (a, b) in [(set([]), set([])), (set([1]), set([])), (set([]), set(0..5000)), (set(0..5000), set([])), (set(0..40), set(0..40))] {
        let (need, have, _) = reconcile(&a, &b);
        assert_eq!(need, diff(&b, &a));
        assert_eq!(have, diff(&a, &b));
    }
}

// spec/wire.md §11.3, spec/sync.md §6: about log16(n/32) rounds; tier 2 at size
#[test]
#[ignore]
fn large_sets_rounds() {
    let a = set(0..100_000);
    let b = set((50..100_050).filter(|n| n % 997 != 0));
    let (need, have, rounds) = reconcile(&a, &b);
    assert_eq!(need, diff(&b, &a));
    assert_eq!(have, diff(&a, &b));
    assert!(rounds <= 6, "{rounds} rounds");
}

proptest! {
    // spec/wire.md §11.3: two arbitrary sets reconcile exactly within bounded rounds
    #[test]
    fn arbitrary_sets_reconcile(common in 0u64..3000, only_a in 0u64..300, only_b in 0u64..300, sparse in 1u64..5) {
        let a = set((0..common).map(|n| n * sparse).chain((0..only_a).map(|n| 1_000_000 + n)));
        let b = set((0..common).map(|n| n * sparse).chain((0..only_b).map(|n| 2_000_000 + n)));
        let (need, have, rounds) = reconcile(&a, &b);
        prop_assert_eq!(need, diff(&b, &a));
        prop_assert_eq!(have, diff(&a, &b));
        prop_assert!(rounds <= 5, "{} rounds", rounds);
    }
}

// spec/wire.md §11.3: reply ranges must answer what was asked; unsolicited ones add nothing
#[test]
fn unsolicited_replies_are_dropped() {
    let own = set(0..100);
    let mut r = Reconciler::new(&own);
    let (token, _) = r.next_batch().unwrap();
    let fake = set(1_000_000..1_001_000);
    // a mode 2 range answering our mode 0 range, and replies to tokens never issued
    r.on_reply(token, &own, &[Range { lower: Bound::empty(), upper: Bound::empty(), mode: Mode::Diff { theirs: fake[..1000].to_vec(), lacking: vec![] } }]);
    assert!(!r.on_reply(token, &own, &[Range { lower: Bound::empty(), upper: Bound::empty(), mode: Mode::Ids(fake[..5].to_vec()) }]));
    assert!(!r.on_reply(99, &own, &[Range { lower: Bound::empty(), upper: Bound::empty(), mode: Mode::Fingerprint([1; 16]) }]));
    assert!(r.need.is_empty());
    assert!(r.is_done());
    // a subrange inside an asked range is taken
    let mut r = Reconciler::new(&own);
    let (t, _) = r.next_batch().unwrap();
    let (lo, hi) = (Bound::of(&fake[0]), Bound::of(&fake[3]));
    assert!(r.on_reply(t, &own, &[Range { lower: lo, upper: hi, mode: Mode::Ids(fake[..3].to_vec()) }]));
    assert_eq!(r.need.len(), 3);
}

/// IDs `0..n` of the transcript universe: 32-byte slices of BLAKE3 XOF("osis proto reconcile").
fn universe(n: usize) -> Vec<BlobId> {
    let mut out = vec![0u8; 32 * n];
    osis_core::hash::Hasher::new().update(b"osis proto reconcile").finalize_xof(&mut out);
    out.as_chunks::<32>().0.iter().map(|c| BlobId(*c)).collect()
}

// spec/wire.md §11.3: two 10 000-ID sets with 100 differences each way reconcile in 2 round trips
// with the reference split (deterministic; records this implementation's batching choices)
#[test]
fn transcript_ten_thousand() {
    let u = universe(10_100);
    let mut a: Vec<_> = u[..10_000].to_vec();
    let mut b: Vec<_> = u[..9_900].iter().chain(&u[10_000..]).copied().collect();
    a.sort();
    b.sort();
    let (need, have, rounds) = reconcile(&a, &b);
    assert_eq!(need, u[10_000..].iter().copied().collect());
    assert_eq!(have, u[9_900..10_000].iter().copied().collect());
    assert_eq!(rounds, 2);
}
