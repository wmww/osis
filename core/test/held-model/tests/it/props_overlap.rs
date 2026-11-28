//! Properties of S3's overlap rule (notes/redesign-plan.md S3; spec/commits.md §4),
//! `Overlap::Valid`, over `held_model::overlap` worlds: the hand worlds and random ones, every
//! subset of a world's events a held set. Each property has its negative control. Two fail as
//! the rule stands, and are tests of that: the verdict reads itself where a void commit carries
//! a rule's input (`no_verdict_*`), and a dot two held commits claim has no owner
//! (`shared_dot_has_no_owner`). spec: commits §4
use held_model::gen::shuffle;
use held_model::overlap::*;
use held_model::*;
use std::collections::{BTreeMap, BTreeSet};

const SEEDS: u64 = 30;

/// Hand worlds, then random ones: hostile with rule inputs in session form, hostile without,
/// honest.
fn worlds(seeds: u64) -> Vec<World> {
    let mut v = hand();
    for s in 0..seeds {
        v.extend([world(s, false, true), world(s, false, false), world(s, true, true)]);
    }
    v
}

fn held_sets(w: &World) -> impl Iterator<Item = Held> + '_ {
    (0..=w.all()).map(|m| w.held(m, ADMIN))
}

/// The verdicts on the events: each part's validity and the void set.
fn verdicts(h: &Held, o: &Outcome) -> (BTreeMap<PartRef, bool>, BTreeSet<CommitId>) {
    let ev: BTreeSet<CommitId> = h.commits.iter().map(|c| c.id).filter(|&c| (100..1000).contains(&c)).collect();
    (o.valid.iter().filter(|(k, _)| ev.contains(&k.0)).map(|(k, v)| (*k, *v)).collect(), o.void.clone())
}

/// `h` in another order: commits, records, frontiers and dot ranges.
fn reorder(h: &Held, seed: u64) -> Held {
    let mut n = shuffle(h, seed);
    gen::Rng::new(seed ^ 7).shuffle(&mut n.dots);
    n
}

/// (a) Every order of every held set judges alike. Control: the overlap judged as each commit
/// arrives and kept (`sticky`) differs by order.
#[test]
fn overlap_verdicts_are_a_function_of_the_held_set_spec_commits_4() {
    let mut sets = 0;
    let mut sticky_differs = 0;
    for (k, w) in worlds(SEEDS).iter().enumerate() {
        for h in held_sets(w) {
            let want = verdicts(&h, &evaluate_with(&h, &Overlap::Valid));
            for s in 0..3 {
                let r = reorder(&h, k as u64 * 31 + s);
                assert_eq!(verdicts(&r, &evaluate_with(&r, &Overlap::Valid)), want, "{} order {s}", w.name);
            }
            sets += 1;
        }
        // the control: arrival one event at a time in two orders, each void kept
        let full = w.held(w.all(), ADMIN);
        let orders = [(0..w.events.len()).collect::<Vec<_>>(), (0..w.events.len()).rev().collect()];
        let got: Vec<_> = orders.iter().map(|o| verdicts(&full, &evaluate_with(&full, &Overlap::Given(sticky(w, o))))).collect();
        sticky_differs += (got[0] != got[1]) as usize;
    }
    println!("held sets {sets}; worlds where the sticky control differs by order: {sticky_differs}");
    assert!(sticky_differs > 0, "control: an overlap judged at arrival and kept differs by order");
}

/// Voids judged by `Valid` at each prefix of arrival `order` and never lifted.
fn sticky(w: &World, order: &[usize]) -> BTreeSet<CommitId> {
    let mut mask = 0u64;
    let mut void = BTreeSet::new();
    for &k in order {
        mask |= 1 << k;
        let h = w.held(mask, ADMIN);
        void.extend(evaluate_with(&h, &Overlap::Valid).void);
    }
    void
}

/// Event commits of `h` invalid for another reason: plain content (no rule input) none of whose
/// parts is valid by every rule but overlap.
fn junk(h: &Held, o: &Outcome) -> Vec<CommitId> {
    h.commits
        .iter()
        .filter(|c| (100..1000).contains(&c.id) && c.kind == CommitKind::Content && c.purge.is_empty() && o.applied.contains(&c.id))
        .filter(|c| c.parts.iter().all(|p| ![Aspect::ADDENDA, Aspect::RETENTION].contains(&p.aspect)))
        .filter(|c| (0..c.parts.len()).all(|i| o.otherwise.get(&(c.id, i)) != Some(&true)))
        .map(|c| c.id)
        .collect()
}

/// Whether taking junk `x` out of `h` changes any other commit's verdict under `ov`.
fn junk_moves(h: &Held, x: CommitId, ov: &Overlap) -> bool {
    let without = Held { commits: h.commits.iter().filter(|c| c.id != x).cloned().collect(), dots: h.dots.iter().filter(|r| r.commit != x).cloned().collect(), ..h.clone() };
    let (mut a, mut av) = verdicts(h, &evaluate_with(h, ov));
    a.retain(|k, _| k.0 != x);
    av.remove(&x);
    (a, av) != verdicts(&without, &evaluate_with(&without, ov))
}

/// (b) No commit invalid for another reason changes another's verdict. Control: `Held`, where
/// a removed node's or a stranger's junk voids honest writes.
#[test]
fn junk_voids_nothing_spec_commits_4() {
    let (mut checked, mut held_moved) = (0, 0);
    for w in worlds(SEEDS) {
        for h in held_sets(&w) {
            for x in junk(&h, &evaluate_with(&h, &Overlap::Valid)) {
                assert!(!junk_moves(&h, x, &Overlap::Valid), "{}: junk {x} moves a verdict", w.name);
                checked += 1;
                held_moved += junk_moves(&h, x, &Overlap::Held) as usize;
            }
        }
    }
    println!("junk commits checked {checked}; under Held moving a verdict: {held_moved}");
    assert!(checked > 0 && held_moved > 0, "control: under Held junk voids honest writes");
}

/// (b) by hand: the removed node's and the stranger's junk; a commit made to count by a later
/// addendum then voids its partner, at every node alike (every order).
#[test]
fn junk_and_late_vouches_by_hand_spec_commits_4() {
    let valid = |w: &World, mask: u64, c: CommitId, ov: &Overlap| {
        let h = w.held(mask, ADMIN);
        (0..3).all(|s| evaluate_with(&reorder(&h, s), ov).valid[&(c, 0)]) as u8 + (0..3).all(|s| !evaluate_with(&reorder(&h, s), ov).valid[&(c, 0)]) as u8 * 2
    };
    let (yes, no) = (1, 2);
    for w in [removed_junk(), stranger_junk()] {
        assert_eq!(valid(&w, w.all(), 100, &Overlap::Valid), yes, "{}: the honest write stands", w.name);
        assert_eq!(valid(&w, w.all(), 100, &Overlap::Held), no, "{}: control", w.name);
    }
    let w = vouched_later();
    let unvouched = w.all() & !w.bit(103);
    assert_eq!(valid(&w, unvouched, 100, &Overlap::Valid), yes, "H2 unlisted: H1 stands");
    assert_eq!(valid(&w, unvouched, 101, &Overlap::Valid), no);
    assert_eq!(valid(&w, w.all(), 100, &Overlap::Valid), no, "H2 vouched for: both void");
    assert_eq!(valid(&w, w.all(), 101, &Overlap::Valid), no);
}

/// (c) An honest writer's sequential commits never overlap: no void in an honest world, under
/// either rule. Control: the hostile worlds void some.
#[test]
fn honest_sessions_never_overlap_spec_commits_4() {
    let (mut hostile, mut sets) = (0, 0);
    for s in 0..SEEDS {
        let w = world(s, true, true);
        for h in held_sets(&w) {
            assert!(evaluate_with(&h, &Overlap::Valid).void.is_empty() && evaluate_with(&h, &Overlap::Held).void.is_empty(), "seed {s}");
            sets += 1;
        }
        let w = world(s, false, true);
        hostile += held_sets(&w).filter(|h| !evaluate_with(h, &Overlap::Valid).void.is_empty()).count();
    }
    println!("honest held sets {sets}; hostile ones with a void: {hostile}");
    assert!(hostile > 0, "control");
}

/// (d) What a current writer can still do: void its own (its key's) valid commits by an
/// overlapping valid one; nothing outside its session moves its verdicts but by validity: a
/// commit of another session that is plain content and no rule input changes no verdict of X's.
/// Counted: held sets where X voids its own valid commit while holding write (the hole kept).
#[test]
fn a_writer_voids_only_its_own_session_spec_commits_4() {
    let mut own = 0;
    for s in 0..SEEDS {
        let w = world(s, false, false);
        for h in held_sets(&w) {
            let o = evaluate_with(&h, &Overlap::Valid);
            for c in h.commits.iter().filter(|c| (100..1000).contains(&c.id) && c.signer == W && c.kind == CommitKind::Content && !c.parts.iter().any(|p| p.aspect == Aspect::ADDENDA)) {
                let without = Held { commits: h.commits.iter().filter(|x| x.id != c.id).cloned().collect(), dots: h.dots.iter().filter(|r| r.commit != c.id).cloned().collect(), ..h.clone() };
                let ow = evaluate_with(&without, &Overlap::Valid);
                let xs = |h: &Held, o: &Outcome| verdicts(h, o).0.into_iter().filter(|(k, _)| h.commits.iter().any(|c| c.id == k.0 && c.signer == X)).collect::<Vec<_>>();
                assert_eq!(xs(&h, &o), xs(&without, &ow), "seed {s}: W's {} moves X's verdicts", c.id);
            }
            own += (o.void.iter().filter(|c| h.commits.iter().any(|x| x.id == **c && x.signer == X)).count() >= 2) as usize;
        }
    }
    println!("held sets where X voids its own valid commits: {own}");
    assert!(own > 0, "the hole kept: a writer equivocating in its own session voids its own writes");
}

/// The definition is well-founded where no void commit carries a rule's input: there the one
/// verdict a rule reading verdicts settles on is `Valid`'s. Control (and the failure): worlds
/// with addenda and settings in session form have held sets with no consistent verdict.
#[test]
fn no_verdict_reads_itself_without_rule_inputs_spec_commits_4() {
    let (mut sets, mut circular) = (0, 0);
    for w in worlds(SEEDS) {
        for h in held_sets(&w) {
            let c = consistent(&h);
            if rule_inputs(&h).is_empty() {
                assert_eq!(c, vec![evaluate_with(&h, &Overlap::Valid).void], "{}: one verdict", w.name);
                sets += 1;
            } else {
                circular += (c.len() != 1) as usize;
            }
        }
    }
    println!("held sets without rule inputs in session form {sets}; with, and no single verdict: {circular}");
    assert!(circular > 0, "control: a void commit carrying a rule's input");
}

/// The smallest worlds where the verdict reads itself: a setting in a session-form commit (its
/// fire and a later fire of its removed author) and an addendum in one (vouching, through a
/// witness, for the commit sharing its counters). No void set is consistent.
#[test]
fn no_verdict_where_a_void_commit_carries_a_rule_input_spec_commits_4() {
    for w in [liar_setting(), liar_addenda()] {
        let h = w.held(w.all(), ADMIN);
        assert!(consistent(&h).is_empty(), "{}", w.name);
        assert!(!rule_inputs(&h).is_empty());
    }
}

/// The second failure: X's listed write H1 and its junk J after removal claim one dot of a
/// text. `Valid` keeps H1 valid, but un-merge (spec/crdt.md §4.6) attributes a write by its dot
/// alone (§2.4) and the dot has two owners: by the order of the ranges, J's char joins as H1's
/// or H1's goes as J's; H1's own char never reads. `Held` voids both: nothing reads.
#[test]
fn shared_dot_has_no_owner_spec_commits_4() {
    use crdt_model::state::{Anchor, Content, SeqElem};
    let text = gen::TEXT;
    let d = Dot { source: session(X, 0), ctr: 1 };
    let el = |h: u64, c: char| Body::Held(Delta::Writes(Frag::Seq { text: true, c: Default::default(), elems: [(d.clone(), SeqElem::new(Stamp { ts: hour(h), dot: d.clone() }, Anchor::Head, Content::Char(c)))].into() }));
    let events = vec![
        sess(100, X, 1, &session(X, 0), vec![(text, el(1, 'a'), 1, 2)]),
        grant(101, ADMIN, 2, X, None, Some(vec![100])),
        sess(102, X, 3, &session(X, 0), vec![(text, el(3, 'z'), 1, 2)]),
    ];
    let w = World { name: "shared_dot", base: base(), events };
    let h = w.held(w.all(), ADMIN);
    let mut r = h.clone();
    r.dots.reverse();
    let read = |h: &Held, ov: &Overlap| evaluate_with(h, ov).reads.get(&(THING, text)).cloned().flatten();
    assert!(evaluate_with(&h, &Overlap::Valid).valid[&(100, 0)]);
    assert_eq!([read(&h, &Overlap::Valid), read(&r, &Overlap::Valid)], [Some(Value::Str("z".into())), None]);
    assert_eq!([read(&h, &Overlap::Held), read(&r, &Overlap::Held)], [None, None]);
}
