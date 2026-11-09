//! Fetching what judges what is held (notes/expiry-creation-design.md §3, spec/crypto.md
//! Reading-only secrets): a part that cannot be judged is discarded and fetched again; the boxes
//! of what was opened stay as reading-only keys, so a grant whose only key opens the label holding
//! the record that judges it does not deadlock; forged boxes never change a read.
use crate::util::*;
use held_model::fetch::{creation_first, reachable, settle, Library};
use held_model::gen::{creation, Rng, CREATION_ID, REG};
use held_model::*;
use std::collections::{BTreeMap, BTreeSet};

const ME: NodeId = 7;
const HOME: Label = 1;
const L: Label = 2;
const NO_LABEL: Label = 999;

/// The grant (first admin 0 gives `ME` read on T) with its key box.
fn grant(key: Label) -> Commit {
    let mut c = edge(30, FIRST_ADMIN, 1, ME, Some(Role::Read), None);
    c.boxes = vec![KeyBox { thing: T, key }];
    c
}

fn made() -> Commit {
    creation(T, RecordLink::Admin(FIRST_ADMIN), FIRST_ADMIN, ts(0), Retention::ROLE, None)
}

/// T lives under `L`, which only the grant's key opens; `ME` holds `HOME` only; the grant is copied
/// whole under `HOME`.
fn invited(key: Label) -> Library {
    let records = vec![Record { id: FIRST_ADMIN, link: RecordLink::Key }];
    let mut labels = BTreeMap::new();
    labels.insert(T, BTreeSet::from([L]));
    let mut copies = BTreeMap::new();
    copies.insert(30, BTreeSet::from([HOME]));
    let w = reg(40, FIRST_ADMIN, 2, REG, Retention::PLAIN, 5);
    Library { now: at(5), me: ME, records, labels, copies, commits: vec![grant(key), made(), w], keys: BTreeSet::from([HOME]) }
}

fn reads(lib: &Library, reading_only: bool) -> Option<Value> {
    let f = settle(lib, &mut |_| {}, reading_only);
    evaluate(&f.held).reads.get(&(T, REG)).cloned().flatten()
}

// spec/crypto.md (Reading-only secrets), notes/expiry-creation-design.md §3: an invited node has
// neither T's record nor its label's key; the grant's box, read from the commit it could not
// judge, opens the label holding T's record, and the grant then applies
#[test]
fn grant_opens_the_label_holding_its_record_spec_crypto() {
    let lib = invited(L);
    assert_eq!(reads(&lib, true), int(5));
    let f = settle(&lib, &mut |_| {}, true);
    assert!(f.keys.contains(&L));
    assert!(evaluate(&f.held).applied.contains(&30), "fetched again once the record came");
}

// the same world, the box thrown out with the part: deadlock. Why the boxes stay.
#[test]
fn discarding_boxes_deadlocks_spec_crypto() {
    assert_eq!(reads(&invited(L), false), None);
}

// spec/crypto.md: a box that opens nothing changes nothing
#[test]
fn forged_box_changes_no_read_spec_crypto() {
    let lib = invited(NO_LABEL);
    assert_eq!(reads(&lib, true), None);
    let f = settle(&lib, &mut |_| {}, true);
    assert!(!f.keys.contains(&L));
}

// home-label sibling: the commit's whole copy under a label the node holds, parts judged the same
#[test]
fn home_label_sibling_copy_opens_the_label_spec_crypto() {
    let mut lib = invited(L);
    // the content write copied under HOME too: it may arrive before the record
    lib.copies.insert(40, BTreeSet::from([HOME]));
    let mut orders = 0;
    let f = settle(
        &lib,
        &mut |es| {
            orders += 1;
            es.reverse();
        },
        true,
    );
    assert!(orders > 1, "woken: fetched again");
    assert_eq!(evaluate(&f.held).reads.get(&(T, REG)).cloned().flatten(), int(5));
}

/// What is read, absent aspects aside.
fn present(h: &Held) -> BTreeMap<(ThingId, Aspect), Value> {
    evaluate(h).reads.into_iter().filter_map(|(k, v)| Some((k, v?))).collect()
}

/// A random valid world: things under labels, each created by a key actor, valid grants boxing
/// real keys (copied under `HOME` or not), forged boxes that open nothing, writes.
fn world(seed: u64) -> Library {
    let mut r = Rng::new(seed);
    let mut lib = Library { now: at(50), me: ME, keys: BTreeSet::from([HOME]), ..Default::default() };
    lib.records = vec![Record { id: 0, link: RecordLink::Key }, Record { id: 1, link: RecordLink::Key }];
    let n = 3 + r.below(3) as ThingId;
    let mut id: CommitId = 100;
    for t in 0..n {
        let thing = 10 + t;
        let key = r.below(2) as NodeId;
        // half the things answer to an account (a thing created by the key actor): its record
        // up the chain may be behind another label
        let (admin, link) = if r.chance(50) {
            let account = 40 + t;
            let c = creation(account, RecordLink::Admin(key), key, ts(0), Retention::ROLE, None);
            lib.labels.insert(account, BTreeSet::from([10 + r.below(3) as Label]));
            lib.commits.push(c);
            (key, RecordLink::Admin(account))
        } else {
            (key, RecordLink::Admin(key))
        };
        let ls: BTreeSet<Label> = (0..1 + r.below(2)).map(|_| 10 + r.below(3) as Label).collect();
        lib.labels.insert(thing, ls.clone());
        let c = creation(thing, link, admin, ts(0), Retention::ROLE, None);
        if r.chance(25) {
            lib.copies.insert(c.id, BTreeSet::from([HOME]));
        }
        lib.commits.push(c);
        // a grant for ME, with a box for a label this thing is under
        if r.chance(70) {
            id += 1;
            let mut g = edge_on(id, admin, 1, thing, EdgeWrite::role(ME, Some(Role::Read)), None);
            let key = if r.chance(15) { NO_LABEL } else { *ls.iter().next().unwrap() };
            g.boxes = vec![KeyBox { thing, key }];
            if r.chance(70) {
                lib.copies.insert(id, BTreeSet::from([HOME]));
            }
            lib.commits.push(g);
        }
        // writes
        for h in 0..r.below(3) {
            id += 1;
            let w = Commit { parts: vec![Part { thing, ..part(REG, Retention::PLAIN, vec![set(2 + h, id, id as i64)]) }], ..reg(id, admin, 2 + h, REG, Retention::PLAIN, id as i64) };
            if r.chance(30) {
                lib.copies.insert(id, BTreeSet::from([HOME]));
            }
            lib.commits.push(w);
        }
    }
    lib
}

// notes/expiry-creation-design.md §6 step 6: at quiescence, every valid grant with a reachable
// label reads as if everything reachable had arrived creation-first; forged boxes change no read.
// Every arrival order.
#[test]
fn settled_reads_like_creation_first_spec_commits_4() {
    let mut grants = 0;
    for seed in 0..300 {
        let lib = world(seed);
        let keys = reachable(&lib);
        grants += u64::from(keys.len() > lib.keys.len());
        let want = present(&creation_first(&lib, &keys));
        for k in 0..4 {
            let mut o = Rng::new(seed * 8 + k);
            let f = settle(&lib, &mut |es| o.shuffle(es), true);
            let got = present(&f.held);
            assert_eq!(got, want, "seed {seed} order {k}");
        }
    }
    assert!(grants > 100, "worlds reach grants: {grants}");
}

// a forged box's only reach is what it names: a fabricated key changes nothing
#[test]
fn forged_boxes_change_no_read_at_any_size_spec_crypto() {
    for seed in 0..100 {
        let lib = world(seed);
        let mut honest = lib.clone();
        for c in &mut honest.commits {
            c.boxes.retain(|b| b.key != NO_LABEL);
        }
        let a = present(&settle(&lib, &mut |_| {}, true).held);
        let b = present(&settle(&honest, &mut |_| {}, true).held);
        assert_eq!(a, b, "seed {seed}");
    }
}

// a part fetched before its record arrives is judged again and joins (the wake); the discard
// keeps no bytes
#[test]
fn woken_part_joins_spec_commits_4() {
    let w = reg(10, FIRST_ADMIN, 1, REG, Retention::PLAIN, 1);
    let mut lib = Library { now: at(5), me: ME, keys: BTreeSet::from([L]), records: vec![Record { id: FIRST_ADMIN, link: RecordLink::Key }], ..Default::default() };
    lib.labels.insert(T, BTreeSet::from([L]));
    lib.commits.push(w);
    let early = settle(&lib, &mut |_| {}, true);
    assert_eq!(early.held.commits.iter().filter(|c| c.id == 10).count(), 0);
    lib.commits.push(creation(T, RecordLink::Admin(FIRST_ADMIN), FIRST_ADMIN, ts(0), Retention::ROLE, None));
    let done = settle(&lib, &mut |_| {}, true);
    assert!(evaluate(&done.held).applied.contains(&(CREATION_ID + T)));
    assert_eq!(evaluate(&done.held).reads.get(&(T, REG)).cloned().flatten(), int(1));
}

fn covered(c: Commit) -> (Held, Commit) {
    let b = Commit { parts: vec![Part { ..part(REG, Retention::WRITER, vec![set(1, 10, 1)]) }], ..reg(10, 1, 1, REG, Retention::WRITER, 1) };
    let s = snap(20, 1, 3, REG, Retention::WRITER, vec![set(1, 10, 1)]);
    let g = edge(5, FIRST_ADMIN, 0, 1, Some(Role::Write), None);
    (held(5, vec![g, b, s]), c)
}

// notes/expiry-creation-design.md §3: a delete decided while a content commit awaits judgement
// reads as if the commit had come first
#[test]
fn delete_during_a_content_wait_reads_alike_spec_sync_6() {
    let c = reg(30, FIRST_ADMIN, 2, Aspect::plain(5), Retention::PLAIN, 9);
    let (h, c) = covered(c);
    let o = evaluate(&h);
    assert!(matches!(o.fates[&(10, 0)], Fate::MayDrop(DropWhy::Covered { by: 20 })));
    let mut dropped = act(&h, &o, Some((10, 0)));
    dropped.commits.push(c.clone());
    let mut control = h.clone();
    control.commits.push(c);
    assert_eq!(evaluate(&dropped).reads, evaluate(&control).reads);
}

// A delete decided while a role commit awaits, the commit taking the covering snapshot's right
// away: the body is gone until fetched again (`Outcome::uncovered`), as for any such commit that had
// not arrived at all. Not specific to a wait: the node could not tell before it came.
#[test]
fn delete_during_a_demotion_wait_counts_as_never_received_spec_sync_6() {
    let c = edge(6, FIRST_ADMIN, 2, 1, None, Some(vec![10]));
    let (h, c) = covered(c);
    let o = evaluate(&h);
    let mut dropped = act(&h, &o, Some((10, 0)));
    dropped.commits.push(c.clone());
    let mut control = h.clone();
    control.commits.push(c);
    let o = evaluate(&dropped);
    assert_eq!(evaluate(&control).reads.get(&(T, REG)).cloned().flatten(), int(1));
    assert_eq!(o.reads.get(&(T, REG)).cloned().flatten(), None, "the body counts as never received");
    assert!(o.uncovered.contains(&(10, 0)), "fetched again");
}
