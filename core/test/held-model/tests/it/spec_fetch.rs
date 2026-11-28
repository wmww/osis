//! Fetching what judges what is held (notes/expiry-creation-design.md §3, spec/crypto.md
//! Reading-only secrets): a part that cannot be judged is discarded and fetched again; the boxes
//! of what was opened stay as reading-only keys, so a grant whose only key opens the sync ID holding
//! the record that judges it does not deadlock; forged boxes never change a read.
use crate::util::*;
use held_model::fetch::{creation_first, reachable, settle, Library};
use held_model::gen::{creation, Rng, CREATION_ID, REG};
use held_model::*;
use std::collections::{BTreeMap, BTreeSet};

const ME: NodeId = 7;
const MINE: SyncId = 1;
const L: SyncId = 2;
const NO_SYNC_ID: SyncId = 999;

/// The grant (mint admin 0 gives `ME` read on T) with its key box.
fn keyed_grant(key: SyncId) -> Commit {
    let mut c = grant(30, MINT_ADMIN, 1, ME, Some(Role::Read), None);
    c.boxes = vec![KeyBox { thing: T, key }];
    c
}

fn made() -> Commit {
    creation(T, RecordLink::Admin(MINT_ADMIN), MINT_ADMIN, ts(0), PurgeBy::Admin, None)
}

/// T lives under `L`, which only the grant's key opens; `ME` holds `MINE` only; the grant is copied
/// whole under `MINE`.
fn granted(key: SyncId) -> Library {
    let records = vec![Record { id: MINT_ADMIN, link: RecordLink::Key }];
    let mut sync_ids = BTreeMap::new();
    sync_ids.insert(T, BTreeSet::from([L]));
    let mut copies = BTreeMap::new();
    copies.insert(30, BTreeSet::from([MINE]));
    let w = reg(40, MINT_ADMIN, 2, REG, PurgeBy::AuthorOrAdmin, 5);
    Library { now: at(5), me: ME, records, sync_ids, copies, commits: vec![keyed_grant(key), made(), w], keys: BTreeSet::from([MINE]) }
}

fn reads(lib: &Library, reading_only: bool) -> Option<Value> {
    let f = settle(lib, &mut |_| {}, reading_only);
    evaluate(&f.held).reads.get(&(T, REG)).cloned().flatten()
}

// spec/crypto.md (Reading-only secrets), notes/expiry-creation-design.md §3: a granted node has
// neither T's record nor its sync ID's key; the grant's box, read from the commit it could not
// judge, opens the sync ID holding T's record, and the grant then applies
#[test]
fn grant_opens_the_sync_id_holding_its_record_spec_crypto() {
    let lib = granted(L);
    assert_eq!(reads(&lib, true), int(5));
    let f = settle(&lib, &mut |_| {}, true);
    assert!(f.keys.contains(&L));
    assert!(evaluate(&f.held).applied.contains(&30), "fetched again once the record came");
}

// the same world, the box thrown out with the part: deadlock. Why the boxes stay.
#[test]
fn discarding_boxes_deadlocks_spec_crypto() {
    assert_eq!(reads(&granted(L), false), None);
}

// spec/crypto.md: a box that opens nothing changes nothing
#[test]
fn forged_box_changes_no_read_spec_crypto() {
    let lib = granted(NO_SYNC_ID);
    assert_eq!(reads(&lib, true), None);
    let f = settle(&lib, &mut |_| {}, true);
    assert!(!f.keys.contains(&L));
}

// sibling under another sync ID: the commit's whole copy under a sync ID the node holds, parts judged the same
#[test]
fn other_sync_id_sibling_copy_opens_the_sync_id_spec_crypto() {
    let mut lib = granted(L);
    // the content write copied under MINE too: it may arrive before the record
    lib.copies.insert(40, BTreeSet::from([MINE]));
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

/// A random valid world: things under sync IDs, each created by a node thing, valid grants boxing
/// real keys (copied under `MINE` or not), forged boxes that open nothing, writes.
fn world(seed: u64) -> Library {
    let mut r = Rng::new(seed);
    let mut lib = Library { now: at(50), me: ME, keys: BTreeSet::from([MINE]), ..Default::default() };
    lib.records = vec![Record { id: 0, link: RecordLink::Key }, Record { id: 1, link: RecordLink::Key }];
    let n = 3 + r.below(3) as ThingId;
    let mut id: CommitId = 100;
    for t in 0..n {
        let thing = 10 + t;
        let key = r.below(2) as NodeId;
        // half the things answer to an account (minted with the node thing): its record
        // up the chain may be behind another sync ID
        let (admin, link) = if r.chance(50) {
            let account = 40 + t;
            let c = creation(account, RecordLink::Admin(key), key, ts(0), PurgeBy::Admin, None);
            lib.sync_ids.insert(account, BTreeSet::from([10 + r.below(3) as SyncId]));
            lib.commits.push(c);
            (key, RecordLink::Admin(account))
        } else {
            (key, RecordLink::Admin(key))
        };
        let ls: BTreeSet<SyncId> = (0..1 + r.below(2)).map(|_| 10 + r.below(3) as SyncId).collect();
        lib.sync_ids.insert(thing, ls.clone());
        let c = creation(thing, link, admin, ts(0), PurgeBy::Admin, None);
        if r.chance(25) {
            lib.copies.insert(c.id, BTreeSet::from([MINE]));
        }
        lib.commits.push(c);
        // a grant for ME, with a box for a sync ID this thing is under
        if r.chance(70) {
            id += 1;
            let mut g = grant_on(id, admin, 1, thing, GrantWrite::role(ME, Some(Role::Read)), None);
            let key = if r.chance(15) { NO_SYNC_ID } else { *ls.iter().next().unwrap() };
            g.boxes = vec![KeyBox { thing, key }];
            if r.chance(70) {
                lib.copies.insert(id, BTreeSet::from([MINE]));
            }
            lib.commits.push(g);
        }
        // writes
        for h in 0..r.below(3) {
            id += 1;
            let w = Commit { parts: vec![Part { thing, ..part(REG, PurgeBy::AuthorOrAdmin, vec![set(2 + h, id, id as i64)]) }], ..reg(id, admin, 2 + h, REG, PurgeBy::AuthorOrAdmin, id as i64) };
            if r.chance(30) {
                lib.copies.insert(id, BTreeSet::from([MINE]));
            }
            lib.commits.push(w);
        }
    }
    lib
}

// notes/expiry-creation-design.md §5 (Unjudgeable parts): at quiescence, every valid grant with a reachable
// sync ID reads as if everything reachable had arrived creation-first; forged boxes change no read.
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
            let mut o = Rng::new(crdt_model::gen::seed_at(&[seed, k]));
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
            c.boxes.retain(|b| b.key != NO_SYNC_ID);
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
    let w = reg(10, MINT_ADMIN, 1, REG, PurgeBy::AuthorOrAdmin, 1);
    let mut lib = Library { now: at(5), me: ME, keys: BTreeSet::from([L]), records: vec![Record { id: MINT_ADMIN, link: RecordLink::Key }], ..Default::default() };
    lib.sync_ids.insert(T, BTreeSet::from([L]));
    lib.commits.push(w);
    let early = settle(&lib, &mut |_| {}, true);
    assert_eq!(early.held.commits.iter().filter(|c| c.id == 10).count(), 0);
    lib.commits.push(creation(T, RecordLink::Admin(MINT_ADMIN), MINT_ADMIN, ts(0), PurgeBy::Admin, None));
    let done = settle(&lib, &mut |_| {}, true);
    assert!(evaluate(&done.held).applied.contains(&(CREATION_ID + T)));
    assert_eq!(evaluate(&done.held).reads.get(&(T, REG)).cloned().flatten(), int(1));
}

/// Writer 1's body 10, replaced by the mint admin's 15 and covered by 1's snapshot 20 (a cover
/// drops only a body nothing reads on its own: a replaced one), and `c`.
fn covered(c: Commit) -> (Held, Commit) {
    let b = Commit { parts: vec![Part { ..part(REG, PurgeBy::Writer, vec![set(1, 10, 1)]) }], ..reg(10, 1, 1, REG, PurgeBy::Writer, 1) };
    let x = reg(15, MINT_ADMIN, 2, REG, PurgeBy::Writer, 2);
    let s = snap(20, 1, 3, REG, PurgeBy::Writer, vec![set(2, 15, 2)]);
    let g = grant(5, MINT_ADMIN, 0, 1, Some(Role::Write), None);
    (held(5, vec![g, b, x, s]), c)
}

// notes/expiry-creation-design.md §3: a delete decided while a content commit awaits judgement
// reads as if the commit had come first
#[test]
fn delete_during_a_content_wait_reads_alike_spec_sync_6() {
    let c = reg(30, MINT_ADMIN, 2, Aspect::plain(5), PurgeBy::AuthorOrAdmin, 9);
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
    let c = grant(6, MINT_ADMIN, 2, 1, None, Some(vec![10]));
    let (h, c) = covered(c);
    let o = evaluate(&h);
    let mut dropped = act(&h, &o, Some((10, 0)));
    dropped.commits.push(c.clone());
    let mut control = h.clone();
    control.commits.push(c);
    let o = evaluate(&dropped);
    assert_eq!(evaluate(&control).reads.get(&(T, REG)).cloned().flatten(), int(2));
    assert_eq!(o.reads, evaluate(&control).reads, "the replaced body counts as never received");
    assert!(o.uncovered.contains(&(10, 0)), "fetched again");
}
