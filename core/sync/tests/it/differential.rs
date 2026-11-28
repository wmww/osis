//! The reference-graph differential (harness::history, notes/test-properties.md): random
//! histories over a few nodes of fewer accounts; at quiet every node holds what held-model
//! `closure` says its node closure is, built from the history alone. Fresh worlds per seed;
//! `OSIS_SYNC_START`/`OSIS_SYNC_SEEDS` pick the seeds (`history::size`: 6 at small size, 100
//! under `OSIS_FULL=1`); a failure prints the history as a script, `OSIS_SYNC_SHRINK=1` shrinks
//! it. A failure is a finding: its reproducer is a new hand-written test, never the seed.

use crate::harness::history::{check, history, size, world_of};
use crate::harness::{Step, World, play, shrinking};
use osis_base::testenv::Seeds;

/// The world a history plays on, the history played once (twice when `twice`: its two traces,
/// every delivery and the bytes' digest, must be identical, as a history is a function of its
/// seed), then the checks at quiet. The replay call a failure prints is a debugging aid in a
/// scratch test, never a committed test (notes/principles.md, Never pin a seed).
pub(crate) fn holds(seed: u64, steps: &[Step], replay: String, twice: bool) -> World {
    let (n, accounts, _, _) = size();
    holds_on(seed, accounts, n, steps, replay, twice)
}

/// `holds` on a world of `n` nodes of `accounts` accounts.
fn holds_on(seed: u64, accounts: usize, n: usize, steps: &[Step], replay: String, twice: bool) -> World {
    // the script lives through the check: a failing check prints it and shrinks
    let (mut w, _script) = played_with(seed, accounts, n, steps, replay, twice);
    check(&mut w);
    w
}

/// `holds_on` without the oracle's check: the world at quiet, for a hand test's own assertions.
pub(crate) fn played_on(seed: u64, accounts: usize, n: usize, steps: &[Step], replay: String, twice: bool) -> World {
    played_with(seed, accounts, n, steps, replay, twice).0
}

/// `played_on` with the script played (printed, and kept for a shrink, if dropped in a panic).
fn played_with(seed: u64, accounts: usize, n: usize, steps: &[Step], replay: String, twice: bool) -> (World, osis_base::testenv::Script<Step>) {
    let played = |replay: String, again: bool| {
        let mut w = world_of(seed, accounts, n);
        if again {
            w.untrace();
        }
        w.cap = crate::harness::STORM_CAP;
        w.trace = twice;
        w.parks = true;
        let script = play(&mut w, steps, replay);
        // every history ends at quiet (a shrunk one too): healed, every node on, faults off, run
        let end: Vec<Step> = [Step::Lossy(crate::harness::Loss::NONE), Step::Heal].into_iter().chain((0..w.len()).map(Step::PowerOn)).chain([Step::Run]).collect();
        for s in &end {
            crate::harness::step(&mut w, s);
        }
        (w, script)
    };
    let (w, script) = played(replay.clone(), false);
    if twice {
        let (again, _) = played(replay, true);
        if let Some(i) = (0..w.seen.len().max(again.seen.len())).find(|&i| w.seen.get(i) != again.seen.get(i)) {
            panic!("not deterministic: replay differs at delivery {i} of {}: {:?} then {:?}", w.seen.len(), w.seen.get(i), again.seen.get(i));
        }
    }
    (w, script)
}

/// Every fourth seed's history plays twice (the determinism check: a source of order a run
/// draws from, such as a hashed collection's iteration, reorders any history on its path).
const TWICE_EVERY: u64 = 4;

// spec: none (property: spec/requirements.md Convergence; spec/sync-set.md §1-§4: a node holds
// exactly its node closure): histories of minting things with the account or other
// things as admin, strongs added and removed from roots and things, grants of sync, read and write to
// accounts and to things (chains), lowering, revoking, rotating, a grantee holding what it is
// granted by a strong (or not), pairing and removing a node, and on every second seed power loss,
// partitions, lost, repeated and held-back messages, device faults and clock skew, healed and run
// to quiet (within the storm cap): each node of an account reads a thing exactly when held-model's
// node closure of the account reads it, then as the reference; its sync set and store hold what
// the model holds; a removed node reads and keeps nothing of the history; no needed body is
// deleted everywhere.
#[test]
#[ignore = "property"]
fn histories_hold_their_closure_plain() {
    let (n, accounts, len, _) = size();
    worlds("histories_hold_their_closure_plain", |seed| history(seed, n, accounts, len, seed % 2 == 1));
}

/// `holds` for each seed of `OSIS_SYNC_START`/`OSIS_SYNC_SEEDS` (default: the size's range) on
/// the history `steps_of(seed)`, each failure shrunk under `OSIS_SYNC_SHRINK=1`, the shrunk script
/// then played on seed 0's world too (printed: whether it fails the same way there). A shrunk script
/// replays over many worlds, or shrinks further from where a seed timeout cut it, in a scratch
/// test: `differential::worlds("scratch", |_| vec![New(2), ..])` (notes/sync-test-harness.md,
/// Replaying a script).
pub(crate) fn worlds(name: &str, steps_of: impl Fn(u64) -> Vec<Step> + Sync) {
    let seeds = Seeds::from_env("OSIS_SYNC_START", "OSIS_SYNC_SEEDS", 0..size().3);
    seeds.run(name, |s| format!("OSIS_SYNC_START={s} OSIS_SYNC_SEEDS=1"), |seed| {
        let h = steps_of(seed);
        let replay = format!("differential::holds({seed}, &script, String::new(), false)");
        let twice = seed.is_multiple_of(TWICE_EVERY);
        shrinking(
            || {
                holds(seed, &h, replay.clone(), twice);
            },
            |steps, again| {
                holds(seed, steps, replay.clone(), again && twice);
            },
            if seed == 0 { &[] } else { &[("seed 0's world", &|steps: &[Step]| drop(holds(0, steps, String::new(), false)))] },
        );
    });
}

// spec/sync-set.md §3 (Nothing of R stays): a node's own writes on a thing it releases, not yet
// held elsewhere, go. Node 1 makes a thing and grants node 0's account read; a run connects them
// while no node of that account holds the thing (the grant is an offer); a paired node of the
// account then holds it by a strong and node 1 releases it before any run. The minting's value is
// at no node, and the oracle counts it lost: a run gives a node a value write only where its
// account's node closure held the thing then (`harness::history::ran`).
#[test]
fn a_minting_released_before_a_grantee_held_it_is_lost_spec_sync_set_3() {
    use crate::harness::history::{Gives, Holder};
    let script = [Step::New(1), Step::NewIn(1, 0), Step::Give(1, 1, Holder::Node(0), Gives::Reads), Step::Run, Step::Strong(2, None, 1), Step::Unstrong(1, Some(0), 1)];
    holds_on(0, 2, 3, &script, String::new(), false);
}

// spec/sync-set.md §3 (Nothing of R stays): node 1 makes a thing, gives the public sync and node
// 2's account read, and releases it before any run: its minting and the public's grant are at no
// node, while the grant to node 2's account reaches it as an offer and node 2 holds the thing by
// a strong. The oracle counts a lost grant as it counts a lost value write (`lost_writes`) and
// builds the reference and the model without it, so node 2 reads the roster it holds (failed:
// the reference, handed the public's grant, read a sync role node 2 can never learn of).
#[test]
fn a_grant_released_before_anyone_received_it_is_lost_spec_sync_set_3() {
    use crate::harness::history::{Gives, Holder};
    let script = [Step::New(1), Step::Give(1, 0, Holder::Public, Gives::Syncs), Step::Give(1, 0, Holder::Node(2), Gives::Reads), Step::Unstrong(1, None, 0), Step::Strong(2, None, 0)];
    holds_on(0, 3, 4, &script, String::new(), false);
}

// spec: none (test harness): a hand probe tells the engine copies apart (`osis_base::trace::copy`):
// a node the world hands out or steps is named by the world's number and its index, each
// reference twin by the world's number and its account's, and a copy of a world is a world of
// its own number.
#[test]
fn each_engine_copy_is_named_for_probes() {
    use osis_base::trace::{Copy, copy};
    let mut w = world_of(0, 2, 3);
    w.engine(1);
    assert_eq!(copy(), Copy { world: w.id, kind: 'n', index: 1 });
    let a = w.node(2).account.expect("an account");
    assert_eq!(copy(), Copy { world: w.id, kind: 'n', index: 2 });
    let mut refs = crate::harness::history::reference(&mut w, &Default::default());
    refs.of(&a);
    assert_eq!((copy().world, copy().kind), (w.id, 'r'));
    assert_ne!(w.copy().id, w.id);
}

// spec: none (test harness): a history is a function of its seed, faults included, and the
// property's seeds at small size draw every kind of step the oracle judges.
#[test]
fn a_history_is_a_function_of_its_seed() {
    let (n, accounts, len, seeds) = size();
    assert_eq!(history(0, n, accounts, len, true), history(0, n, accounts, len, true));
    let hs: Vec<Vec<Step>> = (0..seeds).map(|seed| history(seed, n, accounts, len, seed % 2 == 1)).collect();
    let drawn = |f: &dyn Fn(&Step) -> bool| hs.iter().flatten().any(f);
    for (name, has) in [
        ("new", drawn(&|s| matches!(s, Step::New(..) | Step::NewIn(..)))),
        ("give", drawn(&|s| matches!(s, Step::Give(..)))),
        ("hold", drawn(&|s| matches!(s, Step::Strong(_, None, _)))),
        ("pair", drawn(&|s| matches!(s, Step::Pair(..)))),
        ("unpair", drawn(&|s| matches!(s, Step::Unpair(..)))),
        ("public", drawn(&|s| matches!(s, Step::Give(_, _, crate::harness::history::Holder::Public, _)))),
        ("redeem", drawn(&|s| matches!(s, Step::Redeem(..)))),
        ("card", drawn(&|s| matches!(s, Step::Card(..)))),
        ("inbox", drawn(&|s| matches!(s, Step::Inbox(_, Some(_))))),
        ("fault", drawn(&|s| matches!(s, Step::Lossy(..) | Step::Disk(..) | Step::PowerOff(..)))),
    ] {
        assert!(has, "no {name} step");
    }
}

// spec/sync-set.md §2 (T's keys open: what the public reads), §4 (Redeeming a locator: the
// strong, reached by the grants held), §5: node 0 makes a thing public; node 1, of another
// account holding no role on it, redeems a locator of it and reads it as the reference does, as
// held-model's closure says, the public's grant in its roster. Failed while a head listing the
// public counted as the link reaching the thing: node 1 stopped following the locator's sync ID
// before it held any of the thing's role commits, so nothing synced it and the public's grant
// never came. Control: never made public, the redeem writes nothing and node 1 reads nothing.
#[test]
fn a_public_thing_redeemed_is_read_until_the_public_goes_spec_sync_set_4() {
    use crate::harness::history::{Gives, Holder, reads};
    let (n, accounts, ..) = size();
    let script = [Step::New(0), Step::Give(0, 0, Holder::Public, Gives::Reads), Step::Run, Step::Redeem(1, 0), Step::Run];
    let mut w = holds_on(0, accounts, n, &script, String::new(), false);
    let t = w.history.things[0].0;
    assert!(reads(w.engine(1), &t).value.is_some(), "node 1 reads the public thing it redeemed");
    let control = [Step::New(0), Step::Run, Step::Redeem(1, 0), Step::Run];
    let mut w = holds_on(0, accounts, n, &control, String::new(), false);
    assert!(reads(w.engine(1), &t).value.is_none(), "control: not public, not read");
}

// spec/sync-set.md §2 (Own things: the public's role is every party's), spec/permissions.md §1:
// thing 0 is public and holds read on thing 1; node 1's account holds both at sync and by
// strongs. Every party reads thing 1 through thing 0: node 1, reading thing 0 (holding the public's
// grant), reads thing 1 too, as the reference does (whose node role left the public out: it had
// node 1 keep thing 1 unread).
#[test]
fn the_publics_read_through_a_holder_is_every_nodes_spec_sync_set_2() {
    use crate::harness::history::{Gives, Holder};
    let (n, accounts, ..) = size();
    let script = [Step::New(0), Step::Give(0, 0, Holder::Public, Gives::Reads), Step::Give(0, 0, Holder::Node(1), Gives::Syncs), Step::New(0), Step::Give(0, 1, Holder::Thing(0), Gives::Reads), Step::Give(0, 1, Holder::Node(1), Gives::Syncs), Step::Run, Step::Strong(1, None, 0), Step::Strong(1, None, 1), Step::Write(0, 1), Step::Run];
    holds_on(0, accounts, n, &script, String::new(), false);
}

// spec/sync-ids.md §6 (Steps: at a source on a step past its keys, at once), spec/sync-judgement.md
// §6 (Stops): thing 0's sync epoch moves on (thing 1 is given sync on it and removed), then node
// 1's account is given sync on it and holds it by a strong: node 1 holds the newest sync epoch
// alone. Its store is registered the genesis step, whose sync key it does not hold: it takes
// nothing there, so it never shows the role commits the next step depends on. Node 0 registers
// at once while the store is past the keys S opened there by, and it stands at the readers' head
// (failed without: it stayed at genesis for good, which the end check flags).
#[test]
fn a_store_granted_past_genesis_is_moved_spec_sync_ids_6() {
    use crate::harness::history::{Gives, Holder};
    let (n, accounts, ..) = size();
    let script = [Step::New(0), Step::New(0), Step::Give(0, 0, Holder::Thing(1), Gives::Syncs), Step::Revoke(0, 0, Holder::Thing(1)), Step::Give(0, 0, Holder::Node(1), Gives::Syncs), Step::Run, Step::Strong(1, None, 0), Step::Write(0, 0), Step::Run];
    holds_on(0, accounts, n, &script, String::new(), false);
}

// spec/sync-streams.md §4 (Fill order: an entry waits for the read secrets that open it):
// node 0's thing 0 holds by a strong thing 1, which node 1 made public and holds from its
// thing 2 that node 0 reads; node 1 then removes the public. Node 2, of node 0's account, held
// thing 1's minting whole while the public read it, part of it from another blob; the removal
// drops that part, so the minting's blob it holds waits for thing 1's read secrets. Every entry
// waiting for a read secret is parked under it (failed: what a blob waited for was judged on the
// parts missing at its opening, and a part dropped later parked nothing).
#[test]
fn an_entry_waits_for_a_part_dropped_after_its_opening_spec_sync_streams_4() {
    use crate::harness::history::{Gives, Holder};
    let script = [
        Step::New(0),
        Step::New(1),
        Step::NewIn(1, 1),
        Step::Give(1, 2, Holder::Node(0), Gives::Reads),
        Step::Strong(0, None, 2),
        Step::Strong(1, Some(2), 1),
        Step::Give(1, 1, Holder::Public, Gives::Reads),
        Step::Run,
        Step::New(0),
        Step::Strong(0, Some(0), 1),
        Step::Revoke(1, 1, Holder::Public),
    ];
    let mut w = world_of(0, 2, 3);
    w.cap = crate::harness::STORM_CAP;
    w.parks = true;
    play(&mut w, &script, String::new());
    for s in [Step::Heal, Step::Run] {
        crate::harness::step(&mut w, &s);
    }
}

// spec/permissions.md §3 (Lost access: a node keeps what its roles give): the public's read on a
// thing removed, a node whose account holds a grant of read on it still reads it.
#[test]
fn the_publics_removal_keeps_what_a_nodes_own_role_gives_spec_permissions_3() {
    use crate::harness::history::{Gives, Holder, reads};
    let (n, accounts, ..) = size();
    let script = [Step::New(1), Step::Give(1, 0, Holder::Node(0), Gives::Reads), Step::Strong(0, None, 0), Step::Give(1, 0, Holder::Public, Gives::Reads), Step::Run, Step::Revoke(1, 0, Holder::Public)];
    let mut w = holds_on(0, accounts, n, &script, String::new(), false);
    let t = w.history.things[0].0;
    assert!(reads(w.engine(0), &t).value.is_some(), "node 0 reads thing 0 by its account's grant");
}

// spec/permissions.md §3 (Lost access), spec/sync-set.md §4: a node that redeemed a locator
// reads the thing by the public alone, so the public's removal is its loss too, the removal
// coming after a quiet run or while the redemption is in flight. Control: no removal, it reads.
#[test]
fn a_locators_redeemer_loses_the_thing_with_the_public_spec_permissions_3() {
    use crate::harness::history::{Gives, Holder, reads};
    let (n, accounts, ..) = size();
    let start = [Step::New(0), Step::Give(0, 0, Holder::Public, Gives::Reads), Step::Run, Step::Redeem(1, 0)];
    let mut w = holds_on(0, accounts, n, &start, String::new(), false);
    let t = w.history.things[0].0;
    assert!(reads(w.engine(1), &t).value.is_some(), "control: node 1 reads thing 0 by the link");
    for quiet in [true, false] {
        let mid = if quiet { vec![Step::Run] } else { vec![] };
        let script: Vec<Step> = start.iter().cloned().chain(mid).chain([Step::Revoke(0, 0, Holder::Public)]).collect();
        let mut w = holds_on(0, accounts, n, &script, String::new(), false);
        assert!(reads(w.engine(1), &t).value.is_none(), "node 1 reads thing 0 after the public's removal (quiet run before it: {quiet})");
    }
}

// spec/permissions.md §3 (Lost access), §1: the public's read removed and granted again (with
// and without a quiet run between), a node that read the thing by the public reads it again by
// the new grant's epoch.
#[test]
fn the_public_granted_again_is_read_again_spec_permissions_3() {
    use crate::harness::history::{Gives, Holder, reads};
    let (n, accounts, ..) = size();
    for quiet in [true, false] {
        let mid = if quiet { vec![Step::Run] } else { vec![] };
        let script: Vec<Step> = [Step::New(1), Step::NewIn(1, 0), Step::Give(1, 1, Holder::Node(0), Gives::Reads), Step::Strong(0, None, 1), Step::Strong(1, Some(1), 0), Step::Give(1, 0, Holder::Public, Gives::Reads), Step::Run, Step::Revoke(1, 0, Holder::Public)]
            .into_iter()
            .chain(mid)
            .chain([Step::Give(1, 0, Holder::Public, Gives::Reads)])
            .collect();
        let mut w = holds_on(0, accounts, n, &script, String::new(), false);
        let t = w.history.things[0].0;
        assert!(reads(w.engine(0), &t).value.is_some(), "node 0 reads thing 0 by the public again (quiet run between: {quiet})");
    }
}

// spec/sync-opens.md §6 (Where it stopped: a node that stops holding S tells each stop kept),
// spec/sync-ids.md §6 (Walk: a Hit refused counts as that credential not shown): node 1 grants
// node 0's account sync on thing 0, a thing minted with thing 0 as mint admin beside it; node 0 holds thing 0 and
// removes its account's other node, so node 1 rotates thing 0's sync role and issues a step.
// Node 0 takes the step before the box under it, judges itself past its keys, stops
// S (its store shredded) and syncs it again before its sync modules see it leave. Node 0 keeps
// thing 0 unread at its readers' head. Failed without either rule: node 1 kept node 0's old head
// and registered onto an empty path (13), or tested the newest step's key first forever, a beacon
// node 0's filter keeps showing.
#[test]
fn a_store_that_stops_and_syncs_again_is_registered_from_genesis_spec_sync_opens_6() {
    use crate::harness::script::*;
    let script = [New(1), Give(1, 0, Holder::Node(0), Syncs), NewIn(1, 0), Run, Strong(0, None, 0), Unpair(0, 3)];
    holds_on(0, 3, 4, &script, String::new(), false);
}

// spec/sync-ids.md §6 (Steps; Taking a stamped entry: one under a superseded write key goes as a
// deposit), spec/sync-judgement.md §3 (Giving a body): node 1 grants node 0's account sync on
// thing 0 and makes thing 1 in it, which issues step 2; node 0, holding both steps' sync secrets
// and no head, keeps thing 0, so node 1 opens S there by step 2's key and moves it from genesis
// to step 2 at once (a source on a step past its keys): node 0 never takes the rotation pinned
// under genesis. Removing node 0's account's other node issues step 3, which waits on it too.
// Failed while a writer gave a store nothing but what it pulls: node 0 refused the genesis stamp
// (a superseded write key) and kept thing 0 unread at step 2; node 1 now deposits the entry.
#[test]
fn a_store_moved_at_once_takes_the_next_step_spec_sync_ids_6() {
    use crate::harness::script::*;
    let script = [New(1), Give(1, 0, Holder::Node(0), Syncs), NewIn(1, 0), Run, Strong(0, None, 0), Run, Unpair(0, 3)];
    holds_on(0, 3, 4, &script, String::new(), false);
}


// spec/permissions.md §3 (Complete pass: a holder's keyset arriving), spec/crypto.md §4 (Seal: a
// holder actor left out is re-sealed once a keyset exists): node 1 grants node 0's account sync on its
// thing, which node 3 (paired into that account) strongs; node 3 removes node 2 from the account.
// Node 1, rotating its thing for node 2's departure before it holds the account's new keyset,
// leaves the account out, so the account's nodes are at a head past their keys; the keyset's
// arrival makes a pass of the thing due, at whose end node 1 re-seals the account, and node 0
// keeps the thing unread, as the model says. Failed while only the thing's own role commits made
// a pass due: node 1 held the keyset and never re-sealed.
#[test]
fn a_holder_left_out_is_re_sealed_once_its_keyset_arrives_spec_permissions_3() {
    use crate::harness::script::*;
    holds_on(0, 2, 3, &[New(1), Give(1, 0, Holder::Node(0), Syncs), Pair(0), Run, Strong(3, None, 0), Unpair(3, 2)], String::new(), false);
}

// spec/sync-set.md §2 (T's keys open: a chain through a dependent admin), held-model (a dependent
// thing's role entries are its independent's): node 0 mints thing 1 with thing 0, its account's
// dependent, as admin, held from thing 0, then grants node 1's account read on it, making it
// independent; node 1 holds it by a strong. Node 0 still reads thing 1 through thing 0, as its
// node closure says (failed: the model knew thing 0's roster only under its own tid, so the chain
// account, thing 0, thing 1 was missed and the model held thing 1 at node 0 not at all).
#[test]
fn a_thing_minted_with_a_dependent_is_read_through_it_once_independent_spec_sync_set_2() {
    use crate::harness::history::{Gives, Holder, reads};
    let script = [Step::New(0), Step::NewIn(0, 0), Step::Give(0, 1, Holder::Node(1), Gives::Reads), Step::Strong(1, None, 1)];
    let mut w = holds_on(0, 2, 3, &script, String::new(), false);
    let t = w.history.things[1].0;
    assert!(reads(w.engine(0), &t).value.is_some(), "node 0 reads thing 1");
}

// spec/sync-ids.md §2 (One sync ID per thing), spec/permissions.md §3
// (concurrent rotations of the thing's one sync ID): node 0 and node 3, of one account and apart, each make
// thing 0 independent by a grant, to nodes 1 and 2's accounts; each holds it by a strong. Both
// give it the one sync ID its genesis seed fixes, with sibling first steps; healed, every node
// reads thing 0 with both grants (failed with a sync ID each: the grantee of the lesser one was
// told of it alone, and once its granter moved to the greater nobody served the lesser).
#[test]
fn grantees_of_concurrent_promotions_read_on_one_sync_id_spec_sync_ids_2() {
    use crate::harness::history::{Gives, Holder};
    let script = [Step::New(0), Step::Run, Step::Partition(0, 3), Step::Give(0, 0, Holder::Node(1), Gives::Reads), Step::Give(3, 0, Holder::Node(2), Gives::Reads), Step::Strong(1, None, 0), Step::Strong(2, None, 0)];
    holds_on(0, 3, 4, &script, String::new(), false);
}

// spec/sync-inbox.md §2 (delivery: it ends at the first peer taking it), §5 (Grant signal:
// followed while held), spec/sync-set.md §3: node 1 grants node 0's account sync on its thing,
// told by a grant signal; node 0 removes node 3 from the account before any run, so node 3, not
// yet knowing it, may take the fire, ending node 1's delivery, and erase it once it learns. A
// removed node relaying what it took before it learned is honest: node 0 holds the thing's stub
// exactly while its inbox holds the fire, as the model says of a signal some node of the account
// holds (failed: the model held the signal for good and gave node 0 its stub with the fire held
// nowhere). Control: no removal, node 0 holds the fire and the stub.
#[test]
fn a_signal_is_followed_while_its_account_holds_it_spec_sync_inbox_5() {
    use crate::harness::script::*;
    let ak = osis_base::Ak::new(osis_schema::core_types::INBOX_SIGNALS[0]).unwrap();
    for removed in [true, false] {
        let mut script = vec![New(1), Give(1, 0, Holder::Node(0), Syncs)];
        script.extend(removed.then_some(Unpair(0, 3)));
        let mut w = holds_on(0, 3, 4, &script, String::new(), false);
        let t = w.history.things[0].0;
        let held = w.engine(0).sync_set().unwrap().ids.values().any(|(ts, _)| ts.contains(&t));
        let inbox = w.node(0).inbox.expect("an inbox");
        let fire = w.engine(0).body_page(&inbox, &ak, true, 0, usize::MAX).unwrap().iter().any(|b| b.valid && b.value.is_some());
        assert_eq!(held, fire, "node 0 holds thing 0 exactly while it holds the fire (node 3 removed: {removed})");
        assert!(removed || held, "control: node 0 holds the fire and the stub");
    }
}

// spec/sync-ids.md §2 (What a sync holder learns: never the tids of what its sync unit holds),
// spec/sync-set.md §2 (Stubs; Holding a stub): node 2 reads thing 0,
// which holds sync on thing 1 (an untold grant to a thing) and strongs thing 2, a dependent of
// thing 1. Thing 0's readers cannot know thing 2 is thing 1's: the strong brings thing 1's sync-only
// stub (its sync-only cut), never thing 1 kept unread, and node 2 follows nothing of it, as
// the model says (failed: the model counted the strong to thing 2 as one naming thing 1 and kept
// thing 1 unread at node 2).
#[test]
fn a_strong_to_a_dependent_of_a_thing_held_at_sync_enters_nothing_spec_sync_ids_2() {
    use crate::harness::script::*;
    let mut w = holds_on(0, 3, 4, &[New(0), Strong(2, None, 0), Give(0, 0, Holder::Node(2), Reads), New(0), NewIn(0, 1), Strong(0, Some(0), 2), Give(0, 1, Holder::Thing(0), Syncs)], String::new(), false);
    let t = w.history.things[1].0;
    assert!(!w.engine(2).sync_set().unwrap().ids.values().any(|(ts, _)| ts.contains(&t)), "node 2 holds nothing of thing 1");
}

// spec/sync-set.md §3 (Nothing of R stays: a release waits for no peer not connected),
// spec/sync-inbox.md §1: node 1's account makes thing 0 its inbox, node 1 grants node 2's account
// read on it and releases it before any run. Node 1 keeps the grant commit only as evidence of its
// account's `keys.0` (spec/commits.md §5 What a held thing needs), under no sync ID of thing 0:
// no node serves it, so node 2 never gets the grant, as the model says of a write held only by
// nodes not holding its thing (failed while the model counted any node holding the commit).
#[test]
fn a_grant_on_an_inbox_its_account_releases_first_is_lost_spec_sync_set_3() {
    use crate::harness::script::*;
    holds_on(0, 3, 4, &[New(1), Inbox(1, Some(0)), Give(1, 0, Holder::Node(2), Reads), Unstrong(1, None, 0), Strong(2, None, 0)], String::new(), false);
}

// spec/permissions.md §4 (Stub: the sync-only cut names the holders on the unit's chains),
// spec/sync-set.md §2 (Stubs: chain holders at every hop), spec/sync-ids.md §3 (Claims: a sync
// claim sealed to the holder's sync keyset, a read holder's too): node 1 makes things 0, 1 and 2,
// grants node 2's account read on thing 2, thing 2 sync on thing 1, thing 1 read on thing 0 and
// node 3's account sync on thing 0, and strongs thing 0 from thing 2. Node 2 holds sync on thing 0
// only through thing 1, whose grant it cannot read: node 1, reading thing 0's roster, logs thing
// 0's cut under thing 2 naming thing 1 alone (never node 3's account, on no chain of thing 2's),
// and thing 1's stub; node 2 takes thing 1's sync secret by thing 2's sync claim there and thing
// 0's by thing 1's sync claim, and keeps thing 0 unread (failed with a cut naming no holder, chain
// stubs at read hops alone, or a read holder's one claim sealed to its read keyset: node 2 held a
// stub).
#[test]
fn a_sync_only_chain_is_entered_by_the_holders_its_cut_names_spec_permissions_4() {
    use crate::harness::script::*;
    let script = [New(1), New(1), New(1), Give(1, 2, Holder::Node(2), Reads), Give(1, 1, Holder::Thing(2), Syncs), Give(1, 0, Holder::Thing(1), Reads), Give(1, 0, Holder::Node(3), Syncs), Strong(1, Some(2), 0), Run, Strong(2, None, 2)];
    let mut w = holds_on(0, 4, 4, &script, String::new(), false);
    let things: Vec<_> = w.history.things.iter().map(|t| t.0).collect();
    let held: Vec<_> = w.engine(2).sync_set().unwrap().ids.values().filter(|(ts, _)| ts.contains(&things[0])).map(|(_, h)| *h).collect();
    assert_eq!(held, vec![osis_engine::sync::Holding::Unread], "node 2 keeps thing 0 unread");
    let s = w.engine(1).sync_id_of(&things[2]).unwrap().unwrap();
    let named: Vec<_> = w.engine(1).sync_cuts_carried(&s).unwrap().values().filter(|(_, c)| c.thing == things[0]).map(|(_, c)| c.holders.clone()).collect();
    assert_eq!(named, vec![vec![things[1]]], "thing 0's cut under thing 2 names thing 1 alone");
}

// spec/requirements.md (a grant's holder may not know of it), spec/sync-set.md §2 (Stubs: a
// chain holder only as some reader of the unit holding the target's role entries logs it): node 1
// grants node 2's account sync on things 1 and 0, node 2 strongs thing 0, node 1 grants thing 1
// sync on thing 0 and removes node 2's account from it, and node 2 strongs thing 1. No node
// reading node 2's account reads thing 0's roster, so nothing names thing 1 to node 2 as a holder
// it reaches thing 0 through: node 2 keeps thing 1 unread and holds thing 0 as a stub, as the model
// says (failed while the model gave every unit the grants of each thing it logged, whoever
// logged it: it had node 2 keep thing 0 unread).
#[test]
fn a_sync_chain_no_reader_can_name_enters_nothing_spec_sync_set_2() {
    use crate::harness::script::*;
    let script = [New(1), New(1), Give(1, 1, Holder::Node(2), Syncs), Give(1, 0, Holder::Node(2), Syncs), Strong(2, None, 0), Give(1, 0, Holder::Thing(1), Syncs), Revoke(1, 0, Holder::Node(2)), Strong(2, None, 1)];
    let mut w = holds_on(0, 3, 4, &script, String::new(), false);
    let things: Vec<_> = w.history.things.iter().map(|t| t.0).collect();
    let set = w.engine(2).sync_set().unwrap();
    let held = |t| set.ids.values().filter(|(ts, _)| ts.contains(t)).map(|(_, h)| *h).collect::<Vec<_>>();
    assert_eq!((held(&things[0]), held(&things[1])), (vec![osis_engine::sync::Holding::Stub], vec![osis_engine::sync::Holding::Unread]));
}

// spec/sync-set.md §2 (Stubs: a chain holder only as some reader of the unit holding the
// target's role entries logs it), the same at read: node 2 grants node 1's account write and node 0's read on thing 1, node 1
// strongs thing 1 from thing 0, node 1 grants node 0's account sync on thing 0 (told) and thing 1
// read on thing 0 (told to nobody), and node 0 strongs thing 0. Node 0 reads thing 1 but no reader
// of its account reads thing 0's roster: it keeps thing 0 unread by its own grant, as the model
// says (failed while the model had node 0 read thing 0 through thing 1).
#[test]
fn a_read_chain_no_reader_can_name_reads_nothing_spec_sync_set_2() {
    use crate::harness::script::*;
    let script = [New(1), New(2), Give(2, 1, Holder::Node(1), Writes), Give(2, 1, Holder::Node(0), Reads), Strong(1, Some(0), 1), Run, Give(1, 0, Holder::Node(0), Syncs), Give(1, 0, Holder::Thing(1), Reads), Strong(0, None, 0)];
    let mut w = holds_on(0, 3, 4, &script, String::new(), false);
    let t = w.history.things[0].0;
    let held: Vec<_> = w.engine(0).sync_set().unwrap().ids.values().filter(|(ts, _)| ts.contains(&t)).map(|(_, h)| *h).collect();
    assert_eq!(held, vec![osis_engine::sync::Holding::Unread]);
}

// spec/sync-judgement.md §6 (Stops), spec/sync-inbox.md §5 (Grant signal: followed while held): node 3 grants node 2's account sync on its thing (told) and removes it once node 2 keeps
// the thing unread. Node 2 is no reader, so is told no departure: it stops at the step its sync
// secrets no longer derive and keeps the thing unread there, while the model, holding the signal,
// gives it the thing's stub. The oracle takes the stop as it does where the model holds nothing
// (failed: it flagged the stopped store against the signal's stub).
#[test]
fn a_removed_sync_holder_still_signalled_stops_spec_sync_judgement_6() {
    use crate::harness::script::*;
    holds_on(0, 3, 4, &[New(3), Give(3, 0, Holder::Node(2), Syncs), Run, Strong(2, None, 0), Revoke(3, 0, Holder::Node(2))], String::new(), false);
}

// spec/data-model.md §8 (Held history: a strong in a held body of a thing whose setting holds its
// targets counts as one in a current value), spec/sync-inbox.md §1: node 2's account makes thing
// 0 its inbox (whose setting holds its targets), strongs thing 1 from it and removes the strong
// once node 3 grants it read on thing 1. The removed strong is still in thing 0's held history,
// so node 2 reads thing 1, as the model says (failed: the model counted current strongs alone).
#[test]
fn a_strong_in_an_inboxs_held_history_holds_its_target_spec_data_model_8() {
    use crate::harness::history::reads;
    use crate::harness::script::*;
    let mut w = holds_on(0, 3, 4, &[New(2), Inbox(2, Some(0)), New(0), Run, Strong(2, Some(0), 1), Give(3, 1, Holder::Node(2), Reads), Unstrong(2, Some(0), 1)], String::new(), false);
    let t = w.history.things[1].0;
    assert!(reads(w.engine(2), &t).value.is_some(), "node 2 reads thing 1");
}

// spec/sync-set.md §2 (Stubs: T holds sync or above on X; Own things: the public's role is every
// party's, spec/permissions.md §1), held-model (a unit's roles count the public's sync on a thing
// whose role entries it carries): node 2 grants node 0's account read on its thing and the public
// sync; node 0's account strongs it and is removed, holding the public's grant. Its unit carries
// the thing by the public's sync, so node 0 keeps it unread by the public's box, as the model says
// (failed while a unit's carriage counted its own thing's role alone: node 0 held its signal's
// stub).
#[test]
fn a_removed_reader_keeps_a_thing_the_public_syncs_unread_spec_sync_set_2() {
    use crate::harness::script::*;
    holds_on(0, 3, 4, &[New(2), Give(2, 0, Holder::Node(0), Reads), Give(2, 0, Holder::Public, Syncs), Strong(0, None, 0), Run, Revoke(2, 0, Holder::Node(0))], String::new(), false);
}

// spec/crypto.md §4 (History box: what a node holds is a function of the secrets it holds,
// however it learned them), spec/sync-opens.md §6: node 0 grants node 1's account sync on its thing (a signal; no
// strong) and the public sync, then removes node 1's account. Node 1 holds the box's history
// under the public's sync epoch and learns that epoch's secret: it opens the history it holds,
// as an open of its store does. Failed while a
// sync secret learned by a node reading nothing of the thing opened nothing: the live index
// lacked the epoch's superseded epochs and names a rebuild gave.
#[test]
fn a_learned_sync_secret_opens_the_history_held_spec_crypto_4() {
    use crate::harness::script::*;
    let mut w = played_on(0, 2, 3, &[New(0), Give(0, 0, Holder::Node(1), Syncs), Give(0, 0, Holder::Public, Syncs), Revoke(0, 0, Holder::Node(1))], String::new(), false);
    for i in 0..w.len() {
        w.engine(i).check_index();
    }
}

// spec/sync-opens.md §4 (Admissible: the public's claim key also where a node holds S without
// reading it), spec/sync-ids.md §3 Taking a claim: node 0 grants node 1's account sync on its
// thing, node 1 holds it by a strong (kept unread), then node 0 grants the public read. Node 1
// holds no read grant, but anyone computes the public's claim key: it takes the public's claim at its
// head and reads the thing.
#[test]
fn a_node_keeping_a_thing_unread_reads_it_once_the_public_reads_spec_sync_opens_4() {
    use crate::harness::script::*;
    holds_on(0, 2, 3, &[New(0), Give(0, 0, Holder::Node(1), Syncs), Strong(1, None, 0), Give(0, 0, Holder::Public, Reads)], String::new(), false);
}

// spec/sync-ids.md §3 Taking a claim (the public's claim held without reading S: in the blocks
// bound to its head alone): node 0 grants the public read and removes it, then grants node 1's
// account sync, which keeps the thing unread. The grant's block carries the public's claim at an
// older step: node 1 takes nothing from it and reads nothing.
#[test]
fn a_node_keeping_a_thing_unread_takes_no_older_public_claim_spec_sync_ids_3() {
    use crate::harness::script::*;
    holds_on(0, 2, 3, &[New(0), Give(0, 0, Holder::Public, Reads), Revoke(0, 0, Holder::Public), Give(0, 0, Holder::Node(1), Syncs), Strong(1, None, 0)], String::new(), false);
}

// spec/permissions.md §4 (Logging certificates: a record a role entry's evidence names goes as a
// record), spec/sync-set.md §2 (Holding a stub: role entries alone): node 1 makes thing 1 in
// thing 0 and grants node 0's account read on it (thing 1 independent); thing 1 holds thing 0 by
// a strong and the public reads thing 0, so thing 1's readers open its minting from thing 0.
// Node 0 holds thing 1 as a stub until its grant applies, shown role entries alone, and reads it
// once the record blob carries thing 1's record (failed: the record went in the minting alone,
// node 0's grant pended for it, and node 0 read neither thing).
#[test]
fn a_grantee_judges_a_thing_minted_in_another_by_its_record_blob_spec_permissions_4() {
    use crate::harness::script::*;
    let script = [New(1), NewIn(1, 0), Give(1, 1, Holder::Node(0), Reads), Strong(0, None, 1), Strong(1, Some(1), 0), Give(1, 0, Holder::Public, Reads), Run];
    let mut w = holds_on(0, 2, 3, &script, String::new(), false);
    let t = w.history.things[1].0;
    assert!(crate::harness::history::reads(w.engine(0), &t).value.is_some(), "node 0 reads thing 1 by its account's grant");
}


// spec/permissions.md §6 (Invalid deltas: one dropped that turns valid again counts as never
// received and is fetched), spec: none (test harness: the reference is perfect delivery at the
// world's time): past the drift bound, node 0 grants node 1's account write on its thing and node 1
// makes things in it. Every node and twin reads each, held by thing 0's strongs, as the model says
// (failed while a twin's clock stayed at the world's making until after the commits were handed:
// each later commit pended on its `ts` and the tick took them by commit ID, a minting before the grant
// dropped as invalid and never handed again; the model, reading thing 0's strongs from that twin,
// held the minting nowhere, and node 0 read it).
#[test]
fn the_reference_takes_writes_at_the_worlds_time_spec_permissions_6() {
    use crate::harness::script::*;
    let mut script = vec![New(0), Give(0, 0, Holder::Node(1), Syncs), Run, Advance(2 * osis_base::format::MAX_DRIFT_MS), Unpair(0, 2), Run, Give(0, 0, Holder::Node(1), Writes), Strong(1, None, 0), Run];
    script.push(NewIn(1, 0));
    holds_on(0, 2, 3, &script, String::new(), false);
}

// spec/sync-set.md §2 (Own things: the node's role by the grants of what it holds, read or kept
// unread, and of the holders on the way; Role entries a unit's chains read: a chain at read counts
// every grant held), spec/permissions.md §3 (Own secrets add only: the mint admin a holder for keys
// by its record grant): node 1 mints thing 1 in thing 0, grants node 2's account sync on thing 1
// (independent then) and read on thing 0, each told; node 2 holds thing 1 by a strong and thing 0
// as the signal's stub. Thing 1's record names thing 0 its mint admin, so node 2 reads thing 1
// through thing 0, its account's read there, as the model says (failed while the model counted a
// record grant only where the thing's roster is read: it had node 2 keep thing 1 unread).
#[test]
fn a_record_grant_is_read_through_where_its_thing_is_held_spec_sync_set_2() {
    use crate::harness::history::reads;
    use crate::harness::script::*;
    let mut w = holds_on(0, 3, 3, &[New(1), NewIn(1, 0), Give(1, 1, Holder::Node(2), Syncs), Strong(2, None, 1), Give(1, 0, Holder::Node(2), Reads)], String::new(), false);
    let t = w.history.things[1].0;
    assert!(reads(w.engine(2), &t).value.is_some(), "node 2 reads thing 1");
}

// spec: none (test harness: a write's outcome is unknown only when its store fails): node 0's account pairs node 3, which removes node 2 before it holds the account's roles,
// so the removal is refused; node 3 then makes a thing. Node 2 is still of the account and reads
// it, as the model says (failed while any refused removal stood where the remover's roster lacked
// the node, as a fresh node's lacks every one: the oracle took node 2 for removed).
#[test]
fn a_refused_removal_removes_no_one() {
    use crate::harness::script::*;
    holds_on(0, 2, 3, &[Pair(0), Unpair(3, 2), Run, New(3)], String::new(), false);
}

// spec/sync-judgement.md §6 (Stops: a claim giving it its head's sync secret keeps S again):
// node 0 grants node 2's account sync on its thing, node 2 keeps it unread, is removed (its store
// stops at a head past its keys), then is granted read. The grant's claim bound to the head gets
// it in through the one open rule, and it reads the thing (failed while a stopped store took
// nothing: no claim could reach it).
#[test]
fn a_stopped_store_granted_again_reads_spec_sync_judgement_6() {
    use crate::harness::script::*;
    holds_on(0, 3, 4, &[New(0), Give(0, 0, Holder::Node(2), Syncs), Strong(2, None, 0), Run, Revoke(0, 0, Holder::Node(2)), Give(0, 0, Holder::Node(2), Reads)], String::new(), false);
}

// spec/sync-ids.md §4 (Owner: kept unread, the sync ID of its own reading is a hint while no step
// bears a held key), spec/permissions.md §3 (Lost access): node 0 grants node 1's account read on
// its thing, removes it, then grants it sync, and node 1 strongs it. Node 1 learned its removal
// while it read; its new sync secret comes by the claim alone, which no step it recorded bears.
// It keeps the thing unread, as the model says (failed: the `keys.0` it read named the thing no
// sync ID until a recorded step bore a held key).
#[test]
fn a_reader_removed_then_granted_sync_keeps_it_unread_spec_sync_ids_4() {
    use crate::harness::script::*;
    holds_on(0, 3, 4, &[New(0), Give(0, 0, Holder::Node(1), Reads), Revoke(0, 0, Holder::Node(1)), Give(0, 0, Holder::Node(1), Syncs), Strong(1, None, 0)], String::new(), false);
}

// spec/sync-opens.md §5 (Testing: a Head unanswered tested nothing), §1 (one connection per pair):
// node 2 grants node 1's account sync on its thing twice, node 1 strongs it, and node 2's disk
// fails. Node 1 asks Head of the thing's sync ID on a connection that then loses the pair rule to
// one dialed meanwhile; the survivor takes the record, which counted S tested. Node 1 keeps the
// thing unread, as the model says (failed: it never asked Head again and held a stub).
#[test]
fn a_head_unanswered_on_a_released_connection_is_asked_again_spec_sync_opens_5() {
    use crate::harness::script::*;
    holds_on(0, 3, 4, &[New(2), Give(2, 0, Holder::Node(1), Syncs), Strong(1, None, 0), Give(2, 0, Holder::Node(1), Syncs), Disk(2, 0, Fail)], String::new(), false);
}
