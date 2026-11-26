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
    let (mut w, _script) = played(replay.clone(), false);
    if twice {
        let (again, _) = played(replay, true);
        if let Some(i) = (0..w.seen.len().max(again.seen.len())).find(|&i| w.seen.get(i) != again.seen.get(i)) {
            panic!("not deterministic: replay differs at delivery {i} of {}: {:?} then {:?}", w.seen.len(), w.seen.get(i), again.seen.get(i));
        }
    }
    check(&mut w);
    w
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
/// the history `steps_of(seed)`, each failure shrunk under `OSIS_SYNC_SHRINK=1`. A shrunk script
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
        );
    });
}

// spec/sync-set.md §3 (Nothing of R stays): a node's own writes on a thing it releases, not yet
// held elsewhere, go. Node 1 makes a thing and grants node 0's account read; a run connects them
// while no node of that account holds the thing (the grant is an offer); a paired node of the
// account then holds it by a strong and node 1 releases it before any run. The making's value is
// at no node, and the oracle counts it lost: a run gives a node a value write only where its
// account's node closure held the thing then (`harness::history::ran`).
#[test]
#[ignore = "stub rewrite: entry by references and stubs, pairing by values (R2, R3)"]
fn a_making_released_before_a_grantee_held_it_is_lost_spec_sync_set_3() {
    use crate::harness::history::{Gives, Holder};
    let script = [Step::New(1), Step::NewIn(1, 0), Step::Give(1, 1, Holder::Node(0), Gives::Reads), Step::Run, Step::Strong(2, None, 1), Step::Unstrong(1, Some(0), 1)];
    holds_on(0, 2, 3, &script, String::new(), false);
}

// spec/sync-set.md §3 (Nothing of R stays): node 1 makes a thing, gives the public sync and node
// 2's account read, and releases it before any run: its making and the public's grant are at no
// node, while the grant to node 2's account reaches it as an offer and node 2 holds the thing by
// a strong. The oracle counts a lost grant as it counts a lost value write (`lost_writes`) and
// builds the reference and the model without it, so node 2 reads the roster it holds (failed:
// the reference, handed the public's grant, read a sync role node 2 can never learn of).
#[test]
#[ignore = "stub rewrite: entry by references and stubs, pairing by values (R2, R3)"]
fn a_grant_released_before_anyone_received_it_is_lost_spec_sync_set_3() {
    use crate::harness::history::{Gives, Holder};
    let script = [Step::New(1), Step::Give(1, 0, Holder::Public, Gives::Syncs), Step::Give(1, 0, Holder::Node(2), Gives::Reads), Step::Unstrong(1, None, 0), Step::Strong(2, None, 0)];
    holds_on(0, 3, 4, &script, String::new(), false);
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

// spec/sync-set.md §2 (T's keys open: what the public reads), §4 (Redeeming a public link: the
// strong): node 0 makes a thing public; node 1, of another account holding no role on it,
// redeems a public link to it and reads it as the reference does, as held-model's closure says.
// Control: never made public, the redeem writes nothing and node 1 reads nothing.
#[test]
#[ignore = "stub rewrite: entry by references and stubs, pairing by values (R2, R3)"]
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

// spec/sync-opens.md §4 (lapsed secrets), §6 (A reader tells a public reader the public's removal):
// node 0 makes a thing public, node 1 of another account redeems a public link to it, then node 0
// removes the public and writes again while node 1 is off. Node 1 holds the removal and reads the
// thing no more (fails without the lapsed read secrets: no reader opens the thing's sync ID toward
// it again).
#[test]
#[ignore = "stub rewrite: entry by references and stubs, pairing by values (R2, R3)"]
fn a_redeemer_hears_the_public_removed_spec_sync_opens_6() {
    use crate::harness::history::{Gives, Holder, reads};
    let (n, accounts, ..) = size();
    let script = [Step::New(0), Step::Give(0, 0, Holder::Public, Gives::Reads), Step::Run, Step::Redeem(1, 0), Step::Run, Step::PowerOff(1), Step::Revoke(0, 0, Holder::Public), Step::Write(0, 0), Step::Run];
    let mut w = holds_on(0, accounts, n, &script, String::new(), false);
    let t = w.history.things[0].0;
    assert!(reads(w.engine(1), &t).value.is_none(), "node 1 reads the thing no more");
}

// spec/sync-opens.md §6 (A reader tells a public reader the public's removal; Lost: a member
// opened after the first Pull has no reported position until a join names it): as above, but
// while node 1 is off node 0 first removes another reader (thing 1), rotating the thing's read
// keys with the public boxed again, and writes. Node 1 hears the removal: the member opened on its
// lapsed secret is served from where the public entry's member stopped (failed: closed at once on
// the stream's position, past both, node 1 reading v1 for good).
#[test]
#[ignore = "stub rewrite: entry by references and stubs, pairing by values (R2, R3)"]
fn a_redeemer_misses_a_rotation_and_hears_the_public_removed_spec_sync_opens_6() {
    use crate::harness::history::{Gives, Holder};
    let (n, accounts, ..) = size();
    let script = [
        Step::New(0),
        Step::Give(0, 0, Holder::Public, Gives::Reads),
        Step::Run,
        Step::Redeem(1, 0),
        Step::Run,
        Step::PowerOff(1),
        Step::New(0),
        Step::Give(0, 0, Holder::Thing(1), Gives::Reads),
        Step::Revoke(0, 0, Holder::Thing(1)),
        Step::Write(0, 0),
        Step::Revoke(0, 0, Holder::Public),
        Step::Write(0, 0),
        Step::Run,
    ];
    holds_on(0, accounts, n, &script, String::new(), false);
}

// spec/sync-opens.md §4 (lapsed secrets), spec/sync-hostile.md §2: a public link made while
// the public read a thing, redeemed by a stranger (node 1) only after the public's removal, opens
// nothing: holding no read secret of the thing, node 1 hits nothing, and no store entry of the thing
// reaches it (failed with a lapsed public entry, which every holder of the sync ID hits: node 1 was
// served the thing up to the removal, the public's open boxes with it). Control: with the public
// not removed, the same redeem is served the thing.
#[test]
fn a_public_link_redeemed_after_the_removal_opens_nothing_spec_sync_opens_4() {
    use crate::harness::history::{Gives, Holder};
    let (n, accounts, ..) = size();
    for removed in [true, false] {
        let mut w = world_of(0, accounts, n);
        w.cap = crate::harness::STORM_CAP;
        play(&mut w, &[Step::New(0), Step::Give(0, 0, Holder::Public, Gives::Reads), Step::Run], String::new());
        let t = w.history.things[0].0;
        let s = w.engine(0).sync_id_of(&t).unwrap().expect("a sync ID");
        let link = w.public_link(0, t).expect("the public reads it");
        if removed {
            play(&mut w, &[Step::Revoke(0, 0, Holder::Public), Step::Write(0, 0), Step::Run], String::new());
        }
        w.redeem_any(1, &link);
        let mut most = 0;
        while w.step_or_wake() {
            most = most.max(w.store(1).entries(&s).unwrap().len());
        }
        assert_eq!(most == 0, removed, "node 1 held {most} entries of the thing (removed: {removed})");
    }
}

// spec/sync-opens.md §4 (Admissible: a node keeping S unread takes its head's public entry): node 1's
// account holds thing 0 at sync and holds it by a strong; node 0 makes it public and writes, and
// node 1 reads it by its head's public entry box, as the reference does (failed without: it kept
// it unread, never holding the public's grant). Then (second) node 0 removes the public and
// writes: node 1 reads the removal, drops its read secrets and keeps it unread again at the head
// it held while reading, which lists the public but bears a sync epoch the removal superseded, so
// it takes nothing there (failed taking any head's box: it read again, dropped again, and the pair
// churned past the storm cap).
#[test]
#[ignore = "stub rewrite: entry by references and stubs, pairing by values (R2, R3)"]
fn a_sync_holder_reads_a_thing_made_public_spec_sync_opens_4() {
    use crate::harness::history::{Gives, Holder};
    let (n, accounts, ..) = size();
    let made = [Step::New(0), Step::Give(0, 0, Holder::Node(1), Gives::Syncs), Step::Strong(1, None, 0), Step::Run, Step::Give(0, 0, Holder::Public, Gives::Reads), Step::Write(0, 0), Step::Run];
    holds_on(0, accounts, n, &made, String::new(), false);
    let removed: Vec<Step> = made.iter().cloned().chain([Step::Revoke(0, 0, Holder::Public), Step::Write(0, 0), Step::Run]).collect();
    holds_on(0, accounts, n, &removed, String::new(), false);
}

// spec/permissions.md §3 (No secret taken back: a held epoch's history boxes): thing 0 is made
// public, node 1's account given sync on it, and thing 0 then granted read on thing 1, which
// moves thing 0's epochs on; node 1 strongs thing 0 and reads it by its head's public entry box.
// That box gives the newest epochs alone; the public's grant is under an earlier one, which only
// their history boxes give. Taking those only once node 1's roles give read (known
// only from that grant) left it holding read secrets of a thing it judged it could not read: its
// loss due for good, the pair churned past the storm cap.
#[test]
#[ignore = "stub rewrite: entry by references and stubs, pairing by values (R2, R3)"]
fn an_entry_box_epochs_history_is_taken_spec_permissions_3() {
    use crate::harness::history::{Gives, Holder};
    let (n, accounts, ..) = size();
    let script = [Step::New(0), Step::Give(0, 0, Holder::Public, Gives::Reads), Step::New(0), Step::Give(0, 0, Holder::Node(1), Gives::Syncs), Step::Give(0, 1, Holder::Thing(0), Gives::Reads), Step::Run, Step::Strong(1, None, 0), Step::Run];
    holds_on(0, accounts, n, &script, String::new(), false);
}

// spec/permissions.md §3 (Sync ID role keys: a step due for the public; Left out): node 1
// grants thing 1 read on its thing 0 while node 0, the admin of thing 1, makes thing 1 public;
// node 1, a writer of thing 1, rotates its read keys for the grant before seeing the public's,
// so the public is left out of thing 1's newest read epoch. Every node settles (failed: thing 1's
// admin issued a step per settle round, due for the public that no step could list before its
// re-seal, past the settle loop's bound).
#[test]
#[ignore = "stub rewrite: entry by references and stubs, pairing by values (R2, R3)"]
fn a_public_left_out_of_a_rotation_is_listed_once_re_sealed_spec_permissions_3() {
    use crate::harness::history::{Gives, Holder};
    let script = [Step::New(1), Step::New(0), Step::Give(0, 1, Holder::Node(1), Gives::Writes), Step::Strong(1, None, 1), Step::Run, Step::Give(1, 0, Holder::Thing(1), Gives::Reads), Step::Give(0, 1, Holder::Public, Gives::Reads)];
    holds_on(0, 2, 3, &script, String::new(), false);
}

// spec/sync-set.md §2 (Own things: the public's role is every party's), spec/permissions.md §1:
// thing 0 is public and holds read on thing 1; node 1's account holds both at sync and by
// strongs. Every party reads thing 1 through thing 0: node 1, reading thing 0 (holding the public's
// grant), reads thing 1 too, as the reference does (whose node role left the public out: it had
// node 1 keep thing 1 unread).
#[test]
#[ignore = "stub rewrite: entry by references and stubs, pairing by values (R2, R3)"]
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
#[ignore = "stub rewrite: entry by references and stubs, pairing by values (R2, R3)"]
fn a_store_granted_past_genesis_is_moved_spec_sync_ids_6() {
    use crate::harness::history::{Gives, Holder};
    let (n, accounts, ..) = size();
    let script = [Step::New(0), Step::New(0), Step::Give(0, 0, Holder::Thing(1), Gives::Syncs), Step::Revoke(0, 0, Holder::Thing(1)), Step::Give(0, 0, Holder::Node(1), Gives::Syncs), Step::Run, Step::Strong(1, None, 0), Step::Write(0, 0), Step::Run];
    holds_on(0, accounts, n, &script, String::new(), false);
}

// spec/sync-opens.md §4 (Admissible: a node keeping S unread takes its head's public entry),
// spec/sync.md §3 (Holders by copies: a record alone is none of the admins' word): as above with
// thing 0 public and its epochs moved on by its read grant on thing 1. Node 1's store is moved to
// the head listing the public and reads thing 0 by its entry box; it takes thing 0's record before
// the role commits placing its steps, and reads it once they come (failed judging by the record
// alone: thing 0 dependent on its mint admin, of which node 1 holds nothing, so nothing fetched the
// role commits and it dropped thing 0 for good).
#[test]
#[ignore = "stub rewrite: entry by references and stubs, pairing by values (R2, R3)"]
fn a_public_reader_keeps_a_thing_on_taking_its_record_spec_sync_3() {
    use crate::harness::history::{Gives, Holder};
    let (n, accounts, ..) = size();
    let script = [Step::New(0), Step::Give(0, 0, Holder::Public, Gives::Reads), Step::New(0), Step::Give(0, 1, Holder::Thing(0), Gives::Reads), Step::Give(0, 0, Holder::Node(1), Gives::Syncs), Step::Run, Step::Strong(1, None, 0), Step::Write(0, 0), Step::Run];
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
#[ignore = "stub rewrite: entry by references and stubs, pairing by values (R2, R3)"]
fn the_publics_removal_keeps_what_a_nodes_own_role_gives_spec_permissions_3() {
    use crate::harness::history::{Gives, Holder, reads};
    let (n, accounts, ..) = size();
    let script = [Step::New(1), Step::Give(1, 0, Holder::Node(0), Gives::Reads), Step::Strong(0, None, 0), Step::Give(1, 0, Holder::Public, Gives::Reads), Step::Run, Step::Revoke(1, 0, Holder::Public)];
    let mut w = holds_on(0, accounts, n, &script, String::new(), false);
    let t = w.history.things[0].0;
    assert!(reads(w.engine(0), &t).value.is_some(), "node 0 reads thing 0 by its account's grant");
}

// spec/permissions.md §3 (Lost access), spec/sync-set.md §4: a node that redeemed a public link
// reads the thing by the public alone, so the public's removal is its loss too, the removal
// coming after a quiet run or while the redemption is in flight. Control: no removal, it reads.
#[test]
#[ignore = "stub rewrite: entry by references and stubs, pairing by values (R2, R3)"]
fn a_public_links_redeemer_loses_the_thing_with_the_public_spec_permissions_3() {
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
#[ignore = "stub rewrite: entry by references and stubs, pairing by values (R2, R3)"]
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
// node 0's account sync on thing 0, a thing made in thing 0 beside it; node 0 holds thing 0 and
// removes its account's other node, so node 1 rotates thing 0's sync role and issues a step.
// Node 0 takes the step's sealed copy before the box under it, judges itself past its keys, stops
// S (its store shredded) and syncs it again before its sync modules see it leave. Node 0 keeps
// thing 0 unread at its readers' head. Failed without either rule: node 1 kept node 0's old head
// and registered onto an empty path (13), or tested the newest step's key first forever, a beacon
// node 0's filter keeps showing.
#[test]
#[ignore = "stub rewrite: entry by references and stubs, pairing by values (R2, R3)"]
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
#[ignore = "stub rewrite: entry by references and stubs, pairing by values (R2, R3)"]
fn a_store_moved_at_once_takes_the_next_step_spec_sync_ids_6() {
    use crate::harness::script::*;
    let script = [New(1), Give(1, 0, Holder::Node(0), Syncs), NewIn(1, 0), Run, Strong(0, None, 0), Run, Unpair(0, 3)];
    holds_on(0, 3, 4, &script, String::new(), false);
}

// spec/sync-opens.md §4 (Admissible: keeping S unread, the head it was lowered to sync at gives
// nothing): node 2 makes a thing the public reads; node 0, of its account, grants node 1's account
// sync and node 1 holds the thing, reading it by the public's grant; node 0 lowers the public to
// sync, which rotates read and no sync epoch. Node 1 drops its read secrets and keeps the thing
// unread at the head it read, whose claim set lists the public entry: taking that entry's box it
// would read again, drop again on the role entries, and refuse while reading each Register moving
// its head, a storm past the world's cap. It reaches quiet, keeping the thing unread as the model
// says, and its index rebuilds from what it holds once the role commits it read are forgotten.
#[test]
#[ignore = "stub rewrite: entry by references and stubs, pairing by values (R2, R3)"]
fn a_node_lowered_with_the_public_reads_no_more_by_its_head_spec_sync_opens_4() {
    use crate::harness::history::{Gives, Holder};
    let script = [Step::New(2), Step::Run, Step::Give(2, 0, Holder::Public, Gives::Reads), Step::Give(0, 0, Holder::Node(1), Gives::Syncs), Step::Run, Step::Strong(1, None, 0), Step::Lower(0, 0, Holder::Public, Gives::Syncs)];
    holds_on(0, 2, 3, &script, String::new(), false);
}

// spec/sync-opens.md §4 (Admissible: keeping S unread, the head it was lowered to sync at gives
// nothing), across a start: node 1, lowered with the public as above, is powered off and on while
// it keeps the thing unread at the head it read, before the Register moving it arrives. Started,
// it keeps the thing unread, never reading it by that head's public entry again (a start judges
// as the live node did).
#[test]
#[ignore = "stub rewrite: entry by references and stubs, pairing by values (R2, R3)"]
fn a_node_lowered_with_the_public_reads_no_more_after_a_start_spec_sync_opens_4() {
    use crate::harness::history::{Gives, Holder, reads};
    const TAKEN: &str = "unread: read by its head's public entry @node 1";
    let taken = || osis_base::costs::take().iter().find(|x| x.0 == TAKEN).map_or(0, |x| x.2);
    let script = [Step::New(2), Step::Run, Step::Give(2, 0, Holder::Public, Gives::Reads), Step::Give(0, 0, Holder::Node(1), Gives::Syncs), Step::Run, Step::Strong(1, None, 0), Step::Run];
    let mut w = world_of(0, 2, 3);
    w.cap = crate::harness::STORM_CAP;
    osis_base::costs::take();
    play(&mut w, &script, String::new());
    taken();
    let t = w.history.things[0].0;
    let s = w.engine(0).sync_id_of(&t).unwrap().unwrap();
    play(&mut w, &[Step::Lower(0, 0, Holder::Public, Gives::Syncs)], String::new());
    let at_read_head = |w: &mut World| reads(w.engine(1), &t).value.is_none() && w.store(1).path(&s).unwrap().and_then(|p| p.steps.last().and_then(|x| x.1.clone())).is_some_and(|c| c.lists_public(&s));
    while !at_read_head(&mut w) {
        assert!(w.step_or_wake(), "node 1 is lowered at the head it read");
    }
    assert_eq!(taken(), 1, "node 1 reads by the public's entry, then is lowered");
    play(&mut w, &[Step::PowerOff(1), Step::PowerOn(1), Step::Run], String::new());
    assert_eq!(taken(), 0, "started, it reads no more by the head it was lowered at");
    check(&mut w);
}

// spec/sync-opens.md §4 (Admissible: the head it was lowered at gives nothing until a Register
// moves it): node 1, lowered with the public as above, reads the thing again once the public is
// granted read again (a new step listing the public entry is registered with it).
#[test]
#[ignore = "stub rewrite: entry by references and stubs, pairing by values (R2, R3)"]
fn a_node_lowered_with_the_public_reads_again_on_its_regrant_spec_sync_opens_4() {
    use crate::harness::history::{Gives, Holder};
    let script = [Step::New(2), Step::Run, Step::Give(2, 0, Holder::Public, Gives::Reads), Step::Give(0, 0, Holder::Node(1), Gives::Syncs), Step::Run, Step::Strong(1, None, 0), Step::Lower(0, 0, Holder::Public, Gives::Syncs), Step::Run, Step::Give(0, 0, Holder::Public, Gives::Reads), Step::Run];
    let mut w = holds_on(0, 2, 3, &script, String::new(), false);
    let t = w.history.things[0].0;
    assert!(crate::harness::history::reads(w.engine(1), &t).value.is_some(), "node 1 reads the thing again by the public's grant");
}


// spec/permissions.md §3 (No secret taken back): a removed reader takes the public's
// box as any party does, and no more. Node 0's account reads node 1's public thing and strongs
// it; it is removed and a write follows (read by the public), then the public is removed and a
// write follows: node 0 reads neither that write nor any secret of the epoch the public's removal
// minted, whether the removals have a run between them or node 0 is off through both.
// Control: the public not removed, node 0 reads the last write by the public.
#[test]
#[ignore = "stub rewrite: entry by references and stubs, pairing by values (R2, R3)"]
fn a_removed_reader_takes_from_the_publics_box_no_more_than_a_stranger_spec_permissions_3() {
    use crate::harness::history::{Gives, Holder, reads};
    let start = [Step::New(1), Step::Give(1, 0, Holder::Node(0), Gives::Reads), Step::Give(1, 0, Holder::Public, Gives::Reads), Step::Strong(0, None, 0), Step::Run];
    for (case, mid, off) in [("a run between", vec![Step::Run], false), ("node 0 off", vec![], true)] {
        for ended in [true, false].into_iter().filter(|e| *e || !off) {
            let mut s: Vec<Step> = start.to_vec();
            s.extend(off.then_some(Step::PowerOff(0)));
            s.extend([Step::Revoke(1, 0, Holder::Node(0)), Step::Write(1, 0)].into_iter().chain(mid.clone()));
            s.extend(ended.then_some(Step::Revoke(1, 0, Holder::Public)));
            s.extend([Step::Write(1, 0), Step::PowerOn(0), Step::Run]);
            let mut w = world_of(0, 2, 3);
            w.cap = crate::harness::STORM_CAP;
            play(&mut w, &s, String::new());
            let t = w.history.things[0].0;
            let last = reads(w.engine(1), &t).value;
            let newest = w.engine(1).epochs(&t).unwrap().read.newest().unwrap();
            let got = w.engine(0).epochs(&t).is_some_and(|e| e.read.secret(&newest).is_some());
            match ended {
                true => assert!(reads(w.engine(0), &t).value != last && !got, "{case}: node 0 reads nothing written after the public's read ended"),
                false => assert!(reads(w.engine(0), &t).value == last && got, "{case}: control: node 0 reads the last write by the public"),
            }
        }
    }
}

// spec/sync-opens.md §6 (A member whose peer J judges departed is ended too: served its notices
// and the public's edge): node 0's
// account reads node 1's public thing and strongs it; both removed (the public's first, with no
// run between; or node 0's, a run, then the public's), node 0 is departed at every reader, so a
// notice tells it its own removal, and the public's removal, which has no notice (the public
// holds no keys), reaches it only as the public's edge: it reads the thing no more, as the model
// says. Failed while a departed member was served its notices alone: node 0 kept reading at the
// public's role, its roster still listing the public.
#[test]
#[ignore = "stub rewrite: entry by references and stubs, pairing by values (R2, R3)"]
fn a_departed_public_reader_holds_the_publics_removal_spec_sync_opens_6() {
    use crate::harness::history::{Gives, Holder};
    let start = [Step::New(1), Step::Give(1, 0, Holder::Node(0), Gives::Reads), Step::Give(1, 0, Holder::Public, Gives::Reads), Step::Strong(0, None, 0), Step::Run];
    let ends = [vec![Step::Revoke(1, 0, Holder::Public), Step::Revoke(1, 0, Holder::Node(0))], vec![Step::Revoke(1, 0, Holder::Node(0)), Step::Run, Step::Revoke(1, 0, Holder::Public)]];
    for end in ends {
        let script: Vec<Step> = start.iter().cloned().chain(end).collect();
        holds_on(0, 2, 3, &script, String::new(), false);
    }
}

// spec/permissions.md §3 (Complete pass: a holder's keyset arriving), spec/crypto.md §4 (Seal: a
// holder actor left out is re-sealed once a keyset exists): node 1 grants node 0's account sync on its
// thing, which node 3 (paired into that account) strongs; node 3 removes node 2 from the account.
// Node 1, rotating its thing for node 2's departure before it holds the account's new keyset,
// leaves the account out, so the account's nodes are at a head past their keys; the keyset's
// arrival makes a pass of the thing due, at whose end node 1 re-seals the account, and node 0
// keeps the thing unread, as the model says. Failed while only the thing's own role commits made
// a pass due: node 1 held the keyset and never re-sealed, and node 0 followed the thing by the
// public entry.
#[test]
#[ignore = "stub rewrite: entry by references and stubs, pairing by values (R2, R3)"]
fn a_holder_left_out_is_re_sealed_once_its_keyset_arrives_spec_permissions_3() {
    use crate::harness::script::*;
    holds_on(0, 2, 3, &[New(1), Give(1, 0, Holder::Node(0), Syncs), Pair(0), Run, Strong(3, None, 0), Unpair(3, 2)], String::new(), false);
}

// spec/permissions.md §3 (Lost access: its role there counts the public's sync its head lists),
// spec/sync.md §3 (Holders by copies): node 0's account, a reader, is removed after the public is
// given only sync and node 0's strong names the thing. Node 0 follows it by the public entry and
// takes the public's box, the sync secret alone, while it still holds the read secrets its loss
// has not dropped: the drop keeps that sync secret, so it keeps the thing unread as the model says.
// Failed while lost access judged the sync secret by the grants alone: it dropped the public's
// sync secret with the rest and followed the thing again, holding nothing.
#[test]
#[ignore = "stub rewrite: entry by references and stubs, pairing by values (R2, R3)"]
fn a_removed_reader_keeps_the_publics_sync_secret_through_its_loss_spec_permissions_3() {
    use crate::harness::script::*;
    holds_on(0, 3, 4, &[New(2), Give(2, 0, Holder::Node(0), Reads), Give(2, 0, Holder::Node(1), Reads), Revoke(2, 0, Holder::Node(1)), Give(2, 0, Holder::Public, Syncs), Strong(0, None, 0), Revoke(2, 0, Holder::Node(0))], String::new(), false);
}
