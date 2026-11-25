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
fn a_making_released_before_a_grantee_held_it_is_lost_spec_sync_set_3() {
    use crate::harness::history::{Gives, Holder};
    let script = [Step::New(1), Step::NewIn(1, 0), Step::Give(1, 1, Holder::Node(0), Gives::Reads), Step::Run, Step::Strong(2, None, 1), Step::Unstrong(1, Some(0), 1)];
    holds_on(0, 2, 3, &script, String::new(), false);
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

// spec/sync-inbox.md §1 (Card: a move writes a `since` above every card; inbox: the one the card
// with the greatest `since` names), §5 (Grant from outside): node 0 moves its
// account's inbox to a thing of its own and back again; node 1, a contact, takes each move from the
// profile's card, and its grant from outside reaches node 0's account at the inbox the card names
// (the oracle's card clause: every node takes every inbox as the reference does). Control: a
// card on a thing node 0 writes changes no inbox.
#[test]
fn an_inbox_moved_takes_grants_from_outside_spec_sync_inbox_1() {
    use crate::harness::history::{Gives, Holder, reads};
    let (n, accounts, ..) = size();
    for back in [false, true] {
        let mut script = vec![Step::New(0), Step::Inbox(0, Some(0)), Step::Run];
        if back {
            script.extend([Step::Inbox(0, None), Step::Run]);
        }
        script.extend([Step::New(1), Step::Give(1, 1, Holder::Node(0), Gives::Reads), Step::Strong(0, None, 1), Step::Run]);
        let mut w = holds_on(0, accounts, n, &script, String::new(), false);
        let (a, moved) = (w.node(0).account.unwrap(), w.history.things[0].0);
        let want = if back { w.node(0).inbox.unwrap() } else { moved };
        assert_eq!(w.engine(1).inbox_of(&a).unwrap(), Some(want), "node 1 takes the move (back: {back})");
        let granted = w.history.things[1].0;
        assert!(reads(w.engine(0), &granted).value.is_some(), "the grant from outside reached the account (back: {back})");
    }
    let control = [Step::New(0), Step::Card(0, 0), Step::Run];
    let mut w = holds_on(0, accounts, n, &control, String::new(), false);
    let a = w.node(0).account.unwrap();
    assert_eq!(w.engine(1).inbox_of(&a).unwrap(), w.node(0).inbox, "control: a card on a thing moves no inbox");
}

// spec/sync-opens.md §4 (lapsed secrets), §6 (A reader tells a public reader the public's removal):
// node 0 makes a thing public, node 1 of another account redeems a public link to it, then node 0
// removes the public and writes again while node 1 is off. Node 1 holds the removal and reads the
// thing no more (fails without the lapsed read secrets: no reader opens the thing's sync ID toward
// it again).
#[test]
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

// spec/sync-set.md §2 (T's keys open): node 1's account holds thing 0 at
// sync and holds it by a strong; node 0 then makes it public and writes. Node 1 should read it as
// the reference does; it keeps it unread, never holding the public's grant
// (issues/public-pieces-unheld.md).
#[test]
#[ignore = "issues/public-pieces-unheld.md"]
fn repro_a_sync_holder_reads_a_thing_made_public() {
    use crate::harness::history::{Gives, Holder};
    let (n, accounts, ..) = size();
    let script = [Step::New(0), Step::Give(0, 0, Holder::Node(1), Gives::Syncs), Step::Strong(1, None, 0), Step::Run, Step::Give(0, 0, Holder::Public, Gives::Reads), Step::Write(0, 0), Step::Run];
    holds_on(0, accounts, n, &script, String::new(), false);
}

// spec/permissions.md §8 (Removing: erasing), spec/sync-inbox.md §5 (a removal from outside goes
// as a grant does): node 0 removes node 2 from their account; node 2 should learn it and hold
// nothing of the history: node 0 serves it its departure (spec/sync-opens.md §6).
#[test]
fn a_removed_node_learns_its_removal_spec_sync_opens_6() {
    let (n, accounts, ..) = size();
    holds_on(0, accounts, n, &[Step::New(0), Step::Run, Step::Unpair(0, 2), Step::Run], String::new(), false);
}

// spec/sync-inbox.md §2 (Sealed copy: held as any role commit), §3 (a node reading S opens a
// deposit it takes): node 0 removes node 2 from their account, cut off from node 1, which grants
// the account sync on its thing and revokes it. Node 0 takes the sealed copies deposited in its
// inbox; nothing it holds needs the grant's, so it forgets it. It settles: a deposit taken is
// opened again only as any entry of a read sync ID (its read secrets moving), never as its
// commit goes (failed: the inbox opened the deposit again at every settle round, retention
// forgetting what it took, past the settle loop's bound).
#[test]
fn a_taken_deposit_whose_commit_goes_is_not_taken_again_spec_sync_inbox_3() {
    use crate::harness::history::{Gives, Holder};
    let script = [Step::New(1), Step::Cut(0, 1), Step::Unpair(0, 2), Step::Give(1, 0, Holder::Node(0), Gives::Syncs), Step::Revoke(1, 0, Holder::Node(0)), Step::Run];
    holds_on(0, 2, 3, &script, String::new(), false);
}

// spec/permissions.md §3 (Sync ID role keys: a step due for the public; Left out): node 1
// grants thing 1 read on its thing 0 while node 0, the admin of thing 1, makes thing 1 public;
// node 1, a writer of thing 1, rotates its read keys for the grant before seeing the public's,
// so the public is left out of thing 1's newest read epoch. Every node settles (failed: thing 1's
// admin issued a step per settle round, due for the public that no step could list before its
// re-seal, past the settle loop's bound).
#[test]
fn a_public_left_out_of_a_rotation_is_listed_once_re_sealed_spec_permissions_3() {
    use crate::harness::history::{Gives, Holder};
    let script = [Step::New(1), Step::New(0), Step::Give(0, 1, Holder::Node(1), Gives::Writes), Step::Strong(1, None, 1), Step::Run, Step::Give(1, 0, Holder::Thing(1), Gives::Reads), Step::Give(0, 1, Holder::Public, Gives::Reads)];
    holds_on(0, 2, 3, &script, String::new(), false);
}
