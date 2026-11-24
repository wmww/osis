//! External fires (spec/permissions.md §5.2 External fires, spec/commits.md §5 The setting): a fire
//! of an external signal valid by its author's authority is valid whatever the setting; any other
//! only while the thing's current setting enables the signal. Each path from a fire to an effect:
//! a reader's write, the fire's listing and validity, promotion, a sealed grant fire taken, each in
//! both orders against the setting.

use crate::common::{REG, ak, edge, edge_write, new_shared, s, set_edge, set_setting, test_setting};
use crate::flows::{edge_of, people, send_carried};
use osis_base::{CommitId, Role, Tid};
use osis_crdt::{Op, PathOp};
use osis_engine::Mutation;
use osis_engine::local_peer::LocalPeer;
use osis_engine::sync::{Opened, Promote};
use osis_schema::core_types as ct;

const PING: &str = "x:ping@~0";

/// `test_setting`, enabling `PING` (its fires kept for good) or not.
fn setting(enabled: bool) -> ct::RetentionSetting {
    let mut x = test_setting();
    if enabled {
        x.rules.insert(ak(PING), ct::RetentionEntry { history: Some(osis_schema::History::FOREVER), ..Default::default() });
    }
    x
}

/// Peer `i` fires `PING` on `g` as it writes.
fn fire(lp: &mut LocalPeer, i: usize, g: Tid) -> osis_engine::Result<CommitId> {
    let mut m = Mutation::new();
    m.op(g, &ak(PING), PathOp { path: vec![], op: Op::Set(s("ping")) }).unwrap();
    lp.peers[i].commit(m).map(|c| c.expect("a commit"))
}

/// Whether peer `i` holds fire `c` on `g` judged valid.
fn valid(lp: &LocalPeer, i: usize, c: &CommitId, g: Tid) -> bool {
    let e = &lp.peers[i].engine;
    let Some(h) = e.header(c) else { return false };
    let ai = h.aspects.iter().position(|a| a.tid == g && a.ak == ak(PING)).expect("a fire on g");
    e.judged_valid(c, &[ai])
}

fn listed(lp: &mut LocalPeer, i: usize, c: &CommitId, g: Tid) -> bool {
    lp.peers[i].engine.listed_at(c, &[(g, ak(PING))]).unwrap()
}

/// Whether peer `i` (a writer of `g`) would promote fire `c` under `g`'s sync ID.
fn promotable(lp: &mut LocalPeer, i: usize, c: &CommitId, g: Tid) -> bool {
    let e = &mut lp.peers[i].engine;
    let s = e.sync_ids(&g).unwrap()[0].id;
    matches!(e.promotable(&s, c).unwrap(), Promote::Yes { .. })
}

/// Three accounts: peer 0 mints `g` (its admin, the only writer), peers 1 and 2 read it; `g`'s
/// setting enables nothing external.
fn three() -> (LocalPeer, Tid) {
    let mut lp = crate::common::net(3, 0);
    let g = new_shared(&mut lp, 0);
    lp.sync_all().unwrap();
    (lp, g)
}

// spec/permissions.md §5.2 External fires, spec/sync-inbox.md §4 Promotion: a reader may not fire
// a signal `g` does not enable (refused before signing, naming the setting); a writer's fire
// stands whatever the setting (a writer fires only what the setting keeps). Enabled, the reader's fire is valid, listed and promoted at the
// writer; disabled after it, before anything acted on it, it is invalid there (unlisted, never
// promoted), the writer's still valid; enabled again, valid again. A third node receiving the
// fire before any enabling setting and the settings after judges as the writer does.
#[test]
fn a_fire_counts_only_while_its_signal_is_enabled_spec_permissions_5_2() {
    let (mut lp, g) = three();
    assert!(matches!(fire(&mut lp, 1, g), Err(osis_engine::Error::NotEnabled { tid, .. }) if tid == g), "a reader's fire of an unenabled signal is refused");
    let s1 = set_setting(&mut lp, 0, g, &setting(true));
    let w = fire(&mut lp, 0, g).unwrap();
    send_carried(&mut lp, 0, 1, &[s1]);
    let f = fire(&mut lp, 1, g).expect("enabled: the reader fires");
    send_carried(&mut lp, 1, 0, &[f]);
    assert!(valid(&lp, 0, &f, g) && listed(&mut lp, 0, &f, g), "enabled then fired: valid and listed");
    assert!(promotable(&mut lp, 0, &f, g), "promoted");
    let s2 = set_setting(&mut lp, 0, g, &setting(false));
    assert!(!valid(&lp, 0, &f, g) && !listed(&mut lp, 0, &f, g), "disabled after the fire: invalid, unlisted");
    assert!(!promotable(&mut lp, 0, &f, g), "never promoted while invalid");
    assert!(valid(&lp, 0, &w, g), "the writer's fire stands");
    let s3 = set_setting(&mut lp, 0, g, &setting(true));
    assert!(valid(&lp, 0, &f, g), "enabled again: valid");
    // the other order: the fire first, the settings after
    send_carried(&mut lp, 1, 2, &[f]);
    assert!(!valid(&lp, 2, &f, g), "fired before any enabling setting here: invalid");
    send_carried(&mut lp, 0, 2, &[s1, s2, s3]);
    assert!(valid(&lp, 2, &f, g), "fired then enabled: valid, as at the writer");
    // dropped while invalid, it counts as never received: it joins when it comes again
    send_carried(&mut lp, 1, 2, &[f]);
    assert!(listed(&mut lp, 2, &f, g) && listed(&mut lp, 0, &f, g), "listed alike");
}

// spec/permissions.md §5.2 External fires (a valid one is valid by the rules above, a writer's
// whatever the setting; any other only while enabled): a writer's fire stays valid when the
// signal is disabled; once its author's removal's frontier leaves it out it is judged as a
// stranger's, invalid while `g` does not enable the signal, valid once it does.
#[test]
fn a_removed_writers_unlisted_fire_is_judged_as_a_strangers_spec_permissions_5_2() {
    let (mut lp, g) = three();
    let p1 = lp.peers[1].engine.me();
    let s1 = set_setting(&mut lp, 0, g, &setting(true));
    let up = set_edge(&mut lp.peers[0].engine, g, p1, Some(edge(Role::Write)), None);
    send_carried(&mut lp, 0, 1, &[s1, up]);
    let f = fire(&mut lp, 1, g).unwrap();
    send_carried(&mut lp, 1, 0, &[f]);
    set_setting(&mut lp, 0, g, &setting(false));
    assert!(valid(&lp, 0, &f, g), "a writer's fire: valid whatever the setting");
    edge_write(&mut lp.peers[0].engine, g, p1, Some(edge(Role::Read)), Some(ct::Frontier::default()));
    assert!(!valid(&lp, 0, &f, g), "unlisted by the demotion, not enabled: invalid");
    set_setting(&mut lp, 0, g, &setting(true));
    assert!(valid(&lp, 0, &f, g), "enabled: valid as a stranger's");
}

/// Peer `i` writes its account's inbox setting with `signal` enabled as at creation, or not.
fn inbox_signal(lp: &mut LocalPeer, i: usize, me: Tid, signal: &str, enabled: bool) {
    let inbox = lp.peers[i].engine.inbox_thing(&me).unwrap();
    let mut x = lp.peers[i].engine.get_typed(&inbox, &ct::RETENTION).unwrap().unwrap();
    let mut created = ct::RetentionSetting::default();
    created.take_inbox_signals();
    if enabled {
        x.rules.insert(ak(signal), created.rules[&ak(signal)]);
    } else {
        x.rules.remove(&ak(signal));
    }
    set_setting(lp, i, inbox, &x);
}

/// Peer `to` opens sealed fire `out`.
fn open(lp: &mut LocalPeer, to: usize, out: &osis_engine::sync::SealedFireOut) -> Opened {
    lp.peers[to].engine.open_entry(&out.sync_id, &osis_blob::blob_id(&out.blob), &[0; 57], &out.blob, u64::MAX).unwrap()
}

// spec/sync-inbox.md §5 Grant from outside, spec/permissions.md §5.2 External fires: with
// `grant@~0` disabled on Bob's inbox, Alice's grant fire is refused; enabled, the same fire is
// taken.
#[test]
fn a_grant_fire_is_taken_only_while_enabled_spec_sync_inbox_5() {
    let (mut lp, ps) = crate::flows::accounts(2);
    let t = crate::flows::thing_of(&mut lp, 0, ps[0]);
    crate::flows::spread(&mut lp);
    inbox_signal(&mut lp, 1, ps[1], "grant@~0", false);
    let owed = lp.peers[0].engine.fires_owed();
    lp.peers[0].engine.grant(&t, &ps[1], &edge_of(Role::Read)).unwrap();
    let id = *lp.peers[0].engine.fires_owed().iter().find(|f| !owed.contains(f)).expect("a grant fire owed");
    let out = lp.peers[0].engine.sealed_fire(&id).unwrap().expect("sealed");
    assert!(matches!(open(&mut lp, 1, &out), Opened::Bad), "not enabled: refused");
    inbox_signal(&mut lp, 1, ps[1], "grant@~0", true);
    assert!(matches!(open(&mut lp, 1, &out), Opened::Commit(..)), "enabled: taken");
}

// spec/sync-inbox.md §5 Grant from outside (an offer, held while H's current setting enables and
// keeps the signal): Bob opens Alice's grant fire and holds what it carries of X, which he
// references nowhere. Disabling the signal ends the offer, and what it carried goes with it:
// Bob's node holds nothing of X.
#[test]
fn disabling_grant_fires_ends_the_offer_and_what_it_carried_spec_sync_inbox_5() {
    let (mut lp, ps) = crate::flows::accounts(2);
    let x = crate::flows::thing_of(&mut lp, 0, ps[0]);
    crate::flows::spread(&mut lp);
    let owed = lp.peers[0].engine.fires_owed();
    lp.peers[0].engine.grant(&x, &ps[1], &edge_of(Role::Read)).unwrap();
    let id = *lp.peers[0].engine.fires_owed().iter().find(|f| !owed.contains(f)).expect("a grant fire owed");
    let out = lp.peers[0].engine.sealed_fire(&id).unwrap().expect("sealed");
    assert!(matches!(open(&mut lp, 1, &out), Opened::Commit(..)), "enabled: opened");
    lp.peers[1].engine.unhold(osis_base::Strong(x)).unwrap();
    lp.peers[1].engine.released(&[x].into()).unwrap();
    lp.peers[1].engine.settle_needs().unwrap();
    assert_eq!(lp.peers[1].engine.role_on(&x), Some(Role::Read), "the offer shows the grant");
    assert_eq!(carried_on(&lp, 1, &x).len(), 1, "one offer of X held");
    inbox_signal(&mut lp, 1, ps[1], "grant@~0", false);
    lp.peers[1].engine.settle_needs().unwrap();
    assert_eq!(carried_on(&lp, 1, &x), Vec::new(), "disabled: no offer held");
    assert_eq!(lp.peers[1].engine.role_on(&x), None, "and nothing of X: {}", lp.peers[1].engine.why_kept(&x));
}

// spec/commits.md §5 In force, spec/permissions.md §5.2 External fires: `g`'s setting purges its
// own replaced versions, so a new setting's transaction ends by covering and dropping the old one;
// a move that leaves which signals are enabled as they were leaves the fires as judged (and
// leaves none to judge past the transaction), one that disables `PING` makes a reader's fire
// invalid.
#[test]
fn a_setting_purged_on_replace_moves_no_fire_it_leaves_enabled_spec_commits_5() {
    let (mut lp, g) = three();
    let mut x = setting(true);
    x.rules.insert(ak("retention^.0"), ct::RetentionEntry { history: Some(osis_schema::History::PurgeOnReplace), ..Default::default() });
    let s1 = set_setting(&mut lp, 0, g, &x);
    send_carried(&mut lp, 0, 1, &[s1]);
    let f = fire(&mut lp, 1, g).unwrap();
    send_carried(&mut lp, 1, 0, &[f]);
    assert!(valid(&lp, 0, &f, g));
    let mut y = x.clone();
    y.rules.insert(ak("t:other.0"), ct::RetentionEntry { history: Some(osis_schema::History::FOREVER), ..Default::default() });
    let s2 = set_setting(&mut lp, 0, g, &y);
    assert!(valid(&lp, 0, &f, g), "still enabled");
    send_carried(&mut lp, 0, 1, &[s2]);
    assert!(valid(&lp, 1, &f, g), "still enabled at the reader");
    y.rules.remove(&ak(PING));
    set_setting(&mut lp, 0, g, &y);
    assert!(!valid(&lp, 0, &f, g), "disabled: invalid");
}

// spec/permissions.md §5.2 External fires (the setting is admin-only): a reader's commit past the
// writer's rules carrying both a setting enabling `PING` and a `PING` fire enables nothing: the
// fire is invalid at every node.
#[test]
fn a_readers_own_setting_enables_nothing_spec_permissions_5_2() {
    let (mut lp, g) = three();
    let mut m = Mutation::new();
    m.set(g, &ct::RETENTION, &setting(true)).unwrap();
    m.op(g, &ak(PING), PathOp { path: vec![], op: Op::Set(s("ping")) }).unwrap();
    let c = lp.peers[1].engine.commit_hostile(m).unwrap().unwrap();
    for to in [0, 2] {
        send_carried(&mut lp, 1, to, &[c]);
        assert!(!valid(&lp, to, &c, g) && !listed(&mut lp, to, &c, g), "peer {to}: invalid, unlisted");
    }
}

// spec/commits.md §5 In force (which settings are valid is the role timeline's),
// spec/permissions.md §5.2 External fires: a second admin's enabling setting reaches peer 3 after
// the reader's fire and before the grant making its author admin: the fire is invalid until the
// grant arrives and the setting's body comes again (dropped while invalid), then valid as at the
// reader. The admin's demotion with a frontier leaving the setting out makes it invalid again,
// at a node holding everything and at peer 3 alike.
#[test]
fn a_fire_follows_its_settings_validity_spec_commits_5() {
    let mut lp = crate::common::net(4, 0);
    let g = new_shared(&mut lp, 0);
    lp.sync_all().unwrap();
    let p2 = lp.peers[2].engine.me();
    let up = set_edge(&mut lp.peers[0].engine, g, p2, Some(edge(Role::Admin)), None);
    send_carried(&mut lp, 0, 2, &[up]);
    let s1 = set_setting(&mut lp, 2, g, &setting(true));
    send_carried(&mut lp, 2, 1, &[up, s1]);
    let f = fire(&mut lp, 1, g).expect("enabled at the reader");
    send_carried(&mut lp, 1, 3, &[f]);
    send_carried(&mut lp, 2, 3, &[s1]);
    assert!(!valid(&lp, 3, &f, g), "its setting's author not known admin yet: invalid");
    send_carried(&mut lp, 0, 3, &[up]);
    send_carried(&mut lp, 2, 3, &[s1]);
    assert!(valid(&lp, 3, &f, g), "the grant, then the setting again: valid");
    let dem = edge_write(&mut lp.peers[0].engine, g, p2, Some(edge(Role::Read)), Some(ct::Frontier::default()));
    send_carried(&mut lp, 2, 0, &[s1]);
    send_carried(&mut lp, 1, 0, &[f]);
    assert!(!valid(&lp, 0, &f, g), "the setting unlisted by its author's demotion: invalid");
    send_carried(&mut lp, 0, 3, &[dem]);
    assert!(!valid(&lp, 3, &f, g), "alike at peer 3");
}

// spec/commits.md §5 Signals (a fire is history), spec/sync-inbox.md §2: a reader's first-party
// fire (`flows::inbox::fire`) is never skipped silently: not enabled, it is refused `NotEnabled`;
// enabled with no history, which keeps no fire, refused naming the setting; enabled and kept,
// written. Nothing is owed sealed for a refused one.
#[test]
fn a_readers_fire_its_setting_does_not_take_is_refused_spec_sync_inbox_2() {
    let (mut lp, g) = three();
    let try_fire = |lp: &mut LocalPeer| lp.peers[1].engine.fire_open(&g, PING, s("ping"));
    assert!(matches!(try_fire(&mut lp), Err(osis_engine::Error::NotEnabled { tid, .. }) if tid == g), "not enabled");
    let mut x = test_setting();
    x.rules.insert(ak(PING), ct::RetentionEntry::default());
    let s1 = set_setting(&mut lp, 0, g, &x);
    send_carried(&mut lp, 0, 1, &[s1]);
    assert!(matches!(try_fire(&mut lp), Err(osis_engine::Error::Misuse(m)) if m.contains("setting keeps no history")), "enabled, no history");
    assert!(lp.peers[1].engine.fires_owed().is_empty(), "nothing owed sealed");
    let s2 = set_setting(&mut lp, 0, g, &setting(true));
    send_carried(&mut lp, 0, 1, &[s2]);
    try_fire(&mut lp).expect("enabled and kept: written");
}

/// The `grant@~0` fire peer `from` owes beside those in `owed`, sealed.
fn new_fire(lp: &mut LocalPeer, from: usize, owed: &[osis_engine::sync::FireId]) -> osis_engine::sync::SealedFireOut {
    let id = *lp.peers[from].engine.fires_owed().iter().find(|f| !owed.contains(f)).expect("a grant fire owed");
    lp.peers[from].engine.sealed_fire(&id).unwrap().expect("sealed")
}

// spec/permissions.md §4 Delivering an edge piece (stamped where it may write H): Alice makes a
// group G and a thing X and grants G read on X. She writes G, so no fire goes: Bob, a reader of
// G, reads X through it by X's grants.
#[test]
fn a_grant_by_the_holders_writer_goes_with_no_fire_spec_permissions_4() {
    let (mut lp, ps) = people(2);
    let g = crate::flows::thing_of(&mut lp, 0, ps[0]);
    let x = crate::flows::thing_of(&mut lp, 0, ps[0]);
    lp.peers[0].engine.grant(&g, &ps[1], &edge_of(Role::Read)).unwrap();
    crate::flows::spread(&mut lp);
    let owed = lp.peers[0].engine.fires_owed();
    lp.peers[0].engine.grant(&x, &g, &edge_of(Role::Read)).unwrap();
    assert_eq!(lp.peers[0].engine.fires_owed(), owed, "G's writer: no fire");
    crate::flows::spread(&mut lp);
    assert_eq!(lp.peers[1].engine.role_on(&x), Some(Role::Read), "Bob reads X through G");
}

// spec/sync-inbox.md §5 Grant from outside (an offer; the grant is the target's own data), spec/
// sync-set.md §2 Own actors (the node's role is by the thing's grants as the node holds them):
// Bob makes a group G; Alice, who holds no role on G, grants G read on her X. G's setting
// enables no `grant@~0`: her fire is refused and Bob learns nothing of X. Once Bob enables the
// signal on G the same fire is held, an offer of X, and Bob reads X through G. Disabled again,
// the offer is held no more and the grant stands: Bob's node syncs X, whose grants name G.
#[test]
fn a_grant_from_outside_is_an_offer_and_the_grant_stands_without_it_spec_sync_inbox_5() {
    let (mut lp, ps) = people(2);
    let g = crate::flows::thing_of(&mut lp, 1, ps[1]);
    let x = crate::flows::thing_of(&mut lp, 0, ps[0]);
    // G independent: it has an inbox of its own
    lp.peers[1].engine.grant(&g, &ps[0], &edge_of(Role::Sync)).unwrap();
    crate::flows::spread(&mut lp);
    let owed = lp.peers[0].engine.fires_owed();
    lp.peers[0].engine.grant(&x, &g, &edge_of(Role::Read)).unwrap();
    let out = new_fire(&mut lp, 0, &owed);
    assert!(matches!(open(&mut lp, 1, &out), Opened::Bad), "not enabled: refused");
    assert_eq!(lp.peers[1].engine.role_on(&x), None, "Bob holds nothing on X");
    lp.takes_grants(1, g);
    assert!(matches!(open(&mut lp, 1, &out), Opened::Commit(..)), "enabled: the fire is held");
    assert_eq!(carried_on(&lp, 1, &x).len(), 1, "an offer of X");
    assert_eq!(lp.peers[1].engine.role_on(&x), Some(Role::Read), "Bob reads X through G");
    lp.hold(x);
    crate::flows::spread(&mut lp);
    assert!(lp.peers[1].engine.closure_holds(&x), "Bob's node syncs X");
    set_setting(&mut lp, 1, g, &ct::RetentionSetting::default());
    lp.peers[1].engine.settle_needs().unwrap();
    assert_eq!(carried_on(&lp, 1, &x), Vec::new(), "disabled: no offer held");
    assert_eq!(lp.peers[1].engine.role_on(&x), Some(Role::Read), "the grant is X's: Bob reads it still");
}

/// The role commits the `grant@~0` fires peer `i` holds valid carry on `x`.
fn carried_on(lp: &LocalPeer, i: usize, x: &Tid) -> Vec<CommitId> {
    lp.peers[i].engine.grant_fires_held().into_iter().filter(|c| c.target == *x).map(|c| c.commit).collect()
}

// spec/sync-inbox.md §5 Grant from outside (kept as H's setting keeps the signal; once the
// target syncs, the offer decides nothing): Alice grants Bob read on her X from outside his
// account. Bob holds the offer and syncs X. Past the inbox lifetime the offer is gone and Bob
// reads X as before: his role is by X's grants.
#[test]
fn a_grant_outlives_its_offer_spec_sync_inbox_5() {
    let (mut lp, ps) = crate::flows::accounts(2);
    let x = crate::flows::thing_of(&mut lp, 0, ps[0]);
    let grant = lp.peers[0].engine.grant(&x, &ps[1], &edge_of(Role::Read)).unwrap().commits;
    crate::flows::spread(&mut lp);
    let held = carried_on(&lp, 1, &x);
    assert!(!held.is_empty() && held.iter().all(|c| grant.contains(c)), "Bob holds the grant's offer: {held:?}, grant {grant:?}");
    assert_eq!(lp.peers[1].engine.role_on(&x), Some(Role::Read), "and reads X");
    lp.advance(osis_base::format::INBOX_LIFETIME_MS + 3_600_000);
    lp.peers[1].tick().unwrap();
    lp.peers[1].engine.settle_needs().unwrap();
    assert_eq!(carried_on(&lp, 1, &x), Vec::new(), "past the inbox lifetime: no offer held");
    assert_eq!(lp.peers[1].engine.role_on(&x), Some(Role::Read), "Bob reads X by its grants");
}

/// Hands peer `to` the role-class parts on `x` of peer `from`'s commits `ids`, as a copy of each
/// reaches a node that does not sync `x`.
fn carry_roles(lp: &mut LocalPeer, from: usize, to: usize, ids: &[CommitId], x: Tid) {
    for id in ids {
        let h = lp.peers[from].engine.header(id).unwrap();
        let parts: std::collections::BTreeSet<usize> = h.aspects.iter().enumerate().filter(|(_, a)| a.tid == x && ct::ROLE_CLASS.contains(&a.ak.as_str())).map(|(i, _)| i).collect();
        if parts.is_empty() {
            continue;
        }
        let pk = lp.peers[from].engine.package_of_parts(id, &parts).unwrap().unwrap();
        lp.deliver(to, &pk).unwrap();
    }
}

// spec/sync-set.md §2 Own things (the node's role is by the thing's grants as the node holds
// them): Alice makes Carol admin of X and grants Bob read. Alice removes Carol; before Carol
// hears of it she removes Bob, and her removal reaches Bob first: his edge has ended. Then
// Alice's removal of Carol reaches him: Carol's removal is judged invalid, Bob's grant stands
// again and he reads X by it, with no new fire from anyone.
#[test]
fn a_grant_standing_again_by_an_invalid_removal_gives_its_role_again_spec_sync_set_2() {
    let (mut lp, ps) = people(3);
    let x = crate::flows::thing_of(&mut lp, 0, ps[0]);
    lp.peers[0].engine.grant(&x, &ps[2], &edge_of(Role::Admin)).unwrap();
    crate::flows::spread(&mut lp);
    lp.peers[0].engine.grant(&x, &ps[1], &edge_of(Role::Read)).unwrap();
    crate::flows::spread(&mut lp);
    assert_eq!(lp.peers[1].engine.role_on(&x), Some(Role::Read), "Bob reads X");
    let carol_out = lp.peers[0].engine.demote(&x, &osis_engine::flows::Demotion { holder: ps[2], new: None, retain: Some(false) }).unwrap().commits;
    lp.advance(1_000);
    let removal = lp.peers[2].engine.demote(&x, &osis_engine::flows::Demotion { holder: ps[1], new: None, retain: Some(false) }).unwrap().commits;
    lp.sync(2, 1).unwrap();
    carry_roles(&mut lp, 2, 1, &removal, x);
    assert_eq!(lp.peers[1].engine.role_on(&x), None, "Carol's removal applies at Bob");
    carry_roles(&mut lp, 0, 1, &carol_out, x);
    assert!(lp.peers[1].engine.roster(&x).contains_key(&ps[1]), "Carol's removal is invalid: Bob's grant stands");
    assert_eq!(lp.peers[1].engine.role_on(&x), Some(Role::Read), "Bob reads X again");
}

/// Alice grants Bob read on X and removes him, erasing, and Bob lets X go: the world, Bob's
/// account, X and the grant's sealed fire.
fn an_ended_grant() -> (LocalPeer, Tid, osis_engine::sync::SealedFireOut) {
    let (mut lp, ps) = people(2);
    let x = crate::flows::thing_of(&mut lp, 0, ps[0]);
    crate::flows::spread(&mut lp);
    let owed = lp.peers[0].engine.fires_owed();
    lp.peers[0].engine.grant(&x, &ps[1], &edge_of(Role::Read)).unwrap();
    let grant = new_fire(&mut lp, 0, &owed);
    crate::flows::spread(&mut lp);
    assert_eq!(lp.peers[1].engine.role_on(&x), Some(Role::Read), "Bob reads X");
    lp.advance(1_000);
    lp.peers[0].engine.demote(&x, &osis_engine::flows::Demotion { holder: ps[1], new: None, retain: Some(false) }).unwrap();
    crate::flows::spread(&mut lp);
    assert_eq!(lp.peers[1].engine.role_on(&x), None, "removed");
    lp.peers[1].engine.unhold(osis_base::Strong(x)).unwrap();
    lp.peers[1].engine.released(&[x].into()).unwrap();
    (lp, x, grant)
}

// spec/sync-inbox.md §5 Grant from outside (a removal from outside goes as a grant does, kept
// as long): an old offer never reinstates a grant its edge's later write ended. Bob let X go
// and his node syncs nothing of it, but holds the removal as it holds any offer, and the
// removal is the later write: the grant's sealed fire offered again within the inbox lifetime (a
// store's stale copy, or anyone who kept it) is judged against it and gives Bob nothing.
#[test]
fn a_replayed_offer_of_an_ended_grant_gives_no_role_spec_sync_inbox_5() {
    let (mut lp, x, grant) = an_ended_grant();
    lp.advance(3_600_000);
    lp.peers[1].tick().unwrap();
    lp.peers[1].engine.settle_needs().unwrap();
    let _ = open(&mut lp, 1, &grant);
    lp.peers[1].engine.settle_needs().unwrap();
    assert_eq!(lp.peers[1].engine.role_on(&x), None, "the ended grant gives Bob nothing");
}

// spec/sync-inbox.md §5 Grant from outside (kept as H's setting keeps the signal: a fire past
// its keep is no offer): past the inbox lifetime Bob's node holds nothing of X, and the grant's
// sealed fire offered again is past its keep too: never taken.
#[test]
fn an_offer_past_its_keep_is_never_taken_spec_sync_inbox_5() {
    let (mut lp, x, grant) = an_ended_grant();
    lp.advance(osis_base::format::INBOX_LIFETIME_MS + 3_600_000);
    lp.peers[1].tick().unwrap();
    lp.peers[1].engine.settle_needs().unwrap();
    assert_eq!(carried_on(&lp, 1, &x), Vec::new(), "no offer of X is held");
    let _ = open(&mut lp, 1, &grant);
    assert_eq!(carried_on(&lp, 1, &x), Vec::new(), "the late copy is no offer");
    assert!(!lp.peers[1].engine.roster(&x).contains_key(&lp.peers[1].engine.me()), "the ended grant is not standing at Bob again");
    assert_eq!(lp.peers[1].engine.role_on(&x), None, "and gives him nothing");
}

// spec/sync-set.md §2 Own things (a grant is its target's own data: a node judges its role on a
// thing by what it syncs): Alice grants Bob read on X. No offer reaches him and he references X
// nowhere, so the grant's commits handed to his node are held as another thing's certificate
// would be: they name him on X's roster and give no role and no secret of X. A strong to X makes
// X his to sync, and the same commits give him read and X's secrets. Fails with a role read
// from every held edge write.
#[test]
fn a_held_grant_counts_only_where_its_thing_is_synced_spec_sync_set_2() {
    let (mut lp, ps) = people(2);
    lp.hold_fires(true);
    let before: std::collections::BTreeSet<CommitId> = lp.peers[0].engine.commit_ids().into_iter().collect();
    let e = &mut lp.peers[0].engine;
    let mut m = Mutation::new();
    let x = e.new_thing(&mut m, ps[0]);
    m.set(x, &REG, &s("x")).unwrap();
    e.commit(m).unwrap().unwrap();
    e.grant(&x, &ps[1], &edge_of(Role::Read)).unwrap();
    let mut new: Vec<CommitId> = e.commit_ids().into_iter().filter(|c| !before.contains(c)).collect();
    new.sort_by_key(|c| e.header(c).unwrap().ts);
    let hand = |lp: &mut LocalPeer| {
        for c in &new {
            let pk = lp.peers[0].engine.package(c).unwrap().unwrap();
            lp.deliver(1, &pk).unwrap();
        }
    };
    hand(&mut lp);
    let held = |lp: &LocalPeer| lp.peers[1].engine.epochs(&x).is_some_and(|e| e.read.held().next().is_some());
    assert!(lp.peers[1].engine.roster(&x).contains_key(&ps[1]), "Bob's node holds the grant");
    assert_eq!(lp.peers[1].engine.role_on(&x), None, "which gives no role on a thing he does not sync");
    assert!(!held(&lp), "and no secret of it");
    lp.hold_at(1, x);
    hand(&mut lp);
    assert_eq!(lp.peers[1].engine.role_on(&x), Some(Role::Read), "synced, X's grants count");
    assert!(held(&lp), "and its boxes open");
    assert_eq!(lp.peers[1].engine.get(&x, &ak("t:reg.0")).unwrap(), Some(s("x")), "Bob reads X");
}

// spec/permissions.md §4 (Delivering an edge piece): Alice grants her node thing read on X: the
// node writes its node thing, whose key part carries the grant, so no fire goes, and the grant is
// X's as any.
#[test]
fn a_grant_to_the_node_thing_fires_nothing_spec_permissions_4() {
    let (mut lp, ps) = crate::flows::accounts(1);
    let x = crate::flows::thing_of(&mut lp, 0, ps[0]);
    let node = lp.peers[0].engine.tid();
    let owed = lp.peers[0].engine.fires_owed();
    lp.peers[0].engine.grant(&x, &node, &edge_of(Role::Read)).unwrap();
    assert_eq!(lp.peers[0].engine.fires_owed(), owed, "its node writes it: no fire");
    assert!(lp.peers[0].engine.roster(&x).contains_key(&node), "granted");
}
