//! External fires (spec/permissions.md §5.2 External fires, spec/commits.md §5 The setting): a fire
//! of an external signal valid by its author's authority is valid whatever the setting; any other
//! only while the thing's current setting enables the signal. Each path from a fire to an effect:
//! a reader's write, the fire's listing and validity, promotion, each in
//! both orders against the setting.

use crate::common::{REG, ak, edge, edge_write, new_shared, s, set_edge, set_setting, test_setting};
use crate::flows::{edge_of, people, send_carried};
use osis_base::{CommitId, Role, Tid};
use osis_crdt::{Op, PathOp};
use osis_engine::Mutation;
use osis_engine::local_peer::LocalPeer;
use osis_engine::sync::Promote;
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
    let p1 = lp.peers[1].engine.tid();
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
    let p2 = lp.peers[2].engine.tid();
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

// spec/sync-set.md §2 Own things, First entry, The local part's log (a grant is its target's own
// data: a node judges its role on a thing by what it syncs, and enters it only by a route that
// gives it the thing's role entries): Alice grants Bob read on X, its signal held back. The
// grant's commits handed to his node are held as another thing's certificate would be: they name
// him on X's roster and give no role and no secret of X, and a strong to X from his node root
// changes nothing (being handed role commits is no entry). The grant's signal then reaches him:
// he follows X, and the same commits give him read, X's secrets and X. Fails with a role read
// from every held edge write (or the local part judged from them).
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
    assert_eq!(lp.peers[1].engine.role_on(&x), None, "a strong alone: still no role");
    assert!(!held(&lp), "nor a secret");
    assert_eq!(lp.peers[1].engine.get(&x, &ak("t:reg.0")).unwrap(), None, "nor X");
    lp.hold_fires(false);
    lp.pass_fires(1).unwrap();
    hand(&mut lp);
    assert_eq!(lp.peers[1].engine.role_on(&x), Some(Role::Read), "signalled, X's grants count");
    assert!(held(&lp), "and its boxes open");
    assert_eq!(lp.peers[1].engine.get(&x, &ak("t:reg.0")).unwrap(), Some(s("x")), "Bob reads X");
}
