//! External fires (spec/permissions.md §5.2 External fires, spec/commits.md §5 The setting): a fire
//! of an external signal valid by its author's authority is valid whatever the setting; any other
//! only while the thing's current setting enables the signal. Each path from a fire to an effect:
//! a reader's write, the fire's listing and validity, promotion, a sealed fire's ticket and removal
//! notice taken, each in both orders against the setting.

use crate::common::{ak, edge, edge_write, new_shared, s, set_edge, set_setting, test_setting};
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
fn inbox_signal(lp: &mut LocalPeer, i: usize, signal: &str, enabled: bool) {
    let me = lp.peers[i].engine.me();
    let inbox = lp.peers[i].engine.inbox_thing(&me).unwrap();
    let mut x = lp.peers[i].engine.get_typed(&inbox, &ct::RETENTION).unwrap().unwrap();
    let keep = ct::RetentionEntry { history: Some(osis_schema::History::Keep { until: None, after: Some(osis_base::format::INBOX_LIFETIME_MS) }), ..Default::default() };
    if enabled {
        x.rules.insert(ak(signal), keep);
    } else {
        x.rules.remove(&ak(signal));
    }
    set_setting(lp, i, inbox, &x);
}

/// Peer `to` opens sealed fire `out`.
fn open(lp: &mut LocalPeer, to: usize, out: &osis_engine::sync::SealedFireOut) -> Opened {
    lp.peers[to].engine.open_entry(&out.sync_id, &osis_blob::blob_id(&out.blob), &[0; 57], &out.blob, u64::MAX).unwrap()
}

// spec/sync-inbox.md §5 Carried commits; removal notices: Interim (issues/tickets-retired.md); spec/permissions.md §5.2 External fires:
// Alice removes Bob from X; her removal notice reaches Bob's inbox sealed. With `removal@~0`
// disabled there it is refused whole and nothing of it is taken (Bob still reads X by his
// timeline); enabled, the same sealed fire is taken and the removal applies; disabled again,
// the fire turns invalid but what was taken stands.
#[test]
fn a_removal_notice_is_taken_only_while_enabled_spec_sync_inbox_5() {
    let (mut lp, ps) = people(2);
    let x = crate::flows::thing_of(&mut lp, 0, ps[0]);
    lp.peers[0].engine.grant(&x, &ps[1], &edge_of(Role::Read)).unwrap();
    crate::flows::spread(&mut lp);
    inbox_signal(&mut lp, 1, "removal@~0", false);
    let owed = lp.peers[0].engine.fires_owed();
    lp.peers[0].engine.demote(&x, &osis_engine::flows::Demotion { holder: ps[1], new: None, retain: Some(false) }).unwrap();
    let id = *lp.peers[0].engine.fires_owed().iter().find(|f| !owed.contains(f)).expect("a removal notice owed");
    let out = lp.peers[0].engine.sealed_fire(&id).unwrap().expect("sealed");
    assert!(matches!(open(&mut lp, 1, &out), Opened::Bad), "not enabled: refused");
    lp.peers[1].engine.take_carried().unwrap();
    assert_eq!(lp.peers[1].engine.role_on(&x), Some(Role::Read), "nothing taken");
    inbox_signal(&mut lp, 1, "removal@~0", true);
    let Opened::Commit(f, _) = open(&mut lp, 1, &out) else { panic!("enabled: taken") };
    lp.peers[1].engine.take_carried().unwrap();
    assert_eq!(lp.peers[1].engine.role_on(&x), None, "the removal applied");
    inbox_signal(&mut lp, 1, "removal@~0", false);
    let inbox = lp.peers[1].engine.inbox_thing(&ps[1]).unwrap();
    let e = &lp.peers[1].engine;
    let ai = e.header(&f).unwrap().aspects.iter().position(|a| a.tid == inbox).unwrap();
    assert!(!e.judged_valid(&f, &[ai]), "disabled: the notice is invalid");
    lp.peers[1].engine.take_carried().unwrap();
    assert_eq!(lp.peers[1].engine.role_on(&x), None, "what was taken stands");
}

// spec/sync-inbox.md §5; ticket fires: Interim (issues/tickets-retired.md); spec/permissions.md §5.2
// External fires: with `ticket@~0` disabled on Bob's inbox, Alice's ticket fire is refused and
// Bob holds no ticket; enabled, the same fire is taken and Bob holds the ticket.
#[test]
fn a_ticket_is_taken_only_while_enabled_spec_sync_inbox_5() {
    let (mut lp, ps) = people(2);
    let t = crate::flows::thing_of(&mut lp, 0, ps[0]);
    crate::flows::spread(&mut lp);
    inbox_signal(&mut lp, 1, "ticket@~0", false);
    let owed = lp.peers[0].engine.fires_owed();
    lp.peers[0].engine.grant(&t, &ps[1], &edge_of(Role::Read)).unwrap();
    let id = *lp.peers[0].engine.fires_owed().iter().find(|f| !owed.contains(f)).expect("a ticket owed");
    let out = lp.peers[0].engine.sealed_fire(&id).unwrap().expect("sealed");
    assert!(matches!(open(&mut lp, 1, &out), Opened::Bad), "not enabled: refused");
    assert!(lp.peers[1].engine.ticket_for(&t).unwrap().is_none(), "no ticket held");
    inbox_signal(&mut lp, 1, "ticket@~0", true);
    assert!(matches!(open(&mut lp, 1, &out), Opened::Commit(..)), "enabled: taken");
    assert!(lp.peers[1].engine.ticket_for(&t).unwrap().is_some(), "the ticket is held");
}

// spec/sync-inbox.md §5 Carried commits, spec/permissions.md §5.2 External fires: a removal
// notice opened while `removal@~0` is enabled on Bob's inbox, disabled before its carried commit
// is taken: the notice is invalid and out of history, so nothing of it is taken (`take_fire`;
// passes with every external fire valid too, the dropped body alone stopping it).
#[test]
fn a_removal_notice_disabled_before_taken_is_not_taken_spec_sync_inbox_5() {
    let (mut lp, ps) = people(2);
    let x = crate::flows::thing_of(&mut lp, 0, ps[0]);
    lp.peers[0].engine.grant(&x, &ps[1], &edge_of(Role::Read)).unwrap();
    crate::flows::spread(&mut lp);
    let owed = lp.peers[0].engine.fires_owed();
    lp.peers[0].engine.demote(&x, &osis_engine::flows::Demotion { holder: ps[1], new: None, retain: Some(false) }).unwrap();
    let id = *lp.peers[0].engine.fires_owed().iter().find(|f| !owed.contains(f)).expect("a removal notice owed");
    let out = lp.peers[0].engine.sealed_fire(&id).unwrap().expect("sealed");
    assert!(matches!(open(&mut lp, 1, &out), Opened::Commit(..)), "enabled: opened");
    inbox_signal(&mut lp, 1, "removal@~0", false);
    lp.peers[1].engine.take_carried().unwrap();
    assert_eq!(lp.peers[1].engine.role_on(&x), Some(Role::Read), "disabled before taken: nothing taken");
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
