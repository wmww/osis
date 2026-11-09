//! Features with no server, relay or internet (issues/no-server-audit.md, `row N`): nodes that
//! only sometimes reach each other. Each `repro_` asserts what users should observe and is
//! ignored until the job named in its `#[ignore]` fixes the row (renamed and un-ignored there).
//! Model time only: timeouts are the audit's, on `World`'s clock.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use osis::internals::Internals as _;
use osis::{Ak, CommitQuery, DynamicAspectKey, GrantOpts, LinkOpts, MemStore, Osis, Role, Scope, Store, SyncScope, SyncState, Tid, Value};
use osis_sim::ClockSpec;
use osis_sim::reach::{PORT, Route, Uplink};
use osis_sim::world::World;
use osis_transport::nat::Nat;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::task::{Context, Poll, Waker};

const AK: &str = "s:peer.0";
/// Past every retry: the audit's 100 s.
const LONG_MS: u64 = 100_000;
const STEP_MS: u64 = 5_000;
const STEPS: usize = (LONG_MS / STEP_MS) as usize;

fn key() -> DynamicAspectKey {
    DynamicAspectKey::untyped(Ak::new(AK).unwrap())
}

fn say(db: &Osis, t: Tid, v: &str) {
    let mut w = db.write();
    w.at(t, key()).set(&Value::Str(v.into())).unwrap();
    w.commit().unwrap();
}

fn heard(db: &Osis, t: Tid) -> Option<String> {
    match db.at(t, key()).get().ok().flatten() {
        Some(Value::Str(s)) => Some(s),
        _ => None,
    }
}

/// A new synced group of `db`.
fn group(db: &Osis) -> Tid {
    let mut w = db.write();
    let g = w.create().unwrap();
    w.commit().unwrap();
    db.sync(g, &[]).unwrap();
    g
}

fn direct() -> LinkOpts {
    LinkOpts { direct: true, ..Default::default() }
}

/// Two accounts, public addresses and a relay; Bob joined Alice's group `g` by a direct link.
fn co_readers(seed: u64, role: Role) -> (World, Osis, Osis, Tid) {
    let mut w = World::new();
    let r = w.reach.add_relay(None);
    let a = w.account(seed, &[]);
    let b = w.account(seed + 1, &[]);
    w.place(&a, &[], Uplink::Public, &[r]);
    w.place(&b, &[], Uplink::Public, &[r]);
    w.run();
    let g = join(&mut w, &a, &b, role);
    (w, a, b, g)
}

/// `to` joins a new group of `from` by a direct link.
fn join(w: &mut World, from: &Osis, to: &Osis, role: Role) -> Tid {
    let g = group(from);
    say(from, g, "first");
    w.run();
    let link = from.make_link(g, role, direct()).unwrap();
    w.run();
    assert_eq!(w.until(to.redeem(&link), 1000, 40).unwrap(), g);
    w.run();
    g
}

/// Each node of `lan` announces itself to every node on its segments.
fn announce(w: &mut World, lan: &[&Osis]) {
    for n in lan {
        w.lan_announce(n, |_| true);
    }
}

/// Polls `f` over `STEPS` steps of model time, each node of `lan` announcing at every step.
fn over_lan<F: Future>(w: &mut World, lan: &[&Osis], f: F) -> Option<F::Output> {
    let mut f = std::pin::pin!(f);
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..STEPS {
        announce(w, lan);
        w.run();
        if let Poll::Ready(v) = f.as_mut().poll(&mut cx) {
            return Some(v);
        }
        w.advance(STEP_MS);
    }
    None
}

/// Time past the peers' retry pause.
fn pause_ms() -> u64 {
    osis_node::sync::SyncConfig::default().peer_retry_ms + 1_000
}

/// A second node of `a`'s account, paired by text alone.
fn pair(w: &World, a: &Osis, seed: u64) -> Osis {
    let mut c = w.cfg(seed, &[]);
    c.store = Store::Memory(MemStore::new());
    let join = osis::internals::pair(c, &a.pair_offer().unwrap()).unwrap();
    let (_, reply) = a.pair_accept(join.request()).unwrap();
    join.finish(&reply).unwrap()
}

// Row 5, spec/permissions.md §7: a link can be made on any node, saved peers or runtime or not.
#[test]
#[ignore = "issues/net-first-contact.md"]
fn repro_row5_a_link_needs_no_saved_peer() {
    let mut w = World::new();
    let a = w.account(1, &[]);
    let g = group(&a);
    a.make_link(g, Role::Read, LinkOpts::default()).unwrap();
    let none = osis::internals::create(osis::internals::Opening::at(Store::Memory(MemStore::new()))).unwrap();
    let g = group(&none);
    none.make_link(g, Role::Read, LinkOpts::default()).unwrap();
}

// Row 6, spec/sync.md §10: two strangers on one LAN, no uplink: a link
// finds its sharer within the audit's 40 s.
#[test]
#[ignore = "issues/net-first-contact.md"]
fn repro_row6_redeem_a_direct_link_on_a_lan() {
    let mut w = World::new();
    let a = w.account(1, &[]);
    let b = w.account(2, &[]);
    w.place(&a, &[1], Uplink::None, &[]);
    w.place(&b, &[1], Uplink::None, &[]);
    w.run();
    let g = group(&a);
    say(&a, g, "first");
    let link = a.make_link(g, Role::Read, direct()).unwrap();
    w.run();
    let got = over_lan(&mut w, &[&a, &b], b.redeem(&link));
    assert!(matches!(got, Some(Ok(t)) if t == g), "{got:?}");
    assert_eq!(heard(&b, g).as_deref(), Some("first"));
}

// Row 8, spec/permissions.md §7: a contact card and profile with no saved peer.
#[test]
#[ignore = "issues/net-first-contact.md"]
fn repro_row8_a_contact_card_needs_no_saved_peer() {
    let mut w = World::new();
    let a = w.account(1, &[]);
    a.contact_card().unwrap();
    a.profile().unwrap();
}

// Row 9, spec/sync.md §3: a grant to an account this node shares a group with reaches it, with
// nodes only: Bob holds the role within 100 s.
#[test]
#[ignore = "issues/net-first-contact.md"]
fn repro_row9_a_grant_reaches_a_known_account() {
    let (mut w, a, b, _) = co_readers(1, Role::Read);
    let mut wr = a.write();
    let t = wr.create().unwrap();
    wr.commit().unwrap();
    say(&a, t, "for bob");
    a.grant(t, b.me(), Role::Read, GrantOpts::default()).unwrap();
    w.advance(LONG_MS);
    assert_eq!(b.role_on(t).unwrap(), Some(Role::Read), "the grant arrived");
    assert_eq!(heard(&b, t).as_deref(), Some("for bob"));
}

// Row 9, spec/sync.md §3: a grant with no way to arrive is not reported delivered: with Bob unreachable the wait
// does not end `Ok`.
#[test]
fn an_undelivered_grant_keeps_the_wait_open_row_9_spec_sync_3() {
    let (mut w, a, b, _) = co_readers(1, Role::Read);
    w.set_peer_reachable(&a, &b, false);
    w.run();
    let mut wr = a.write();
    let t = wr.create().unwrap();
    wr.commit().unwrap();
    a.grant(t, b.me(), Role::Read, GrantOpts::default()).unwrap();
    let got = w.try_until(a.wait_synced(SyncScope::All), STEP_MS, STEPS);
    assert!(got.is_none(), "reported done with the grant undelivered: {got:?}");
    assert_eq!(a.sync_engine(|s| s.deliveries_pending()), 1, "still pending, not marked sent");
}

// spec: none (API surface), notes/api.md Sync configuration and status: `Deliveries` waits only for
// this node's own deliveries: done with nothing pending though a group has nobody connected, open
// while a grant has no way to arrive.
#[test]
fn deliveries_wait_only_for_deliveries() {
    let (mut w, a, b, _) = co_readers(1, Role::Read);
    let _lonely = group(&a);
    w.run();
    assert_eq!(w.until(a.wait_synced(SyncScope::Deliveries), STEP_MS, STEPS), Ok(()), "a group with nobody connected is not a delivery");
    w.set_peer_reachable(&a, &b, false);
    w.run();
    let mut wr = a.write();
    let t = wr.create().unwrap();
    wr.commit().unwrap();
    a.grant(t, b.me(), Role::Read, GrantOpts::default()).unwrap();
    assert!(w.try_until(a.wait_synced(SyncScope::Deliveries), STEP_MS, STEPS).is_none(), "the grant is undelivered");
}

// Row 10, spec/permissions.md §7: nothing Alice does to her key cuts off a connected joiner: a
// grant, a second direct link, ending it, rotating by hand. Her writes still reach Bob.
#[test]
fn key_changes_keep_a_connected_joiner_row_10_spec_permissions_7() {
    let (mut w, a, b, g) = co_readers(1, Role::Read);
    let check = |w: &mut World, what: &str| {
        w.advance(LONG_MS);
        say(&a, g, what);
        w.advance(LONG_MS);
        assert_eq!(heard(&b, g).as_deref(), Some(what));
    };
    a.grant(g, b.me(), Role::Write, GrantOpts::default()).unwrap();
    check(&mut w, "after a grant");
    let first: Vec<_> = a.links().unwrap().into_iter().map(|l| l.id).collect();
    a.make_link(g, Role::Read, direct()).unwrap();
    check(&mut w, "after a second link");
    let id = a.links().unwrap().into_iter().map(|l| l.id).find(|i| !first.contains(i)).unwrap();
    a.revoke_link(id).unwrap();
    check(&mut w, "after ending it");
    a.rotate_peer_address().unwrap();
    check(&mut w, "after rotating");
}

// Row 10, spec/permissions.md §7: a key change while a joiner is away does not strand it: Bob,
// who can only dial (behind a NAT), reaches Alice again when he is back.
#[test]
#[ignore = "issues/net-connect.md"]
fn repro_row10_a_key_change_while_away_does_not_strand_a_joiner() {
    let mut w = World::new();
    let r = w.reach.add_relay(None);
    let cone = w.reach.add_nat(Nat::CONE);
    let a = w.account(1, &[]);
    let b = w.account(2, &[]);
    w.place(&a, &[], Uplink::Public, &[r]);
    w.place(&b, &[], Uplink::Nat(cone), &[]);
    w.run();
    let g = join(&mut w, &a, &b, Role::Read);
    let first: Vec<_> = a.links().unwrap().into_iter().map(|l| l.id).collect();
    a.make_link(g, Role::Read, direct()).unwrap();
    w.run();
    let id = a.links().unwrap().into_iter().map(|l| l.id).find(|i| !first.contains(i)).unwrap();
    w.set_online(&b, false);
    a.revoke_link(id).unwrap();
    w.run();
    w.set_online(&b, true);
    say(&a, g, "while away");
    w.advance(LONG_MS);
    assert_eq!(heard(&b, g).as_deref(), Some("while away"));
}

// Row 15 (spec: none, notes/api.md Sync configuration and status): a write nobody received: `wait_synced` waits, it does not end `Ok`.
#[test]
fn a_wait_with_nobody_connected_waits_row_15_spec_none() {
    let mut w = World::new();
    let a = w.account(1, &[]);
    let g = group(&a);
    say(&a, g, "nobody got this");
    let got = w.try_until(a.wait_synced(SyncScope::All), STEP_MS, STEPS);
    assert!(got.is_none(), "ended with nobody connected: {got:?}");
}

// Row 16 (spec: none, notes/api.md Sync configuration and status): waiting on a thing caught up with a connected peer ends `Ok`.
#[test]
fn a_thing_wait_ends_when_caught_up_with_a_peer_row_16_spec_none() {
    let (mut w, a, b, g) = co_readers(1, Role::Write);
    say(&a, g, "x");
    w.advance(pause_ms());
    assert_eq!(heard(&b, g).as_deref(), Some("x"));
    let got = w.try_until(a.wait_synced(SyncScope::Thing(g)), 1000, 20);
    assert!(matches!(got, Some(Ok(()))), "{got:?}");
}

// Row 17 (spec: none, notes/api.md Sync configuration and status): caught up with every connected peer reads `Synced`, not "connected, nothing said".
#[test]
fn status_says_synced_when_caught_up_with_a_peer_row_17_spec_none() {
    let (mut w, a, b, g) = co_readers(1, Role::Write);
    say(&a, g, "x");
    w.advance(pause_ms());
    assert_eq!(heard(&b, g).as_deref(), Some("x"));
    let state = a.status().unwrap().groups[&g].state;
    assert_eq!(state, SyncState::Synced);
}

// Row 18 (spec: none, notes/api.md Sync configuration and status): while connected with a peer that still holds more, history is not `complete`.
#[test]
fn history_is_not_complete_while_a_peer_holds_more_row_18_spec_none() {
    let (mut w, a, b, g) = co_readers(1, Role::Write);
    w.set_peer_reachable(&a, &b, false);
    w.run();
    say(&a, g, "while apart");
    w.set_peer_reachable(&a, &b, true);
    w.tick(pause_ms());
    let mut judged = 0;
    while w.step(None) {
        if b.status().unwrap().connected > 0 && heard(&b, g).as_deref() != Some("while apart") {
            judged += 1;
            assert!(!b.writes(&Scope::Group(g), &CommitQuery::default()).unwrap().complete, "complete with a peer holding more");
        }
    }
    assert!(judged > 0, "the connection was never up before the write arrived");
    assert_eq!(heard(&b, g).as_deref(), Some("while apart"));
}

/// Polls `f` for `steps` steps of model time; `f` stays alive after a pending result.
fn poll_for<F: Future + Unpin>(w: &mut World, f: &mut F, steps: usize) -> Option<F::Output> {
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..steps {
        w.run();
        if let Poll::Ready(v) = std::pin::Pin::new(&mut *f).poll(&mut cx) {
            return Some(v);
        }
        w.advance(STEP_MS);
    }
    None
}

fn state(db: &Osis, g: Tid) -> SyncState {
    db.status().unwrap().groups[&g].state
}

/// Bob behind a NAT, no relay: Alice cannot dial him, he dials her.
fn served_only(seed: u64, role: Role) -> (World, Osis, Osis, Tid) {
    let mut w = World::new();
    let r = w.reach.add_relay(None);
    let cone = w.reach.add_nat(Nat::CONE);
    let a = w.account(seed, &[]);
    let b = w.account(seed + 1, &[]);
    w.place(&a, &[], Uplink::Public, &[r]);
    w.place(&b, &[], Uplink::Nat(cone), &[]);
    w.run();
    let g = join(&mut w, &a, &b, role);
    w.advance(pause_ms());
    (w, a, b, g)
}

// spec: none (API surface), notes/api.md Sync configuration and status: a connection only Bob
// dialed is judged by his pass: `Synced` for him, `Syncing` at Alice, who runs no pass on it.
#[test]
fn a_served_only_connection_is_synced_at_the_dialer_and_syncing_at_the_served_side() {
    let (mut w, a, b, g) = served_only(10, Role::Write);
    say(&a, g, "x");
    w.advance(pause_ms());
    assert_eq!(heard(&b, g).as_deref(), Some("x"));
    assert_eq!(state(&b, g), SyncState::Synced);
    assert_eq!(state(&a, g), SyncState::Syncing);
}

// spec: none (API surface), notes/api.md Sync configuration and status: a node connected only to a peer that cannot read
// is judged by its own pass there, as at any source.
#[test]
fn a_peer_that_cannot_read_is_a_source() {
    let mut w = World::new();
    let h = w.add_host();
    let a = w.account(20, &[h]);
    w.run();
    let g = a.me();
    say(&a, g, "x");
    w.run();
    assert_eq!(state(&a, g), SyncState::Synced);
    w.until(a.wait_synced(SyncScope::Thing(g)), STEP_MS, STEPS).unwrap();
}

// spec: none (API surface), notes/api.md Sync configuration and status: the wait follows the sources as they change.
#[test]
fn a_wait_follows_sources_that_come_and_go() {
    let (mut w, a, b, g) = co_readers(30, Role::Write);
    w.set_peer_reachable(&a, &b, false);
    w.advance(pause_ms());
    assert_eq!(state(&a, g), SyncState::NotConnected);
    let mut wait = Box::pin(a.wait_synced(SyncScope::Thing(g)));
    assert!(poll_for(&mut w, &mut wait, 4).is_none(), "nobody connected: waits");
    w.set_peer_reachable(&a, &b, true);
    assert!(matches!(poll_for(&mut w, &mut wait, STEPS), Some(Ok(()))), "the source came back");
}

// spec: none (API surface), notes/api.md Sync configuration and status: a source that went mid-pass does not count as
// caught up: nothing is reported until the write reached one.
#[test]
fn a_source_disconnecting_mid_pass_is_not_caught_up() {
    let (mut w, a, b, g) = co_readers(40, Role::Write);
    w.advance(pause_ms());
    say(&a, g, "x");
    w.set_peer_reachable(&a, &b, false);
    w.run();
    assert_eq!(state(&a, g), SyncState::NotConnected);
    assert!(w.try_until(a.wait_synced(SyncScope::Thing(g)), STEP_MS, 4).is_none());
    assert_eq!(heard(&b, g), Some("first".to_owned()));
}

// spec: none (API surface), notes/api.md Sync configuration and status: a write after `Synced` leaves the state until passed
// on, and `Synced` comes back; `last_sync` says when it last was, and stands without a source.
#[test]
fn a_local_write_leaves_synced_and_last_sync_says_when() {
    let (mut w, a, b, g) = co_readers(50, Role::Write);
    say(&a, g, "first of mine");
    w.advance(pause_ms());
    assert_eq!(state(&a, g), SyncState::Synced);
    let before = a.status().unwrap().groups[&g].last_sync;
    assert!(before.is_some());
    say(&a, g, "again");
    assert_eq!(state(&a, g), SyncState::Syncing, "not passed on yet");
    w.advance(pause_ms());
    assert_eq!(heard(&b, g).as_deref(), Some("again"));
    assert_eq!(state(&a, g), SyncState::Synced);
    w.set_peer_reachable(&a, &b, false);
    w.advance(pause_ms());
    let st = a.status().unwrap().groups[&g].clone();
    assert_eq!(st.state, SyncState::NotConnected);
    assert!(st.last_sync >= before, "still names the last time: {st:?}");
}

// spec: none (API surface), notes/api.md Sync configuration and status: `leaving` stays until a source has the removal.
// Bob's removal reaches Alice by her own pull; she rotates, so his upload answers code 9 and his reopens code 1:
// `leaving` never clears though she holds the removal (issues/leaving-not-confirmed-after-rotation.md).
#[test]
#[ignore = "issues/leaving-not-confirmed-after-rotation.md"]
fn repro_leaving_stays_until_a_source_has_the_removal() {
    let (mut w, a, b, g) = co_readers(60, Role::Write);
    w.set_peer_reachable(&a, &b, false);
    w.advance(pause_ms());
    b.leave(b.me(), g).unwrap();
    w.advance(pause_ms());
    assert!(b.status().unwrap().groups.get(&g).is_some_and(|s| s.leaving), "nobody has the removal");
    w.set_peer_reachable(&a, &b, true);
    w.advance(LONG_MS);
    assert!(b.status().unwrap().groups.get(&g).is_none_or(|s| !s.leaving), "the removal is held");
}

// spec: none (API surface), notes/api.md Sync configuration and status: a dropped wait leaves nothing behind.
#[test]
fn a_dropped_wait_leaves_nothing() {
    let (mut w, a, _b, g) = co_readers(70, Role::Write);
    say(&a, g, "x");
    {
        let mut wait = Box::pin(a.wait_synced(SyncScope::All));
        assert!(poll_for(&mut w, &mut wait, 2).is_none());
        assert_eq!(a.waiting(), 1);
    }
    w.run();
    w.advance(STEP_MS);
    assert_eq!(a.waiting(), 0);
}

// spec: none (API surface), notes/api.md Commits: `complete` is false before this node first finished a pass of a sync ID it
// did not make, true for one it made, and true offline afterwards.
#[test]
fn history_complete_needs_a_first_pass_and_stands_offline() {
    let (mut w, a, _b, g) = co_readers(80, Role::Write);
    let own = a.writes(&Scope::Group(g), &CommitQuery::default()).unwrap();
    assert!(own.complete, "a sync ID it made");
    let a2 = pair(&w, &a, 90);
    assert!(!a2.writes(&Scope::Group(a.me()), &CommitQuery::default()).unwrap().complete, "no pass yet");
    w.set_online(&a, false);
    w.advance(pause_ms());
    assert!(a.writes(&Scope::Group(g), &CommitQuery::default()).unwrap().complete, "offline: no gap known");
}

// spec: none (API surface), notes/api.md Sync configuration and status: a group is the worst of its sync IDs, and was last
// synced no later than the most behind.
#[test]
fn a_group_is_the_worst_of_its_sync_ids() {
    let g = Tid::from_bytes([1; 15]);
    let label = |sources: usize, idle: usize, last_sync: Option<u64>| osis_node::sync::LabelStatus { group: g, label: osis_schema::osis_base::LabelId([sources as u8; 16]), hosts: 0, sources, idle, opening: 0, stranded: false, refused_by: Vec::new(), leaving: false, last_sync, passed: true, replaced: false };
    let groups = osis::internals::groups_of_labels(&[label(1, 1, Some(30)), label(0, 0, None)]);
    assert_eq!((groups[&g].state, groups[&g].last_sync), (SyncState::NotConnected, None));
    let groups = osis::internals::groups_of_labels(&[label(1, 1, Some(30)), label(2, 1, Some(20))]);
    assert_eq!((groups[&g].state, groups[&g].last_sync), (SyncState::Syncing, Some(osis::Time(20))));
    // a replaced label with no peer beside a live one does not count
    let gone = osis_node::sync::LabelStatus { replaced: true, ..label(0, 0, None) };
    let groups = osis::internals::groups_of_labels(&[gone.clone(), label(1, 1, Some(30))]);
    assert_eq!((groups[&g].state, groups[&g].last_sync), (SyncState::Synced, Some(osis::Time(30))));
    assert_eq!(osis::internals::groups_of_labels(&[gone])[&g].state, SyncState::NotConnected, "the only one still counts");
}

/// Steps the world after a reconnect; at each step while `holder`, connected on `g`, holds `text`
/// that `db` lacks, `db` must not read `Synced`. Returns how many steps were judged.
fn never_synced_while_lacking(w: &mut World, db: &Osis, holder: &Osis, g: Tid, text: &str) -> usize {
    let mut judged = 0;
    w.tick(pause_ms());
    while w.step(None) {
        let connected = matches!(state(holder, g), SyncState::Synced | SyncState::Syncing);
        if connected && heard(db, g).as_deref() != Some(text) {
            judged += 1;
            assert_ne!(state(db, g), SyncState::Synced, "Synced while a connected source holds {text:?}");
        }
    }
    judged
}

// spec: none (API surface), notes/api.md Sync configuration and status: `Synced` is never true while a connected
// co-reader, dialed both ways, holds a write this node lacks, whichever of the two wrote while apart.
#[test]
fn synced_is_never_true_while_a_connected_co_reader_holds_more() {
    let mut judged = 0;
    for seed in 0..6 {
        let (mut w, a, b, g) = co_readers(100 + 10 * seed, Role::Write);
        w.advance(pause_ms());
        w.set_peer_reachable(&a, &b, false);
        w.advance(pause_ms());
        say(&b, g, "while apart");
        w.set_peer_reachable(&a, &b, true);
        judged += never_synced_while_lacking(&mut w, &a, &b, g, "while apart");
        w.advance(LONG_MS);
        assert_eq!(heard(&a, g).as_deref(), Some("while apart"));
        assert_eq!(state(&a, g), SyncState::Synced, "and it does end Synced");
    }
    assert!(judged > 0, "no step had the connection up before the write arrived");
}

// spec: none (API surface), notes/api.md Sync configuration and status: a served session counts
// as its own source unless it is a node this node dialed: Carol, reachable only by dialing Alice,
// is not paired with Bob, so Alice never reads `Synced` while Carol holds more.
#[test]
fn synced_is_never_true_while_a_served_only_source_holds_more() {
    let (mut w, a, b, g) = co_readers(200, Role::Write);
    let cone = w.reach.add_nat(Nat::CONE);
    let c = w.account(202, &[]);
    w.place(&c, &[], Uplink::Nat(cone), &[]);
    w.run();
    let link = a.make_link(g, Role::Write, direct()).unwrap();
    w.run();
    assert_eq!(w.until(c.redeem(&link), 1000, 40).unwrap(), g);
    w.advance(pause_ms());
    // Carol reaches Alice only by her own dial: no path through Bob
    w.set_peer_reachable(&b, &c, false);
    w.set_peer_reachable(&a, &c, false);
    w.advance(pause_ms());
    say(&c, g, "from carol");
    w.set_peer_reachable(&a, &c, true);
    let judged = never_synced_while_lacking(&mut w, &a, &c, g, "from carol");
    assert!(judged > 0, "no step had the connection up before the write arrived");
}

// spec: none (API surface), notes/api.md Sync configuration and status: a co-reader dialed both
// ways is one source: its session names it, so Alice ends `Synced`, not `Syncing` on a session
// taken for another node.
#[test]
fn a_co_reader_dialed_both_ways_is_one_source_and_ends_synced() {
    let (mut w, a, b, g) = co_readers(210, Role::Write);
    w.advance(pause_ms());
    assert_eq!(a.status().unwrap().connected, 2, "one connection each way");
    assert_eq!(state(&a, g), SyncState::Synced);
    assert_eq!(state(&b, g), SyncState::Synced);
}

// spec: none (API surface), notes/api.md Sync configuration and status: `Thing(t)` waits on what
// `t` itself travels under: group g, caught up with Bob, resolves though it lists under a home
// group no other node is connected on; a thing inside g resolves on g.
#[test]
fn a_thing_wait_leaves_out_a_lonely_home() {
    let (mut w, a, _b, g) = co_readers(220, Role::Write);
    let mut wr = a.write();
    let t = wr.create().unwrap();
    wr.commit().unwrap();
    let home = group(&a);
    let mut wr = a.write();
    wr.group(home).add(osis::Member::Subgroup(g)).unwrap();
    wr.group(g).add(osis::Member::Item(t)).unwrap();
    wr.commit().unwrap();
    w.advance(pause_ms());
    assert_eq!(state(&a, home), SyncState::NotConnected, "the premise: nobody else on home");
    w.until(a.wait_synced(SyncScope::Thing(g)), STEP_MS, STEPS).unwrap();
    w.until(a.wait_synced(SyncScope::Thing(t)), STEP_MS, STEPS).unwrap();
}

// spec: none (API surface), notes/api.md Sync configuration and status: a sync ID with no source promises nothing, so
// `Thing(t)` does not hang on a lonely group listing `t` when a group further up has a source.
#[test]
fn a_thing_wait_leaves_out_a_lonely_group_when_another_has_a_source() {
    let (mut w, a, _b, parent) = co_readers(240, Role::Write);
    let near = group(&a);
    let mut wr = a.write();
    let t = wr.create().unwrap();
    wr.commit().unwrap();
    let mut wr = a.write();
    wr.group(near).add(osis::Member::Item(t)).unwrap();
    wr.group(parent).add(osis::Member::Subgroup(near)).unwrap();
    wr.commit().unwrap();
    w.advance(pause_ms());
    assert_eq!(state(&a, near), SyncState::NotConnected, "the premise: nobody on the nearest group");
    w.until(a.wait_synced(SyncScope::Thing(t)), STEP_MS, STEPS).unwrap();
}

// spec: none (API surface), notes/api.md Sync configuration and status: `Thing(t)` covers every sync ID carrying `t` with a
// source: Bob's connection on the group further up is not caught up, so the wait holds though the nearest
// group is caught up with Carol.
#[test]
fn a_thing_wait_covers_a_source_further_up() {
    let (mut w, a, _b, parent) = served_only(250, Role::Write);
    let c = w.account(252, &[]);
    w.place(&c, &[], Uplink::Public, &[]);
    w.run();
    let near = join(&mut w, &a, &c, Role::Write);
    let mut wr = a.write();
    let t = wr.create().unwrap();
    wr.commit().unwrap();
    let mut wr = a.write();
    wr.group(near).add(osis::Member::Item(t)).unwrap();
    wr.group(parent).add(osis::Member::Subgroup(near)).unwrap();
    wr.commit().unwrap();
    w.advance(pause_ms());
    w.until(a.wait_synced(SyncScope::Thing(near)), STEP_MS, STEPS).unwrap();
    assert_eq!(state(&a, parent), SyncState::Syncing, "the premise: a source further up not caught up");
    assert!(w.try_until(a.wait_synced(SyncScope::Thing(t)), STEP_MS, 4).is_none(), "resolved past a source that holds more");
}

// spec/sync.md §2: a grant to a node has no route outside pairing, so a commit stored for it is no delivery: an
// earlier one holds up no later `Deliveries` wait.
#[test]
fn a_grant_to_a_node_holds_up_no_later_delivery_wait() {
    let (mut w, a, _b, g) = co_readers(270, Role::Write);
    let c = pair(&w, &a, 272);
    w.run();
    w.until(a.wait_synced(SyncScope::Deliveries), STEP_MS, STEPS).unwrap();
    a.grant(g, c.node(), Role::Read, Default::default()).unwrap();
    w.until(a.wait_synced(SyncScope::Deliveries), STEP_MS, STEPS).unwrap();
}

// spec: none (API surface), notes/api.md Sync configuration and status: a thing that lost its carrier while this node still
// holds a role on it is not forgotten, so the wait does not end as if it were.
#[test]
fn a_thing_wait_does_not_end_when_only_its_carrier_went() {
    let (mut w, a, _b, g) = served_only(280, Role::Write);
    let mut wr = a.write();
    let t = wr.create().unwrap();
    wr.commit().unwrap();
    let mut wr = a.write();
    wr.group(g).add(osis::Member::Item(t)).unwrap();
    wr.commit().unwrap();
    w.advance(pause_ms());
    assert_eq!(state(&a, g), SyncState::Syncing, "the premise: a source not caught up");
    let mut f = Box::pin(a.wait_synced(SyncScope::Thing(t)));
    assert!(w.try_until(&mut f, STEP_MS, 2).is_none(), "the premise: pending");
    let mut wr = a.write();
    wr.group(g).remove(osis::Member::Item(t)).unwrap();
    wr.commit().unwrap();
    assert!(w.try_until(&mut f, STEP_MS, 4).is_none(), "ended though this node still holds the thing");
}

// spec: none (API surface), notes/api.md Sync configuration and status: a leave waits on what the leaver left, not on an
// unrelated group nobody is connected on, and ends once the node has forgotten it.
#[test]
fn a_leave_wait_ends_when_the_removal_landed_whatever_else_is_lonely() {
    let mut w = World::new();
    let h = w.add_host();
    let (a, b) = (w.account(260, &[h]), w.account(261, &[]));
    w.run();
    let g = group(&a);
    say(&a, g, "first");
    w.run();
    let link = a.make_link(g, Role::Write, LinkOpts::default()).unwrap();
    w.run();
    w.until(b.redeem(&link), 1000, 40).unwrap();
    w.run();
    let lonely = group(&b);
    w.advance(pause_ms());
    assert_eq!(state(&b, lonely), SyncState::NotConnected, "the premise");
    b.leave(b.me(), g).unwrap();
    w.until(b.wait_synced(SyncScope::Thing(g)), STEP_MS, STEPS).unwrap();
    assert!(!b.status().unwrap().groups.contains_key(&g), "forgotten once it landed");
    w.advance(pause_ms());
    assert!(a.holders(g).unwrap().iter().all(|h| h.actor != b.me()), "Alice has the removal");
}

// spec: none (API surface), notes/api.md Sync configuration and status: `last_sync` needs no one to have looked while `Synced`.
#[test]
fn last_sync_stands_though_nobody_asked_while_synced() {
    let (mut w, a, b, g) = co_readers(70, Role::Write);
    w.advance(pause_ms());
    let before = a.status().unwrap().groups[&g].last_sync;
    w.advance(pause_ms());
    say(&a, g, "x");
    w.advance(pause_ms());
    w.set_peer_reachable(&a, &b, false);
    w.advance(pause_ms());
    let st = a.status().unwrap().groups[&g].clone();
    assert_eq!(st.state, SyncState::NotConnected);
    assert!(st.last_sync > before, "{before:?} {st:?}");
}

// Row 21, spec/wire.md §8, §12: a link redeems from a bundle alone, Alice and Bob unable to connect.
#[test]
#[ignore = "issues/net-first-contact.md"]
fn repro_row21_a_link_redeems_from_a_bundle_alone() {
    let mut w = World::new();
    let a = w.account(1, &[]);
    let b = w.account(2, &[]);
    w.place(&a, &[], Uplink::Public, &[]);
    w.place(&b, &[], Uplink::Public, &[]);
    w.run();
    let g = group(&a);
    say(&a, g, "first");
    let link = a.make_link(g, Role::Read, direct()).unwrap();
    w.set_peer_reachable(&a, &b, false);
    w.run();
    let mut bundle = Vec::new();
    a.export_bundle(&[g], &mut bundle).unwrap();
    b.import_bundle(&bundle[..]).unwrap();
    let got = w.try_until(b.redeem(&link), STEP_MS, 8);
    assert!(matches!(got, Some(Ok(t)) if t == g), "{got:?}");
}

// Row 22, spec/sync.md §10: joiners of a link-shared group find each other: with the sharer and
// the relay gone, Bob's write reaches Carol.
#[test]
fn joiners_of_a_link_reach_each_other_row_22_spec_sync_10() {
    let (mut w, a, b, g) = co_readers(1, Role::Write);
    let c = w.account(3, &[]);
    w.place(&c, &[], Uplink::Public, &[0]);
    w.run();
    let link = a.make_link(g, Role::Write, direct()).unwrap();
    w.run();
    assert_eq!(w.until(c.redeem(&link), 1000, 40).unwrap(), g);
    w.advance(pause_ms());
    w.set_online(&a, false);
    w.set_relay_up(0, false);
    say(&b, g, "from bob");
    w.advance(LONG_MS);
    assert_eq!(heard(&c, g).as_deref(), Some("from bob"));
}

// Row 23, spec/sync.md §10: a joiner hears its sharer's LAN announcement.
#[test]
fn a_joiner_finds_its_sharer_on_the_lan_row_23_spec_sync_10() {
    let mut w = World::new();
    let r = w.reach.add_relay(None);
    let sym = w.reach.add_nat(Nat::SYMMETRIC);
    let a = w.account(1, &[]);
    let b = w.account(2, &[]);
    w.place(&a, &[1], Uplink::Nat(sym), &[r]);
    w.place(&b, &[1], Uplink::Nat(sym), &[r]);
    w.run();
    let g = join(&mut w, &a, &b, Role::Write);
    w.set_relay_up(r, false);
    w.run();
    assert_eq!(w.peer_routes(&a), [], "the relay was their only link");
    say(&a, g, "over the lan");
    announce(&mut w, &[&a, &b]);
    w.run();
    announce(&mut w, &[&a, &b]);
    w.advance(pause_ms());
    assert!(w.peer_routes(&b).iter().any(|r| matches!(r, Route::Lan(_))), "{:?}", w.peer_routes(&b));
    assert_eq!(heard(&b, g).as_deref(), Some("over the lan"));
}

/// A and C on separate LANs, B on both as an admin that made C's link: `g` shared by all three.
fn over_a_reader() -> (World, Osis, Osis, Osis, Tid) {
    let mut w = World::new();
    let r1 = w.reach.add_relay(Some(1));
    let r2 = w.reach.add_relay(Some(2));
    let a = w.account(1, &[]);
    let b = w.account(2, &[]);
    let c = w.account(3, &[]);
    w.place(&a, &[1], Uplink::None, &[r1]);
    w.place(&b, &[1, 2], Uplink::None, &[r1, r2]);
    w.place(&c, &[2], Uplink::None, &[r2]);
    w.run();
    let g = join(&mut w, &a, &b, Role::Admin);
    let link = b.make_link(g, Role::Write, direct()).unwrap();
    w.run();
    assert_eq!(w.until(c.redeem(&link), 1000, 40).unwrap(), g);
    w.advance(pause_ms());
    (w, a, b, c, g)
}

// Row 24, spec/sync.md §3: A and C apart with B, a reader, between them: writes cross both ways.
#[test]
fn writes_cross_a_reader_both_ways_row_24_spec_sync_3() {
    let (mut w, a, _b, c, g) = over_a_reader();
    say(&c, g, "c to a");
    w.advance(LONG_MS);
    assert_eq!(heard(&a, g).as_deref(), Some("c to a"));
    say(&a, g, "a to c");
    w.advance(LONG_MS);
    assert_eq!(heard(&c, g).as_deref(), Some("a to c"));
}

// spec/sync.md §3: as above, A writing first: a pass must not find a grant's copy wanted after
// an earlier pass found it all there (`inbox_certificates`' debug assertion).
#[test]
#[ignore = "issues/inbox-copied-stale.md"]
fn repro_a_write_then_a_reply_over_a_reader_keeps_the_inbox_copy_cache_true() {
    let (mut w, a, _b, c, g) = over_a_reader();
    say(&a, g, "a to c");
    w.advance(LONG_MS);
    assert_eq!(heard(&c, g).as_deref(), Some("a to c"));
    say(&c, g, "c to a");
    w.advance(LONG_MS);
    assert_eq!(heard(&a, g).as_deref(), Some("c to a"));
}

// Row 26, spec/sync.md §10: a peer that cannot read can be added to a group already synced.
#[test]
#[ignore = "issues/net-one-peer.md"]
fn repro_row26_a_peer_can_be_added_later() {
    let mut w = World::new();
    let a = w.account(1, &[]);
    let g = group(&a);
    let box_addr: osis::Address = format!("quic://box:1#{}", osis_schema::osis_base::base64url::encode(&[9u8; 32])).parse().unwrap();
    a.sync(g, std::slice::from_ref(&box_addr)).unwrap();
    assert!(a.peers(g).unwrap().contains(&box_addr));
}

// Row 27, spec/sync.md §10: a saved peer named by key is dialed.
#[test]
#[ignore = "issues/net-one-peer.md"]
fn repro_row27_a_saved_peer_named_by_key_is_dialed() {
    let mut w = World::new();
    let a = w.account(1, &[]);
    let b = w.account(2, &[]);
    w.place(&a, &[], Uplink::Public, &[]);
    w.place(&b, &[], Uplink::Public, &[]);
    w.run();
    let reach = b.sync_engine(|s| s.own_reach()).unwrap();
    let url = osis_transport::peer_url(&reach.items);
    let addr: osis::Address = format!("{url}#{}", osis_schema::osis_base::base64url::encode(&reach.dialable)).parse().unwrap();
    let mut wr = a.write();
    let g = wr.create().unwrap();
    wr.commit().unwrap();
    a.sync(g, &[addr]).unwrap();
    w.advance(LONG_MS);
    assert!(!w.peer_routes(&a).is_empty(), "never dialed");
}

// Row 28, spec/sync.md §10: nodes on one LAN connect with nothing shared.
#[test]
#[ignore = "issues/net-connect.md"]
fn repro_row28_lan_nodes_connect_with_nothing_shared() {
    let mut w = World::new();
    let a = w.account(1, &[]);
    let b = w.account(2, &[]);
    w.place(&a, &[1], Uplink::None, &[]);
    w.place(&b, &[1], Uplink::None, &[]);
    w.run();
    over_lan(&mut w, &[&a, &b], std::future::pending::<()>());
    assert!(!w.peer_routes(&a).is_empty(), "no connection");
}

// Row 30, spec/sync.md §10: an announcement counts whatever source address carried it: CGNAT,
// global and mesh sources as a private one does.
#[test]
#[ignore = "issues/net-connect.md"]
fn repro_row30_a_lan_announcement_counts_from_any_source() {
    let (_w, a, b, _) = co_readers(1, Role::Read);
    let key = a.sync_engine(|s| s.own_reach()).unwrap().dialable;
    let an = a.sync_engine(|s| s.lan_announcement([7; 32], PORT)).unwrap();
    let matches = |ip: &str| b.sync_engine(|s| s.lan_seen(&an, SocketAddr::new(ip.parse::<IpAddr>().unwrap(), PORT)).0) == Some(key);
    let dropped: Vec<&str> = ["100.64.0.1", "8.8.8.8", "2001:db8::1", "200::1"].into_iter().filter(|ip| !matches(ip)).collect();
    assert!(matches("10.0.0.1"), "control: a private source matches");
    assert_eq!(dropped, Vec::<&str>::new(), "dropped sources");
}

// Row 34, spec/sync.md §10: nodes whose clocks differ by less than `MAX_DRIFT` still recognise each
// other on the LAN (30 min apart).
#[test]
#[ignore = "issues/net-connect.md"]
fn repro_row34_lan_recognition_tolerates_max_drift() {
    let mut w = World::new();
    let r = w.reach.add_relay(None);
    let sym = w.reach.add_nat(Nat::SYMMETRIC);
    let a = w.account(1, &[]);
    let b = osis::internals::create(w.cfg_clocked(2, &[], ClockSpec { skew_ms: 30 * 60_000, drift_ppm: 0 })).unwrap();
    w.place(&a, &[1], Uplink::Nat(sym), &[r]);
    w.place(&b, &[1], Uplink::Nat(sym), &[r]);
    w.run();
    let g = join(&mut w, &a, &b, Role::Write);
    let apart = b.engine(|e| e.now().0).abs_diff(a.engine(|e| e.now().0));
    assert!(apart >= 25 * 60_000, "the clocks still differ: {apart}");
    w.set_relay_up(r, false);
    w.run();
    say(&a, g, "over the lan");
    announce(&mut w, &[&a, &b]);
    w.run();
    announce(&mut w, &[&a, &b]);
    w.advance(pause_ms());
    assert!(w.peer_routes(&b).iter().any(|r| matches!(r, Route::Lan(_))), "{:?}", w.peer_routes(&b));
}

// Row 35, spec/sync.md §6 (a wrong local clock harms only that node's own writes): Alice's
// clock 120 min slow does not stop Bob redeeming her link.
#[test]
#[ignore = "issues/clock-peer-offset.md"]
fn repro_row35_a_slow_peer_does_not_stop_a_redeem() {
    let mut w = World::new();
    let r = w.reach.add_relay(None);
    let a = osis::internals::create(w.cfg_clocked(1, &[], ClockSpec { skew_ms: -120 * 60_000, drift_ppm: 0 })).unwrap();
    let b = w.account(2, &[]);
    w.place(&a, &[], Uplink::Public, &[r]);
    w.place(&b, &[], Uplink::Public, &[r]);
    w.run();
    let g = group(&a);
    say(&a, g, "first");
    w.run();
    let link = a.make_link(g, Role::Read, direct()).unwrap();
    w.run();
    let got = w.until(b.redeem(&link), 1000, 40);
    assert!(got.is_ok(), "{got:?}");
}

// Row 36, spec/sync.md §10: unreachable co-readers never hide a reachable one (8 newer ones
// reachable by nobody, the 9th the only way).
#[test]
#[ignore = "issues/net-connect.md"]
fn repro_row36_unreachable_co_readers_do_not_hide_a_reachable_one() {
    let mut w = World::new();
    let h = w.add_host();
    let a = w.account(100, &[h]);
    w.run();
    let older = pair(&w, &a, 101);
    w.run();
    w.advance(60_000);
    let hidden: Vec<Osis> = (0..8).map(|i| pair(&w, &a, 110 + i)).collect();
    w.run();
    for n in [&a, &older].into_iter().chain(hidden.iter()) {
        w.place(n, &[], Uplink::Public, &[]);
    }
    w.run();
    w.advance(60_000);
    for n in [&a, &older].into_iter().chain(hidden.iter()) {
        w.set_reachable(n, h, false);
    }
    for n in &hidden {
        w.set_peer_reachable(&a, n, false);
        w.set_peer_reachable(&older, n, false);
    }
    w.run();
    let home = a.home();
    say(&a, home, "to the reachable one");
    w.advance(LONG_MS);
    assert_eq!(heard(&older, home).as_deref(), Some("to the reachable one"));
}

// Row 37, spec/permissions.md §7: any node of the sharer's account finalizes an ended link, with
// its maker gone and no saved peer.
#[test]
#[ignore = "issues/net-first-contact.md"]
fn repro_row37_another_node_of_the_sharer_finalizes_a_link() {
    let mut w = World::new();
    let r = w.reach.add_relay(None);
    let a = w.account(1, &[]);
    w.place(&a, &[], Uplink::Public, &[r]);
    w.run();
    let a2 = pair(&w, &a, 2);
    w.place(&a2, &[], Uplink::Public, &[r]);
    w.run();
    w.advance(pause_ms());
    let g = group(&a);
    w.advance(pause_ms());
    let until = osis::Time(a.now().unwrap().0 + LONG_MS);
    a.make_link(g, Role::Read, LinkOpts { direct: true, until: Some(until), single_use: false }).unwrap();
    w.advance(pause_ms());
    let k = a.links().unwrap().into_iter().find(|l| l.target == g).unwrap().id.actor();
    assert!(a2.grants(g).unwrap().contains_key(&k), "the other node knows the link");
    w.set_online(&a, false);
    w.advance(2 * LONG_MS);
    assert!(!a2.grants(g).unwrap().contains_key(&k), "still not finalized");
}
