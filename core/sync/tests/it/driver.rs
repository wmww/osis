//! The driver: whom a node dials and when, the pair rule's held dials, restarts in place after a
//! store failure, and the one place outputs are applied (spec/sync-opens.md §1,
//! spec/sync-transport.md; the old sync's scenarios dial-bound, store-reopen, eph-sim-unlisted and
//! one-wake-last). World tests run the product's node; the dial rules alone
//! run on `Dials` with a table of dial peers.

use crate::harness::{Seen, World, contacts, siblings, two_nodes};
use osis_base::{BlobId, SyncId, WallMs};
use osis_blob::{Address, Class, Prefix};
use osis_store::Fault;
use osis_sync::driver::dials::{DISCOVERED_KEEP, Dials, Peers, State, Why};
use osis_sync::driver::{MAX_PEERS, REDIAL_MS};
use osis_sync::session::DIAL_TIMEOUT_MS;
use osis_sync::types::{ConnId, Entry};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

/// Dials node `i` made to node `j`'s key.
fn dials_to(w: &World, i: usize, j: usize) -> usize {
    let k = w.node(j).key.0;
    w.net.dials.iter().filter(|(f, _, t)| *f == i && *t == k).count()
}

fn connected(w: &World, i: usize, j: usize) -> bool {
    w.links_of(i).iter().any(|(_, t)| *t == j)
}

/// Dials node `i` made to node `j` that came up.
fn ups_to(w: &World, i: usize, j: usize) -> usize {
    w.net.ups.iter().filter(|u| **u == (i, j)).count()
}

/// `w` with node 0 configured to dial node 1.
fn configured(mut w: World) -> World {
    let a = w.address(1);
    w.configure(0, |c| c.dial = vec![a]);
    w
}

// spec/sync-opens.md §1 (where to dial; keep or close): a configured address is dialed and comes
// up; the connection, sharing nothing, with nothing under way and its peer quiet, closes, by its
// dialer (spec/sync-transport.md §5: the listener closes none for sharing nothing); the peer is
// not dialed again by time alone.
#[test]
fn a_configured_address_is_dialed_and_closes_sharing_nothing_spec_sync_opens_1() {
    let mut w = configured(two_nodes());
    w.trace = true;
    w.run();
    assert_eq!((dials_to(&w, 0, 1), ups_to(&w, 0, 1)), (1, 1));
    assert!(!connected(&w, 0, 1) && !connected(&w, 1, 0), "closed sharing nothing");
    assert!(w.seen.iter().any(|s| matches!(s, Seen::Closed { node: 1, .. })) && !w.seen.iter().any(|s| matches!(s, Seen::Closed { node: 0, .. })), "the dialer closed it");
    assert_eq!(w.dials(0).state(&w.node(1).key.0), Some(State::Idle));
    w.advance(10 * REDIAL_MS);
    assert_eq!(dials_to(&w, 0, 1), 1, "quiet: dialed again only after a change");
}

// spec/sync-opens.md §1 (own key): a node never dials its own key, whatever lists it.
#[test]
fn a_node_never_dials_its_own_key_spec_sync_opens_1() {
    let mut w = two_nodes();
    let own = w.address(0);
    w.configure(0, |c| c.dial = vec![own]);
    w.discover(0, 0);
    w.run();
    assert_eq!(dials_to(&w, 0, 0), 0);
    assert!(w.dials(0).is_empty());
}

// spec/sync-opens.md §1 (where to dial): a node discovery finds is dialed.
#[test]
fn a_discovered_node_is_dialed_spec_sync_opens_1() {
    let mut w = two_nodes();
    w.discover(0, 1);
    w.run();
    assert_eq!(ups_to(&w, 0, 1), 1);
}

// spec/sync-opens.md §1 (dial timeout), scenario dial-bound: a dial not up `DIAL_TIMEOUT_MS`
// after it started, whatever the route does, closes as failed and is dialed again; once the
// route answers, the redial connects.
#[test]
fn a_silent_dial_times_out_and_redials_spec_sync_opens_1() {
    let mut w = two_nodes();
    w.net.hang.insert(1);
    let mut w = configured(w);
    w.flush();
    assert_eq!(dials_to(&w, 0, 1), 1);
    w.advance(DIAL_TIMEOUT_MS - 1);
    assert_eq!(dials_to(&w, 0, 1), 1, "still waiting");
    w.advance(1);
    assert_eq!(dials_to(&w, 0, 1), 2, "timed out, dialed again (the pause since the last dial is over)");
    w.net.hang.clear();
    w.advance(DIAL_TIMEOUT_MS);
    assert_eq!(dials_to(&w, 0, 1), 3);
    w.run();
    assert_eq!(ups_to(&w, 0, 1), 1);
}

// spec/sync-opens.md §1 (Redial: it dials it again `REDIAL_MS` after its last dial): the pause
// is the node's to keep whatever its wall clock does: with both nodes' clocks gone back an hour
// while each waits to redial the other, they connect within a pause of the heal, not an hour on.
#[test]
#[ignore = "issues/clock-back-stalls-timers.md"]
fn repro_a_clock_gone_back_delays_no_redial_spec_sync_opens_1() {
    let mut w = contacts();
    w.partition(0, 1);
    w.advance(REDIAL_MS + 5_000);
    assert!(dials_to(&w, 0, 1) > 0 && !connected(&w, 0, 1), "node 0 dialed node 1 and waits to again");
    for i in [0, 1] {
        w.skew(i, -3_600_000);
    }
    w.heal();
    w.advance(2 * REDIAL_MS);
    assert!(connected(&w, 0, 1), "connected within a pause of the heal");
}

// spec/sync-opens.md §1 (redial): a failed dial is dialed again `REDIAL_MS` after it, not sooner
// without a change; a new address for the peer is a change: dialed at once.
#[test]
fn a_failed_dial_waits_one_pause_spec_sync_opens_1() {
    let mut w = two_nodes();
    w.power_off(1);
    let mut w = configured(w);
    w.flush();
    assert_eq!(dials_to(&w, 0, 1), 1);
    assert_eq!(w.dials(0).state(&w.node(1).key.0), Some(State::Idle));
    w.advance(REDIAL_MS - 1);
    assert_eq!(dials_to(&w, 0, 1), 1);
    w.advance(1);
    assert_eq!(dials_to(&w, 0, 1), 2);
    let moved = Address { url: format!("{} 192.0.2.7:9", w.address(1).url), key: w.node(1).key.0 };
    w.configure(0, |c| c.dial = vec![moved]);
    w.flush();
    assert_eq!(dials_to(&w, 0, 1), 3, "a new address: dialed at once");
    w.power_on(1);
    w.advance(REDIAL_MS);
    w.run();
    assert_eq!(ups_to(&w, 0, 1), 1);
}

// spec/sync-opens.md §1 (whom to dial): within `max_peers`, which counts connections sharing
// something and dials in flight, never candidates.
#[test]
fn max_peers_bounds_dials_in_flight_spec_sync_opens_1() {
    let mut w = World::new(0);
    for _ in 0..3 {
        w.add_node();
    }
    w.net.hang.extend([1, 2]);
    let (a, b) = (w.address(1), w.address(2));
    w.configure(0, |c| {
        c.max_peers = 1;
        c.dial = vec![a, b];
    });
    w.flush();
    assert_eq!(w.net.dials.iter().filter(|(f, ..)| *f == 0).count(), 1, "one dial in flight");
}

// spec/sync-opens.md §1 (proves once): a connection where this node proved its own, after the node
// came to act for an actor it did not prove there (a link key held), closes and its dialer dials
// again.
#[test]
fn acting_for_a_new_actor_redials_spec_sync_opens_1() {
    let mut w = configured(two_nodes());
    // the dial up to node 0's proofs done, the connection live
    let proved = |w: &World| w.links_of(0).iter().any(|(c, _)| w.node(0).node.session(*c).is_some_and(|s| s.acted_for().is_some()));
    while !proved(&w) {
        assert!(w.step(), "the dial came up and proved");
    }
    w.write(0, |e| e.hold_key_actor(osis_crypto::Secret32::from_bytes([0x33; 32])).unwrap());
    assert_eq!(dials_to(&w, 0, 1), 2, "closed and dialed again at once");
    w.run();
    assert_eq!(ups_to(&w, 0, 1), 2);
}

// spec/sync-opens.md §1 (proves once): a connection where this node proved no actor (it acted for
// none) closes too once it acts for one (an account made), and its dialer dials again; so a node
// whose account's epoch was closed while it dialed (a sibling's rotation, its seed not yet held)
// proves the account once the seed comes.
#[test]
fn acting_for_a_first_actor_redials_spec_sync_opens_1() {
    let mut w = World::new(0);
    w.add_node();
    let n = w.add_bare_node();
    let a = w.address(0);
    w.configure(n, |c| c.dial = vec![a]);
    let proved = |w: &World| w.links_of(n).iter().any(|(c, _)| w.node(n).node.session(*c).and_then(|s| s.acted_for()).is_some_and(|x| x.is_empty()));
    while !proved(&w) {
        assert!(w.step(), "the dial came up and proved nothing");
    }
    w.write(n, |e| e.create_account().expect("account"));
    assert_eq!(dials_to(&w, n, 0), 2, "closed and dialed again at once");
    w.run();
    assert_eq!(ups_to(&w, n, 0), 2);
}

/// Whether node `i` holds a live connection from node `j` on which `j` proved its account with
/// `key`, the account at an epoch open at `i`.
fn proven_at(w: &mut World, i: usize, j: usize, key: [u8; 32]) -> bool {
    let account = w.node(j).account.expect("an account");
    let proofs: Vec<(osis_base::CreationRecord, [u8; 32])> = w.links_of(i).into_iter().filter(|(_, t)| *t == j).filter_map(|(c, _)| w.node(i).node.session(c)?.proven().account.clone()).collect();
    proofs.into_iter().any(|(r, k)| r.tid() == account && k == key && w.engine(i).key_open(&r, &k))
}

// spec/sync-opens.md §1 (proves once), §2 (its account by a signature at an epoch): a node whose
// account rotates by its own write closes each connection where it proved the account at the
// closed epoch and dials again; its new Prove carries the rotation, so the peer holds it and
// counts the account proved at the new epoch.
#[test]
fn an_own_rotation_proves_again_spec_sync_opens_1() {
    let mut w = contacts();
    let a0 = w.node(0).account.expect("an account");
    let old = w.engine(0).account_open_key().expect("an open key");
    assert!(proven_at(&mut w, 1, 0, old), "node 0's account proved to node 1");
    let dials = dials_to(&w, 0, 1);
    let r = w.write(0, |e| e.rotate_account(&a0)).unwrap().expect("rotated");
    assert_eq!(dials_to(&w, 0, 1), dials + 1, "closed and dialed again at once");
    w.run();
    let new = w.engine(0).account_open_key().expect("an open key");
    assert_ne!(new, old);
    assert!(w.engine(1).account_rotations(&a0).contains(&r), "the Prove carried the rotation");
    assert!(proven_at(&mut w, 1, 0, new), "proved again at the new epoch");
    assert!(!proven_at(&mut w, 1, 0, old), "no connection left on the closed epoch");
}

// spec/sync-opens.md §1 (proves once), §2 (its account by a signature at an epoch),
// spec/permissions.md §5.4 (Roster): when another node of its account rotates it, a node keeps
// its home throughout (D's roster is the chain's, never D's lists), takes the rotation whole and so the new seed, and proves its account again at the
// new key.
#[test]
fn a_sibling_rotation_proves_again_spec_sync_opens_1() {
    let mut w = siblings();
    let a1 = w.node(1).account.expect("an account");
    assert_eq!(w.node(2).account, Some(a1), "node 2 is a node of account 1");
    let old = w.engine(2).account_open_key().expect("an open key");
    assert!(proven_at(&mut w, 0, 2, old), "node 2's account proved to node 0");
    let d = w.engine(2).account().unwrap().expect("an account").1;
    let home = w.engine(2).home_sync_id(&d).unwrap().expect("a home");
    let held = |w: &World| w.node(2).store.entries(&home).unwrap().len();
    let entries = held(&w);
    assert!(entries > 0, "node 2 holds its home");
    let r = w.write(1, |e| e.rotate_account(&a1)).unwrap().expect("rotated");
    while w.step() {
        assert!(w.store(2).synced(&home).is_some(), "node 2 keeps its home throughout");
    }
    w.run();
    w.advance(REDIAL_MS);
    w.run();
    let new = w.engine(1).account_open_key().expect("an open key");
    assert_ne!(new, old);
    assert!(w.engine(2).commit_parts_missing()[&r].is_empty(), "node 2 holds the rotation whole");
    assert!(held(&w) >= entries, "node 2 keeps its home");
    assert_eq!(w.engine(2).account_open_key(), Some(new), "node 2 holds the new seed");
    assert!(proven_at(&mut w, 0, 2, new), "proved again at the new epoch");
    for j in [0, 1] {
        assert!(!proven_at(&mut w, j, 2, old), "node {j} counts node 2's account at the closed epoch");
    }
}

// spec/sync-ids.md §2 (from the deposit seed of the thing's actor): a node paired after its account
// rotated holds the account's deposit seed and its D's deposit keys, whatever of the earlier
// rotations it holds only as certificates.
#[test]
fn a_node_paired_after_rotations_holds_the_deposit_seed_spec_sync_ids_2() {
    let mut w = contacts();
    let a1 = w.node(1).account.expect("an account");
    for _ in 0..2 {
        w.write(1, |e| e.rotate_account(&a1)).unwrap().expect("rotated");
        w.run();
    }
    let n = w.pair(1);
    w.run();
    w.advance(REDIAL_MS);
    w.run();
    let d = w.engine(n).account().unwrap().expect("an account").1;
    let missing: Vec<_> = w.engine(n).commit_parts_missing().into_iter().filter(|(_, x)| !x.is_empty()).collect();
    assert_eq!(w.engine(n).deposit_seed(&d).unwrap().map(|s| *s.expose()), w.engine(1).deposit_seed(&d).unwrap().map(|s| *s.expose()), "the account's deposit seed; parts missing {missing:?}");
}

/// A blob of `class` expiring at `expiry`.
fn blob(n: usize, class: Class, expiry: u64) -> (BlobId, Vec<u8>) {
    let mut rng = osis_crypto::SeededRng::from_u64(n as u64);
    let p = Prefix::for_keys([n as u8; 16], &[1; 16], Some(WallMs(expiry)), &[]).unwrap().with_class(class);
    let (_, bytes) = osis_blob::frame(&p, &vec![n as u8; n], &mut rng).unwrap();
    (osis_blob::blob_id(&bytes), bytes)
}

fn own(b: BlobId, class: Class, expiry: u64) -> Entry {
    Entry { blob: b, wrap: [1; osis_crypto::WRAP_LEN], stamp: None, deposited: false, own: true, role: false, class, expires: Some(WallMs(expiry)) }
}

const SID: SyncId = SyncId([7; 16]);

// spec/sync-opens.md §1 (where to dial: the granting node of each grant it holds, by the inbox
// blob's hint), scenario store-reopen: after a restart in place, a grant taken from node 1's
// inbox blob and accepted makes node 1 a hinted candidate of node 0 (the hints are followed
// afresh).
#[test]
fn hints_are_followed_after_a_restart_in_place_spec_sync_opens_1() {
    let mut w = crate::harness::contacts();
    let t = w.now().0;
    let mut st = w.node(0).store.clone();
    let (d, dx) = blob(80, Class::Durable, t + 60_000);
    assert_eq!(st.log(&SID, own(d, Class::Durable, t + 60_000), Some(dx), None).unwrap(), osis_proto::Code::OK);
    w.write(0, |_| ());
    w.store_faults(0).at(0, Fault::Fail);
    w.advance(60_000);
    assert_eq!(w.restarts(0), 1);
    w.run();
    let (a0, a1) = (w.node(0).account.unwrap(), w.node(1).account.unwrap());
    let x = w.write(1, |e| {
        let mut m = osis_engine::Mutation::new();
        let x = e.new_thing(&mut m, a1);
        e.commit(m).unwrap();
        e.give_own_secrets(&x).unwrap();
        e.grant(&x, &a0, &osis_schema::core_types::Edge { role: osis_base::Role::Sync, until: None, invite: None, tied: None, floor: None }).unwrap();
        x
    });
    w.run();
    // an offered grant's hint is dialed once its sync ID is kept: accepted
    w.write(0, |e| {
        let d = e.account().unwrap().unwrap().1;
        e.accept_invite(&x, &d).unwrap();
    });
    w.run();
    assert!(w.dials(0).why(&w.node(1).key.0).contains(&Why::Hint), "{:?}", w.dials(0).why(&w.node(1).key.0));
}

// scenario store-reopen and eph-sim-unlisted (spec/sync-opens.md §1 redial): a failed store
// write closes every connection and restarts the node's modules from the store, once per
// stretch until a commit lands; the ephemeral entries it holds in memory stay (a store failure
// judges none); its dials go on (it connects again), and its next wake still comes
// (one-wake-last: a step's one wake, last).
#[test]
fn a_store_failure_restarts_in_place_once_per_stretch() {
    let mut w = configured(two_nodes());
    w.run();
    let t = w.now().0;
    let mut st = w.node(0).store.clone();
    let (d, dx) = blob(80, Class::Durable, t + 60_000);
    let (e, ex) = blob(90, Class::Ephemeral, t + 36_000_000);
    let late = t + 7_200_000;
    let (d2, d2x) = blob(81, Class::Durable, late);
    assert_eq!(st.log(&SID, own(d, Class::Durable, t + 60_000), Some(dx), None).unwrap(), osis_proto::Code::OK);
    assert_eq!(st.log(&SID, own(d2, Class::Durable, late), Some(d2x), None).unwrap(), osis_proto::Code::OK);
    assert_eq!(st.log(&SID, own(e, Class::Ephemeral, t + 36_000_000), Some(ex), None).unwrap(), osis_proto::Code::OK);
    // the test wrote the store beside the node: a step takes up its wake
    w.write(0, |_| ());
    let faults = w.store_faults(0);
    faults.at(0, Fault::Fail);
    w.advance(60_000);
    assert_eq!(w.restarts(0), 1, "the failed expiry closed every connection and restarted");
    assert!(st.entry(&SID, &e).unwrap().is_some(), "the memory class stays");
    assert!(st.entry(&SID, &d).unwrap().is_none(), "the retried write landed");
    w.run();
    // a stretch: every write fails until writes work again; one restart
    faults.forbid_writes(true);
    w.advance(late - w.now().0);
    w.advance(5 * REDIAL_MS);
    assert_eq!(w.restarts(0), 2, "once per stretch");
    assert!(!connected(&w, 0, 1));
    faults.forbid_writes(false);
    w.advance(REDIAL_MS);
    w.run();
    assert!(st.entry(&SID, &d2).unwrap().is_none() && st.entry(&SID, &e).unwrap().is_some());
    let _ = &mut st;
}

// a failed step sends nothing it queued (notes/sync-driver.md, Failures): here a listener's
// Hello, queued as the connection came up in a step whose store write failed; the dialer sees
// a dropped connection, and the next dial comes up whole.
#[test]
fn a_failed_step_sends_nothing_it_queued() {
    let mut w = two_nodes();
    let t = w.now().0;
    let mut st = w.node(1).store.clone();
    let (d, dx) = blob(80, Class::Durable, t + 60_000);
    assert_eq!(st.log(&SID, own(d, Class::Durable, t + 60_000), Some(dx), None).unwrap(), osis_proto::Code::OK);
    // node 1's clock past the expiry: its next step writes it, and that write fails
    w.skew(1, 61_000);
    w.store_faults(1).at(0, Fault::Fail);
    w.trace = true;
    let a = w.address(1);
    w.configure(0, |c| c.dial = vec![a]);
    w.flush();
    let failed: Vec<_> = w.stepped.iter().filter(|(i, f, _)| *i == 1 && *f).collect();
    assert_eq!(failed.len(), 1, "{:?}", w.stepped);
    assert_eq!(failed[0].2, 0, "the failed step sent nothing");
    w.run();
    assert!(st.entry(&SID, &d).unwrap().is_none(), "the retried write landed");
    assert!(ups_to(&w, 0, 1) >= 1);
}

// ---- the dial rules alone, on `Dials` ----

/// Dial peers per sync ID, set by the test.
#[derive(Default)]
struct Table {
    peers: BTreeMap<SyncId, Arc<Vec<Address>>>,
    due: Vec<SyncId>,
}

impl Table {
    fn set(&mut self, s: SyncId, a: Vec<Address>) {
        self.peers.insert(s, Arc::new(a));
        self.due.push(s);
    }
}

impl Peers for Table {
    fn due(&mut self) -> Vec<SyncId> {
        std::mem::take(&mut self.due)
    }
    fn peers(&mut self, s: &SyncId) -> Arc<Vec<Address>> {
        self.peers.get(s).cloned().unwrap_or_default()
    }
}

fn addr(n: u32) -> Address {
    let mut key = [0u8; 32];
    key[..4].copy_from_slice(&n.to_be_bytes());
    key[31] = 1;
    Address { url: format!("peer://10.0.0.1:{}", n % 60_000 + 1), key }
}

const T0: WallMs = WallMs(1_000_000);

// spec/sync-opens.md §1 (where to dial): addresses are priorities: the dial peers of a sync ID it
// syncs first, then configured, then discovered; a reason withdrawn forgets the candidate.
#[test]
fn candidates_dial_by_priority_spec_sync_opens_1() {
    let mut d = Dials::default();
    let mut t = Table::default();
    d.offer(Why::Discovered, addr(1), T0);
    d.configure(&[addr(2)], T0);
    t.set(SID, vec![addr(3)]);
    d.settle_peers(&mut t, T0);
    let order: Vec<[u8; 32]> = d.dial(T0, MAX_PEERS).into_iter().map(|(_, a)| a.key).collect();
    assert_eq!(order, [addr(3).key, addr(2).key, addr(1).key]);
    t.set(SID, vec![]);
    d.settle_peers(&mut t, T0);
    assert_eq!(d.state(&addr(3).key), Some(State::Dialing(ConnId(1))), "kept while its dial lasts");
    d.ended(ConnId(1), None, T0);
    assert_eq!(d.state(&addr(3).key), None, "no reason left: forgotten");
}

// spec/sync-opens.md §1 (whom to dial): `max_peers` counts connections sharing something and dials
// in flight; a connection up and sharing nothing frees its slot, one sharing holds it.
#[test]
fn max_peers_counts_sharing_connections_spec_sync_opens_1() {
    let mut d = Dials::default();
    d.configure(&[addr(1), addr(2), addr(3)], T0);
    let first = d.dial(T0, 1);
    assert_eq!(first.len(), 1);
    assert!(d.dial(T0, 1).is_empty(), "a dial in flight takes the slot");
    let c = first[0].0;
    d.up(c);
    d.sharing(c, true);
    assert!(d.dial(T0, 1).is_empty(), "a sharing connection takes the slot");
    d.sharing(c, false);
    assert_eq!(d.dial(T0, 1).len(), 1, "sharing nothing: the slot is free");
}

// spec/sync-opens.md §1 (redial; keep or close): a candidate not connected is due `REDIAL_MS`
// after its last dial; one whose connection closed sharing nothing only after a change, and
// still no sooner than `REDIAL_MS` after its last dial, so changes on every step dial it at most
// once per `REDIAL_MS`.
#[test]
fn a_quiet_candidate_waits_for_a_change_spec_sync_opens_1() {
    let at = |ms: u64| WallMs(T0.0 + ms);
    let mut d = Dials::default();
    d.configure(&[addr(1), addr(2)], T0);
    let cs: Vec<ConnId> = d.dial(T0, MAX_PEERS).into_iter().map(|(c, _)| c).collect();
    d.ended(cs[0], None, at(10));
    d.up(cs[1]);
    d.closed_quiet(cs[1], at(10));
    d.tick(at(REDIAL_MS));
    let due: Vec<[u8; 32]> = d.dial(at(REDIAL_MS), MAX_PEERS).into_iter().map(|(_, a)| a.key).collect();
    assert_eq!(due, [addr(1).key], "the failed one by time; the quiet one waits");
    d.tick(at(10 * REDIAL_MS));
    assert!(d.dial(at(10 * REDIAL_MS), MAX_PEERS).is_empty() && d.next_wake().is_none());
    // a change: dialed at once (its last dial is long past)
    d.changed(at(10 * REDIAL_MS));
    let (c, a) = d.dial(at(10 * REDIAL_MS), MAX_PEERS).remove(0);
    assert_eq!(a.key, addr(2).key);
    d.up(c);
    d.closed_quiet(c, at(10 * REDIAL_MS + 5));
    // a change on every step: no sooner than `REDIAL_MS` after the last dial
    for ms in (10 * REDIAL_MS + 6..11 * REDIAL_MS).step_by(1000) {
        d.changed(at(ms));
        d.tick(at(ms));
        assert!(d.dial(at(ms), MAX_PEERS).is_empty(), "at {ms}");
    }
    d.tick(at(11 * REDIAL_MS));
    assert_eq!(d.dial(at(11 * REDIAL_MS), MAX_PEERS).len(), 1);
}

// spec/sync-opens.md §1 (whom to dial; redial): due dials go by priority, then the longest
// undialed first: silent candidates that time out together never keep the others from a slot.
#[test]
fn due_dials_take_turns_spec_sync_opens_1() {
    let mut d = Dials::default();
    d.configure(&[addr(1), addr(2), addr(3)], T0);
    let mut seen = Vec::new();
    let mut now = T0;
    for _ in 0..3 {
        let (c, a) = d.dial(now, 1).remove(0);
        seen.push(a.key);
        now = WallMs(now.0 + DIAL_TIMEOUT_MS);
        d.ended(c, None, now);
        d.tick(now);
    }
    seen.sort();
    assert_eq!(seen, [addr(1).key, addr(2).key, addr(3).key], "each in turn");
}

// spec/sync-opens.md §1 (one connection per pair): a dialer whose connection closed losing its
// pair does not dial that peer while the winner lasts, whatever changes; then it may again.
#[test]
fn a_lost_dial_waits_for_the_winner_spec_sync_opens_1() {
    let mut d = Dials::default();
    d.configure(&[addr(1)], T0);
    let (c, _) = d.dial(T0, MAX_PEERS)[0].clone();
    d.up(c);
    let winner = ConnId(ConnId::ACCEPTED | 5);
    d.ended(c, Some(winner), T0);
    assert_eq!(d.state(&addr(1).key), Some(State::Held(winner)));
    d.changed(WallMs(T0.0 + 20));
    d.tick(WallMs(T0.0 + 10 * REDIAL_MS));
    assert!(d.dial(WallMs(T0.0 + 10 * REDIAL_MS), MAX_PEERS).is_empty());
    d.ended(winner, None, WallMs(T0.0 + 10 * REDIAL_MS));
    assert_eq!(d.dial(WallMs(T0.0 + 10 * REDIAL_MS), MAX_PEERS).len(), 1);
}

// spec/sync-transport.md §4 (dialing): what a node remembers of its discoveries is bounded: past
// `DISCOVERED_KEEP` the oldest is forgotten.
#[test]
fn discoveries_kept_are_bounded_spec_sync_transport_4() {
    let mut d = Dials::default();
    for i in 0..=DISCOVERED_KEEP as u32 {
        d.offer(Why::Discovered, addr(i), T0);
    }
    assert_eq!(d.len(), DISCOVERED_KEEP);
    assert_eq!(d.state(&addr(0).key), None);
}

/// Work of `steps` steps with nothing due, and of one sync ID's peers moving, at `n`
/// candidates waiting.
fn work_at(n: u32) -> (u64, u64) {
    let mut d = Dials::default();
    let mut t = Table::default();
    let sid = |k: u32| {
        let mut b = [0u8; 16];
        b[..4].copy_from_slice(&k.to_be_bytes());
        SyncId(b)
    };
    // two candidates per sync ID
    for k in 0..n / 2 {
        t.set(sid(k), vec![addr(2 * k), addr(2 * k + 1)]);
    }
    d.settle_peers(&mut t, T0);
    let conns: Vec<ConnId> = d.dial(T0, usize::MAX).into_iter().map(|(c, _)| c).collect();
    for c in conns {
        d.ended(c, None, T0);
    }
    let w0 = d.work().touched;
    for s in 1..100u64 {
        let now = WallMs(T0.0 + s);
        d.settle_peers(&mut t, now);
        d.tick(now);
        assert!(d.dial(now, usize::MAX).is_empty());
    }
    let idle = d.work().touched - w0;
    let w1 = d.work().touched;
    t.set(sid(0), vec![addr(n + 1)]);
    d.settle_peers(&mut t, WallMs(T0.0 + 100));
    (idle, d.work().touched - w1)
}

// spec/sync-opens.md §1 (whom to dial), counted at n and 10n: steps with nothing due touch no
// candidate; one sync ID's dial peers moving touches that sync ID's candidates only (the same at
// n and 10n).
#[test]
fn dial_work_follows_change_spec_sync_opens_1() {
    let (idle_n, one_n) = work_at(400);
    let (idle_10n, one_10n) = work_at(4_000);
    assert_eq!((idle_n, idle_10n), (0, 0));
    assert!(one_n > 0 && one_10n == one_n, "one sync ID's change: {one_n} at n, {one_10n} at 10n");
}

// ---- by hand: the product's links over real QUIC ----

/// A node with an account of its own over in-memory disks, on the system clock.
fn real_node(seed: u64, key: [u8; 32]) -> osis_sync::Node {
    use osis_crypto::SeededRng;
    use osis_store::{MemoryBackend, MemoryRoot};
    let clock: Arc<dyn osis_base::Clock> = Arc::new(osis_base::SystemClock);
    let store = osis_sync::Store::open(Box::new(MemoryBackend::new()), Box::new(MemoryRoot::new()), Box::new(SeededRng::from_u64(seed ^ 1))).unwrap();
    let mut engine = osis_engine::Engine::create(Box::new(MemoryBackend::new()), Box::new(MemoryRoot::new()), store.cipher(), osis_engine::Config::default(), clock, Box::new(SeededRng::from_u64(seed))).unwrap();
    engine.create_account().unwrap();
    let cfg = osis_sync::SyncConfig { key: Some(osis_sync::NodeKey(key)), ..osis_sync::SyncConfig::default() };
    osis_sync::Node::open(engine, store, cfg, Box::new(SeededRng::from_u64(seed ^ 2))).unwrap()
}

/// Node A, configured with B's address, dials B over `ta`/`tb` (B listening at `url`) through
/// `TransportLinks`: the dial comes up and B's session answers (Hello, proofs, opens).
async fn dial_up<T: osis_transport::Transport>(ta: T, tb: T, url: &str) {
    use osis_sync::driver::links::TransportLinks;
    use osis_transport::StaticSecret;
    let clock: Arc<dyn osis_base::Clock> = Arc::new(osis_base::SystemClock);
    let (sa, sb) = (StaticSecret::from_bytes([0xa1; 32]), StaticSecret::from_bytes([0xb2; 32]));
    let mut b = real_node(2, sb.public_key());
    let mut lb = TransportLinks::new(Arc::new(tb), clock.clone());
    let addr_b = lb.listen(osis_sync::Listening::Urls, &[url.to_string()], &sb).await.unwrap().remove(0);
    let mut a = real_node(1, sa.public_key());
    let mut la = TransportLinks::new(Arc::new(ta), clock.clone());
    let mut cfg = a.config().clone();
    cfg.dial = vec![addr_b.clone()];
    a.set_config(cfg);
    // B steps on its links as the osis handle's driver does (core/osis/src/net.rs `drive`)
    let served = tokio::spawn(async move {
        osis_sync::apply(b.handle(osis_sync::Input::Wrote), &mut lb);
        loop {
            let input = lb.next().await;
            let out = osis_transport::link::blocking(|| b.handle(input));
            osis_sync::apply(out, &mut lb);
        }
    });
    let first = a.handle(osis_sync::Input::Wrote);
    osis_sync::apply(first, &mut la);
    let up = async {
        let mut bytes = 0;
        loop {
            let input = la.next().await;
            bytes += usize::from(matches!(input, osis_sync::Input::Bytes { .. }));
            let out = osis_transport::link::blocking(|| a.handle(input));
            osis_sync::apply(out, &mut la);
            if matches!(a.dials().state(&addr_b.key), Some(State::Up(_))) && bytes >= 3 {
                return;
            }
        }
    };
    tokio::time::timeout(Duration::from_secs(10), up).await.expect("the dial came up and was answered");
    served.abort();
}

// spec/sync-transport.md §1 (address): a configured address is dialed through the
// product's `TransportLinks` over an in-process transport; the dial comes up and the peer's
// session answers.
#[test]
fn transport_links_dial_in_process_spec_sync_transport_1() {
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    rt.block_on(async {
        let net = osis_transport::Net::new(0);
        dial_up(net.endpoint("a"), net.endpoint("b"), "mem://b").await;
    });
}

// spec/sync-transport.md §5 (Key change: every listener moves to the new key): a listener set
// listened again at the port it holds, under a new key, finds the port free (its listeners are
// closed when `listen` returns), over real QUIC and `peer://` sockets on loopback; another set
// keeps its port meanwhile.
#[test]
fn a_listener_set_listens_again_at_its_own_port_spec_sync_transport_5() {
    use osis_sync::Listening;
    use osis_transport::StaticSecret;
    async fn again<T: osis_transport::Transport>(new: impl Fn() -> T, url: &str) {
        let clock: Arc<dyn osis_base::Clock> = Arc::new(osis_base::SystemClock);
        let mut l = osis_sync::TransportLinks::new(Arc::new(new()), clock);
        let (s1, s2) = (StaticSecret::from_bytes([1; 32]), StaticSecret::from_bytes([2; 32]));
        let kept = l.listen(Listening::Dialable, &[url.to_string()], &s1).await.unwrap().remove(0);
        let a = l.listen(Listening::Urls, &[url.to_string()], &s1).await.unwrap().remove(0);
        for _ in 0..3 {
            let b = l.listen(Listening::Urls, std::slice::from_ref(&a.url), &s2).await.expect("the set's own port is free again").remove(0);
            assert_eq!(b.url, a.url);
        }
        assert!(osis_transport::listen_all(&new(), Vec::new(), std::slice::from_ref(&kept.url), &s1).await.is_err(), "the other set still holds its port");
    }
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    rt.block_on(async {
        again(osis_transport::Quic::new, "quic://127.0.0.1:0").await;
        again(|| osis_transport::P2p::new(osis_transport::QuicUdp::new()), "peer://127.0.0.1:0").await;
    });
}

// spec/sync-transport.md §5 (Key change: rotate_peer_address returns once every listener listens
// under the new key, keeping no listener on the old key): a listener set with a live accepted
// connection listens again at its own port, over real QUIC and `peer://` sockets on loopback: the
// listener keeps its socket; under the same key its session goes on, under a new key the session
// taken under the old one closes at both ends.
#[test]
fn a_listener_set_with_a_live_connection_listens_again_spec_sync_transport_5() {
    use osis_sync::{Input, Listening};
    use osis_transport::StaticSecret;
    async fn again<T: osis_transport::Transport>(new: impl Fn() -> T, url: &str) {
        let clock: Arc<dyn osis_base::Clock> = Arc::new(osis_base::SystemClock);
        let mut l = osis_sync::TransportLinks::new(Arc::new(new()), clock);
        let (s1, s2) = (StaticSecret::from_bytes([1; 32]), StaticSecret::from_bytes([2; 32]));
        let a = l.listen(Listening::Urls, &[url.to_string()], &s1).await.unwrap().remove(0);
        let dialer = new();
        let c = osis_transport::link::dial(&dialer, &a, Duration::from_secs(5)).await.unwrap();
        assert!(c.tx.send(b"hi".to_vec(), usize::MAX));
        let up = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Input::Up { conn, .. } = l.next().await {
                    return conn;
                }
            }
        });
        let conn = up.await.expect("the listener took the connection");
        let same = tokio::time::timeout(Duration::from_secs(5), l.listen(Listening::Urls, std::slice::from_ref(&a.url), &s1)).await.expect("relisten ends");
        assert_eq!(same.expect("the same key listens again").remove(0).key, a.key);
        // under the same key the session goes on
        assert!(c.tx.send(b"again".to_vec(), usize::MAX));
        let more = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Input::Bytes { bytes, .. } = l.next().await
                    && bytes.ends_with(b"again")
                {
                    return;
                }
            }
        });
        more.await.expect("the connection carries bytes after the relisten");
        let b = tokio::time::timeout(Duration::from_secs(5), l.listen(Listening::Urls, std::slice::from_ref(&a.url), &s2)).await.expect("relisten ends");
        let b = b.expect("the set's own port is free again with a connection up").remove(0);
        assert_eq!((b.url.as_str(), b.key), (a.url.as_str(), s2.public_key()));
        // the session taken under the old key closes here and at the dialer
        let closed = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Input::Closed { conn: c2 } = l.next().await
                    && c2 == conn
                {
                    return;
                }
            }
        });
        closed.await.expect("the old key's session is closed");
        let mut rx = c.rx;
        let end = tokio::time::timeout(Duration::from_secs(5), async {
            while rx.recv().await.is_some() {}
        });
        end.await.expect("the dialer's session ends");
        // a dial under the new key comes up, under the old one fails
        assert!(osis_transport::link::dial(&dialer, &b, Duration::from_secs(5)).await.is_ok());
        assert!(osis_transport::link::dial(&dialer, &a, Duration::from_secs(5)).await.is_err(), "nothing under the old key");
        drop(c.tx);
    }
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    rt.block_on(async {
        again(osis_transport::Quic::new, "quic://127.0.0.1:0").await;
        again(|| osis_transport::P2p::new(osis_transport::QuicUdp::new()), "peer://127.0.0.1:0").await;
    });
}

// spec/sync-transport.md §2 (QUIC v1), by hand: real QUIC on loopback: as above over `quic://`. Run with
// `cargo test -p osis-sync --test it -- --ignored quic_loopback`.
#[test]
#[ignore = "by hand: real sockets"]
fn quic_loopback_smoke() {
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
    rt.block_on(dial_up(osis_transport::Quic::new(), osis_transport::Quic::new(), "quic://127.0.0.1:0"));
}

// spec/sync-opens.md §1 (where to dial: addresses are priorities, never a filter; Redial): a
// node known at a dial list's address and a configured one dials the first, and when that dial
// fails the configured one at once; it stays at an address that came up.
#[test]
fn a_failed_address_gives_way_to_the_next_spec_sync_opens_1() {
    let mut d = Dials::default();
    let mut t = Table::default();
    let stale = addr(1);
    let configured = Address { url: "quic://10.0.0.2:4040".into(), key: stale.key };
    t.set(SID, vec![stale.clone()]);
    d.settle_peers(&mut t, T0);
    d.configure(std::slice::from_ref(&configured), T0);
    let urls = |v: Vec<(ConnId, Address)>| v.into_iter().map(|(c, a)| (c, a.url)).collect::<Vec<_>>();
    let first = urls(d.dial(T0, MAX_PEERS));
    assert_eq!(first.iter().map(|(_, u)| u.as_str()).collect::<Vec<_>>(), [stale.url.as_str()]);
    d.ended(first[0].0, None, T0);
    let second = urls(d.dial(T0, MAX_PEERS));
    assert_eq!(second.iter().map(|(_, u)| u.as_str()).collect::<Vec<_>>(), [configured.url.as_str()], "at once");
    d.up(second[0].0);
    d.ended(second[0].0, None, T0);
    assert!(d.dial(T0, MAX_PEERS).is_empty(), "a connection that ended waits a pause");
    let later = WallMs(T0.0 + REDIAL_MS);
    d.tick(later);
    assert_eq!(urls(d.dial(later, MAX_PEERS)).iter().map(|(_, u)| u.as_str()).collect::<Vec<_>>(), [configured.url.as_str()], "an address that came up stays");
}

// spec/sync-opens.md §1 (Redial): a node known at several dead addresses, one of them by many
// sync IDs, dials each distinct address once a turn (not once per reason), its best reason's
// first, the others at once after each failure, then nothing until `REDIAL_MS` after the turn's
// last dial: published addresses add no dials past one per address per pause.
#[test]
fn dead_addresses_take_turns_at_the_redial_pace_spec_sync_opens_1() {
    let mut d = Dials::default();
    let mut t = Table::default();
    let synced = addr(1);
    let hint = Address { url: "quic://10.0.0.3:4040".into(), key: synced.key };
    let configured = Address { url: "quic://10.0.0.2:4040".into(), key: synced.key };
    for i in 0..50u8 {
        t.set(SyncId([i; 16]), vec![synced.clone()]);
    }
    d.settle_peers(&mut t, T0);
    d.hint(std::slice::from_ref(&hint), T0);
    d.configure(std::slice::from_ref(&configured), T0);
    let mut turns = Vec::new();
    let mut now = T0;
    for _ in 0..2 {
        let mut turn = Vec::new();
        while let Some((conn, a)) = d.dial(now, MAX_PEERS).pop() {
            assert!(turn.len() < 3, "a turn dials each address once: {turn:?}");
            turn.push(a.url);
            d.ended(conn, None, now);
        }
        let quiet = WallMs(now.0 + REDIAL_MS - 1);
        d.tick(quiet);
        assert!(d.dial(quiet, MAX_PEERS).is_empty(), "no dial before the pause ends");
        now = WallMs(now.0 + REDIAL_MS);
        d.tick(now);
        turns.push(turn);
    }
    assert_eq!(turns[0][0], synced.url, "the best reason's address first");
    let mut seen = turns[0].clone();
    seen.sort();
    let mut all = vec![synced.url.clone(), hint.url.clone(), configured.url.clone()];
    all.sort();
    assert_eq!(seen, all, "each distinct address once a turn");
    assert_eq!(turns[1], turns[0], "then again in the same order");
}

// spec/sync-set.md §1 (dial list: a node removed from D has no entry), spec/sync-opens.md §1
// (whom to dial: the nodes of accounts holding a role, by their dial list): a contact dials a
// node of an account holding a role on what it reads; once that node is removed (and gone
// quiet, powered off), the contact dials it no more.
#[test]
fn a_removed_node_is_dialed_no_more_by_a_contact_spec_sync_set_1() {
    let (mut w, t, _) = crate::flows::granted_and_read(osis_base::Role::Write);
    let s = w.engine(1).sync_ids(&t).unwrap()[0].id;
    let n = w.pair(0);
    w.run();
    let nk = w.node(n).key.0;
    let listed = |w: &mut World| w.engine(1).dial_peers(&s).unwrap().iter().any(|a| a.key == nk);
    assert!(listed(&mut w), "a node of a holding account: a candidate");
    let (node, d) = (w.engine(n).tid(), w.engine(0).account().unwrap().unwrap().1);
    w.write(0, |e| e.demote(&d, &osis_engine::flows::Demotion { holder: node, new: None, retain: None })).unwrap();
    w.power_off(n);
    w.run();
    assert!(!listed(&mut w), "removed: no candidate");
    let before = dials_to(&w, 1, n);
    w.advance(10 * REDIAL_MS);
    w.run();
    assert_eq!(dials_to(&w, 1, n), before, "never dialed again");
}
