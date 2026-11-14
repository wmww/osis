//! The driver: whom a node dials and when, the pair rule's held dials, restarts in place after a
//! store failure, and the one place outputs are applied (spec/sync-opens.md §1,
//! spec/sync-transport.md; scenarios dial-bound, store-reopen, eph-sim-unlisted and no-host-chain
//! of notes/sync-rewrite-inputs.md). World tests run the product's node; the dial rules alone
//! run on `Dials` with a table of dial peers.

use crate::harness::{World, two_nodes};
use osis_base::{BlobId, SyncId, WallMs};
use osis_label::{Address, Class, Prefix};
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

/// `w` with node 0 configured to dial node 1.
fn configured(mut w: World) -> World {
    let a = w.address(1);
    w.configure(0, |c| c.dial = vec![a]);
    w
}

// spec/sync-opens.md §1 (where to dial): a configured address is dialed, and the connection comes
// up at both ends.
#[test]
fn a_configured_address_is_dialed_spec_sync_opens_1() {
    let mut w = configured(two_nodes());
    w.run();
    assert_eq!(dials_to(&w, 0, 1), 1);
    assert!(connected(&w, 0, 1) && connected(&w, 1, 0));
    assert!(matches!(w.dials(0).state(&w.node(1).key.0), Some(State::Up(_))));
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
    assert!(connected(&w, 0, 1));
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
    assert!(connected(&w, 0, 1));
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
    assert!(connected(&w, 0, 1));
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
    w.run();
    let before = dials_to(&w, 0, 1);
    w.write(0, |e| e.hold_key_actor(osis_crypto::Secret32::from_bytes([0x33; 32])).unwrap());
    w.run();
    assert_eq!(dials_to(&w, 0, 1), before + 1, "closed and dialed again at once");
    assert!(connected(&w, 0, 1));
}

/// A blob of `class` expiring at `expiry`.
fn blob(n: usize, class: Class, expiry: u64) -> (BlobId, Vec<u8>) {
    let mut rng = osis_crypto::SeededRng::from_u64(n as u64);
    let p = Prefix::for_keys([n as u8; 16], &[1; 16], Some(WallMs(expiry)), &[]).unwrap().with_class(class);
    let (_, bytes) = osis_label::frame(&p, &vec![n as u8; n], &mut rng).unwrap();
    (osis_label::blob_id(&bytes), bytes)
}

fn own(b: BlobId, class: Class, expiry: u64) -> Entry {
    Entry { blob: b, wrap: [1; osis_crypto::WRAP_LEN], stamp: None, deposited: false, own: true, role: false, class, expires: Some(WallMs(expiry)) }
}

const SID: SyncId = SyncId([7; 16]);

// scenario store-reopen and eph-sim-unlisted (spec/sync-opens.md §1 redial): a failed store
// write closes every connection and restarts the node's modules from the store, once per
// stretch until a commit lands; the ephemeral entries it holds in memory stay (a store failure
// judges none); its dials go on (it connects again), and its next wake still comes
// (no-host-chain: a step's one wake, last).
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
    assert!(connected(&w, 0, 1), "dialed again");
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
    assert!(connected(&w, 0, 1));
    let _ = &mut st;
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

// spec/sync-opens.md §1 (redial): a candidate not connected is due `REDIAL_MS` after its last
// dial, or at once after a change that could make a peer share something.
#[test]
fn a_change_makes_every_waiting_candidate_due_spec_sync_opens_1() {
    let mut d = Dials::default();
    d.configure(&[addr(1)], T0);
    let (c, _) = d.dial(T0, MAX_PEERS)[0].clone();
    d.ended(c, None, WallMs(T0.0 + 10));
    d.tick(WallMs(T0.0 + 10));
    assert!(d.dial(WallMs(T0.0 + 10), MAX_PEERS).is_empty());
    assert_eq!(d.next_wake(), Some(WallMs(T0.0 + REDIAL_MS)));
    d.changed();
    assert_eq!(d.dial(WallMs(T0.0 + 20), MAX_PEERS).len(), 1, "a change: at once");
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
    d.changed();
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
    engine.create_account(&[]).unwrap();
    let cfg = osis_sync::SyncConfig { key: Some(osis_sync::NodeKey(key)), ..osis_sync::SyncConfig::default() };
    osis_sync::Node::open(engine, store, cfg, Box::new(SeededRng::from_u64(seed ^ 2))).unwrap()
}

/// Node A, configured with B's address, dials B over `ta`/`tb` (B listening at `url`) through
/// `TransportLinks`: the dial comes up and B's session answers (Hello, proofs, opens).
async fn dial_up<T: osis_transport::Transport>(ta: T, tb: T, url: &str) {
    use osis_sync::driver::links::{TransportLinks, run};
    use osis_transport::StaticSecret;
    let clock: Arc<dyn osis_base::Clock> = Arc::new(osis_base::SystemClock);
    let (sa, sb) = (StaticSecret::from_bytes([0xa1; 32]), StaticSecret::from_bytes([0xb2; 32]));
    let mut b = real_node(2, sb.public_key());
    let mut lb = TransportLinks::new(Arc::new(tb), clock.clone());
    let addr_b = lb.listen(&[url.to_string()], &sb).await.unwrap().remove(0);
    let mut a = real_node(1, sa.public_key());
    let mut la = TransportLinks::new(Arc::new(ta), clock.clone());
    let mut cfg = a.config().clone();
    cfg.dial = vec![addr_b.clone()];
    a.set_config(cfg);
    let served = tokio::spawn(async move {
        run(&mut b, &mut lb, tokio::time::sleep(Duration::from_secs(10))).await;
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

// spec/sync-transport.md §1 (streams and addresses): a configured address is dialed through the
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

// spec/sync-transport.md §2 (by hand: real QUIC on loopback): as above over `quic://`. Run with
// `cargo test -p osis-sync --test it -- --ignored quic_loopback`.
#[test]
#[ignore = "by hand: real sockets"]
fn quic_loopback_smoke() {
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
    rt.block_on(dial_up(osis_transport::Quic::new(), osis_transport::Quic::new(), "quic://127.0.0.1:0"));
}
