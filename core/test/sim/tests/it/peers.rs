//! Peer links over the sims' reachability model (`osis_sim::reach`): each route kind connects,
//! each blocked case does not, a restart reconnects, in `NetSim` and in `World`. Model time.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use osis::internals::Internals as _;
use osis::{Ak, DynamicAspectKey, MemStore, Osis, Store, Value};
use osis_sim::ClockSpec;
use osis_sim::net::scenarios::{ak, peer_group};
use osis_sim::net::{NetConfig, NetSim, Party};
use osis_sim::reach::{Reach, Route, Uplink};
use osis_sim::workload;
use osis_sim::world::World;
use osis_transport::nat::Nat;

fn net(place: impl FnOnce(&mut Reach, usize, usize)) -> (NetSim, usize, usize) {
    let mut sim = NetSim::new("peers", 3, NetConfig::default());
    let a = sim.add_node(&[], ClockSpec::default()).unwrap();
    let b = sim.add_node(&[], ClockSpec::default()).unwrap();
    place(&mut sim.reach, a, b);
    (sim, a, b)
}

/// A group of `a` shared with `b`, then one item written by `a` after setup: whether `b` reads
/// it says the link carried it (the setup is handed over directly).
fn writes_arrive(sim: &mut NetSim, a: usize, b: usize) -> bool {
    peer_group(sim, &[a, b]).unwrap();
    sim.quiet(40).unwrap();
    let g = sim.groups[0].g;
    let t = sim.item(a, g).unwrap();
    sim.quiet(40).unwrap();
    let k = ak(sim, &workload::REG).unwrap();
    sim.engine(b).unwrap().get(&t, &k).unwrap().is_some()
}

fn relay(r: &mut Reach) -> usize {
    r.add_relay(None)
}

// spec/sync.md §10: a dial connects through a LAN address on a shared segment, a public
// address, a punch the NAT pair allows or a relay both reach, and the data goes over it.
#[test]
fn each_route_kind_connects_spec_sync_10() {
    let lan = net(|r, a, b| {
        r.place(a, &[1], Uplink::None, &[]);
        r.place(b, &[1], Uplink::None, &[]);
    });
    let public = net(|r, a, b| {
        r.place(a, &[], Uplink::Public, &[]);
        r.place(b, &[], Uplink::Public, &[]);
    });
    let punched = net(|r, a, b| {
        let x = relay(r);
        let (na, nb) = (r.add_nat(Nat::CONE), r.add_nat(Nat::CONE));
        r.place(a, &[], Uplink::Nat(na), &[x]);
        r.place(b, &[], Uplink::Nat(nb), &[x]);
    });
    let relayed = net(|r, a, b| {
        let x = relay(r);
        let (na, nb) = (r.add_nat(Nat::SYMMETRIC), r.add_nat(Nat::SYMMETRIC));
        r.place(a, &[], Uplink::Nat(na), &[x]);
        r.place(b, &[], Uplink::Nat(nb), &[x]);
    });
    for ((mut sim, a, b), want) in [(lan, Route::Lan(1)), (public, Route::Public), (punched, Route::Punch(0)), (relayed, Route::Relay(0))] {
        assert!(writes_arrive(&mut sim, a, b), "{want:?}: the write arrives");
        let routes = sim.peer_routes();
        assert!(!routes.is_empty() && routes.iter().all(|r| *r == want), "{want:?}: {routes:?}");
    }
}

// spec/sync.md §10: no item routes, so no connection and no data: separate LANs, NATs with
// no relay, a relay only one side reaches, a node with no uplink, a partition.
#[test]
fn blocked_cases_do_not_connect_spec_sync_10() {
    let separate = net(|r, a, b| {
        r.place(a, &[1], Uplink::None, &[]);
        r.place(b, &[2], Uplink::None, &[]);
    });
    let nats = net(|r, a, b| {
        let (na, nb) = (r.add_nat(Nat::CONE), r.add_nat(Nat::CONE));
        r.place(a, &[], Uplink::Nat(na), &[]);
        r.place(b, &[], Uplink::Nat(nb), &[]);
    });
    let unreached_relay = net(|r, a, b| {
        let x = r.add_relay(Some(1));
        let (na, nb) = (r.add_nat(Nat::SYMMETRIC), r.add_nat(Nat::SYMMETRIC));
        r.place(a, &[1], Uplink::Nat(na), &[x]);
        r.place(b, &[], Uplink::Nat(nb), &[]);
    });
    let no_uplink = net(|r, a, b| {
        r.place(a, &[], Uplink::None, &[]);
        r.place(b, &[], Uplink::Public, &[]);
    });
    let mut partitioned = net(|r, a, b| {
        r.place(a, &[], Uplink::Public, &[]);
        r.place(b, &[], Uplink::Public, &[]);
    });
    let (a, b) = (partitioned.1, partitioned.2);
    partitioned.0.sever(Party::N(a), Party::N(b));
    for (i, (mut sim, a, b)) in [separate, nats, unreached_relay, no_uplink, partitioned].into_iter().enumerate() {
        assert!(!writes_arrive(&mut sim, a, b), "case {i}: nothing carried it");
        assert_eq!(sim.peer_routes(), [], "case {i}");
    }
}

// spec/sync.md §10: a relayed connection ends with its relay; a punched one is direct and stays.
#[test]
fn a_relay_stopping_cuts_only_what_it_carries_spec_sync_10() {
    for (nat, want) in [(Nat::CONE, 2), (Nat::SYMMETRIC, 0)] {
        let (mut sim, a, b) = net(|r, a, b| {
            let x = relay(r);
            let (na, nb) = (r.add_nat(nat), r.add_nat(nat));
            r.place(a, &[], Uplink::Nat(na), &[x]);
            r.place(b, &[], Uplink::Nat(nb), &[x]);
        });
        assert!(writes_arrive(&mut sim, a, b));
        assert_eq!(sim.peer_routes().len(), 2, "both dialed");
        sim.set_relay_up(0, false);
        assert_eq!(sim.peer_routes().len(), want, "{nat:?}");
    }
}

// spec/sync.md §5: a peer restarts over its own store under the key it listened with: dials reach
// it again and what was written while it was down arrives.
#[test]
fn a_restart_reconnects_over_the_same_store_spec_sync_5() {
    // only `a` can dial: `b` has a public address, `a` sits behind a NAT with no relay
    let (mut sim, a, b) = net(|r, a, b| {
        let cone = r.add_nat(Nat::CONE);
        r.place(a, &[], Uplink::Nat(cone), &[]);
        r.place(b, &[], Uplink::Public, &[]);
    });
    assert!(writes_arrive(&mut sim, a, b));
    sim.node_down(b).unwrap();
    assert_eq!(sim.peer_routes(), [], "its links went down with it");
    let g = sim.groups[0].g;
    let t = sim.item(a, g).unwrap();
    sim.restart_node(b).unwrap();
    sim.quiet(40).unwrap();
    assert!(!sim.peer_routes().is_empty(), "reconnected");
    let k = ak(&sim, &workload::REG).unwrap();
    assert!(sim.engine(b).unwrap().get(&t, &k).unwrap().is_some());
}

// spec/sync.md §10: a dropped LAN announcement is no route; one heard is, on the segment, from
// `lan_seen` alone (no reach item lists a LAN address).
#[test]
fn a_lan_announcement_makes_the_route_and_a_drop_does_not_spec_sync_10() {
    let (mut sim, a, b) = net(|r, a, b| {
        r.place(a, &[1], Uplink::None, &[]);
        r.place(b, &[1], Uplink::None, &[]);
    });
    peer_group(&mut sim, &[a, b]).unwrap();
    sim.drain_queue().unwrap();
    assert_eq!(sim.peer_routes(), [], "no item names the LAN");
    sim.lan_announce(a, 100).unwrap();
    sim.lan_announce(b, 100).unwrap();
    sim.drain_queue().unwrap();
    assert_eq!(sim.peer_routes(), [], "both dropped");
    sim.lan_announce(a, 0).unwrap();
    sim.drain_queue().unwrap();
    let routes = sim.peer_routes();
    assert!(!routes.is_empty() && routes.iter().all(|r| *r == Route::Lan(1)), "{routes:?}");
}

/// A group of `a` granted to `b` with nothing handed to `b` (no contact exchange).
fn grant_without_handover(sim: &mut NetSim, a: usize, b: usize) {
    let pa = sim.account(a, &[]).unwrap().account;
    sim.listen_peer(a).unwrap();
    let pb = sim.account(b, &[]).unwrap().account;
    sim.listen_peer(b).unwrap();
    sim.introduce(b, a).unwrap();
    let g = sim.group_with(a, pa, &[], true).unwrap();
    sim.grant(a, g, pb, osis::Role::Write).unwrap();
}

// spec: none (test harness: issues/net-tests.md, Checks over peers): a holder the model keeps connected and that cannot
// read fails liveness with no host in the run; one the model cuts off is left out (counted), computed
// from the model alone.
#[test]
fn liveness_judges_the_holders_the_model_connects() {
    let place = |r: &mut Reach, a, b| {
        r.place(a, &[], Uplink::Public, &[]);
        r.place(b, &[], Uplink::Public, &[]);
    };
    let (mut sim, a, b) = net(place);
    grant_without_handover(&mut sim, a, b);
    let e = sim.run_until_quiescent(40).unwrap_err();
    assert!(e.what.contains("liveness"), "{e}");
    let (mut sim, a, b) = net(place);
    grant_without_handover(&mut sim, a, b);
    sim.sever(Party::N(a), Party::N(b));
    sim.run_until_quiescent(40).unwrap();
    assert_eq!(sim.report.unjudged, 1, "{:?}", sim.report);
}

// spec: none (test harness: issues/net-tests.md, Checks over peers): a holder the model cuts off
// counts whether or not it reads, and a run that left any cut off (not `excused`) fails at
// `finish`: a generator that cuts everyone off cannot pass by judging nobody.
#[test]
fn a_run_with_holders_cut_off_fails() {
    let (mut sim, a, b) = net(|r, a, b| {
        r.place(a, &[1], Uplink::None, &[]);
        r.place(b, &[2], Uplink::None, &[]);
    });
    peer_group(&mut sim, &[a, b]).unwrap();
    sim.run_until_quiescent(40).unwrap();
    assert_eq!(sim.report.unjudged, 1, "a reader, cut off: {:?}", sim.report);
    assert!(sim.finish().unwrap_err().what.contains("cut off"));
}

const AK: &str = "s:peer.0";

fn say(db: &Osis, v: &str) {
    let mut w = db.write();
    w.at(db.home(), DynamicAspectKey::untyped(Ak::new(AK).unwrap())).set(&Value::Str(v.into())).unwrap();
    w.commit().unwrap();
}

fn heard(db: &Osis) -> Option<Value> {
    db.at(db.home(), DynamicAspectKey::untyped(Ak::new(AK).unwrap())).get().unwrap()
}

/// Two nodes of one account over a hub (their `reach.0` travels through it), placed by `place`,
/// then cut off the hub. The second node's store, for a restart.
fn world(place: impl FnOnce(&mut World, &Osis, &Osis), seed: u64) -> (World, Osis, Osis, MemStore) {
    let mut w = World::new();
    let h = w.add_host();
    let a = w.account(seed, &[h]);
    w.run();
    let store = MemStore::new();
    let mut c = w.cfg(seed + 1, &[]);
    c.store = Store::Memory(store.clone());
    let join = osis::internals::pair(c, &a.pair_offer().unwrap()).unwrap();
    let (_, reply) = a.pair_accept(join.request()).unwrap();
    let b = join.finish(&reply).unwrap();
    w.run();
    place(&mut w, &a, &b);
    w.run();
    say(&a, "over the hub");
    w.run();
    assert_eq!(heard(&b), Some(Value::Str("over the hub".into())));
    w.set_reachable(&a, h, false);
    w.set_reachable(&b, h, false);
    w.run();
    (w, a, b, store)
}

fn public(w: &mut World, a: &Osis, b: &Osis) {
    w.place(a, &[], Uplink::Public, &[]);
    w.place(b, &[], Uplink::Public, &[]);
}

/// Time past the peers' retry pause (`SyncConfig::peer_retry_ms`).
fn pause_ms() -> u64 {
    osis_node::sync::SyncConfig::default().peer_retry_ms + 1_000
}

// spec/sync.md §10: in `World` a `peer://` dial reaches a node's listener by a route of the
// model (here public addresses), `SyncEngine::accept` serves it, and writes go over it with the hub cut off.
#[test]
fn world_public_route_connects_spec_sync_10() {
    let (mut w, a, b, _) = world(public, 11);
    say(&a, "over the peer link");
    w.advance(pause_ms());
    assert!(w.peer_routes(&a).contains(&Route::Public), "{:?}", w.peer_routes(&a));
    assert_eq!(heard(&b), Some(Value::Str("over the peer link".into())));
}

// spec/sync.md §10: separate LANs: no route, no data.
#[test]
fn world_blocked_case_does_not_connect_spec_sync_10() {
    let (mut w, a, b, _) = world(
        |w, a, b| {
            w.place(a, &[1], Uplink::None, &[]);
            w.place(b, &[2], Uplink::None, &[]);
        },
        12,
    );
    say(&a, "stays home");
    w.advance(pause_ms());
    assert_eq!(w.peer_routes(&a), []);
    assert_ne!(heard(&b), Some(Value::Str("stays home".into())));
}

// spec/sync.md §10: a LAN announcement heard is the route; a partition ends it and a heal lets it
// connect again.
#[test]
fn world_lan_route_and_partition_spec_sync_10() {
    let (mut w, a, b, _) = world(
        |w, a, b| {
            w.place(a, &[1], Uplink::None, &[]);
            w.place(b, &[1], Uplink::None, &[]);
        },
        13,
    );
    assert_eq!(w.peer_routes(&a), [], "not announced yet");
    w.lan_announce(&a, |_| false);
    w.run();
    assert_eq!(w.peer_routes(&a), [], "dropped");
    w.lan_announce(&a, |_| true);
    w.lan_announce(&b, |_| true);
    say(&a, "over the lan");
    w.run();
    assert!(w.peer_routes(&b).contains(&Route::Lan(1)), "{:?}", w.peer_routes(&b));
    assert_eq!(heard(&b), Some(Value::Str("over the lan".into())));
    w.set_peer_reachable(&a, &b, false);
    w.run();
    assert_eq!(w.peer_routes(&b), [], "partitioned");
    w.set_peer_reachable(&a, &b, true);
    w.advance(pause_ms());
    w.lan_announce(&a, |_| true);
    w.lan_announce(&b, |_| true);
    w.run();
    assert!(!w.peer_routes(&b).is_empty(), "healed");
}

// spec/sync.md §5: a node reopened over its own store is reached again at its place and key, and
// catches up.
#[test]
fn world_restart_reconnects_spec_sync_5() {
    let (mut w, a, b, store) = world(public, 14);
    w.advance(pause_ms());
    assert!(!w.peer_routes(&a).is_empty());
    let mut c = w.cfg(99, &[]);
    c.store = Store::Memory(store);
    let b = w.restart(b, c);
    assert_eq!(w.peer_routes(&a), [], "its connections went with it");
    say(&a, "while it was away");
    w.advance(pause_ms());
    assert!(!w.peer_routes(&b).is_empty(), "reached again");
    assert_eq!(heard(&b), Some(Value::Str("while it was away".into())));
}

// spec: none (test harness): a node made with its own clock keeps its skew as time moves.
#[test]
fn world_nodes_have_their_own_clocks() {
    let mut w = World::new();
    let spec = ClockSpec { skew_ms: 5_000, drift_ppm: 0 };
    let c = w.cfg_clocked(1, &[], spec);
    let a = osis::internals::create(c).unwrap();
    let b = w.account(2, &[]);
    w.advance(1_000);
    let (ta, tb) = (a.engine(|e| e.now().0), b.engine(|e| e.now().0));
    assert_eq!(ta, tb + 5_000, "{ta} {tb}");
}
