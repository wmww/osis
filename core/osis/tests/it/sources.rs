//! Sources per group (notes/client-port.md §1, §5, §6): routing, moving a group, reconnects, the
//! client listener. Two nodes P and N of one account sync through a peer; P connects to N's client
//! listener as a thin client whose actor N minted.

use osis::internals::CommitRaw as _;
use osis::internals::schema::RawKey as _;
use crate::common::watched;
use crate::common::TestWrites as _;
use crate::common::{ak, block_on};
use osis::internals::Internals as _;
use osis::{SetRoleOpts, Member, ClientSecret, Error, GroupSource, Address, MemStore, NodeLogin, Osis, Role, Runtime, Store, SyncScope, SyncState, Tid, Value};
use std::sync::mpsc::channel;
use std::time::{Duration, Instant};

const W: Duration = Duration::from_secs(20);
const SHORT: Duration = Duration::from_millis(400);

fn until(what: &str, f: impl Fn() -> bool) {
    let end = Instant::now() + W;
    while !f() {
        assert!(Instant::now() < end, "not reached: {what}");
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn cfg_on(net: &osis_transport::Net, ep: &str, store: &MemStore, hosts: Vec<Address>) -> osis::internals::Opening {
    let mut c = osis::internals::Opening::at(Store::Memory(store.clone()));
    c.runtime = Runtime::Own;
    c.app.internals.transport = Some(net.endpoint(ep));
    c.hosts = hosts;
    c.app.internals.connection_wait = Some(W);
    // no co-reader sessions: N and P meet only through the peer, and through the client port
    c.direct_sync = false;
    c
}

/// Keeps the peer running; `n`, `p` two nodes of an account, a group `g` of it with a thing `t`,
/// both synced; `nc` N's client address, `secret` a client with `Write` on `g`.
struct World {
    p_wait: Duration,
    net: osis_transport::Net,
    host: Option<Osis>,
    n: Osis,
    n_store: MemStore,
    p: Osis,
    p_store: MemStore,
    addr: Address,
    nc: Address,
    urls: Vec<osis::Url>,
    secret: ClientSecret,
    actor: Tid,
    g: Tid,
    t: Tid,
}

fn title() -> osis::Ak {
    ak("note:title.0")
}

// spec: none (API surface); notes/api.md Serving: a group read at another node is that node's to name for peers: never an empty answer from this one's copy
#[test]
fn admission_ids_of_a_group_read_elsewhere_api_design() {
    let x = world();
    x.connect_p();
    let here = x.p.sync_ids(x.g).unwrap();
    assert!(!here.is_empty(), "synced here");
    assert_eq!(x.n.sync_ids(x.g).unwrap(), here, "one group, one name");
    x.to_node();
    assert!(matches!(x.p.sync_ids(x.g), Err(Error::Unsupported(_))), "asked of the node, which keeps it from this client's actor");
}

fn world() -> World {
    world_waiting(W)
}

/// `p_wait`: how long this test waits for P's moves of a group (`World::move_group`).
fn world_waiting(p_wait: Duration) -> World {
    let net = osis_transport::Net::new(3);
    let mut hc = cfg_on(&net, "s", &MemStore::new(), vec![]);
    hc.direct_sync = false;
    let host = osis::internals::create(hc).unwrap();
    host.set_serving(Some(osis::Serving { listen: vec!["mem://s".parse().unwrap()], admit: osis::Admit::Open, ..Default::default() })).unwrap();
    until("host address", || host.serving_address().unwrap().is_some());
    let addr = host.serving_address().unwrap().unwrap();
    let (n_store, p_store) = (MemStore::new(), MemStore::new());
    let n = osis::internals::create(cfg_on(&net, "n", &n_store, vec![addr.clone()])).unwrap();
    let pc = cfg_on(&net, "p", &p_store, vec![addr.clone()]);
    let joining = osis::internals::pair(pc, &n.pair_offer().unwrap()).unwrap();
    let (_, reply) = n.pair_accept(joining.request()).unwrap();
    let p = joining.finish(&reply).unwrap();
    let (g, t) = n
        .commit_with(|w| {
            let g = w.create()?;
            let t = w.create_with_admin(g)?;
            w.group(g).add(osis::Member::Item(t))?;
            w.at(t, osis::DynamicAspectKey::untyped(title())).set(&Value::Str("first".into()))?;
            Ok((g, t))
        })
        .unwrap();
    n.sync(g, &[]).unwrap();
    let (actor, secret) = n.add_client(None).unwrap();
    n.grant(g, actor, Role::Write, Default::default()).unwrap();
    block_on(n.wait_synced(SyncScope::Thing(g))).unwrap();
    let urls: Vec<osis::Url> = vec!["mem://n-clients".parse().unwrap()];
    let nc = n.client_listen(&urls).unwrap().remove(0);
    until("P has the group", || {
        let _ = p.nudge_sync();
        p.at(t, osis::DynamicAspectKey::untyped(title())).get().ok().flatten() == Some(Value::Str("first".into()))
    });
    World { p_wait, net, host: Some(host), n, n_store, p, p_store, addr, nc, urls, secret, actor, g, t }
}

fn s(x: &str) -> Value {
    Value::Str(x.into())
}

impl World {
    /// P's move of a group, as a caller's timeout of `p_wait` gives it up: changes nothing more.
    fn move_group(&self, g: Tid, to: GroupSource) -> osis::Result<()> {
        crate::common::within(self.p_wait, self.p.group_source(g, to)).unwrap_or_else(|| Err(Error::Network("the test's timeout".into())))
    }

    fn connect_p(&self) {
        crate::common::block_on(self.p.connect_node(&NodeLogin { addr: self.nc.clone(), secret: self.secret.clone() })).unwrap();
    }

    fn to_node(&self) {
        block_on(self.p.group_source(self.g, GroupSource::Node(self.nc.clone()))).unwrap();
    }

    fn thin(&self, ep: &str) -> Osis {
        let mut c = osis::internals::Opening::memory();
        c.app.internals.transport = Some(self.net.endpoint(ep));
        c.app.internals.connection_wait = Some(W);
        crate::common::block_on(osis::internals::connect(&self.nc, &self.secret, c)).unwrap()
    }

    fn p_local_copy(&self) -> Option<Value> {
        self.p.engine(|e| e.get(&self.t, &ak("note:title.0")).unwrap())
    }

    fn set_n(&self, v: &str) {
        self.n.commit_set(self.t, osis::DynamicAspectKey::untyped(title()), &s(v)).unwrap();
    }
}

// spec/sync.md §10, notes/client-port.md §6: a group with no source node is local whatever a connected node also offers; a thing known only at the connected node goes there; with the node unreachable the local thing still reads and the one at the node fails Network
#[test]
fn known_stays_here_and_unknown_goes_to_the_node() {
    let x = world();
    x.connect_p();
    // only at N, in the group the client may read, not synced to P yet (N is cut from the peer)
    x.net.partition("n", "s");
    let only_n = x.n.commit_with(|w| {
        let o = w.create_with_admin(x.g)?;
        w.group(x.g).add(osis::Member::Item(o))?;
        w.at(o, osis::DynamicAspectKey::untyped(title())).set(&s("at n"))?;
        Ok(o)
    }).unwrap();
    x.set_n("n's");
    // no route: P reads its own synced copy, not N's newer one
    assert_eq!(x.p.at(x.t, osis::DynamicAspectKey::untyped(title())).get().unwrap(), Some(s("first")));
    // known here nowhere: the connected node answers
    assert_eq!(x.p.at(only_n, osis::DynamicAspectKey::untyped(title())).get().unwrap(), Some(s("at n")));
    assert!(!x.p.engine(|e| e.knows(&only_n)));
    // a write to it goes there, not here
    x.p.commit_set(only_n, osis::DynamicAspectKey::untyped(title()), &s("from p")).unwrap();
    assert_eq!(x.n.at(only_n, osis::DynamicAspectKey::untyped(title())).get().unwrap(), Some(s("from p")));
    assert!(!x.p.engine(|e| e.knows(&only_n)));
    // a commit over both sources is refused, nothing written
    assert!(matches!(x.p.commit_with(|w| { w.at(only_n, osis::DynamicAspectKey::untyped(title())).set(&s("a"))?; w.at(x.t, osis::DynamicAspectKey::untyped(title())).set(&s("b")) }), Err(Error::Invalid(_))));
    assert_eq!(x.n.at(only_n, osis::DynamicAspectKey::untyped(title())).get().unwrap(), Some(s("from p")));
    assert_eq!(x.p.at(x.t, osis::DynamicAspectKey::untyped(title())).get().unwrap(), Some(s("first")));
    // down: local goes on, the node's is Network, never UnknownThing and never a local answer
    x.net.partition("p", "n");
    x.net.disconnect("p", "n");
    until("connection down", || !x.p.status().unwrap().node_connections[0].connected);
    assert_eq!(x.p.at(x.t, osis::DynamicAspectKey::untyped(title())).get().unwrap(), Some(s("first")));
    assert!(matches!(x.p.at(only_n, osis::DynamicAspectKey::untyped(title())).get(), Err(Error::Network(_))));
    assert!(matches!(x.p.commit_set(only_n, osis::DynamicAspectKey::untyped(title()), &s("z")), Err(Error::Network(_))));
    assert!(!x.p.engine(|e| e.knows(&only_n)));
    drop(x.host);
}

// spec/sync.md §10, notes/client-port.md §6 Moving: to Node this node stops syncing for itself alone (N keeps syncing: the group's label is not replaced), reads and writes go to N at once, P's copy stays and is not read; back to Local it catches up before calls come home; a move refused changes nothing
#[test]
fn moving_a_group_both_ways() {
    let x = world();
    x.connect_p();
    // not connected, unknown there: refused, nothing changed
    let ghost = Address::new(&"mem://nobody".parse().unwrap(), [7; 32]);
    assert!(matches!(x.move_group(x.g, GroupSource::Node(ghost)), Err(Error::Invalid(_))));
    assert!(matches!(x.move_group(x.p.me(), GroupSource::Node(x.nc.clone())), Err(Error::Invalid(_))));
    assert!(x.p.group_sources().is_empty());
    x.to_node();
    assert_eq!(x.p.group_sources().get(&x.g), Some(&x.nc));
    assert!(x.p.sync_options(x.g).unwrap().mode == osis::SyncMode::LogOnly);
    // only for P: N's label lives and syncs
    block_on(x.n.wait_synced(SyncScope::Thing(x.g))).unwrap();
    until("N synced", || x.n.status().unwrap().groups[&x.g].state == SyncState::Synced);
    // N's write reads at P at once, P's own copy unchanged
    x.set_n("n1");
    assert_eq!(x.p.at(x.t, osis::DynamicAspectKey::untyped(title())).get().unwrap(), Some(s("n1")));
    assert_eq!(x.p_local_copy(), Some(s("first")));
    // P's write lands at N, not in P's copy
    x.p.commit_set(x.t, osis::DynamicAspectKey::untyped(title()), &s("p1")).unwrap();
    assert_eq!(x.n.at(x.t, osis::DynamicAspectKey::untyped(title())).get().unwrap(), Some(s("p1")));
    assert_eq!(x.p_local_copy(), Some(s("first")));
    // a new thing in the routed group is made there; this engine never hears of it
    let mut w = x.p.write();
    let o = w.create_with_admin(x.g).unwrap();
    w.group(x.g).add(osis::Member::Item(o)).unwrap();
    w.at(o, osis::DynamicAspectKey::untyped(title())).set(&s("made through p")).unwrap();
    let made = o;
    w.commit().unwrap();
    assert_eq!(x.n.at(made, osis::DynamicAspectKey::untyped(title())).get().unwrap(), Some(s("made through p")));
    assert!(!x.p.engine(|e| e.knows(&made)));
    assert_eq!(x.p.at(made, osis::DynamicAspectKey::untyped(title())).get().unwrap(), Some(s("made through p")));
    // merged status: the node's state for the routed group, the connection up
    until("the node's state shows", || x.p.status().unwrap().groups[&x.g].state == SyncState::Synced);
    assert!(x.p.status().unwrap().node_connections[0].connected);
    // a node it reaches as a thin client adds no links
    assert!(x.p.links().unwrap().is_empty());
    // home: nothing left to catch up with a peer gone is a failure that keeps the route
    block_on(x.n.wait_synced(SyncScope::Thing(x.g))).unwrap();
    x.move_group(x.g, GroupSource::Local).unwrap();
    assert!(x.p.group_sources().is_empty());
    assert!(!(x.p.sync_options(x.g).unwrap().mode == osis::SyncMode::LogOnly));
    // what P wrote through N is here: no stale read after the move
    assert_eq!(x.p.at(x.t, osis::DynamicAspectKey::untyped(title())).get().unwrap(), Some(s("p1")));
    assert_eq!(x.p_local_copy(), Some(s("p1")));
    // and P's own writes sync again
    x.p.commit_set(x.t, osis::DynamicAspectKey::untyped(title()), &s("p2")).unwrap();
    block_on(x.p.wait_synced(SyncScope::Thing(x.g))).unwrap();
    until("N got P's write", || {
        let _ = x.n.nudge_sync();
        x.n.at(x.t, osis::DynamicAspectKey::untyped(title())).get().unwrap() == Some(s("p2"))
    });
    drop(x.host);
}

// spec/sync.md §10, notes/client-port.md §6: moves with writes pending on either side refuse, changing nothing, and each write stays where it is readable: a local write not yet at a peer holds the move away; going home while this engine cannot catch up, or while the node holds a write no peer has, keeps the route, so calls still go to the node and the local copy never answers behind
#[test]
fn moves_with_pending_writes_refuse() {
    let x = world_waiting(Duration::from_millis(300));
    x.connect_p();
    x.net.partition("p", "s");
    x.net.disconnect("p", "s");
    x.p.commit_set(x.t, osis::DynamicAspectKey::untyped(title()), &s("pending")).unwrap();
    let r = x.move_group(x.g, GroupSource::Node(x.nc.clone()));
    assert!(matches!(r, Err(Error::Network(_) | Error::Unsynced { .. })), "{r:?}");
    assert!(x.p.group_sources().is_empty());
    assert!(x.p.sync_options(x.g).unwrap().mode != osis::SyncMode::LogOnly);
    assert_eq!(x.p.at(x.t, osis::DynamicAspectKey::untyped(title())).get().unwrap(), Some(s("pending")));
    // another world: away with nothing pending, then home with P cut from the peer
    let x = world_waiting(Duration::from_millis(300));
    x.connect_p();
    x.to_node();
    x.set_n("newer");
    x.net.partition("p", "s");
    x.net.disconnect("p", "s");
    let r = x.move_group(x.g, GroupSource::Local);
    assert!(r.is_err(), "{r:?}");
    assert_eq!(x.p.group_sources().get(&x.g), Some(&x.nc));
    assert_eq!(x.p.at(x.t, osis::DynamicAspectKey::untyped(title())).get().unwrap(), Some(s("newer")), "the route stays until caught up");
    assert_eq!(x.p_local_copy(), Some(s("first")));
    // another: home while only the node holds a write
    let x = world_waiting(Duration::from_millis(300));
    x.connect_p();
    x.to_node();
    x.net.partition("n", "s");
    x.net.disconnect("n", "s");
    x.p.commit_set(x.t, osis::DynamicAspectKey::untyped(title()), &s("only at n")).unwrap();
    let r = x.move_group(x.g, GroupSource::Local);
    assert!(matches!(r, Err(Error::Network(_))), "{r:?}");
    assert_eq!(x.p.group_sources().get(&x.g), Some(&x.nc));
    assert_eq!(x.p.at(x.t, osis::DynamicAspectKey::untyped(title())).get().unwrap(), Some(s("only at n")), "still at the node");
    drop(x.host);
}

// spec/sync.md §10, notes/client-port.md §6: the same moves finish once the link heals, and no write was lost (tier 2: each heal waits a sync retry, 5 s)
#[test]
#[ignore]
fn moves_with_pending_writes_finish_after_healing() {
    let x = world_waiting(Duration::from_secs(1));
    x.connect_p();
    x.net.partition("p", "s");
    x.net.disconnect("p", "s");
    x.p.commit_set(x.t, osis::DynamicAspectKey::untyped(title()), &s("pending")).unwrap();
    assert!(x.move_group(x.g, GroupSource::Node(x.nc.clone())).is_err());
    x.net.heal("p", "s");
    until("the pending write reaches N", || {
        let _ = x.p.nudge_sync();
        let _ = x.n.nudge_sync();
        x.n.at(x.t, osis::DynamicAspectKey::untyped(title())).get().unwrap() == Some(s("pending"))
    });
    block_on(x.p.wait_synced(SyncScope::Thing(x.g))).unwrap();
    x.to_node();
    x.set_n("newer");
    x.net.partition("p", "s");
    x.net.disconnect("p", "s");
    assert!(x.move_group(x.g, GroupSource::Local).is_err());
    x.net.heal("p", "s");
    until("moved after P caught up", || {
        let _ = x.p.nudge_sync();
        x.move_group(x.g, GroupSource::Local).is_ok()
    });
    assert_eq!(x.p.at(x.t, osis::DynamicAspectKey::untyped(title())).get().unwrap(), Some(s("newer")));
    x.to_node();
    x.net.partition("n", "s");
    x.net.disconnect("n", "s");
    x.p.commit_set(x.t, osis::DynamicAspectKey::untyped(title()), &s("only at n")).unwrap();
    assert!(x.move_group(x.g, GroupSource::Local).is_err());
    x.net.heal("n", "s");
    until("home with the write", || {
        let _ = x.n.nudge_sync();
        let _ = x.p.nudge_sync();
        x.move_group(x.g, GroupSource::Local).is_ok()
    });
    assert_eq!(x.p.at(x.t, osis::DynamicAspectKey::untyped(title())).get().unwrap(), Some(s("only at n")));
    drop(x.host);
}

// spec/sync.md §10, notes/client-port.md §6 Offline: a disconnected node fails Network at once, with no stale value from the copy this node still holds, no write to it; a Watch reads Err(Network) while down; status says connected: false; a new watch fails too; moving home still works with the node gone
#[test]
fn disconnected_node_is_network_never_stale() {
    let x = world();
    x.connect_p();
    x.to_node();
    let watch = watched(&x.p, x.t, osis::DynamicAspectKey::untyped(title())).unwrap();
    x.set_n("seen");
    until("watch", || watch.current().ok().flatten() == Some(s("seen")));
    x.net.partition("p", "n");
    x.net.disconnect("p", "n");
    until("down", || !x.p.status().unwrap().node_connections[0].connected);
    assert!(x.p_local_copy().is_some());
    assert!(matches!(x.p.at(x.t, osis::DynamicAspectKey::untyped(title())).get(), Err(Error::Network(_))));
    assert!(matches!(x.p.aspects(x.t), Err(Error::Network(_))));
    assert!(matches!(watched(&x.p, x.t, osis::DynamicAspectKey::untyped(title())), Err(Error::Network(_))));
    // every read of a thing there says so, none answers with a default
    assert!(matches!(x.p.has_content(x.t), Err(Error::Network(_))));
    assert!(matches!(x.p.groups_of(x.t), Err(Error::Network(_))));
    assert!(matches!(x.p.grants(x.t), Err(Error::Network(_))));
    assert!(matches!(x.p.role_on(x.t), Err(Error::Network(_))));
    assert!(matches!(x.p.created(x.t), Err(Error::Network(_))));
    assert!(matches!(x.p.changed(x.t), Err(Error::Network(_))));
    assert!(matches!(x.p.holders(x.t), Err(Error::Network(_))));
    assert!(x.p.links().unwrap().is_empty(), "the links are this node's: none is at the node gone");
    assert!(matches!(x.p.on_thing_change(x.t, |_, _| {}), Err(Error::Network(_))));
    assert!(matches!(x.p.on_grants_change(x.t, |_, _| {}), Err(Error::Network(_))));
    let before = x.p_local_copy();
    assert!(matches!(x.p.commit_set(x.t, osis::DynamicAspectKey::untyped(title()), &s("lost?")), Err(Error::Network(_))));
    assert_eq!(x.p_local_copy(), before);
    assert_eq!(x.n.at(x.t, osis::DynamicAspectKey::untyped(title())).get().unwrap(), Some(s("seen")));
    until("the watch tells", || watch.current().is_err());
    assert!(matches!(watch.current(), Err(Error::Network(_))));
    // back: the watch closes the gap
    x.set_n("in the gap");
    x.net.heal("p", "n");
    until("watch after reconnect", || watch.current().ok().flatten() == Some(s("in the gap")));
    assert_eq!(x.p.at(x.t, osis::DynamicAspectKey::untyped(title())).get().unwrap(), Some(s("in the gap")));
    x.p.commit_set(x.t, osis::DynamicAspectKey::untyped(title()), &s("after")).unwrap();
    assert_eq!(x.n.at(x.t, osis::DynamicAspectKey::untyped(title())).get().unwrap(), Some(s("after")));
    drop(x.host);
}

// spec/sync.md §10, notes/api.md Tracked reads: a tracked read whose group moved listens at the new source, not at
// the subscription the move ended.
#[test]
fn a_tracked_read_listens_at_its_new_source_after_a_move() {
    let x = world();
    x.connect_p();
    let (tx, rx) = channel();
    let set = osis::ReadSet::new(move |_| tx.send(()).unwrap());
    let h = x.p.tracking(&set);
    let key = osis::DynamicAspectKey::untyped(title());
    h.at(x.t, key.clone()).get().unwrap();
    x.to_node();
    rx.recv_timeout(W).unwrap();
    h.at(x.t, key.clone()).get().unwrap();
    x.n.commit_set(x.t, key, &s("second")).unwrap();
    rx.recv_timeout(W).expect("told at the node the group moved to");
}

// spec/sync.md §10, notes/client-port.md §6: moving a group ends a watch on the source it left with one last error: a local watch does not go silent over a group this node stopped syncing, a watch at the node does not outlive the move
#[test]
fn a_move_ends_watches_of_the_group() {
    let x = world();
    x.connect_p();
    let local = watched(&x.p, x.t, osis::DynamicAspectKey::untyped(title())).unwrap();
    let (tx, rx) = channel();
    let sub = x.p.at(x.t, osis::DynamicAspectKey::untyped(title())).on_change(move |_, c| tx.send(c.value.is_err()).unwrap()).unwrap();
    assert!(!(rx.recv_timeout(W).unwrap()));
    x.to_node();
    until("local watch ended", || local.current().is_err());
    assert!(rx.recv_timeout(W).unwrap());
    drop(sub);
    let at_node = watched(&x.p, x.t, osis::DynamicAspectKey::untyped(title())).unwrap();
    assert!(at_node.current().is_ok());
    x.move_group(x.g, GroupSource::Local).unwrap();
    until("the watch at the node ended", || at_node.current().is_err());
    // a node's own client must not read the stale copy of a group the node moved away (below)
    drop(x.host);
}

// spec/sync.md §10, notes/client-port.md §6, §3: a client of a node reads nothing the node stopped syncing: it is stale there, the client gets UnknownThing, not an old value, and through the node's own connection nothing runs as the node's actor
#[test]
fn a_nodes_client_does_not_read_what_it_moved_away() {
    let x = world();
    // N3 is a third way in: a client of P
    let (a, sec) = x.p.add_client(None).unwrap();
    x.p.grant(x.g, a, Role::Read, Default::default()).unwrap();
    let pc = x.p.client_listen(&["mem://p-clients".parse().unwrap()]).unwrap().remove(0);
    let mut c = osis::internals::Opening::memory();
    c.app.internals.transport = Some(x.net.endpoint("pc"));
    let client = crate::common::block_on(osis::internals::connect(&pc, &sec, c)).unwrap();
    assert_eq!(client.at(x.t, osis::DynamicAspectKey::untyped(title())).get().unwrap(), Some(s("first")));
    let w = watched(&client, x.t, osis::DynamicAspectKey::untyped(title())).unwrap();
    x.connect_p();
    x.to_node();
    x.set_n("newer");
    assert_eq!(client.at(x.t, osis::DynamicAspectKey::untyped(title())).get().unwrap(), None);
    assert!(!client.has_content(x.t).unwrap());
    until("its subscription lapsed", || w.current().is_err());
    drop(x.host);
}

// spec/sync.md §10, notes/client-port.md §1 Reconnect: a write whose first send ran and whose reply was lost is answered from the node's memory under the same epoch: applied once, and the caller gets its one result
#[test]
fn lost_reply_retried_applies_once() {
    let x = world();
    let c = x.thin("c1");
    let name = ak("note:n.0");
    c.commit_set(x.t, osis::DynamicAspectKey::untyped(title()), &s("before")).unwrap();
    let before = commits_of(&x.n, x.t);
    x.n.port_panic_next(true);
    c.commit_set(x.t, osis::DynamicAspectKey::untyped(name.clone()), &s("once")).unwrap();
    assert_eq!(x.n.at(x.t, osis::DynamicAspectKey::untyped(name)).get().unwrap(), Some(s("once")));
    assert_eq!(commits_of(&x.n, x.t), before + 1, "applied exactly once");
    // a set of an equal value commits nothing, so only a count tells a second run
    let count = count_key(&[&x.n]);
    x.n.port_panic_next(true);
    let mut w = c.write();
    w.at(x.t, count.clone()).path(osis::Path::root()).contribute(&1i64).unwrap();
    w.commit().unwrap();
    assert_eq!(x.n.at(x.t, count).get().unwrap(), Some(Value::Int(1)), "applied exactly once");
    drop(x.host);
}

/// A counter's key, its schema registered on `dbs`: an op whose second run shows.
fn count_key(dbs: &[&Osis]) -> osis::DynamicAspectKey {
    for db in dbs {
        db.register_schema("count.osis", "revision 1;\naspect count:n.0: counter<int>;\n").unwrap();
    }
    dbs[0].aspect_key("count:n.0").unwrap()
}

fn commits_of(db: &Osis, t: Tid) -> usize {
    crate::common::listed(db, osis::Scope::Thing(t)).len()
}

// spec/sync.md §10, notes/client-port.md §1 Reconnect: a write that never reached the node (the worker died before it) is sent again and applied once
#[test]
fn unsent_write_retried_applies_once() {
    let x = world();
    let c = x.thin("c1");
    // a session's very first write: the node holds nothing for it, so a resend may be of a
    // session it evicted: unknown, though it never ran
    let before = commits_of(&x.n, x.t);
    x.n.port_panic_next(false);
    let r = c.commit_set(x.t, osis::DynamicAspectKey::untyped(title()), &s("first write"));
    assert!(matches!(&r, Err(Error::OutcomeUnknown)), "{r:?}");
    assert_eq!(commits_of(&x.n, x.t), before);
    // a new write makes the session known (a resend right after that unknown could be of a write
    // that ran before the state went: unknown too, `every_resent_nonce_of_a_lost_session_is_unknown`)
    c.commit_set(x.t, osis::DynamicAspectKey::untyped(title()), &s("new")).unwrap();
    // with the session known: sent again, it runs once (a count: a second run shows)
    let count = count_key(&[&x.n]);
    x.n.port_panic_next(false);
    let mut w = c.write();
    w.at(x.t, count.clone()).path(osis::Path::root()).contribute(&1i64).unwrap();
    w.commit().unwrap();
    assert_eq!(x.n.at(x.t, count).get().unwrap(), Some(Value::Int(1)), "applied exactly once");
    assert_eq!(commits_of(&x.n, x.t), before + 2);
    drop(x.host);
}

// spec/sync.md §10, issues/cli-proxy.md Port worker panic: a panic ends that session at once, not after a stall timeout: its in-flight read fails Network, it reconnects; another client's session never noticed, and the worker lives on
#[test]
fn a_worker_panic_ends_one_session_and_the_port_lives() {
    let x = world();
    let (c1, c2) = (x.thin("c1"), x.thin("c2"));
    let w2 = watched(&c2, x.t, osis::DynamicAspectKey::untyped(title())).unwrap();
    x.n.port_panic_next(true);
    let t0 = Instant::now();
    assert!(matches!(c1.at(x.t, osis::DynamicAspectKey::untyped(title())).get(), Err(Error::Network(_))));
    assert!(t0.elapsed() < Duration::from_secs(30), "no stall timeout");
    until("c1 reconnected", || c1.at(x.t, osis::DynamicAspectKey::untyped(title())).get().is_ok());
    assert_eq!(c2.at(x.t, osis::DynamicAspectKey::untyped(title())).get().unwrap(), Some(s("first")));
    x.set_n("still live");
    until("c2's watch still live", || w2.current().ok().flatten() == Some(s("still live")));
    drop(x.host);
}

// spec/sync.md §10, notes/client-port.md §1 Reconnect: node restart: Auth again; subscriptions again with the new value; later writes work
#[test]
fn restart_keeps_the_node_connection_working() {
    let mut x = world();
    let mut cc = osis::internals::Opening::memory();
    cc.app.internals.transport = Some(x.net.endpoint("c1"));
    cc.app.internals.connection_wait = Some(W);
    let c = crate::common::block_on(osis::internals::connect(&x.nc, &x.secret, cc)).unwrap();
    let w = watched(&c, x.t, osis::DynamicAspectKey::untyped(title())).unwrap();
    let (c2, t) = (c.clone(), x.t);
    x.net.partition("c1", "n");
    x.net.disconnect("c1", "n");
    until("down", || !c.status().unwrap().node_connections[0].connected);
    // the time is the node's: never this process's stand-in
    assert!(matches!(c.now(), Err(Error::Network(_))));
    // calls while down are definite: not sent
    assert!(matches!(c2.commit_set(t, osis::DynamicAspectKey::untyped(title()), &s("not sent")), Err(Error::Network(_))));
    // the node restarts on its store and listens again
    let (net, store, addr, urls) = (x.net.clone(), x.n_store.clone(), x.addr.clone(), x.urls.clone());
    assert_eq!(std::mem::replace(&mut x.n, osis::internals::create(osis::internals::Opening::memory()).unwrap()).close().unwrap(), osis::Close::Closed);
    let n2 = osis::internals::open(cfg_on(&net, "n", &store, vec![addr])).unwrap();
    assert_eq!(n2.client_listen(&urls).unwrap().remove(0), x.nc, "the client listener's key survives a restart");
    net.heal("c1", "n");
    until("client back up", || c.status().unwrap().node_connections[0].connected);
    n2.commit_set(t, osis::DynamicAspectKey::untyped(title()), &s("after restart")).unwrap();
    until("the watch came back", || w.current().ok().flatten() == Some(s("after restart")));
    c.commit_set(t, osis::DynamicAspectKey::untyped(title()), &s("again")).unwrap();
    assert_eq!(n2.at(t, osis::DynamicAspectKey::untyped(title())).get().unwrap(), Some(s("again")));
    drop(x.host.take());
}

// spec/wire.md §11.2 write nonces, notes/client-port.md §1: a write in flight when the connection drops, across a restart: the caller's one answer is `OutcomeUnknown`, and nothing runs twice
#[test]
fn write_in_flight_across_a_restart_is_unknown() {
    let mut x = world();
    let mut cc = osis::internals::Opening::memory();
    cc.app.internals.transport = Some(x.net.endpoint("c1"));
    cc.app.internals.connection_wait = Some(W);
    let c = crate::common::block_on(osis::internals::connect(&x.nc, &x.secret, cc)).unwrap();
    let before = commits_of(&x.n, x.t);
    // the reply goes missing, the connection drops, and before a redial (at least 100 ms) the node
    // is gone: partition first so the redial cannot beat the restart
    x.n.port_panic_next(true);
    let (tx, rx) = channel();
    let (c2, t) = (c.clone(), x.t);
    let th = std::thread::spawn(move || {
        tx.send(()).unwrap();
        c2.commit_set(t, osis::DynamicAspectKey::untyped(title()), &s("maybe"))
    });
    rx.recv().unwrap();
    until("the node ran it", || commits_of(&x.n, t) == before + 1);
    x.net.partition("c1", "n");
    x.net.disconnect("c1", "n");
    let (net, store, addr, urls) = (x.net.clone(), x.n_store.clone(), x.addr.clone(), x.urls.clone());
    assert_eq!(std::mem::replace(&mut x.n, osis::internals::create(osis::internals::Opening::memory()).unwrap()).close().unwrap(), osis::Close::Closed);
    let n2 = osis::internals::open(cfg_on(&net, "n", &store, vec![addr])).unwrap();
    n2.client_listen(&urls).unwrap();
    net.heal("c1", "n");
    let r = th.join().unwrap();
    // unknown, or the redial beat the cut and the node's memory answered first
    assert!(matches!(&r, Err(Error::OutcomeUnknown)) || r.is_ok(), "{r:?}");
    assert_eq!(commits_of(&n2, t), before + 1, "not run twice");
    drop(x.host.take());
}

// spec/wire.md §11.2, notes/client-port.md §1: a write sent again and marked so, to a session the node holds nothing for (evicted, or never seen), is unknown: it may have run, never again; unmarked it is new; a marked one the node remembers has its first result
#[test]
fn resent_nonce_of_an_unknown_session_is_unknown() {
    use osis_proto::{Command, Outcome};
    const WRITE: u64 = 10;
    let x = world();
    let ep = x.net.endpoint("r");
    let mut raw = crate::port::Raw::over(&ep, osis_transport::Address { url: x.nc.url().to_string(), key: x.nc.key() });
    let a = raw.ask(Command::Auth { token: 0, session: [5; 16], secret: Some(osis_crypto::Secret32::from_bytes(*x.secret.expose())) }, 0);
    assert!(matches!(a, Ok(Outcome::Ok { .. })), "{a:?}");
    let resent = 1u64 << 62;
    let batch = |nonce: u64, v: &str| crate::port::set_write(nonce, x.actor, x.t, &title(), s(v));
    let unknown = |o: &Outcome| matches!(o, Outcome::Err { .. });
    let o = raw.call_at(1, WRITE, batch(1 | resent, "marked"));
    assert!(unknown(&o), "{o:?}");
    assert_eq!(x.n.at(x.t, osis::DynamicAspectKey::untyped(title())).get().unwrap(), Some(s("first")));
    // the session is known now: a later nonce is new, and marked it answers from memory
    let o = raw.call_at(2, WRITE, batch(2, "two"));
    assert!(matches!(o, Outcome::Ok { .. }), "{o:?}");
    let before = commits_of(&x.n, x.t);
    let again = raw.call_at(3, WRITE, batch(2 | resent, "two"));
    assert!(matches!(again, Outcome::Ok { .. }), "{again:?}");
    assert_eq!(commits_of(&x.n, x.t), before);
    drop(x.host);
}

// spec/sync.md §10, notes/client-port.md §1: schemas registered through a main-actor connection are registered again after a node restart, and watches come back over the unix socket
#[test]
fn main_reconnect_registers_schemas_again() {
    let d = std::env::temp_dir().join(format!("osis-sources-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    let sock = d.join("n.sock");
    let (net, store) = (osis_transport::Net::new(5), MemStore::new());
    let open = |create: bool| {
        let mut c = cfg_on(&net, "n", &store, vec![]);
        c.direct_sync = false;
        let db = if create { osis::internals::create(c).unwrap() } else { osis::internals::open(c).unwrap() };
        db.listen_socket_at(&sock).unwrap();
        db
    };
    let n = open(true);
    let c = crate::common::block_on(osis::internals::connect_socket(&sock, osis::internals::Opening::memory())).unwrap();
    let src = "revision 1;\naspect re:title.0: string;\n";
    c.register_schema("re.osis", src).unwrap();
    assert!(n.aspect_key("re:title.0").unwrap().schema().is_some());
    let mut w = c.write();
    let t = w.create().unwrap();
    w.at(t, osis::DynamicAspectKey::untyped(title())).set(&s("x")).unwrap();
    w.commit().unwrap();
    let watch = watched(&c, t, osis::DynamicAspectKey::untyped(title())).unwrap();
    assert_eq!(n.close().unwrap(), osis::Close::Closed);
    until("down", || !c.status().unwrap().node_connections[0].connected);
    let n = open(false);
    until("reconnected", || c.status().unwrap().node_connections[0].connected);
    c.settle();
    until("registered again", || n.aspect_key("re:title.0").unwrap().schema().is_some());
    until("the watch came back", || watch.current().ok().flatten() == Some(s("x")));
    let _ = std::fs::remove_dir_all(&d);
}

// spec/sync.md §10, notes/client-port.md §1: a write held across a drop gives up after `CONNECTION_WAIT` with no connection, with one answer: unknown
#[test]
fn write_in_flight_gives_up_after_connection_wait() {
    let x = world();
    let mut cc = osis::internals::Opening::memory();
    cc.app.internals.transport = Some(x.net.endpoint("c1"));
    cc.app.internals.connection_wait = Some(SHORT);
    let c = crate::common::block_on(osis::internals::connect(&x.nc, &x.secret, cc)).unwrap();
    let before = commits_of(&x.n, x.t);
    x.n.port_panic_next(true);
    let (c2, t) = (c.clone(), x.t);
    let th = std::thread::spawn(move || c2.commit_set(t, osis::DynamicAspectKey::untyped(title()), &s("maybe")));
    until("the node ran it", || commits_of(&x.n, t) == before + 1);
    x.net.partition("c1", "n");
    x.net.disconnect("c1", "n");
    let r = th.join().unwrap();
    // unknown, or the redial beat the cut and the node's memory answered; never Network, never twice
    assert_eq!(commits_of(&x.n, t), before + 1);
    assert!(matches!(&r, Err(Error::OutcomeUnknown)) || r.is_ok(), "{r:?}");
    drop(x.host);
}

// spec/sync.md §10, notes/client-port.md §5, N-B4: the client listener's key is its own: not the dialable key, the signing key, a host's or a LAN key; a rotate_reach leaves its clients connected; rotate_client_key ends them: an old-key client sees Network and connected: false, never reaches the new listener; a new address works; no URL shreds the key and a later listen has another
#[test]
fn client_listener_key_is_its_own() {
    let x = world();
    let c = x.thin("c1");
    let key = x.nc.key();
    // nor the node's signing key
    let node = x.n.node();
    let Some(osis::internals::CreationRecord::KeyActor { public_key, .. }) = x.n.engine(|e| e.core.created(&node).cloned()) else { panic!("a node is a key actor") };
    assert_ne!(public_key, key);
    let dialable = x.n.sync_engine(|s| s.dialable_secret());
    let own = |sec: &[u8; 32]| osis_transport::InProcess::public_key(&osis_transport::StaticSecret::from_bytes(*sec));
    assert_ne!(key, own(dialable.expose()));
    let lan = x.n.sync_engine(|s| s.lan_secret());
    assert_ne!(key, own(lan.expose()));
    assert_ne!(Some(key), x.n.serving_key().unwrap());
    assert_eq!(x.n.sync_engine(|s| s.client_listen_key()), Some(key));
    // rotate_reach: nothing changes for clients
    x.n.rotate_peer_address().unwrap();
    until("dialable key rotated", || own(x.n.sync_engine(|s| s.dialable_secret()).expose()) != own(dialable.expose()));
    assert_eq!(c.at(x.t, osis::DynamicAspectKey::untyped(title())).get().unwrap(), Some(s("first")));
    assert_eq!(x.n.sync_engine(|s| s.client_listen_key()), Some(key));
    // rotate_client_key: the old client is out for good
    let new = x.n.rotate_client_address().unwrap().remove(0);
    assert_ne!(new.key(), key);
    assert_ne!(new.key(), own(x.n.sync_engine(|s| s.dialable_secret()).expose()));
    until("old-key client down", || !c.status().unwrap().node_connections[0].connected);
    assert!(matches!(c.at(x.t, osis::DynamicAspectKey::untyped(title())).get(), Err(Error::Network(_))));
    std::thread::sleep(SHORT);
    assert!(matches!(c.at(x.t, osis::DynamicAspectKey::untyped(title())).get(), Err(Error::Network(_))));
    // same URL, new key: the old address cannot reach it, a new one can
    let mut cfg = osis::internals::Opening::memory();
    cfg.app.internals.transport = Some(x.net.endpoint("c2"));
    cfg.app.internals.connection_wait = Some(SHORT);
    assert!(matches!(crate::common::block_on(osis::internals::connect(&x.nc, &x.secret, cfg.clone())), Err(Error::Network(_))));
    cfg.app.internals.connection_wait = Some(W);
    let c2 = crate::common::block_on(osis::internals::connect(&new, &x.secret, cfg.clone())).unwrap();
    assert_eq!(c2.at(x.t, osis::DynamicAspectKey::untyped(title())).get().unwrap(), Some(s("first")));
    // no URL: stops, ends sessions, shreds
    assert!(x.n.client_listen(&[]).unwrap().is_empty());
    assert_eq!(x.n.sync_engine(|s| s.client_listen_key()), None);
    until("session ended", || !c2.status().unwrap().node_connections[0].connected);
    let again = x.n.client_listen(&x.urls).unwrap().remove(0);
    assert_ne!(again.key(), new.key());
    drop(x.host);
}

// spec/sync.md §10, notes/client-port.md §3: a bearer secret is only sent to the pinned key: an impostor at the node's URL under another key gets no session (the dial fails), and a unix address is refused before any dial
#[test]
fn bearer_secret_only_to_the_pinned_key() {
    let x = world();
    let mut cfg = osis::internals::Opening::memory();
    cfg.app.internals.transport = Some(x.net.endpoint("c1"));
    cfg.app.internals.connection_wait = Some(SHORT);
    let wrong = Address::new(&x.nc.url(), [9; 32]);
    assert!(matches!(crate::common::block_on(osis::internals::connect(&wrong, &x.secret, cfg.clone())), Err(Error::Network(_))));
    let unix = Address::new(&"unix:///tmp/x.sock".parse().unwrap(), x.nc.key());
    assert!(matches!(crate::common::block_on(osis::internals::connect(&unix, &x.secret, cfg)), Err(Error::Invalid(_))));
    drop(x.host);
}

// spec/sync.md §10, issues/cli-proxy.md: connect's wait for Hello has a deadline: a listener that takes the connection and never answers fails Network within `CONNECTION_WAIT`, not forever
#[test]
fn connect_to_a_silent_listener_ends() {
    let net = osis_transport::Net::new(4);
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(1).enable_all().build().unwrap();
    let sec = osis_transport::StaticSecret::from_bytes([3; 32]);
    let key = osis_transport::InProcess::public_key(&sec);
    let ep = net.endpoint("silent");
    let listener = rt.block_on(async { osis_transport::Transport::listen(&ep, osis_transport::ListenConfig { url: "mem://silent".into(), secret: sec }).await.unwrap() });
    // accepts and keeps every connection, says nothing
    rt.spawn(async move {
        let mut held = Vec::new();
        let mut l = listener;
        while let Ok(c) = osis_transport::Listener::accept(&mut l).await {
            held.push(c);
        }
    });
    let mut cfg = osis::internals::Opening::memory();
    cfg.app.internals.transport = Some(net.endpoint("c"));
    cfg.app.internals.connection_wait = Some(SHORT);
    let (tx, rx) = channel();
    let addr = Address::new(&"mem://silent".parse().unwrap(), key);
    std::thread::spawn(move || {
        tx.send(crate::common::block_on(osis::internals::connect(&addr, &ClientSecret::from_bytes([1; 32]), cfg)).map(drop)).unwrap();
    });
    let r = rx.recv_timeout(Duration::from_secs(30)).expect("connect never ended");
    assert!(matches!(r, Err(Error::Network(_))), "{r:?}");
}

// spec/sync.md §10, notes/client-port.md §6: osis::internals::Opening.node_connections without a store: every group at the node; two nodes as two actors are Invalid (one acting actor per process); with a store: the sources record survives a restart, without its attachment a group source fails Network (never the local copy), with it works again; status lists the source's node; a group whose source node was removed can go home
#[test]
fn config_connections_and_the_persisted_source() {
    let mut x = world();
    // no store
    let mut c = osis::internals::Opening::memory();
    c.app.internals.transport = Some(x.net.endpoint("c1"));
    c.app.internals.connection_wait = Some(W);
    let thin = crate::common::block_on(osis::internals::connect(&x.nc, &x.secret, c)).unwrap();
    assert_eq!(thin.me(), x.actor);
    assert_eq!(thin.at(x.t, osis::DynamicAspectKey::untyped(title())).get().unwrap(), Some(s("first")));
    assert!(matches!(block_on(thin.group_source(x.g, GroupSource::Local)), Err(Error::Unsupported(_))));
    assert!(matches!(crate::common::block_on(thin.connect_node(&NodeLogin { addr: x.nc.clone(), secret: x.secret.clone() })), Err(Error::Unsupported(_))));
    // a second client actor at the same node: two actors in one store-less process
    let (other, sec2) = x.n.add_client(None).unwrap();
    x.n.grant(x.g, other, Role::Read, Default::default()).unwrap();
    let mut c = osis::internals::Opening::memory();
    c.app.internals.transport = Some(x.net.endpoint("c2"));
    c.app.internals.connection_wait = Some(W);
    assert!(matches!(crate::common::block_on(osis::internals::connect_all(&[NodeLogin { addr: x.nc.clone(), secret: x.secret.clone() }, NodeLogin { addr: x.nc.clone(), secret: sec2 }], c)), Err(Error::Invalid(_))));
    // with a store: the record
    x.connect_p();
    x.to_node();
    x.set_n("n1");
    assert_eq!(x.p.at(x.t, osis::DynamicAspectKey::untyped(title())).get().unwrap(), Some(s("n1")));
    let (net, pstore, addr) = (x.net.clone(), x.p_store.clone(), x.addr.clone());
    assert_eq!(std::mem::replace(&mut x.p, osis::internals::create(osis::internals::Opening::memory()).unwrap()).close().unwrap(), osis::Close::Closed);
    // reopened without its node connection: Network, never the copy here
    let p2 = osis::internals::open(cfg_on(&net, "p", &pstore, vec![addr.clone()])).unwrap();
    assert_eq!(p2.group_sources().get(&x.g), Some(&x.nc));
    assert!(matches!(p2.at(x.t, osis::DynamicAspectKey::untyped(title())).get(), Err(Error::Network(_))));
    assert!(matches!(p2.commit_set(x.t, osis::DynamicAspectKey::untyped(title()), &s("z")), Err(Error::Network(_))));
    let st = p2.status().unwrap();
    assert_eq!(st.node_connections, vec![osis::NodeConnection { address: x.nc.clone(), connected: false }]);
    assert_eq!(p2.close().unwrap(), osis::Close::Closed);
    // reopened with it: the route works, nothing to redo
    let p3 = osis::internals::open(cfg_on(&net, "p", &pstore, vec![addr.clone()])).unwrap();
    crate::common::block_on(p3.connect_node(&NodeLogin { addr: x.nc.clone(), secret: x.secret.clone() })).unwrap();
    until("the connection came up", || p3.at(x.t, osis::DynamicAspectKey::untyped(title())).get().ok().flatten() == Some(s("n1")));
    assert_eq!(p3.close().unwrap(), osis::Close::Closed);
    // a route naming a node gone for good: home works with no node connection at all
    let p4 = osis::internals::open(cfg_on(&net, "p", &pstore, vec![addr])).unwrap();
    block_on(p4.group_source(x.g, GroupSource::Local)).unwrap();
    assert!(p4.group_sources().is_empty());
    assert_eq!(p4.at(x.t, osis::DynamicAspectKey::untyped(title())).get().unwrap(), Some(s("n1")));
    drop(x.host.take());
}

// spec/sync.md §10, notes/client-port.md §6, sources.rs invariant: a write decided Local and then overtaken by a move fails under its own lock: nothing lands in a group that no longer syncs here
#[test]
fn a_write_overtaken_by_a_move_fails() {
    let x = world();
    x.connect_p();
    let (p, g, addr) = (x.p.clone(), x.g, x.nc.clone());
    x.p.after_source(Box::new(move || {
        p.set_source(g, Some(addr.clone()));
        let _ = p.set_sync_options(g, osis::SyncOptions { mode: osis::SyncMode::LogOnly });
    }));
    let before = x.p_local_copy();
    let r = x.p.commit_set(x.t, osis::DynamicAspectKey::untyped(title()), &s("stranded?"));
    x.p.after_source(Box::new(|| {}));
    assert!(matches!(&r, Err(Error::Network(m)) if m.contains("moved")), "{r:?}");
    assert_eq!(x.p_local_copy(), before);
    drop(x.host);
}

// spec/sync.md §10, notes/client-port.md §3, §5 (networking tier: `cargo test -p osis --test it -- --ignored quic`): a thin client over real QUIC with bearer Auth: reads, writes, watches at the client listener; a wrong pinned key dials nothing; a wrong secret is refused; a node restart on the same port reconnects under the same key; a rotation strands the old address
#[test]
#[ignore]
fn thin_client_over_quic() {
    let store = MemStore::new();
    let open = |create: bool| {
        let mut c = osis::internals::Opening::at(Store::Memory(store.clone()));
        c.runtime = Runtime::Own;
                c.direct_sync = false;
        if create { osis::internals::create(c).unwrap() } else { osis::internals::open(c).unwrap() }
    };
    let n = open(true);
    let (g, t) = n.commit_with(|w| {
        let g = w.create()?;
        let t = w.create_with_admin(g)?;
        w.group(g).add(osis::Member::Item(t))?;
        w.at(t, osis::DynamicAspectKey::untyped(title())).set(&s("first"))?;
        Ok((g, t))
    }).unwrap();
    let (actor, secret) = n.add_client(None).unwrap();
    n.grant(g, actor, Role::Write, Default::default()).unwrap();
    let addr = n.client_listen(&["quic://127.0.0.1:0".parse().unwrap()]).unwrap().remove(0);
    assert!(addr.url().as_str().starts_with("quic://127.0.0.1:"), "{addr}");
    let mut cfg = osis::internals::Opening::memory();
        cfg.app.internals.connection_wait = Some(W);
    let c = crate::common::block_on(osis::internals::connect(&addr, &secret, cfg.clone())).unwrap();
    assert_eq!(c.me(), actor);
    assert_eq!(c.at(t, osis::DynamicAspectKey::untyped(title())).get().unwrap(), Some(s("first")));
    let watch = watched(&c, t, osis::DynamicAspectKey::untyped(title())).unwrap();
    c.commit_set(t, osis::DynamicAspectKey::untyped(title()), &s("from client")).unwrap();
    assert_eq!(n.at(t, osis::DynamicAspectKey::untyped(title())).get().unwrap(), Some(s("from client")));
    until("watch", || watch.current().ok().flatten() == Some(s("from client")));
    // an impostor key at the same URL: the handshake fails, no secret sent
    let mut short = cfg.clone();
    short.app.internals.connection_wait = Some(Duration::from_secs(3));
    assert!(matches!(crate::common::block_on(osis::internals::connect(&Address::new(&addr.url(), [8; 32]), &secret, short.clone())), Err(Error::Network(_))));
    assert!(matches!(crate::common::block_on(osis::internals::connect(&addr, &ClientSecret::from_bytes([1; 32]), short.clone())), Err(Error::Refused(_))));
    // restart on the same store and port: the same address, the session comes back
    assert_eq!(n.close().unwrap(), osis::Close::Closed);
    until("down", || !c.status().unwrap().node_connections[0].connected);
    assert!(matches!(c.at(t, osis::DynamicAspectKey::untyped(title())).get(), Err(Error::Network(_))));
    assert!(matches!(watch.current(), Err(Error::Network(_))));
    let n = open(false);
    assert_eq!(n.client_listen(&[addr.url()]).unwrap().remove(0), addr);
    until("reconnected", || c.status().unwrap().node_connections[0].connected);
    until("the watch came back", || watch.current().ok().flatten() == Some(s("from client")));
    c.commit_set(t, osis::DynamicAspectKey::untyped(title()), &s("again")).unwrap();
    assert_eq!(n.at(t, osis::DynamicAspectKey::untyped(title())).get().unwrap(), Some(s("again")));
    // a rotation: the old address never answers again
    let new = n.rotate_client_address().unwrap().remove(0);
    assert_ne!(new.key(), addr.key());
    assert_eq!(new.url(), addr.url());
    until("old-key client down", || !c.status().unwrap().node_connections[0].connected);
    assert!(matches!(crate::common::block_on(osis::internals::connect(&addr, &secret, short.clone())), Err(Error::Network(_))));
    assert_eq!(crate::common::block_on(osis::internals::connect(&new, &secret, cfg)).unwrap().at(t, osis::DynamicAspectKey::untyped(title())).get().unwrap(), Some(s("again")));
}

// spec/sync.md §10, issues/cli-proxy.md Transport slots: a flood of connections past the client listener's pending slots, each from a source of its own and never authenticating, neither drops an authenticated client (no error ever reached its watch) nor keeps a new one out
#[test]
fn a_flood_keeps_clients_in() {
    let x = world();
    let c = x.thin("c1");
    let (tx, rx) = channel();
    let _sub = c.at(x.t, osis::DynamicAspectKey::untyped(title())).on_change(move |_, ch| tx.send(ch.value.is_err()).unwrap()).unwrap();
    assert!(!rx.recv_timeout(W).unwrap());
    let slots = x.n.sync_engine(|s| s.config().client_pending);
    let addr = osis_transport::Address { url: x.nc.url().to_string(), key: x.nc.key() };
    let mut flood = Vec::new();
    for i in 0..slots + 8 {
        flood.push(crate::port::Raw::over(&x.net.endpoint(&format!("f{i}")), addr.clone()));
    }
    // none of it touched the client
    assert_eq!(c.at(x.t, osis::DynamicAspectKey::untyped(title())).get().unwrap(), Some(s("first")));
    assert!(rx.try_recv().is_err(), "the client's connection was dropped");
    assert!(c.status().unwrap().node_connections[0].connected);
    // a new client gets in during it
    assert_eq!(x.thin("c2").at(x.t, osis::DynamicAspectKey::untyped(title())).get().unwrap(), Some(s("first")));
    drop(flood);
    drop(x.host);
}

// spec/sync.md §10, notes/client-port.md §6: with several node connections a thing known here to none goes to the first that knows it; an unreachable earlier one stops the search: Network, not the later one's answer, so a write cannot land at a node chosen by who happens to be up
#[test]
fn several_node_connections_never_skip_a_down_one() {
    let x = world();
    // a second node, of another account, with a client for us, and a thing only it has
    let m = osis::internals::create(cfg_on(&x.net, "m", &MemStore::new(), vec![])).unwrap();
    let mc = m.client_listen(&["mem://m-clients".parse().unwrap()]).unwrap().remove(0);
    let (ma, msec) = m.add_client(None).unwrap();
    let mut w = m.write();
    let g = w.create().unwrap();
    let g2 = g;
    w.commit().unwrap();
    m.grant(g2, ma, Role::Write, Default::default()).unwrap();
    let mut w = m.write();
    let o = w.create_with_admin(g2).unwrap();
    w.group(g2).add(osis::Member::Item(o)).unwrap();
    w.at(o, osis::DynamicAspectKey::untyped(title())).set(&s("at m")).unwrap();
    let there = o;
    w.commit().unwrap();
    x.connect_p();
    crate::common::block_on(x.p.connect_node(&NodeLogin { addr: mc.clone(), secret: msec.clone() })).unwrap();
    assert_eq!(x.p.at(there, osis::DynamicAspectKey::untyped(title())).get().unwrap(), Some(s("at m")));
    x.p.commit_set(there, osis::DynamicAspectKey::untyped(title()), &s("from p")).unwrap();
    assert_eq!(m.at(there, osis::DynamicAspectKey::untyped(title())).get().unwrap(), Some(s("from p")));
    // the first node connection goes down: nothing is known about `there` at it any more
    x.net.partition("p", "n");
    x.net.disconnect("p", "n");
    until("down", || !x.p.status().unwrap().node_connections[0].connected);
    assert!(matches!(x.p.at(there, osis::DynamicAspectKey::untyped(title())).get(), Err(Error::Network(_))));
    assert!(matches!(x.p.commit_set(there, osis::DynamicAspectKey::untyped(title()), &s("wrong place?")), Err(Error::Network(_))));
    assert_eq!(m.at(there, osis::DynamicAspectKey::untyped(title())).get().unwrap(), Some(s("from p")));
    drop(x.host);
}

/// The next of a small deterministic stream.
struct Rng(u64);

impl Rng {
    fn next(&mut self, n: u64) -> u64 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        (self.0 >> 33) % n
    }
}

// spec/sync.md §10, notes/client-port.md §6, the invariant of core/osis/src/sources.rs: random groups, routes, syncs and node connections against a model of the rule: each call reaches exactly the source the model names, a value only from it, a write only to it, Network when that one is down, never another's answer
#[test]
fn routing_differential_against_a_model() {
    let refused: usize = [1, 2].into_iter().map(differential).sum();
    assert!(refused > 0, "the seeds wrote on no split thing");
}

/// Returns how many writes on a split thing were refused.
fn differential(seed: u64) -> usize {
    let x = world();
    let mut r = Rng(seed);
    // three groups and a thing per membership mix, every thing known on both sides, then the peer goes
    let mk = |n: usize| -> Vec<Tid> {
        x.n.commit_with(|w| {
            let mut v = Vec::new();
            for _ in 0..n {
                let g = w.create()?;
                v.push(g);
            }
            Ok(v)
        })
        .unwrap()
    };
    let gs = mk(3);
    for g in &gs {
        x.n.sync(*g, &[]).unwrap();
        x.n.grant(*g, x.actor, Role::Write, Default::default()).unwrap();
    }
    let mut things: Vec<(Tid, Vec<Tid>)> = Vec::new();
    for mask in 1u8..8 {
        let of: Vec<Tid> = gs.iter().enumerate().filter(|(i, _)| mask & (1 << i) != 0).map(|(_, g)| *g).collect();
        let mut w = x.n.write();
        let t = w.create_with_admin(of[0]).unwrap();
        for g in &of {
            w.group(*g).add(osis::Member::Item(t)).unwrap();
        }
        w.at(t, osis::DynamicAspectKey::untyped(title())).set(&s("start")).unwrap();
        w.commit().unwrap();
        things.push((t, of));
    }
    block_on(x.n.wait_synced(SyncScope::All)).unwrap();
    until("P has them", || {
        let _ = x.p.nudge_sync();
        things.iter().all(|(t, _)| x.p.at(*t, osis::DynamicAspectKey::untyped(title())).get().ok().flatten() == Some(s("start")))
    });
    block_on(x.p.wait_synced(SyncScope::All)).unwrap();
    // from here the two copies diverge: nothing moves between them but what the calls do
    x.net.partition("n", "s");
    x.net.partition("p", "s");
    x.net.disconnect("n", "s");
    x.net.disconnect("p", "s");
    let connect = || crate::common::block_on(x.p.connect_node(&NodeLogin { addr: x.nc.clone(), secret: x.secret.clone() })).unwrap();
    connect();
    let addr = x.nc.clone();
    // the model: the group's source, whether it syncs here, whether the node is connected; the value on each side
    let mut routed = [false; 3];
    let mut stopped = [false; 3];
    let mut connected = true;
    let mut local: Vec<String> = vec!["start".into(); things.len()];
    let mut at_node = local.clone();
    let mut refused = 0;
    let ix = |g: &Tid| gs.iter().position(|x| x == g).unwrap();
    for step in 0..120 {
        let which = r.next(things.len() as u64) as usize;
        let (t, of) = &things[which];
        // the rule, for a thing known here
        let via_node = of.iter().any(|g| routed[ix(g)]);
        // the groups other than the first admin only list it: only the first admin's label carries it
        let split = via_node && !routed[ix(&of[0])] && !stopped[ix(&of[0])];
        match r.next(10) {
            0 | 1 => {
                let i = r.next(3) as usize;
                routed[i] = !routed[i];
                x.p.set_source(gs[i], routed[i].then(|| addr.clone()));
            }
            2 => {
                let i = r.next(3) as usize;
                stopped[i] = !stopped[i];
                x.p.set_sync_options(gs[i], osis::SyncOptions { mode: if stopped[i] { osis::SyncMode::LogOnly } else { osis::SyncMode::Full } }).unwrap();
            }
            3 => {
                if connected {
                    assert!(x.p.disconnect_node(&x.nc).unwrap());
                } else {
                    connect();
                }
                connected = !connected;
            }
            4..=6 => {
                let v = format!("v{step}");
                let w = x.p.commit_set(*t, osis::DynamicAspectKey::untyped(title()), &s(&v));
                match (via_node, connected) {
                    _ if split => {
                        assert!(matches!(w, Err(Error::Invalid(_))), "step {step}: {w:?}");
                        refused += 1;
                    }
                    (false, _) => {
                        w.unwrap();
                        local[which] = v;
                    }
                    (true, true) => {
                        w.unwrap();
                        at_node[which] = v;
                    }
                    (true, false) => assert!(matches!(w, Err(Error::Network(_))), "step {step}: {w:?}"),
                }
            }
            _ => {
                let g = x.p.at(*t, osis::DynamicAspectKey::untyped(title())).get();
                match (via_node, connected) {
                    (false, _) => assert_eq!(g.unwrap(), Some(s(&local[which])), "step {step} seed {seed}: {which}"),
                    (true, true) => assert_eq!(g.unwrap(), Some(s(&at_node[which])), "step {step} seed {seed}: {which}"),
                    (true, false) => assert!(matches!(g, Err(Error::Network(_))), "step {step} seed {seed}: {g:?}"),
                }
            }
        }
        // each side holds only what the model says went there
        if step % 16 == 0 {
            for (i, (t, _)) in things.iter().enumerate() {
                assert_eq!(x.n.at(*t, osis::DynamicAspectKey::untyped(title())).get().unwrap(), Some(s(&at_node[i])), "step {step}");
                assert_eq!(x.p.engine(|e| e.get(t, &ak("note:title.0")).unwrap()), Some(s(&local[i])), "step {step}");
            }
        }
    }
    drop(x.host);
    refused
}

// spec/permissions.md §3, notes/client-port.md §6: lowering the role of a holder of a group this node reads at another node is refused: run here it would commit to a copy that no longer syncs, and the revocation would silently never leave
#[test]
fn lowering_a_role_on_a_routed_group_is_refused() {
    let x = world();
    x.connect_p();
    x.to_node();
    let (other, _) = x.n.add_client(None).unwrap();
    x.n.grant(x.g, other, Role::Read, Default::default()).unwrap();
    block_on(x.n.wait_synced(SyncScope::Thing(x.g))).unwrap();
    let d = SetRoleOpts::default();
    let r = x.p.set_role(x.g, x.actor, None, d);
    assert!(matches!(r, Err(Error::Unsupported(_))), "{r:?}");
    assert!(x.n.grants(x.g).unwrap().contains_key(&x.actor));
    assert!(x.p.engine(|e| e.roster(&x.g).contains_key(&x.actor)), "nothing written to the local copy");
    // a raise, and `grant` by its route: a thin client's connection carries neither (`method::for_client`)
    assert!(matches!(x.p.set_role(x.g, x.actor, Some(Role::Admin), d), Err(Error::Unsupported(_))));
    assert!(matches!(x.p.grant(x.g, x.actor, Role::Admin, Default::default()), Err(Error::Unsupported(_))));
    drop(x.host);
}

// spec/sync.md §10, notes/client-port.md §6: a sharing flow decided Local and overtaken by a move fails under its commit's lock: a grant or revocation never sits unsent in a group that stopped syncing here
#[test]
fn a_sharing_flow_overtaken_by_a_move_fails() {
    let x = world();
    x.connect_p();
    let (other, _) = x.n.add_client(None).unwrap();
    until("P knows the other client", || {
        let _ = x.p.nudge_sync();
        x.p.engine(|e| e.knows(&other))
    });
    let (p, g, addr) = (x.p.clone(), x.g, x.nc.clone());
    // the grant's own step, past `source_write`
    let calls = std::sync::atomic::AtomicUsize::new(0);
    x.p.after_source(Box::new(move || {
        if calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 1 {
            p.set_source(g, Some(addr.clone()));
            let _ = p.set_sync_options(g, osis::SyncOptions { mode: osis::SyncMode::LogOnly });
        }
    }));
    let roster = x.p.engine(|e| e.roster(&x.g).len());
    let r = x.p.grant(x.g, other, Role::Read, Default::default());
    x.p.after_source(Box::new(|| {}));
    assert!(matches!(&r, Err(Error::Network(m)) if m.contains("moved")), "{r:?}");
    assert_eq!(x.p.engine(|e| e.roster(&x.g).len()), roster, "nothing written");
    drop(x.host);
}

// spec/wire.md §11.2: a resent write the node does not remember, in a session whose state it lost, never runs, also after the first such resend recreated the session's entry: two writes that ran, then lost state, are two unknowns
#[test]
fn every_resent_nonce_of_a_lost_session_is_unknown() {
    use osis_proto::{Command, Outcome};
    const WRITE: u64 = 10;
    let x = world();
    let ep = x.net.endpoint("r");
    let mut raw = crate::port::Raw::over(&ep, osis_transport::Address { url: x.nc.url().to_string(), key: x.nc.key() });
    let a = raw.ask(Command::Auth { token: 0, session: [6; 16], secret: Some(osis_crypto::Secret32::from_bytes(*x.secret.expose())) }, 0);
    assert!(matches!(a, Ok(Outcome::Ok { .. })), "{a:?}");
    let resent = 1u64 << 62;
    let batch = |nonce: u64, v: &str| crate::port::set_write(nonce, x.actor, x.t, &title(), s(v));
    let before = commits_of(&x.n, x.t);
    for (i, n) in [7u64, 8, 9].into_iter().enumerate() {
        let o = raw.call_at(1 + i as u64, WRITE, batch(n | resent, "ran before the state went"));
        assert!(matches!(o, Outcome::Err { .. }), "{n}: {o:?}");
    }
    assert_eq!(commits_of(&x.n, x.t), before, "none ran again");
    // later writes are new
    let o = raw.call_at(9, WRITE, batch(10, "new"));
    assert!(matches!(o, Outcome::Ok { .. }), "{o:?}");
    drop(x.host);
}

// spec/wire.md §11.2 (a thing the actor may not read answers as one the node does not know), notes/client-port.md §3: a move of a group ends a client's watch of what it reads there, while its watch of a thing it never could read stays as silent as one of an unknown tid
#[test]
fn a_move_tells_a_client_nothing_of_what_it_never_read() {
    let x = world();
    let (_, sec) = x.p.add_client(None).unwrap();
    let pc = x.p.client_listen(&["mem://p-clients".parse().unwrap()]).unwrap().remove(0);
    let mut c = osis::internals::Opening::memory();
    c.app.internals.transport = Some(x.net.endpoint("pc"));
    let client = crate::common::block_on(osis::internals::connect(&pc, &sec, c)).unwrap();
    assert_eq!(client.at(x.t, osis::DynamicAspectKey::untyped(title())).get().unwrap(), None);
    let w = watched(&client, x.t, osis::DynamicAspectKey::untyped(title())).unwrap();
    x.connect_p();
    x.to_node();
    client.settle();
    assert_eq!(w.current().unwrap(), None);
    drop(x.host);
}

// spec/sync.md §10, notes/client-port.md §6, §3: while a group's move home catches up, the node's own clients read nothing of it: the route stands, the copy here is behind
#[test]
fn a_nodes_client_reads_nothing_during_the_catch_up() {
    let x = world_waiting(Duration::from_millis(300));
    let (a, sec) = x.p.add_client(None).unwrap();
    x.p.grant(x.g, a, Role::Read, Default::default()).unwrap();
    block_on(x.p.wait_synced(SyncScope::Thing(x.g))).unwrap();
    let pc = x.p.client_listen(&["mem://p-clients".parse().unwrap()]).unwrap().remove(0);
    let mut c = osis::internals::Opening::memory();
    c.app.internals.transport = Some(x.net.endpoint("pc"));
    let client = crate::common::block_on(osis::internals::connect(&pc, &sec, c)).unwrap();
    x.connect_p();
    x.to_node();
    x.set_n("newer");
    x.net.partition("p", "s");
    x.net.disconnect("p", "s");
    assert!(x.move_group(x.g, GroupSource::Local).is_err());
    assert!(x.p.sync_options(x.g).unwrap().mode != osis::SyncMode::LogOnly, "syncing again, behind");
    assert_eq!(x.p.group_sources().get(&x.g), Some(&x.nc));
    assert_eq!(client.at(x.t, osis::DynamicAspectKey::untyped(title())).get().unwrap(), None, "a stale value, as if current");
    drop(x.host);
}

// spec/sync.md §10, notes/client-port.md §1 Reconnect: a watch of a thing started while the node is down fails `Network`, and works once it is up.
#[test]
fn a_watch_started_while_down_fails_and_works_once_up() {
    let x = world();
    x.connect_p();
    x.to_node();
    x.net.partition("p", "n");
    x.net.disconnect("p", "n");
    until("down", || !x.p.status().unwrap().node_connections[0].connected);
    assert!(matches!(x.p.on_thing_change(x.t, |_, _| {}), Err(Error::Network(_))));
    x.net.heal("p", "n");
    until("up", || x.p.status().unwrap().node_connections[0].connected);
    let (tx, rx) = channel();
    let _sub = x.p.on_thing_change(x.t, move |_, ch| {
        let _ = tx.send(ch.value.clone());
    }).unwrap();
    loop {
        if rx.recv_timeout(W).unwrap() == Ok(Some(s("first"))) {
            break;
        }
    }
    drop(x.host);
}

// spec/sync.md §10, notes/client-port.md §8: the port worker never waits on another node: a main-actor call on a routed group answers at once, so one silent node holds no other client of this node
#[test]
fn a_silent_node_holds_no_client_of_this_node() {
    let x = world();
    x.connect_p();
    x.to_node();
    let d = std::env::temp_dir().join(format!("osis-sources-silent-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    let sock = d.join("p.sock");
    x.p.listen_socket_at(&sock).unwrap();
    let o1 = crate::common::block_on(osis::internals::connect_socket(&sock, osis::internals::Opening::memory())).unwrap();
    let o2 = crate::common::block_on(osis::internals::connect_socket(&sock, osis::internals::Opening::memory())).unwrap();
    let mut w = x.p.write();
    let t = w.create().unwrap();
    w.group(x.p.home()).add(osis::Member::Item(t)).unwrap();
    w.at(t, osis::DynamicAspectKey::untyped(title())).set(&s("mine")).unwrap();
    let mine = t;
    w.commit().unwrap();
    // silent: no close, nothing answers
    x.net.partition("p", "n");
    let (tx, rx) = channel();
    let t = x.t;
    std::thread::spawn(move || {
        let r = o1.at(t, osis::DynamicAspectKey::untyped(title())).get();
        tx.send(r).unwrap();
    });
    let r = rx.recv_timeout(W).expect("the worker waits on the node");
    assert!(matches!(r, Err(Error::Unsupported(_))), "{r:?}");
    assert!(matches!(o2.at(t, osis::DynamicAspectKey::untyped(title())).writes(&crate::common::page(osis::CommitFrom::Newest, 1)), Err(Error::Unsupported(_))), "a listing too: this node's copy is stale");
    let (tx, rx) = channel();
    std::thread::spawn(move || {
        tx.send((o2.at(mine, osis::DynamicAspectKey::untyped(title())).get(), o2.status().map(|s| s.node_connections.len()))).unwrap();
    });
    let (v, _) = rx.recv_timeout(W).expect("another client is held");
    assert_eq!(v.unwrap(), Some(s("mine")));
    let _ = std::fs::remove_dir_all(&d);
    drop(x.host);
}

// spec/sync.md §10, notes/client-port.md §1, §6: a differential of `group_source` with the peer up: random real moves, drops and lost replies against a model holding every value a write may have left: a read never shows an older acknowledged value through a settled route, no write is applied twice, a failed move changes no source; a thing in a second group that carries it refuses writes while routed (no write acknowledged and silently never sent), and a thing added to a second group while routed still reads there
#[test]
fn group_source_differential_against_a_model() {
    let (mut refused, mut added) = (0, 0);
    for seed in [11, 12, 13] {
        let (r, p) = moves_differential(seed);
        refused += r;
        added += p;
    }
    assert!(refused > 0 && added > 0, "the seeds reached neither: {refused} refused, {added} added while routed");
}

/// One thing of the differential: the last acknowledged value and later ones of unknown outcome.
struct Tracked {
    t: Tid,
    acked: String,
    maybe: Vec<String>,
    ok: usize,
    unknown: usize,
}

fn tracked(t: Tid) -> Tracked {
    Tracked { t, acked: "first".into(), maybe: Vec::new(), ok: 0, unknown: 0 }
}

/// Returns how many writes on the split thing were refused, and whether a thing was added while routed.
fn moves_differential(seed: u64) -> (usize, usize) {
    let x = world_waiting(Duration::from_millis(600));
    // a second synced group H: `both` is carried by it too, `added` is only added there later
    let h = x.n.commit_with(|w| {
        let h = w.create()?;
        Ok(h)
    }).unwrap();
    x.n.sync(h, &[]).unwrap();
    let thing = || x.n.commit_with(|w| {
        let t = w.create_with_admin(x.g)?;
        w.group(x.g).add(osis::Member::Item(t))?;
        w.at(t, osis::DynamicAspectKey::untyped(title())).set(&s("first"))?;
        Ok(t)
    }).unwrap();
    let (both, added) = (thing(), thing());
    x.n.add_with_grant(Member::Item(both), h, Role::Write).unwrap();
    block_on(x.n.wait_synced(SyncScope::All)).unwrap();
    until("P has them", || {
        let _ = x.p.nudge_sync();
        x.p.at(both, osis::DynamicAspectKey::untyped(title())).get().ok().flatten() == Some(s("first")) && x.p.at(added, osis::DynamicAspectKey::untyped(title())).get().ok().flatten() == Some(s("first")) && x.p.engine(|e| e.groups_of(&both).contains(&h))
    });
    x.connect_p();
    let mut r = Rng(seed);
    // writes on `both` are only ever made here, and refused while routed
    let mut both_acked = "first".to_string();
    let mut things = [tracked(x.t), tracked(added)];
    let count = count_key(&[&x.n, &x.p]);
    let mut at_node = false;
    let mut cut = false;
    let mut is_added = false;
    let mut refused = 0;
    for step in 0..60 {
        let which = r.next(2) as usize;
        let m = &mut things[which];
        match r.next(13) {
            0 | 1 if !cut => {
                let to = if at_node { GroupSource::Local } else { GroupSource::Node(x.nc.clone()) };
                match x.move_group(x.g, to) {
                    Ok(()) => at_node = !at_node,
                    Err(e) => assert!(matches!(e, Error::Network(_) | Error::Unsynced { .. }), "step {step}: {e:?}"),
                }
                assert_eq!(x.p.group_sources().contains_key(&x.g), at_node, "step {step}: the table says where it is");
            }
            2 => {
                if cut {
                    x.net.heal("p", "n");
                } else {
                    x.net.partition("p", "n");
                    x.net.disconnect("p", "n");
                }
                cut = !cut;
                if !cut {
                    until("reconnected", || x.p.status().unwrap().node_connections[0].connected);
                } else {
                    until("down", || !x.p.status().unwrap().node_connections[0].connected);
                }
            }
            3 if at_node && !cut => x.n.port_panic_next(r.next(2) == 0),
            4..=6 => {
                let v = format!("v{step}");
                let write = x.p.commit_with(|w| {
                    w.at(m.t, count.clone()).path(osis::Path::root()).contribute(&1i64)?;
                    w.at(m.t, osis::DynamicAspectKey::untyped(title())).set(&s(&v))
                });
                match write {
                    Ok(_) => {
                        m.acked = v;
                        m.maybe.clear();
                        m.ok += 1;
                    }
                    Err(Error::Network(_)) => assert!(at_node, "step {step}: Network from this engine"),
                    Err(Error::OutcomeUnknown) => {
                        m.maybe.push(v);
                        m.unknown += 1;
                    }
                    Err(e) => panic!("step {step}: {e:?}"),
                }
            }
            7 if !at_node => {
                let v = format!("b{step}");
                x.p.commit_set(both, osis::DynamicAspectKey::untyped(title()), &s(&v)).unwrap();
                both_acked = v;
            }
            8 if !at_node => assert_eq!(x.p.at(both, osis::DynamicAspectKey::untyped(title())).get().unwrap(), Some(s(&both_acked)), "step {step} seed {seed}"),
            // no grant: H does not carry it, so nothing is split, and a read stays where it was
            9 if at_node && !is_added => {
                let mut w = x.p.write();
                w.group(h).add(osis::Member::Item(added)).unwrap();
                w.commit().unwrap();
                is_added = true;
            }
            _ => match x.p.at(m.t, osis::DynamicAspectKey::untyped(title())).get() {
                Ok(Some(Value::Str(v))) => {
                    if at_node {
                        // the node may not have pulled what this node uploaded before moving: wait
                        until("the node's copy caught up", || {
                            let _ = x.n.nudge_sync();
                            let now = x.p.at(m.t, osis::DynamicAspectKey::untyped(title())).get().unwrap();
                            now == Some(s(&m.acked)) || m.maybe.iter().any(|y| now == Some(s(y)))
                        });
                    } else {
                        assert!(v == m.acked || m.maybe.contains(&v), "step {step} seed {seed}: read {v}, acked {}, maybe {:?}", m.acked, m.maybe);
                    }
                    if m.maybe.contains(&v) {
                        m.acked = v;
                        m.maybe.clear();
                    }
                }
                Ok(o) => panic!("step {step}: {o:?}"),
                Err(Error::Network(_)) => assert!(at_node, "step {step}: Network from this engine"),
                Err(e) => panic!("step {step}: {e:?}"),
            },
        }
        // after every step, while routed: `both` refuses a write, which would miss H; both of the
        // second-group things read at the node, never this engine's copy
        if at_node {
            let v = format!("refused{step}");
            let write = x.p.commit_set(both, osis::DynamicAspectKey::untyped(title()), &s(&v));
            assert!(matches!(write, Err(Error::Invalid(_))), "step {step} seed {seed}: a write through the route misses H: {write:?}");
            refused += 1;
            assert!(x.p.status().unwrap().two_sources.contains(&both), "step {step}");
            assert!(!x.p.status().unwrap().two_sources.contains(&added), "step {step}: H does not carry it");
            let read = x.p.at(both, osis::DynamicAspectKey::untyped(title())).get();
            if cut {
                assert!(matches!(read, Err(Error::Network(_))), "step {step} seed {seed}: this engine's copy answered: {read:?}");
            } else {
                let m = &things[1];
                until("the node's copies caught up", || {
                    let _ = x.n.nudge_sync();
                    let at = |t| x.p.at(t, osis::DynamicAspectKey::untyped(title())).get().ok().flatten();
                    at(both) == Some(s(&both_acked)) && (at(added) == Some(s(&m.acked)) || m.maybe.iter().any(|y| at(added) == Some(s(y))))
                });
            }
        }
    }
    if cut {
        x.net.heal("p", "n");
    }
    // exactly once: the count adds every write that applied, at either source
    for m in &things {
        let applied = || match x.n.at(m.t, count.clone()).get().unwrap() {
            Some(Value::Int(n)) => n as usize,
            _ => 0,
        };
        until("every acknowledged write reached N", || {
            let _ = x.p.nudge_sync();
            let _ = x.n.nudge_sync();
            applied() >= m.ok
        });
        assert!(applied() <= m.ok + m.unknown, "seed {seed}: a write applied twice: {} of {} + {}", applied(), m.ok, m.unknown);
    }
    // nothing acknowledged on `both` stayed on this node
    until("every acknowledged write on `both` reached N", || {
        let _ = x.p.nudge_sync();
        let _ = x.n.nudge_sync();
        x.n.at(both, osis::DynamicAspectKey::untyped(title())).get().unwrap() == Some(s(&both_acked))
    });
    drop(x.host);
    (refused, is_added as usize)
}

/// A group of the account, synced on P.
fn second_group(x: &World) -> Tid {
    let mut w = x.p.write();
    let h = w.create().unwrap();
    w.at(h, osis::DynamicAspectKey::untyped(ak("t:made.0"))).set(&Value::Bool(true)).unwrap();
    w.commit().unwrap();
    x.p.sync(h, &[]).unwrap();
    block_on(x.p.wait_synced(SyncScope::Thing(h))).unwrap();
    h
}

/// A node W of another account syncing G only, with write from N; has `t` once this returns.
fn third_node(x: &World) -> Osis {
    let w_db = osis::internals::create(cfg_on(&x.net, "w", &MemStore::new(), vec![x.addr.clone()])).unwrap();
    let card = w_db.contact_card().unwrap();
    block_on(w_db.wait_synced(SyncScope::All)).unwrap();
    let who = block_on(x.n.import_contact(&card)).unwrap();
    x.n.grant(x.g, who, Role::Write, Default::default()).unwrap();
    block_on(x.n.wait_synced(SyncScope::All)).unwrap();
    until("W has t", || {
        let _ = w_db.nudge_sync();
        for i in w_db.invite_requests().unwrap() {
            let _ = w_db.accept_invite(i);
        }
        w_db.at(x.t, osis::DynamicAspectKey::untyped(title())).get().ok().flatten() == Some(s("first"))
    });
    w_db
}

// spec/sync.md §2, §10: a routed thing given its own sync ID by a grant elsewhere keeps its one source:
// the node holding the route syncs that ID too, so writes through it reach every holder
#[test]
fn a_routed_thing_given_its_own_sync_id_is_not_split() {
    let x = world();
    x.connect_p();
    x.to_node();
    x.p.commit_set(x.t, osis::DynamicAspectKey::untyped(title()), &s("acked")).unwrap();
    let (actor, _) = x.n.add_client(None).unwrap();
    x.n.grant(x.t, actor, Role::Read, Default::default()).unwrap();
    block_on(x.n.wait_synced(SyncScope::Thing(x.t))).unwrap();
    until("P knows its sync ID", || {
        let _ = x.p.nudge_sync();
        x.p.engine(|e| e.group_labels(&x.t).unwrap().len() == 1)
    });
    assert!(x.p.status().unwrap().two_sources.is_empty(), "no second source");
    x.p.commit_set(x.t, osis::DynamicAspectKey::untyped(title()), &s("again")).unwrap();
    drop(x.host);
}

// spec/sync.md §10, the invariant of core/osis/src/sources.rs: `t` in routed G and in H, which carries it and syncs here: reads go through the route and see what only G carries; a write is refused, not acknowledged and left missing G's or H's other holders; `status` lists it; home again it writes, and every holder gets it
#[test]
fn a_split_thing_reads_at_the_route_and_refuses_writes() {
    let x = world();
    let w_db = third_node(&x);
    let h = second_group(&x);
    x.p.add_with_grant(Member::Item(x.t), h, Role::Write).unwrap();
    block_on(x.p.wait_synced(SyncScope::Thing(h))).unwrap();
    x.connect_p();
    x.to_node();
    assert_eq!(x.p.status().unwrap().two_sources.iter().copied().collect::<Vec<_>>(), vec![x.t]);
    // what only G carries: W syncs G alone
    w_db.commit_with(|w| w.at(x.t, osis::DynamicAspectKey::untyped(title())).set(&s("from w"))).unwrap();
    block_on(w_db.wait_synced(SyncScope::All)).unwrap();
    until("N has W's write", || {
        let _ = x.n.nudge_sync();
        x.n.at(x.t, osis::DynamicAspectKey::untyped(title())).get().unwrap() == Some(s("from w"))
    });
    assert_eq!(x.p.at(x.t, osis::DynamicAspectKey::untyped(title())).get().unwrap(), Some(s("from w")), "the route answers");
    let r = x.p.commit_set(x.t, osis::DynamicAspectKey::untyped(title()), &s("from p"));
    assert!(matches!(r, Err(Error::Invalid(_))), "{r:?}");
    assert!(matches!(x.p.grant(x.t, x.actor, Role::Read, Default::default()), Err(Error::Invalid(_))));
    assert_eq!(x.n.at(x.t, osis::DynamicAspectKey::untyped(title())).get().unwrap(), Some(s("from w")), "nothing written");
    // other things of G are not split
    x.p.commit_set(x.g, osis::DynamicAspectKey::untyped(title()), &s("on g")).unwrap();
    assert_eq!(x.n.at(x.g, osis::DynamicAspectKey::untyped(title())).get().unwrap(), Some(s("on g")));
    // home: no split left, and the write reaches W through G
    block_on(x.n.wait_synced(SyncScope::Thing(x.g))).unwrap();
    x.move_group(x.g, GroupSource::Local).unwrap();
    assert!(x.p.status().unwrap().two_sources.is_empty());
    x.p.commit_set(x.t, osis::DynamicAspectKey::untyped(title()), &s("from p")).unwrap();
    block_on(x.p.wait_synced(SyncScope::Thing(x.t))).unwrap();
    until("W and N have it", || {
        let _ = w_db.nudge_sync();
        let _ = x.n.nudge_sync();
        w_db.at(x.t, osis::DynamicAspectKey::untyped(title())).get().unwrap() == Some(s("from p")) && x.n.at(x.t, osis::DynamicAspectKey::untyped(title())).get().unwrap() == Some(s("from p"))
    });
    drop(x.host);
}

// spec/sync.md §10: a split can arrive from elsewhere, where nothing could refuse it: another holder of H shares routed `t` into H; reads stay where they were, the next write here says why it is refused, and `status` shows it
#[test]
fn a_split_arriving_from_another_node_refuses_the_next_write() {
    let x = world();
    let h = second_group(&x);
    until("N has H", || {
        let _ = x.n.nudge_sync();
        x.n.has_content(h).unwrap() && x.n.status().unwrap().groups.contains_key(&h)
    });
    x.connect_p();
    x.to_node();
    x.p.commit_set(x.t, osis::DynamicAspectKey::untyped(title()), &s("acked")).unwrap();
    assert!(x.p.status().unwrap().two_sources.is_empty());
    x.n.add_with_grant(Member::Item(x.t), h, Role::Write).unwrap();
    block_on(x.n.wait_synced(SyncScope::Thing(h))).unwrap();
    until("P learnt it through H", || {
        let _ = x.p.nudge_sync();
        x.p.status().unwrap().two_sources.contains(&x.t)
    });
    assert_eq!(x.p.at(x.t, osis::DynamicAspectKey::untyped(title())).get().unwrap(), Some(s("acked")));
    let r = x.p.commit_set(x.t, osis::DynamicAspectKey::untyped(title()), &s("again"));
    let Err(Error::Invalid(why)) = r else { panic!("{r:?}") };
    assert!(why.contains(&h.to_string()) && why.contains(&x.g.to_string()), "{why}");
    drop(x.host);
}

// spec/sync.md §10: adding a routed thing to a group synced here changes no source: a write acknowledged through the route does not read as gone; with no grant H does not carry it, so writes go on
#[test]
fn adding_a_routed_thing_to_a_local_group_changes_nothing() {
    let x = world();
    let h = second_group(&x);
    x.connect_p();
    x.to_node();
    x.p.commit_set(x.t, osis::DynamicAspectKey::untyped(title()), &s("acked")).unwrap();
    assert_eq!(x.p_local_copy(), Some(s("first")));
    let mut w = x.p.write();
    w.group(h).add(osis::Member::Item(x.t)).unwrap();
    w.commit().unwrap();
    assert_eq!(x.p.at(x.t, osis::DynamicAspectKey::untyped(title())).get().unwrap(), Some(s("acked")));
    assert!(x.p.status().unwrap().two_sources.is_empty());
    x.p.commit_set(x.t, osis::DynamicAspectKey::untyped(title()), &s("again")).unwrap();
    assert_eq!(x.n.at(x.t, osis::DynamicAspectKey::untyped(title())).get().unwrap(), Some(s("again")));
    // with a tied grant it would be split: refused, two sources
    assert!(matches!(x.p.add_with_grant(Member::Item(x.t), h, Role::Read), Err(Error::Invalid(_))));
    drop(x.host);
}

// spec/sync.md §10, notes/client-port.md §8: a client of this node reads no copy of a routed thing, even one a local group still feeds
#[test]
fn a_client_of_this_node_reads_no_split_thing() {
    let x = world();
    let h = second_group(&x);
    x.p.add_with_grant(Member::Item(x.t), h, Role::Write).unwrap();
    let (a, _) = x.p.add_client(None).unwrap();
    x.p.grant(x.t, a, Role::Read, Default::default()).unwrap();
    assert!(x.p.engine(|e| e.readable_by(&a, &x.t)));
    x.connect_p();
    x.to_node();
    assert!(!x.p.engine(|e| e.readable_by(&a, &x.t)));
    drop(x.host);
}

// spec/sync.md §10, notes/client-port.md §3: what routing asks answers for a thing the client's actor may not read exactly as for a tid nobody knows: no existence oracle.
#[test]
fn routing_to_what_the_actor_may_not_read_is_as_to_nothing() {
    let x = world();
    x.connect_p();
    let mut w = x.n.write();
    let t = w.create().unwrap();
    w.at(t, osis::DynamicAspectKey::untyped(title())).set(&s("not for the client")).unwrap();
    let hidden = t;
    w.commit().unwrap();
    x.n.sync(hidden, &[]).unwrap();
    let ghost = osis::Tid::from_bytes([9; 15]);
    assert_eq!(x.move_group(hidden, GroupSource::Node(x.nc.clone())), Err(Error::UnknownThing { tid: hidden }));
    assert_eq!(x.move_group(ghost, GroupSource::Node(x.nc.clone())), Err(Error::UnknownThing { tid: ghost }));
    assert!(x.p.group_sources().is_empty());
    drop(x.host);
}

// spec/wire.md §11.2, notes/client-port.md §2: a serving address's sessions answer the client port's kinds with protocol Error 11: `Refused`, and the connect does not retry.
#[test]
fn a_serving_address_refuses_a_client() {
    let x = world();
    let mut c = osis::internals::Opening::memory();
    c.app.internals.transport = Some(x.net.endpoint("at-host"));
    c.app.internals.connection_wait = Some(W);
    let r = crate::common::block_on(osis::internals::connect(&x.addr, &x.secret, c));
    assert!(matches!(&r, Err(Error::Refused(m)) if m.contains("client port")), "{:?}", r.map(|_| ()));
    drop(x.host);
}

// spec/sync.md §10, notes/client-port.md §6 Moving: a group with no content yet is held at the node all the same: it can be moved there, though `has_content` reads `false`.
#[test]
fn an_empty_group_at_the_node_can_be_routed_to() {
    let x = world();
    x.connect_p();
    let mut w = x.n.write();
    let e = w.create().unwrap();
    w.commit().unwrap();
    x.n.sync(e, &[]).unwrap();
    x.n.grant(e, x.actor, Role::Read, Default::default()).unwrap();
    let c = x.thin("c9");
    assert!(!c.has_content(e).unwrap(), "no content: the premise");
    x.move_group(e, GroupSource::Node(x.nc.clone())).unwrap();
    assert_eq!(x.p.group_sources().get(&e), Some(&x.nc));
    drop(x.host);
}

// spec/sync.md §10, notes/client-port.md §6 Moving: a write landing after the move's wait ended, before the move takes the lock, is waited for too: no `Unsynced`, no stranded write
#[test]
fn a_move_waits_again_for_a_write_after_its_wait() {
    use std::future::Future;
    use std::task::{Context, Poll, Waker};
    let x = world();
    x.connect_p();
    let key = || osis::DynamicAspectKey::untyped(title());
    x.net.partition("p", "s");
    x.p.commit_set(x.t, key(), &s("one")).unwrap();
    let mut mv = Box::pin(x.p.group_source(x.g, GroupSource::Node(x.nc.clone())));
    let mut cx = Context::from_waker(Waker::noop());
    // polled by hand: the wait ends under the lock, the move only goes on at the next poll
    let end = Instant::now() + W;
    while x.p.waiting() != 1 {
        assert!(mv.as_mut().poll(&mut cx).is_pending());
        assert!(Instant::now() < end, "the move never began its wait");
        std::thread::sleep(Duration::from_millis(5));
    }
    x.net.heal("p", "s");
    until("the move's wait ended", || x.p.waiting() == 0);
    x.net.partition("p", "s");
    x.p.commit_set(x.t, key(), &s("two")).unwrap();
    let r = mv.as_mut().poll(&mut cx);
    assert!(matches!(r, Poll::Pending), "{r:?}");
    assert_eq!(x.p.waiting(), 1, "waiting again");
    assert!(x.p.group_sources().is_empty(), "not moved yet");
    x.net.heal("p", "s");
    block_on(mv).unwrap();
    assert_eq!(x.p.group_sources().get(&x.g), Some(&x.nc));
    until("the write reached the node", || x.n.at(x.t, key()).get().ok().flatten() == Some(s("two")));
    drop(x.host);
}

// spec/sync.md §10, notes/client-port.md §6 Moving: a group held here without a live label comes home: this engine's role decides (the route would ask the node, where the client's actor reads nothing of it), and its first label is written while the route still stands
#[test]
fn a_group_without_a_label_here_comes_home() {
    let x = world();
    x.connect_p();
    let mut w = x.p.write();
    let h = w.create().unwrap();
    w.commit().unwrap();
    x.p.set_source(h, Some(x.nc.clone()));
    x.move_group(h, GroupSource::Local).unwrap();
    assert!(x.p.group_sources().is_empty());
    assert!(x.p.status().unwrap().groups.contains_key(&h));
    drop(x.host);
}

// spec/data-model.md §9, notes/client-port.md §3, §6: removing a client granted on a group this node reads at another node ends its sessions and refuses the role removal rather than commit it to a copy that does not sync; home again, the same call finishes
#[test]
fn removing_a_client_of_a_routed_group_waits_for_it_to_come_home() {
    let x = world();
    let (a, _sec) = x.p.add_client(None).unwrap();
    x.p.grant(x.g, a, Role::Read, Default::default()).unwrap();
    block_on(x.p.wait_synced(SyncScope::Thing(x.g))).unwrap();
    x.connect_p();
    x.to_node();
    let r = x.p.remove_client(a);
    assert!(matches!(r, Err(Error::Unsupported(_))), "{r:?}");
    assert!(x.p.engine(|e| e.roster(&x.g).contains_key(&a)), "nothing written to the local copy");
    assert!(x.p.clients().unwrap().iter().any(|c| c.actor == a), "the entry stays, ended, for the retry");
    block_on(x.n.wait_synced(SyncScope::Thing(x.g))).unwrap();
    x.move_group(x.g, GroupSource::Local).unwrap();
    assert!(x.p.remove_client(a).unwrap());
    assert!(!x.p.engine(|e| e.roster(&x.g).contains_key(&a)));
    drop(x.host);
}

// spec/sync.md §10, notes/client-port.md §1 Reconnect: `watch_status` and `on_diagnostic` need no answer to start: started while the node is down, the first tells so, the second is quiet, and both come up with the connection. A roster watch losing its connection says so, and shows the roster again.
#[test]
fn status_and_diagnostic_watches_started_while_down_come_up() {
    let x = world();
    let c = x.thin("c1");
    let (tx, rx) = channel();
    let _r = c.on_grants_change(x.g, move |_, r| {
        let _ = tx.send(r);
    }).unwrap();
    assert!(rx.recv_timeout(W).unwrap().unwrap().contains_key(&x.actor));
    x.net.partition("c1", "n");
    x.net.disconnect("c1", "n");
    until("down", || c.at(x.t, osis::DynamicAspectKey::untyped(title())).get().is_err());
    assert!(matches!(rx.recv_timeout(W).unwrap(), Err(Error::Network(_))), "the lost connection is told");
    assert!(matches!(c.on_grants_change(x.g, |_, _| {}), Err(Error::Network(_))));
    let (st, sr) = channel();
    let _st = c.on_status_change(move |_, s| {
        let _ = st.send(s.unwrap().node_connections[0].connected);
    }).unwrap();
    assert!(!sr.recv_timeout(W).unwrap(), "down, and says so");
    let (dt, dr) = channel();
    let _d = c.on_diagnostic(move |_, d| {
        let _ = dt.send(d.to_string());
    }).unwrap();
    assert!(dr.recv_timeout(SHORT).is_err(), "quiet while down");
    x.net.heal("c1", "n");
    let first = rx.recv_timeout(W).unwrap().unwrap();
    assert!(first.contains_key(&x.actor));
    while !sr.recv_timeout(W).unwrap() {}
    until("the diagnostics subscription is live", || c.at(x.t, osis::DynamicAspectKey::untyped(title())).get().is_ok());
    c.settle();
    let t = x.t;
    x.n.engine(|e| e.report(osis_node::Diagnostic { kind: osis_node::DiagnosticKind::BadInput, tids: vec![t], commit: None, peer: None, detail: "after the reconnect".into() }));
    assert_eq!(dr.recv_timeout(W).unwrap(), "handled: BadInput: after the reconnect");
    assert!(rx.recv_timeout(SHORT).is_err(), "one roster, no second delivery");
    drop(x.host);
}

// spec/wire.md §9, spec/sync.md §3: a share into a second group sends an inbox blob about the thing,
// which names no group's label: moving the first group away and home finds its label free.
#[test]
fn moving_home_after_a_grant_to_a_second_group() {
    let x = world();
    // sorting after g: a thing's first group by tid was the one named
    let h = loop {
        let mut w = x.p.write();
        let h = w.create().unwrap();
        w.commit().unwrap();
        if h > x.g {
            break h;
        }
    };
    x.p.sync(h, &[]).unwrap();
    block_on(x.p.wait_synced(SyncScope::Thing(h))).unwrap();
    x.p.add_with_grant(Member::Item(x.t), h, Role::Write).unwrap();
    block_on(x.p.wait_synced(SyncScope::Thing(h))).unwrap();
    // the blob opened here before the group stops syncing
    until("the share's inbox blob opened at P", || {
        let _ = x.p.nudge_sync();
        x.p.sync_engine(|e| {
            let labels: Vec<_> = e.labels().into_iter().map(|(_, l)| l.id).collect();
            labels.iter().any(|l| e.entries(l).iter().any(|(_, k)| matches!(k, osis::internals::node::sync::EntryKind::Inbox(Some(_)))))
        })
    });
    x.connect_p();
    x.to_node();
    x.move_group(x.g, GroupSource::Local).unwrap();
    assert!(x.p.group_sources().is_empty());
    drop(x.host);
}

// spec/sync.md §10: undo and revert refuse what they would write on a split thing, also when the call names only the routed group, or a commit this engine never held
#[test]
fn undo_and_revert_refuse_a_split_thing_they_cannot_name() {
    let x = world();
    let h = second_group(&x);
    until("N has H", || {
        let _ = x.n.nudge_sync();
        x.n.has_content(h).unwrap() && x.n.status().unwrap().groups.contains_key(&h)
    });
    x.connect_p();
    x.to_node();
    x.p.commit_set(x.t, osis::DynamicAspectKey::untyped(title()), &s("acked")).unwrap();
    // a commit this engine never holds, of a thing that stays out of H: it cannot tell
    let mut w = x.p.write();
    w.at(x.g, osis::DynamicAspectKey::untyped(title())).set(&s("on g")).unwrap();
    let c = w.commit().unwrap().unwrap();
    x.n.add_with_grant(Member::Item(x.t), h, Role::Write).unwrap();
    block_on(x.n.wait_synced(SyncScope::Thing(h))).unwrap();
    until("P learnt it through H", || {
        let _ = x.p.nudge_sync();
        x.p.status().unwrap().two_sources.contains(&x.t)
    });
    let r = x.p.undo(&osis::Scope::Group(x.g));
    assert!(matches!(r, Err(Error::Invalid(_))), "{r:?}");
    assert!(!x.p.engine(|e| e.header(&c.stamp.id.raw()).is_some()));
    let r = x.p.revert(c.stamp.id);
    assert!(matches!(r, Err(Error::Invalid(_))), "{r:?}");
    assert_eq!(x.n.at(x.t, osis::DynamicAspectKey::untyped(title())).get().unwrap(), Some(s("acked")), "nothing written");
    assert_eq!(x.n.at(x.g, osis::DynamicAspectKey::untyped(title())).get().unwrap(), Some(s("on g")), "nothing written");
    drop(x.host);
}

// spec/sync.md §10, notes/client-port.md §6, cli `status`: a process connected to the node as its main actor sees what the node's status lists as split; so does a reopened node, whose routes come from its record
#[test]
fn split_shows_through_the_port_and_after_a_restart() {
    let mut x = world();
    let h = second_group(&x);
    x.p.add_with_grant(Member::Item(x.t), h, Role::Write).unwrap();
    block_on(x.p.wait_synced(SyncScope::Thing(h))).unwrap();
    x.connect_p();
    x.to_node();
    let d = std::env::temp_dir().join(format!("osis-sources-split-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    let sock = d.join("p.sock");
    x.p.listen_socket_at(&sock).unwrap();
    let o = crate::common::block_on(osis::internals::connect_socket(&sock, osis::internals::Opening::memory())).unwrap();
    assert!(o.status().unwrap().two_sources.contains(&x.t));
    let r = o.commit_set(x.t, osis::DynamicAspectKey::untyped(title()), &s("via main"));
    assert!(matches!(r, Err(Error::Invalid(_))), "{r:?}");
    drop(o);
    let (net, pstore, addr) = (x.net.clone(), x.p_store.clone(), x.addr.clone());
    assert_eq!(std::mem::replace(&mut x.p, osis::internals::create(osis::internals::Opening::memory()).unwrap()).close().unwrap(), osis::Close::Closed);
    let p = osis::internals::open(cfg_on(&net, "p", &pstore, vec![addr])).unwrap();
    crate::common::block_on(p.connect_node(&NodeLogin { addr: x.nc.clone(), secret: x.secret.clone() })).unwrap();
    assert!(p.status().unwrap().two_sources.contains(&x.t));
    let r = p.commit_set(x.t, osis::DynamicAspectKey::untyped(title()), &s("reopened"));
    assert!(matches!(r, Err(Error::Invalid(_))), "{r:?}");
    until("the connection came up", || p.at(x.t, osis::DynamicAspectKey::untyped(title())).get().ok().flatten() == Some(s("first")));
    assert_eq!(p.close().unwrap(), osis::Close::Closed);
    let _ = std::fs::remove_dir_all(&d);
    drop(x.host);
}

// spec/sync.md §10, the invariant of core/osis/src/sources.rs: a move landing between a write's route and its split check: the check sees the route, so a write that would miss H's other holders is refused, not sent where the route it never saw leads
#[test]
fn a_split_made_after_the_route_refuses_the_write() {
    let x = world();
    let h = second_group(&x);
    x.p.add_with_grant(Member::Item(x.t), h, Role::Write).unwrap();
    block_on(x.p.wait_synced(SyncScope::Thing(h))).unwrap();
    x.connect_p();
    let (p, g, addr) = (x.p.clone(), x.g, x.nc.clone());
    x.p.after_source(Box::new(move || {
        p.set_source(g, Some(addr.clone()));
        let _ = p.set_sync_options(g, osis::SyncOptions { mode: osis::SyncMode::LogOnly });
    }));
    let r = x.p.commit_set(x.t, osis::DynamicAspectKey::untyped(title()), &s("late"));
    x.p.after_source(Box::new(|| {}));
    assert!(matches!(r, Err(Error::Invalid(_))), "{r:?}");
    assert_eq!(x.n.at(x.t, osis::DynamicAspectKey::untyped(title())).get().unwrap(), Some(s("first")), "nothing written");
    drop(x.host);
}

// spec/sync.md §10, notes/arbitrary-values.md, notes/client-port.md §1: `CONNECTION_WAIT`, as a test sets it: at 0 nothing connects, `Network`; long, it works as any
#[test]
fn connecting_at_zero_and_infinity() {
    let x = world();
    let at = |t: Duration, ep: &str| {
        let mut c = osis::internals::Opening::memory();
        c.app.internals.transport = Some(x.net.endpoint(ep));
        c.app.internals.connection_wait = Some(t);
        crate::common::block_on(osis::internals::connect(&x.nc, &x.secret, c))
    };
    assert!(matches!(at(Duration::ZERO, "z0"), Err(Error::Network(_))));
    let c = at(Duration::from_secs(3600), "z1").unwrap();
    assert_eq!(c.me(), x.actor);
    assert!(!c.has_store() && x.p.has_store());
    assert_eq!(c.at(x.t, osis::DynamicAspectKey::untyped(title())).get().unwrap(), Some(s("first")));
    crate::common::block_on(x.p.connect_node(&NodeLogin { addr: x.nc.clone(), secret: x.secret.clone() })).unwrap();
    drop(x.host);
}

// spec/sync.md §10, notes/client-port.md §6: a login names its secret: a new secret after a rotation connects at the first call, and a live connection by another secret is `Invalid`, never silently kept as someone else's
#[test]
fn connect_node_takes_a_new_secret_and_refuses_a_second_login() {
    let x = world();
    x.connect_p();
    let (_other, other) = x.n.add_client(None).unwrap();
    let second = NodeLogin { addr: x.nc.clone(), secret: other };
    assert!(matches!(crate::common::block_on(x.p.connect_node(&second)), Err(Error::Invalid(_))));
    assert!(x.p.status().unwrap().node_connections[0].connected, "the connection stands");
    let new = x.n.rotate_client_secret(x.actor).unwrap();
    until("the old session ended", || !x.p.status().unwrap().node_connections[0].connected);
    crate::common::block_on(x.p.connect_node(&NodeLogin { addr: x.nc.clone(), secret: new })).unwrap();
    assert_eq!(x.p.status().unwrap().node_connections, vec![osis::NodeConnection { address: x.nc.clone(), connected: true }]);
    drop(x.host);
}

// spec/sync.md §10, notes/client-port.md §6: a node's connection to a node that is down is `Ok`, `status` says it is down, and it keeps trying; a refused secret keeps nothing; a thing known nowhere here then answers there
#[test]
fn connect_node_keeps_trying_a_node_that_is_down() {
    let x = world();
    let login = NodeLogin { addr: x.nc.clone(), secret: x.secret.clone() };
    x.net.partition("p", "n");
    crate::common::block_on(x.p.connect_node(&login)).unwrap();
    assert_eq!(x.p.status().unwrap().node_connections, vec![osis::NodeConnection { address: x.nc.clone(), connected: false }]);
    crate::common::block_on(x.p.connect_node(&login)).unwrap();
    x.net.heal("p", "n");
    until("up", || x.p.status().unwrap().node_connections[0].connected);
    crate::common::block_on(x.p.connect_node(&login)).unwrap();
    assert!(x.p.disconnect_node(&x.nc).unwrap());
    assert!(!x.p.disconnect_node(&x.nc).unwrap());
    let wrong = NodeLogin { addr: x.nc.clone(), secret: ClientSecret::from_bytes([9; 32]) };
    assert!(matches!(crate::common::block_on(x.p.connect_node(&wrong)), Err(Error::Refused(_))));
    assert!(x.p.status().unwrap().node_connections.is_empty(), "nothing stays");
    drop(x.host);
}

// spec: none (API surface); notes/client-port.md §6: `disconnect_node` ends the connection for whoever holds it: a move home waiting for the node to upload hears it is gone and goes on without it
#[test]
fn disconnecting_ends_a_wait_on_the_node() {
    let x = world();
    x.connect_p();
    x.to_node();
    x.net.partition("n", "s");
    x.net.disconnect("n", "s");
    x.p.commit_set(x.t, osis::DynamicAspectKey::untyped(title()), &s("only at n")).unwrap();
    let (tx, rx) = channel();
    let (p, g) = (x.p.clone(), x.g);
    std::thread::spawn(move || {
        let _ = tx.send(block_on(p.group_source(g, GroupSource::Local)));
    });
    assert!(rx.recv_timeout(Duration::from_millis(300)).is_err(), "the node has not uploaded");
    assert!(x.p.disconnect_node(&x.nc).unwrap());
    rx.recv_timeout(W).expect("still waiting on a node disconnected").unwrap();
    assert!(x.p.group_sources().is_empty());
    drop(x.host);
}

// spec: none (API surface); notes/api.md Design rules, a future gives up when dropped: a node that says nothing does not hold up a caller's timeout
#[test]
fn giving_up_a_move_needs_no_answer_from_the_node() {
    let x = world_waiting(Duration::from_millis(300));
    x.connect_p();
    let (release, released) = channel::<()>();
    let (held_tx, held) = channel();
    let n = x.n.clone();
    let holder = std::thread::spawn(move || {
        n.engine(|_| {
            held_tx.send(()).unwrap();
            let _ = released.recv_timeout(W);
        })
    });
    held.recv().unwrap();
    let r = x.move_group(x.g, GroupSource::Node(x.nc.clone()));
    assert!(release.send(()).is_ok(), "the caller's timeout had to wait for the node");
    holder.join().unwrap();
    assert!(matches!(r, Err(Error::Network(_))), "{r:?}");
    assert!(x.p.group_sources().is_empty());
    drop(x.host);
}
