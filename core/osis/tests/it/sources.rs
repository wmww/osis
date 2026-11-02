//! Sources per group (notes/client-port.md §1, §5, §6): routing, moving a group, reconnects, the
//! client listener. Two devices P and N of one person sync through a host; P attaches to N's client
//! listener as a thin client whose actor N minted.

use crate::common::{ak, block_on};
use osis::internals::Internals as _;
use osis::{ClientSecret, Config, Error, GroupSource, HostAddr, MemStore, Osis, RemoteConfig, Role, Runtime, StoreAt, SyncScope, SyncState, Tid, Transport, Value};
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

fn cfg_on(net: &osis_transport::Net, ep: &str, store: &MemStore, hosts: Vec<HostAddr>) -> Config {
    let mut c = Config::at(StoreAt::Memory(store.clone()));
    c.runtime = Runtime::Own;
    c.transport = Some(Transport::InProcess(net.endpoint(ep)));
    c.hosts = hosts;
    c.wait_timeout = W;
    // no co-reader sessions: N and P meet only through the host, and through the client port
    c.peers = false;
    c
}

/// Keeps the host running; `n`, `p` two devices of a person, a group `g` of it with a thing `t`,
/// both synced; `nc` N's client address, `secret` a client with `Write` on `g`.
struct World {
    net: osis_transport::Net,
    host: Option<Osis>,
    n: Osis,
    n_store: MemStore,
    p: Osis,
    p_store: MemStore,
    addr: HostAddr,
    nc: HostAddr,
    urls: Vec<String>,
    secret: ClientSecret,
    actor: Tid,
    g: Tid,
    t: Tid,
}

fn title() -> osis::Ak {
    ak("note:title.0")
}

fn world() -> World {
    world_waiting(W)
}

/// `p_wait`: P's `Config::wait_timeout`.
fn world_waiting(p_wait: Duration) -> World {
    let net = osis_transport::Net::new(3);
    let mut hc = cfg_on(&net, "s", &MemStore::new(), vec![]);
    hc.peers = false;
    let host = Osis::create(hc).unwrap().0;
    host.set_hosting(Some(osis::Hosting { listen: vec!["mem://s".into()], admit: osis::Admit::Open, ..Default::default() })).unwrap();
    until("host address", || host.host_address().unwrap().is_some());
    let addr = host.host_address().unwrap().unwrap();
    let (n_store, p_store) = (MemStore::new(), MemStore::new());
    let n = Osis::create(cfg_on(&net, "n", &n_store, vec![addr.clone()])).unwrap().0;
    let mut pc = cfg_on(&net, "p", &p_store, vec![addr.clone()]);
    pc.wait_timeout = p_wait;
    let joining = Osis::pair(pc, &n.pair_offer().unwrap()).unwrap();
    let (_, reply) = n.pair_accept(joining.request()).unwrap();
    let p = joining.finish(&reply).unwrap();
    let (g, t) = n
        .write_with(|w| {
            let g = w.create(n.me())?;
            w.make_group(g)?;
            let t = w.create(g)?;
            w.place(t, g)?;
            w.at(t, title()).set(&Value::Str("first".into()))?;
            Ok((g, t))
        })
        .unwrap();
    n.sync(g, &[]).unwrap();
    let (actor, secret) = n.add_client(None).unwrap();
    n.grant(g, actor, Role::Write, Default::default()).unwrap();
    block_on(n.wait_synced(SyncScope::Group(g), W)).unwrap();
    let urls = vec!["mem://n-clients".to_string()];
    let nc = n.client_listen(&urls).unwrap().remove(0);
    until("P has the group", || {
        let _ = p.sync_now();
        p.get(t, title()).ok().flatten() == Some(Value::Str("first".into()))
    });
    World { net, host: Some(host), n, n_store, p, p_store, addr, nc, urls, secret, actor, g, t }
}

fn s(x: &str) -> Value {
    Value::Str(x.into())
}

impl World {
    fn attach_p(&self) {
        let c = cfg_on(&self.net, "p", &MemStore::new(), vec![]);
        self.p.attach_node(&self.nc, &self.secret, &c).unwrap();
    }

    fn to_remote(&self) {
        block_on(self.p.group_source(self.g, GroupSource::Remote(self.nc.clone()))).unwrap();
    }

    fn thin(&self, ep: &str) -> Osis {
        let mut c = Config::memory();
        c.transport = Some(Transport::InProcess(self.net.endpoint(ep)));
        c.wait_timeout = W;
        Osis::attach_client(&self.nc, &self.secret, c).unwrap()
    }

    fn p_local_copy(&self) -> Option<Value> {
        self.p.engine(|e| e.get(&self.t, &ak("note:title.0")).unwrap())
    }

    fn set_n(&self, v: &str) {
        self.n.write_with(|w| w.at(self.t, title()).set(&s(v))).unwrap();
    }
}

// spec/sync.md §10, notes/client-port.md §6: a group synced here is local whatever a remote also offers; a thing known only at the attached node goes there; with the node unreachable the local thing still reads and the remote one fails Network
#[test]
fn local_wins_and_unknown_goes_to_the_node() {
    let x = world();
    x.attach_p();
    // only at N, in the group the client may read, not synced to P yet (N is cut from the host)
    x.net.partition("n", "s");
    let only_n = x.n.write_with(|w| {
        let o = w.create(x.g)?;
        w.place(o, x.g)?;
        w.at(o, title()).set(&s("at n"))?;
        Ok(o)
    }).unwrap();
    x.set_n("n's");
    // local wins: P reads its own synced copy, not N's newer one
    assert_eq!(x.p.get(x.t, title()).unwrap(), Some(s("first")));
    // known here nowhere: the attachment answers
    assert_eq!(x.p.get(only_n, title()).unwrap(), Some(s("at n")));
    assert!(!x.p.engine(|e| e.knows(&only_n)));
    // a write to it goes there, not here
    x.p.write_with(|w| w.at(only_n, title()).set(&s("from p"))).unwrap();
    assert_eq!(x.n.get(only_n, title()).unwrap(), Some(s("from p")));
    assert!(!x.p.engine(|e| e.knows(&only_n)));
    // a batch over both sources is refused, nothing written
    assert!(matches!(x.p.write_with(|w| { w.at(only_n, title()).set(&s("a"))?; w.at(x.t, title()).set(&s("b")) }), Err(Error::Invalid(_))));
    assert_eq!(x.n.get(only_n, title()).unwrap(), Some(s("from p")));
    assert_eq!(x.p.get(x.t, title()).unwrap(), Some(s("first")));
    // down: local goes on, remote is Network, never UnknownThing and never a local answer
    x.net.partition("p", "n");
    x.net.disconnect("p", "n");
    until("attachment down", || !x.p.status().unwrap().remotes[0].connected);
    assert_eq!(x.p.get(x.t, title()).unwrap(), Some(s("first")));
    assert!(matches!(x.p.get(only_n, title()), Err(Error::Network(_))));
    assert!(matches!(x.p.write_with(|w| w.at(only_n, title()).set(&s("z"))), Err(Error::Network(_))));
    assert!(!x.p.engine(|e| e.knows(&only_n)));
    drop(x.host);
}

// spec/sync.md §10, notes/client-port.md §6 Moving: to Remote this node stops syncing for itself alone (N keeps syncing: the group's label is not replaced), reads and writes go to N at once, P's copy stays and is not read; back to Local it catches up before calls come home; a move refused changes nothing
#[test]
fn moving_a_group_both_ways() {
    let x = world();
    x.attach_p();
    // not attached, unknown there: refused, nothing changed
    let ghost = HostAddr::new("mem://nobody", [7; 32]);
    assert!(matches!(block_on(x.p.group_source(x.g, GroupSource::Remote(ghost))), Err(Error::Invalid(_))));
    assert!(matches!(block_on(x.p.group_source(x.p.me(), GroupSource::Remote(x.nc.clone()))), Err(Error::Invalid(_))));
    assert!(x.p.routes().is_empty());
    x.to_remote();
    assert_eq!(x.p.routes().get(&x.g), Some(&x.nc.to_string()));
    assert!(x.p.group_policy(x.g).unwrap().receipts_only);
    // only for P: N's label lives and syncs
    block_on(x.n.wait_synced(SyncScope::Group(x.g), W)).unwrap();
    until("N synced", || x.n.status().unwrap().groups[&x.g].state == SyncState::Synced);
    // N's write reads at P at once, P's own copy unchanged
    x.set_n("n1");
    assert_eq!(x.p.get(x.t, title()).unwrap(), Some(s("n1")));
    assert_eq!(x.p_local_copy(), Some(s("first")));
    // P's write lands at N, not in P's copy
    x.p.write_with(|w| w.at(x.t, title()).set(&s("p1"))).unwrap();
    assert_eq!(x.n.get(x.t, title()).unwrap(), Some(s("p1")));
    assert_eq!(x.p_local_copy(), Some(s("first")));
    // a new thing in the routed group is made there; this engine never hears of it
    let made = x.p.write_with(|w| {
        let o = w.create(x.g)?;
        w.place(o, x.g)?;
        w.at(o, title()).set(&s("made through p"))?;
        Ok(o)
    }).unwrap();
    assert_eq!(x.n.get(made, title()).unwrap(), Some(s("made through p")));
    assert!(!x.p.engine(|e| e.knows(&made)));
    assert_eq!(x.p.get(made, title()).unwrap(), Some(s("made through p")));
    // merged status: the node's state for the routed group, the attachment up
    until("the node's state shows", || x.p.status().unwrap().groups[&x.g].state == SyncState::Synced);
    assert!(x.p.status().unwrap().remotes[0].connected);
    // a transaction over this engine would read the stale copy: refused
    assert!(matches!(x.p.read(|r| r.value(x.t, &ak("note:title.0"))), Err(Error::Unsupported(_))));
    // home: nothing left to catch up with a host gone is a failure that keeps the route
    block_on(x.n.wait_synced(SyncScope::Group(x.g), W)).unwrap();
    block_on(x.p.group_source(x.g, GroupSource::Local)).unwrap();
    assert!(x.p.routes().is_empty());
    assert!(!(x.p.group_policy(x.g).unwrap().receipts_only));
    // what P wrote through N is here: no stale read after the move
    assert_eq!(x.p.get(x.t, title()).unwrap(), Some(s("p1")));
    assert_eq!(x.p_local_copy(), Some(s("p1")));
    // and P's own writes sync again
    x.p.write_with(|w| w.at(x.t, title()).set(&s("p2"))).unwrap();
    block_on(x.p.wait_synced(SyncScope::Group(x.g), W)).unwrap();
    until("N got P's write", || {
        let _ = x.n.sync_now();
        x.n.get(x.t, title()).unwrap() == Some(s("p2"))
    });
    drop(x.host);
}

// spec/sync.md §10, notes/client-port.md §6: a holder that unsyncs a group for everyone (N's `unsync` replaces the label): P, which routes nothing, keeps reading and writing its own copy and says so in status (no fallback to N though N is attached); N's own clients read N's copy, its authority; a later move to N needs no upload wait, there is nothing to upload to
#[test]
fn a_node_unsyncing_a_group_a_process_thinks_is_local() {
    let x = world();
    x.attach_p();
    let c = x.thin("c1");
    x.n.unsync(x.g).unwrap();
    until("P saw the label replaced", || {
        let _ = x.n.sync_now();
        let _ = x.p.sync_now();
        !x.p.engine(|e| e.labels_of(&x.g).iter().any(|l| !l.replaced))
    });
    x.set_n("n after unsync");
    assert_eq!(x.p.get(x.t, title()).unwrap(), Some(s("first")), "still P's, not a fallback");
    x.p.write_with(|w| w.at(x.t, title()).set(&s("p after unsync"))).unwrap();
    assert_eq!(x.p_local_copy(), Some(s("p after unsync")));
    assert_eq!(x.n.get(x.t, title()).unwrap(), Some(s("n after unsync")));
    assert_eq!(c.get(x.t, title()).unwrap(), Some(s("n after unsync")));
    x.to_remote();
    assert_eq!(x.p.get(x.t, title()).unwrap(), Some(s("n after unsync")));
    drop(x.host);
}

// spec/sync.md §10, notes/client-port.md §6: moves with writes pending on either side refuse, changing nothing, and each write stays where it is readable: a local write not yet at a host holds the move away; going home while this engine cannot catch up, or while the node holds a write no host has, keeps the route, so calls still go to the node and the local copy never answers behind
#[test]
fn moves_with_pending_writes_refuse() {
    let x = world_waiting(Duration::from_millis(300));
    x.attach_p();
    x.net.partition("p", "s");
    x.net.disconnect("p", "s");
    x.p.write_with(|w| w.at(x.t, title()).set(&s("pending"))).unwrap();
    let r = block_on(x.p.group_source(x.g, GroupSource::Remote(x.nc.clone())));
    assert!(matches!(r, Err(Error::Network(_) | Error::Unsynced { .. })), "{r:?}");
    assert!(x.p.routes().is_empty());
    assert!(!x.p.group_policy(x.g).unwrap().receipts_only);
    assert_eq!(x.p.get(x.t, title()).unwrap(), Some(s("pending")));
    // another world: away with nothing pending, then home with P cut from the host
    let x = world_waiting(Duration::from_millis(300));
    x.attach_p();
    x.to_remote();
    x.set_n("newer");
    x.net.partition("p", "s");
    x.net.disconnect("p", "s");
    let r = block_on(x.p.group_source(x.g, GroupSource::Local));
    assert!(r.is_err(), "{r:?}");
    assert_eq!(x.p.routes().get(&x.g), Some(&x.nc.to_string()));
    assert_eq!(x.p.get(x.t, title()).unwrap(), Some(s("newer")), "the route stays until caught up");
    assert_eq!(x.p_local_copy(), Some(s("first")));
    // another: home while only the node holds a write
    let x = world_waiting(Duration::from_millis(300));
    x.attach_p();
    x.to_remote();
    x.net.partition("n", "s");
    x.net.disconnect("n", "s");
    x.p.write_with(|w| w.at(x.t, title()).set(&s("only at n"))).unwrap();
    let r = block_on(x.p.group_source(x.g, GroupSource::Local));
    assert!(matches!(r, Err(Error::Network(_))), "{r:?}");
    assert_eq!(x.p.routes().get(&x.g), Some(&x.nc.to_string()));
    assert_eq!(x.p.get(x.t, title()).unwrap(), Some(s("only at n")), "still at the node");
    drop(x.host);
}

// spec/sync.md §10, notes/client-port.md §6: the same moves finish once the link heals, and no write was lost (tier 2: each heal waits a sync retry, 5 s)
#[test]
#[ignore]
fn moves_with_pending_writes_finish_after_healing() {
    let x = world_waiting(Duration::from_secs(1));
    x.attach_p();
    x.net.partition("p", "s");
    x.net.disconnect("p", "s");
    x.p.write_with(|w| w.at(x.t, title()).set(&s("pending"))).unwrap();
    assert!(block_on(x.p.group_source(x.g, GroupSource::Remote(x.nc.clone()))).is_err());
    x.net.heal("p", "s");
    until("the pending write reaches N", || {
        let _ = x.p.sync_now();
        let _ = x.n.sync_now();
        x.n.get(x.t, title()).unwrap() == Some(s("pending"))
    });
    block_on(x.p.wait_synced(SyncScope::Group(x.g), W)).unwrap();
    x.to_remote();
    x.set_n("newer");
    x.net.partition("p", "s");
    x.net.disconnect("p", "s");
    assert!(block_on(x.p.group_source(x.g, GroupSource::Local)).is_err());
    x.net.heal("p", "s");
    until("moved after P caught up", || {
        let _ = x.p.sync_now();
        block_on(x.p.group_source(x.g, GroupSource::Local)).is_ok()
    });
    assert_eq!(x.p.get(x.t, title()).unwrap(), Some(s("newer")));
    x.to_remote();
    x.net.partition("n", "s");
    x.net.disconnect("n", "s");
    x.p.write_with(|w| w.at(x.t, title()).set(&s("only at n"))).unwrap();
    assert!(block_on(x.p.group_source(x.g, GroupSource::Local)).is_err());
    x.net.heal("n", "s");
    until("home with the write", || {
        let _ = x.n.sync_now();
        let _ = x.p.sync_now();
        block_on(x.p.group_source(x.g, GroupSource::Local)).is_ok()
    });
    assert_eq!(x.p.get(x.t, title()).unwrap(), Some(s("only at n")));
    drop(x.host);
}

// spec/sync.md §10, notes/client-port.md §6 Offline: a disconnected remote fails Network at once, with no stale value from the copy this node still holds, no write to it; a Watch reads Err(Network) while down; status says connected: false; a new watch fails too; moving home still works with the node gone
#[test]
fn disconnected_remote_is_network_never_stale() {
    let x = world();
    x.attach_p();
    x.to_remote();
    let watch = x.p.at(x.t, title()).watch().unwrap();
    x.set_n("seen");
    until("watch", || watch.current().ok().flatten() == Some(s("seen")));
    x.net.partition("p", "n");
    x.net.disconnect("p", "n");
    until("down", || !x.p.status().unwrap().remotes[0].connected);
    assert!(x.p_local_copy().is_some());
    assert!(matches!(x.p.get(x.t, title()), Err(Error::Network(_))));
    assert!(matches!(x.p.at(x.t, title()).get_value(), Err(Error::Network(_))));
    assert!(matches!(x.p.aspects(x.t), Err(Error::Network(_))));
    assert!(matches!(x.p.at(x.t, title()).watch(), Err(Error::Network(_))));
    let before = x.p_local_copy();
    assert!(matches!(x.p.write_with(|w| w.at(x.t, title()).set(&s("lost?"))), Err(Error::Network(_))));
    assert_eq!(x.p_local_copy(), before);
    assert_eq!(x.n.get(x.t, title()).unwrap(), Some(s("seen")));
    until("the watch tells", || watch.current().is_err());
    assert!(matches!(watch.current(), Err(Error::Network(_))));
    // back: the watch closes the gap
    x.set_n("in the gap");
    x.net.heal("p", "n");
    until("watch after reconnect", || watch.current().ok().flatten() == Some(s("in the gap")));
    assert_eq!(x.p.get(x.t, title()).unwrap(), Some(s("in the gap")));
    x.p.write_with(|w| w.at(x.t, title()).set(&s("after"))).unwrap();
    assert_eq!(x.n.get(x.t, title()).unwrap(), Some(s("after")));
    drop(x.host);
}

// spec/sync.md §10, notes/client-port.md §6: moving a group ends a watch on the source it left with one last error: a local watch does not go silent over a group this node stopped syncing, a remote watch does not outlive the route
#[test]
fn a_move_ends_watches_of_the_group() {
    let x = world();
    x.attach_p();
    let local = x.p.at(x.t, title()).watch().unwrap();
    let (tx, rx) = channel();
    let sub = x.p.at(x.t, title()).on_change(move |_, c| tx.send(c.value.is_err()).unwrap()).unwrap();
    assert!(!(rx.recv_timeout(W).unwrap()));
    x.to_remote();
    until("local watch ended", || local.current().is_err());
    assert!(rx.recv_timeout(W).unwrap());
    drop(sub);
    let remote = x.p.at(x.t, title()).watch().unwrap();
    assert!(remote.current().is_ok());
    block_on(x.p.group_source(x.g, GroupSource::Local)).unwrap();
    until("remote watch ended", || remote.current().is_err());
    // a node's own client must not read the stale copy of a group the node moved away (below)
    drop(x.host);
}

// spec/sync.md §10, notes/client-port.md §6, §3: a client of a node reads nothing the node stopped syncing: it is stale there, the client gets UnknownThing, not an old value, and through the node's own attachment nothing runs as the node's actor
#[test]
fn a_nodes_client_does_not_read_what_it_moved_away() {
    let x = world();
    // N3 is a third way in: a client of P
    let (a, sec) = x.p.add_client(None).unwrap();
    x.p.grant(x.g, a, Role::Read, Default::default()).unwrap();
    let pc = x.p.client_listen(&["mem://p-clients".to_string()]).unwrap().remove(0);
    let mut c = Config::memory();
    c.transport = Some(Transport::InProcess(x.net.endpoint("pc")));
    let client = Osis::attach_client(&pc, &sec, c).unwrap();
    assert_eq!(client.get(x.t, title()).unwrap(), Some(s("first")));
    let w = client.at(x.t, title()).watch().unwrap();
    x.attach_p();
    x.to_remote();
    x.set_n("newer");
    assert_eq!(client.get(x.t, title()).unwrap(), None);
    assert!(!client.knows(x.t));
    until("its subscription lapsed", || w.current().is_err());
    drop(x.host);
}

// spec/sync.md §10, notes/client-port.md §1 Reconnect: a write whose first send ran and whose reply was lost is answered from the node's memory under the same epoch: applied once, and the caller gets its one result
#[test]
fn lost_reply_retried_applies_once() {
    let x = world();
    let c = x.thin("c1");
    let name = ak("note:n.0");
    c.write_with(|w| w.at(x.t, title()).set(&s("before"))).unwrap();
    let before = commits_of(&x.n, x.t);
    x.n.port_panic_next(true);
    c.write_with(|w| w.at(x.t, name.clone()).set(&s("once"))).unwrap();
    assert_eq!(x.n.get(x.t, name).unwrap(), Some(s("once")));
    assert_eq!(commits_of(&x.n, x.t), before + 1, "applied exactly once");
    // a set of an equal value commits nothing, so only a count tells a second run
    let count = count_key(&[&x.n]);
    x.n.port_panic_next(true);
    c.write_with(|w| w.at(x.t, count.clone()).inc(&1i64)).unwrap();
    assert_eq!(x.n.get(x.t, count).unwrap(), Some(Value::Int(1)), "applied exactly once");
    drop(x.host);
}

/// A counter's key, its schema registered on `dbs`: an op whose second run shows.
fn count_key(dbs: &[&Osis]) -> osis::Key {
    for db in dbs {
        db.register_schema_source("count.osis", "version 1;\naspect count:n.0: counter<int>;\n").unwrap();
    }
    dbs[0].key("count:n.0").unwrap()
}

fn commits_of(db: &Osis, t: Tid) -> usize {
    db.commits(&osis::CommitQuery::new().scope(osis::Scope::Thing(t))).unwrap().len()
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
    let r = c.write_with(|w| w.at(x.t, title()).set(&s("first write")));
    assert!(matches!(&r, Err(Error::OutcomeUnknown)), "{r:?}");
    assert_eq!(commits_of(&x.n, x.t), before);
    // a new write makes the session known (a resend right after that unknown could be of a write
    // that ran before the state went: unknown too, `every_resent_nonce_of_a_lost_session_is_unknown`)
    c.write_with(|w| w.at(x.t, title()).set(&s("new"))).unwrap();
    // with the session known: sent again, it runs once (a count: a second run shows)
    let count = count_key(&[&x.n]);
    x.n.port_panic_next(false);
    c.write_with(|w| w.at(x.t, count.clone()).inc(&1i64)).unwrap();
    assert_eq!(x.n.get(x.t, count).unwrap(), Some(Value::Int(1)), "applied exactly once");
    assert_eq!(commits_of(&x.n, x.t), before + 2);
    drop(x.host);
}

// spec/sync.md §10, issues/cli-proxy.md Port worker panic: a panic ends that session at once, not after a stall timeout: its in-flight read fails Network, it reconnects; another client's session never noticed, and the worker lives on
#[test]
fn a_worker_panic_ends_one_session_and_the_port_lives() {
    let x = world();
    let (c1, c2) = (x.thin("c1"), x.thin("c2"));
    let w2 = c2.at(x.t, title()).watch().unwrap();
    x.n.port_panic_next(true);
    let t0 = Instant::now();
    assert!(matches!(c1.get(x.t, title()), Err(Error::Network(_))));
    assert!(t0.elapsed() < Duration::from_secs(30), "no stall timeout");
    until("c1 reconnected", || c1.get(x.t, title()).is_ok());
    assert_eq!(c2.get(x.t, title()).unwrap(), Some(s("first")));
    x.set_n("still live");
    until("c2's watch still live", || w2.current().ok().flatten() == Some(s("still live")));
    drop(x.host);
}

// spec/sync.md §10, notes/client-port.md §1 Reconnect: node restart: Auth again; subscriptions again with the new value; later writes work
#[test]
fn restart_keeps_the_attachment_working() {
    let mut x = world();
    let mut cc = Config::memory();
    cc.transport = Some(Transport::InProcess(x.net.endpoint("c1")));
    cc.wait_timeout = W;
    let c = Osis::attach_client(&x.nc, &x.secret, cc).unwrap();
    let w = c.at(x.t, title()).watch().unwrap();
    let (c2, t) = (c.clone(), x.t);
    x.net.partition("c1", "n");
    x.net.disconnect("c1", "n");
    until("down", || !c.status().unwrap().remotes[0].connected);
    // calls while down are definite: not sent
    assert!(matches!(c2.write_with(|w| w.at(t, title()).set(&s("not sent"))), Err(Error::Network(_))));
    // the node restarts on its store and listens again
    let (net, store, addr, urls) = (x.net.clone(), x.n_store.clone(), x.addr.clone(), x.urls.clone());
    std::mem::replace(&mut x.n, Osis::create(Config::memory()).unwrap().0).close().unwrap();
    let n2 = Osis::open(cfg_on(&net, "n", &store, vec![addr])).unwrap();
    assert_eq!(n2.client_listen(&urls).unwrap().remove(0), x.nc, "the client listener's key survives a restart");
    net.heal("c1", "n");
    until("client back up", || c.status().unwrap().remotes[0].connected);
    n2.write_with(|w| w.at(t, title()).set(&s("after restart"))).unwrap();
    until("the watch came back", || w.current().ok().flatten() == Some(s("after restart")));
    c.write_with(|w| w.at(t, title()).set(&s("again"))).unwrap();
    assert_eq!(n2.get(t, title()).unwrap(), Some(s("again")));
    drop(x.host.take());
}

// spec/wire.md §11.2 write nonces, notes/client-port.md §1: a write in flight when the connection drops, across a restart: the caller's one answer is `OutcomeUnknown`, and nothing runs twice
#[test]
fn write_in_flight_across_a_restart_is_unknown() {
    let mut x = world();
    let mut cc = Config::memory();
    cc.transport = Some(Transport::InProcess(x.net.endpoint("c1")));
    cc.wait_timeout = W;
    let c = Osis::attach_client(&x.nc, &x.secret, cc).unwrap();
    let before = commits_of(&x.n, x.t);
    // the reply goes missing, the connection drops, and before a redial (at least 100 ms) the node
    // is gone: partition first so the redial cannot beat the restart
    x.n.port_panic_next(true);
    let (tx, rx) = channel();
    let (c2, t) = (c.clone(), x.t);
    let th = std::thread::spawn(move || {
        tx.send(()).unwrap();
        c2.write_with(|w| w.at(t, title()).set(&s("maybe")))
    });
    rx.recv().unwrap();
    until("the node ran it", || commits_of(&x.n, t) == before + 1);
    x.net.partition("c1", "n");
    x.net.disconnect("c1", "n");
    let (net, store, addr, urls) = (x.net.clone(), x.n_store.clone(), x.addr.clone(), x.urls.clone());
    std::mem::replace(&mut x.n, Osis::create(Config::memory()).unwrap().0).close().unwrap();
    let n2 = Osis::open(cfg_on(&net, "n", &store, vec![addr])).unwrap();
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
    const WRITE: u64 = 11;
    let x = world();
    let ep = x.net.endpoint("r");
    let mut raw = crate::port::Raw::over(&ep, osis_transport::Address { url: x.nc.url().to_string(), key: x.nc.key() });
    let a = raw.ask(Command::Auth { token: 0, session: [5; 16], secret: Some(osis_crypto::Secret32::from_bytes(*x.secret.expose())) }, 0);
    assert!(matches!(a, Ok(Outcome::Ok { .. })), "{a:?}");
    let resent = 1u64 << 62;
    let batch = |nonce: u64, v: &str| crate::port::set_batch(nonce, x.actor, x.t, &title(), s(v));
    let unknown = |o: &Outcome| matches!(o, Outcome::Err { .. });
    let o = raw.call_at(1, WRITE, batch(1 | resent, "marked"));
    assert!(unknown(&o), "{o:?}");
    assert_eq!(x.n.get(x.t, title()).unwrap(), Some(s("first")));
    // the session is known now: a later nonce is new, and marked it answers from memory
    let o = raw.call_at(2, WRITE, batch(2, "two"));
    assert!(matches!(o, Outcome::Ok { .. }), "{o:?}");
    let before = commits_of(&x.n, x.t);
    let again = raw.call_at(3, WRITE, batch(2 | resent, "two"));
    assert!(matches!(again, Outcome::Ok { .. }), "{again:?}");
    assert_eq!(commits_of(&x.n, x.t), before);
    drop(x.host);
}

// spec/sync.md §10, notes/client-port.md §1: schemas registered through an Owner attachment are registered again after a node restart, and watches come back over the unix socket
#[test]
fn owner_reconnect_registers_schemas_again() {
    use osis::AspectKey as _;
    let d = std::env::temp_dir().join(format!("osis-sources-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    let sock = d.join("n.sock");
    let (net, store) = (osis_transport::Net::new(5), MemStore::new());
    let open = |create: bool| {
        let mut c = cfg_on(&net, "n", &store, vec![]);
        c.peers = false;
        let db = if create { Osis::create(c).unwrap().0 } else { Osis::open(c).unwrap() };
        db.listen_unix(&sock).unwrap();
        db
    };
    let n = open(true);
    let c = Osis::attach(&sock, Config::memory()).unwrap();
    let src = "version 1;\naspect re:title.0: string;\n";
    c.register_schema_source("re.osis", src).unwrap();
    assert!(n.key("re:title.0").unwrap().schema().is_some());
    let t = c.write_with(|w| {
        let t = w.create(c.me())?;
        w.at(t, title()).set(&s("x"))?;
        Ok(t)
    }).unwrap();
    let watch = c.at(t, title()).watch().unwrap();
    n.close().unwrap();
    until("down", || !c.status().unwrap().remotes[0].connected);
    let n = open(false);
    until("reconnected", || c.status().unwrap().remotes[0].connected);
    c.settle();
    until("registered again", || n.key("re:title.0").unwrap().schema().is_some());
    until("the watch came back", || watch.current().ok().flatten() == Some(s("x")));
    let _ = std::fs::remove_dir_all(&d);
}

// spec/sync.md §10, notes/client-port.md §1: a write held across a drop gives up after wait_timeout with no connection, with one answer: unknown
#[test]
fn write_in_flight_gives_up_after_wait_timeout() {
    let x = world();
    let mut cc = Config::memory();
    cc.transport = Some(Transport::InProcess(x.net.endpoint("c1")));
    cc.wait_timeout = SHORT;
    let c = Osis::attach_client(&x.nc, &x.secret, cc).unwrap();
    let before = commits_of(&x.n, x.t);
    x.n.port_panic_next(true);
    let (c2, t) = (c.clone(), x.t);
    let th = std::thread::spawn(move || c2.write_with(|w| w.at(t, title()).set(&s("maybe"))));
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
    let Some(osis::CreationRecord::KeyActor { public_key, .. }) = x.n.engine(|e| e.core.created(&node).cloned()) else { panic!("a node is a key actor") };
    assert_ne!(public_key, key);
    let dialable = x.n.sync_engine(|s| s.dialable_secret());
    let own = |sec: &[u8; 32]| osis_transport::InProcess::public_key(&osis_transport::StaticSecret::from_bytes(*sec));
    assert_ne!(key, own(dialable.expose()));
    let lan = x.n.sync_engine(|s| s.lan_secret());
    assert_ne!(key, own(lan.expose()));
    assert_ne!(Some(key), x.n.host_key());
    assert_eq!(x.n.sync_engine(|s| s.client_listen_key()), Some(key));
    // rotate_reach: nothing changes for clients
    x.n.rotate_reach().unwrap();
    until("dialable key rotated", || own(x.n.sync_engine(|s| s.dialable_secret()).expose()) != own(dialable.expose()));
    assert_eq!(c.get(x.t, title()).unwrap(), Some(s("first")));
    assert_eq!(x.n.sync_engine(|s| s.client_listen_key()), Some(key));
    // rotate_client_key: the old client is out for good
    let new = x.n.rotate_client_key().unwrap().remove(0);
    assert_ne!(new.key(), key);
    assert_ne!(new.key(), own(x.n.sync_engine(|s| s.dialable_secret()).expose()));
    until("old-key client down", || !c.status().unwrap().remotes[0].connected);
    assert!(matches!(c.get(x.t, title()), Err(Error::Network(_))));
    std::thread::sleep(SHORT);
    assert!(matches!(c.get(x.t, title()), Err(Error::Network(_))));
    // same URL, new key: the old address cannot reach it, a new one can
    let mut cfg = Config::memory();
    cfg.transport = Some(Transport::InProcess(x.net.endpoint("c2")));
    cfg.wait_timeout = SHORT;
    assert!(matches!(Osis::attach_client(&x.nc, &x.secret, cfg.clone()), Err(Error::Network(_))));
    let c2 = Osis::attach_client(&new, &x.secret, cfg.clone()).unwrap();
    assert_eq!(c2.get(x.t, title()).unwrap(), Some(s("first")));
    // no URL: stops, ends sessions, shreds
    assert!(x.n.client_listen(&[]).unwrap().is_empty());
    assert_eq!(x.n.sync_engine(|s| s.client_listen_key()), None);
    until("session ended", || !c2.status().unwrap().remotes[0].connected);
    let again = x.n.client_listen(&x.urls).unwrap().remove(0);
    assert_ne!(again.key(), new.key());
    drop(x.host);
}

// spec/sync.md §10, notes/client-port.md §3: a bearer secret is only sent to the pinned key: an impostor at the node's URL under another key gets no session (the dial fails), and a unix address is refused before any dial
#[test]
fn bearer_secret_only_to_the_pinned_key() {
    let x = world();
    let mut cfg = Config::memory();
    cfg.transport = Some(Transport::InProcess(x.net.endpoint("c1")));
    cfg.wait_timeout = SHORT;
    let wrong = HostAddr::new(x.nc.url(), [9; 32]);
    assert!(matches!(Osis::attach_client(&wrong, &x.secret, cfg.clone()), Err(Error::Network(_))));
    let unix = HostAddr::new("unix:///tmp/x.sock", x.nc.key());
    assert!(matches!(Osis::attach_client(&unix, &x.secret, cfg), Err(Error::Invalid(_))));
    drop(x.host);
}

// spec/sync.md §10, issues/cli-proxy.md: attach's wait for Hello has a deadline: a listener that takes the connection and never answers fails Network within wait_timeout, not forever
#[test]
fn attach_to_a_silent_listener_ends() {
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
    let mut cfg = Config::memory();
    cfg.transport = Some(Transport::InProcess(net.endpoint("c")));
    cfg.wait_timeout = SHORT;
    let (tx, rx) = channel();
    let addr = HostAddr::new("mem://silent", key);
    std::thread::spawn(move || {
        tx.send(Osis::attach_client(&addr, &ClientSecret::from_bytes([1; 32]), cfg).map(drop)).unwrap();
    });
    let r = rx.recv_timeout(Duration::from_secs(30)).expect("attach never ended");
    assert!(matches!(r, Err(Error::Network(_))), "{r:?}");
}

// spec/sync.md §10, notes/client-port.md §6: Config.remotes without a store: every group remote; two nodes as two actors are Invalid (one acting actor per process); with a store: the sources record survives a restart, without its attachment a route fails Network (never the local copy), with it works again; status lists the route's node; a route to a removed node can go home
#[test]
fn config_remotes_and_the_persisted_route() {
    let mut x = world();
    // no store
    let mut c = Config::memory();
    c.transport = Some(Transport::InProcess(x.net.endpoint("c1")));
    c.wait_timeout = W;
    c.remotes = vec![RemoteConfig { addr: x.nc.clone(), secret: x.secret.clone() }];
    let thin = Osis::attach_remotes(c).unwrap();
    assert_eq!(thin.me(), x.actor);
    assert_eq!(thin.get(x.t, title()).unwrap(), Some(s("first")));
    assert!(matches!(block_on(thin.group_source(x.g, GroupSource::Local)), Err(Error::Unsupported(_))));
    assert!(matches!(thin.attach_node(&x.nc, &x.secret, &Config::memory()), Err(Error::Unsupported(_))));
    // a second client actor at the same node: two actors in one store-less process
    let (other, sec2) = x.n.add_client(None).unwrap();
    x.n.grant(x.g, other, Role::Read, Default::default()).unwrap();
    let mut c = Config::memory();
    c.transport = Some(Transport::InProcess(x.net.endpoint("c2")));
    c.wait_timeout = W;
    c.remotes = vec![RemoteConfig { addr: x.nc.clone(), secret: x.secret.clone() }, RemoteConfig { addr: x.nc.clone(), secret: sec2 }];
    assert!(matches!(Osis::attach_remotes(c), Err(Error::Invalid(_))));
    // with a store: the record
    x.attach_p();
    x.to_remote();
    x.set_n("n1");
    assert_eq!(x.p.get(x.t, title()).unwrap(), Some(s("n1")));
    let (net, pstore, addr) = (x.net.clone(), x.p_store.clone(), x.addr.clone());
    std::mem::replace(&mut x.p, Osis::create(Config::memory()).unwrap().0).close().unwrap();
    // reopened without its attachment: Network, never the copy here
    let p2 = Osis::open(cfg_on(&net, "p", &pstore, vec![addr.clone()])).unwrap();
    assert_eq!(p2.routes().get(&x.g), Some(&x.nc.to_string()));
    assert!(matches!(p2.get(x.t, title()), Err(Error::Network(_))));
    assert!(matches!(p2.write_with(|w| w.at(x.t, title()).set(&s("z"))), Err(Error::Network(_))));
    let st = p2.status().unwrap();
    assert_eq!(st.remotes, vec![osis::RemoteStatus { address: x.nc.to_string(), connected: false }]);
    p2.close().unwrap();
    // reopened with it: the route works, nothing to redo
    let mut c = cfg_on(&net, "p", &pstore, vec![addr.clone()]);
    c.remotes = vec![RemoteConfig { addr: x.nc.clone(), secret: x.secret.clone() }];
    let p3 = Osis::open(c).unwrap();
    until("the attachment came up", || p3.get(x.t, title()).ok().flatten() == Some(s("n1")));
    p3.close().unwrap();
    // a route naming a node gone for good: home works with no attachment at all
    let p4 = Osis::open(cfg_on(&net, "p", &pstore, vec![addr])).unwrap();
    block_on(p4.group_source(x.g, GroupSource::Local)).unwrap();
    assert!(p4.routes().is_empty());
    assert_eq!(p4.get(x.t, title()).unwrap(), Some(s("n1")));
    drop(x.host.take());
}

// spec/sync.md §10, notes/client-port.md §6, sources.rs invariant: a write decided Local and then overtaken by a move fails under its own lock: nothing lands in a group that no longer syncs here
#[test]
fn a_write_overtaken_by_a_move_fails() {
    let x = world();
    x.attach_p();
    let (p, g, addr) = (x.p.clone(), x.g, x.nc.to_string());
    x.p.after_route(Box::new(move || {
        p.set_route(g, Some(addr.clone()));
        let _ = p.sync_policy(g, osis::GroupPolicy { receipts_only: true, ..Default::default() });
    }));
    let before = x.p_local_copy();
    let r = x.p.write_with(|w| w.at(x.t, title()).set(&s("stranded?")));
    x.p.after_route(Box::new(|| {}));
    assert!(matches!(&r, Err(Error::Network(m)) if m.contains("moved")), "{r:?}");
    assert_eq!(x.p_local_copy(), before);
    drop(x.host);
}

// spec/sync.md §10, notes/client-port.md §3, §5 (networking tier: `cargo test-net -- --ignored quic`): a thin client over real QUIC with bearer Auth: reads, writes, watches at the client listener; a wrong pinned key dials nothing; a wrong secret is refused; a node restart on the same port reconnects under the same key; a rotation strands the old address
#[test]
#[ignore]
fn thin_client_over_quic() {
    let store = MemStore::new();
    let open = |create: bool| {
        let mut c = Config::at(StoreAt::Memory(store.clone()));
        c.runtime = Runtime::Own;
        c.transport = Some(Transport::Quic);
        c.peers = false;
        if create { Osis::create(c).unwrap().0 } else { Osis::open(c).unwrap() }
    };
    let n = open(true);
    let (g, t) = n.write_with(|w| {
        let g = w.create(n.me())?;
        w.make_group(g)?;
        let t = w.create(g)?;
        w.place(t, g)?;
        w.at(t, title()).set(&s("first"))?;
        Ok((g, t))
    }).unwrap();
    let (actor, secret) = n.add_client(None).unwrap();
    n.grant(g, actor, Role::Write, Default::default()).unwrap();
    let addr = n.client_listen(&["quic://127.0.0.1:0".to_string()]).unwrap().remove(0);
    assert!(addr.url().starts_with("quic://127.0.0.1:"), "{addr}");
    let mut cfg = Config::memory();
    cfg.transport = Some(Transport::Quic);
    cfg.wait_timeout = W;
    let c = Osis::attach_client(&addr, &secret, cfg.clone()).unwrap();
    assert_eq!(c.me(), actor);
    assert_eq!(c.get(t, title()).unwrap(), Some(s("first")));
    let watch = c.at(t, title()).watch().unwrap();
    c.write_with(|w| w.at(t, title()).set(&s("from client"))).unwrap();
    assert_eq!(n.get(t, title()).unwrap(), Some(s("from client")));
    until("watch", || watch.current().ok().flatten() == Some(s("from client")));
    // an impostor key at the same URL: the handshake fails, no secret sent
    let mut short = cfg.clone();
    short.wait_timeout = Duration::from_secs(3);
    assert!(matches!(Osis::attach_client(&HostAddr::new(addr.url(), [8; 32]), &secret, short.clone()), Err(Error::Network(_))));
    assert!(matches!(Osis::attach_client(&addr, &ClientSecret::from_bytes([1; 32]), short.clone()), Err(Error::Unsupported(_))));
    // restart on the same store and port: the same address, the session comes back
    n.close().unwrap();
    until("down", || !c.status().unwrap().remotes[0].connected);
    assert!(matches!(c.get(t, title()), Err(Error::Network(_))));
    assert!(matches!(watch.current(), Err(Error::Network(_))));
    let n = open(false);
    assert_eq!(n.client_listen(&[addr.url().to_string()]).unwrap().remove(0), addr);
    until("reconnected", || c.status().unwrap().remotes[0].connected);
    until("the watch came back", || watch.current().ok().flatten() == Some(s("from client")));
    c.write_with(|w| w.at(t, title()).set(&s("again"))).unwrap();
    assert_eq!(n.get(t, title()).unwrap(), Some(s("again")));
    // a rotation: the old address never answers again
    let new = n.rotate_client_key().unwrap().remove(0);
    assert_ne!(new.key(), addr.key());
    assert_eq!(new.url(), addr.url());
    until("old-key client down", || !c.status().unwrap().remotes[0].connected);
    assert!(matches!(Osis::attach_client(&addr, &secret, short.clone()), Err(Error::Network(_))));
    assert_eq!(Osis::attach_client(&new, &secret, cfg).unwrap().get(t, title()).unwrap(), Some(s("again")));
}

// spec/sync.md §10, issues/cli-proxy.md Transport slots: a flood of connections past the client listener's pending slots, each from a source of its own and never authenticating, neither drops an authenticated client (no error ever reached its watch) nor keeps a new one out
#[test]
fn a_flood_keeps_clients_in() {
    let x = world();
    let c = x.thin("c1");
    let (tx, rx) = channel();
    let _sub = c.at(x.t, title()).on_change(move |_, ch| tx.send(ch.value.is_err()).unwrap()).unwrap();
    assert!(!rx.recv_timeout(W).unwrap());
    let slots = x.n.sync_engine(|s| s.config().client_pending);
    let addr = osis_transport::Address { url: x.nc.url().to_string(), key: x.nc.key() };
    let mut flood = Vec::new();
    for i in 0..slots + 8 {
        flood.push(crate::port::Raw::over(&x.net.endpoint(&format!("f{i}")), addr.clone()));
    }
    // none of it touched the client
    assert_eq!(c.get(x.t, title()).unwrap(), Some(s("first")));
    assert!(rx.try_recv().is_err(), "the client's connection was dropped");
    assert!(c.status().unwrap().remotes[0].connected);
    // a new client gets in during it
    assert_eq!(x.thin("c2").get(x.t, title()).unwrap(), Some(s("first")));
    drop(flood);
    drop(x.host);
}

// spec/sync.md §10, notes/client-port.md §6: with several attachments a thing known here to none goes to the first that knows it; an unreachable earlier one stops the search: Network, not the later one's answer, so a write cannot land at a node chosen by who happens to be up
#[test]
fn several_attachments_never_skip_a_down_one() {
    let x = world();
    // a second node, of another person, with a client for us, and a thing only it has
    let m = Osis::create(cfg_on(&x.net, "m", &MemStore::new(), vec![])).unwrap().0;
    let mc = m.client_listen(&["mem://m-clients".to_string()]).unwrap().remove(0);
    let (ma, msec) = m.add_client(None).unwrap();
    let g2 = m.write_with(|w| {
        let g = w.create(m.me())?;
        w.make_group(g)?;
        Ok(g)
    }).unwrap();
    m.grant(g2, ma, Role::Write, Default::default()).unwrap();
    let there = m.write_with(|w| {
        let o = w.create(g2)?;
        w.place(o, g2)?;
        w.at(o, title()).set(&s("at m"))?;
        Ok(o)
    }).unwrap();
    x.attach_p();
    x.p.attach_node(&mc, &msec, &cfg_on(&x.net, "p", &MemStore::new(), vec![])).unwrap();
    assert_eq!(x.p.get(there, title()).unwrap(), Some(s("at m")));
    x.p.write_with(|w| w.at(there, title()).set(&s("from p"))).unwrap();
    assert_eq!(m.get(there, title()).unwrap(), Some(s("from p")));
    // the first attachment goes down: nothing is known about `there` at it any more
    x.net.partition("p", "n");
    x.net.disconnect("p", "n");
    until("down", || !x.p.status().unwrap().remotes[0].connected);
    assert!(matches!(x.p.get(there, title()), Err(Error::Network(_))));
    assert!(matches!(x.p.write_with(|w| w.at(there, title()).set(&s("wrong place?"))), Err(Error::Network(_))));
    assert_eq!(m.get(there, title()).unwrap(), Some(s("from p")));
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

// spec/sync.md §10, notes/client-port.md §6, the invariant of core/osis/src/sources.rs: random groups, routes, syncs and attachments against a model of the rule: each call reaches exactly the source the model names, a value only from it, a write only to it, Network when that one is down, never another's answer
#[test]
fn routing_differential_against_a_model() {
    for seed in [1, 2] {
        differential(seed);
    }
}

fn differential(seed: u64) {
    let x = world();
    let mut r = Rng(seed);
    // three groups and a thing per placement mix, every thing known on both sides, then the host goes
    let mk = |n: usize| -> Vec<Tid> {
        x.n.write_with(|w| {
            let mut v = Vec::new();
            for _ in 0..n {
                let g = w.create(x.n.me())?;
                w.make_group(g)?;
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
        let t = x.n.write_with(|w| {
            let t = w.create(of[0])?;
            for g in &of {
                w.place(t, *g)?;
            }
            w.at(t, title()).set(&s("start"))?;
            Ok(t)
        }).unwrap();
        things.push((t, of));
    }
    block_on(x.n.wait_synced(SyncScope::All, W)).unwrap();
    until("P has them", || {
        let _ = x.p.sync_now();
        things.iter().all(|(t, _)| x.p.get(*t, title()).ok().flatten() == Some(s("start")))
    });
    block_on(x.p.wait_synced(SyncScope::All, W)).unwrap();
    // from here the two copies diverge: nothing moves between them but what the calls do
    x.net.partition("n", "s");
    x.net.partition("p", "s");
    x.net.disconnect("n", "s");
    x.net.disconnect("p", "s");
    let attach = || x.p.attach_node(&x.nc, &x.secret, &cfg_on(&x.net, "p", &MemStore::new(), vec![])).unwrap();
    attach();
    let addr = x.nc.to_string();
    // the model: the group's route, whether it syncs here, whether the node is attached; the value on each side
    let mut routed = [false; 3];
    let mut stopped = [false; 3];
    let mut attached = true;
    let mut local: Vec<String> = vec!["start".into(); things.len()];
    let mut remote = local.clone();
    let ix = |g: &Tid| gs.iter().position(|x| x == g).unwrap();
    for step in 0..120 {
        let which = r.next(things.len() as u64) as usize;
        let (t, of) = &things[which];
        // the rule, for a thing known here
        let is_remote = of.iter().any(|g| routed[ix(g)]);
        // the groups other than the owner only place it: only the owner's label carries it
        let split = is_remote && !routed[ix(&of[0])] && !stopped[ix(&of[0])];
        match r.next(10) {
            0 | 1 => {
                let i = r.next(3) as usize;
                routed[i] = !routed[i];
                x.p.set_route(gs[i], routed[i].then(|| addr.clone()));
            }
            2 => {
                let i = r.next(3) as usize;
                stopped[i] = !stopped[i];
                x.p.sync_policy(gs[i], osis::GroupPolicy { receipts_only: stopped[i], ..Default::default() }).unwrap();
            }
            3 => {
                if attached {
                    assert!(x.p.detach_node(&x.nc).unwrap());
                } else {
                    attach();
                }
                attached = !attached;
            }
            4..=6 => {
                let v = format!("v{step}");
                let w = x.p.write_with(|w| w.at(*t, title()).set(&s(&v)));
                match (is_remote, attached) {
                    _ if split => assert!(matches!(w, Err(Error::Invalid(_))), "step {step}: {w:?}"),
                    (false, _) => {
                        w.unwrap();
                        local[which] = v;
                    }
                    (true, true) => {
                        w.unwrap();
                        remote[which] = v;
                    }
                    (true, false) => assert!(matches!(w, Err(Error::Network(_))), "step {step}: {w:?}"),
                }
            }
            _ => {
                let g = x.p.get(*t, title());
                match (is_remote, attached) {
                    (false, _) => assert_eq!(g.unwrap(), Some(s(&local[which])), "step {step} seed {seed}: {which}"),
                    (true, true) => assert_eq!(g.unwrap(), Some(s(&remote[which])), "step {step} seed {seed}: {which}"),
                    (true, false) => assert!(matches!(g, Err(Error::Network(_))), "step {step} seed {seed}: {g:?}"),
                }
            }
        }
        // each side holds only what the model says went there
        if step % 16 == 0 {
            for (i, (t, _)) in things.iter().enumerate() {
                assert_eq!(x.n.get(*t, title()).unwrap(), Some(s(&remote[i])), "step {step}");
                assert_eq!(x.p.engine(|e| e.get(t, &ak("note:title.0")).unwrap()), Some(s(&local[i])), "step {step}");
            }
        }
    }
    drop(x.host);
}

// spec/permissions.md §3, notes/client-port.md §6: a demotion of a holder of a group this node reads at another node is refused: run here it would commit to a copy that no longer syncs, and the revocation would silently never leave
#[test]
fn a_demotion_of_a_routed_group_is_refused() {
    let x = world();
    x.attach_p();
    x.to_remote();
    let (other, _) = x.n.add_client(None).unwrap();
    x.n.grant(x.g, other, Role::Read, Default::default()).unwrap();
    block_on(x.n.wait_synced(SyncScope::Group(x.g), W)).unwrap();
    let d = osis::Demotion { sync: osis::WaitForSync::Skip, ..Default::default() };
    let r = block_on(x.p.demote(x.g, x.actor, osis::Lower::Remove, d));
    assert!(matches!(r, Err(Error::Unsupported(_))), "{r:?}");
    assert!(x.n.roster(x.g).contains_key(&x.actor));
    assert!(x.p.engine(|e| e.roster(&x.g).contains_key(&x.actor)), "nothing written to the local copy");
    drop(x.host);
}

// spec/sync.md §10, notes/client-port.md §6: a sharing flow decided Local and overtaken by a move fails under its commit's lock: a grant or revocation never sits unsent in a group that stopped syncing here
#[test]
fn a_sharing_flow_overtaken_by_a_move_fails() {
    let x = world();
    x.attach_p();
    let (other, _) = x.n.add_client(None).unwrap();
    until("P knows the other client", || {
        let _ = x.p.sync_now();
        x.p.engine(|e| e.knows(&other))
    });
    let (p, g, addr) = (x.p.clone(), x.g, x.nc.to_string());
    // the grant's own step, past the `persist` before it
    let calls = std::sync::atomic::AtomicUsize::new(0);
    x.p.after_route(Box::new(move || {
        if calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 1 {
            p.set_route(g, Some(addr.clone()));
            let _ = p.sync_policy(g, osis::GroupPolicy { receipts_only: true, ..Default::default() });
        }
    }));
    let roster = x.p.engine(|e| e.roster(&x.g).len());
    let r = x.p.grant(x.g, other, Role::Read, Default::default());
    x.p.after_route(Box::new(|| {}));
    assert!(matches!(&r, Err(Error::Network(m)) if m.contains("moved")), "{r:?}");
    assert_eq!(x.p.engine(|e| e.roster(&x.g).len()), roster, "nothing written");
    drop(x.host);
}

// spec/wire.md §11.2: a resent write the node does not remember, in a session whose state it lost, never runs, also after the first such resend recreated the session's entry: two writes that ran, then lost state, are two unknowns
#[test]
fn every_resent_nonce_of_a_lost_session_is_unknown() {
    use osis_proto::{Command, Outcome};
    const WRITE: u64 = 11;
    let x = world();
    let ep = x.net.endpoint("r");
    let mut raw = crate::port::Raw::over(&ep, osis_transport::Address { url: x.nc.url().to_string(), key: x.nc.key() });
    let a = raw.ask(Command::Auth { token: 0, session: [6; 16], secret: Some(osis_crypto::Secret32::from_bytes(*x.secret.expose())) }, 0);
    assert!(matches!(a, Ok(Outcome::Ok { .. })), "{a:?}");
    let resent = 1u64 << 62;
    let batch = |nonce: u64, v: &str| crate::port::set_batch(nonce, x.actor, x.t, &title(), s(v));
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
    let pc = x.p.client_listen(&["mem://p-clients".to_string()]).unwrap().remove(0);
    let mut c = Config::memory();
    c.transport = Some(Transport::InProcess(x.net.endpoint("pc")));
    let client = Osis::attach_client(&pc, &sec, c).unwrap();
    assert_eq!(client.get(x.t, title()).unwrap(), None);
    let w = client.at(x.t, title()).watch().unwrap();
    x.attach_p();
    x.to_remote();
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
    block_on(x.p.wait_synced(SyncScope::Group(x.g), W)).unwrap();
    let pc = x.p.client_listen(&["mem://p-clients".to_string()]).unwrap().remove(0);
    let mut c = Config::memory();
    c.transport = Some(Transport::InProcess(x.net.endpoint("pc")));
    let client = Osis::attach_client(&pc, &sec, c).unwrap();
    x.attach_p();
    x.to_remote();
    x.set_n("newer");
    x.net.partition("p", "s");
    x.net.disconnect("p", "s");
    assert!(block_on(x.p.group_source(x.g, GroupSource::Local)).is_err());
    assert!(!x.p.group_policy(x.g).unwrap().receipts_only, "syncing again, behind");
    assert_eq!(x.p.routes().get(&x.g), Some(&x.nc.to_string()));
    assert_eq!(client.get(x.t, title()).unwrap(), None, "a stale value, as if current");
    drop(x.host);
}

// spec/sync.md §10, notes/client-port.md §1 Reconnect: a watch started while the node is down, on a call that returns no error, tells so and comes up with the connection: no silent dead subscription
#[test]
fn a_watch_started_while_down_comes_up() {
    let x = world();
    x.attach_p();
    x.to_remote();
    x.net.partition("p", "n");
    x.net.disconnect("p", "n");
    until("down", || !x.p.status().unwrap().remotes[0].connected);
    let (tx, rx) = channel();
    let _sub = x.p.watch_thing(x.t, move |_, ch| {
        let _ = tx.send(ch.value.clone());
    });
    assert!(matches!(rx.recv_timeout(W).unwrap(), Err(Error::Network(_))));
    x.net.heal("p", "n");
    loop {
        if rx.recv_timeout(W).unwrap() == Ok(Some(s("first"))) {
            break;
        }
    }
    drop(x.host);
}

// spec/sync.md §10, notes/client-port.md §8: the port worker never waits on another node: an Owner's call on a routed group answers at once, so one silent remote holds no other client of this node
#[test]
fn a_silent_remote_holds_no_client_of_this_node() {
    let x = world();
    x.attach_p();
    x.to_remote();
    let d = std::env::temp_dir().join(format!("osis-sources-silent-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    let sock = d.join("p.sock");
    x.p.listen_unix(&sock).unwrap();
    let o1 = Osis::attach(&sock, Config::memory()).unwrap();
    let o2 = Osis::attach(&sock, Config::memory()).unwrap();
    let mine = x.p.write_with(|w| {
        let t = w.create(x.p.me())?;
        w.place(t, x.p.home())?;
        w.at(t, title()).set(&s("mine"))?;
        Ok(t)
    }).unwrap();
    // silent: no close, nothing answers
    x.net.partition("p", "n");
    let (tx, rx) = channel();
    let t = x.t;
    std::thread::spawn(move || {
        let r = o1.get(t, title());
        tx.send(r).unwrap();
    });
    let r = rx.recv_timeout(W).expect("the worker waits on the remote");
    assert!(matches!(r, Err(Error::Unsupported(_))), "{r:?}");
    let (tx, rx) = channel();
    std::thread::spawn(move || {
        tx.send((o2.get(mine, title()), o2.status().map(|s| s.remotes.len()))).unwrap();
    });
    let (v, _) = rx.recv_timeout(W).expect("another client is held");
    assert_eq!(v.unwrap(), Some(s("mine")));
    let _ = std::fs::remove_dir_all(&d);
    drop(x.host);
}

// spec/sync.md §10, notes/client-port.md §1, §6: a differential of `group_source` with the host up: random real moves, drops and lost replies against a model holding every value a write may have left: a read never shows an older acknowledged value through a settled route, no write is applied twice, a failed move changes no source; a thing in a second group that carries it refuses writes while routed (no write acknowledged and silently never sent), and a thing placed in a second group while routed still reads there
#[test]
fn group_source_differential_against_a_model() {
    let (mut refused, mut placed) = (0, 0);
    for seed in [11, 12, 13] {
        let (r, p) = moves_differential(seed);
        refused += r;
        placed += p;
    }
    assert!(refused > 0 && placed > 0, "the seeds reached neither: {refused} refused, {placed} placed while routed");
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

/// Returns how many writes on the split thing were refused, and whether a thing was placed while routed.
fn moves_differential(seed: u64) -> (usize, usize) {
    let x = world_waiting(Duration::from_millis(600));
    // a second synced group H: `both` is carried by it too, `placed` is only placed there later
    let h = x.n.write_with(|w| {
        let h = w.create(x.n.me())?;
        w.make_group(h)?;
        Ok(h)
    }).unwrap();
    x.n.sync(h, &[]).unwrap();
    let thing = || x.n.write_with(|w| {
        let t = w.create(x.g)?;
        w.place(t, x.g)?;
        w.at(t, title()).set(&s("first"))?;
        Ok(t)
    }).unwrap();
    let (both, placed) = (thing(), thing());
    x.n.share_into(both, h, Role::Write, Default::default()).unwrap();
    block_on(x.n.wait_synced(SyncScope::All, W)).unwrap();
    until("P has them", || {
        let _ = x.p.sync_now();
        x.p.get(both, title()).ok().flatten() == Some(s("first")) && x.p.get(placed, title()).ok().flatten() == Some(s("first")) && x.p.engine(|e| e.groups_of(&both).contains(&h))
    });
    x.attach_p();
    let mut r = Rng(seed);
    // writes on `both` are only ever made here, and refused while routed
    let mut both_acked = "first".to_string();
    let mut things = [tracked(x.t), tracked(placed)];
    let count = count_key(&[&x.n, &x.p]);
    let mut remote = false;
    let mut cut = false;
    let mut is_placed = false;
    let mut refused = 0;
    for step in 0..60 {
        let which = r.next(2) as usize;
        let m = &mut things[which];
        match r.next(13) {
            0 | 1 if !cut => {
                let to = if remote { GroupSource::Local } else { GroupSource::Remote(x.nc.clone()) };
                match block_on(x.p.group_source(x.g, to)) {
                    Ok(()) => remote = !remote,
                    Err(e) => assert!(matches!(e, Error::Network(_) | Error::Unsynced { .. }), "step {step}: {e:?}"),
                }
                assert_eq!(x.p.routes().contains_key(&x.g), remote, "step {step}: the table says where it is");
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
                    until("reconnected", || x.p.status().unwrap().remotes[0].connected);
                } else {
                    until("down", || !x.p.status().unwrap().remotes[0].connected);
                }
            }
            3 if remote && !cut => x.n.port_panic_next(r.next(2) == 0),
            4..=6 => {
                let v = format!("v{step}");
                let write = x.p.write_with(|w| {
                    w.at(m.t, count.clone()).inc(&1i64)?;
                    w.at(m.t, title()).set(&s(&v))
                });
                match write {
                    Ok(_) => {
                        m.acked = v;
                        m.maybe.clear();
                        m.ok += 1;
                    }
                    Err(Error::Network(_)) => assert!(remote, "step {step}: Network from this engine"),
                    Err(Error::OutcomeUnknown) => {
                        m.maybe.push(v);
                        m.unknown += 1;
                    }
                    Err(e) => panic!("step {step}: {e:?}"),
                }
            }
            7 if !remote => {
                let v = format!("b{step}");
                x.p.write_with(|w| w.at(both, title()).set(&s(&v))).unwrap();
                both_acked = v;
            }
            8 if !remote => assert_eq!(x.p.get(both, title()).unwrap(), Some(s(&both_acked)), "step {step} seed {seed}"),
            // no edge: H does not carry it, so nothing is split, and a read stays where it was
            9 if remote && !is_placed => {
                x.p.write_with(|w| w.place(placed, h)).unwrap();
                is_placed = true;
            }
            _ => match x.p.get(m.t, title()) {
                Ok(Some(Value::Str(v))) => {
                    if remote {
                        // the node may not have pulled what this device uploaded before moving: wait
                        until("the node's copy caught up", || {
                            let _ = x.n.sync_now();
                            let now = x.p.get(m.t, title()).unwrap();
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
                Err(Error::Network(_)) => assert!(remote, "step {step}: Network from this engine"),
                Err(e) => panic!("step {step}: {e:?}"),
            },
        }
        // after every step, while routed: `both` refuses a write, which would miss H; both of the
        // second-group things read at the node, never this engine's copy
        if remote {
            let v = format!("refused{step}");
            let write = x.p.write_with(|w| w.at(both, title()).set(&s(&v)));
            assert!(matches!(write, Err(Error::Invalid(_))), "step {step} seed {seed}: a write through the route misses H: {write:?}");
            refused += 1;
            assert!(x.p.status().unwrap().split.contains(&both), "step {step}");
            assert!(!x.p.status().unwrap().split.contains(&placed), "step {step}: H does not carry it");
            let read = x.p.get(both, title());
            if cut {
                assert!(matches!(read, Err(Error::Network(_))), "step {step} seed {seed}: this engine's copy answered: {read:?}");
            } else {
                let m = &things[1];
                until("the node's copies caught up", || {
                    let _ = x.n.sync_now();
                    let at = |t| x.p.get(t, title()).ok().flatten();
                    at(both) == Some(s(&both_acked)) && (at(placed) == Some(s(&m.acked)) || m.maybe.iter().any(|y| at(placed) == Some(s(y))))
                });
            }
        }
    }
    if cut {
        x.net.heal("p", "n");
    }
    // exactly once: the count adds every write that applied, at either source
    for m in &things {
        let applied = || match x.n.get(m.t, count.clone()).unwrap() {
            Some(Value::Int(n)) => n as usize,
            _ => 0,
        };
        until("every acknowledged write reached N", || {
            let _ = x.p.sync_now();
            let _ = x.n.sync_now();
            applied() >= m.ok
        });
        assert!(applied() <= m.ok + m.unknown, "seed {seed}: a write applied twice: {} of {} + {}", applied(), m.ok, m.unknown);
    }
    // nothing acknowledged on `both` stayed on this device
    until("every acknowledged write on `both` reached N", || {
        let _ = x.p.sync_now();
        let _ = x.n.sync_now();
        x.n.get(both, title()).unwrap() == Some(s(&both_acked))
    });
    drop(x.host);
    (refused, is_placed as usize)
}

/// A group of the person, synced on P.
fn second_group(x: &World) -> Tid {
    let h = x.p.write_with(|w| {
        let h = w.create(x.p.me())?;
        w.make_group(h)?;
        Ok(h)
    }).unwrap();
    x.p.sync(h, &[]).unwrap();
    block_on(x.p.wait_synced(SyncScope::Group(h), W)).unwrap();
    h
}

/// A node W of another person syncing G only, with write from N; has `t` once this returns.
fn third_node(x: &World) -> Osis {
    let w_db = Osis::create(cfg_on(&x.net, "w", &MemStore::new(), vec![x.addr.clone()])).unwrap().0;
    let card = w_db.contact_card().unwrap();
    block_on(w_db.wait_synced(SyncScope::All, W)).unwrap();
    let who = block_on(x.n.import_contact(&card)).unwrap();
    x.n.grant(x.g, who, Role::Write, Default::default()).unwrap();
    block_on(x.n.wait_synced(SyncScope::All, W)).unwrap();
    until("W has t", || {
        let _ = w_db.sync_now();
        for i in w_db.invite_requests().unwrap() {
            let _ = w_db.accept_invite(i);
        }
        w_db.get(x.t, title()).ok().flatten() == Some(s("first"))
    });
    w_db
}

// spec/sync.md §10, the invariant of core/osis/src/sources.rs: `t` in routed G and in H, which carries it and syncs here: reads go through the route and see what only G carries; a write is refused, not acknowledged and left missing G's or H's other holders; `status` lists it; home again it writes, and every holder gets it
#[test]
fn a_split_thing_reads_at_the_route_and_refuses_writes() {
    let x = world();
    let w_db = third_node(&x);
    let h = second_group(&x);
    x.p.share_into(x.t, h, Role::Write, Default::default()).unwrap();
    block_on(x.p.wait_synced(SyncScope::Group(h), W)).unwrap();
    x.attach_p();
    x.to_remote();
    assert_eq!(x.p.status().unwrap().split.iter().copied().collect::<Vec<_>>(), vec![x.t]);
    // what only G carries: W syncs G alone
    w_db.write_with(|w| w.at(x.t, title()).set(&s("from w"))).unwrap();
    block_on(w_db.wait_synced(SyncScope::All, W)).unwrap();
    until("N has W's write", || {
        let _ = x.n.sync_now();
        x.n.get(x.t, title()).unwrap() == Some(s("from w"))
    });
    assert_eq!(x.p.get(x.t, title()).unwrap(), Some(s("from w")), "the route answers");
    let r = x.p.write_with(|w| w.at(x.t, title()).set(&s("from p")));
    assert!(matches!(r, Err(Error::Invalid(_))), "{r:?}");
    assert!(matches!(x.p.grant(x.t, x.actor, Role::Read, Default::default()), Err(Error::Invalid(_))));
    assert_eq!(x.n.get(x.t, title()).unwrap(), Some(s("from w")), "nothing written");
    // other things of G are not split
    x.p.write_with(|w| w.at(x.g, title()).set(&s("on g"))).unwrap();
    assert_eq!(x.n.get(x.g, title()).unwrap(), Some(s("on g")));
    // home: no split left, and the write reaches W through G
    block_on(x.n.wait_synced(SyncScope::Group(x.g), W)).unwrap();
    block_on(x.p.group_source(x.g, GroupSource::Local)).unwrap();
    assert!(x.p.status().unwrap().split.is_empty());
    x.p.write_with(|w| w.at(x.t, title()).set(&s("from p"))).unwrap();
    block_on(x.p.wait_synced(SyncScope::Group(x.t), W)).unwrap();
    until("W and N have it", || {
        let _ = w_db.sync_now();
        let _ = x.n.sync_now();
        w_db.get(x.t, title()).unwrap() == Some(s("from p")) && x.n.get(x.t, title()).unwrap() == Some(s("from p"))
    });
    drop(x.host);
}

// spec/sync.md §10: a split can arrive from elsewhere, where nothing could refuse it: another holder of H shares routed `t` into H; reads stay where they were, the next write here says why it is refused, and `status` shows it
#[test]
fn a_split_arriving_from_another_node_refuses_the_next_write() {
    let x = world();
    let h = second_group(&x);
    until("N has H", || {
        let _ = x.n.sync_now();
        x.n.knows(h) && x.n.status().unwrap().groups.contains_key(&h)
    });
    x.attach_p();
    x.to_remote();
    x.p.write_with(|w| w.at(x.t, title()).set(&s("acked"))).unwrap();
    assert!(x.p.status().unwrap().split.is_empty());
    x.n.share_into(x.t, h, Role::Write, Default::default()).unwrap();
    block_on(x.n.wait_synced(SyncScope::Group(h), W)).unwrap();
    until("P learnt it through H", || {
        let _ = x.p.sync_now();
        x.p.status().unwrap().split.contains(&x.t)
    });
    assert_eq!(x.p.get(x.t, title()).unwrap(), Some(s("acked")));
    let r = x.p.write_with(|w| w.at(x.t, title()).set(&s("again")));
    let Err(Error::Invalid(why)) = r else { panic!("{r:?}") };
    assert!(why.contains(&h.to_string()) && why.contains(&x.g.to_string()), "{why}");
    drop(x.host);
}

// spec/sync.md §10: placing a routed thing in a group synced here changes no source: a write acknowledged through the route does not read as gone; with no edge H does not carry it, so writes go on
#[test]
fn placing_a_routed_thing_in_a_local_group_changes_nothing() {
    let x = world();
    let h = second_group(&x);
    x.attach_p();
    x.to_remote();
    x.p.write_with(|w| w.at(x.t, title()).set(&s("acked"))).unwrap();
    assert_eq!(x.p_local_copy(), Some(s("first")));
    x.p.write_with(|w| w.place(x.t, h)).unwrap();
    assert_eq!(x.p.get(x.t, title()).unwrap(), Some(s("acked")));
    assert!(x.p.status().unwrap().split.is_empty());
    x.p.write_with(|w| w.at(x.t, title()).set(&s("again"))).unwrap();
    assert_eq!(x.n.get(x.t, title()).unwrap(), Some(s("again")));
    // with a shared edge it would be split: refused, two sources
    assert!(matches!(x.p.share_into(x.t, h, Role::Read, Default::default()), Err(Error::Invalid(_))));
    drop(x.host);
}

// spec/sync.md §10, notes/client-port.md §8: a client of this node reads no copy of a routed thing, even one a local group still feeds
#[test]
fn a_client_of_this_node_reads_no_split_thing() {
    let x = world();
    let h = second_group(&x);
    x.p.share_into(x.t, h, Role::Write, Default::default()).unwrap();
    let (a, _) = x.p.add_client(None).unwrap();
    x.p.grant(x.t, a, Role::Read, Default::default()).unwrap();
    assert!(x.p.engine(|e| e.readable_by(&a, &x.t)));
    x.attach_p();
    x.to_remote();
    assert!(!x.p.engine(|e| e.readable_by(&a, &x.t)));
    drop(x.host);
}

// spec/sync.md §10, notes/client-port.md §6 Moving: a group held here without a live label comes home: this engine's role decides (the route would ask the node, where the client's actor reads nothing of it), and its first label is written while the route still stands
#[test]
fn a_group_without_a_label_here_comes_home() {
    let x = world();
    x.attach_p();
    let h = x.p.write_with(|w| {
        let h = w.create(x.p.me())?;
        w.make_group(h)?;
        Ok(h)
    }).unwrap();
    x.p.set_route(h, Some(x.nc.to_string()));
    block_on(x.p.group_source(h, GroupSource::Local)).unwrap();
    assert!(x.p.routes().is_empty());
    assert!(x.p.status().unwrap().groups.contains_key(&h));
    drop(x.host);
}

// spec/data-model.md §9, notes/client-port.md §3, §6: removing a client granted on a group this node reads at another node ends its sessions and refuses the demotion rather than commit it to a copy that does not sync; home again, the same call finishes
#[test]
fn removing_a_client_of_a_routed_group_waits_for_it_to_come_home() {
    let x = world();
    let (a, _sec) = x.p.add_client(None).unwrap();
    x.p.grant(x.g, a, Role::Read, Default::default()).unwrap();
    block_on(x.p.wait_synced(SyncScope::Group(x.g), W)).unwrap();
    x.attach_p();
    x.to_remote();
    let r = x.p.remove_client(a);
    assert!(matches!(r, Err(Error::Unsupported(_))), "{r:?}");
    assert!(x.p.engine(|e| e.roster(&x.g).contains_key(&a)), "nothing written to the local copy");
    assert!(x.p.clients().unwrap().iter().any(|c| c.actor == a), "the entry stays, ended, for the retry");
    block_on(x.n.wait_synced(SyncScope::Group(x.g), W)).unwrap();
    block_on(x.p.group_source(x.g, GroupSource::Local)).unwrap();
    assert!(x.p.remove_client(a).unwrap());
    assert!(!x.p.engine(|e| e.roster(&x.g).contains_key(&a)));
    drop(x.host);
}

// spec/sync.md §10, notes/client-port.md §1 Reconnect: `watch_roster` and `on_diagnostic` started while the node is down say nothing (no way to) and come up with the connection, each its value once
#[test]
fn roster_and_diagnostic_watches_started_while_down_come_up() {
    let x = world();
    let c = x.thin("c1");
    x.net.partition("c1", "n");
    x.net.disconnect("c1", "n");
    until("down", || c.get(x.t, title()).is_err());
    let (tx, rx) = channel();
    let _r = c.watch_roster(x.g, move |_, r| {
        let _ = tx.send(r);
    });
    let (dt, dr) = channel();
    let _d = c.on_diagnostic(move |_, d| {
        let _ = dt.send(d.detail.clone());
    });
    assert!(rx.recv_timeout(SHORT).is_err(), "quiet while down");
    x.net.heal("c1", "n");
    let first = rx.recv_timeout(W).unwrap();
    assert!(first.contains_key(&x.actor));
    until("the diagnostics subscription is live", || c.get(x.t, title()).is_ok());
    c.settle();
    let t = x.t;
    x.n.engine(|e| e.report(osis_node::Diagnostic { kind: osis_node::DiagnosticKind::BadInput, tids: vec![t], commit: None, peer: None, detail: "after the reconnect".into() }));
    assert_eq!(dr.recv_timeout(W).unwrap(), "after the reconnect");
    assert!(rx.recv_timeout(SHORT).is_err(), "one roster, no second delivery");
    drop(x.host);
}

// spec/wire.md §9, spec/sync.md §3: a share into a second group sends an inbox blob about the thing,
// which names no group's label: moving the first group away and home finds its label free.
#[test]
fn moving_home_after_a_share_into_a_second_group() {
    let x = world();
    // sorting after g: a thing's first group by tid was the one named
    let h = loop {
        let h = x.p.write_with(|w| {
            let h = w.create(x.p.me())?;
            w.make_group(h)?;
            Ok(h)
        }).unwrap();
        if h > x.g {
            break h;
        }
    };
    x.p.sync(h, &[]).unwrap();
    block_on(x.p.wait_synced(SyncScope::Group(h), W)).unwrap();
    x.p.share_into(x.t, h, Role::Write, Default::default()).unwrap();
    block_on(x.p.wait_synced(SyncScope::Group(h), W)).unwrap();
    // the blob opened here before the group stops syncing
    until("the share's inbox blob opened at P", || {
        let _ = x.p.sync_now();
        x.p.sync_engine(|e| {
            let labels: Vec<_> = e.labels().into_iter().map(|(_, l)| l.id).collect();
            labels.iter().any(|l| e.entries(l).iter().any(|(_, k)| matches!(k, osis::internals::node::sync::EntryKind::Inbox(Some(_)))))
        })
    });
    x.attach_p();
    x.to_remote();
    block_on(x.p.group_source(x.g, GroupSource::Local)).unwrap();
    assert!(x.p.routes().is_empty());
    drop(x.host);
}
