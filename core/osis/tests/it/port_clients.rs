//! Thin clients on the client port (notes/client-port.md §3): a node serves a bearer secret its
//! `clients.0^` lists over a keyed listener (here the in-process transport), acting as the client's
//! actor for every row. The rights of that actor are the whole authorization.

use crate::common::{T0, ak, block_on};
use crate::port::{Raw, set_batch};
use osis::internals::Internals as _;
use osis::{ClientSecret, CommitQuery, Config, Demotion, Error, HostAddr, LinkOpts, Lower, ManualClock, MemStore, Osis, Role, Runtime, Scope, StoreAt, Tid, Transport, Value, WaitForSync, WallMs};
use osis_proto::{Command, Outcome};
use osis_schema::core_types as ct;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::channel;
use std::time::Duration;

const WRITE: u64 = 11;
const GET: u64 = 1;
const SETTLE: u64 = 20;

static NAMES: AtomicUsize = AtomicUsize::new(0);

/// A node with a runtime on the in-process transport, on a manual clock; things it serves.
struct Node {
    n: Osis,
    net: osis_transport::Net,
    clock: Arc<ManualClock>,
    store: MemStore,
    /// A group the person owns, a thing it owns, a thing the person owns placed in it, one only
    /// the person owns, another group with a thing of its own.
    g: Tid,
    t: Tid,
    placed: Tid,
    out: Tid,
    h: Tid,
    u: Tid,
}

fn open(store: &MemStore, net: &osis_transport::Net, clock: &Arc<ManualClock>, create: bool) -> Osis {
    let mut c = Config::at(StoreAt::Memory(store.clone()));
    c.runtime = Runtime::Own;
    c.transport = Some(Transport::InProcess(net.endpoint("n")));
    c.clock = Some(clock.clone());
    let n = if create { Osis::create(c).unwrap().0 } else { Osis::open(c).unwrap() };
    // the keyed listener is up once reach.0 is published
    for _ in 0..2000 {
        if n.sync_engine(|s| s.own_reach()).is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    n
}

fn node() -> Node {
    let (net, clock, store) = (osis_transport::Net::new(1), Arc::new(ManualClock::new(WallMs(T0))), MemStore::new());
    let n = open(&store, &net, &clock, true);
    let me = n.me();
    let (g, t, placed, out, h, u) = n
        .write_with(|w| {
            let g = w.create(me)?;
            w.make_group(g)?;
            let t = w.create(g)?;
            w.place(t, g)?;
            let placed = w.create(me)?;
            w.place(placed, g)?;
            let out = w.create(me)?;
            let h = w.create(me)?;
            w.make_group(h)?;
            let u = w.create(h)?;
            Ok((g, t, placed, out, h, u))
        })
        .unwrap();
    for x in [t, placed, out, u] {
        n.write_with(|w| w.at(x, ak("name.0")).set(&Value::Str("x".into()))).unwrap();
    }
    Node { n, net, clock, store, g, t, placed, out, h, u }
}

impl Node {
    fn addr(&self) -> HostAddr {
        HostAddr::new("mem://n-peer", self.key())
    }

    fn key(&self) -> [u8; 32] {
        let secret = self.n.sync_engine(|s| s.dialable_secret());
        osis_transport::InProcess::public_key(&osis_transport::StaticSecret::from_bytes(*secret.expose()))
    }

    fn attach(&self, secret: &ClientSecret) -> osis::Result<Osis> {
        let mut c = Config::memory();
        c.transport = Some(Transport::InProcess(self.net.endpoint(&format!("c{}", NAMES.fetch_add(1, Ordering::Relaxed)))));
        // a reopened node: its reach is stored, its listener comes up a moment later
        for _ in 0..2000 {
            match Osis::attach_client(&self.addr(), secret, c.clone()) {
                Err(Error::Network(m)) if m.contains("unreachable") => std::thread::sleep(Duration::from_millis(10)),
                r => return r,
            }
        }
        panic!("the node's listener did not come up");
    }

    /// A client with `role` on the group.
    fn client(&self, role: Role) -> (Tid, ClientSecret, Osis) {
        let (a, s) = self.n.add_client(None).unwrap();
        self.n.grant(self.g, a, role, Default::default()).unwrap();
        let c = self.attach(&s).unwrap();
        (a, s, c)
    }

    fn raw(&self, secret: &ClientSecret) -> Raw {
        let ep = self.net.endpoint(&format!("r{}", NAMES.fetch_add(1, Ordering::Relaxed)));
        let mut r = Raw::over(&ep, osis_transport::Address { url: "mem://n-peer".into(), key: self.key() });
        let a = r.ask(Command::Auth { token: 0, session: [1; 16], secret: Some(osis_crypto::Secret32::from_bytes(*secret.expose())) }, 0);
        assert!(matches!(a, Ok(Outcome::Ok { .. })), "{a:?}");
        r
    }

    /// Served sessions now.
    fn served(&self) -> usize {
        self.n.sync_engine(|s| s.served_opened().len())
    }

    /// Waits until `f` holds (the port worker and the driver run off this thread).
    fn until(&self, f: impl Fn(&Node) -> bool) {
        for _ in 0..2000 {
            if f(self) {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("condition not reached");
    }
}

/// Everything a client can ask about a tid, errors with the tid taken out: a thing its actor may
/// not read must answer this exactly as a tid nobody knows.
fn answers(c: &Osis, t: Tid) -> String {
    let k = ak("name.0");
    let e = |r: osis::Result<String>| r.unwrap_or_else(|e| format!("{e:?}").replace(&format!("{t:?}"), "T"));
    let mut out = vec![
        e(c.at(t, k.clone()).get_value().map(|v| format!("{v:?}"))),
        e(c.aspects(t).map(|v| format!("{v:?}"))),
        format!("{:?}", c.knows(t)),
        format!("{:?}", c.groups_of(t)),
        format!("{:?}", c.roster(t)),
        format!("{:?}", c.role_on(t)),
        format!("{:?}", c.owner_of(t)),
        format!("{:?}", c.created(t)),
        format!("{:?}", c.changed(t)),
        format!("{:?}", c.same_thing(t, t)),
        e(c.commits(&CommitQuery::new().scope(Scope::Thing(t))).map(|v| format!("{v:?}"))),
        e(c.at(t, k.clone()).stream().map(|s| format!("{:?}", s.map(|x| x.len())))),
        e(c.write_with(|w| w.at(t, k.clone()).set(&Value::Int(1))).map(|_| "written".to_string())),
        e(c.write_with(|w| w.delete(t)).map(|_| "written".to_string())),
        e(c.undo(&Scope::Thing(t)).map(|v| format!("{v:?}"))),
    ];
    let w = c.at(t, k).watch().unwrap();
    out.push(format!("{:?}", w.current()));
    out.join("\n")
}

// spec/wire.md §11.2, notes/client-port.md §3: a client granted Read on a group reads what the group owns; the person, its node, a link's K and seed, another group and its thing, a thing placed in the group but owned elsewhere all answer every read and write exactly as a tid nobody knows; no row runs as the node's account
#[test]
fn reads_are_exactly_the_actors() {
    let x = node();
    let (a, _, c) = x.client(Role::Read);
    assert_eq!(c.me(), a);
    assert_eq!(c.home(), a);
    assert_eq!(c.at(x.t, ak("name.0")).get_value().unwrap(), Some(Value::Str("x".into())));
    assert_eq!(c.role_on(x.t), Some(Role::Read));
    assert_eq!(c.role_on(x.g), Some(Role::Read));
    assert!(c.knows(x.t));
    assert_eq!(c.groups_of(x.t), x.n.groups_of(x.t));
    assert_eq!(c.owner_of(x.t), Some(x.g));
    assert_eq!(c.commits(&CommitQuery::new().scope(Scope::Thing(x.t))).unwrap(), x.n.commits(&CommitQuery::new().scope(Scope::Thing(x.t))).unwrap());
    // a group listing it shows only groups it reads
    x.n.write_with(|w| w.place(x.t, x.h)).unwrap();
    assert!(c.groups_of(x.t).item_of.contains(&x.g) && !c.groups_of(x.t).item_of.contains(&x.h));
    assert!(x.n.groups_of(x.t).item_of.contains(&x.h));
    // what it may not read: the person, its node, a link, another group
    let link_target = x.u;
    let _link = x.n.make_link(link_target, Role::Read, LinkOpts { until: None, single_use: false, direct: true }).unwrap();
    let k = x.n.links(link_target)[0].id;
    let home = x.n.get(x.n.me(), ct::GROUP).unwrap().unwrap();
    let seed = home.items.iter().copied().find(|i| x.n.aspects(*i).unwrap().iter().any(|a| a.as_str() == "link:seed.0")).unwrap();
    let ghost = Tid::from_bytes([9; 15]);
    let g_answers = answers(&c, ghost);
    let d = |t: Tid| answers(&c, t).replace(&format!("{t:?}"), "T");
    let gd = g_answers.replace(&format!("{ghost:?}"), "T");
    assert!(gd.contains("UnknownThing"), "{gd}");
    for (name, t) in [("person", x.n.me()), ("node", x.n.node()), ("k", k), ("seed", seed), ("other group", x.h), ("its thing", x.u), ("placed only", x.placed), ("owned elsewhere", x.out)] {
        assert_eq!(d(t), gd, "{name}");
    }
    // nothing of it changed through those attempts
    assert_eq!(x.n.get(x.out, ak("name.0")).unwrap(), Some(Value::Str("x".into())));
    assert!(x.n.knows(x.out));
    // unscoped: no entry on what it may not read, and status lists no group it may not read
    let all = c.commits(&CommitQuery::new()).unwrap();
    assert!(!all.is_empty());
    assert!(all.iter().all(|e| e.aspects.iter().all(|(t, _)| *t == x.t || *t == x.g || *t == a)), "{all:?}");
    x.n.sync(x.h, &[]).unwrap();
    assert!(x.n.status().unwrap().groups.contains_key(&x.h));
    assert!(!c.status().unwrap().groups.contains_key(&x.h));
}

// spec/wire.md §11.2, notes/client-port.md §3 (Acting as the actor): a write needs the actor's rights, however wide the node's: Permission on what it only reads, its commits carry its actor and this node as author; created things need a writable owner, its own actor refused; a batch naming another actor is refused; placing what it may not read fails as unknown; a purge needs admin
#[test]
fn writes_are_the_actors() {
    let x = node();
    let name = ak("name.0");
    let (a, s, c) = x.client(Role::Read);
    assert!(matches!(c.write_with(|w| w.at(x.t, name.clone()).set(&Value::Int(1))), Err(Error::Permission { tid, .. }) if tid == x.t));
    assert!(matches!(c.write_with(|w| w.create(x.g)), Err(Error::Permission { .. })), "read on the owner is no write");
    x.n.change_edge(x.g, a, Role::Write, Default::default()).unwrap();
    c.write_with(|w| w.at(x.t, name.clone()).set(&Value::Int(2))).unwrap();
    assert_eq!(x.n.get(x.t, name.clone()).unwrap(), Some(Value::Int(2)));
    let last = &x.n.commits(&CommitQuery::new().scope(Scope::Thing(x.t))).unwrap()[0];
    assert_eq!((last.commit.actor, last.commit.node), (a, x.n.node()));
    // created things
    let made = c.write_with(|w| {
        let m = w.create(x.g)?;
        w.at(m, name.clone()).set(&Value::Int(3))?;
        Ok(m)
    });
    let made = made.unwrap();
    assert_eq!(x.n.owner_of(made), Some(x.g));
    assert_eq!(c.get(made, name.clone()).unwrap(), Some(Value::Int(3)));
    assert!(matches!(c.write_with(|w| w.create(a)), Err(Error::Invalid(_))), "its own actor as owner");
    assert!(matches!(c.write_with(|w| w.create(x.n.me())), Err(Error::Permission { .. })), "the person as owner");
    // a batch naming another actor: a raw session (the API records its own)
    let mut r = x.raw(&s);
    let forged = r.call_at(1, WRITE, set_batch(1, x.n.me(), x.t, &name, Value::Int(4)));
    assert!(matches!(forged, Outcome::Err { .. }), "{forged:?}");
    assert_eq!(x.n.get(x.t, name.clone()).unwrap(), Some(Value::Int(2)));
    // placing what it may not read
    assert!(matches!(c.write_with(|w| w.place(x.out, x.g)), Err(Error::UnknownThing { .. })));
    assert!(matches!(c.write_with(|w| w.place(x.t, x.h)), Err(Error::UnknownThing { .. })), "a group it does not read");
    // a purge needs admin, whatever the node may do
    assert!(matches!(c.write_with(|w| w.at(x.t, name.clone()).purge()), Err(Error::Permission { .. })));
    x.n.change_edge(x.g, a, Role::Admin, Default::default()).unwrap();
    c.write_with(|w| w.at(x.t, name.clone()).purge()).unwrap();
    // an aspect of the node needs the actor's rights too
    let node_thing = x.n.node();
    assert!(matches!(c.write_with(|w| w.at(node_thing, ct::CLIENTS).remove()), Err(Error::UnknownThing { .. })));
}

// spec/commits.md §7, notes/client-port.md §3 (Undo/redo/revert): undo picks the actor's own commits; a revert of someone else's needs the actor's write on all it touches; a revert of what it may not read is unknown
#[test]
fn undo_and_revert_are_the_actors() {
    let x = node();
    let (a, b) = (ak("t:a.0"), ak("t:b.0"));
    let (ca, _, c) = x.client(Role::Write);
    x.n.write_with(|w| w.at(x.t, a.clone()).set(&Value::Int(1))).unwrap();
    c.write_with(|w| w.at(x.t, b.clone()).set(&Value::Int(2))).unwrap();
    x.n.write_with(|w| w.at(x.t, a.clone()).set(&Value::Int(3))).unwrap();
    // only its own: the node's newer write stays
    assert!(c.undo(&Scope::Thing(x.t)).unwrap().is_some());
    assert_eq!(x.n.get(x.t, a.clone()).unwrap(), Some(Value::Int(3)));
    assert_eq!(x.n.get(x.t, b.clone()).unwrap(), None);
    c.redo(&Scope::Thing(x.t)).unwrap().unwrap();
    assert_eq!(x.n.get(x.t, b.clone()).unwrap(), Some(Value::Int(2)));
    assert!(c.undo(&Scope::Thing(x.t)).unwrap().is_some());
    assert!(c.undo(&Scope::Thing(x.t)).unwrap().is_none(), "nothing of its own is left");
    let q = |t: Tid| CommitQuery::new().scope(Scope::Thing(t));
    // someone else's on what it writes
    let id = x.n.commits(&q(x.t)).unwrap().iter().find(|e| e.commit.actor != ca && e.aspects.iter().any(|(_, k)| *k == a)).unwrap().commit.id;
    c.revert(id).unwrap();
    // what it may not read
    let hidden = x.n.commits(&q(x.u)).unwrap()[0].commit.id;
    assert!(matches!(c.revert(hidden), Err(Error::Invalid(m)) if m.contains("unknown commit")));
    // Read only: a revert it may not write
    x.n.write_with(|w| w.at(x.t, a.clone()).set(&Value::Int(5))).unwrap();
    let mine = x.n.commits(&q(x.t)).unwrap()[0].commit.id;
    block_on(x.n.demote(x.g, ca, Lower::To(Role::Read), Demotion { sync: WaitForSync::Skip, backdate: None })).unwrap();
    assert!(matches!(c.revert(mine), Err(Error::Permission { .. })));
    assert_eq!(x.n.get(x.t, a).unwrap(), Some(Value::Int(5)));
}

// spec/sync.md §10, notes/client-port.md §3 (until, Checked at execution): an expired client: a request after the clock passed its until is refused at execution before any tick closed it; the driver then closes the connection with no other change; a later Auth is refused; `until` at or before now is refused; a restart keeps the entry and the rule
#[test]
fn until_ends_the_client() {
    let x = node();
    let name = ak("name.0");
    assert!(matches!(x.n.add_client(Some(WallMs(T0))), Err(Error::Invalid(_))));
    assert!(matches!(x.n.add_client(Some(WallMs(T0 - 1))), Err(Error::Invalid(_))));
    let (a, s) = x.n.add_client(Some(WallMs(T0 + 60_000))).unwrap();
    x.n.grant(x.g, a, Role::Write, Default::default()).unwrap();
    assert_eq!(x.n.clients().unwrap(), vec![osis::Client { actor: a, until: Some(WallMs(T0 + 60_000)) }]);
    let mut r = x.raw(&s);
    assert!(matches!(r.call_at(1, GET, vec![Value::Tid(x.t), Value::Str("name.0".into()), Value::List(vec![])]), Outcome::Ok { .. }));
    let c = x.attach(&s).unwrap();
    c.write_with(|w| w.at(x.t, name.clone()).set(&Value::Int(1))).unwrap();
    x.clock.advance(60_000);
    // whatever the driver did by now, the row does not run
    assert!(c.write_with(|w| w.at(x.t, name.clone()).set(&Value::Int(2))).is_err());
    assert_eq!(x.n.get(x.t, name.clone()).unwrap(), Some(Value::Int(1)));
    // the driver's wake for its until (asked for: osis-node `bound_sessions_end_with_their_entry`)
    x.n.feed(osis_node::sync::Event::Tick);
    x.until(|x| x.served() == 0);
    assert!(matches!(x.attach(&s), Err(Error::Unsupported(_))));
    // the entry stays until removed, its actor with its grants
    assert!(x.n.clients().unwrap().iter().any(|e| e.actor == a));
    assert!(x.n.roster(x.g).contains_key(&a));
    drop((c, r));
}

// spec/data-model.md §9, notes/client-port.md §3 (until), restart with a timer pending: sessions do not survive a restart and no timer is stored: a reopened node takes a client's Auth before its until and ends it at its until from the entry alone
#[test]
fn restart_with_a_client_until_pending() {
    let (net, clock, store) = (osis_transport::Net::new(1), Arc::new(ManualClock::new(WallMs(T0))), MemStore::new());
    let n = open(&store, &net, &clock, true);
    let (a, s) = n.add_client(Some(WallMs(T0 + 60_000))).unwrap();
    n.close().unwrap();
    let n = open(&store, &net, &clock, false);
    let x = Node { n, net, clock, store, g: a, t: a, placed: a, out: a, h: a, u: a };
    let c = x.attach(&s).unwrap();
    assert_eq!(c.me(), a);
    assert_eq!(x.served(), 1);
    x.clock.advance(60_000);
    x.n.feed(osis_node::sync::Event::Tick);
    x.until(|x| x.served() == 0);
    assert!(matches!(x.attach(&s), Err(Error::Unsupported(_))));
    // a restart past it: refused from the entry alone
    let Node { n, net, clock, store, .. } = x;
    n.close().unwrap();
    let n = open(&store, &net, &clock, false);
    let x = Node { n, net, clock, store, g: a, t: a, placed: a, out: a, h: a, u: a };
    assert!(matches!(x.attach(&s), Err(Error::Unsupported(_))));
}

// spec/permissions.md §3, notes/client-port.md §3 (remove_client): removal closes its connections, demotes its actor everywhere with the normal rotation, and removes the entry; the next Auth fails; a second call says none; a stale session never comes back; a demotion made elsewhere (the node's own API) leaves an entry whose actor reads nothing
#[test]
fn remove_client_revokes() {
    let x = node();
    let (a, s, c) = x.client(Role::Write);
    x.n.grant(x.h, a, Role::Read, Default::default()).unwrap();
    assert!(c.knows(x.u));
    let keys_before = x.n.engine(|e| e.epochs(&x.g).map(|ep| format!("{:?}", ep.role(Role::Read).newest_held().map(|h| h.0))));
    assert_eq!(x.served(), 1);
    assert!(x.n.remove_client(a).unwrap());
    x.until(|x| x.served() == 0);
    assert!(!x.n.roster(x.g).contains_key(&a) && !x.n.roster(x.h).contains_key(&a));
    assert_ne!(x.n.engine(|e| e.epochs(&x.g).map(|ep| format!("{:?}", ep.role(Role::Read).newest_held().map(|h| h.0)))), keys_before, "the removal rotated");
    assert!(x.n.clients().unwrap().is_empty());
    assert!(matches!(x.attach(&s), Err(Error::Unsupported(_))));
    assert!(c.get(x.t, ak("name.0")).is_err());
    assert!(!x.n.remove_client(a).unwrap());
    assert!(!x.n.remove_client(x.n.me()).unwrap(), "only a registered client: never a demotion of something else");
    assert!(x.n.roster(x.n.me()).contains_key(&x.n.node()));
    // its until passed already (a removal cut short ends there): the removal still demotes
    let (late, s2) = x.n.add_client(Some(WallMs(T0 + 1))).unwrap();
    x.n.grant(x.g, late, Role::Read, Default::default()).unwrap();
    x.clock.advance(1);
    assert!(matches!(x.attach(&s2), Err(Error::Unsupported(_))));
    assert!(x.n.remove_client(late).unwrap());
    assert!(!x.n.roster(x.g).contains_key(&late));
    // demoted elsewhere: the entry stays, its actor reads nothing
    let (b, _, d) = x.client(Role::Read);
    assert!(d.knows(x.t));
    block_on(x.n.demote(x.g, b, Lower::Remove, Demotion { sync: WaitForSync::Skip, backdate: None })).unwrap();
    assert!(!d.knows(x.t));
    assert!(x.n.clients().unwrap().iter().any(|e| e.actor == b));
}

// spec/wire.md §11.2 (checked at the time it runs), notes/client-port.md §3: a write already queued when the client's entry goes does not run: the worker asks at execution, not at enqueue (the worker is held on a settle behind a callback of the node's while the entry goes; the grant is still there, so only that check stops it)
#[test]
fn queued_request_rechecked_at_execution() {
    let x = node();
    let name = ak("name.0");
    let (a, s, _c) = x.client(Role::Write);
    let mut r = x.raw(&s);
    // the node's dispatcher blocks on this callback, the worker on its settle behind it
    let (hold_tx, hold_rx) = channel::<()>();
    let (in_tx, in_rx) = channel::<()>();
    let _w = x.n.at(x.t, ak("t:hold.0")).on_change(move |_, _: osis::Change<Value>| {
        let _ = in_tx.send(());
        let _ = hold_rx.recv();
    });
    in_rx.recv_timeout(Duration::from_secs(20)).unwrap();
    r.send(Command::Call { token: 1, max_reply: osis_proto::client::SMALL_REPLY as u64, method: SETTLE, args: vec![] });
    r.pump(100);
    // queued behind the settle
    r.send(Command::Call { token: 2, max_reply: osis_proto::client::SMALL_REPLY as u64, method: WRITE, args: set_batch(1, a, x.t, &name, Value::Int(7)) });
    // both requests are at the worker (the sync engine answered nothing yet); revoke the entry alone
    r.pump(200);
    let node = x.n.node();
    x.n.write_with(|w| w.at(node, ct::CLIENTS).path(osis_schema::Path::root()).remove_key(&a)).unwrap();
    hold_tx.send(()).unwrap();
    x.until(|x| x.served() == 0);
    // the worker's queue drained: a settle of a live session of another client goes behind it
    let (_, _, d) = x.client(Role::Read);
    d.settle();
    assert_eq!(x.n.get(x.t, name).unwrap(), Some(Value::Str("x".into())), "the queued write did not run");
    assert_eq!(x.n.roster(x.g).get(&a).map(|e| e.role), Some(Role::Write), "the grant alone would have let it");
}

// spec/data-model.md §9 (`secret_hash`), notes/client-port.md §3: the secret's hash is what is kept, the secret never is; rotation invalidates the old secret and its live connections, keeps the actor and its grants; an unknown secret is refused
#[test]
fn secret_hash_and_rotation() {
    let x = node();
    let (a, s, c) = x.client(Role::Read);
    let e = x.n.get(x.n.node(), ct::CLIENTS).unwrap().unwrap().remove(&a).unwrap();
    assert_eq!(e.secret_hash, osis_base::hash::hash(s.expose()));
    assert_ne!(&e.secret_hash, s.expose());
    assert_eq!(format!("{s:?}").matches("Secret32(..)").count(), 1, "redacted");
    let auth = osis_proto::Message::Auth { id: 1, secret: Some(osis_crypto::Secret32::from_bytes(*s.expose())), session: [0; 16] };
    assert!(!format!("{auth:?}").contains(&format!("{:?}", s.expose()[0..4].to_vec())));
    assert!(matches!(x.attach(&ClientSecret::from_bytes([1; 32])), Err(Error::Unsupported(_))));
    assert!(matches!(x.n.rotate_client_secret(x.n.me()), Err(Error::Invalid(_))));
    let s2 = x.n.rotate_client_secret(a).unwrap();
    assert_ne!(s2.expose(), s.expose());
    x.until(|x| x.served() == 0);
    assert!(c.get(x.t, ak("name.0")).is_err());
    assert!(matches!(x.attach(&s), Err(Error::Unsupported(_))));
    let c2 = x.attach(&s2).unwrap();
    assert_eq!(c2.me(), a);
    assert!(c2.knows(x.t), "actor and grants kept");
}

// spec/wire.md §11.2, notes/client-port.md §2 (Writes): a client's nonce outcomes are its own: another client's same session id and nonce is a new write, a repeat of its own is answered once
#[test]
fn nonces_per_client() {
    let x = node();
    let name = ak("name.0");
    let (a, s, _c) = x.client(Role::Write);
    let (b, s2, _d) = x.client(Role::Write);
    let mut ra = x.raw(&s);
    let mut rb = x.raw(&s2);
    assert!(matches!(ra.call_at(1, WRITE, set_batch(1, a, x.t, &name, Value::Int(1))), Outcome::Ok { .. }));
    assert_eq!(x.n.get(x.t, name.clone()).unwrap(), Some(Value::Int(1)));
    assert!(matches!(rb.call_at(1, WRITE, set_batch(1, b, x.t, &name, Value::Int(2))), Outcome::Ok { .. }));
    assert_eq!(x.n.get(x.t, name.clone()).unwrap(), Some(Value::Int(2)), "the same session id and nonce of another client");
    assert!(matches!(ra.call_at(2, WRITE, set_batch(1, a, x.t, &name, Value::Int(3))), Outcome::Ok { .. }));
    assert_eq!(x.n.get(x.t, name).unwrap(), Some(Value::Int(2)), "its own repeat ran once");
}

// spec/wire.md §11.2, notes/client-port.md §2, §3: a watch sees what its actor may read, lapses when it stops being readable; a watch of what it never could read stays as silent as one of an unknown tid; process-wide rows are Unsupported
#[test]
fn watches_and_rows() {
    let x = node();
    let name = ak("name.0");
    let (a, _, c) = x.client(Role::Read);
    let w = c.at(x.t, name.clone()).watch().unwrap();
    let hidden = c.at(x.out, name.clone()).watch().unwrap();
    assert_eq!(hidden.current().unwrap(), None);
    x.n.write_with(|w| w.at(x.t, name.clone()).set(&Value::Int(1))).unwrap();
    x.n.write_with(|w| w.at(x.out, name.clone()).set(&Value::Int(1))).unwrap();
    c.settle();
    assert_eq!(w.current().unwrap(), Some(Value::Int(1)));
    assert_eq!(hidden.current().unwrap(), None, "nothing of what it cannot read");
    // a fired signal on what it may not read: not queued for it, not sent
    let (stx, srx) = channel();
    let sig = ak("t:sig.0*");
    let _s = c.at(x.out, sig.clone()).on_change(move |_, ch: osis::Change<Value>| stx.send(ch.value.unwrap()).unwrap()).unwrap();
    assert_eq!(srx.recv_timeout(Duration::from_secs(20)).unwrap(), None);
    x.n.write_with(|w| w.at(x.out, sig.clone()).set(&Value::Int(9))).unwrap();
    c.settle();
    assert!(srx.try_recv().is_err(), "a signal of what it cannot read");
    // diagnostics: those naming only what it reads
    let (dtx, drx) = channel();
    let _d = c.on_diagnostic(move |_, d| dtx.send(d.detail).unwrap());
    let diag = |tids: Vec<Tid>, detail: &str| osis_node::Diagnostic { kind: osis_node::DiagnosticKind::Storage, tids, commit: None, peer: None, detail: detail.into() };
    x.n.engine(|e| {
        e.report(diag(vec![x.out], "hidden"));
        e.report(diag(vec![], "general"));
        e.report(diag(vec![x.t, x.out], "partly"));
        e.report(diag(vec![x.t], "shown"));
    });
    assert_eq!(drx.recv_timeout(Duration::from_secs(20)).unwrap(), "shown");
    assert!(drx.try_recv().is_err());
    let subs = x.n.watches();
    block_on(x.n.demote(x.g, a, Lower::Remove, Demotion { sync: WaitForSync::Skip, backdate: None })).unwrap();
    x.n.write_with(|w| w.at(x.t, name.clone()).set(&Value::Int(2))).unwrap();
    c.settle();
    assert!(!matches!(w.current(), Ok(Some(Value::Int(2)))), "{:?}", w.current());
    // the one it could read lapsed; the one it never could stays, as for an unknown tid
    assert_eq!(x.n.watches(), subs - 1, "exactly the watch of what it stopped reading");
    drop(hidden);
    // rows
    assert!(matches!(c.sync(x.g, &[]), Err(Error::Unsupported(_))));
    assert!(matches!(c.grant(x.t, a, Role::Admin, Default::default()), Err(Error::Unsupported(_))));
    assert!(matches!(c.add_client(None), Err(Error::Unsupported(_))));
    assert!(matches!(c.clients(), Err(Error::Unsupported(_))));
    assert!(matches!(c.remove_client(a), Err(Error::Unsupported(_))));
    assert!(matches!(c.rotate_client_secret(a), Err(Error::Unsupported(_))));
    assert!(matches!(c.register_schema_source("x.osis", "version 1;\naspect x:y.0: int;\n"), Err(Error::Unsupported(_))));
}

// spec/wire.md §11.2 (Error 4), notes/client-port.md §3: the API's view of the connection cap: the ninth attachment fails Network, one going frees a slot
#[test]
fn attachments_past_the_cap() {
    let x = node();
    let (_, s) = x.n.add_client(None).unwrap();
    let mut all: Vec<Osis> = (0..osis::MAX_CONNS_PER_CLIENT).map(|_| x.attach(&s).unwrap()).collect();
    assert!(matches!(x.attach(&s), Err(Error::Network(_))));
    drop(all.pop());
    x.until(|x| x.served() < osis::MAX_CONNS_PER_CLIENT + 1);
    for _ in 0..2000 {
        if x.attach(&s).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("a slot was not freed");
}

// spec/sync.md §10 (never on another transport), notes/client-port.md §3 (Owner rows): the registry calls run through a daemon's Owner session; a client secret never goes to a unix socket
#[test]
fn registry_through_the_owner_session() {
    let (net, clock, store) = (osis_transport::Net::new(1), Arc::new(ManualClock::new(WallMs(T0))), MemStore::new());
    let n = open(&store, &net, &clock, true);
    let dir = std::env::temp_dir().join(format!("osis-port-clients-{}-{}", std::process::id(), NAMES.fetch_add(1, Ordering::Relaxed)));
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("n.sock");
    n.listen_unix(&sock).unwrap();
    let o = Osis::attach(&sock, Config::memory()).unwrap();
    let (a, s) = o.add_client(Some(WallMs(T0 + 1000))).unwrap();
    assert_eq!(n.clients().unwrap(), o.clients().unwrap());
    assert_eq!(n.get(n.node(), ct::CLIENTS).unwrap().unwrap().remove(&a).unwrap().secret_hash, osis_base::hash::hash(s.expose()));
    let s2 = o.rotate_client_secret(a).unwrap();
    assert_eq!(n.get(n.node(), ct::CLIENTS).unwrap().unwrap().remove(&a).unwrap().secret_hash, osis_base::hash::hash(s2.expose()));
    assert!(o.remove_client(a).unwrap());
    assert!(!o.remove_client(a).unwrap());
    let unix = HostAddr::new(&format!("unix://{}", sock.display()), [0; 32]);
    assert!(matches!(Osis::attach_client(&unix, &s2, Config::memory()), Err(Error::Invalid(_))));
    drop((o, n));
    let _ = std::fs::remove_dir_all(&dir);
}

// spec/wire.md §11.2, notes/client-port.md §3: `group.0` written as an aspect (a path op, a whole value) places nothing the actor may not read, as the group calls: the check judges what the mutation writes, not which call recorded it
#[test]
fn group_aspect_ops_place_only_what_it_reads() {
    let x = node();
    let items = osis_schema::Path(vec![osis_schema::Step::Field(0)]);
    let (_, _, c) = x.client(Role::Write);
    let hidden = |r: osis::Result<()>| assert!(matches!(r, Err(Error::UnknownThing { .. })), "{r:?}");
    hidden(c.write_with(|w| w.at(x.g, ct::GROUP).path(items.clone()).add(&x.out)));
    hidden(c.write_with(|w| w.at(x.g, ct::GROUP).path(items.clone()).add(&Tid::from_bytes([9; 15]))));
    let with_out = ct::Group { items: [x.t, x.out].into_iter().collect(), subgroups: Default::default() };
    hidden(c.write_with(|w| w.at(x.g, ct::GROUP).set(&with_out)));
    hidden(c.write_with(|w| w.at(x.g, ct::GROUP).replace(&with_out)));
    assert!(!x.n.groups_of(x.out).item_of.contains(&x.g));
    // what it reads, and what the batch creates
    let g2 = c
        .write_with(|w| {
            let m = w.create(x.g)?;
            w.at(x.g, ct::GROUP).path(items.clone()).add(&m)?;
            Ok(m)
        })
        .unwrap();
    assert!(x.n.groups_of(g2).item_of.contains(&x.g));
    // a listed name it may not read may go: it holds write on the list
    x.n.write_with(|w| w.place(x.out, x.g)).unwrap();
    c.write_with(|w| w.unplace(x.out, x.g)).unwrap();
    assert!(!x.n.groups_of(x.out).item_of.contains(&x.g));
}

// spec/wire.md §11.2 (a thing the actor may not read answers as unknown), spec/commits.md §7: a group it may not read scopes nothing, even an item it reads: no membership oracle, and no undo through it
#[test]
fn hidden_group_scopes_nothing() {
    let x = node();
    let name = ak("name.0");
    let (_, _, c) = x.client(Role::Write);
    x.n.write_with(|w| w.place(x.t, x.h)).unwrap();
    c.write_with(|w| w.at(x.t, name.clone()).set(&Value::Int(1))).unwrap();
    let ghost = Tid::from_bytes([9; 15]);
    let scoped = |g: Tid| c.commits(&CommitQuery::new().scope(Scope::Group(g))).unwrap();
    assert!(scoped(ghost).is_empty());
    assert!(scoped(x.h).is_empty(), "an item's commits through a group it may not read");
    assert_eq!(c.undo(&Scope::Group(x.h)).unwrap(), None);
    assert_eq!(x.n.get(x.t, name.clone()).unwrap(), Some(Value::Int(1)));
    assert!(!scoped(x.g).is_empty());
    assert!(c.undo(&Scope::Group(x.g)).unwrap().is_some());
    // the synthetic list of its groups shows what `groups_of` shows
    assert_eq!(c.at(x.t, ak("groups.0")).get_value().unwrap(), Some(Value::Set([Value::Tid(x.g)].into_iter().collect())));
    assert!(matches!(x.n.at(x.t, ak("groups.0")).get_value().unwrap(), Some(Value::Set(s)) if s.len() == 2));
}

// spec/wire.md §11.2, notes/client-port.md §3 (Undo/redo/revert): a revert that would write what the actor may not read is refused naming only what it reads; an ephemeral change of a thing it may not read answers as one with no log here
#[test]
fn revert_names_only_what_it_reads() {
    let x = node();
    let name = ak("name.0");
    let (_, _, c) = x.client(Role::Write);
    let id = {
        let mut w = x.n.write();
        w.at(x.t, name.clone()).set(&Value::Int(7)).unwrap();
        w.at(x.out, name.clone()).set(&Value::Int(7)).unwrap();
        w.commit().unwrap().unwrap().id
    };
    let r = c.revert(id);
    assert!(matches!(r, Err(Error::Permission { tid, .. }) if tid == x.t), "{r:?}");
    assert_eq!(x.n.get(x.out, name.clone()).unwrap(), Some(Value::Int(7)));
    let eph = {
        let mut w = x.n.write();
        w.at(x.out, ak("t:e.0~")).set(&Value::Int(7)).unwrap();
        w.commit().unwrap().unwrap().id
    };
    let r = c.revert(eph);
    assert!(matches!(r, Err(Error::NotUndoable { .. })), "{r:?}");
    assert_eq!(x.n.get(x.out, ak("t:e.0~")).unwrap(), Some(Value::Int(7)));
}

// spec/crdt.md §4.6, spec/permissions.md §5.2, notes/client-port.md §3: reverting a creation deletes the thing: every held aspect, every placement this node may write. The node may; the actor must too: a writer removes no admin-only aspect that way, and no placement in a group it may not write
#[test]
fn revert_of_a_creation_needs_what_the_delete_writes() {
    let x = node();
    let (name, adm) = (ak("name.0"), ak("t:adm.0^"));
    let (_, _, c) = x.client(Role::Write);
    let made = |x: &Node| {
        let mut w = x.n.write();
        let m = w.create(x.g).unwrap();
        w.at(m, name.clone()).set(&Value::Int(1)).unwrap();
        w.place(m, x.g).unwrap();
        (m, w.commit().unwrap().unwrap().id)
    };
    let (m, id) = made(&x);
    x.n.write_with(|w| w.at(m, adm.clone()).set(&Value::Int(2))).unwrap();
    assert!(matches!(c.revert(id), Err(Error::Permission { .. })));
    assert_eq!(x.n.get(m, adm).unwrap(), Some(Value::Int(2)));
    let (m, id) = made(&x);
    x.n.write_with(|w| w.place(m, x.h)).unwrap();
    let r = c.revert(id);
    assert!(matches!(r, Err(Error::Permission { tid, .. }) if tid != x.h), "{r:?}");
    assert!(x.n.get(x.h, ct::GROUP).unwrap().unwrap().items.contains(&m), "a placement in a group it may not write");
    assert!(x.n.knows(m));
    // nothing beyond its rights: the revert runs
    let (m, id) = made(&x);
    c.revert(id).unwrap();
    assert!(!x.n.knows(m));
}

// spec/data-model.md §8, spec/wire.md §11.2, notes/client-port.md §3: persisting a thing converts its ephemeral placements in the groups the writer may write: the actor's, not this node's
#[test]
fn persisting_converts_only_placements_the_actor_may_write() {
    let x = node();
    let (_, _, c) = x.client(Role::Write);
    let e = x
        .n
        .write_with(|w| {
            let e = w.create(x.g)?;
            w.place(e, x.h)?;
            Ok(e)
        })
        .unwrap();
    c.write_with(|w| w.at(e, ak("name.0")).set(&Value::Int(1))).unwrap();
    assert_eq!(x.n.get(e, ak("name.0")).unwrap(), Some(Value::Int(1)));
    assert!(!x.n.get(x.h, ct::GROUP).unwrap().unwrap().items.contains(&e), "written durably with this node's rights");
    // the same write by the node converts it
    let e2 = x
        .n
        .write_with(|w| {
            let e = w.create(x.g)?;
            w.place(e, x.h)?;
            Ok(e)
        })
        .unwrap();
    x.n.write_with(|w| w.at(e2, ak("name.0")).set(&Value::Int(1))).unwrap();
    assert!(x.n.get(x.h, ct::GROUP).unwrap().unwrap().items.contains(&e2));
}

/// A small xorshift (the walk's choices; failure messages name the seed).
struct Rng(u64);
impl Rng {
    fn next(&mut self, n: u64) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0 % n
    }
}

// spec/sync.md §10, spec/wire.md §11.2, notes/client-port.md §3 (Invariant: every client-session row runs as the client's actor; authority ends at revocation), spec/permissions.md §1: a random walk of grants, demotions, secret rotations, expiries and removals against a model of plain grants: at every step every read answers what the model says the actor may read, as an unknown tid otherwise, and every write succeeds exactly when the model says it may write
#[test]
fn client_session_differential_against_grants() {
    for seed in [0x51u64, 0x7a3, 0x10f07] {
        walk(seed);
    }
}

fn walk(seed: u64) {
    let mut rng = Rng(seed);
    let x = node();
    let name = ak("name.0");
    // the model: per group the role granted; a direct grant on a thing; the thing's owner
    let things = [(x.t, Some(x.g)), (x.u, Some(x.h)), (x.placed, None), (x.out, None)];
    let mut on_group: [Option<Role>; 2] = [None, None];
    let mut on_thing: Option<Role> = None; // on `x.out`, directly
    let (g, h) = (x.g, x.h);
    // an item of a group it may not read tells nothing of that group
    x.n.write_with(|w| w.place(x.t, h)).unwrap();
    let items = osis_schema::Path(vec![osis_schema::Step::Field(0)]);
    let (mut a, mut s) = x.n.add_client(None).unwrap();
    let mut c = x.attach(&s).unwrap();
    let skip = Demotion { sync: WaitForSync::Skip, backdate: None };
    let mut value = 100i64;
    let mut last: [Value; 4] = std::array::from_fn(|_| Value::Str("x".into()));
    for step in 0..40 {
        let why = format!("seed {seed:#x} step {step}");
        match rng.next(10) {
            0 | 1 => {
                let i = rng.next(2) as usize;
                let r = [Role::Read, Role::Write][rng.next(2) as usize];
                let target = [g, h][i];
                match on_group[i] {
                    Some(old) if r < old => block_on(x.n.demote(target, a, Lower::To(r), skip)).unwrap(),
                    _ => x.n.grant(target, a, r, Default::default()).unwrap(),
                }
                on_group[i] = Some(r);
            }
            2 => {
                let i = rng.next(2) as usize;
                if on_group[i].take().is_some() {
                    block_on(x.n.demote([g, h][i], a, Lower::Remove, skip)).unwrap();
                }
            }
            3 => {
                let r = [Role::Read, Role::Write][rng.next(2) as usize];
                match on_thing {
                    Some(old) if r < old => block_on(x.n.demote(x.out, a, Lower::To(r), skip)).unwrap(),
                    _ => x.n.grant(x.out, a, r, Default::default()).unwrap(),
                }
                on_thing = Some(r);
            }
            4 => {
                s = x.n.rotate_client_secret(a).unwrap();
                assert!(c.get(x.t, name.clone()).is_err() || x.served() >= 1, "{why}");
                x.until(|x| x.served() == 0);
                assert!(c.get(x.t, name.clone()).is_err(), "{why}: a session of the old secret");
                c = x.attach(&s).unwrap();
            }
            5 => {
                // removal: nothing of the old actor works; a new client starts with no grants
                assert!(x.n.remove_client(a).unwrap(), "{why}");
                x.until(|x| x.served() == 0);
                assert!(c.get(x.t, name.clone()).is_err(), "{why}");
                assert!(matches!(x.attach(&s), Err(Error::Unsupported(_))), "{why}");
                (a, s) = x.n.add_client(None).unwrap();
                c = x.attach(&s).unwrap();
                on_group = [None, None];
                on_thing = None;
            }
            6 => {
                // an until set directly and passed: revoked with the grants still there
                let at = WallMs(x.n.now().0 + 1000);
                let e = x.n.get(x.n.node(), ct::CLIENTS).unwrap().unwrap().remove(&a).unwrap();
                let node = x.n.node();
                x.n.write_with(|w| w.at(node, ct::CLIENTS).path(osis_schema::Path::root()).put(&a, &ct::Client { until: Some(at), ..e })).unwrap();
                if rng.next(2) == 0 {
                    x.clock.advance(1000);
                    assert!(c.get(x.t, name.clone()).is_err(), "{why}: past its until");
                    assert!(c.write_with(|w| w.at(x.t, name.clone()).set(&Value::Int(0))).is_err(), "{why}");
                    x.until(|x| x.served() == 0);
                    assert!(matches!(x.attach(&s), Err(Error::Unsupported(_))), "{why}");
                    // back in by a new until (an admin's edit), with a new secret
                    let node = x.n.node();
                    s = x.n.rotate_client_secret(a).unwrap();
                    let e = x.n.get(node, ct::CLIENTS).unwrap().unwrap().remove(&a).unwrap();
                    x.n.write_with(|w| w.at(node, ct::CLIENTS).path(osis_schema::Path::root()).put(&a, &ct::Client { until: None, ..e })).unwrap();
                    c = x.attach(&s).unwrap();
                } else {
                    let e = x.n.get(node, ct::CLIENTS).unwrap().unwrap().remove(&a).unwrap();
                    x.n.write_with(|w| w.at(node, ct::CLIENTS).path(osis_schema::Path::root()).put(&a, &ct::Client { until: None, ..e })).unwrap();
                }
            }
            7 => {
                // a placement through an op on the group's aspect: it needs write on the group
                // and to read the thing; a successful one leaves it placed only for this step
                let i = rng.next(2) as usize;
                let target = [g, h][i];
                let may = on_group[i] >= Some(Role::Write) && on_thing.is_some();
                let r = c.write_with(|w| w.at(target, ct::GROUP).path(items.clone()).add(&x.out));
                assert_eq!(r.is_ok(), may, "{why}: placing out in group {i} with {:?} on it and {on_thing:?} on out: {r:?}", on_group[i]);
                assert_eq!(x.n.groups_of(x.out).item_of.contains(&target), may, "{why}");
                if may {
                    x.n.write_with(|w| w.unplace(x.out, target)).unwrap();
                }
            }
            _ => {
                // a write through the client on a random thing
                let (t, _) = things[rng.next(4) as usize];
                let i = things.iter().position(|(x, _)| *x == t).unwrap();
                let may = role_of(&x, t, on_group, on_thing) >= Some(Role::Write);
                value += 1;
                let r = c.write_with(|w| w.at(t, name.clone()).set(&Value::Int(value)));
                match (&r, may) {
                    (Ok(_), true) => last[i] = Value::Int(value),
                    (Err(Error::Permission { .. }), false) if role_of(&x, t, on_group, on_thing).is_some() => {}
                    (Err(Error::UnknownThing { .. }), false) if role_of(&x, t, on_group, on_thing).is_none() => {}
                    _ => panic!("{why}: write of {t} with role {:?}: {r:?}", role_of(&x, t, on_group, on_thing)),
                }
                assert_eq!(x.n.get(t, name.clone()).unwrap(), Some(last[i].clone()), "{why}");
            }
        }
        // every read, every step
        for (i, (t, _)) in things.iter().enumerate() {
            let role = role_of(&x, *t, on_group, on_thing);
            let got = c.at(*t, name.clone()).get_value().unwrap();
            let want = role.map(|_| last[i].clone());
            assert_eq!(got, want, "{why}: read of {t} with role {role:?}");
            assert_eq!(c.knows(*t), role.is_some(), "{why}: knows {t}");
            assert_eq!(c.role_on(*t), role, "{why}: role_on {t}");
            assert_eq!(c.commits(&CommitQuery::new().scope(Scope::Thing(*t))).unwrap().is_empty(), role.is_none(), "{why}: commits {t}");
        }
        for (i, group) in [g, h].into_iter().enumerate() {
            assert_eq!(c.commits(&CommitQuery::new().scope(Scope::Group(group))).unwrap().is_empty(), on_group[i].is_none(), "{why}: scope of group {i}");
        }
        if on_group[0].is_some() {
            let shown = c.at(x.t, ak("groups.0")).get_value().unwrap();
            assert!(matches!(&shown, Some(Value::Set(s)) if s.contains(&Value::Tid(h)) == on_group[1].is_some()), "{why}: groups.0 {shown:?}");
        }
        // what it may not ever read, whatever it holds
        assert!(!c.knows(x.n.me()) && !c.knows(x.n.node()), "{why}");
    }
}

/// The model: a direct grant on `out`, a grant on the group owning `t` or `u`. `placed` and `out`
/// are the person's: placement gives nothing.
fn role_of(x: &Node, t: Tid, g: [Option<Role>; 2], thing: Option<Role>) -> Option<Role> {
    if t == x.t {
        g[0]
    } else if t == x.u {
        g[1]
    } else if t == x.out {
        thing
    } else {
        None
    }
}
