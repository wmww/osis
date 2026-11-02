//! The client port (notes/client-port.md): a node serving its unix socket, a second
//! handle attached to it as Owner; raw protocol sessions for the nonce and tier rules.

use crate::common::ak;
use osis::internals::Internals as _;
use osis::{Ak, Change, CommitQuery, Config, MemStore, Osis, Runtime, Scope, Source, StoreAt, Transport, Value};
use osis_proto::{ClientConfig, ClientEvent, ClientInput, ClientOutput, ClientSession, Code, Command, Outcome};
use std::path::PathBuf;
use std::sync::mpsc::channel;
use std::time::Duration;

const W: Duration = Duration::from_secs(20);

/// A temp directory for sockets (removed on drop).
struct Dir(PathBuf);

impl Dir {
    fn new() -> Dir {
        use std::hash::{BuildHasher, RandomState};
        let d = std::env::temp_dir().join(format!("osis-port-{}-{:x}", std::process::id(), RandomState::new().hash_one(std::time::SystemTime::now())));
        std::fs::create_dir_all(&d).unwrap();
        Dir(d)
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A node over `store` with a runtime, serving the client port at `sock`.
fn node(store: &MemStore, net: &osis_transport::Net, sock: &std::path::Path, create: bool) -> Osis {
    let mut c = Config::at(StoreAt::Memory(store.clone()));
    c.runtime = Runtime::Own;
    c.transport = Some(Transport::InProcess(net.endpoint("n")));
    let db = if create { Osis::create(c).unwrap().0 } else { Osis::open(c).unwrap() };
    db.listen_unix(sock).unwrap();
    db
}

fn attach(sock: &std::path::Path) -> Osis {
    Osis::attach(sock, Config::memory()).unwrap()
}

// spec/wire.md §11.2 (client port), notes/client-port.md §1, §2 (b): an attached handle reads, writes, watches and undoes at the node as its Owner: me/node/home are the node's; every read agrees with the node's own; a node-side write reaches the client's watch, a client write the node's
#[test]
fn attached_handle_works_at_the_node() {
    let d = Dir::new();
    let sock = d.0.join("n.sock");
    let net = osis_transport::Net::new(1);
    let n = node(&MemStore::new(), &net, &sock, true);
    let c = attach(&sock);
    assert!(c.is_attached());
    assert_eq!((c.me(), c.home(), c.node()), (n.me(), n.home(), n.node()));
    let title = ak("note:title.0");
    // a batch naming no existing thing goes to the node too
    c.write_with(|w| w.create(c.me())).unwrap();
    let (t, g) = c
        .write_with(|w| {
            let g = w.create(c.me())?;
            w.make_group(g)?;
            let t = w.create(c.me())?;
            w.at(t, title.clone()).set(&Value::Str("a".into()))?;
            w.place(t, g)?;
            Ok((t, g))
        })
        .unwrap();
    assert_eq!(n.get(t, title.clone()).unwrap(), Some(Value::Str("a".into())));
    assert_eq!(c.get(t, title.clone()).unwrap(), Some(Value::Str("a".into())));
    assert_eq!(c.aspects(t).unwrap(), n.aspects(t).unwrap());
    assert!(c.knows(t) && !c.knows(osis::Tid::from_bytes([7; 15])));
    assert_eq!(c.groups_of(t), n.groups_of(t));
    assert!(c.groups_of(t).item_of.contains(&g));
    assert_eq!(c.roster(t), n.roster(t));
    assert_eq!(c.role_on(t), n.role_on(t));
    assert_eq!(c.owner_of(t), Some(n.me()));
    assert_eq!(c.created(t), n.created(t));
    assert_eq!(c.changed(t), n.changed(t));
    assert!(c.same_thing(t, t));
    // a client's status adds its attachment
    let mut cs = c.status().unwrap();
    assert_eq!(cs.remotes.len(), 1);
    assert!(cs.remotes[0].connected);
    cs.remotes.clear();
    assert_eq!(cs, n.status().unwrap());
    // an unknown thing's write fails as locally
    let ghost = osis::Tid::from_bytes([9; 15]);
    assert!(matches!(c.write_with(|w| w.at(ghost, title.clone()).set(&Value::Int(1))), Err(osis::Error::UnknownThing { .. })));
    // watches: the client sees the node's write; settle inside a callback does not deadlock
    let (tx, rx) = channel();
    let sub = c
        .at(t, title.clone())
        .on_change(move |db, ch: Change<Value>| {
            db.settle();
            tx.send((ch.value.unwrap(), ch.source)).unwrap();
        })
        .unwrap();
    assert_eq!(rx.recv_timeout(W).unwrap(), (Some(Value::Str("a".into())), Source::Initial));
    let w = c.at(t, title.clone()).watch().unwrap();
    assert_eq!(w.current().unwrap(), Some(Value::Str("a".into())));
    n.write_with(|w| w.at(t, title.clone()).set(&Value::Str("b".into()))).unwrap();
    let (v, src) = rx.recv_timeout(W).unwrap();
    assert_eq!(v, Some(Value::Str("b".into())));
    assert!(matches!(src, Source::Local(_)), "{src:?}");
    c.settle();
    assert_eq!(w.current().unwrap(), Some(Value::Str("b".into())));
    // the node's watch sees the client's write
    let nw = n.at(t, title.clone()).watch().unwrap();
    c.write_with(|w| w.at(t, title.clone()).set(&Value::Str("c".into()))).unwrap();
    n.settle();
    assert_eq!(nw.current().unwrap(), Some(Value::Str("c".into())));
    // undo, redo and commits at the node, the node's actor's
    assert!(c.undo(&Scope::Thing(t)).unwrap().is_some());
    assert_eq!(c.get(t, title.clone()).unwrap(), Some(Value::Str("b".into())));
    c.redo(&Scope::Thing(t)).unwrap().unwrap();
    assert_eq!(c.get(t, title.clone()).unwrap(), Some(Value::Str("c".into())));
    let q = CommitQuery::new().scope(Scope::Thing(t));
    assert_eq!(c.commits(&q).unwrap(), n.commits(&q).unwrap());
    let last = c.commits(&q).unwrap()[0].commit.id;
    c.revert(last).unwrap();
    assert_eq!(c.get(t, title.clone()).unwrap(), Some(Value::Str("b".into())));
    // a thing watch and a dropped subscription
    let (ttx, trx) = channel();
    let ts = c.watch_thing(t, move |_, ch| ttx.send(ch.ak).unwrap());
    let mut seen = Vec::new();
    while !seen.contains(&title) {
        seen.push(trx.recv_timeout(W).unwrap());
    }
    drop(sub);
    drop(ts);
    // process-wide calls the port does not carry fail Unsupported, never act on the stand-in
    assert!(matches!(c.devices(), Err(osis::Error::Unsupported(_))));
    assert!(matches!(c.add_host(&osis::HostAddr::new("quic://x:1", [1; 32])), Err(osis::Error::Unsupported(_))));
    // the stand-in database is never read: a read transaction and Internals fail
    assert!(matches!(c.read(|r| r.knows(t)), Err(osis::Error::Unsupported(_))));
    let c2 = c.clone();
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| c2.engine(|_| ()))).is_err(), "Internals on an attached handle");
    drop(c);
    n.close().unwrap();
}

// spec/wire.md §11.2 (max_reply), notes/client-port.md §2 Reply allowance: a value above the reply bound reads TooLarge; `stream` reads it by stream_read pages
#[test]
fn too_large_then_stream_read() {
    let d = Dir::new();
    let sock = d.0.join("n.sock");
    let net = osis_transport::Net::new(1);
    let n = node(&MemStore::new(), &net, &sock, true);
    let mut cfg = Config::memory();
    cfg.materialize_limit = 1000;
    let c = Osis::attach(&sock, cfg).unwrap();
    let k = ak("f:blob.0");
    let big: Vec<u8> = (0..3_000_000u32).map(|i| (i % 251) as u8).collect();
    let t = n.write_with(|w| {
        let t = w.create(n.me())?;
        w.at(t, k.clone()).set(&Value::Bytes(big.clone()))?;
        Ok(t)
    })
    .unwrap();
    assert!(matches!(c.get(t, k.clone()), Err(osis::Error::TooLarge { .. })));
    let mut s = c.at(t, k.clone()).stream().unwrap().unwrap();
    assert_eq!(s.len(), big.len() as u64);
    let mut got = Vec::new();
    std::io::Read::read_to_end(&mut s, &mut got).unwrap();
    assert!(got == big, "stream equals the value");
    assert_eq!(c.at(t, k).len().unwrap(), Some(big.len() as u64));
    drop(c);
    n.close().unwrap();
}

/// A raw protocol session (tests of the wire rules).
pub(crate) struct Raw {
    rt: tokio::runtime::Runtime,
    cs: ClientSession,
    link: osis_transport::Link,
    events: Vec<ClientEvent>,
}

impl Raw {
    pub(crate) fn over<T: osis_transport::Transport>(t: &T, addr: osis_transport::Address) -> Raw {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let link = rt.block_on(osis_transport::link::dial(t, &addr, None, W)).unwrap();
        let mut r = Raw { rt, cs: ClientSession::new(ClientConfig { peer_static_key: addr.key, challenge: [3; 32] }), link, events: Vec::new() };
        let o = r.cs.handle(0, ClientInput::Start);
        r.out(o);
        r
    }

    fn unix(sock: &std::path::Path) -> Raw {
        let uid = {
            let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
            let _g = rt.enter();
            osis_transport::unix::own_uid().unwrap()
        };
        Raw::over(&osis_transport::Unix, osis_transport::Address { url: osis_transport::unix::url_of(sock), key: osis_transport::unix::uid_key(uid) })
    }

    fn out(&mut self, o: Vec<ClientOutput>) {
        for x in o {
            match x {
                ClientOutput::Send(b) => assert!(self.link.tx.send(b, usize::MAX)),
                ClientOutput::Event(e) => self.events.push(e),
                _ => {}
            }
        }
    }

    /// Sends `cmd` and waits for the reply of `token`.
    pub(crate) fn ask(&mut self, cmd: Command, token: u64) -> Result<Outcome, Code> {
        let o = self.cs.handle(0, ClientInput::Command(cmd));
        self.out(o);
        loop {
            if let Some(i) = self.events.iter().position(|e| matches!(e, ClientEvent::Reply { token: t, .. } if *t == token)) {
                let ClientEvent::Reply { reply, .. } = self.events.remove(i) else { unreachable!() };
                return reply;
            }
            let b = self.rt.block_on(async { tokio::time::timeout(W, self.link.rx.recv()).await }).unwrap().expect("connection closed");
            let o = self.cs.handle(0, ClientInput::Bytes(b));
            self.out(o);
        }
    }

    /// Sends `cmd` without waiting for its reply.
    pub(crate) fn send(&mut self, cmd: Command) {
        let o = self.cs.handle(0, ClientInput::Command(cmd));
        self.out(o);
    }

    /// Lets the link's tasks run for `ms`: what `send` queued reaches the node.
    pub(crate) fn pump(&mut self, ms: u64) {
        self.rt.block_on(async { tokio::time::sleep(Duration::from_millis(ms)).await });
    }

    fn auth(&mut self, session: [u8; 16]) -> Result<Outcome, Code> {
        self.ask(Command::Auth { token: 0, session, secret: None }, 0)
    }

    pub(crate) fn call_at(&mut self, token: u64, method: u64, args: Vec<Value>) -> Outcome {
        self.call(token, method, args)
    }

    fn call(&mut self, token: u64, method: u64, args: Vec<Value>) -> Outcome {
        self.ask(Command::Call { token, max_reply: osis_proto::client::SMALL_REPLY as u64, method, args }, token).unwrap()
    }
}

/// A `write` call's args setting `k` of `t` to `v` (the port's batch form: nonce, actor, keys, ops).
pub(crate) fn set_batch(nonce: u64, actor: osis::Tid, t: osis::Tid, k: &Ak, v: Value) -> Vec<Value> {
    let op = Value::List(vec![Value::List(vec![]), Value::List(vec![Value::Int(0), v])]);
    vec![Value::uint(nonce), Value::Tid(actor), Value::List(vec![Value::Str(k.as_str().into())]), Value::List(vec![Value::List(vec![Value::Int(3), Value::Tid(t), Value::Int(0), op])])]
}

const WRITE: u64 = 11;

// spec/wire.md §11.2, notes/client-port.md §2 Writes: a repeated nonce is answered with its first result and applies once; one at or below the highest seen and not remembered is outcome unknown; two sessions keep separate ranges; a restarted node remembers nothing: a marked resend is unknown, never run
#[test]
fn write_nonces_per_session() {
    let d = Dir::new();
    let sock = d.0.join("n.sock");
    let net = osis_transport::Net::new(1);
    let store = MemStore::new();
    let n = node(&store, &net, &sock, true);
    let k = ak("note:n.0");
    let t = n.write_with(|w| w.create(n.me())).unwrap();
    let mut r = Raw::unix(&sock);
    assert!(matches!(r.auth([1; 16]), Ok(Outcome::Ok { .. })));
    let first = r.call(1, WRITE, set_batch(1, n.me(), t, &k, Value::Int(1)));
    assert!(matches!(first, Outcome::Ok { .. }), "{first:?}");
    let commits = |n: &Osis| n.commits(&CommitQuery::new().scope(Scope::Thing(t))).unwrap().len();
    let before = commits(&n);
    // the reply was lost: the retry under nonce 1 answers the first result, writing nothing
    let again = r.call(2, WRITE, set_batch(1, n.me(), t, &k, Value::Int(2)));
    let (Outcome::Ok { value: a, .. }, Outcome::Ok { value: b, .. }) = (&first, &again) else { panic!() };
    assert_eq!(a, b);
    assert_eq!(commits(&n), before);
    assert_eq!(n.get(t, k.clone()).unwrap(), Some(Value::Int(1)));
    let r3 = r.call(3, WRITE, set_batch(3, n.me(), t, &k, Value::Int(3)));
    assert!(matches!(r3, Outcome::Ok { .. }));
    // nonce 2 was skipped: below the highest seen and not remembered
    let unknown = r.call(4, WRITE, set_batch(2, n.me(), t, &k, Value::Int(9)));
    assert!(matches!(&unknown, Outcome::Err { code: 12, .. }), "{unknown:?}");
    // another session of the same Owner: its own range
    let mut r2 = Raw::unix(&sock);
    r2.auth([2; 16]).unwrap();
    assert!(matches!(r2.call(1, WRITE, set_batch(1, n.me(), t, &k, Value::Int(4))), Outcome::Ok { .. }));
    assert_eq!(n.get(t, k.clone()).unwrap(), Some(Value::Int(4)));
    // the first session's memory survives its reconnect within the same node process
    drop(r);
    let mut r = Raw::unix(&sock);
    assert!(matches!(r.auth([1; 16]), Ok(Outcome::Ok { .. })));
    let again = r.call(1, WRITE, set_batch(1, n.me(), t, &k, Value::Int(5)));
    let (Outcome::Ok { value: a, .. }, Outcome::Ok { value: b, .. }) = (&first, &again) else { panic!() };
    assert_eq!(a, b);
    drop((r, r2));
    // a restart: nothing remembered, so a resend of what ran is unknown, every one of them
    n.close().unwrap();
    let n = node(&store, &net, &sock, false);
    let mut r = Raw::unix(&sock);
    assert!(matches!(r.auth([1; 16]), Ok(Outcome::Ok { .. })));
    let resent = 1u64 << 62;
    for (i, nonce) in [1u64, 3].into_iter().enumerate() {
        let o = r.call(5 + i as u64, WRITE, set_batch(nonce | resent, n.me(), t, &k, Value::Int(9)));
        assert!(matches!(&o, Outcome::Err { code: 12, .. }), "{o:?}");
    }
    assert_ne!(n.get(t, k.clone()).unwrap(), Some(Value::Int(9)));
    drop(r);
    n.close().unwrap();
}

// spec/sync.md §10 (unix), spec/wire.md §11.2 (Error 1), notes/client-port.md §0, §5: the Owner tier comes from the unix transport alone: a keyed InProcess peer on the node's own listener is refused at Auth (Error 1) and its calls too
#[test]
fn keyed_peer_is_never_owner() {
    let d = Dir::new();
    let sock = d.0.join("n.sock");
    let net = osis_transport::Net::new(1);
    let n = node(&MemStore::new(), &net, &sock, true);
    let secret = n.sync_engine(|s| s.dialable_secret());
    let key = osis_transport::InProcess::public_key(&osis_transport::StaticSecret::from_bytes(*secret.expose()));
    let mut r = Raw::over(&net.endpoint("intruder"), osis_transport::Address { url: "mem://n-peer".into(), key });
    assert_eq!(r.auth([1; 16]), Err(Code::REFUSED));
    let call = r.ask(Command::Call { token: 5, max_reply: osis_proto::client::SMALL_REPLY as u64, method: 0, args: vec![] }, 5);
    assert_eq!(call, Err(Code::REFUSED));
    // over the socket, the same Auth is answered
    let mut u = Raw::unix(&sock);
    assert!(matches!(u.auth([1; 16]), Ok(Outcome::Ok { .. })));
    drop((r, u));
    n.close().unwrap();
}

// spec/wire.md §11.2, notes/client-port.md §2 Port stall bounds: the worst method rows as the port worker runs them (each one engine transaction holding the lock the sync driver needs) against a Sync pass's per-input bound (notes/sync.md Hub stall bounds: 1024 puts in one commit, about 0.45 s at 10^5 entries). Wall time of the call at an otherwise idle node (the worker is one thread). Release, by hand: `cargo test --release -p osis --test it -- --ignored port::bench_worst_rows --nocapture`
#[test]
#[ignore = "timing, release"]
fn bench_worst_rows() {
    let d = Dir::new();
    let sock = d.0.join("n.sock");
    let net = osis_transport::Net::new(1);
    let n = node(&MemStore::new(), &net, &sock, true);
    let k = ak("b:v.0");
    let count = 10_000;
    let mut things = Vec::new();
    for chunk in 0..count / 100 {
        things.extend(
            n.write_with(|w| {
                (0..100)
                    .map(|i| {
                        let t = w.create(n.me())?;
                        w.at(t, k.clone()).set(&Value::Int(chunk * 100 + i))?;
                        Ok(t)
                    })
                    .collect::<osis::Result<Vec<_>>>()
            })
            .unwrap(),
        );
    }
    for t in things.iter().take(1000) {
        n.write_with(|w| w.at(*t, k.clone()).set(&Value::Int(-1))).unwrap();
    }
    let c = attach(&sock);
    let time = |what: &str, f: &mut dyn FnMut()| {
        let t0 = std::time::Instant::now();
        f();
        eprintln!("{what}: {:.3} s", t0.elapsed().as_secs_f64());
    };
    // the sync engine's own per-event cost at this store (every port request and reply is one)
    time("sync engine: one Tick", &mut || n.feed(osis::internals::node::sync::Event::Tick));
    time("local get", &mut || drop(n.get(things[0], k.clone()).unwrap()));
    {
        let d2 = Dir::new();
        let s2 = d2.0.join("s.sock");
        let small = node(&MemStore::new(), &osis_transport::Net::new(2), &s2, true);
        let cs = attach(&s2);
        let t = cs.write_with(|w| w.create(cs.me())).unwrap();
        time("get, small store, 100 times", &mut || {
            for _ in 0..100 {
                drop(cs.get(t, k.clone()).unwrap());
            }
        });
        drop(cs);
        small.close().unwrap();
    }
    time("get", &mut || drop(c.get(things[0], k.clone()).unwrap()));
    time("write 1024 sets", &mut || {
        c.write_with(|w| {
            for t in things.iter().take(1024) {
                w.at(*t, k.clone()).set(&Value::Int(-2))?;
            }
            Ok(())
        })
        .unwrap();
    });
    time("commits, whole store (10^4 things, 1100 commits)", &mut || drop(c.commits(&CommitQuery::new()).unwrap()));
    time("commits, one thing", &mut || drop(c.commits(&CommitQuery::new().scope(Scope::Thing(things[0]))).unwrap()));
    time("undo, home group", &mut || drop(c.undo(&Scope::Group(c.home()))));
    time("status", &mut || drop(c.status().unwrap()));
    drop(c);
    n.close().unwrap();
}


// spec/sync.md §10 (unix path sockets), notes/client-port.md §5: the socket directory is made 0700 and used only when it is this uid's, mode 0700 and not a symlink; the socket name fits sun_path
#[test]
fn socket_dir_rules() {
    use std::os::unix::fs::PermissionsExt;
    let uid = osis::own_uid().unwrap();
    let d = Dir::new();
    let ok = d.0.join("ok");
    osis::socket_dir(&ok, uid).unwrap();
    assert_eq!(std::fs::metadata(&ok).unwrap().permissions().mode() & 0o777, 0o700);
    osis::socket_dir(&ok, uid).unwrap();
    let open = d.0.join("open");
    std::fs::create_dir(&open).unwrap();
    std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(osis::socket_dir(&open, uid).is_err(), "group/other access");
    let link = d.0.join("link");
    std::os::unix::fs::symlink(&ok, &link).unwrap();
    assert!(osis::socket_dir(&link, uid).is_err(), "a symlink");
    assert!(osis::socket_dir(&ok, uid.wrapping_add(1)).is_err(), "another uid's");
    let p = osis::socket_path(&d.0.join("store")).unwrap();
    assert!(p.as_os_str().len() <= osis_transport::unix::MAX_PATH, "{p:?}");
    assert!(p.extension().is_some_and(|e| e == "sock"));
}

/// A node on `net` at endpoint `ep` with `hosts` and a runtime, serving the client port at `sock`.
fn node_on(net: &osis_transport::Net, ep: &str, hosts: Vec<osis::HostAddr>, sock: &std::path::Path) -> Osis {
    let mut c = Config::at(StoreAt::Memory(MemStore::new()));
    c.runtime = Runtime::Own;
    c.transport = Some(Transport::InProcess(net.endpoint(ep)));
    c.hosts = hosts;
    let db = Osis::create(c).unwrap().0;
    db.listen_unix(sock).unwrap();
    db
}

// spec/wire.md §11.2 (Sub, Notify), notes/client-port.md §2 (wait_synced), notes/api.md Sync status: an attached handle's `wait_synced` has the node's outcomes: Ok once synced (All, and Group after `sync` through the port), Unsynced for a group without a label, Network after the deadline when the host is unreachable; at most `MAX_WAITS` waits at once per connection; `sync`, `grant`, `make_link`, `sync_now` and the sharing reads go through too
#[test]
fn attached_wait_synced_as_at_the_node() {
    use crate::common::block_on;
    use osis::{Role, SyncScope};
    let d = Dir::new();
    let net = osis_transport::Net::new(2);
    // a host hosting any label
    let mut hc = Config::at(StoreAt::Memory(MemStore::new()));
    hc.runtime = Runtime::Own;
    hc.transport = Some(Transport::InProcess(net.endpoint("s")));
    hc.peers = false;
    let host = Osis::create(hc).unwrap().0;
    host.set_hosting(Some(osis::Hosting { listen: vec!["mem://s".into()], admit: osis::Admit::Open, ..Default::default() })).unwrap();
    let end = std::time::Instant::now() + W;
    let addr = loop {
        if let Some(a) = host.host_address().unwrap() {
            break a;
        }
        assert!(std::time::Instant::now() < end, "the host did not listen");
        std::thread::sleep(Duration::from_millis(10));
    };
    let sock = d.0.join("n.sock");
    let n = node_on(&net, "n", vec![addr], &sock);
    let c = attach(&sock);
    block_on(c.wait_synced(SyncScope::All, W)).unwrap();
    // a group without a label: Unsynced naming it, at once, as at the node
    let (g, t) = c
        .write_with(|w| {
            let g = w.create(c.me())?;
            w.make_group(g)?;
            let t = w.create(g)?;
            w.at(t, ak("note:title.0")).set(&Value::Str("a".into()))?;
            w.place(t, g)?;
            Ok((g, t))
        })
        .unwrap();
    let r = block_on(c.wait_synced(SyncScope::Group(t), W));
    assert!(matches!(&r, Err(osis::Error::Unsynced { groups }) if groups == &vec![t]), "{r:?}");
    assert_eq!(format!("{r:?}"), format!("{:?}", block_on(n.wait_synced(SyncScope::Group(t), W))));
    // synced through the port, with a grant and a link delivered: Group and All resolve
    c.sync(g, &[]).unwrap();
    c.grant(g, n.node(), Role::Read, Default::default()).unwrap();
    let link = c.make_link(g, Role::Read, Default::default()).unwrap();
    assert!(!link.to_string().is_empty());
    // the sharing reads agree with the node's
    assert_eq!(c.links(g).len(), 1);
    assert_eq!(c.links(g), n.links(g));
    assert_eq!(c.reach(t), n.reach(t));
    assert!(!c.holder_path(g, n.node()).is_empty());
    assert_eq!(c.holder_path(g, n.node()), n.holder_path(g, n.node()));
    c.sync_now().unwrap();
    block_on(c.wait_synced(SyncScope::Group(t), W)).unwrap();
    block_on(c.wait_synced(SyncScope::All, W)).unwrap();
    assert_eq!(n.status().unwrap().groups[&g].state, osis::SyncState::Synced);
    // a node whose only host nobody serves: Network after the deadline, as at the node
    let sock2 = d.0.join("m.sock");
    let m = node_on(&net, "m", vec![osis::HostAddr::new("mem://nobody", [3; 32])], &sock2);
    let cm = attach(&sock2);
    let short = Duration::from_millis(500);
    assert!(matches!(block_on(cm.wait_synced(SyncScope::All, short)), Err(osis::Error::Network(_))));
    assert!(matches!(block_on(m.wait_synced(SyncScope::All, short)), Err(osis::Error::Network(_))));
    // at most 16 waits at once per connection (each a waiter the node checks per change); an
    // ended one frees its place
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    let mut waits: Vec<_> = (0..16).map(|_| Box::pin(cm.wait_synced(SyncScope::All, W))).collect();
    for w in &mut waits {
        assert!(w.as_mut().poll(&mut cx).is_pending());
    }
    assert!(matches!(block_on(cm.wait_synced(SyncScope::All, short)), Err(osis::Error::Invalid(_))));
    waits.pop();
    assert!(matches!(block_on(cm.wait_synced(SyncScope::All, short)), Err(osis::Error::Network(_))));
    drop(waits);
    drop((c, cm));
    m.close().unwrap();
    n.close().unwrap();
}

// spec/wire.md §11.1-§11.2 (max_reply, MAX_SUBS), notes/client-port.md §2: a Sub whose initial Reply exceeds max_reply is answered TooLarge and is not kept live at the node's worker either, so MAX_SUBS bounds the worker's subscriptions and a later change costs nothing for them
#[test]
fn too_large_sub_is_not_kept() {
    let d = Dir::new();
    let sock = d.0.join("n.sock");
    let net = osis_transport::Net::new(1);
    let n = node(&MemStore::new(), &net, &sock, true);
    let k = ak("f:blob.0");
    let small = osis_proto::client::SMALL_REPLY;
    let t = n
        .write_with(|w| {
            let t = w.create(n.me())?;
            w.at(t, k.clone()).set(&Value::Bytes(vec![7; small + 1000]))?;
            Ok(t)
        })
        .unwrap();
    let before = n.watches();
    let mut r = Raw::unix(&sock);
    r.auth([1; 16]).unwrap();
    let filter = Value::List(vec![Value::uint(0), Value::Tid(t), Value::Str(k.as_str().into())]);
    // fewer than MAX_SUBS suffice: each one kept would show in the worker's registrations
    for tok in 1..=300u64 {
        let rep = r.ask(Command::Sub { token: tok, max_reply: small as u64, filter: filter.clone() }, tok);
        assert_eq!(rep, Ok(Outcome::too_large(small)), "sub {tok}");
    }
    // the protocol's call settles behind every Sub: none is held by the worker
    assert!(matches!(r.call(1_000_000, 20, vec![]), Outcome::Ok { .. }));
    assert_eq!(n.watches(), before);
    drop(r);
    n.close().unwrap();
}

// spec: none (API surface); notes/client-port.md §1: an attached handle's calls with no row fail Unsupported rather than answer as if done: sync_policy, group_policy, rotate_reach
#[test]
fn attached_policy_calls_are_unsupported() {
    let d = Dir::new();
    let sock = d.0.join("n.sock");
    let net = osis_transport::Net::new(1);
    let n = node(&MemStore::new(), &net, &sock, true);
    let c = attach(&sock);
    let g = n.home();
    let unsupported = |r: osis::Result<()>| assert!(matches!(r, Err(osis::Error::Unsupported(_))), "{r:?}");
    unsupported(c.sync_policy(g, osis::GroupPolicy { publish_reach: Some(false), ..Default::default() }));
    unsupported(c.group_policy(g).map(|_| ()));
    unsupported(c.rotate_reach());
    drop(c);
    n.close().unwrap();
}

// spec/wire.md §11.2 (client port), notes/client-port.md §2 Writes: writes from several threads of one attached handle all apply: nonces leave the client in the order they were taken (on its I/O thread), so none reaches the node below a later one and reads "outcome unknown" without having run
#[test]
fn threads_writing_on_one_handle() {
    let d = Dir::new();
    let sock = d.0.join("n.sock");
    let net = osis_transport::Net::new(1);
    let n = node(&MemStore::new(), &net, &sock, true);
    let c = attach(&sock);
    let k = ak("note:n.0");
    let t = n.write_with(|w| w.create(n.me())).unwrap();
    let hs: Vec<_> = (0..8)
        .map(|i| {
            let (c, k) = (c.clone(), k.clone());
            std::thread::spawn(move || (0..50).filter(|j| c.write_with(|w| w.at(t, k.clone()).set(&Value::Int(i * 1000 + j))).is_err()).count())
        })
        .collect();
    let failed: usize = hs.into_iter().map(|h| h.join().unwrap()).sum();
    assert_eq!(failed, 0);
    drop(c);
    n.close().unwrap();
}

// spec/wire.md §11.2 (client port), notes/client-port.md §2 (MAX_SCHEMA_BYTES): schema sources registered through the port count per node, not per connection (registrations are process-wide and kept); the same source again costs nothing
#[test]
fn schema_bytes_per_node() {
    let d = Dir::new();
    let sock = d.0.join("n.sock");
    let net = osis_transport::Net::new(1);
    let n = node(&MemStore::new(), &net, &sock, true);
    let src = |name: &str| format!("version 1;\naspect test:{name}.0: string;\n//{}\n", "x".repeat(osis::MAX_SCHEMA_BYTES * 3 / 5));
    let reg = |r: &mut Raw, tok, name: &str| r.call(tok, 17, vec![Value::Str("t.osis".into()), Value::Str(src(name))]);
    let mut a = Raw::unix(&sock);
    a.auth([1; 16]).unwrap();
    assert!(matches!(reg(&mut a, 1, "a"), Outcome::Ok { .. }));
    drop(a);
    let mut b = Raw::unix(&sock);
    b.auth([2; 16]).unwrap();
    assert!(matches!(reg(&mut b, 1, "a"), Outcome::Ok { .. }), "the same source again");
    assert!(matches!(reg(&mut b, 2, "b"), Outcome::Err { code: 5, .. }), "past the node's bound");
    drop(b);
    n.close().unwrap();
}
