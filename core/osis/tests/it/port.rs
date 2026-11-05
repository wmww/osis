//! The client port (notes/client-port.md): a node serving its unix socket, a second
//! handle attached to it as Owner; raw protocol sessions for the nonce and tier rules.

use crate::common::watched;
use crate::common::TestWrites as _;
use crate::common::ak;
use osis::internals::Internals as _;
use osis::{SetRole, SyncFirst, Ak, Change, CommitQuery, Config, MemStore, Osis, Runtime, Scope, Source, StoreAt, Transport, Value};
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
    assert_eq!((c.me(), c.node()), (n.me(), n.node()));
    let title = ak("note:title.0");
    // a batch naming no existing thing goes to the node too
    c.batch(|w| w.create(c.me())).unwrap();
    let (t, g) = c
        .batch(|w| {
            let g = w.create(c.me())?;
            w.make_group(g)?;
            let t = w.create(c.me())?;
            w.at(t, title.clone()).set(&Value::Str("a".into()))?;
            w.place(t, g)?;
            Ok((t, g))
        })
        .unwrap();
    assert_eq!(n.at(t, title.clone()).get().unwrap(), Some(Value::Str("a".into())));
    assert_eq!(c.at(t, title.clone()).get().unwrap(), Some(Value::Str("a".into())));
    assert_eq!(c.aspects(t).unwrap(), n.aspects(t).unwrap());
    assert!(c.knows(t).unwrap() && !c.knows(osis::Tid::from_bytes([7; 15])).unwrap());
    assert_eq!(c.groups_of(t).unwrap(), n.groups_of(t).unwrap());
    assert!(c.groups_of(t).unwrap().item_of.contains(&g));
    assert_eq!(c.grants(t).unwrap(), n.grants(t).unwrap());
    assert_eq!(c.role_on(t).unwrap(), n.role_on(t).unwrap());
    assert_eq!(c.owner_of(t).unwrap(), Some(n.me()));
    assert_eq!(c.created(t).unwrap(), n.created(t).unwrap());
    assert_eq!(c.changed(t).unwrap(), n.changed(t).unwrap());
    // a client's status adds its attachment
    let mut cs = c.status().unwrap();
    assert_eq!(cs.remotes.len(), 1);
    assert!(cs.remotes[0].connected);
    cs.remotes.clear();
    assert_eq!(cs, n.status().unwrap());
    // an unknown thing's write fails as locally
    let ghost = osis::Tid::from_bytes([9; 15]);
    assert!(matches!(c.commit_set(ghost, title.clone(), &Value::Int(1)), Err(osis::Error::UnknownThing { .. })));
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
    let w = watched(&c, t, title.clone()).unwrap();
    assert_eq!(w.current().unwrap(), Some(Value::Str("a".into())));
    n.commit_set(t, title.clone(), &Value::Str("b".into())).unwrap();
    let (v, src) = rx.recv_timeout(W).unwrap();
    assert_eq!(v, Some(Value::Str("b".into())));
    assert!(matches!(src, Source::Local(_)), "{src:?}");
    c.settle();
    assert_eq!(w.current().unwrap(), Some(Value::Str("b".into())));
    // the node's watch sees the client's write
    let nw = watched(&n, t, title.clone()).unwrap();
    c.commit_set(t, title.clone(), &Value::Str("c".into())).unwrap();
    n.settle();
    assert_eq!(nw.current().unwrap(), Some(Value::Str("c".into())));
    // undo, redo and commits at the node, the node's actor's
    assert!(c.undo(&Scope::Thing(t)).unwrap().is_some());
    assert_eq!(c.at(t, title.clone()).get().unwrap(), Some(Value::Str("b".into())));
    c.redo(&Scope::Thing(t)).unwrap().unwrap();
    assert_eq!(c.at(t, title.clone()).get().unwrap(), Some(Value::Str("c".into())));
    let q = CommitQuery::new().scope(Scope::Thing(t));
    assert_eq!(c.commits(&q).unwrap(), n.commits(&q).unwrap());
    let last = c.commits(&q).unwrap()[0].commit.id;
    c.revert(last).unwrap();
    assert_eq!(c.at(t, title.clone()).get().unwrap(), Some(Value::Str("b".into())));
    // a thing watch and a dropped subscription
    let (ttx, trx) = channel();
    let ts = c.watch_thing(t, move |_, ch| ttx.send(ch.ak).unwrap()).unwrap();
    let mut seen = Vec::new();
    while !seen.contains(&title) {
        seen.push(trx.recv_timeout(W).unwrap());
    }
    drop(sub);
    drop(ts);
    // what needs this process to be the node fails Unsupported, never acts on the stand-in
    assert!(matches!(c.client_listen(&[]), Err(osis::Error::Unsupported(_))));
    assert!(matches!(c.listen_unix(&d.0.join("other.sock")), Err(osis::Error::Unsupported(_))));
    assert!(matches!(crate::common::block_on(c.group_source(t, osis::GroupSource::Local)), Err(osis::Error::Unsupported(_))));
    // the stand-in database is never read: Internals fail
    let c2 = c.clone();
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| c2.engine(|_| ()))).is_err(), "Internals on an attached handle");
    drop(c);
    assert_eq!(n.close().unwrap(), osis::Close::Closed);
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
    let mut w = n.write();
    let t = w.create(n.me()).unwrap();
    w.at(t, k.clone()).set(&Value::Bytes(big.clone())).unwrap();
    w.commit().unwrap();
    assert!(matches!(c.at(t, k.clone()).get(), Err(osis::Error::TooLarge { .. })));
    let mut s = c.at(t, k.clone()).stream().unwrap().unwrap();
    assert_eq!(s.len(), big.len() as u64);
    let mut got = Vec::new();
    std::io::Read::read_to_end(&mut s, &mut got).unwrap();
    assert!(got == big, "stream equals the value");
    assert_eq!(c.at(t, k).len().unwrap(), Some(big.len() as u64));
    drop(c);
    assert_eq!(n.close().unwrap(), osis::Close::Closed);
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

const WRITE: u64 = 10;

// spec/wire.md §11.2, notes/client-port.md §2 Writes: a repeated nonce is answered with its first result and applies once; one at or below the highest seen and not remembered is outcome unknown; two sessions keep separate ranges; a restarted node remembers nothing: a marked resend is unknown, never run
#[test]
fn write_nonces_per_session() {
    let d = Dir::new();
    let sock = d.0.join("n.sock");
    let net = osis_transport::Net::new(1);
    let store = MemStore::new();
    let n = node(&store, &net, &sock, true);
    let k = ak("note:n.0");
    let mut w = n.write();
    let t = w.create(n.me()).unwrap();
    w.commit().unwrap();
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
    assert_eq!(n.at(t, k.clone()).get().unwrap(), Some(Value::Int(1)));
    let r3 = r.call(3, WRITE, set_batch(3, n.me(), t, &k, Value::Int(3)));
    assert!(matches!(r3, Outcome::Ok { .. }));
    // nonce 2 was skipped: below the highest seen and not remembered
    let unknown = r.call(4, WRITE, set_batch(2, n.me(), t, &k, Value::Int(9)));
    assert!(matches!(&unknown, Outcome::Err { code: 12, .. }), "{unknown:?}");
    // another session of the same Owner: its own range
    let mut r2 = Raw::unix(&sock);
    r2.auth([2; 16]).unwrap();
    assert!(matches!(r2.call(1, WRITE, set_batch(1, n.me(), t, &k, Value::Int(4))), Outcome::Ok { .. }));
    assert_eq!(n.at(t, k.clone()).get().unwrap(), Some(Value::Int(4)));
    // the first session's memory survives its reconnect within the same node process
    drop(r);
    let mut r = Raw::unix(&sock);
    assert!(matches!(r.auth([1; 16]), Ok(Outcome::Ok { .. })));
    let again = r.call(1, WRITE, set_batch(1, n.me(), t, &k, Value::Int(5)));
    let (Outcome::Ok { value: a, .. }, Outcome::Ok { value: b, .. }) = (&first, &again) else { panic!() };
    assert_eq!(a, b);
    drop((r, r2));
    // a restart: nothing remembered, so a resend of what ran is unknown, every one of them
    assert_eq!(n.close().unwrap(), osis::Close::Closed);
    let n = node(&store, &net, &sock, false);
    let mut r = Raw::unix(&sock);
    assert!(matches!(r.auth([1; 16]), Ok(Outcome::Ok { .. })));
    let resent = 1u64 << 62;
    for (i, nonce) in [1u64, 3].into_iter().enumerate() {
        let o = r.call(5 + i as u64, WRITE, set_batch(nonce | resent, n.me(), t, &k, Value::Int(9)));
        assert!(matches!(&o, Outcome::Err { code: 12, .. }), "{o:?}");
    }
    assert_ne!(n.at(t, k.clone()).get().unwrap(), Some(Value::Int(9)));
    drop(r);
    assert_eq!(n.close().unwrap(), osis::Close::Closed);
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
    assert_eq!(n.close().unwrap(), osis::Close::Closed);
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
            n.batch(|w| {
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
        n.commit_set(*t, k.clone(), &Value::Int(-1)).unwrap();
    }
    let c = attach(&sock);
    let time = |what: &str, f: &mut dyn FnMut()| {
        let t0 = std::time::Instant::now();
        f();
        eprintln!("{what}: {:.3} s", t0.elapsed().as_secs_f64());
    };
    // the sync engine's own per-event cost at this store (every port request and reply is one)
    time("sync engine: one Tick", &mut || n.feed(osis::internals::node::sync::Event::Tick));
    time("local get", &mut || drop(n.at(things[0], k.clone()).get().unwrap()));
    {
        let d2 = Dir::new();
        let s2 = d2.0.join("s.sock");
        let small = node(&MemStore::new(), &osis_transport::Net::new(2), &s2, true);
        let cs = attach(&s2);
        let mut w = cs.write();
        let t = w.create(cs.me()).unwrap();
        w.commit().unwrap();
        time("get, small store, 100 times", &mut || {
            for _ in 0..100 {
                drop(cs.at(t, k.clone()).get().unwrap());
            }
        });
        drop(cs);
        assert_eq!(small.close().unwrap(), osis::Close::Closed);
    }
    time("get", &mut || drop(c.at(things[0], k.clone()).get().unwrap()));
    time("write 1024 sets", &mut || {
        let mut w = c.write();
        for t in things.iter().take(1024) {
            w.at(*t, k.clone()).set(&Value::Int(-2)).unwrap();
        }
        w.commit().unwrap();
    });
    time("commits, whole store (10^4 things, 1100 commits)", &mut || drop(c.commits(&CommitQuery::new()).unwrap()));
    time("commits, one thing", &mut || drop(c.commits(&CommitQuery::new().scope(Scope::Thing(things[0]))).unwrap()));
    time("undo, home group", &mut || drop(c.undo(&Scope::Group(c.me()))));
    time("status", &mut || drop(c.status().unwrap()));
    drop(c);
    assert_eq!(n.close().unwrap(), osis::Close::Closed);
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

// spec/wire.md §11.2 (Sub, Notify), notes/client-port.md §2 (rows that wait), notes/api.md Sync status: an attached handle's `wait_synced` has the node's outcomes: Ok once synced (All, and Group after `sync` through the port), Unsynced for a group without a label, Network after the deadline when the host is unreachable; at most `MAX_WAITS` waits at once per connection; `sync`, `grant`, `make_link`, `sync_now` and the sharing reads go through too
#[test]
fn attached_wait_synced_as_at_the_node() {
    use crate::common::block_on;
    use osis::{Role, SyncScope};
    let d = Dir::new();
    let net = osis_transport::Net::new(2);
    let (_host, addr) = mem_host(&net);
    let sock = d.0.join("n.sock");
    let n = node_on(&net, "n", vec![addr], &sock);
    let c = attach(&sock);
    block_on(c.wait_synced(SyncScope::All, W)).unwrap();
    // a group without a label: Unsynced naming it, at once, as at the node
    let (g, t) = c
        .batch(|w| {
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
    // through the port: the node syncs a thing nothing carries, and it has a label there
    let lone = c.batch(|w| w.create(c.me())).unwrap();
    c.sync(lone, &[]).unwrap();
    c.grant(lone, n.node(), Role::Read, Default::default()).unwrap();
    assert_eq!(n.status().unwrap().groups[&lone].labels.len(), 1);
    block_on(c.wait_synced(SyncScope::Group(lone), W)).unwrap();
    // the sharing reads agree with the node's
    assert_eq!(c.links_of(g).unwrap().len(), 1);
    assert_eq!(c.links_of(g).unwrap(), n.links_of(g).unwrap());
    assert!(!c.holders(g).unwrap().is_empty());
    assert_eq!(c.holders(g).unwrap(), n.holders(g).unwrap());
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
    assert_eq!(m.close().unwrap(), osis::Close::Closed);
    assert_eq!(n.close().unwrap(), osis::Close::Closed);
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
    let mut w = n.write();
    let t = w.create(n.me()).unwrap();
    w.at(t, k.clone()).set(&Value::Bytes(vec![7; small + 1000])).unwrap();
    w.commit().unwrap();
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
    assert!(matches!(r.call(1_000_000, 19, vec![]), Outcome::Ok { .. }));
    assert_eq!(n.watches(), before);
    drop(r);
    assert_eq!(n.close().unwrap(), osis::Close::Closed);
}

/// A host on `net` taking any label, with its address.
fn mem_host(net: &osis_transport::Net) -> (Osis, osis::HostAddr) {
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
    (host, addr)
}

fn until(mut f: impl FnMut() -> bool, what: &str) {
    let end = std::time::Instant::now() + W;
    while !f() {
        assert!(std::time::Instant::now() < end, "{what}");
        std::thread::sleep(Duration::from_millis(10));
    }
}

// spec/wire.md §11.2 (Sub, Notify), notes/client-port.md §2 (rows that wait), spec/permissions.md §8: the flows that wait on other nodes run at the node with the node's outcomes, all through the socket: redeem, demote (a link joiner, a direct holder lowered, an error), revoke_link, revoke_joiner, import_contact
#[test]
fn rows_that_wait_through_the_socket() {
    use crate::common::block_on;
    use osis::{Role, SyncScope};
    let d = Dir::new();
    let net = osis_transport::Net::new(2);
    let (host, addr) = mem_host(&net);
    let (sa, sb) = (d.0.join("a.sock"), d.0.join("b.sock"));
    let a = node_on(&net, "a", vec![addr.clone()], &sa);
    let b = node_on(&net, "b", vec![addr.clone()], &sb);
    let (ca, cb) = (attach(&sa), attach(&sb));
    let k = ak("note:title.0");
    let group = |text: &str| {
        let (g, t) = ca
            .batch(|w| {
                let g = w.create(ca.me())?;
                w.make_group(g)?;
                let t = w.create(g)?;
                w.at(t, k.clone()).set(&Value::Str(text.into()))?;
                w.place(t, g)?;
                Ok((g, t))
            })
            .unwrap();
        ca.sync(g, &[]).unwrap();
        (g, t)
    };
    let (g, t) = group("x");
    let plain = SetRole { sync: SyncFirst::Required, keep: None };
    // a joiner by link, through its daemon
    let link = ca.make_link(g, Role::Write, Default::default()).unwrap();
    block_on(ca.wait_synced(SyncScope::All, W)).unwrap();
    assert_eq!(block_on(cb.redeem(&link)).unwrap(), g);
    until(|| cb.at(t, k.clone()).get().is_ok_and(|v| v == Some(Value::Str("x".into()))), "the group's content at Bob");
    let bob = cb.me();
    until(|| ca.holders(g).unwrap().iter().any(|h| h.actor == bob), "the join reached Alice");
    // its removal, through hers: the link ends with it
    assert_eq!(ca.links_of(g).unwrap().len(), 1);
    // an error of the flow comes back as itself
    assert!(matches!(block_on(ca.set_role(g, bob, Some(Role::Read), plain)), Err(osis::Error::Invalid(_))));
    block_on(ca.set_role(g, bob, None, plain)).unwrap();
    assert!(!ca.holders(g).unwrap().iter().any(|h| h.actor == bob));
    assert_eq!(ca.links_of(g).unwrap().len(), 0);
    // a direct holder lowered: the role goes over the wire
    let (g2, _) = group("y");
    ca.grant(g2, bob, Role::Write, Default::default()).unwrap();
    block_on(ca.set_role(g2, bob, Some(Role::Read), SetRole { sync: SyncFirst::Try(Duration::from_secs(5)), ..plain })).unwrap();
    assert_eq!(a.grants(g2).unwrap().get(&bob).map(|e| e.role), Some(Role::Read));
    // ending a link, and a joiner of one
    let (g3, _) = group("z");
    let l3 = ca.make_link(g3, Role::Read, Default::default()).unwrap();
    let id = ca.links_of(g3).unwrap()[0].id.actor();
    block_on(ca.revoke_link(crate::common::link_id(id), SyncFirst::Required)).unwrap();
    assert_eq!(ca.links_of(g3).unwrap().len(), 0);
    assert!(!l3.to_string().is_empty());
    let (g4, _) = group("w");
    let l4 = ca.make_link(g4, Role::Read, Default::default()).unwrap();
    block_on(ca.wait_synced(SyncScope::All, W)).unwrap();
    assert_eq!(block_on(cb.redeem(&l4)).unwrap(), g4);
    until(|| ca.holders(g4).unwrap().iter().any(|h| h.actor == bob), "the second join reached Alice");
    block_on(ca.set_role(g4, bob, None, SetRole { keep: Some(false), ..plain })).unwrap();
    assert!(!ca.holders(g4).unwrap().iter().any(|h| h.actor == bob));
    // a contact card made and imported through the sockets
    let card = cb.contact_card().unwrap();
    assert_eq!(card, b.contact_card().unwrap());
    assert_eq!(block_on(ca.import_contact(&card)).unwrap(), bob);
    let profile = cb.profile().unwrap();
    assert_eq!(ca.profile_of(bob).unwrap(), Some(profile));
    assert_eq!(ca.profile_of(ca.me()).unwrap(), None);
    drop((ca, cb));
    assert_eq!(a.close().unwrap(), osis::Close::Closed);
    assert_eq!(b.close().unwrap(), osis::Close::Closed);
    assert_eq!(host.close().unwrap(), osis::Close::Closed);
}

// spec: none (API surface); notes/client-port.md §2 (rows that wait): a row that waits holds neither the worker (another call is answered meanwhile) nor the database: the last handle going ends it, told, and the store closes well before its deadline
#[test]
fn a_waiting_row_holds_nothing() {
    use osis::{Role, ShareLink};
    use std::future::Future;
    let d = Dir::new();
    let net = osis_transport::Net::new(2);
    // a link on a host nobody serves: its redeem waits for good
    let s2 = d.0.join("m.sock");
    let m = node_on(&net, "m", vec![osis::HostAddr::new("mem://nobody", [3; 32])], &s2);
    let mut w = m.write();
    let g = w.create(m.me()).unwrap();
    w.make_group(g).unwrap();
    w.commit().unwrap();
    let link: ShareLink = m.make_link(g, Role::Read, Default::default()).unwrap();
    let sock = d.0.join("n.sock");
    let mut cfg = Config::at(StoreAt::Memory(MemStore::new()));
    cfg.runtime = Runtime::Own;
    cfg.transport = Some(Transport::InProcess(net.endpoint("n")));
    cfg.wait_timeout = Duration::from_secs(3600);
    let n = Osis::create(cfg).unwrap().0;
    n.listen_unix(&sock).unwrap();
    let c = attach(&sock);
    let (tx, rx) = channel();
    let (go_tx, go_rx) = channel::<()>();
    let t = std::thread::spawn(move || {
        let mut r = Box::pin(c.redeem(&link));
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(r.as_mut().poll(&mut cx).is_pending());
        // the worker answers while it waits
        tx.send(c.now()).unwrap();
        go_rx.recv().unwrap();
        crate::common::block_on(r)
    });
    rx.recv_timeout(W).expect("the worker answered beside a waiting row");
    let (ctx, crx) = channel();
    std::thread::spawn(move || ctx.send(n.close()).unwrap());
    assert_eq!(crx.recv_timeout(W).expect("close waited for a row that waits").unwrap(), osis::Close::Closed);
    go_tx.send(()).unwrap();
    assert!(t.join().unwrap().is_err(), "told");
    drop(m);
}

// spec: none (API surface); notes/client-port.md §2 (rows that wait): no user handle left on a database something else still holds: a new row that waits is refused, or it would hold the database to its deadline
#[test]
fn no_waiting_row_once_the_handles_went() {
    use osis::Role;
    let d = Dir::new();
    let net = osis_transport::Net::new(2);
    let s2 = d.0.join("m.sock");
    let m = node_on(&net, "m", vec![osis::HostAddr::new("mem://nobody", [3; 32])], &s2);
    let mut w = m.write();
    let g = w.create(m.me()).unwrap();
    w.make_group(g).unwrap();
    w.commit().unwrap();
    let link = m.make_link(g, Role::Read, Default::default()).unwrap();
    let sock = d.0.join("n.sock");
    let n = node_on(&net, "n", vec![], &sock);
    let c = attach(&sock);
    // a callback stuck in the dispatcher holds the database after the last handle
    let mut w = n.write();
    let t = w.create(n.me()).unwrap();
    w.commit().unwrap();
    let (stuck_tx, stuck_rx) = channel::<()>();
    let (in_tx, in_rx) = channel();
    let k = ak("note:title.0");
    let sub = n.at(t, k.clone()).on_change(move |_, ch: Change<Value>| {
        if matches!(ch.source, Source::Initial) {
            return;
        }
        in_tx.send(()).unwrap();
        let _ = stuck_rx.recv();
    }).unwrap();
    n.commit_set(t, k.clone(), &Value::Int(1)).unwrap();
    in_rx.recv_timeout(W).unwrap();
    std::mem::forget(sub);
    drop(n);
    let r = crate::common::block_on(c.redeem(&link));
    assert!(matches!(r, Err(osis::Error::Storage(_))), "{r:?}");
    stuck_tx.send(()).unwrap();
    drop(m);
}

// spec: none (API surface); notes/client-port.md §1: every call that is the node's and not this process's is a row: devices, hosts, hosting (it starts at once under the running node), pairing and removing a device, policies, reach, invites, moves and bundles of more than a page, through the socket
#[test]
fn process_wide_rows_through_the_socket() {
    use osis::{GroupPolicy, SyncScope};
    let d = Dir::new();
    let net = osis_transport::Net::new(2);
    let (host, addr) = mem_host(&net);
    let sock = d.0.join("n.sock");
    let n = node_on(&net, "n", vec![], &sock);
    let c = attach(&sock);
    let g = n.me();
    // devices and hosts
    assert_eq!(c.devices().unwrap(), n.devices().unwrap());
    assert_eq!(c.devices().unwrap().len(), 1);
    c.add_host(&addr).unwrap();
    assert_eq!(n.hosts().unwrap(), vec![addr.clone()]);
    assert_eq!(c.hosts().unwrap(), vec![addr.clone()]);
    c.remove_host(&addr).unwrap();
    assert_eq!(n.hosts().unwrap(), vec![]);
    c.add_host(&addr).unwrap();
    // hosting: shown, set, and up without a restart; off
    assert_eq!(c.hosting().unwrap(), None);
    assert_eq!(c.host_key().unwrap(), None);
    let h = osis::Hosting { listen: vec!["mem://n2".into()], admit: osis::Admit::Own, ..Default::default() };
    c.set_hosting(Some(h.clone())).unwrap();
    assert_eq!(n.hosting().unwrap(), Some(h.clone()));
    assert_eq!(c.hosting().unwrap(), Some(h));
    assert_eq!(c.host_key().unwrap(), n.host_key().unwrap());
    assert!(c.host_key().unwrap().is_some());
    until(|| matches!(n.host_address(), Ok(Some(_))), "hosting did not start under the running node");
    c.set_hosting(None).unwrap();
    assert_eq!(c.hosting().unwrap(), None);
    until(|| matches!(n.host_address(), Ok(None)), "hosting did not stop");
    // policies, reach
    let p = GroupPolicy { publish_reach: Some(false), receipts_only: false };
    assert_eq!(c.group_policy(g).unwrap(), GroupPolicy::default());
    c.sync_policy(g, p).unwrap();
    assert_eq!(n.group_policy(g).unwrap(), p);
    assert_eq!(c.group_policy(g).unwrap(), p);
    c.sync_policy(g, GroupPolicy::default()).unwrap();
    c.rotate_reach().unwrap();
    // invites: none
    assert_eq!(c.invite_requests().unwrap(), vec![]);
    // pairing a new device, through the old one's socket
    let mut pc = Config::at(StoreAt::Memory(MemStore::new()));
    pc.runtime = Runtime::Own;
    pc.transport = Some(Transport::InProcess(net.endpoint("p")));
    let join = Osis::pair(pc, &c.pair_offer().unwrap()).unwrap();
    let (node, reply) = c.pair_accept(join.request()).unwrap();
    let p2 = join.finish(&reply).unwrap();
    assert_eq!(p2.node(), node);
    assert_eq!(p2.me(), c.me());
    assert_eq!(c.devices().unwrap().len(), 2);
    until(|| p2.devices().is_ok_and(|x| x.len() == 2), "the new device reads the person");
    // a bundle of more than a page, out through the socket and in through another's
    let big = "b".repeat(osis::STREAM_CHUNK * 3 / 2);
    let mut w = c.write();
    let t = w.create(g).unwrap();
    w.at(t, ak("note:big.0")).set(&Value::Str(big.clone())).unwrap();
    w.place(t, g).unwrap();
    w.commit().unwrap();
    crate::common::block_on(c.wait_synced(SyncScope::All, W)).unwrap();
    let mut out = Vec::new();
    c.export_bundle(&[g], &mut out).unwrap();
    assert!(out.len() > osis::STREAM_CHUNK, "{}", out.len());
    let s3 = d.0.join("p.sock");
    p2.listen_unix(&s3).unwrap();
    let c3 = attach(&s3);
    c3.import_bundle(&out[..]).unwrap();
    until(|| p2.at(t, ak("note:big.0")).get().is_ok_and(|v| v == Some(Value::Str(big.clone()))), "the bundle's value at the other device");
    // the new device removed, through the socket
    crate::common::block_on(c.remove_device(node, SetRole { sync: SyncFirst::Skip, keep: None })).unwrap();
    assert_eq!(c.devices().unwrap().len(), 1);
    // pages lost to a reconnect: the import says so and runs nothing
    let mut raw = Raw::unix(&sock);
    raw.auth([9; 16]).unwrap();
    assert!(matches!(raw.call(1, 60, vec![Value::Bytes(vec![1, 2])]), Outcome::Ok { .. }));
    assert!(matches!(raw.call(2, 61, vec![Value::uint(5)]), Outcome::Err { code: 10, .. }));
    drop(raw);
    drop((c, c3));
    assert_eq!(p2.close().unwrap(), osis::Close::Closed);
    assert_eq!(n.close().unwrap(), osis::Close::Closed);
    assert_eq!(host.close().unwrap(), osis::Close::Closed);
}

// spec: none (API surface); notes/client-port.md §2 (Bundles): export and import share one connection without mixing: a bundle exported, read to its end, and imported on the same handle
#[test]
fn bundle_out_and_in_on_one_handle() {
    let d = Dir::new();
    let sock = d.0.join("n.sock");
    let net = osis_transport::Net::new(1);
    let n = node(&MemStore::new(), &net, &sock, true);
    let c = attach(&sock);
    let mut out = Vec::new();
    c.export_bundle(&[n.me()], &mut out).unwrap();
    assert!(!out.is_empty());
    c.import_bundle(&out[..]).unwrap();
    // an import coming before an export ends: its pages stay its own
    let mut raw = Raw::unix(&sock);
    raw.auth([9; 16]).unwrap();
    assert!(matches!(raw.call(1, 60, vec![Value::Bytes(out[..3].to_vec())]), Outcome::Ok { .. }));
    assert!(matches!(raw.call(2, 58, vec![Value::List(vec![Value::Tid(n.me())])]), Outcome::Ok { .. }));
    assert!(matches!(raw.call(3, 60, vec![Value::Bytes(out[3..].to_vec())]), Outcome::Ok { .. }));
    assert!(matches!(raw.call(4, 61, vec![Value::uint(out.len() as u64)]), Outcome::Ok { .. }));
    drop((raw, c));
    assert_eq!(n.close().unwrap(), osis::Close::Closed);
}

// spec: none (API surface); notes/client-port.md §2: a pairing reply above the small allowance comes back from the one send: an offer is used once, so a retry under a larger allowance would be refused
#[test]
fn pair_reply_above_the_small_allowance() {
    let d = Dir::new();
    let net = osis_transport::Net::new(2);
    let (host, addr) = mem_host(&net);
    let sock = d.0.join("n.sock");
    let n = node_on(&net, "n", vec![addr], &sock);
    let c = attach(&sock);
    let mut pc = Config::at(StoreAt::Memory(MemStore::new()));
    pc.runtime = Runtime::Own;
    pc.transport = Some(Transport::InProcess(net.endpoint("p")));
    let join = Osis::pair(pc, &c.pair_offer().unwrap()).unwrap();
    osis::internals::Internals::port_pad_pair_reply(&n, osis_proto::client::SMALL_REPLY * 2);
    let (node, reply) = c.pair_accept(join.request()).unwrap();
    let p = join.finish(&reply).unwrap();
    assert_eq!(p.node(), node);
    drop((c, p));
    assert_eq!(n.close().unwrap(), osis::Close::Closed);
    assert_eq!(host.close().unwrap(), osis::Close::Closed);
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
    let mut w = n.write();
    let t = w.create(n.me()).unwrap();
    w.commit().unwrap();
    let hs: Vec<_> = (0..8)
        .map(|i| {
            let (c, k) = (c.clone(), k.clone());
            std::thread::spawn(move || (0..50).filter(|j| c.commit_set(t, k.clone(), &Value::Int(i * 1000 + j)).is_err()).count())
        })
        .collect();
    let failed: usize = hs.into_iter().map(|h| h.join().unwrap()).sum();
    assert_eq!(failed, 0);
    drop(c);
    assert_eq!(n.close().unwrap(), osis::Close::Closed);
}

// spec/wire.md §11.2 (client port), notes/client-port.md §2 (MAX_SCHEMA_BYTES): schema sources registered through the port count per node, not per connection (registrations are process-wide and kept); the same source again costs nothing
#[test]
fn schema_bytes_per_node() {
    let d = Dir::new();
    let sock = d.0.join("n.sock");
    let net = osis_transport::Net::new(1);
    let n = node(&MemStore::new(), &net, &sock, true);
    let src = |name: &str| format!("version 1;\naspect test:{name}.0: string;\n//{}\n", "x".repeat(osis::MAX_SCHEMA_BYTES * 3 / 5));
    let reg = |r: &mut Raw, tok, name: &str| r.call(tok, 16, vec![Value::Str("t.osis".into()), Value::Str(src(name))]);
    let mut a = Raw::unix(&sock);
    a.auth([1; 16]).unwrap();
    assert!(matches!(reg(&mut a, 1, "a"), Outcome::Ok { .. }));
    drop(a);
    let mut b = Raw::unix(&sock);
    b.auth([2; 16]).unwrap();
    assert!(matches!(reg(&mut b, 1, "a"), Outcome::Ok { .. }), "the same source again");
    assert!(matches!(reg(&mut b, 2, "b"), Outcome::Err { code: 5, .. }), "past the node's bound");
    drop(b);
    assert_eq!(n.close().unwrap(), osis::Close::Closed);
}

// notes/api.md Handle and sync: an attached handle's connection thread that dies of a panic closes
// its subscriptions as it unwinds, so a `wait_synced` waiting at the node fails `Network` at once
// instead of hanging, and so does every later call
// spec: none (an API property)
#[test]
fn client_thread_panic_fails_waits() {
    let d = Dir::new();
    let net = osis_transport::Net::new(2);
    let sock = d.0.join("m.sock");
    // a host nobody answers at: `wait_synced(All)` waits
    let m = node_on(&net, "m", vec![osis::HostAddr::new("mem://nobody", [3; 32])], &sock);
    let c = attach(&sock);
    let far = Duration::from_secs(600);
    let (tx, rx) = channel();
    let c2 = c.clone();
    std::thread::spawn(move || {
        let _ = tx.send(crate::common::block_on(c2.wait_synced(osis::SyncScope::All, far)));
    });
    let t0 = std::time::Instant::now();
    while m.waiting() == 0 {
        assert!(t0.elapsed() < W, "the wait never reached the node");
        std::thread::sleep(Duration::from_millis(5));
    }
    c.panic_client_thread();
    let r = rx.recv_timeout(W).expect("a wait hung on a dead connection thread");
    assert!(matches!(r, Err(osis::Error::Network(_))), "{r:?}");
    let r = crate::common::block_on(c.wait_synced(osis::SyncScope::All, far));
    assert!(matches!(r, Err(osis::Error::Network(_))), "{r:?}");
    drop(c);
    assert_eq!(m.close().unwrap(), osis::Close::Closed);
}
