//! The client port (notes/client-port.md, step (b)): a node serving its unix socket, a second
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
    assert_eq!(c.status().unwrap(), n.status().unwrap());
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
struct Raw {
    rt: tokio::runtime::Runtime,
    cs: ClientSession,
    link: osis_transport::Link,
    events: Vec<ClientEvent>,
}

impl Raw {
    fn over<T: osis_transport::Transport>(t: &T, addr: osis_transport::Address) -> Raw {
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
    fn ask(&mut self, cmd: Command, token: u64) -> Result<Outcome, Code> {
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

    fn auth(&mut self, session: [u8; 16]) -> Result<Outcome, Code> {
        self.ask(Command::Auth { token: 0, session }, 0)
    }

    fn call(&mut self, token: u64, method: u64, args: Vec<Value>) -> Outcome {
        self.ask(Command::Call { token, max_reply: osis_proto::client::SMALL_REPLY as u64, method, args }, token).unwrap()
    }
}

/// A `write` call's args setting `k` of `t` to `v` (the port's batch form: nonce, actor, keys, ops).
fn set_batch(nonce: u64, actor: osis::Tid, t: osis::Tid, k: &Ak, v: Value) -> Vec<Value> {
    let op = Value::List(vec![Value::List(vec![]), Value::List(vec![Value::Int(0), v])]);
    vec![Value::uint(nonce), Value::Tid(actor), Value::List(vec![Value::Str(k.as_str().into())]), Value::List(vec![Value::List(vec![Value::Int(3), Value::Tid(t), Value::Int(0), op])])]
}

const WRITE: u64 = 11;

// spec/wire.md §11.2 (Auth node_epoch), notes/client-port.md §2 Writes: a repeated nonce is answered with its first result and applies once; one at or below the highest seen and not remembered is "outcome unknown"; two sessions keep separate ranges; a restarted node has another epoch (a client never retries across it)
#[test]
fn write_nonces_per_session_and_epoch() {
    let d = Dir::new();
    let sock = d.0.join("n.sock");
    let net = osis_transport::Net::new(1);
    let store = MemStore::new();
    let n = node(&store, &net, &sock, true);
    let k = ak("note:n.0");
    let t = n.write_with(|w| w.create(n.me())).unwrap();
    let mut r = Raw::unix(&sock);
    let Ok(Outcome::Ok { value: epoch, .. }) = r.auth([1; 16]) else { panic!() };
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
    assert!(matches!(&unknown, Outcome::Err { code: 8, detail } if detail == &vec![Value::Str("outcome unknown".into())]), "{unknown:?}");
    // another session of the same Owner: its own range
    let mut r2 = Raw::unix(&sock);
    r2.auth([2; 16]).unwrap();
    assert!(matches!(r2.call(1, WRITE, set_batch(1, n.me(), t, &k, Value::Int(4))), Outcome::Ok { .. }));
    assert_eq!(n.get(t, k.clone()).unwrap(), Some(Value::Int(4)));
    // the first session's memory survives its reconnect within the same node process
    drop(r);
    let mut r = Raw::unix(&sock);
    let Ok(Outcome::Ok { value: same, .. }) = r.auth([1; 16]) else { panic!() };
    assert_eq!(same, epoch);
    let again = r.call(1, WRITE, set_batch(1, n.me(), t, &k, Value::Int(5)));
    let (Outcome::Ok { value: a, .. }, Outcome::Ok { value: b, .. }) = (&first, &again) else { panic!() };
    assert_eq!(a, b);
    drop((r, r2));
    // a restart: another epoch, so a client fails its unanswered writes "outcome unknown"
    n.close().unwrap();
    let n = node(&store, &net, &sock, false);
    let mut r = Raw::unix(&sock);
    let Ok(Outcome::Ok { value: other, .. }) = r.auth([1; 16]) else { panic!() };
    assert_ne!(other, epoch);
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
