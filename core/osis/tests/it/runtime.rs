//! A handle on a real runtime (notes/api.md Handle and lifecycle; `Runtime::Own`, `Runtime::Tokio`):
//! close and reopen, stores in use or unwritable, `keep_alive`, a text session's idle commit,
//! and the client socket's directory rules. Real timers run here; no assert is on wall time.
//! spec: none (API surface, notes/api.md)

use crate::common::*;
use osis::{DynamicAspectKey, Error, Osis, Runtime, Store, Value};
use std::path::PathBuf;
use std::time::Duration;

/// A directory of this test's own under the system's temp directory, removed when dropped.
struct Dir(PathBuf);

impl Dir {
    fn new(name: &str) -> Dir {
        use std::hash::{BuildHasher, Hasher};
        let mut h = std::collections::hash_map::RandomState::new().build_hasher();
        h.write_u8(0);
        let d = std::env::temp_dir().join(format!("osis-{name}-{}-{:x}", std::process::id(), h.finish()));
        std::fs::create_dir_all(&d).unwrap();
        Dir(d)
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn at(dir: &std::path::Path, rt: Runtime) -> osis::internals::Opening {
    let mut c = osis::internals::Opening::at(Store::Dir(dir.to_path_buf()));
    c.runtime = rt;
    c
}

// `close` returns once the store is closed, also with `Runtime::Own` (whose runtime stops in
// the background) and on the app's `Runtime::Tokio`: the store opens again at once, holding
// every write.
#[test]
fn reopen_right_after_close() {
    let tokio = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    for rt in [Runtime::Own, Runtime::Tokio(tokio.handle().clone())] {
        let d = Dir::new("reopen");
        let k = DynamicAspectKey::untyped(ak("n:v.0"));
        let db = osis::internals::create(at(&d.0, rt.clone())).unwrap();
        let t = db.commit_with(|w| w.create_with_content(db.home())).unwrap();
        assert_eq!(db.close().unwrap(), osis::Close::Closed);
        for i in 1..6i64 {
            let db = osis::internals::open(at(&d.0, rt.clone())).unwrap();
            assert_eq!(db.at(t, k.clone()).get().unwrap(), (i > 1).then(|| Value::Int(i - 1)), "{rt:?}");
            db.commit_set(t, k.clone(), &Value::Int(i)).unwrap();
            assert_eq!(db.close().unwrap(), osis::Close::Closed);
        }
    }
}

// A store directory that cannot be opened fails `Storage` naming the path and the cause: the
// only trace a full disk leaves in a log.
#[test]
fn a_store_it_cannot_write_names_the_path() {
    let d = Dir::new("unwritable");
    // the store file's name taken by a directory: its open fails as a full disk's would
    std::fs::create_dir_all(d.0.join("db.redb")).unwrap();
    let e = osis::internals::create(at(&d.0, Runtime::None)).map(drop).unwrap_err();
    assert!(matches!(&e, Error::Storage(m) if m.contains(d.0.to_str().unwrap())), "{e:?}");
}

// notes/api.md Errors: a store open elsewhere, by a node of this process not yet closed or by
// another process, fails `InUse` (nothing is wrong with it), and opens once closed.
#[test]
fn a_store_open_elsewhere_is_in_use() {
    // the other process: this test run again, holding the store until its stdin closes
    if let Some(dir) = std::env::var_os("OSIS_HOLD_STORE") {
        let _held = osis::internals::open(at(std::path::Path::new(&dir), Runtime::None)).unwrap();
        println!("held");
        let _ = std::io::Read::read_to_end(&mut std::io::stdin(), &mut Vec::new());
        return;
    }
    let d = Dir::new("in-use");
    let open = || osis::internals::open(at(&d.0, Runtime::None));
    let db = osis::internals::create(at(&d.0, Runtime::None)).unwrap();
    assert_eq!(open().map(drop).unwrap_err(), Error::InUse, "a node of this process");
    assert_eq!(db.close().unwrap(), osis::Close::Closed);
    let mut other = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "runtime::a_store_open_elsewhere_is_in_use", "--nocapture", "--test-threads", "1"])
        .env("OSIS_HOLD_STORE", &d.0)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut out = std::io::BufRead::lines(std::io::BufReader::new(other.stdout.take().unwrap()));
    assert!(out.by_ref().any(|l| l.unwrap().contains("held")), "the other process opened the store");
    assert_eq!(open().map(drop).unwrap_err(), Error::InUse, "another process");
    drop(other.stdin.take());
    out.for_each(drop);
    assert!(other.wait().unwrap().success());
    assert_eq!(open().unwrap().close().unwrap(), osis::Close::Closed, "free once the other process ends");
}

/// A node in memory on `Runtime::Own`, on manual clock `c`.
fn own(c: &std::sync::Arc<osis::internals::ManualClock>) -> Osis {
    let mut o = cfg(0, osis::MemStore::new(), c);
    o.runtime = Runtime::Own;
    o.app.idle_commit = Duration::from_millis(20);
    osis::internals::create(o).unwrap()
}

// notes/ephemeral.md Values that live while their author is there: a kept-alive value (expiring
// 60 ms after each write) is rewritten while its `KeepAlive` lives and is gone by its expiry once dropped; a key without a default expiry is refused, and so is a
// handle with no runtime. Expiry reads a manual clock moved only here, the rewrites run on real
// timers, so no scheduling gap lets a value lapse.
#[test]
fn keep_alive_rewrites_until_dropped() {
    let c = clock();
    let db = own(&c);
    db.register_schema("c.osis", "revision 1;\nexpires(60ms) ephemeral aspect c:on+.0: int;\nephemeral aspect c:flag+.0: int;\n").unwrap();
    let (on, flag) = (db.aspect_key("c:on+.0").unwrap(), db.aspect_key("c:flag+.0").unwrap());
    let t = db.commit_with(|w| w.create()).unwrap();
    assert!(matches!(db.at(t, flag).keep_alive(&Value::Int(1)), Err(Error::Invalid(_))), "no default expiry");
    let none = osis::internals::create(cfg(1, osis::MemStore::new(), &c)).unwrap();
    none.register_schema("c.osis", "revision 1;\nexpires(60ms) ephemeral aspect c:on+.0: int;\n").unwrap();
    let u = none.commit_with(|w| w.create()).unwrap();
    assert!(matches!(none.at(u, none.aspect_key("c:on+.0").unwrap()).keep_alive(&Value::Int(1)), Err(Error::Network(_))), "no runtime");
    let ka = db.at(t, on.clone()).keep_alive(&Value::Int(1)).unwrap();
    let get = || db.at(t, on.clone()).get().unwrap();
    // the commit the value reads from: a rewrite is a new one
    let newest = || db.at(t, on.clone()).writes(&osis::CommitQuery::default()).unwrap().commits.first().map(|k| k.stamp.id);
    assert_eq!(get(), Some(Value::Int(1)));
    // after each rewrite seen the clock moves 20 ms: five moves outlast the first write's 60 ms
    for _ in 0..5 {
        let before = newest();
        let end = std::time::Instant::now() + Duration::from_secs(20);
        while newest() == before {
            assert!(std::time::Instant::now() < end, "no rewrite");
            std::thread::sleep(Duration::from_millis(5));
        }
        c.advance(20);
        assert_eq!(get(), Some(Value::Int(1)));
    }
    drop(ka);
    // a rewrite already running at the drop may land after a move: past one expiry, two more
    // rewrite periods of real time, then past another, it is gone and stays so
    c.advance(61);
    std::thread::sleep(Duration::from_millis(100));
    c.advance(61);
    assert_eq!(get(), None, "rewritten after the drop");
}

// notes/api.md Text editing sessions, spec/requirements.md (Generality: one commit per editing
// pause): with a runtime, a session commits after `idle_commit` without edits, with no further
// edit or call.
#[test]
fn a_text_session_commits_when_idle() {
    let db = own(&clock());
    db.register_schema("t.osis", "revision 1;\naspect n:body.0: text;\n").unwrap();
    let k = db.aspect_key("n:body.0").unwrap();
    let t = db.commit_with(|w| w.create()).unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    let _w = db.at(t, k.clone()).on_write(move |_, e| drop(tx.send(e))).unwrap();
    let s = db.at(t, k.clone()).path(osis::p![]).edit_text().unwrap();
    s.edit("", "typed").unwrap();
    recv(&rx);
    assert_eq!(db.at(t, k).get().unwrap(), Some(Value::Str("typed".into())));
    drop(s);
}

// notes/api.md Handle and lifecycle: closing a node on the app's runtime and then shutting that
// runtime down must not let anything of the node poll a timer of the shut-down runtime. By hand:
// a race, seen in about a third of runs at 40 rounds per thread when `close` did not wait.
#[test]
#[ignore = "by hand"]
fn close_then_runtime_shutdown_polls_no_dead_timer() {
    static PANICS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |i| {
        if i.to_string().contains("being shutdown") {
            PANICS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        prev(i);
    }));
    std::thread::scope(|sc| {
        for t in 0..8u64 {
            sc.spawn(move || {
                for i in 0..40 {
                    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
                    let mut c = osis::internals::Opening::memory();
                    c.app.internals.seed = Some(t * 1000 + i);
                    c.runtime = Runtime::Tokio(rt.handle().clone());
                    let db = osis::internals::create(c).unwrap();
                    let _ = within(Duration::from_millis(1), db.wait_synced(osis::SyncScope::All));
                    assert_eq!(db.close().unwrap(), osis::Close::Closed);
                    drop(rt);
                }
            });
        }
    });
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(PANICS.load(std::sync::atomic::Ordering::Relaxed), 0);
}

// spec/sync-transport.md §6 (unix path sockets), notes/client-port.md §5: the socket directory is
// made 0700 and used only when it is this uid's, mode 0700 and not a symlink; the socket's name
// fits `sun_path`, one per store however its path is spelled; a runtime directory too deep for a
// socket fails `Storage`, which a daemon survives.
#[test]
fn socket_dir_rules_spec_sync_transport_6() {
    use osis::internals::{own_uid, socket_dir, socket_path_under, SOCKET_MAX_PATH};
    use std::os::unix::fs::PermissionsExt;
    let uid = own_uid().unwrap();
    let d = Dir::new("socket");
    let ok = d.0.join("ok");
    socket_dir(&ok, uid).unwrap();
    assert_eq!(std::fs::metadata(&ok).unwrap().permissions().mode() & 0o777, 0o700);
    socket_dir(&ok, uid).unwrap();
    let open = d.0.join("open");
    std::fs::create_dir(&open).unwrap();
    std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(socket_dir(&open, uid), Err(Error::Storage(_))), "group/other access");
    let link = d.0.join("link");
    std::os::unix::fs::symlink(&ok, &link).unwrap();
    assert!(matches!(socket_dir(&link, uid), Err(Error::Storage(_))), "a symlink");
    assert!(matches!(socket_dir(&ok, uid.wrapping_add(1)), Err(Error::Storage(_))), "another uid's");
    let run = Some(d.0.as_path());
    let store = d.0.join("real-store");
    std::fs::create_dir(&store).unwrap();
    let sock = socket_path_under(run, &store).unwrap();
    assert!(sock.as_os_str().len() <= SOCKET_MAX_PATH && sock.extension().is_some_and(|e| e == "sock"), "{sock:?}");
    let alias = d.0.join("alias");
    std::os::unix::fs::symlink(&store, &alias).unwrap();
    assert_eq!(socket_path_under(run, &alias).unwrap(), sock, "through a symlink");
    assert_eq!(socket_path_under(run, &store.join(".")).unwrap(), sock);
    assert_eq!(socket_path_under(run, &alias.join("..").join("real-store")).unwrap(), sock, "with ..");
    assert_ne!(socket_path_under(run, &ok).unwrap(), sock, "another store, another socket");
    let deep = d.0.join("d".repeat(SOCKET_MAX_PATH));
    std::fs::create_dir(&deep).unwrap();
    assert!(matches!(socket_path_under(Some(&deep), &store), Err(Error::Storage(_))));
}
