//! The localhost end-to-end session (notes/apps.md, notes/cli.md Tests), tier 2: a node
//! hosting in an `osis serve` process over QUIC on 127.0.0.1 and three more store directories
//! (Alice's two devices, Bob), driven only through the `osis` binary: init, pair offer/join, link make/redeem, writes
//! on all three, sync, status, undo, bundles, inspect. Assertions read `--json` output.
//! Run: `cargo test --workspace --test it localhost:: -- --ignored`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

const OSIS: &str = env!("CARGO_BIN_EXE_osis");

thread_local! {
    /// This test's `osis` runs have no `XDG_RUNTIME_DIR` (a client follows `<store>/sock` only to
    /// the socket its own environment names, so client and daemon must agree).
    static NO_XDG: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// The binary, in this test's environment.
fn cmd() -> Command {
    let mut c = Command::new(OSIS);
    if NO_XDG.get() {
        c.env_remove("XDG_RUNTIME_DIR");
    }
    c
}

/// Kills the host when the test ends, also on a panic.
struct Host(Child);

impl Drop for Host {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn dir(name: &str) -> PathBuf {
    let d = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("osis-e2e-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d
}

/// Runs `osis -s STORE --timeout 60s ARGS` with `stdin`; returns stdout, panics on failure.
fn osis_in(store: &Path, args: &[&str], stdin: &[u8]) -> Vec<u8> {
    let mut c = cmd().arg("-s").arg(store).args(["--timeout", "60s"]).args(args).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    c.stdin.take().unwrap().write_all(stdin).unwrap();
    let o = c.wait_with_output().unwrap();
    assert!(o.status.success(), "osis {args:?}: {}", String::from_utf8_lossy(&o.stderr));
    o.stdout
}

fn osis(store: &Path, args: &[&str]) -> String {
    String::from_utf8(osis_in(store, args, b"")).unwrap().trim_end().to_string()
}

/// The value of `"key":"…"` in one JSON line (enough for the flat results asserted here).
fn field<'a>(json: &'a str, key: &str) -> &'a str {
    let pat = format!("\"{key}\":\"");
    let i = json.find(&pat).unwrap_or_else(|| panic!("no {key} in {json}")) + pat.len();
    &json[i..i + json[i..].find('"').unwrap()]
}

/// Pairs `new` (an empty store) to the person of `old`: the offer and request/reply lines are
/// carried between the two processes, as a person would by QR code. `host`: the new store's.
fn pair(old: &Path, new: &Path, host: Option<&str>) {
    let mut offer = Command::new(OSIS).arg("-s").arg(old).args(["--timeout", "60s", "pair", "offer"]).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
    let mut offer_out = BufReader::new(offer.stdout.take().unwrap());
    let mut line = String::new();
    offer_out.read_line(&mut line).unwrap();
    let host = host.map(|h| vec!["--host", h]).unwrap_or_default();
    let mut join = Command::new(OSIS).arg("-s").arg(new).args(["--timeout", "60s", "pair", "join"]).args(host).arg(line.trim()).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
    let mut join_out = BufReader::new(join.stdout.take().unwrap());
    let mut req = String::new();
    join_out.read_line(&mut req).unwrap();
    offer.stdin.as_mut().unwrap().write_all(req.as_bytes()).unwrap();
    let mut reply = String::new();
    offer_out.read_line(&mut reply).unwrap();
    join.stdin.as_mut().unwrap().write_all(reply.as_bytes()).unwrap();
    assert!(join.wait().unwrap().success(), "pair join");
    assert!(offer.wait().unwrap().success(), "pair offer");
}

// spec/sync.md §10 (QUIC to a known address), spec/permissions.md §9 (links), notes/api.md
// (Devices, Sync), notes/cli.md Tests (tier 2): two people and three devices meet only through
// one host process.
#[test]
#[ignore]
fn two_people_three_devices_one_host_localhost() {
    // a fresh box: `init`, then `serve` hosting any label (`host.0^` written by the flags)
    let sd = dir("host");
    osis(&sd, &["init"]);
    let (_host, addr) = serve(&sd, &["--listen", "quic://127.0.0.1:0", "--admit", "open"]);
    assert!(addr.starts_with("quic://127.0.0.1:"), "{addr}");

    let (a1, a2, b) = (dir("alice1"), dir("alice2"), dir("bob"));
    osis(&a1, &["init", "--host", &addr]);
    osis(&b, &["init", "--host", &addr]);
    pair(&a1, &a2, Some(&addr));
    let me1 = osis(&a1, &["--json", "whoami"]);
    let me2 = osis(&a2, &["--json", "whoami"]);
    assert_eq!(field(&me1, "me"), field(&me2, "me"), "one person, two devices");
    assert_eq!(osis(&a1, &["device", "ls"]).lines().count(), 2);

    // Alice shares a group by link; Bob redeems it
    let g = osis(&a1, &["create", "--owner", "me", "--in", "home", "--group", "t:made.0", "true"]);
    osis(&a1, &["group", "sync", &g]);
    let t = osis(&a1, &["create", "--owner", &g, "--in", &g, "t:x.0", "\"hello\""]);
    let link = osis(&a1, &["link", "make", &g, "write"]);
    osis(&a1, &["sync"]);
    // Alice's devices are all closed now: the link works from the host alone
    assert_eq!(osis(&b, &["link", "redeem", &link]), g);
    osis(&b, &["sync"]);
    assert_eq!(osis(&b, &["get", &t, "t:x.0"]), "\"hello\"");

    // writes on all three devices meet
    osis(&b, &["set", &t, "t:y.0", "1"]);
    osis(&a2, &["sync"]);
    osis(&a2, &["set", &t, "t:z.0", "2"]);
    osis(&b, &["sync"]);
    osis(&a2, &["sync"]);
    osis(&a1, &["sync"]);
    for s in [&a1, &a2, &b] {
        osis(s, &["sync"]);
        let j = osis(s, &["--json", "get", &t, "t:y.0"]);
        assert_eq!(j, "1", "{}", s.display());
        assert_eq!(osis(s, &["get", &t, "t:z.0"]), "2");
    }
    let st = osis(&a1, &["--json", "status"]);
    assert!(st.contains(&g) && !st.contains("unreachable"), "{st}");

    // undo on the other device of the same person
    osis(&a1, &["undo", "--thing", &t]);
    osis(&a1, &["sync"]);
    osis(&b, &["sync"]);
    let absent = Command::new(OSIS).arg("-s").arg(&b).args(["get", &t, "t:z.0"]).output().unwrap();
    assert_eq!(absent.status.code(), Some(3), "Alice's last change undone everywhere: absent");

    // a bundle carries the home group to the other device by hand
    let n = osis(&a1, &["create", "--owner", "me", "--in", "home", "t:x.0", "\"by hand\""]);
    // a bundle holds what is placed under the label: a pass places it (the device syncs; a2 does not)
    osis(&a1, &["sync"]);
    let bundle = osis_in(&a1, &["bundle", "export", "home"], b"");
    osis_in(&a2, &["bundle", "import"], &bundle);
    assert_eq!(osis(&a2, &["get", &n, "t:x.0"]), "\"by hand\"");
    assert!(osis(&a2, &["inspect", "thing", &n]).contains("t:x.0"));
}

/// Runs `osis -s STORE serve ARGS` until dropped; returns it and the host address it prints.
/// Only that first line is read, then stdout is closed: the diagnostics `serve` prints after it
/// are best effort (notes/cli.md serve), so the host goes on (the tests below need it).
fn serve(store: &Path, args: &[&str]) -> (Host, String) {
    let mut c = cmd().arg("-s").arg(store).arg("serve").args(args).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().unwrap();
    let mut out = BufReader::new(c.stdout.take().unwrap());
    let mut addr = String::new();
    out.read_line(&mut addr).unwrap();
    drop(out);
    (Host(c), addr.trim().to_string())
}

/// A `serve` of `store` that prints a `client URL#KEY` line first: that address.
fn serve_clients(store: &Path) -> (Host, String) {
    let (h, line) = serve(store, &["--client-listen", "quic://127.0.0.1:0"]);
    let a = line.strip_prefix("client ").unwrap_or_else(|| panic!("{line}")).to_string();
    (h, a)
}

// spec/sync.md §10 (client port), notes/client-port.md §3, §5, notes/cli.md: a thin CLI (`--node ADDR --client-secret FILE`, no store) over real QUIC with bearer Auth: the client listener's address from `serve --client-listen`; reads and writes within its grant, as its actor; not beyond it; a rotated client key strands the old address, exit 6-class `Network`, while the new one works; a wrong secret is refused; `--remote` and `group source` route a group of another store there, and fail, not fall back, once it is gone
#[test]
#[ignore]
fn thin_cli_quic_localhost() {
    let n = dir("thin-node");
    osis(&n, &["init"]);
    let g = osis(&n, &["create", "--owner", "me", "--group", "note:title.0", "\"g\""]);
    let t = osis(&n, &["create", "--owner", &g, "--in", &g, "note:title.0", "\"hello\""]);
    let hidden = osis(&n, &["create", "--owner", "me", "note:title.0", "\"hidden\""]);
    let add = osis(&n, &["clients", "add"]);
    let (actor, secret) = add.split_once(' ').unwrap();
    osis(&n, &["grant", &g, actor, "write"]);
    let f = dir("thin-secret").join("client.secret");
    std::fs::create_dir_all(f.parent().unwrap()).unwrap();
    std::fs::write(&f, secret).unwrap();
    let file = f.to_str().unwrap();
    let (daemon, addr) = serve_clients(&n);
    let none = dir("thin-unused");
    let thin = |args: &[&str]| {
        let mut a = vec!["--timeout", "30s", "--node", addr.as_str(), "--client-secret", file];
        a.extend_from_slice(args);
        run(&none, &a)
    };
    let g1 = thin(&["get", &t, "note:title.0"]);
    assert_eq!((g1.0, g1.1.trim()), (0, "\"hello\""), "{}", g1.2);
    let w = thin(&["set", &t, "note:title.0", "\"from thin\""]);
    assert_eq!(w.0, 0, "{}", w.2);
    let g2 = thin(&["get", &t, "note:title.0"]);
    assert_eq!(g2.1.trim(), "\"from thin\"");
    // what its actor may not read reads as absent, what it may not write fails
    assert_ne!(thin(&["get", &hidden, "note:title.0"]).0, 0);
    assert_ne!(thin(&["set", &hidden, "note:title.0", "\"x\""]).0, 0);
    // through the daemon, the store sees the client's write
    assert_eq!(osis(&n, &["get", &t, "note:title.0"]), "\"from thin\"");
    // a wrong secret
    let bad = f.with_extension("bad");
    std::fs::write(&bad, "00".repeat(32)).unwrap();
    let r = run(&none, &["--timeout", "30s", "--node", &addr, "--client-secret", bad.to_str().unwrap(), "get", &t, "note:title.0"]);
    assert_ne!(r.0, 0);
    assert!(r.2.contains("refused"), "{}", r.2);
    // a new client listener key: the old address is out, the new one in
    let new = osis(&n, &["clients", "rotate-key"]);
    assert_ne!(new, addr);
    let old = run(&none, &["--timeout", "3s", "--node", &addr, "--client-secret", file, "get", &t, "note:title.0"]);
    assert_ne!(old.0, 0);
    let r = run(&none, &["--timeout", "30s", "--node", &new, "--client-secret", file, "get", &t, "note:title.0"]);
    assert_eq!(r.0, 0, "{}", r.2);
    // another node's store routes a group it does not hold there; with the node gone it fails
    let m = dir("thin-other");
    osis(&m, &["init"]);
    let route = |args: &[&str]| {
        let mut a = vec!["--timeout", "5s", "--remote", new.as_str(), "--remote-secret", file];
        a.extend_from_slice(args);
        run(&m, &a)
    };
    let r = route(&["group", "source", &g, &new]);
    assert_eq!(r.0, 0, "{}", r.2);
    let r = route(&["get", &t, "note:title.0"]);
    assert_eq!((r.0, r.1.trim()), (0, "\"from thin\""), "{}", r.2);
    drop(daemon);
    let r = route(&["get", &g, "note:title.0"]);
    assert_ne!(r.0, 0, "not a local answer: {}", r.1);
    let r = run(&m, &["get", &g, "note:title.0"]);
    assert_ne!(r.0, 0, "without the attachment too: {}", r.1);
}

/// `osis serve` on `store` as a plain daemon, up once its socket is named.
fn daemon(store: &Path) -> Host {
    let c = cmd().arg("-s").arg(store).arg("serve").stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    let end = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while !store.join("sock").exists() {
        assert!(std::time::Instant::now() < end, "no daemon");
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    Host(c)
}

// spec: none. notes/chat.md, notes/dogfood.md: the channel's flow over real QUIC: a host taking anyone, two stores already in use, daemons on both: a chat created through the daemon on one, a link, joined through the daemon on the other (again by either: the chat), `chat watch` through the socket wakes on a post, the JSON has id, sender, name, time, text and reply; read from a cursor; an edit and a delete; a kick through the daemon
#[test]
#[ignore]
fn chat_channel_localhost() {
    let (hs, a, b) = (dir("chat-host"), dir("chat-a"), dir("chat-b"));
    osis(&hs, &["init"]);
    let (_host, addr) = serve(&hs, &["--listen", "quic://127.0.0.1:0", "--admit", "open"]);
    osis(&a, &["init", "--host", &addr]);
    osis(&b, &["init", "--host", &addr]);
    // stores already in use
    osis(&b, &["create", "--owner", "me", "note:title.0", "\"before\""]);
    let da = daemon(&a);
    let c = osis(&a, &["chat", "create", "--name", "channel"]);
    let link = osis(&a, &["chat", "link", &c]);
    let first = osis(&a, &["chat", "post", &c, "--from", "alice", "--subject", "hello", "the body"]);
    let db = daemon(&b);
    let bc = osis(&b, &["chat", "join", &link]);
    assert_eq!(bc, c);
    // already held: the chat again, for the joiner and the maker
    assert_eq!(osis(&b, &["chat", "join", &link]), c);
    assert_eq!(osis(&a, &["chat", "join", &link]), c);
    let read = osis(&b, &["--json", "chat", "read", &c]);
    let line = read.lines().next().unwrap();
    assert_eq!(field(line, "id"), first);
    assert_eq!(field(line, "name"), "alice");
    assert_eq!(field(line, "text"), "hello\\n\\nthe body");
    assert!(field(line, "sender").starts_with("osis://"));
    assert!(line.contains("\"reply_to\":null") && line.contains("\"time\":"), "{line}");
    let cursor = field(read.lines().last().unwrap(), "cursor").to_string();
    // the listener: wakes on the next message, through the socket
    let w = cmd().arg("-s").arg(&b).args(["--json", "--timeout", "60s", "chat", "watch", &c, "--count", "1"]).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    std::thread::sleep(std::time::Duration::from_secs(1));
    let second = osis(&a, &["chat", "post", &c, "--from", "alice", "--reply-to", &first, "second"]);
    let out = w.wait_with_output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let heard = String::from_utf8(out.stdout).unwrap();
    assert_eq!(field(&heard, "id"), second, "{heard}");
    assert_eq!(field(&heard, "reply_to"), first);
    assert_eq!(field(&heard, "text"), "second");
    // new since the cursor; a watch from it says the same at once
    let new = osis(&b, &["--json", "chat", "read", &c, "--after", &cursor]);
    assert_eq!(field(new.lines().next().unwrap(), "id"), second, "{new}");
    let caught = osis(&b, &["--json", "chat", "watch", &c, "--after", &cursor, "--count", "1"]);
    assert_eq!(field(&caught, "id"), second);
    let mine = osis(&b, &["chat", "post", &c, "--from", "bob", "from bob"]);
    // the people who joined, by their link; not the link's actor
    let whom = field(&osis(&b, &["--json", "whoami"]), "me").to_string();
    let m = osis(&a, &["chat", "members", &c]);
    assert!(m.lines().any(|l| l.starts_with(&format!("{whom} Write via "))) && m.lines().any(|l| l.starts_with("link ")), "{m}");
    let end = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while !osis(&a, &["chat", "read", &c]).contains("from bob") {
        assert!(std::time::Instant::now() < end, "not at Alice");
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let fixed = osis(&b, &["chat", "edit", &c, &mine, "from bob, fixed"]);
    assert_ne!(fixed, mine);
    let end = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while !osis(&a, &["chat", "read", &c]).contains("from bob, fixed") {
        assert!(std::time::Instant::now() < end, "no edit at Alice");
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    osis(&a, &["chat", "delete", &c, &second]);
    let end = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while osis(&b, &["chat", "read", &c]).contains(": second") {
        assert!(std::time::Instant::now() < end, "no delete at Bob");
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let bob = field(&osis(&b, &["--json", "whoami"]), "me").to_string();
    osis(&a, &["chat", "kick", &c, &bob]);
    drop(db);
    drop(da);
    let r = run(&b, &["--timeout", "30s", "chat", "post", &c, "after"]);
    let r = if r.0 == 0 { run(&b, &["--timeout", "30s", "chat", "post", &c, "after"]) } else { r };
    assert_ne!(r.0, 0, "{}", r.1);
    assert!(osis(&b, &["chat", "read", &c]).contains("from bob, fixed"), "a kicked member keeps a copy");
}

// spec/data-model.md §9 (`host.0^` `own`), notes/cli.md Hosting: a dedicated host device of
// Alice's, paired and then hosting under `own` (its address from `hosting show`, before it
// serves, so one port picked up front), the only host she has: her home, a group made afterwards and a
// link to it reach it; Bob, on that host only, redeems the link (his own home it refuses:
// his `sync` exits 6 naming the host that does not admit it).
#[test]
#[ignore]
fn own_host_device_localhost() {
    let (a, h, b) = (dir("own-alice"), dir("own-host"), dir("own-bob"));
    osis(&a, &["init"]);
    pair(&a, &h, None);
    let port = std::net::UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let url = format!("quic://127.0.0.1:{port}");
    osis(&h, &["hosting", "set", "--listen", &url, "--admit", "own"]);
    let show = osis(&h, &["hosting", "show"]);
    let addr = show.lines().find_map(|l| l.strip_prefix("address ")).unwrap_or_else(|| panic!("{show}")).to_string();
    assert!(addr.starts_with(&format!("{url}#")), "{addr}");
    osis(&h, &["hosts", "add", &addr]);
    osis(&a, &["hosts", "add", &addr]);
    let (_host, served) = serve(&h, &[]);
    assert_eq!(served, addr, "the address `hosting show` said");

    let g = osis(&a, &["create", "--owner", "me", "--in", "home", "--group", "t:made.0", "true"]);
    osis(&a, &["group", "sync", &g]);
    let t = osis(&a, &["create", "--owner", &g, "--in", &g, "t:x.0", "\"hello\""]);
    let link = osis(&a, &["link", "make", &g, "write"]);
    osis(&a, &["sync"]);
    osis(&b, &["init", "--host", &addr]);
    assert_eq!(osis(&b, &["link", "redeem", &link]), g);
    assert_eq!(osis(&b, &["get", &t, "t:x.0"]), "\"hello\"");
    let home = osis(&b, &["whoami", "--json"]);
    let o = Command::new(OSIS).arg("-s").arg(&b).args(["--timeout", "5s", "sync"]).output().unwrap();
    let err = String::from_utf8_lossy(&o.stderr);
    assert_eq!(o.status.code(), Some(6), "{err}");
    assert!(err.contains(&format!("host {addr} does not admit group {} (yet)", field(&home, "home"))), "{err}");
}

/// Runs `osis` once; (exit code, stdout, stderr).
fn run(store: &Path, args: &[&str]) -> (i32, String, String) {
    run_in(store, args, b"")
}

/// `run` with `stdin`.
fn run_in(store: &Path, args: &[&str], stdin: &[u8]) -> (i32, String, String) {
    let mut c = cmd().arg("-s").arg(store).args(args).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    c.stdin.take().unwrap().write_all(stdin).unwrap();
    let o = c.wait_with_output().unwrap();
    (o.status.code().unwrap_or(-1), String::from_utf8_lossy(&o.stdout).into_owned(), String::from_utf8_lossy(&o.stderr).into_owned())
}

/// A new thing on `store`, to move.
fn gt_of(store: &Path) -> String {
    osis(store, &["create", "--owner", "me", "t:x.0", "1"])
}

/// A `write` script whose last line names an unknown thing (exit 3, nothing committed).
const BAD_SCRIPT: &[u8] = b"create --owner me --in home --as x a:b.0 1\nset osis://AAAAAAAAAAAAAAAAAAAA a:b.0 1\n";

// spec/sync.md §10 (unix), notes/client-port.md §7, notes/cli.md Design (daemon): while `serve` holds the store, a second `osis` process runs its command through the daemon's unix socket as Owner, with output and exit codes as the local run's (`get`, `--json`, `write` incl. a failing script, `watch`, `group sync`, `grant`, `sync`, `wait`: the grant reaches Bob, a group without a label fails `wait` as locally; `device ls`, `card show`, `hosting set/show/off`, `hosts add/rm`, `link redeem/revoke`, `demote`, `move`, `bundle export/import`, `pair offer`, `device rm`); `inspect` and a dead daemon stay exit 8, `group source` exit 1 saying why; no XDG_RUNTIME_DIR falls back to /tmp/osis-<uid>/
#[test]
#[ignore]
fn daemon_clients_localhost() {
    // a host, and Bob on it, a contact of the daemon's person both ways (before it serves)
    let sd = dir("daemon-host");
    osis(&sd, &["init"]);
    let (_hosting, addr) = serve(&sd, &["--listen", "quic://127.0.0.1:0", "--admit", "open"]);
    let s = dir("daemon");
    osis(&s, &["init", "--host", &addr]);
    let b = dir("daemon-bob");
    osis(&b, &["init", "--host", &addr]);
    let card = osis(&b, &["card", "show"]);
    let bob = osis(&s, &["card", "import", &card]);
    // contacts both ways: Bob takes the grant without an invite request
    let scard = osis(&s, &["card", "show"]);
    osis(&b, &["card", "import", &scard]);
    let local = dir("daemon-local");
    osis(&local, &["init"]);
    // the same commands locally first, for the expected forms
    let lt = osis(&local, &["create", "--owner", "me", "note:title.0", "\"x\""]);
    let lget = run(&local, &["get", &lt, "note:title.0"]);
    let lmiss = run(&local, &["get", &lt, "note:none.0"]);
    let ljson = run(&local, &["--json", "get", &lt, "note:title.0"]);
    let lbad = run_in(&local, &["write"], BAD_SCRIPT);
    assert_eq!(lbad.0, 3, "{}", lbad.2);
    for xdg in [true, false] {
        // a killed daemon's pointer stays (stale): wait for the new one
        let _ = std::fs::remove_file(s.join("sock"));
        NO_XDG.set(!xdg);
        let child = cmd().arg("-s").arg(&s).arg("serve").stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
        let host = Host(child);
        // `serve` names its socket in the store once it listens
        let end = std::time::Instant::now() + std::time::Duration::from_secs(30);
        while !s.join("sock").exists() {
            assert!(std::time::Instant::now() < end, "serve did not listen");
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let sock = std::fs::read_to_string(s.join("sock")).unwrap();
        if !xdg {
            assert!(sock.starts_with("/tmp/osis-"), "{sock}");
        }
        let t = osis(&s, &["create", "--owner", "me", "note:title.0", "\"x\""]);
        assert!(t.starts_with("osis://"), "{t}");
        let get = run(&s, &["get", &t, "note:title.0"]);
        assert_eq!((get.0, get.1.as_str()), (lget.0, lget.1.as_str()));
        let miss = run(&s, &["get", &t, "note:none.0"]);
        assert_eq!((miss.0, miss.1.as_str()), (lmiss.0, lmiss.1.as_str()));
        let json = run(&s, &["--json", "get", &t, "note:title.0"]);
        assert_eq!((json.0, json.1.as_str()), (ljson.0, ljson.1.as_str()));
        // a write script: one commit; a failing one commits nothing, with the local run's error
        let w = run_in(&s, &["write"], format!("set {t} note:body.0 \"b\"\n").as_bytes());
        assert_eq!((w.0, w.1.lines().next().map(str::len)), (0, Some(64)), "{}", w.2);
        assert_eq!(osis(&s, &["get", &t, "note:body.0"]), "\"b\"");
        let bad = run_in(&s, &["write"], BAD_SCRIPT);
        assert_eq!((bad.0, bad.1.as_str(), bad.2.as_str()), (lbad.0, lbad.1.as_str(), lbad.2.as_str()));
        // a watch through the daemon: its initial line, then the change another client makes
        let mut w = cmd().arg("-s").arg(&s).args(["--timeout", "60s", "watch", &t, "note:title.0", "--count", "1"]).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
        let mut wout = BufReader::new(w.stdout.take().unwrap());
        let mut first = String::new();
        wout.read_line(&mut first).unwrap();
        assert!(first.contains("\"x\""), "{first}");
        osis(&s, &["set", &t, "note:title.0", "\"y\""]);
        let mut second = String::new();
        wout.read_line(&mut second).unwrap();
        assert!(second.contains("\"y\""), "{second}");
        assert!(w.wait().unwrap().success());
        // sharing and sync through the daemon: a synced group, a grant Bob receives, `sync`
        // and `wait` (which wait at the node); a group without a label fails `wait` as locally
        let mut unsynced = None;
        if xdg {
            let g = osis(&s, &["create", "--owner", "me", "--in", "home", "--group", "t:made.0", "true"]);
            assert_eq!(osis(&s, &["group", "sync", &g]), "");
            let gt = osis(&s, &["create", "--owner", &g, "--in", &g, "t:x.0", "\"shared\""]);
            assert_eq!(osis(&s, &["grant", &g, &bob, "read"]), "");
            assert_eq!(osis(&s, &["sync"]), "");
            assert_eq!(osis(&s, &["wait", "--group", &gt]), "");
            let end = std::time::Instant::now() + std::time::Duration::from_secs(60);
            loop {
                osis(&b, &["sync"]);
                if run(&b, &["get", &gt, "t:x.0"]).1.trim_end() == "\"shared\"" {
                    break;
                }
                assert!(std::time::Instant::now() < end, "Bob never received the grant");
            }
            let h = osis(&s, &["create", "--owner", "me", "--group", "t:made.0", "true"]);
            let ht = osis(&s, &["create", "--owner", &h, "--in", &h, "t:x.0", "\"local\""]);
            let w = run(&s, &["wait", "--group", &ht]);
            assert_ne!(w.0, 0, "{}", w.2);
            unsynced = Some((ht, w));
        }
        // inspect needs the store itself
        assert_eq!(run(&s, &["inspect", "thing", &t]).0, 8);
        // so does `group source`: it says what to do
        let src = run(&s, &["group", "source", &t, "local"]);
        assert!(src.0 == 1 && src.2.contains("stop `osis serve`"), "{src:?}");
        // the node's own commands through the socket: its devices, hosts, hosting, cards, links
        if xdg {
            assert_eq!(osis(&s, &["device", "ls"]).lines().count(), 1);
            assert_eq!(osis(&s, &["card", "show"]), scard);
            let port = std::net::UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
            osis(&s, &["hosting", "set", "--listen", &format!("quic://127.0.0.1:{port}"), "--admit", "open"]);
            let show = osis(&s, &["hosting", "show"]);
            let own = show.lines().find_map(|l| l.strip_prefix("address ")).unwrap_or_else(|| panic!("{show}")).to_string();
            osis(&s, &["hosts", "add", &own]);
            assert!(osis(&s, &["hosts", "ls"]).contains(&own));
            osis(&s, &["hosts", "rm", &own]);
            osis(&s, &["hosting", "off"]);
            assert_eq!(run(&s, &["hosting", "show"]).0, 3);
            // a link redeemed and ended through daemons
            let g = osis(&b, &["create", "--owner", "me", "--in", "home", "--group", "t:made.0", "true"]);
            osis(&b, &["group", "sync", &g]);
            let link = osis(&b, &["link", "make", &g, "read"]);
            assert_eq!(osis(&s, &["link", "redeem", &link]), g);
            // ... and made there: a joiner, removed with `demote`; another link, revoked
            let sg = osis(&s, &["create", "--owner", "me", "--in", "home", "--group", "t:made.0", "true"]);
            osis(&s, &["group", "sync", &sg]);
            let link = osis(&s, &["link", "make", &sg, "read"]);
            assert_eq!(osis(&b, &["link", "redeem", &link]), sg);
            osis(&b, &["sync"]);
            let bob_me = field(&osis(&b, &["--json", "whoami"]), "me").to_string();
            let end = std::time::Instant::now() + std::time::Duration::from_secs(30);
            while run(&s, &["via", &sg, &bob_me]).0 != 0 {
                assert!(std::time::Instant::now() < end, "the join did not reach the daemon");
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            osis(&s, &["demote", &sg, &bob_me, "remove"]);
            assert_ne!(run(&s, &["via", &sg, &bob_me]).0, 0);
            osis(&s, &["link", "make", &sg, "read"]);
            let ls = osis(&s, &["link", "ls", &sg]);
            let id = ls.split_whitespace().next().unwrap_or_else(|| panic!("{ls}")).to_string();
            osis(&s, &["link", "revoke", &id]);
            assert_eq!(osis(&s, &["link", "ls", &sg]), "");
            // moves, a bundle, and a new device paired through the daemon's stdin flow
            let copy = osis(&s, &["move", &gt_of(&s), &sg]);
            assert!(copy.starts_with("osis://"), "{copy}");
            let bundle = cmd().arg("-s").arg(&s).args(["bundle", "export", "home"]).output().unwrap();
            assert!(bundle.status.success() && bundle.stdout.starts_with(b"osisbndl"), "{}", String::from_utf8_lossy(&bundle.stderr));
            assert_eq!(run_in(&s, &["bundle", "import"], &bundle.stdout).0, 0);
            let dev = dir("daemon-device");
            pair(&s, &dev, Some(&addr));
            let ls = osis(&s, &["device", "ls"]);
            assert_eq!(ls.lines().count(), 2);
            let node = field(&osis(&s, &["--json", "whoami"]), "node").to_string();
            let other = ls.lines().find(|l| *l != node).unwrap().to_string();
            // spec/permissions.md §9: the removed device keeps the seeds: `device rm` says so, or
            // with --end-links ends them
            osis(&s, &["link", "make", &sg, "read"]);
            let open = osis(&s, &["device", "rm", &other, "--sync", "skip"]);
            assert!(open.contains("osis link revoke"), "{open}");
            assert_eq!(osis(&s, &["device", "ls"]).lines().count(), 1);
            assert_eq!(osis(&s, &["link", "ls"]).lines().count(), open.lines().count(), "the person's links");
            let dev = dir("daemon-device-2");
            pair(&s, &dev, Some(&addr));
            let ls = osis(&s, &["device", "ls"]);
            let other = ls.lines().find(|l| *l != node).unwrap().to_string();
            let ended = osis(&s, &["device", "rm", &other, "--sync", "skip", "--end-links"]);
            assert!(ended.starts_with("ended link"), "{ended}");
            assert_eq!(osis(&s, &["link", "ls"]), "");
        }
        drop(host);
        if let Some((ht, w)) = unsynced {
            assert_eq!(run(&s, &["wait", "--group", &ht]), w, "the local run's outcome");
        }
        // the daemon was killed: its pointer stays, stale; the store opens locally again
        assert_eq!(osis(&s, &["get", &t, "note:title.0"]), "\"y\"");
        osis(&s, &["set", &t, "note:title.0", "\"x\""]);
    }
}
