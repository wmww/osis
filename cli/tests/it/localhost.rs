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
    let mut c = Command::new(OSIS).arg("-s").arg(store).args(["--timeout", "60s"]).args(args).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
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
    let mut c = Command::new(OSIS).arg("-s").arg(store).arg("serve").args(args).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().unwrap();
    let mut out = BufReader::new(c.stdout.take().unwrap());
    let mut addr = String::new();
    out.read_line(&mut addr).unwrap();
    drop(out);
    (Host(c), addr.trim().to_string())
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
    let o = Command::new(OSIS).arg("-s").arg(store).args(args).stdin(Stdio::null()).output().unwrap();
    (o.status.code().unwrap_or(-1), String::from_utf8_lossy(&o.stdout).into_owned(), String::from_utf8_lossy(&o.stderr).into_owned())
}

// notes/client-port.md §7, notes/cli.md Design (daemon): while `serve` holds the store, a second `osis` process runs its command through the daemon's unix socket as Owner, with output and exit codes as the local run's; `inspect` and a dead daemon stay exit 8; no XDG_RUNTIME_DIR falls back to /tmp/osis-<uid>/
#[test]
#[ignore]
fn daemon_clients_localhost() {
    let s = dir("daemon");
    osis(&s, &["init"]);
    let local = dir("daemon-local");
    osis(&local, &["init"]);
    // the same commands locally first, for the expected forms
    let lt = osis(&local, &["create", "--owner", "me", "note:title.0", "\"x\""]);
    let lget = run(&local, &["get", &lt, "note:title.0"]);
    let lmiss = run(&local, &["get", &lt, "note:none.0"]);
    for xdg in [true, false] {
        // a killed daemon's pointer stays (stale): wait for the new one
        let _ = std::fs::remove_file(s.join("sock"));
        let mut c = Command::new(OSIS);
        if !xdg {
            c.env_remove("XDG_RUNTIME_DIR");
        }
        let child = c.arg("-s").arg(&s).arg("serve").stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
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
        // a watch through the daemon: its initial line, then the change another client makes
        let mut w = Command::new(OSIS).arg("-s").arg(&s).args(["--timeout", "60s", "watch", &t, "note:title.0", "--count", "1"]).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
        let mut wout = BufReader::new(w.stdout.take().unwrap());
        let mut first = String::new();
        wout.read_line(&mut first).unwrap();
        assert!(first.contains("\"x\""), "{first}");
        osis(&s, &["set", &t, "note:title.0", "\"y\""]);
        let mut second = String::new();
        wout.read_line(&mut second).unwrap();
        assert!(second.contains("\"y\""), "{second}");
        assert!(w.wait().unwrap().success());
        // inspect needs the store itself
        assert_eq!(run(&s, &["inspect", "thing", &t]).0, 8);
        drop(host);
        // the daemon was killed: its pointer stays, stale; the store opens locally again
        assert_eq!(osis(&s, &["get", &t, "note:title.0"]), "\"y\"");
        osis(&s, &["set", &t, "note:title.0", "\"x\""]);
    }
}
