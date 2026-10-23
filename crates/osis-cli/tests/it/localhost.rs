//! The localhost end-to-end session (notes/apps.md, notes/cli.md Tests), tier 2: a real
//! `osis serve` process over QUIC on 127.0.0.1 and three store directories (Alice's two devices,
//! Bob), driven only through the `osis` binary: init, pair offer/join, link make/redeem, writes
//! on all three, sync, status, undo, bundles, inspect. Assertions read `--json` output.
//! Run: `cargo test -p osis-cli --test it localhost:: -- --ignored`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

const OSIS: &str = env!("CARGO_BIN_EXE_osis");

/// Kills the server when the test ends, also on a panic.
struct Server(Child);

impl Drop for Server {
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
/// carried between the two processes, as a person would by QR code.
fn pair(old: &Path, new: &Path, server: &str) {
    let mut offer = Command::new(OSIS).arg("-s").arg(old).args(["--timeout", "60s", "pair", "offer"]).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
    let mut offer_out = BufReader::new(offer.stdout.take().unwrap());
    let mut line = String::new();
    offer_out.read_line(&mut line).unwrap();
    let mut join = Command::new(OSIS).arg("-s").arg(new).args(["--timeout", "60s", "pair", "join", "--server", server, line.trim()]).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
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
// one blind server process.
#[test]
#[ignore]
fn two_people_three_devices_one_server_localhost() {
    let sd = dir("server");
    let mut serve = Command::new(OSIS).args(["serve", "--data"]).arg(&sd).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().unwrap();
    let mut addr = String::new();
    BufReader::new(serve.stdout.take().unwrap()).read_line(&mut addr).unwrap();
    let _server = Server(serve);
    let addr = addr.trim().to_string();
    assert!(addr.starts_with("quic://127.0.0.1:"), "{addr}");

    let (a1, a2, b) = (dir("alice1"), dir("alice2"), dir("bob"));
    osis(&a1, &["init", "--server", &addr]);
    osis(&b, &["init", "--server", &addr]);
    pair(&a1, &a2, &addr);
    let me1 = osis(&a1, &["--json", "whoami"]);
    let me2 = osis(&a2, &["--json", "whoami"]);
    assert_eq!(field(&me1, "me"), field(&me2, "me"), "one person, two devices");
    assert_eq!(osis(&a1, &["device", "ls"]).lines().count(), 2);

    // Alice shares a group by link; Bob redeems it
    let g = osis(&a1, &["create", "--owner", "me", "--in", "home", "--group"]);
    osis(&a1, &["group", "sync", &g]);
    let t = osis(&a1, &["create", "--owner", &g, "--in", &g, "/t/x", "\"hello\""]);
    let link = osis(&a1, &["link", "make", &g, "write"]);
    osis(&a1, &["sync"]);
    // Alice's devices are all closed now: the link works from the server alone
    assert_eq!(osis(&b, &["link", "redeem", &link]), g);
    osis(&b, &["sync"]);
    assert_eq!(osis(&b, &["get", &t, "/t/x"]), "\"hello\"");

    // writes on all three devices meet
    osis(&b, &["set", &t, "/t/y", "1"]);
    osis(&a2, &["sync"]);
    osis(&a2, &["set", &t, "/t/z", "2"]);
    osis(&b, &["sync"]);
    osis(&a2, &["sync"]);
    osis(&a1, &["sync"]);
    for s in [&a1, &a2, &b] {
        osis(s, &["sync"]);
        let j = osis(s, &["--json", "get", &t, "/t/y"]);
        assert_eq!(j, "1", "{}", s.display());
        assert_eq!(osis(s, &["get", &t, "/t/z"]), "2");
    }
    let st = osis(&a1, &["--json", "status"]);
    assert!(st.contains(&g) && !st.contains("unreachable"), "{st}");

    // undo on the other device of the same person
    osis(&a1, &["undo", "--thing", &t]);
    osis(&a1, &["sync"]);
    osis(&b, &["sync"]);
    let absent = Command::new(OSIS).arg("-s").arg(&b).args(["get", &t, "/t/z"]).output().unwrap();
    assert_eq!(absent.status.code(), Some(3), "Alice's last change undone everywhere: absent");

    // a bundle carries the home group to the other device by hand
    let n = osis(&a1, &["create", "--owner", "me", "--in", "home", "/t/x", "\"by hand\""]);
    // a bundle holds what is placed under the label: a pass places it (the device syncs; a2 does not)
    osis(&a1, &["sync"]);
    let bundle = osis_in(&a1, &["bundle", "export", "home"], b"");
    osis_in(&a2, &["bundle", "import"], &bundle);
    assert_eq!(osis(&a2, &["get", &n, "/t/x"]), "\"by hand\"");
    assert!(osis(&a2, &["inspect", "thing", &n]).contains("/t/x"));
}
