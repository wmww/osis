#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! The `osis` binary run in-process (notes/cli.md Tests, default tests; one test spawns `serve`): commands over memory and
//! temp-dir stores, exit codes per error category, `--json`, `write` scripts, named
//! keys with a schema, the command table's coverage of the API. No network, no sleeps.
//! spec: none (client surface: notes/cli.md).

use clap::CommandFactory;
use osis::{MemStore, Store};
use osis_cli::args::Cli;
use osis_cli::{Io, run};
use std::path::PathBuf;

struct Out {
    code: i32,
    out: String,
    err: String,
}

impl Out {
    fn line(&self) -> &str {
        self.out.trim_end()
    }
}

/// One store; every call is one invocation, with `pre` before its arguments.
struct S {
    sel: Store,
    pre: Vec<String>,
}

impl S {
    fn mem() -> S {
        let s = S { sel: Store::Memory(MemStore::new()), pre: Vec::new() };
        assert_eq!(s.ok(&["init"]).code, 0);
        s
    }

    fn call(&self, args: &[&str], stdin: &str) -> Out {
        let (mut o, mut e) = (Vec::new(), Vec::new());
        let mut i = stdin.as_bytes();
        let code = run(["osis", "--no-lan"].into_iter().chain(self.pre.iter().map(String::as_str)).chain(args.iter().copied()), Some(self.sel.clone()), Io { stdin: &mut i, stdout: &mut o, stderr: &mut e, tty: false });
        Out { code, out: String::from_utf8(o).unwrap(), err: String::from_utf8(e).unwrap() }
    }

    fn ok(&self, args: &[&str]) -> Out {
        let o = self.call(args, "");
        assert_eq!(o.code, 0, "{args:?}: {}", o.err);
        o
    }

    fn code(&self, args: &[&str]) -> i32 {
        self.call(args, "").code
    }

    fn thing(&self) -> String {
        self.ok(&["create", "t:made.0", "true"]).line().to_string()
    }

    /// A thing whose setting (`retention^.0`, written in its creating commit) keeps every
    /// aspect's history for good.
    fn kept_thing(&self) -> String {
        let keep = "{history: #some(#keep({until: #some(9223372036854775807), after: #none})), expires: #none, final: false, purge_before: #none}";
        let setting = format!("{{rules: {{}}, retain: false, default: #some({keep}), history_holds_targets: false}}");
        self.ok(&["create", "t:made.0", "true", "retention^.0", &setting]).line().to_string()
    }
}

fn tmp(name: &str) -> PathBuf {
    let d = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("osis-cli-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d
}

// notes/cli.md Tests: argument parsing for every command (clap's debug_assert).
#[test]
fn command_tree_is_consistent_plan_cli_tests() {
    Cli::command().debug_assert();
}

// CLI Things and aspects: create, get, set, replace, rm, show, aspects, delete.
#[test]
fn things_and_aspects_plan_cli_4() {
    let s = S::mem();
    let t = s.ok(&["create", "note:title.0", "\"hi\"", "note:n.0", "3", "note:neg.0", "-3"]).line().to_string();
    assert_eq!(s.ok(&["get", &t, "note:neg.0"]).line(), "-3");
    assert!(t.starts_with("osis://"));
    assert_eq!(s.ok(&["get", &t, "note:title.0"]).line(), "\"hi\"");
    s.ok(&["set", &t, "note:m.0", "{\"a\": [1, 2.5], 1: #{h'00'}}"]);
    assert_eq!(s.ok(&["get", &t, "note:m.0"]).line(), "{1: #{h'00'}, \"a\": [1, 2.5]}");
    assert_eq!(s.ok(&["get", &t, "note:m.0", "[\"a\"]"]).line(), "[1, 2.5]");
    assert_eq!(s.ok(&["get", &t, "note:m.0", "[1]"]).line(), "#{h'00'}");
    s.ok(&["set", &t, "note:m.0", "[\"b\"]", "true"]);
    assert_eq!(s.ok(&["get", &t, "note:m.0", "[\"b\"]"]).line(), "true");
    s.ok(&["rm", &t, "note:m.0", "[\"b\"]"]);
    assert_eq!(s.code(&["get", &t, "note:m.0", "[\"b\"]"]), 3);
    s.ok(&["overwrite", &t, "note:n.0", "4"]);
    assert_eq!(s.ok(&["get", &t, "note:n.0"]).line(), "4");
    let aks = s.ok(&["aspects", &t]).out;
    assert!(aks.contains("note:title.0") && aks.contains("created.0"), "{aks}");
    let show = s.ok(&["show", &t]).out;
    assert!(show.contains("note:title.0\t\"hi\"") && show.contains("role\tadmin") && show.contains("created.0\t{admin: weak(osis://"), "{show}");
    s.ok(&["rm", &t, "note:title.0"]);
    assert_eq!(s.code(&["get", &t, "note:title.0"]), 3);
}

// notes/cli.md Exit codes: exit codes by error category.
#[test]
fn exit_codes_plan_cli_6() {
    let s = S::mem();
    let t = s.thing();
    // 2: usage, unparsable argument
    assert_eq!(s.code(&["get"]), 2);
    assert_eq!(s.code(&["set", &t, "a:b.0", "{oops"]), 2);
    assert_eq!(s.code(&["get", "not-a-tid", "a:b.0"]), 2);
    // 3: absent, unknown thing; a failure always says why
    let o = s.call(&["get", &t, "a:b.0"], "");
    assert_eq!((o.code, o.err.trim_end()), (3, format!("error: absent: a:b.0 of {t}").as_str()));
    let other = "osis://AAAAAAAAAAAAAAAAAAAA";
    assert_eq!(s.code(&["set", other, "a:b.0", "1"]), 3);
    // 7: invalid (role-class aspects are written only through sharing calls)
    assert_eq!(s.code(&["set", &t, "roles.0", "{}"]), 7);
    // 8: store missing
    let d = tmp("missing");
    let o = osis_cli::main_with(["osis", "--no-lan", "-s", d.to_str().unwrap(), "whoami"], &mut &b""[..], &mut Vec::new(), &mut Vec::new());
    assert_eq!(o, 8);
    // a secret is read from `@FILE` or `-` (a link need not sit in argv)
    let o = s.call(&["link", "redeem", "@/nonexistent/link"], "");
    assert_eq!(o.code, 2, "{}", o.err);
    assert!(o.err.contains("/nonexistent/link"), "{}", o.err);
}

// notes/cli.md Design: one process at a time; a second opener fails with exit 8.
#[test]
fn store_dir_init_lock_plan_cli_2() {
    let d = tmp("lock");
    let ds = d.to_str().unwrap();
    let call = |args: &[&str]| {
        let (mut o, mut e) = (Vec::new(), Vec::new());
        let code = osis_cli::main_with(["osis", "--no-lan", "-s", ds].iter().chain(args).copied(), &mut &b""[..], &mut o, &mut e);
        (code, String::from_utf8(o).unwrap(), String::from_utf8(e).unwrap())
    };
    let (c, out, _) = call(&["init"]);
    assert_eq!(c, 0);
    assert!(out.starts_with("me\tosis://"));
    // spec/requirements.md, Deletion (local keys): the store directory, its node and its
    // root key are the owner's only
    #[cfg(unix)]
    for (p, m) in [(d.clone(), 0o700), (d.join("db.redb"), 0o600), (d.join("root"), 0o600)] {
        let mode = std::os::unix::fs::PermissionsExt::mode(&std::fs::metadata(&p).unwrap().permissions());
        assert_eq!(mode & 0o777, m, "{}", p.display());
    }
    assert_eq!(call(&["init"]).0, 8, "refuses a non-empty store");
    let (c, t, _) = call(&["create", "a:b.0", "1"]);
    assert_eq!(c, 0);
    assert_eq!(call(&["get", t.trim(), "a:b.0"]).1, "1\n");
    let held = osis::internals::open(osis::internals::Opening::dir(&d)).unwrap();
    let (c, _, err) = call(&["whoami"]);
    assert_eq!(c, 8, "{err}");
    assert!(err.contains("store in use"), "{err}");
    drop(held);
    assert_eq!(call(&["whoami"]).0, 0);
    let _ = std::fs::remove_dir_all(&d);
}

// notes/cli.md Design (daemon), notes/client-port.md §2: beside a node serving the store's
// socket, commands run there as its main actor: chat read and watch (listings and a commit
// listener), card show, profile and import (a row that waits), sync (a wait timing out), diag.
#[test]
fn commands_run_through_the_daemon_plan_cli() {
    let d = tmp("daemon");
    let ds = d.to_str().unwrap();
    let call = |args: &[&str]| {
        let (mut o, mut e) = (Vec::new(), Vec::new());
        let code = osis_cli::main_with(["osis", "--no-lan", "-s", ds].iter().chain(args).copied(), &mut &b""[..], &mut o, &mut e);
        (code, String::from_utf8(o).unwrap(), String::from_utf8(e).unwrap())
    };
    let ok = |args: &[&str]| {
        let (c, out, err) = call(args);
        assert_eq!(c, 0, "{args:?}: {err}");
        out
    };
    ok(&["init"]);
    let c = ok(&["chat", "create", "--name", "room"]).trim().to_string();
    let one = ok(&["chat", "post", &c, "one"]).trim().to_string();
    let mut o = osis::internals::Opening::dir(&d);
    o.runtime = osis::Runtime::Own;
    o.app.internals.no_listen = true;
    let held = osis::internals::open(o).unwrap();
    held.listen_socket().unwrap();
    let read = ok(&["chat", "read", &c]);
    assert!(read.contains(&format!("{one} ")) && read.contains(": one"), "{read}");
    let cursor = read.lines().last().unwrap().strip_prefix("cursor ").unwrap().to_string();
    let two = ok(&["chat", "post", &c, "two"]).trim().to_string();
    let after = ok(&["chat", "read", &c, "--after", &cursor]);
    assert!(after.contains(&format!("{two} ")) && !after.contains(": one"), "{after}");
    let watched = ok(&["chat", "watch", &c, "--after", &cursor, "--count", "1", "--timeout", "60s"]);
    assert!(watched.contains(": two"), "{watched}");
    let card = ok(&["card", "show"]);
    assert_eq!(card.trim(), held.contact_card().unwrap().to_string());
    assert_eq!(ok(&["card", "profile"]).trim(), held.profile().unwrap().to_uri());
    assert_eq!(ok(&["card", "import", card.trim(), "--timeout", "60s"]).trim(), held.me().to_uri());
    // a one-node account: nothing it holds is held by another node (spec/sync-status.md §3)
    ok(&["sync", "--timeout", "60s"]);
    ok(&["diag"]);
    drop(held);
    let _ = std::fs::remove_dir_all(&d);
}

// notes/cli.md JSON mapping: --json output carries tids under their API names.
#[test]
fn json_output_plan_cli_5() {
    let s = S::mem();
    let o = s.ok(&["--json", "create", "a:b.0", "1.5"]);
    assert!(o.out.starts_with("{\"commit\":\"") && o.out.contains("\"tid\":\"osis://"), "{}", o.out);
    let t = o.out.split("\"tid\":\"").nth(1).unwrap().split('"').next().unwrap().to_string();
    assert_eq!(s.ok(&["--json", "get", &t, "a:b.0"]).line(), "1.5");
    let w = s.ok(&["--json", "whoami"]).out;
    assert!(w.contains("\"me\":\"osis://") && w.contains("\"node\":\"osis://"), "{w}");
    let e = s.call(&["--json", "get", &t, "a:b.0", ".x"], "");
    assert_eq!(e.code, 2);
    assert!(e.err.contains("\"kind\":\"Usage\""), "{}", e.err);
}

// CLI write: one Write, one commit; a failing line commits nothing.
#[test]
fn write_script_atomic_plan_cli_4() {
    let s = S::mem();
    let script = "# a note with a tag\ncreate --as n note:title.0 \"a b\"\nset $n note:tags.0 #{\"x\"}\nset $n note:m.0 [\"k\"] [weak($n), weak(me)]\n";
    let o = s.call(&["write"], script);
    assert_eq!(o.code, 0, "{}", o.err);
    let mut lines = o.out.lines();
    let commit = lines.next().unwrap();
    assert_eq!(commit.len(), 64);
    let n = lines.next().unwrap().strip_prefix("n\t").unwrap().to_string();
    assert_eq!(s.ok(&["get", &n, "note:title.0"]).line(), "\"a b\"");
    let me = s.ok(&["--json", "whoami"]).out.split("\"me\":\"").nth(1).unwrap().split('"').next().unwrap().to_string();
    assert_eq!(s.ok(&["get", &n, "note:m.0", "[\"k\"]"]).line(), format!("[weak({n}), weak({me})]"));
    // the third line fails: nothing of the script is committed
    let bad = format!("create --as x a:b.0 1\nset {n} a:c.0 2\nset osis://AAAAAAAAAAAAAAAAAAAA a:b.0 1\n");
    let o = s.call(&["write"], &bad);
    assert_eq!(o.code, 3, "{}", o.err);
    assert_eq!(s.code(&["get", &n, "a:c.0"]), 3);
    // a script parse error is usage, reported once
    let o = s.call(&["write"], "frobnicate x\n");
    assert_eq!(o.code, 2);
    assert!(o.err.starts_with("error: line 1: ") && o.err.matches("error:").count() == 1, "{}", o.err);
}

// notes/cli.md Paths: `[n]` on an untyped position. Reads index a saved list; writes never turn
// an index into a map key: a saved untyped list or an aspect written earlier in the same commit
// (whose pending state is invisible) is an error, and nothing is committed.
#[test]
fn untyped_index_paths_notes_cli() {
    let s = S::mem();
    let t = s.ok(&["create", "x:l.0", "[10, 20]", "x:m.0", "{1: \"a\"}"]).line().to_string();
    assert_eq!(s.ok(&["get", &t, "x:l.0", "[1]"]).line(), "20");
    let o = s.call(&["set", &t, "x:l.0", "[0]", "5"], "");
    assert_eq!(o.code, 2, "{}", o.err);
    assert!(o.err.contains("untyped list"), "{}", o.err);
    assert_eq!(s.code(&["rm", &t, "x:l.0", "[0]"]), 2);
    assert_eq!(s.ok(&["get", &t, "x:l.0"]).line(), "[10, 20]");
    // a map key on a saved untyped map is fine
    s.ok(&["set", &t, "x:m.0", "[1]", "\"b\""]);
    assert_eq!(s.ok(&["get", &t, "x:m.0"]).line(), "{1: \"b\"}");
    // in a script, an aspect written by an earlier line cannot be resolved against saved state
    let before = s.ok(&["writes", "--thing", &t]).out;
    let o = s.call(&["write"], &format!("set {t} x:m.0 {{1: \"c\"}}\nset {t} x:m.0 [1] \"d\"\n"));
    assert_eq!(o.code, 2, "{}", o.err);
    assert!(o.err.contains("line 2") && o.err.contains("earlier in this script"), "{}", o.err);
    let o = s.call(&["write"], "create --as a x:l.0 [1, 2]\nset $a x:l.0 [0] 5\n");
    assert_eq!(o.code, 2, "{}", o.err);
    assert_eq!(s.ok(&["writes", "--thing", &t]).out, before);
}

// notes/cli.md Design `--timeout` parses (`0` is no timeout: `deadline_never_overflows_plan_cli_2`); a wait past it exits 6.
#[test]
fn timeout_zero_plan_cli_2() {
    let s = S::mem();
    assert_eq!(s.code(&["--timeout", "5x", "wait"]), 2);
    assert_eq!(s.code(&["diag", "--since", "0"]), 2, "--since is gone");
    // a wait past its `--timeout`: a thing never known here is never synced here
    let never = S::mem().thing();
    let o = s.call(&["--timeout", "1ms", "sync", "--thing", &never], "");
    assert_eq!(o.code, 6, "{}", o.err);
}

/// The commit id in a line `writes` or `fired` prints (its place `TS/ID` first).
fn id_of(line: &str) -> &str {
    line.split(' ').next().unwrap().split('/').nth(1).unwrap()
}

// CLI Commits and undo: a listing's filters, undo, redo, revert.
#[test]
fn commits_undo_redo_plan_cli_4() {
    // an undo writes back a replaced value only from kept history (spec/commits.md §7): the
    // thing's setting keeps it
    let d = tmp("undo");
    std::fs::create_dir_all(&d).unwrap();
    let f = d.join("kept.osis");
    std::fs::write(&f, "revision 1;\naspect a:x.0: int;\n").unwrap();
    let mut s = S::mem();
    s.pre = vec!["--schema".into(), f.to_str().unwrap().into()];
    let t = s.kept_thing();
    s.ok(&["set", &t, "a:x.0", "1"]);
    s.ok(&["set", &t, "a:x.0", "2"]);
    let h = s.ok(&["writes", "--thing", &t]).out;
    // a dependent thing: its creation and the two writes
    assert_eq!(h.lines().count(), 3, "{h}");
    assert_eq!(h.lines().filter(|l| l.contains(" content in-effect ")).count(), 3, "{h}");
    assert_eq!(s.ok(&["writes", "--thing", &t, "--next", "redo"]).out, "");
    let next = s.ok(&["writes", "--thing", &t, "--next", "undo"]).out;
    assert_eq!(next.lines().count(), 1, "{next}");
    s.ok(&["undo", "--thing", &t]);
    assert_eq!(s.ok(&["get", &t, "a:x.0"]).line(), "1");
    let undone = s.ok(&["writes", "--thing", &t, "--in-effect", "false"]).out;
    let undone = id_of(&undone);
    assert_eq!(id_of(&next), undone, "undo reverted what --next undo listed");
    assert_eq!(s.code(&["writes", "--next", "undo"]), 2, "--next needs a scope");
    assert_eq!(s.code(&["writes", "--thing", &t, "--next", "nope"]), 2);
    let rev = s.ok(&["writes", "--thing", &t, "--reverts", undone]).out;
    assert_eq!(rev.lines().count(), 1, "{rev}");
    assert!(rev.contains(" revert in-effect reverts="), "{rev}");
    s.ok(&["redo", "--aspect", &t, "a:x.0"]);
    assert_eq!(s.ok(&["get", &t, "a:x.0"]).line(), "2");
    assert_eq!(s.ok(&["writes", "--thing", &t, "--kind", "revert"]).out.lines().count(), 2);
    let newest = s.ok(&["writes", "--thing", &t, "--max", "1"]).out;
    let pos = newest.split(' ').next().unwrap();
    assert_eq!(s.ok(&["writes", "--thing", &t, "--before", pos]).out.lines().count(), 4);
    s.ok(&["revert", id_of(&newest)]);
    assert_eq!(s.ok(&["get", &t, "a:x.0"]).line(), "1");
    assert_eq!(s.code(&["writes", "--thing", &t, "--kind", "nope"]), 2);
    s.ok(&["set", &t, "a:x.0", "3"]);
    assert_eq!(s.code(&["redo", "--thing", &t]), 3, "nothing to redo after a new change");
    // without a setting no write is undone, a first set included
    let t = s.thing();
    s.ok(&["set", &t, "a:x.0", "1"]);
    assert_eq!(s.code(&["undo", "--aspect", &t, "a:x.0"]), 1, "NotUndoable");
    s.ok(&["set", &t, "a:x.0", "2"]);
    assert_eq!(s.code(&["undo", "--aspect", &t, "a:x.0"]), 1, "NotUndoable");
    assert_eq!(s.ok(&["get", &t, "a:x.0"]).line(), "2");
}


// CLI Things and aspects (`--stream`, `--len`), notes/api.md Large values: a value
// written from stdin streams back raw; its length reads without materializing.
#[test]
fn stream_and_len_plan_cli_4() {
    let s = S::mem();
    let t = s.thing();
    let big = "x".repeat(300_000);
    assert_eq!(s.call(&["set", &t, "a:doc.0", "--stream"], &big).code, 0);
    assert_eq!(s.ok(&["get", &t, "a:doc.0", "--len"]).line(), "300000");
    assert_eq!(s.ok(&["--json", "get", &t, "a:doc.0", "--len"]).line(), "{\"len\":300000}");
    let o = s.ok(&["get", &t, "a:doc.0", "--stream"]);
    assert!(o.out.as_bytes() == big.as_bytes(), "untyped: stored as a blob, streamed raw");
    assert_eq!(s.code(&["get", &t, "a:none.0", "--len"]), 3);
}

// notes/api.md Large values: `[0]` on an untyped aspect needs its value to tell list from map:
// a value past the limit fails `TooLarge`, and never reads as absent.
#[test]
fn an_untyped_index_past_the_limit_says_so() {
    let s = S::mem();
    let t = s.ok(&["create", "t:l.0", "[\"a long enough string\"]"]).line().to_string();
    assert_eq!(s.ok(&["get", &t, "t:l.0", "[0]"]).line(), "\"a long enough string\"");
    assert_eq!(s.code(&["--limit", "4", "get", &t, "t:l.0", "[0]"]), 5);
}

// CLI Sharing and roles, Sync, Identity and nodes: the local half of the
// sharing commands on one store (nobody to dial): links, cards, nodes, grants by error
// category, status. The delivering ones (notes/cli.md) wait on nothing on a node alone.
#[test]
fn sharing_commands_local_plan_cli_4() {
    let s = S::mem();
    // under the account, so `me` reads it as its mint admin
    let g = s.ok(&["create", "--admin", "me", "t:made.0", "true"]).line().to_string();
    // spec/sync-inbox.md §6: `make_link` works on every node; the link names this node
    let link = s.ok(&["link", "make", &g, "write", "--single-use"]).line().to_string();
    assert!(link.starts_with("osis://link/"), "{link}");
    assert!(s.ok(&["--json", "link", "ls", &g]).line().contains("\"single_use\":true"));
    assert!(s.ok(&["card", "show"]).line().starts_with("osis://link/"));
    assert_eq!(s.ok(&["node", "ls"]).out.lines().count(), 1);
    let other = S::mem();
    let stranger = other.ok(&["whoami"]).out.lines().next().unwrap().split('\t').nth(1).unwrap().to_string();
    assert_eq!(s.code(&["grant", &g, &stranger, "read"]), 3, "keys unknown: import a card first");
    assert_eq!(s.code(&["node", "rm", &stranger]), 0, "no node of this account: nothing to do");
    assert_eq!(s.code(&["grant", &g, "me", "superuser"]), 2);
    // `--reads` (`osis::Reads`): from-now or all; from-now on a holder reading what came before
    // is Invalid; all, or none given, keeps the grant reading everything
    assert_eq!(s.code(&["grant", &g, "me", "admin", "--reads", "sometimes"]), 2);
    assert_eq!(s.code(&["grant", &g, "me", "admin", "--reads", "from-now"]), 7);
    assert_eq!(s.code(&["grant", &g, "me", "admin", "--reads", "all"]), 0);
    assert!(!s.ok(&["grants", &g]).out.contains("from-now"));
    let st = s.ok(&["--json", "status"]).line().to_string();
    assert!(st.starts_with("{\"units\":[") && st.ends_with("\"connected\":0}"), "{st}");
    assert_eq!(s.ok(&["status"]).out.lines().next(), Some("connected 0"));
    // CLI `source T`: shows where T's sync unit's calls go
    assert_eq!(s.ok(&["source", &g]).out, "local\n");
    assert_eq!(s.ok(&["--json", "source", &g]).line(), "{\"source\":\"local\"}");
}

// CLI `chat relay` (issues of notes/dogfood.md: a relay of another account) grants as `grant`
// does, so an account whose keys are not here is exit 3.
#[test]
fn relay_command() {
    let s = S::mem();
    let c = s.ok(&["chat", "create"]).line().to_string();
    let other = S::mem();
    let stranger = other.ok(&["whoami"]).out.lines().next().unwrap().split('\t').nth(1).unwrap().to_string();
    assert_eq!(s.code(&["chat", "relay", &c, &stranger]), 3, "keys unknown: import a card first");
}

// CLI `backlinks T`: the things whose values reference T, one `tid aspect` line each.
#[test]
fn backlinks_lists_the_referrers() {
    let s = S::mem();
    let (a, t) = (s.thing(), s.thing());
    let before = s.ok(&["backlinks", &t]).out;
    s.ok(&["set", &a, "note:link.0", &format!("weak({t})")]);
    let out = s.ok(&["backlinks", &t]).out;
    assert!(out.lines().count() == before.lines().count() + 1 && out.contains(&format!("{a} note:link.0\n")), "{out}");
    assert!(s.ok(&["--json", "backlinks", &t]).line().contains(&format!("{{\"tid\":\"{a}\",\"ak\":\"note:link.0\"}}")));
}

// CLI: commands over API pieces not built yet (queries) parse and report it; sharing commands
// without a runtime or peers fail as the API does.
#[test]
fn unbuilt_commands_say_so_plan_cli_4() {
    let s = S::mem();
    assert_eq!(s.ok(&["node", "ls"]).out.lines().count(), 1, "this node");
    assert_eq!(s.code(&["link", "redeem", "x"]), 7, "malformed link");
}

// CLI Watching: initial value first, printed but not counted by
// --count (no other node writes here, so --count 1 meets the timeout); roster --watch alike.
#[test]
fn watch_initial_not_counted_plan_cli_4() {
    let s = S::mem();
    let t = s.ok(&["create", "a:b.0", "7"]).line().to_string();
    let o = s.call(&["--timeout", "50ms", "watch", &t, "a:b.0", "--count", "1"], "");
    assert_eq!((o.code, o.line(), o.err.trim()), (6, "initial - - a:b.0 7", "error: timed out after 0 change(s)"));
    let o = s.call(&["--json", "--timeout", "50ms", "watch", &t, "--count", "1"], "");
    assert_eq!(o.code, 6, "{}", o.err);
    // the whole thing: one initial line per present aspect (`a:b.0`, `created.0`: a dependent thing
    // under the account root), none counted
    assert_eq!(o.out.lines().count(), 2, "{}", o.out);
    assert!(o.out.lines().all(|l| l.contains("\"origin\":\"initial\"")) && o.out.contains("\"value\":7}"), "{}", o.out);
    // a path inside the aspect, as `get` reads it
    s.ok(&["set", &t, "a:m.0", "{\"a\": 1, \"b\": 2}"]);
    let o = s.call(&["--timeout", "50ms", "watch", &t, "a:m.0", "[\"b\"]", "--count", "1"], "");
    assert_eq!((o.code, o.line()), (6, "initial - - a:m.0 2"), "{}", o.err);
    let o = s.call(&["--timeout", "50ms", "grants", "me", "--watch", "--count", "1"], "");
    assert_eq!((o.code, o.out.lines().count(), o.err.trim()), (6, 1, "error: timed out after 0 change(s)"), "{}", o.out);
    assert_eq!(s.ok(&["--json", "retained"]).line(), "[]");
}

const SCHEMA: &str = "revision 1;
type task = struct { title 0: string, done 1: bool, due 2: option<timestamp> };
aspect todo:task.0: task;
aspect todo:list.0: list<task>;
aspect todo:note.0: text;
aspect todo:count.0: counter<int>;
ephemeral signal todo:ping+~0: int;
";

// notes/cli.md Design Honest about names: named forms with a registered schema; --raw numbered.
#[test]
fn named_keys_with_schema_plan_cli_1() {
    let d = tmp("schema");
    std::fs::create_dir_all(&d).unwrap();
    let f = d.join("todo.osis");
    std::fs::write(&f, SCHEMA).unwrap();
    let store = d.join("store");
    let st = store.to_str().unwrap();
    let call = |args: &[&str], stdin: &str| {
        let (mut o, mut e) = (Vec::new(), Vec::new());
        let code = osis_cli::main_with(["osis", "--no-lan", "-s", st].iter().chain(args).copied(), &mut stdin.as_bytes(), &mut o, &mut e);
        (code, String::from_utf8(o).unwrap(), String::from_utf8(e).unwrap())
    };
    assert_eq!(call(&["init"], "").0, 0);
    assert_eq!(call(&["schema", "add", f.to_str().unwrap()], "").0, 0);
    assert!(call(&["schema", "ls"], "").1.contains("todo.osis"));
    let (c, t, e) = call(&["create", "todo:task.0", "{title: \"buy\", done: false, due: #some(2026-01-02T03:04:05Z)}"], "");
    assert_eq!(c, 0, "{e}");
    let t = t.trim();
    assert_eq!(call(&["get", t, "todo:task.0"], "").1, "{title: \"buy\", done: false, due: #some(2026-01-02T03:04:05Z)}\n");
    assert_eq!(call(&["--raw", "get", t, "todo:task.0"], "").1, "{0: \"buy\", 1: false, 2: #1(1767323045000)}\n");
    assert_eq!(call(&["get", t, "todo:task.0", ".due#some"], "").1, "2026-01-02T03:04:05Z\n");
    assert_eq!(call(&["--json", "get", t, "todo:task.0"], "").1, "{\"title\":\"buy\",\"done\":false,\"due\":{\"$case\":\"some\",\"$payload\":1767323045000}}\n");
    // a write is validated against the schema (exit 5) and paths use names
    assert_eq!(call(&["set", t, "todo:task.0", "{title: 1}"], "").0, 5);
    assert_eq!(call(&["set", t, "todo:task.0", ".done", "true"], "").0, 0);
    assert_eq!(call(&["set", t, "todo:task.0", ".due", "#none"], "").0, 0);
    // the thing's retain default is one field of its setting
    let (c, _, e) = call(&["set", t, "retention^.0", "{rules: {}, retain: true, default: #none, history_holds_targets: false}"], "");
    assert_eq!(c, 0, "{e}");
    assert_eq!(call(&["get", t, "retention^.0", ".retain"], "").1, "true\n");
    assert_eq!(call(&["get", t, "todo:task.0"], "").1, "{title: \"buy\", done: true, due: #none}\n");
    // edit: only what changed since --base
    let base = "{title: \"buy\", done: true, due: #none}";
    let (c, _, e) = call(&["edit", t, "todo:task.0", "--base", base], "{title: \"buy milk\", done: true, due: #none}");
    assert_eq!(c, 0, "{e}");
    assert!(call(&["get", t, "todo:task.0"], "").1.contains("\"buy milk\""));
    // typed list ops
    assert_eq!(call(&["set", t, "todo:list.0", "[]"], "").0, 0);
    let (c, _, e) = call(&["op", t, "todo:list.0", "", "splice", "0..0", "{title: \"a\", done: false, due: #none}", "{title: \"b\", done: false, due: #none}"], "");
    assert_eq!(c, 0, "{e}");
    assert_eq!(call(&["get", t, "todo:list.0", "[1].title"], "").1, "\"b\"\n");
    assert_eq!(call(&["op", t, "todo:list.0", "", "splice", "0..1"], "").0, 0);
    assert_eq!(call(&["get", t, "todo:list.0", "[0].title"], "").1, "\"b\"\n");
    // a text position: quoted or bare; no text deletes
    assert_eq!(call(&["set", t, "todo:note.0", "\"hello world\""], "").0, 0);
    assert_eq!(call(&["op", t, "todo:note.0", "", "splice", "0..5", "\"goodbye\""], "").0, 0);
    assert_eq!(call(&["get", t, "todo:note.0"], "").1, "\"goodbye world\"\n");
    assert_eq!(call(&["op", t, "todo:note.0", "", "splice", "0..0", "oh"], "").0, 0);
    assert_eq!(call(&["get", t, "todo:note.0"], "").1, "\"ohgoodbye world\"\n");
    assert_eq!(call(&["op", t, "todo:note.0", "", "splice", "0..2"], "").0, 0);
    assert_eq!(call(&["get", t, "todo:note.0"], "").1, "\"goodbye world\"\n");
    assert_eq!(call(&["op", t, "todo:note.0", "", "splice", "0..0", "a", "b"], "").0, 2, "one text");
    assert_eq!(call(&["op", t, "todo:count.0", "", "contribute", "5"], "").0, 0);
    assert_eq!(call(&["op", t, "todo:count.0", "", "contribute", "-2"], "").0, 0);
    assert_eq!(call(&["get", t, "todo:count.0"], "").1, "3\n");
    // a signal aspect fires and holds nothing; it is not set, nor a value aspect fired
    assert_eq!(call(&["fire", t, "todo:ping+~0", "1"], "").0, 0);
    assert!(call(&["set", t, "todo:ping+~0", "1"], "").2.contains("fire"));
    assert!(call(&["fire", t, "todo:count.0", "1"], "").2.contains("set"));
    assert_eq!(call(&["get", t, "todo:ping+~0"], "").0, 3, "absent");
    assert!(!call(&["aspects", t], "").1.contains("todo:ping+~0"));
    assert_eq!(call(&["schema", "check", f.to_str().unwrap()], "").1, "ok revision 1\n");
    // a schema that does not parse: exit 7
    let bad = d.join("bad.osis");
    std::fs::write(&bad, "schema nonsense").unwrap();
    assert_eq!(call(&["--schema", bad.to_str().unwrap(), "get", t, "todo:task.0"], "").0, 7);
    assert_eq!(call(&["schema", "add", bad.to_str().unwrap()], "").0, 7);
    // with a schema, typed index writes work (untyped ones are refused)
    assert_eq!(call(&["set", t, "todo:list.0", "[0].done", "true"], "").0, 0);
    assert_eq!(call(&["get", t, "todo:list.0", "[0].done"], "").1, "true\n");
    assert_eq!(call(&["schema", "rm", f.to_str().unwrap()], "").0, 0);
    assert_eq!(call(&["get", t, "todo:task.0"], "").1, "{0: \"buy milk\", 1: true, 2: #0}\n");
    let _ = std::fs::remove_dir_all(&d);
}

// CLI Inspection (format not stable): runs over the engine.
#[test]
fn inspect_and_diag_plan_cli_4() {
    let s = S::mem();
    let t = s.ok(&["create", "a:b.0", "1"]).line().to_string();
    let o = s.ok(&["inspect", "thing", &t]).out;
    assert!(o.contains("aspect a:b.0 commits=1"), "{o}");
    // notes/api.md Reads: `show` names the creating commit; `now` the clock
    let shown = s.ok(&["show", &t]).out;
    assert!(shown.contains("created\t"), "{shown}");
    assert!(!s.ok(&["now"]).out.trim().is_empty());
    assert!(s.ok(&["inspect", "actor", "me"]).out.starts_with("actor osis://"));
    let id = id_of(&s.ok(&["writes", "--thing", &t]).out).to_string();
    assert!(s.ok(&["inspect", "commit", &id]).out.contains("Header"));
    s.ok(&["diag"]);
}

// CLI `chat`, notes/chat.md: a local chat through the commands: post and read, the JSON, a cursor, edit (the id stays; kept history in `earlier`), delete, editing off, bad arguments
#[test]
fn chat_commands_plan_cli() {
    let s = S::mem();
    let c = s.ok(&["chat", "create", "--name", "room"]).line().to_string();
    // an empty chat's cursor is null; given back empty, everything is after it
    assert!(s.ok(&["--json", "chat", "read", &c]).out.contains("\"cursor\":null"));
    let one = s.ok(&["chat", "post", &c, "--from", "ann", "--subject", "head", "body"]).line().to_string();
    assert!(s.ok(&["chat", "read", &c, "--after", ""]).out.contains(&format!("{one} ")));
    assert!(s.ok(&["chat", "watch", &c, "--after", "", "--count", "1", "--timeout", "60s"]).out.contains(&format!("{one} ")));
    let read = s.ok(&["--json", "chat", "read", &c]).out;
    assert!(read.contains(&format!("\"id\":\"{one}\"")) && read.contains("\"name\":\"ann\"") && read.contains("head\\n\\nbody") && read.contains("\"reply_to\":null") && read.contains("\"edited\":false"), "{read}");
    let last = read.lines().last().unwrap();
    let cursor = &last[last.find("\"cursor\":\"").unwrap() + 10..];
    let cursor = &cursor[..cursor.find('"').unwrap()];
    let two = s.ok(&["chat", "post", &c, "--reply-to", &one, "two"]).line().to_string();
    let after = s.ok(&["chat", "read", &c, "--after", cursor]).out;
    assert!(after.contains(&format!("(to {one}): two")) && !after.contains("body"), "{after}");
    assert_eq!(s.ok(&["chat", "read", &c, "--max", "1"]).out.lines().count(), 2, "a message and the cursor");
    assert!(s.ok(&["chat", "read", &c, "--before", &two]).out.contains(": head"));
    assert_eq!(s.ok(&["chat", "edit", &c, &two, "two!"]).line(), two, "the message keeps its id");
    let read = s.ok(&["chat", "read", &c]).out;
    assert!(read.contains(&format!("{two} ")) && read.contains(&format!("(to {one}) (edited): two!")), "{read}");
    assert!(s.ok(&["--json", "chat", "read", &c]).out.contains("\"earlier\":[]"), "edits purge the old text");
    // an edit arrives after the cursor as its message again
    let cursor2 = s.ok(&["chat", "read", &c]).out.lines().last().unwrap().strip_prefix("cursor ").unwrap().to_string();
    s.ok(&["chat", "edit", &c, &two, "two!!"]);
    let again = s.ok(&["chat", "read", &c, "--after", &cursor2]).out;
    assert!(again.contains(&format!("{two} ")) && again.contains("two!!") && again.lines().count() == 2, "{again}");
    s.ok(&["chat", "delete", &c, &one]);
    let who = s.ok(&["whoami"]).out;
    let me = who.lines().find_map(|l| l.strip_prefix("me\t")).unwrap().to_string();
    assert!(s.ok(&["chat", "read", &c]).out.contains(&format!("<deleted by {me}>")));
    assert!(s.ok(&["--json", "chat", "read", &c]).out.contains(&format!("\"deleted_by\":\"{me}\"")));
    assert_ne!(s.code(&["chat", "resend", &c, &two]), 0, "delivered: nothing to send again");
    assert!(s.ok(&["chat", "participants", &c]).out.contains("Admin"));
    assert_ne!(s.code(&["chat", "create", "--purge", "x"]), 0);
    assert_eq!(s.code(&["chat", "edit", &c, "not/an/id", "x"]), 2, "an unparsable id is a usage error");
    // keep: earlier versions in `earlier`, newest first; off: refused
    let k = s.ok(&["chat", "create", "--edit", "keep"]).line().to_string();
    let m = s.ok(&["chat", "post", &k, "one"]).line().to_string();
    s.ok(&["chat", "edit", &k, &m, "two"]);
    s.ok(&["chat", "edit", &k, &m, "three"]);
    let read = s.ok(&["--json", "chat", "read", &k]).out;
    assert!(read.contains("\"text\":\"three\"") && read.contains("\"earlier\":[\"two\",\"one\"]"), "{read}");
    let off = s.ok(&["chat", "create", "--edit", "off"]).line().to_string();
    let m = s.ok(&["chat", "post", &off, "fixed"]).line().to_string();
    assert_ne!(s.code(&["chat", "edit", &off, &m, "x"]), 0, "editing off");
    assert!(s.ok(&["chat", "read", &off]).out.contains(": fixed"));
}

// CLI `clients`, notes/client-port.md §3: `add` prints the actor and the secret once (only the hash stays), `ls` lists them, `rotate` prints a new secret, `rm` removes (again: exit 3); an until not in the future is refused; `--node` needs `--client-secret` and a readable secret file
#[test]
fn clients_commands_plan_cli() {
    let s = S::mem();
    let add = s.ok(&["clients", "add", "--until", "1900000000000"]);
    let (actor, secret) = add.line().split_once(' ').unwrap();
    assert_eq!(secret.len(), 64);
    assert_eq!(s.ok(&["clients", "ls"]).out, format!("{actor} 1900000000000\n"));
    assert!(s.ok(&["--json", "clients", "ls"]).out.contains("1900000000000"));
    let rotated = s.ok(&["clients", "rotate", actor]).line().to_string();
    assert_eq!(rotated.len(), 64);
    assert_ne!(rotated, secret);
    assert_ne!(s.code(&["clients", "add", "--until", "1"]), 0);
    s.ok(&["clients", "rm", actor]);
    assert_eq!(s.ok(&["clients", "ls"]).out, "");
    assert_eq!(s.code(&["clients", "rm", actor]), 3);
    assert_eq!(s.code(&["clients", "rotate", actor]), 7);
    // thin arguments
    assert_eq!(s.code(&["--node", "quic://127.0.0.1:1#00", "whoami"]), 2);
    assert_eq!(s.code(&["--client-secret", "/nonexistent", "whoami"]), 2);
    let d = tmp("thin");
    std::fs::create_dir_all(&d).unwrap();
    let bad = d.join("bad");
    std::fs::write(&bad, "xyz").unwrap();
    let k = "00".repeat(32);
    let addr = format!("quic://127.0.0.1:1#{k}");
    assert_eq!(s.code(&["--node", &addr, "--client-secret", bad.to_str().unwrap(), "whoami"]), 2);
    assert_eq!(s.code(&["--node", &addr, "--client-secret", "/nonexistent", "whoami"]), 8);
    assert_eq!(s.code(&["--node", &addr, "--client-secret", bad.to_str().unwrap(), "inspect", "actor", "me"]), 2);
}


// notes/cli.md Design (daemon), notes/client-port.md §5: a socket directory another user made first (here: one of the wrong mode) does not stop `serve`: it warns and serves without the client socket; with a good one, its first line is the socket's path (the one test here that runs the binary)
#[test]
fn serve_survives_a_bad_socket_dir() {
    use std::io::BufRead;
    use std::os::unix::fs::PermissionsExt;
    let d = tmp("badsockdir");
    let ds = d.to_str().unwrap();
    assert_eq!(osis_cli::main_with(["osis", "--no-lan", "-s", ds, "init"], &mut &b""[..], &mut Vec::new(), &mut Vec::new()), 0);
    let xdg = d.with_extension("xdg");
    std::fs::create_dir_all(xdg.join("osis")).unwrap();
    std::fs::set_permissions(xdg.join("osis"), std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut c = std::process::Command::new(env!("CARGO_BIN_EXE_osis")).env("XDG_RUNTIME_DIR", &xdg).args(["--no-lan", "-s", ds, "serve"]).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::piped()).spawn().unwrap();
    // read on a thread: a serve that never warns runs on and keeps stderr open
    let err = std::io::BufReader::new(c.stderr.take().unwrap());
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || tx.send(err.lines().map_while(Result::ok).any(|l| l.contains("serving without a client socket"))));
    let warned = rx.recv_timeout(std::time::Duration::from_secs(60)).unwrap_or(false);
    let running = c.try_wait().unwrap().is_none();
    let _ = c.kill();
    let _ = c.wait();
    assert!(warned && running);
    // a socket it may use: its line, once it takes clients, is the socket's path
    std::fs::set_permissions(xdg.join("osis"), std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut c = std::process::Command::new(env!("CARGO_BIN_EXE_osis")).env("XDG_RUNTIME_DIR", &xdg).args(["--no-lan", "-s", ds, "serve"]).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::null()).spawn().unwrap();
    let out = std::io::BufReader::new(c.stdout.take().unwrap());
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || tx.send(out.lines().map_while(Result::ok).next()));
    let line = rx.recv_timeout(std::time::Duration::from_secs(60)).ok().flatten();
    let _ = c.kill();
    let _ = c.wait();
    let line = line.expect("a socket line");
    assert!(line.starts_with(xdg.join("osis").to_str().unwrap()) && line.ends_with(".sock"), "{line}");
    let _ = std::fs::remove_dir_all(&d);
    let _ = std::fs::remove_dir_all(&xdg);
}

// CLI `writes`, `fired`, `purge`: pages by place, each part in its line, a tombstone, purge by
// commit and by author; a signal's fires; `--follow`; a thing destroyed.
#[test]
fn writes_and_purge_commands_plan_cli() {
    let s = S::mem();
    let t = s.kept_thing();
    s.ok(&["set", &t, "note:m.0", "\"one\""]);
    s.ok(&["set", &t, "note:m.0", "\"two\""]);
    let lines = s.ok(&["writes", &t, "note:m.0"]).out;
    let rows: Vec<&str> = lines.lines().collect();
    assert_eq!(rows.len(), 2, "{lines}");
    assert!(rows[0].contains("two") && rows[1].contains("one"), "{lines}");
    let pos = rows[0].split(' ').next().unwrap();
    assert!(rows[0].contains(&format!("{t}note:m.0 valid")), "{lines}");
    let older = s.ok(&["writes", &t, "note:m.0", "--before", pos]).out;
    assert_eq!(older, format!("{}\n", rows[1]));
    assert!(s.ok(&["writes", &t, "note:m.0", "--oldest", "--max", "1"]).out.contains("one"));
    let j = s.ok(&["--json", "writes", &t, "note:m.0", "--max", "1"]).out;
    assert!(j.contains("\"more\":true") || j.contains("\"more\": true"), "{j}");
    let one = rows[1].split(' ').next().unwrap().split('/').nth(1).unwrap();
    s.ok(&["purge", &t, "note:m.0", "--commit", one]);
    let lines = s.ok(&["writes", &t, "note:m.0"]).out;
    assert!(lines.lines().any(|l| l.contains(one) && l.contains("purged=")), "{lines}");
    let me = rows[0].split(' ').nth(2).unwrap();
    s.ok(&["purge", &t, "note:m.0", "--author", me]);
    // what was written, every line a tombstone (a writer may add a snapshot of the aspect)
    let lines = s.ok(&["writes", &t, "note:m.0", "--kind", "content"]).out;
    assert!(lines.lines().count() == 2 && lines.lines().all(|l| l.contains("purged=")), "{lines}");
    assert_eq!(s.code(&["writes", &t, "note:m.0", "--before", "nonsense"]), 2);
    // a signal: listed by `fired`, not by `writes`; `watch` points there
    s.ok(&["fire", &t, "note:ping~0", "1"]);
    let fired = s.ok(&["fired", &t, "note:ping~0"]).out;
    assert_eq!(fired.lines().count(), 1);
    assert_eq!(s.ok(&["writes", &t, "note:ping~0"]).out, "");
    // a fire replaced: listed in its place with its newest value, its versions on request
    let f = id_of(&fired).to_string();
    s.ok(&["fire", "--replaces", &f, &t, "note:ping~0", "2"]);
    let fired = s.ok(&["fired", &t, "note:ping~0"]).out;
    assert!(fired.lines().count() == 1 && id_of(&fired) == f && fired.contains("Int(2)") && fired.contains("edited="), "{fired}");
    let v = s.ok(&["fired", &t, "note:ping~0", "--versions-of", &f, "--oldest"]).out;
    let rows: Vec<&str> = v.lines().collect();
    assert!(rows.len() == 2 && id_of(rows[0]) == f && rows[0].contains("Int(1)") && rows[1].contains("Int(2)") && !v.contains("edited="), "{v}");
    assert_eq!(s.code(&["fire", "--replaces", id_of(rows[1]), &t, "note:ping~0", "3"]), 7, "a replacement is not replaced");
    let w = s.call(&["watch", &t, "note:ping~0"], "");
    assert!(w.code == 2 && w.err.contains("fired"), "{}", w.err);
    // --follow: what comes after it, until --count
    assert_eq!(s.code(&["--timeout", "1s", "writes", &t, "note:m.0", "--follow", "--count", "1"]), 6, "nothing new");
    // with no AK, T is destroyed: nothing of it reads
    assert_eq!(s.code(&["purge", &t, "--commit", one]), 2);
    s.ok(&["purge", &t]);
    assert_eq!(s.code(&["get", &t, "note:m.0"]), 3);
}

// CLI `write` expiry flags, `op`, `--admin` naming who stays
#[test]
fn expiry_admin_and_splice_commands() {
    let s = S::mem();
    let g = s.thing();
    let t = s.thing();
    let two = s.call(&["write"], &format!("set --expires-in 1h {t} a:x.0 1\nset --expires-in 2h {t} a:y.0 1\n"));
    assert!(two.code == 2 && two.err.contains("one expiry"), "{}", two.err);
    assert_eq!(s.call(&["write"], &format!("set --expires-in 1h {t} a:x.0 1\nset {t} a:y.0 1\n")).code, 0, "the flag is the commit's, whichever line gives it");
    assert_eq!(s.call(&["write"], &format!("set {t} a:x.0 1\nset {t} a:cursor+.0 1\n")).code, 7, "durable beside ephemeral");
    // spec/permissions.md §1: `--admin G` makes G the mint admin, which `grants` lists
    let made = s.ok(&["create", "--admin", &g, "t:x.0", "1"]).line().to_string();
    let gs = s.ok(&["grants", &made]).out;
    assert!(gs.lines().any(|l| l.starts_with(&format!("{g} admin "))), "{gs}");
    assert_ne!(s.code(&["create", "--admin", &g[..g.len() - 1], "t:x.0", "1"]), 0, "a malformed admin");
    let schema = s.ok(&["create", "t:made.0", "true"]).line().to_string();
    assert_eq!(s.code(&["op", &schema, "t:made.0", "", "splice"]), 2, "a range");
}

// spec/permissions.md §7, notes/cli.md Delivering commands: with no peer to dial the CLI still
// makes a chat link (a link and a card: `sharing_commands_local_plan_cli_4`); its wait ends at
// once on a node alone, so a store with no peers is not a dead end.
#[test]
fn a_chat_link_on_a_store_with_no_peer() {
    let s = S::mem();
    let c = s.ok(&["chat", "create", "--name", "room"]).line().to_string();
    assert!(s.ok(&["chat", "link", &c]).line().starts_with("osis://link/"));
}

// spec/permissions.md §5.2 External fires, spec/commits.md §5 The setting: `enable` gives an
// external signal an entry of its own in the thing's setting, kept as asked, beside what the
// setting holds; `disable` drops that entry alone; a key that is no external signal is a usage
// error.
#[test]
fn enable_and_disable_an_external_signal_spec_permissions_5_2() {
    let s = S::mem();
    let t = s.kept_thing();
    s.ok(&["enable", &t, "x:ping@~0", "--keep", "1h"]);
    let r = s.ok(&["get", &t, "retention^.0"]).out;
    assert!(r.contains("\"x:ping@~0\": {history: #some(#keep({until: #none, after: #some(1h)}))") && r.contains("default: #some("), "{r}");
    s.ok(&["fire", &t, "x:ping@~0", "1"]);
    s.ok(&["disable", &t, "x:ping@~0"]);
    let r = s.ok(&["get", &t, "retention^.0"]).out;
    assert!(!r.contains("x:ping@~0") && r.contains("default: #some("), "{r}");
    assert_eq!(s.code(&["enable", &t, "x:ping~0"]), 2);
}
