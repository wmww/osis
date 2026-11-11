//! The `osis` binary run in-process (notes/cli.md Tests, default tests; one test spawns `serve`): commands over memory and
//! temp-dir stores, exit codes per error category, `--json`, `write` scripts, named
//! keys with a schema, the command table's coverage of the API. No network, no sleeps.
//! spec: none (client surface: notes/cli.md).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use osis::internals::Internals as _;
use clap::CommandFactory;
use osis::MemStore;
use osis_cli::args::Cli;
use osis_cli::{Io, StoreSel, run};
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
    sel: StoreSel,
    pre: Vec<String>,
}

impl S {
    fn mem() -> S {
        let s = S { sel: StoreSel::Memory(MemStore::new()), pre: Vec::new() };
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
        self.ok(&["create", "--in", "me", "t:made.0", "true"]).line().to_string()
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
    let t = s.ok(&["create", "--in", "me", "note:title.0", "\"hi\"", "note:n.0", "3", "note:neg.0", "-3"]).line().to_string();
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
    assert!(show.contains("note:title.0\t\"hi\"") && show.contains("role\tadmin") && show.contains("created.0\t{admin: osis://"), "{show}");
    s.ok(&["rm", &t, "note:title.0"]);
    assert_eq!(s.code(&["get", &t, "note:title.0"]), 3);
    s.ok(&["delete", &t]);
    assert_eq!(s.code(&["get", &t, "note:n.0"]), 3);
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
    // 1: not built yet (queries)
    let o = s.call(&["--json", "ls", "me"], "");
    assert_eq!(o.code, 1);
    assert!(o.err.starts_with("{\"error\":{\"kind\":\"Cli\""), "{}", o.err);
    assert!(o.err.contains("not built yet"), "{}", o.err);
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

// notes/cli.md JSON mapping: --json output carries tids under their API names.
#[test]
fn json_output_plan_cli_5() {
    let s = S::mem();
    let o = s.ok(&["--json", "create", "--in", "me", "a:b.0", "1.5"]);
    assert!(o.out.starts_with("{\"commit\":\"") && o.out.contains("\"tid\":\"osis://"), "{}", o.out);
    let t = o.out.split("\"tid\":\"").nth(1).unwrap().split('"').next().unwrap().to_string();
    assert_eq!(s.ok(&["--json", "get", &t, "a:b.0"]).line(), "1.5");
    let w = s.ok(&["--json", "whoami"]).out;
    assert!(w.contains("\"me\":\"osis://") && w.contains("\"node\":\"osis://") && w.contains("\"peers\":[]"), "{w}");
    let e = s.call(&["--json", "get", &t, "a:b.0", ".x"], "");
    assert_eq!(e.code, 2);
    assert!(e.err.contains("\"kind\":\"Usage\""), "{}", e.err);
}

// CLI write: one Write, one commit; a failing line commits nothing.
#[test]
fn write_script_atomic_plan_cli_4() {
    let s = S::mem();
    let script = "# a note with a tag\ncreate --in me --as n note:title.0 \"a b\"\nset $n note:tags.0 #{\"x\"}\nset $n note:m.0 [\"k\"] [$n, me]\n";
    let o = s.call(&["write"], script);
    assert_eq!(o.code, 0, "{}", o.err);
    let mut lines = o.out.lines();
    let commit = lines.next().unwrap();
    assert_eq!(commit.len(), 64);
    let n = lines.next().unwrap().strip_prefix("n\t").unwrap().to_string();
    assert_eq!(s.ok(&["get", &n, "note:title.0"]).line(), "\"a b\"");
    let me = s.ok(&["--json", "whoami"]).out.split("\"me\":\"").nth(1).unwrap().split('"').next().unwrap().to_string();
    assert_eq!(s.ok(&["get", &n, "note:m.0", "[\"k\"]"]).line(), format!("[{n}, {me}]"));
    // the third line fails: nothing of the script is committed
    let bad = "create --in me --as x a:b.0 1\nset $x a:c.0 2\nset osis://AAAAAAAAAAAAAAAAAAAA a:b.0 1\n";
    let before = s.ok(&["writes", "--group", "me"]).out;
    let o = s.call(&["write"], bad);
    assert_eq!(o.code, 3, "{}", o.err);
    assert_eq!(s.ok(&["writes", "--group", "me"]).out, before);
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
    let t = s.ok(&["create", "--in", "me", "x:l.0", "[10, 20]", "x:m.0", "{1: \"a\"}"]).line().to_string();
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
    let before = s.ok(&["writes", "--group", "me"]).out;
    let o = s.call(&["write"], &format!("set {t} x:m.0 {{1: \"c\"}}\nset {t} x:m.0 [1] \"d\"\n"));
    assert_eq!(o.code, 2, "{}", o.err);
    assert!(o.err.contains("line 2") && o.err.contains("earlier in this script"), "{}", o.err);
    let o = s.call(&["write"], "create --in me --as a x:l.0 [1, 2]\nset $a x:l.0 [0] 5\n");
    assert_eq!(o.code, 2, "{}", o.err);
    assert_eq!(s.ok(&["writes", "--group", "me"]).out, before);
}

// notes/cli.md Design `--timeout` parses (`0` is no timeout: `deadline_never_overflows_plan_cli_2`).
#[test]
fn timeout_zero_plan_cli_2() {
    let s = S::mem();
    assert_eq!(s.code(&["--timeout", "5x", "wait"]), 2);
    assert_eq!(s.code(&["diag", "--since", "0"]), 2, "--since is gone");
}

/// The commit id in a line `writes` or `fired` prints (its place `TS/ID` first).
fn id_of(line: &str) -> &str {
    line.split(' ').next().unwrap().split('/').nth(1).unwrap()
}

// CLI Commits and undo: a listing's filters, undo, redo, revert.
#[test]
fn commits_undo_redo_plan_cli_4() {
    // an undo writes back a replaced value only from kept history (spec/commits.md §7)
    let d = tmp("undo");
    std::fs::create_dir_all(&d).unwrap();
    let f = d.join("kept.osis");
    std::fs::write(&f, "revision 1;\nkeep_history(1d) aspect a:x.0: int;\n").unwrap();
    let mut s = S::mem();
    s.pre = vec!["--schema".into(), f.to_str().unwrap().into()];
    let t = s.thing();
    s.ok(&["set", &t, "a:x.0", "1"]);
    s.ok(&["set", &t, "a:x.0", "2"]);
    let h = s.ok(&["writes", "--thing", &t]).out;
    assert_eq!(h.lines().count(), 3, "{h}");
    assert!(h.lines().all(|l| l.contains(" content in-effect ")), "{h}");
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
    assert_eq!(s.code(&["undo", "--thing", &t, "--group", "me"]), 2);
    assert_eq!(s.code(&["writes", "--thing", &t, "--kind", "nope"]), 2);
    s.ok(&["set", &t, "a:x.0", "3"]);
    assert_eq!(s.code(&["redo", "--thing", &t]), 3, "nothing to redo after a new change");
    // a set without the schema keeps no history, but what it replaced does: its undo works
    let t = s.thing();
    s.ok(&["set", &t, "a:x.0", "1"]);
    let pre = std::mem::take(&mut s.pre);
    s.ok(&["set", &t, "a:x.0", "2"]);
    s.ok(&["undo", "--aspect", &t, "a:x.0"]);
    s.pre = pre;
    assert_eq!(s.ok(&["get", &t, "a:x.0"]).line(), "1");
}

// CLI Groups and sharing: group add/rm, groups, members, grants, role.
#[test]
fn groups_plan_cli_4() {
    let s = S::mem();
    s.ok(&["create"]);
    s.ok(&["create", "--in", "me"]);
    let g = s.ok(&["create", "t:made.0", "true"]).line().to_string();
    let t = s.thing();
    s.ok(&["group", "add", &g, &t]);
    assert!(s.ok(&["groups", &t]).out.contains(&g));
    s.ok(&["group", "rm", &g, &t]);
    assert!(!s.ok(&["groups", &t]).out.contains(&g));
    s.ok(&["group", "add", "me", &g, "--subgroup"]);
    assert!(s.ok(&["get", "me", "group.0"]).line().contains(&g));
    assert!(s.ok(&["groups", &g]).out.lines().any(|l| l.starts_with("subgroup\t")), "listed as a subgroup of home");
    assert!(s.ok(&["members", "me"]).out.lines().any(|l| l == format!("subgroup\t{g}")));
    s.ok(&["group", "rm", "me", &g, "--subgroup"]);
    assert_eq!(s.ok(&["role", &t]).line(), "admin");
    s.ok(&["grants", "me"]);
    s.ok(&["delete", &t]);
    assert!(s.ok(&["show", &t]).out.contains("state\tempty"), "a deleted thing has no content");
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

// notes/cli.md: `group sync G` names no peers: on a group already synced elsewhere it does nothing, as
// the API's empty list; naming others is `Invalid`.
#[test]
fn group_sync_without_peers_keeps_the_sync() {
    let s = S::mem();
    let (a, b) = (osis::Address::new(&"mem://a".parse().unwrap(), [1; 32]).to_string(), osis::Address::new(&"mem://b".parse().unwrap(), [2; 32]).to_string());
    s.ok(&["peers", "add", &a]);
    let g = s.ok(&["create", "--in", "me", "t:made.0", "true"]).line().to_string();
    // 6: done, and no peer to deliver to in this test
    assert_eq!(s.code(&["--timeout", "1ms", "group", "sync", &g, "--peer", &b]), 6);
    assert_eq!(s.code(&["--timeout", "1ms", "group", "sync", &g]), 6);
    assert_eq!(s.code(&["--timeout", "1ms", "group", "sync", &g, "--peer", &a]), 7);
}

// notes/api.md Materialization bound: `[0]` on an untyped aspect needs its value to tell list from map:
// a value past the limit fails `TooLarge`, and never reads as absent.
#[test]
fn an_untyped_index_past_the_limit_says_so() {
    let s = S::mem();
    let t = s.ok(&["create", "--in", "me", "t:l.0", "[\"a long enough string\"]"]).line().to_string();
    assert_eq!(s.ok(&["get", &t, "t:l.0", "[0]"]).line(), "\"a long enough string\"");
    assert_eq!(s.code(&["--limit", "4", "get", &t, "t:l.0", "[0]"]), 5);
}

// CLI Sharing and roles, Sync, Identity and nodes: the local half of the
// sharing commands on one store (no peers): links, cards, nodes, grants by error category,
// status (bundles are binary: the localhost e2e).
#[test]
fn sharing_commands_local_plan_cli_4() {
    let s = S::mem();
    let g = s.ok(&["create", "--in", "me", "t:made.0", "true"]).line().to_string();
    s.ok(&["group", "sync", &g]);
    // spec/permissions.md §7: without peers a link reaches nobody unless direct (opt-in)
    assert_eq!(s.code(&["link", "make", &g, "write", "--single-use"]), 7);
    assert_eq!(s.code(&["card", "show"]), 7);
    assert_eq!(s.ok(&["--json", "link", "ls", &g]).line(), "[]");
    assert_eq!(s.ok(&["node", "ls"]).out.lines().count(), 1);
    let other = S::mem();
    let stranger = other.ok(&["whoami"]).out.lines().next().unwrap().split('\t').nth(1).unwrap().to_string();
    assert_eq!(s.code(&["grant", &g, &stranger, "read"]), 3, "keys unknown: import a card first");
    assert_eq!(s.code(&["node", "rm", &stranger]), 0, "no node of this account: nothing to do");
    assert_eq!(s.code(&["grant", &g, "me", "superuser"]), 2);
    let st = s.ok(&["--json", "status"]).line().to_string();
    assert!(st.starts_with("{\"groups\":[") && st.ends_with("\"connected\":0,\"two_sources\":[]}"), "{st}");
    assert_eq!(s.ok(&["status"]).out.lines().next(), Some("connected 0"));
    // CLI `group source G`: shows where G's calls go
    assert_eq!(s.ok(&["group", "source", &g]).out, "local\n");
    assert_eq!(s.ok(&["--json", "group", "source", &g]).line(), "{\"source\":\"local\"}");
}

// CLI: commands over API pieces not built yet (queries, backlinks) parse and
// report it; sharing commands without a runtime or peers fail as the API does.
#[test]
fn unbuilt_commands_say_so_plan_cli_4() {
    let s = S::mem();
    let t = s.thing();
    for args in [vec!["ls", "me"], vec!["backlinks", &t]] {
        let o = s.call(&args, "");
        assert_eq!(o.code, 1, "{args:?}: {}", o.err);
        assert!(o.err.contains("not built yet"), "{args:?}: {}", o.err);
    }
    assert_eq!(s.ok(&["node", "ls"]).out.lines().count(), 1, "this node");
    assert_eq!(s.ok(&["peers", "ls"]).out, "");
    assert_eq!(s.code(&["link", "redeem", "x"]), 7, "malformed link");
}

// CLI Watching: initial value first, printed but not counted by
// --count (no other node writes here, so --count 1 meets the timeout); roster --watch alike.
#[test]
fn watch_initial_not_counted_plan_cli_4() {
    let s = S::mem();
    let t = s.ok(&["create", "--in", "me", "a:b.0", "7"]).line().to_string();
    let o = s.call(&["--timeout", "50ms", "watch", &t, "a:b.0", "--count", "1"], "");
    assert_eq!((o.code, o.line(), o.err.trim()), (6, "initial - - a:b.0 7", "error: timed out after 0 change(s)"));
    let o = s.call(&["--json", "--timeout", "50ms", "watch", &t, "--count", "1"], "");
    assert_eq!(o.code, 6, "{}", o.err);
    // the whole thing: one initial line per present aspect (`a:b.0`, `created.0`), none counted
    assert_eq!(o.out.lines().count(), 2, "{}", o.out);
    assert!(o.out.lines().all(|l| l.contains("\"origin\":\"initial\"")) && o.out.contains("\"value\":7}"), "{}", o.out);
    // a path inside the aspect, as `get` reads it
    s.ok(&["set", &t, "a:m.0", "{\"a\": 1, \"b\": 2}"]);
    let o = s.call(&["--timeout", "50ms", "watch", &t, "a:m.0", "[\"b\"]", "--count", "1"], "");
    assert_eq!((o.code, o.line()), (6, "initial - - a:m.0 2"), "{}", o.err);
    let o = s.call(&["--timeout", "50ms", "grants", "me", "--watch", "--count", "1"], "");
    assert_eq!((o.code, o.out.lines().count(), o.err.trim()), (6, 1, "error: timed out after 0 change(s)"), "{}", o.out);
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
    let (c, t, e) = call(&["create", "--in", "me", "todo:task.0", "{title: \"buy\", done: false, due: #some(2026-01-02T03:04:05Z)}"], "");
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
    // the thing's retain default is one field of a required rule
    let (c, _, e) = call(&["set", t, "required^.0", "{rules: {}, retain: true, default: #none}"], "");
    assert_eq!(c, 0, "{e}");
    assert_eq!(call(&["get", t, "required^.0", ".retain"], "").1, "true\n");
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
    let t = s.ok(&["create", "--in", "me", "a:b.0", "1"]).line().to_string();
    let o = s.ok(&["inspect", "thing", &t]).out;
    assert!(o.contains("aspect a:b.0 commits=1"), "{o}");
    assert!(s.ok(&["inspect", "group", "me"]).out.contains(&t));
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
    let one = s.ok(&["chat", "post", &c, "--from", "ann", "--subject", "head", "body"]).line().to_string();
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
    assert_ne!(s.code(&["chat", "edit", &c, "not/an/id", "x"]), 0);
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

// CLI `serving`: `host^.0` written field by field, shown, stopped; a group names its sync IDs
// (as `status` lists them), a sync ID works too, `''` clears a field.
#[test]
fn serving_commands_plan_cli_4() {
    let s = S::mem();
    assert_eq!(s.code(&["serving", "show"]), 3, "not serving");
    s.ok(&["serving", "set", "--admitted", "me", "--policy", "group_entries=10", "--cap", "me=5,500"]);
    let ids = s.ok(&["serving", "ids", "me"]).out;
    let home_label = ids.trim().to_string();
    assert_eq!(home_label.len(), 32, "{ids}");
    assert!(!s.ok(&["--json", "status"]).out.contains(&home_label), "the id stays with serving");
    let show = s.ok(&["serving", "show"]).out;
    assert_eq!(show, format!("admit own\nadmitted {home_label}\npolicy group_entries 10\ncap {home_label} 5 500\n"));
    // one flag replaces its field, the rest kept; '' clears
    let other = "00112233445566778899aabbccddeeff";
    s.ok(&["serving", "set", "--admit", "open", "--admitted", other, "--policy", ""]);
    let show = s.ok(&["serving", "show"]).out;
    assert_eq!(show, format!("admit open\nadmitted {other}\ncap {home_label} 5 500\n"));
    let j = s.ok(&["--json", "serving", "show"]).out;
    assert!(j.contains(&format!("\"admitted\":[\"{other}\"]")) && j.contains("\"admit\":\"open\""), "{j}");
    // bad input: an unknown knob (Invalid), a group not synced here, not a sync ID
    assert_eq!(s.code(&["serving", "set", "--policy", "no_such_knob=1"]), 7);
    let t = s.thing();
    assert_eq!(s.code(&["serving", "set", "--admitted", &t]), 3);
    assert_eq!(s.code(&["serving", "set", "--admitted", "abc"]), 2);
    assert_eq!(s.code(&["serving", "set", "--cap", "me=5"]), 2);
    s.ok(&["serving", "off"]);
    assert_eq!(s.code(&["serving", "show"]), 3);
    s.ok(&["serving", "set"]);
    assert_eq!(s.ok(&["serving", "show"]).out, "admit own\n");
}

// notes/cli.md Design `-v`: a command that syncs prints the node's diagnostics on stderr
// (as `diag --follow`); without `-v`, or on a local command, none. The diagnostic: a thing
// only in groups no synced group holds (`NotSynced`), by `add-with-grant` (it syncs), for its
// membership commit, before its grant gives the thing a sync ID, and by `group add` (local).
#[test]
fn verbose_prints_diagnostics_plan_cli_4() {
    let s = S::mem();
    let group = || s.ok(&["create", "t:made.0", "true"]).line().to_string();
    let (g, g2, g3, g4, g5) = (group(), group(), group(), group(), group());
    let t = s.ok(&["create", "--in", &g, "t:x.0", "1"]).line().to_string();
    let line = format!("NotSynced {t} only in groups no synced group holds: it stays on this node");
    let o = s.ok(&["-v", "add-with-grant", &t, &g2, "read"]);
    assert_eq!(o.err.lines().filter(|l| *l == line).count(), 1, "{}", o.err);
    let o = s.ok(&["add-with-grant", &t, &g3, "read"]);
    assert_eq!(o.err, "");
    let o = s.ok(&["-v", "group", "add", &g4, &t]);
    assert_eq!(o.err, "", "a local command");
    let t2 = s.ok(&["create", "--in", &g, "t:x.0", "2"]).line().to_string();
    let o = s.ok(&["-v", "--json", "add-with-grant", &t2, &g5, "read"]);
    assert!(o.err.contains("\"kind\":\"NotSynced\""), "{}", o.err);
}

// notes/cli.md Design (daemon), notes/client-port.md §5: a locked store with no live daemon on its socket is exit 8 at once, whether no socket is there or a dead daemon's is left: and another node's socket never answers for this store
#[test]
fn locked_store_with_no_live_daemon() {
    let d = tmp("nodaemon");
    let ds = d.to_str().unwrap();
    let call = |args: &[&str]| {
        let (mut o, mut e) = (Vec::new(), Vec::new());
        let code = osis_cli::main_with(["osis", "--no-lan", "-s", ds, "--timeout", "0"].iter().chain(args).copied(), &mut &b""[..], &mut o, &mut e);
        (code, String::from_utf8(e).unwrap())
    };
    assert_eq!(call(&["init"]).0, 0);
    let held = osis::internals::open(osis::internals::Opening::dir(&d)).unwrap();
    let in_use = |what: &str| {
        let (code, err) = call(&["whoami"]);
        assert_eq!(code, 8, "{what}: {err}");
        assert!(err.contains("store in use"), "{what}: {err}");
    };
    in_use("no socket");
    // a dead daemon's socket: bound, then nobody there
    let sock = osis::internals::socket_path(&d).unwrap();
    drop(std::os::unix::net::UnixListener::bind(&sock).unwrap());
    assert!(sock.exists());
    in_use("a stale socket");
    let _ = std::fs::remove_file(&sock);
    // another node of this uid serving a socket of its own (a short path: `sun_path`)
    let other = std::env::temp_dir().join(format!("osis-cli-nodaemon-{}", std::process::id()));
    std::fs::create_dir_all(&other).unwrap();
    let mut c = osis::internals::Opening::memory();
    c.runtime = osis::Runtime::Own;
    let n = osis::internals::create(c).unwrap();
    n.listen_socket_at(&other.join("n.sock")).unwrap();
    in_use("another node's socket");
    drop((held, n));
    let _ = std::fs::remove_dir_all(&d);
    let _ = std::fs::remove_dir_all(&other);
}

// notes/cli.md Design (daemon), notes/client-port.md §5: a socket directory another user made first (here: one of the wrong mode) does not stop `serve`: it warns and serves without the client socket (the one test here that runs the binary)
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
    let _ = std::fs::remove_dir_all(&d);
    let _ = std::fs::remove_dir_all(&xdg);
}

// CLI `writes`, `fired`, `purge`: pages by place, each part in its line, a tombstone, purge by
// commit and by author; a signal's fires; `--follow`.
#[test]
fn writes_and_purge_commands_plan_cli() {
    let s = S::mem();
    let t = s.thing();
    s.ok(&["set", "--retention", "keep_history=forever", &t, "note:m.0", "\"one\""]);
    s.ok(&["set", "--retention", "keep_history=forever", &t, "note:m.0", "\"two\""]);
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
    s.ok(&["fire", "--retention", "keep_history=forever", &t, "note:ping~0", "1"]);
    let fired = s.ok(&["fired", &t, "note:ping~0"]).out;
    assert_eq!(fired.lines().count(), 1);
    assert_eq!(s.ok(&["writes", &t, "note:ping~0"]).out, "");
    // a fire replaced: listed in its place with its newest value, its versions on request
    let f = id_of(&fired).to_string();
    s.ok(&["fire", "--retention", "keep_history=forever", "--replaces", &f, &t, "note:ping~0", "2"]);
    let fired = s.ok(&["fired", &t, "note:ping~0"]).out;
    assert!(fired.lines().count() == 1 && id_of(&fired) == f && fired.contains("Int(2)") && fired.contains("edited="), "{fired}");
    let v = s.ok(&["fired", &t, "note:ping~0", "--versions-of", &f, "--oldest"]).out;
    let rows: Vec<&str> = v.lines().collect();
    assert!(rows.len() == 2 && id_of(rows[0]) == f && rows[0].contains("Int(1)") && rows[1].contains("Int(2)") && !v.contains("edited="), "{v}");
    assert_eq!(s.code(&["fire", "--retention", "keep_history=forever", "--replaces", id_of(rows[1]), &t, "note:ping~0", "3"]), 7, "a replacement is not replaced");
    let w = s.call(&["watch", &t, "note:ping~0"], "");
    assert!(w.code == 2 && w.err.contains("fired"), "{}", w.err);
    // --follow: what comes after it, until --count
    assert_eq!(s.code(&["--timeout", "1s", "writes", &t, "note:m.0", "--follow", "--count", "1"]), 6, "nothing new");
}

// CLI `group add`, `op`: a membership that expires by flag, `--admin` naming who stays
#[test]
fn group_and_splice_commands() {
    let s = S::mem();
    let g = s.thing();
    let t = s.thing();
    s.ok(&["group", "add", &g, &t, "--expires-in", "1h"]);
    assert!(s.ok(&["members", &g]).out.contains(&t));
    assert_eq!(s.code(&["group", "add", &g, &t, "--expires-in", "1h", "--expires-at", "2030-01-01T00:00:00Z"]), 2, "one expiry");
    let two = s.call(&["write"], &format!("set --expires-in 1h {t} a:x.0 1\nset --expires-in 2h {t} a:y.0 1\n"));
    assert!(two.code == 2 && two.err.contains("one expiry"), "{}", two.err);
    assert_eq!(s.call(&["write"], &format!("set --expires-in 1h {t} a:x.0 1\nset {t} a:y.0 1\n")).code, 0, "the flag is the commit's, whichever line gives it");
    assert_eq!(s.call(&["write"], &format!("set {t} a:x.0 1\nset {t} a:cursor+.0 1\n")).code, 7, "durable beside ephemeral");
    // spec/permissions.md §1: `--admin G` makes G the first admin, which `grants` lists
    let made = s.ok(&["create", "--admin", &g, "t:x.0", "1"]).line().to_string();
    let gs = s.ok(&["grants", &made]).out;
    assert!(gs.lines().any(|l| l.starts_with(&format!("{g} admin "))), "{gs}");
    assert_ne!(s.code(&["create", "--admin", &g[..g.len() - 1], "t:x.0", "1"]), 0, "a malformed admin");
    let schema = s.ok(&["create", "t:made.0", "true"]).line().to_string();
    assert_eq!(s.code(&["op", &schema, "t:made.0", "", "splice"]), 2, "a range");
}

// notes/cli.md Futures: a link that cannot be judged within `--timeout` says it could not be confirmed and that retrying is safe; nothing says it is bad
#[test]
fn redeem_past_its_wait_says_retrying_is_safe_notes_cli() {
    let s = S::mem();
    let a = osis::Address::new(&"mem://a".parse().unwrap(), [1; 32]).to_string();
    s.ok(&["peers", "add", &a]);
    let g = s.thing();
    let link = s.call(&["--timeout", "1ms", "link", "make", &g, "read"], "");
    let link = link.out.lines().next().unwrap_or_else(|| panic!("{}", link.err)).to_string();
    let other = S::mem();
    let o = other.call(&["--timeout", "100ms", "link", "redeem", &link], "");
    assert_eq!(o.code, 6, "{}", o.err);
    assert!(o.err.contains("could not confirm this link yet; trying again is safe"), "{}", o.err);
}

// Audit rows 3 and 12 (issues/no-server-audit.md), spec/permissions.md §7: with no saved peers
// the CLI still makes a link, a chat link and a contact card; a store with no peers is not a dead end.
#[test]
#[ignore = "issues/net-first-contact.md"]
fn repro_row3_row12_links_and_cards_on_a_store_with_no_saved_peer() {
    let s = S::mem();
    let g = s.ok(&["create", "--in", "me", "t:made.0", "true"]).line().to_string();
    s.ok(&["group", "sync", &g]);
    assert_eq!(s.code(&["link", "make", &g, "write"]), 0, "link make");
    assert_eq!(s.code(&["card", "show"]), 0, "card show");
    let c = s.ok(&["chat", "create", "--name", "room"]).line().to_string();
    assert_eq!(s.code(&["chat", "link", &c, "write"]), 0, "chat link");
}
