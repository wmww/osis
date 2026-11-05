//! The `osis` binary run in-process (notes/cli.md Tests, tier 1; one test spawns `serve`): commands over memory and
//! temp-dir stores, exit codes per error category, `--json`, `write` scripts, named
//! keys with a schema, the command table's coverage of the API. No network, no sleeps.
//! spec: none (client surface: notes/cli.md).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

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

/// One store; every call is one invocation.
struct S {
    sel: StoreSel,
}

impl S {
    fn mem() -> S {
        let s = S { sel: StoreSel::Memory(MemStore::new()) };
        assert_eq!(s.ok(&["init"]).code, 0);
        s
    }

    fn call(&self, args: &[&str], stdin: &str) -> Out {
        let (mut o, mut e) = (Vec::new(), Vec::new());
        let mut i = stdin.as_bytes();
        let code = run(std::iter::once("osis").chain(args.iter().copied()), Some(self.sel.clone()), Io { stdin: &mut i, stdout: &mut o, stderr: &mut e, tty: false });
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
        self.ok(&["create", "--owner", "me", "--in", "home", "t:made.0", "true"]).line().to_string()
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

// notes/cli.md Command table Things and aspects: create, get, set, replace, rm, show, aspects, delete.
#[test]
fn things_and_aspects_plan_cli_4() {
    let s = S::mem();
    let t = s.ok(&["create", "--owner", "me", "--in", "home", "note:title.0", "\"hi\"", "note:n.0", "3", "note:neg.0", "-3"]).line().to_string();
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
    s.ok(&["replace", &t, "note:n.0", "4"]);
    assert_eq!(s.ok(&["get", &t, "note:n.0"]).line(), "4");
    let aks = s.ok(&["aspects", &t]).out;
    assert!(aks.contains("note:title.0") && aks.contains("created.0"), "{aks}");
    let show = s.ok(&["show", &t]).out;
    assert!(show.contains("note:title.0\t\"hi\"") && show.contains("role\tadmin") && show.contains("created.0\t{owner: osis://"), "{show}");
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
    // 3: absent, unknown thing
    assert_eq!(s.code(&["get", &t, "a:b.0"]), 3);
    let other = "osis://AAAAAAAAAAAAAAAAAAAA";
    assert_eq!(s.code(&["set", other, "a:b.0", "1"]), 3);
    // 7: invalid (role-class aspects are written only through sharing calls)
    assert_eq!(s.code(&["set", &t, "roles.0", "{}"]), 7);
    // 1: not built yet (queries)
    let o = s.call(&["--json", "ls", "home"], "");
    assert_eq!(o.code, 1);
    assert!(o.err.starts_with("{\"error\":{\"kind\":\"Cli\""), "{}", o.err);
    assert!(o.err.contains("not built yet"), "{}", o.err);
    // 8: store missing
    let d = tmp("missing");
    let o = osis_cli::main_with(["osis", "-s", d.to_str().unwrap(), "whoami"], &mut &b""[..], &mut Vec::new(), &mut Vec::new());
    assert_eq!(o, 8);
    // `restore` reads its card from `@FILE` or `-` (a recovery key need not sit in argv)
    let d = tmp("restore-arg");
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let o = osis_cli::main_with(["osis", "-s", d.to_str().unwrap(), "restore", "@/nonexistent/card"], &mut &b""[..], &mut out, &mut err);
    assert_eq!(o, 2, "{}", String::from_utf8_lossy(&err));
    assert!(String::from_utf8_lossy(&err).contains("/nonexistent/card"));
    let _ = std::fs::remove_dir_all(&d);
}

// notes/cli.md Design: one process at a time; a second opener fails with exit 8.
#[test]
fn store_dir_init_lock_plan_cli_2() {
    let d = tmp("lock");
    let ds = d.to_str().unwrap();
    let call = |args: &[&str]| {
        let (mut o, mut e) = (Vec::new(), Vec::new());
        let code = osis_cli::main_with(["osis", "-s", ds].iter().chain(args).copied(), &mut &b""[..], &mut o, &mut e);
        (code, String::from_utf8(o).unwrap(), String::from_utf8(e).unwrap())
    };
    let (c, out, _) = call(&["init"]);
    assert_eq!(c, 0);
    assert!(out.starts_with("me\tosis://"));
    // spec/requirements.md, Deletion (local keys): the store directory, its database and its
    // root key are the owner's only
    #[cfg(unix)]
    for (p, m) in [(d.clone(), 0o700), (d.join("db.redb"), 0o600), (d.join("root"), 0o600)] {
        let mode = std::os::unix::fs::PermissionsExt::mode(&std::fs::metadata(&p).unwrap().permissions());
        assert_eq!(mode & 0o777, m, "{}", p.display());
    }
    assert_eq!(call(&["init"]).0, 8, "refuses a non-empty store");
    let (c, t, _) = call(&["create", "--owner", "me", "a:b.0", "1"]);
    assert_eq!(c, 0);
    assert_eq!(call(&["get", t.trim(), "a:b.0"]).1, "1\n");
    let held = osis::Osis::open(osis::Config::dir(&d)).unwrap();
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
    let o = s.ok(&["--json", "create", "--owner", "me", "--in", "home", "a:b.0", "1.5"]);
    assert!(o.out.starts_with("{\"commit\":\"") && o.out.contains("\"tid\":\"osis://"), "{}", o.out);
    let t = o.out.split("\"tid\":\"").nth(1).unwrap().split('"').next().unwrap().to_string();
    assert_eq!(s.ok(&["--json", "get", &t, "a:b.0"]).line(), "1.5");
    let w = s.ok(&["--json", "whoami"]).out;
    assert!(w.contains("\"me\":\"osis://") && w.contains("\"node\":\"osis://") && w.contains("\"hosts\":[]"), "{w}");
    let e = s.call(&["--json", "get", &t, "a:b.0", ".x"], "");
    assert_eq!(e.code, 2);
    assert!(e.err.contains("\"kind\":\"Usage\""), "{}", e.err);
}

// notes/cli.md Command table write: one Write, one commit; a failing line commits nothing.
#[test]
fn write_script_atomic_plan_cli_4() {
    let s = S::mem();
    let script = "# a note with a tag\ncreate --owner me --in home --as n note:title.0 \"a b\"\nset $n note:tags.0 #{\"x\"}\nop $n note:m.0 '' put \"k\" [$n, me]\n";
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
    let bad = "create --owner me --in home --as x a:b.0 1\nset $x a:c.0 2\nset osis://AAAAAAAAAAAAAAAAAAAA a:b.0 1\n";
    let before = s.ok(&["commits", "--group", "home"]).out;
    let o = s.call(&["write"], bad);
    assert_eq!(o.code, 3, "{}", o.err);
    assert_eq!(s.ok(&["commits", "--group", "home"]).out, before);
    // a script parse error is usage, reported once
    let o = s.call(&["write"], "frobnicate x\n");
    assert_eq!(o.code, 2);
    assert!(o.err.starts_with("error: line 1: ") && o.err.matches("error:").count() == 1, "{}", o.err);
}

// notes/cli.md Paths: `[n]` on an untyped position. Reads index a saved list; writes never turn
// an index into a map key: a saved untyped list or an aspect written earlier in the same batch
// (whose pending state is invisible) is an error, and nothing is committed.
#[test]
fn untyped_index_paths_notes_cli() {
    let s = S::mem();
    let t = s.ok(&["create", "--owner", "me", "--in", "home", "x:l.0", "[10, 20]", "x:m.0", "{1: \"a\"}"]).line().to_string();
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
    let before = s.ok(&["commits", "--group", "home"]).out;
    let o = s.call(&["write"], &format!("set {t} x:m.0 {{1: \"c\"}}\nset {t} x:m.0 [1] \"d\"\n"));
    assert_eq!(o.code, 2, "{}", o.err);
    assert!(o.err.contains("line 2") && o.err.contains("earlier in this batch"), "{}", o.err);
    let o = s.call(&["write"], "create --owner me --in home --as a x:l.0 [1, 2]\nset $a x:l.0 [0] 5\n");
    assert_eq!(o.code, 2, "{}", o.err);
    assert_eq!(s.ok(&["commits", "--group", "home"]).out, before);
}

// notes/cli.md Design `--timeout 0` = no timeout; waits take it without overflow.
#[test]
fn timeout_zero_plan_cli_2() {
    let s = S::mem();
    for args in [vec!["--timeout", "0", "wait"], vec!["--timeout", "0", "sync"]] {
        let o = s.call(&args, "");
        assert_ne!(o.code, 2, "{args:?}: {}", o.err);
    }
    assert_eq!(s.code(&["--timeout", "5x", "wait"]), 2);
    assert_eq!(s.code(&["diag", "--since", "0"]), 2, "--since is gone");
}

// notes/cli.md Command table Commits and undo: the query's filters, undo, redo, revert.
#[test]
fn commits_undo_redo_plan_cli_4() {
    let s = S::mem();
    let t = s.thing();
    s.ok(&["set", &t, "a:x.0", "1"]);
    s.ok(&["set", &t, "a:x.0", "2"]);
    let h = s.ok(&["commits", "--thing", &t]).out;
    assert_eq!(h.lines().count(), 3, "{h}");
    assert!(h.lines().all(|l| l.contains(" change in-effect ")), "{h}");
    assert_eq!(s.ok(&["commits", "--thing", &t, "--next", "redo"]).out, "");
    let next = s.ok(&["commits", "--thing", &t, "--next", "undo"]).out;
    assert_eq!(next.lines().count(), 1, "{next}");
    s.ok(&["undo", "--thing", &t]);
    assert_eq!(s.ok(&["get", &t, "a:x.0"]).line(), "1");
    let undone = s.ok(&["commits", "--thing", &t, "--in-effect", "false"]).out;
    let undone = undone.split(' ').next().unwrap();
    assert_eq!(next.split(' ').next(), Some(undone), "undo reverted what --next undo listed");
    assert_eq!(s.code(&["commits", "--next", "undo"]), 7, "--next needs a scope");
    assert_eq!(s.code(&["commits", "--thing", &t, "--next", "nope"]), 2);
    let rev = s.ok(&["commits", "--reverts", undone]).out;
    assert_eq!(rev.lines().count(), 1, "{rev}");
    assert!(rev.contains(" revert in-effect reverts="), "{rev}");
    s.ok(&["redo", "--aspect", &t, "a:x.0"]);
    assert_eq!(s.ok(&["get", &t, "a:x.0"]).line(), "2");
    assert_eq!(s.ok(&["commits", "--thing", &t, "--kind", "revert"]).out.lines().count(), 2);
    let newest = s.ok(&["commits", "--thing", &t, "--max", "1"]).out;
    let id = newest.split(' ').next().unwrap();
    assert_eq!(s.ok(&["commits", "--thing", &t, "--after", id]).out.lines().count(), 4);
    s.ok(&["revert", id]);
    assert_eq!(s.ok(&["get", &t, "a:x.0"]).line(), "1");
    assert_eq!(s.code(&["undo", "--thing", &t, "--group", "home"]), 2);
    assert_eq!(s.code(&["commits", "--kind", "nope"]), 2);
    s.ok(&["set", &t, "a:x.0", "3"]);
    assert_eq!(s.code(&["redo", "--thing", &t]), 3, "nothing to redo after a new change");
}

// notes/cli.md Command table Groups and Sharing: place, sub, groups, roster, role.
#[test]
fn groups_plan_cli_4() {
    let s = S::mem();
    assert_eq!(s.code(&["create", "--owner", "me"]), 2, "nothing durable: gone at exit");
    assert_eq!(s.code(&["create", "--owner", "me", "--in", "home", "--group"]), 2, "an ephemeral group, placed ephemerally");
    let g = s.ok(&["create", "--owner", "me", "--group", "t:made.0", "true"]).line().to_string();
    let t = s.thing();
    s.ok(&["place", &t, &g]);
    assert!(s.ok(&["groups", &t]).out.contains(&g));
    s.ok(&["unplace", &t, &g]);
    assert!(!s.ok(&["groups", &t]).out.contains(&g));
    s.ok(&["sub", "add", "home", &g]);
    assert!(s.ok(&["get", "home", "group.0"]).line().contains(&g));
    assert!(s.ok(&["groups", &g]).out.lines().any(|l| l.starts_with("subgroup\t")), "listed as a subgroup of home");
    s.ok(&["sub", "rm", "home", &g]);
    assert_eq!(s.ok(&["role", &t]).line(), "admin");
    s.ok(&["roster", "me"]);
    s.ok(&["delete", &t]);
    assert!(s.ok(&["show", &t]).out.contains("state\tempty"), "a deleted thing has no content");
}

// notes/cli.md Command table Things and aspects (`--stream`, `--len`), notes/api.md Large values: a value
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

// notes/cli.md Command table Sharing and roles, Sync, Identity and devices: the local half of the
// sharing commands on one store (no hosts): links, cards, devices, grants by error category,
// status (bundles are binary: the localhost e2e).
#[test]
fn sharing_commands_local_plan_cli_4() {
    let s = S::mem();
    let g = s.ok(&["create", "--owner", "me", "--in", "home", "--group", "t:made.0", "true"]).line().to_string();
    s.ok(&["group", "sync", &g]);
    // spec/permissions.md §8: without hosts a link reaches nobody unless direct (opt-in)
    assert_eq!(s.code(&["link", "make", &g, "write", "--single-use"]), 7);
    assert_eq!(s.code(&["card", "show"]), 7);
    assert_eq!(s.ok(&["--json", "link", "ls", &g]).line(), "[]");
    assert_eq!(s.ok(&["device", "ls"]).out.lines().count(), 1);
    let other = S::mem();
    let stranger = other.ok(&["whoami"]).out.lines().next().unwrap().split('\t').nth(1).unwrap().to_string();
    assert_eq!(s.code(&["grant", &g, &stranger, "read"]), 3, "keys unknown: import a card first");
    assert_eq!(s.code(&["device", "rm", &stranger]), 0, "no device of this person: nothing to do");
    assert_eq!(s.code(&["grant", &g, "me", "superuser"]), 2);
    let st = s.ok(&["--json", "status"]).line().to_string();
    assert!(st.starts_with("{\"groups\":[") && st.ends_with("\"split\":[]}"), "{st}");
}

// notes/cli.md Command table: commands over API pieces not built yet (queries, backlinks) parse and
// report it; sharing commands without a runtime or hosts fail as the API does.
#[test]
fn unbuilt_commands_say_so_plan_cli_4() {
    let s = S::mem();
    let t = s.thing();
    for args in [vec!["ls", "home"], vec!["backlinks", &t]] {
        let o = s.call(&args, "");
        assert_eq!(o.code, 1, "{args:?}: {}", o.err);
        assert!(o.err.contains("not built yet"), "{args:?}: {}", o.err);
    }
    assert_eq!(s.ok(&["device", "ls"]).out.lines().count(), 1, "this device");
    assert_eq!(s.ok(&["hosts", "ls"]).out, "");
    assert_eq!(s.code(&["link", "redeem", "x"]), 7, "malformed link");
}

// notes/cli.md Command table Watching: initial value first, printed but not counted by
// --count (no other node writes here, so --count 1 meets the timeout); roster --watch alike.
#[test]
fn watch_initial_not_counted_plan_cli_4() {
    let s = S::mem();
    let t = s.ok(&["create", "--owner", "me", "--in", "home", "a:b.0", "7"]).line().to_string();
    let o = s.call(&["--timeout", "50ms", "watch", &t, "a:b.0", "--count", "1"], "");
    assert_eq!((o.code, o.line(), o.err.trim()), (6, "initial - - - a:b.0 7", "error: timed out after 0 change(s)"));
    let o = s.call(&["--json", "--timeout", "50ms", "watch", &t, "--count", "1"], "");
    assert_eq!(o.code, 6, "{}", o.err);
    // the whole thing: one initial line per present aspect (`a:b.0`, `created.0`), none counted
    assert_eq!(o.out.lines().count(), 2, "{}", o.out);
    assert!(o.out.lines().all(|l| l.contains("\"source\":\"initial\"")) && o.out.contains("\"value\":7}"), "{}", o.out);
    let o = s.call(&["--timeout", "50ms", "roster", "me", "--watch", "--count", "1"], "");
    assert_eq!((o.code, o.out.lines().count(), o.err.trim()), (6, 1, "error: timed out after 0 change(s)"), "{}", o.out);
}

const SCHEMA: &str = "version 1;
type task = struct { 0 title: string, 1 done: bool, 2 due: option<timestamp> };
aspect todo:task.0: task;
aspect todo:list.0: list<task>;
aspect todo:count.0: counter<int>;
aspect todo:ping.0*: int;
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
        let code = osis_cli::main_with(["osis", "-s", st].iter().chain(args).copied(), &mut stdin.as_bytes(), &mut o, &mut e);
        (code, String::from_utf8(o).unwrap(), String::from_utf8(e).unwrap())
    };
    assert_eq!(call(&["init"], "").0, 0);
    assert_eq!(call(&["schema", "add", f.to_str().unwrap()], "").0, 0);
    assert!(call(&["schema", "ls"], "").1.contains("todo.osis"));
    let (c, t, e) = call(&["create", "--owner", "me", "--in", "home", "todo:task.0", "{title: \"buy\", done: false, due: #some(2026-01-02T03:04:05Z)}"], "");
    assert_eq!(c, 0, "{e}");
    let t = t.trim();
    assert_eq!(call(&["get", t, "todo:task.0"], "").1, "{title: \"buy\", done: false, due: #some(2026-01-02T03:04:05Z)}\n");
    assert_eq!(call(&["--raw", "get", t, "todo:task.0"], "").1, "{0: \"buy\", 1: false, 2: #1(1767323045000)}\n");
    assert_eq!(call(&["get", t, "todo:task.0", ".due#some"], "").1, "2026-01-02T03:04:05Z\n");
    assert_eq!(call(&["--json", "get", t, "todo:task.0"], "").1, "{\"title\":\"buy\",\"done\":false,\"due\":{\"$case\":\"some\",\"$payload\":1767323045000}}\n");
    // a write is validated against the schema (exit 5) and paths use names
    assert_eq!(call(&["set", t, "todo:task.0", "{title: 1}"], "").0, 5);
    assert_eq!(call(&["set", t, "todo:task.0", ".done", "true"], "").0, 0);
    assert_eq!(call(&["op", t, "todo:task.0", ".due", "set-case", "none"], "").0, 0);
    assert_eq!(call(&["get", t, "todo:task.0"], "").1, "{title: \"buy\", done: true, due: #none}\n");
    // edit: only what changed since --base
    let base = "{title: \"buy\", done: true, due: #none}";
    let (c, _, e) = call(&["edit", t, "todo:task.0", "--base", base], "{title: \"buy milk\", done: true, due: #none}");
    assert_eq!(c, 0, "{e}");
    assert!(call(&["get", t, "todo:task.0"], "").1.contains("\"buy milk\""));
    // typed list ops
    assert_eq!(call(&["set", t, "todo:list.0", "[]"], "").0, 0);
    let (c, _, e) = call(&["op", t, "todo:list.0", "", "insert", "0", "{title: \"a\", done: false, due: #none}", "{title: \"b\", done: false, due: #none}"], "");
    assert_eq!(c, 0, "{e}");
    assert_eq!(call(&["get", t, "todo:list.0", "[1].title"], "").1, "\"b\"\n");
    assert_eq!(call(&["op", t, "todo:list.0", "", "delete", "0..1"], "").0, 0);
    assert_eq!(call(&["get", t, "todo:list.0", "[0].title"], "").1, "\"b\"\n");
    assert_eq!(call(&["op", t, "todo:count.0", "", "inc", "5"], "").0, 0);
    assert_eq!(call(&["op", t, "todo:count.0", "", "inc", "-2"], "").0, 0);
    assert_eq!(call(&["get", t, "todo:count.0"], "").1, "3\n");
    // a signal aspect fires and holds nothing
    assert_eq!(call(&["set", t, "todo:ping.0*", "1"], "").0, 0);
    assert_eq!(call(&["get", t, "todo:ping.0*"], "").0, 3, "absent");
    assert!(!call(&["aspects", t], "").1.contains("todo:ping.0*"));
    assert_eq!(call(&["schema", "check", f.to_str().unwrap()], "").1, "ok version 1 no lock\n");
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

// notes/cli.md Command table Inspection (format not stable): runs over the engine.
#[test]
fn inspect_and_diag_plan_cli_4() {
    let s = S::mem();
    let t = s.ok(&["create", "--owner", "me", "--in", "home", "a:b.0", "1"]).line().to_string();
    let o = s.ok(&["inspect", "thing", &t]).out;
    assert!(o.contains("aspect a:b.0 commits=1"), "{o}");
    assert!(s.ok(&["inspect", "group", "home"]).out.contains(&t));
    // notes/api.md Reads: `show` names the owner and the creating commit; `now` the clock
    let shown = s.ok(&["show", &t]).out;
    assert!(shown.contains("owner\tosis://") && shown.contains("created\t"), "{shown}");
    assert!(!s.ok(&["now"]).out.trim().is_empty());
    assert!(s.ok(&["inspect", "actor", "me"]).out.starts_with("actor osis://"));
    let id = s.ok(&["commits", "--thing", &t]).out.split(' ').next().unwrap().to_string();
    assert!(s.ok(&["inspect", "commit", &id]).out.contains("Header"));
    s.ok(&["diag"]);
}

/// Public `Osis` methods (`pub fn` / `pub async fn` in `impl Osis` blocks under core/osis/src).
fn osis_methods() -> Vec<String> {
    let mut files = vec![PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../core/osis/src")];
    let mut out = Vec::new();
    while let Some(p) = files.pop() {
        if p.is_dir() {
            files.extend(std::fs::read_dir(p).unwrap().map(|f| f.unwrap().path()));
            continue;
        }
        let text = std::fs::read_to_string(p).unwrap();
        let mut inside = false;
        for l in text.lines() {
            if l.starts_with("impl Osis {") {
                inside = true;
            } else if l == "}" {
                inside = false;
            } else if inside && let Some(r) = l.trim_start().strip_prefix("pub fn ").or_else(|| l.trim_start().strip_prefix("pub async fn ")) {
                out.push(r.split(['(', '<']).next().unwrap().to_string());
            }
        }
    }
    out
}

// notes/cli.md Tests: every public `Osis` method appears in notes/cli.md's command table, so
// coverage cannot drift silently.
#[test]
fn every_api_method_has_a_command_plan_cli_tests() {
    let table = std::fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../notes/cli.md")).unwrap();
    let methods = osis_methods();
    assert!(methods.len() > 30, "{methods:?}");
    let missing: Vec<&String> = methods.iter().filter(|m| !table.contains(&format!("`{m}`"))).collect();
    assert!(missing.is_empty(), "API methods without a command (notes/cli.md table): {missing:?}");
}

// notes/cli.md Command table `chat`, notes/chat.md: a local chat through the commands: post and read, the JSON, a cursor, edit, delete, bad arguments
#[test]
fn chat_commands_plan_cli() {
    let s = S::mem();
    let c = s.ok(&["chat", "create", "--name", "room"]).line().to_string();
    let one = s.ok(&["chat", "post", &c, "--from", "ann", "--subject", "head", "body"]).line().to_string();
    let read = s.ok(&["--json", "chat", "read", &c]).out;
    assert!(read.contains(&format!("\"id\":\"{one}\"")) && read.contains("\"name\":\"ann\"") && read.contains("head\\n\\nbody") && read.contains("\"reply_to\":null") && read.contains("\"cursor\""), "{read}");
    let two = s.ok(&["chat", "post", &c, "--reply-to", &one, "two"]).line().to_string();
    assert!(s.ok(&["chat", "read", &c, "--after", &one]).out.contains(&format!("(to {one}): two")));
    assert_eq!(s.ok(&["chat", "read", &c, "--max", "1"]).out.lines().count(), 2, "a message and the cursor");
    s.ok(&["chat", "edit", &c, &two, "two!"]);
    assert!(s.ok(&["chat", "read", &c]).out.contains("(edited): two!"));
    s.ok(&["chat", "delete", &c, &one]);
    let who = s.ok(&["whoami"]).out;
    let me = who.lines().find_map(|l| l.strip_prefix("me\t")).unwrap().to_string();
    assert!(s.ok(&["chat", "read", &c]).out.contains(&format!("<deleted by {me}>")));
    assert!(s.ok(&["--json", "chat", "read", &c]).out.contains(&format!("\"deleted_by\":\"{me}\"")));
    assert_ne!(s.code(&["chat", "resend", &c, &two]), 0, "delivered: nothing to send again");
    assert!(s.ok(&["chat", "members", &c]).out.contains("Admin"));
    assert_ne!(s.code(&["chat", "create", "--purge", "x"]), 0);
    assert_ne!(s.code(&["chat", "edit", &c, "not/an/id", "x"]), 0);
}

// notes/cli.md Command table `clients`, notes/client-port.md §3: `add` prints the actor and the secret once (only the hash stays), `ls` lists them, `rotate` prints a new secret, `rm` removes (again: exit 3); an until not in the future is refused; `--node` needs `--client-secret` and a readable secret file
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

// notes/cli.md Command table `hosting`: `host.0^` written field by field, shown (with the host
// address each listen URL will have, known without serving), stopped (a new start, a new key); a
// group names its labels (as `status` lists them), a label ID works too, `''` clears a field.
#[test]
fn hosting_commands_plan_cli_4() {
    let s = S::mem();
    assert_eq!(s.code(&["hosting", "show"]), 3, "not hosting");
    s.ok(&["hosting", "set", "--listen", "quic://0.0.0.0:7400", "--label", "home", "--policy", "cap_entries=10", "--cap", "home=5,500"]);
    let st = s.ok(&["--json", "status"]).out;
    let home_label = st.split("\"labels\":[\"").nth(1).unwrap().split('"').next().unwrap().to_string();
    assert_eq!(home_label.len(), 32, "{st}");
    let show = s.ok(&["hosting", "show"]).out;
    let addr = show.lines().find_map(|l| l.strip_prefix("address ")).unwrap_or_else(|| panic!("{show}")).to_string();
    let key = addr.strip_prefix("quic://0.0.0.0:7400#").unwrap_or_else(|| panic!("{addr}"));
    assert_eq!(key.len(), 43, "a base64url 32-byte key: {addr}");
    assert_eq!(show, format!("listen quic://0.0.0.0:7400\naddress {addr}\nadmit own\nlabel {home_label}\npolicy cap_entries 10\ncap {home_label} 5 500\n"));
    // the address works as a host to add (`hosts add` on the host device itself)
    s.ok(&["hosts", "add", &addr]);
    assert_eq!(s.ok(&["hosts", "ls"]).out, format!("{addr}\n"));
    s.ok(&["hosts", "rm", &addr]);
    // one flag replaces its field, the rest kept; '' clears
    let other = "00112233445566778899aabbccddeeff";
    s.ok(&["hosting", "set", "--admit", "open", "--label", other, "--policy", ""]);
    let show = s.ok(&["hosting", "show"]).out;
    assert_eq!(show, format!("listen quic://0.0.0.0:7400\naddress {addr}\nadmit open\nlabel {other}\ncap {home_label} 5 500\n"), "the key kept");
    let j = s.ok(&["--json", "hosting", "show"]).out;
    assert!(j.contains(&format!("\"labels\":[\"{other}\"]")) && j.contains("\"admit\":\"open\"") && j.contains(&format!("\"addresses\":[\"{addr}\"]")), "{j}");
    // bad input: an unknown knob (Invalid), a group not synced here, not a label
    assert_eq!(s.code(&["hosting", "set", "--policy", "no_such_knob=1"]), 7);
    let t = s.thing();
    assert_eq!(s.code(&["hosting", "set", "--label", &t]), 3);
    assert_eq!(s.code(&["hosting", "set", "--label", "abc"]), 2);
    assert_eq!(s.code(&["hosting", "set", "--cap", "home=5"]), 2);
    s.ok(&["hosting", "off"]);
    assert_eq!(s.code(&["hosting", "show"]), 3);
    // stopping shreds the host secret: a new start has a new address; no listen URL, no address
    s.ok(&["hosting", "set"]);
    assert_eq!(s.ok(&["hosting", "show"]).out, "admit own\n");
    s.ok(&["hosting", "set", "--listen", "quic://0.0.0.0:7400"]);
    let again = s.ok(&["hosting", "show"]).out;
    assert!(again.contains("address quic://0.0.0.0:7400#") && !again.contains(&addr), "{again}");
    // a port 0 is picked when it listens: no address printed for it
    s.ok(&["hosting", "set", "--listen", "quic://127.0.0.1:0", "--listen", "quic://0.0.0.0:7400"]);
    let two = s.ok(&["hosting", "show"]).out;
    assert_eq!(two.lines().filter(|l| l.starts_with("address ")).collect::<Vec<_>>().len(), 1, "{two}");
    assert!(two.contains("address quic://0.0.0.0:7400#"), "{two}");
}

// notes/cli.md Deviations `-v`: a command that syncs prints the node's diagnostics on stderr
// (as `diag --follow`); without `-v`, or on a local command, none. The diagnostic: a thing
// placed only in groups no synced group holds (`NotSynced`), by `share-into` (it syncs) and by
// `place` (local).
#[test]
fn verbose_prints_diagnostics_plan_cli_4() {
    let s = S::mem();
    let group = || s.ok(&["create", "--owner", "me", "--group", "t:made.0", "true"]).line().to_string();
    let (g, g2, g3, g4, g5) = (group(), group(), group(), group(), group());
    let t = s.ok(&["create", "--owner", "me", "--in", &g, "t:x.0", "1"]).line().to_string();
    let line = format!("NotSynced {t} placed only in groups no synced group holds: it stays on this device");
    let o = s.ok(&["-v", "share-into", &t, &g2, "read"]);
    assert_eq!(o.err.lines().filter(|l| *l == line).count(), 1, "{}", o.err);
    let o = s.ok(&["share-into", &t, &g3, "read"]);
    assert_eq!(o.err, "");
    let o = s.ok(&["-v", "place", &t, &g4]);
    assert_eq!(o.err, "", "a local command");
    let o = s.ok(&["-v", "--json", "share-into", &t, &g5, "read"]);
    assert!(o.err.contains("\"kind\":\"NotSynced\""), "{}", o.err);
}

// notes/cli.md Design (daemon), notes/client-port.md §5: a locked store's `<store>/sock` naming another socket than the store's own (`socket_path`) is not followed: another store's daemon never answers for this one
#[test]
fn sock_pointer_must_be_the_stores() {
    let d = tmp("sockptr");
    let ds = d.to_str().unwrap();
    let call = |args: &[&str]| {
        let (mut o, mut e) = (Vec::new(), Vec::new());
        let code = osis_cli::main_with(["osis", "-s", ds].iter().chain(args).copied(), &mut &b""[..], &mut o, &mut e);
        (code, String::from_utf8(e).unwrap())
    };
    assert_eq!(call(&["init"]).0, 0);
    let held = osis::Osis::open(osis::Config::dir(&d)).unwrap();
    // another node of this uid serving a socket of its own
    // (a short path: `sun_path`)
    let other = std::env::temp_dir().join(format!("osis-cli-sockptr-{}", std::process::id()));
    std::fs::create_dir_all(&other).unwrap();
    let mut c = osis::Config::memory();
    c.runtime = osis::Runtime::Own;
    let (n, _) = osis::Osis::create(c).unwrap();
    let sock = other.join("n.sock");
    n.listen_unix(&sock).unwrap();
    std::fs::write(d.join(osis::SOCK_FILE), format!("{}\n", sock.display())).unwrap();
    let (code, err) = call(&["whoami"]);
    assert_eq!(code, 8, "{err}");
    assert!(err.contains("store in use"), "{err}");
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
    assert_eq!(osis_cli::main_with(["osis", "-s", ds, "init"], &mut &b""[..], &mut Vec::new(), &mut Vec::new()), 0);
    let xdg = d.with_extension("xdg");
    std::fs::create_dir_all(xdg.join("osis")).unwrap();
    std::fs::set_permissions(xdg.join("osis"), std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut c = std::process::Command::new(env!("CARGO_BIN_EXE_osis")).env("XDG_RUNTIME_DIR", &xdg).args(["-s", ds, "serve"]).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::piped()).spawn().unwrap();
    // read on a thread: a serve that never warns runs on and keeps stderr open
    let err = std::io::BufReader::new(c.stderr.take().unwrap());
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || tx.send(err.lines().map_while(Result::ok).any(|l| l.contains("serving without a client socket"))));
    let warned = rx.recv_timeout(std::time::Duration::from_secs(60)).unwrap_or(false);
    let running = c.try_wait().unwrap().is_none();
    let _ = c.kill();
    let _ = c.wait();
    assert!(warned && running);
    assert!(!d.join(osis::SOCK_FILE).exists());
    let _ = std::fs::remove_dir_all(&d);
    let _ = std::fs::remove_dir_all(&xdg);
}

// notes/cli.md Command table `ownerless`, spec/permissions.md §1: an ownerless thing has no owner
// and this person as first admin; a key actor or unknown actor as admin is refused.
#[test]
fn ownerless_plan_cli() {
    let s = S::mem();
    let t = s.ok(&["ownerless", "me"]).line().to_string();
    assert_eq!(s.ok(&["role", &t]).line(), "admin");
    assert!(s.ok(&["show", &t]).out.contains("owner\tnone"));
    assert!(s.ok(&["roster", &t]).out.contains("admin"));
    s.ok(&["set", &t, "name.0", "\"chat\""]);
    assert_ne!(s.code(&["ownerless", &t[..t.len() - 1]]), 0);
}

// notes/cli.md Command table `history`, `purge`: pages by place, a tombstone in its line, purge by
// commit and by author.
#[test]
fn history_and_purge_commands_plan_cli() {
    let s = S::mem();
    let t = s.ok(&["create", "--owner", "me", "--in", "home", "note:m.0", "\"one\""]).line().to_string();
    s.ok(&["set", &t, "note:m.0", "\"two\""]);
    let lines = s.ok(&["history", &t, "note:m.0"]).out;
    let rows: Vec<&str> = lines.lines().collect();
    assert_eq!(rows.len(), 2, "{lines}");
    assert!(rows[0].contains("two") && rows[1].contains("one"), "{lines}");
    let pos = rows[0].split(' ').next().unwrap();
    let older = s.ok(&["history", &t, "note:m.0", "--before", pos]).out;
    assert_eq!(older, format!("{}\n", rows[1]));
    assert!(s.ok(&["history", &t, "note:m.0", "--oldest", "--max", "1"]).out.contains("one"));
    let j = s.ok(&["--json", "history", &t, "note:m.0", "--max", "1"]).out;
    assert!(j.contains("\"more\":true") || j.contains("\"more\": true"), "{j}");
    let one = rows[1].split(' ').next().unwrap().split('/').nth(1).unwrap();
    s.ok(&["purge", &t, "note:m.0", "--commit", one]);
    let lines = s.ok(&["history", &t, "note:m.0"]).out;
    assert!(lines.lines().any(|l| l.contains(one) && l.contains("purged=")), "{lines}");
    let me = rows[0].split(' ').nth(2).unwrap();
    s.ok(&["purge", &t, "note:m.0", "--author", me]);
    assert!(s.ok(&["history", &t, "note:m.0"]).out.lines().all(|l| l.contains("purged=")));
    assert_eq!(s.code(&["history", &t, "note:m.0", "--before", "nonsense"]), 2);
}
