//! The `osis` binary run in-process (plans/cli.md Tests, tier 1): commands over memory and
//! temp-dir stores, exit codes per error category (§6), `--json` (§5), `write` scripts, named
//! keys with a schema, the command table's coverage of the API. No network, no sleeps.
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
        self.ok(&["create", "--owner", "me", "--in", "home"]).line().to_string()
    }
}

fn tmp(name: &str) -> PathBuf {
    let d = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("osis-cli-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d
}

// plans/cli.md Tests: argument parsing for every command (clap's debug_assert).
#[test]
fn command_tree_is_consistent_plan_cli_tests() {
    Cli::command().debug_assert();
}

// plans/cli.md §4 Things and aspects: create, get, set, replace, rm, show, aspects, delete.
#[test]
fn things_and_aspects_plan_cli_4() {
    let s = S::mem();
    let t = s.ok(&["create", "--owner", "me", "--in", "home", "/note/title", "\"hi\"", "/note/n", "3", "/note/neg", "-3"]).line().to_string();
    assert_eq!(s.ok(&["get", &t, "/note/neg"]).line(), "-3");
    assert!(t.starts_with("osis://"));
    assert_eq!(s.ok(&["get", &t, "/note/title"]).line(), "\"hi\"");
    s.ok(&["set", &t, "/note/m", "{\"a\": [1, 2.5], 1: #{h'00'}}"]);
    assert_eq!(s.ok(&["get", &t, "/note/m"]).line(), "{1: #{h'00'}, \"a\": [1, 2.5]}");
    assert_eq!(s.ok(&["get", &t, "/note/m", "[\"a\"]"]).line(), "[1, 2.5]");
    assert_eq!(s.ok(&["get", &t, "/note/m", "[1]"]).line(), "#{h'00'}");
    s.ok(&["set", &t, "/note/m", "[\"b\"]", "true"]);
    assert_eq!(s.ok(&["get", &t, "/note/m", "[\"b\"]"]).line(), "true");
    s.ok(&["rm", &t, "/note/m", "[\"b\"]"]);
    assert_eq!(s.code(&["get", &t, "/note/m", "[\"b\"]"]), 3);
    s.ok(&["replace", &t, "/note/n", "4"]);
    assert_eq!(s.ok(&["get", &t, "/note/n"]).line(), "4");
    let aks = s.ok(&["aspects", &t]).out;
    assert!(aks.contains("/note/title") && aks.contains("/created"), "{aks}");
    let show = s.ok(&["show", &t]).out;
    assert!(show.contains("/note/title\t\"hi\"") && show.contains("role\tadmin") && show.contains("/created\t{owner: osis://"), "{show}");
    s.ok(&["rm", &t, "/note/title"]);
    assert_eq!(s.code(&["get", &t, "/note/title"]), 3);
    s.ok(&["delete", &t]);
    assert_eq!(s.code(&["get", &t, "/note/n"]), 3);
}

// plans/cli.md §6: exit codes by error category.
#[test]
fn exit_codes_plan_cli_6() {
    let s = S::mem();
    let t = s.thing();
    // 2: usage, unparsable argument
    assert_eq!(s.code(&["get"]), 2);
    assert_eq!(s.code(&["set", &t, "/a/b", "{oops"]), 2);
    assert_eq!(s.code(&["get", "not-a-tid", "/a/b"]), 2);
    // 3: absent, unknown thing, same false
    assert_eq!(s.code(&["get", &t, "/a/b"]), 3);
    let other = "osis://AAAAAAAAAAAAAAAAAAAA";
    assert_eq!(s.code(&["set", other, "/a/b", "1"]), 3);
    assert_eq!(s.code(&["same", &t, other]), 3);
    assert_eq!(s.code(&["same", &t, &t]), 0);
    // 7: invalid (membership-class aspects are written only through sharing calls)
    assert_eq!(s.code(&["set", &t, "/members", "{}"]), 7);
    // 1: not supported yet (queries)
    let o = s.call(&["--json", "ls", "home"], "");
    assert_eq!(o.code, 1);
    assert!(o.err.starts_with("{\"error\":{\"kind\":\"Unsupported\""), "{}", o.err);
    // 8: store missing
    let d = tmp("missing");
    let o = osis_cli::main_with(["osis", "-s", d.to_str().unwrap(), "whoami"], &mut &b""[..], &mut Vec::new(), &mut Vec::new());
    assert_eq!(o, 8);
}

// plans/cli.md §2: one process at a time; a second opener fails with exit 8.
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
    assert_eq!(call(&["init"]).0, 8, "refuses a non-empty store");
    let (c, t, _) = call(&["create", "--owner", "me", "--unsynced", "/a/b", "1"]);
    assert_eq!(c, 0);
    assert_eq!(call(&["get", t.trim(), "/a/b"]).1, "1\n");
    let held = osis::Osis::open(osis::Config::dir(&d)).unwrap();
    let (c, _, err) = call(&["whoami"]);
    assert_eq!(c, 8, "{err}");
    assert!(err.contains("store in use"), "{err}");
    drop(held);
    assert_eq!(call(&["whoami"]).0, 0);
    let _ = std::fs::remove_dir_all(&d);
}

// plans/cli.md §5: --json output carries tids under their API names.
#[test]
fn json_output_plan_cli_5() {
    let s = S::mem();
    let o = s.ok(&["--json", "create", "--owner", "me", "--in", "home", "/a/b", "1.5"]);
    assert!(o.out.starts_with("{\"commit\":\"") && o.out.contains("\"tid\":\"osis://"), "{}", o.out);
    let t = o.out.split("\"tid\":\"").nth(1).unwrap().split('"').next().unwrap().to_string();
    assert_eq!(s.ok(&["--json", "get", &t, "/a/b"]).line(), "1.5");
    let w = s.ok(&["--json", "whoami"]).out;
    assert!(w.contains("\"me\":\"osis://") && w.contains("\"node\":\"osis://") && w.contains("\"servers\":[]"), "{w}");
    let e = s.call(&["--json", "get", &t, "/a/b", ".x"], "");
    assert_eq!(e.code, 2);
    assert!(e.err.contains("\"kind\":\"Usage\""), "{}", e.err);
}

// plans/cli.md §4 write: one Write, one commit; a failing line commits nothing.
#[test]
fn write_script_atomic_plan_cli_4() {
    let s = S::mem();
    let script = "# a note with a tag\ncreate --owner me --in home --as n /note/title \"a b\"\nset $n /note/tags #{\"x\"}\nop $n /note/m '' put \"k\" [$n, me]\n";
    let o = s.call(&["write"], script);
    assert_eq!(o.code, 0, "{}", o.err);
    let mut lines = o.out.lines();
    let commit = lines.next().unwrap();
    assert_eq!(commit.len(), 64);
    let n = lines.next().unwrap().strip_prefix("n\t").unwrap().to_string();
    assert_eq!(s.ok(&["get", &n, "/note/title"]).line(), "\"a b\"");
    let me = s.ok(&["--json", "whoami"]).out.split("\"me\":\"").nth(1).unwrap().split('"').next().unwrap().to_string();
    assert_eq!(s.ok(&["get", &n, "/note/m", "[\"k\"]"]).line(), format!("[{n}, {me}]"));
    // the third line fails: nothing of the script is committed
    let bad = "create --owner me --in home --as x /a/b 1\nset $x /a/c 2\nset osis://AAAAAAAAAAAAAAAAAAAA /a/b 1\n";
    let before = s.ok(&["history", "--group", "home"]).out;
    let o = s.call(&["write"], bad);
    assert_eq!(o.code, 3, "{}", o.err);
    assert_eq!(s.ok(&["history", "--group", "home"]).out, before);
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
    let t = s.ok(&["create", "--owner", "me", "--in", "home", "/x/l", "[10, 20]", "/x/m", "{1: \"a\"}"]).line().to_string();
    assert_eq!(s.ok(&["get", &t, "/x/l", "[1]"]).line(), "20");
    let o = s.call(&["set", &t, "/x/l", "[0]", "5"], "");
    assert_eq!(o.code, 2, "{}", o.err);
    assert!(o.err.contains("untyped list"), "{}", o.err);
    assert_eq!(s.code(&["rm", &t, "/x/l", "[0]"]), 2);
    assert_eq!(s.ok(&["get", &t, "/x/l"]).line(), "[10, 20]");
    // a map key on a saved untyped map is fine
    s.ok(&["set", &t, "/x/m", "[1]", "\"b\""]);
    assert_eq!(s.ok(&["get", &t, "/x/m"]).line(), "{1: \"b\"}");
    // in a script, an aspect written by an earlier line cannot be resolved against saved state
    let before = s.ok(&["history", "--group", "home"]).out;
    let o = s.call(&["write"], &format!("set {t} /x/m {{1: \"c\"}}\nset {t} /x/m [1] \"d\"\n"));
    assert_eq!(o.code, 2, "{}", o.err);
    assert!(o.err.contains("line 2") && o.err.contains("earlier in this batch"), "{}", o.err);
    let o = s.call(&["write"], "create --owner me --in home --as a /x/l [1, 2]\nset $a /x/l [0] 5\n");
    assert_eq!(o.code, 2, "{}", o.err);
    assert_eq!(s.ok(&["history", "--group", "home"]).out, before);
}

// plans/cli.md §2 `--timeout 0` = no timeout; waits take it without overflow.
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

// plans/cli.md §4 History and undo.
#[test]
fn history_undo_redo_plan_cli_4() {
    let s = S::mem();
    let t = s.thing();
    s.ok(&["set", &t, "/a/x", "1"]);
    s.ok(&["set", &t, "/a/x", "2"]);
    let h = s.ok(&["history", "--thing", &t]).out;
    assert_eq!(h.lines().count(), 3, "{h}");
    assert!(h.lines().all(|l| l.contains(" undoable ")), "{h}");
    s.ok(&["undo", "--thing", &t]);
    assert_eq!(s.ok(&["get", &t, "/a/x"]).line(), "1");
    s.ok(&["redo", "--aspect", &t, "/a/x"]);
    assert_eq!(s.ok(&["get", &t, "/a/x"]).line(), "2");
    let newest = s.ok(&["history", "--thing", &t, "--max", "1"]).out;
    let id = newest.split(' ').next().unwrap();
    s.ok(&["undo-commit", id]);
    assert_eq!(s.ok(&["get", &t, "/a/x"]).line(), "1");
    assert_eq!(s.code(&["undo", "--thing", &t, "--group", "home"]), 2);
    s.ok(&["set", &t, "/a/x", "3"]);
    assert_eq!(s.code(&["redo", "--thing", &t]), 3, "nothing to redo after a new change");
}

// plans/cli.md §4 Groups and Sharing: place, sub, groups, roster, role, move, same.
#[test]
fn groups_and_moves_plan_cli_4() {
    let s = S::mem();
    let g = s.ok(&["create", "--owner", "me", "--unsynced", "--group"]).line().to_string();
    let t = s.thing();
    s.ok(&["place", &t, &g]);
    assert!(s.ok(&["groups", &t]).out.contains(&g));
    s.ok(&["unplace", &t, &g]);
    assert!(!s.ok(&["groups", &t]).out.contains(&g));
    s.ok(&["sub", "add", "home", &g]);
    assert!(s.ok(&["get", "home", "/group"]).line().contains(&g));
    s.ok(&["sub", "rm", "home", &g]);
    assert_eq!(s.ok(&["role", &t]).line(), "admin");
    s.ok(&["roster", "me"]);
    let n = s.ok(&["move", &t, "me", "--in", "home"]).line().to_string();
    assert_ne!(n, t);
    assert_eq!(s.code(&["same", &t, &n]), 0);
}

// plans/cli.md §4: commands over API pieces not built yet (queries, backlinks, `--len`) parse and
// report Unsupported; sharing commands without a runtime or servers fail as the API does.
#[test]
fn unbuilt_commands_report_unsupported_plan_cli_4() {
    let s = S::mem();
    let t = s.thing();
    for args in [vec!["ls", "home"], vec!["backlinks", &t], vec!["get", &t, "/a/b", "--len"]] {
        let o = s.call(&args, "");
        assert_eq!(o.code, 1, "{args:?}: {}", o.err);
        assert!(o.err.contains("not supported yet"), "{args:?}: {}", o.err);
    }
    assert_eq!(s.ok(&["device", "ls"]).out.lines().count(), 1, "this device");
    assert_eq!(s.ok(&["server", "ls"]).out, "");
    assert_eq!(s.code(&["link", "redeem", "x"]), 7, "malformed link");
}

// plans/cli.md §4 Watching: initial value first; --count ends it.
#[test]
fn watch_initial_plan_cli_4() {
    let s = S::mem();
    let t = s.ok(&["create", "--owner", "me", "--in", "home", "/a/b", "7"]).line().to_string();
    let o = s.ok(&["watch", &t, "/a/b", "--count", "1"]);
    assert_eq!(o.line(), "initial - - - /a/b 7");
    let o = s.ok(&["--json", "watch", &t, "/a/b", "--count", "1"]);
    assert!(o.line().contains("\"source\":\"initial\"") && o.line().ends_with("\"value\":7}"), "{}", o.out);
}

const SCHEMA: &str = "schema 0x0123456789abcdef0123456789abcdef;
revision 1;
type task = struct { 0 title: string, 1 done: bool, 2 due: option<timestamp> };
aspect /todo/task: task;
aspect /todo/list: list<task>;
aspect /todo/count: counter<int>;
signal /todo/ping: int;
";

// plans/cli.md §1 Honest about names: named forms with a registered schema; --raw numbered.
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
    let (c, t, e) = call(&["create", "--owner", "me", "--in", "home", "/todo/task", "{title: \"buy\", done: false, due: #some(2026-01-02T03:04:05Z)}"], "");
    assert_eq!(c, 0, "{e}");
    let t = t.trim();
    assert_eq!(call(&["get", t, "/todo/task"], "").1, "{title: \"buy\", done: false, due: #some(2026-01-02T03:04:05Z)}\n");
    assert_eq!(call(&["--raw", "get", t, "/todo/task"], "").1, "{0: \"buy\", 1: false, 2: #1(1767323045000)}\n");
    assert_eq!(call(&["get", t, "/todo/task", ".due#some"], "").1, "2026-01-02T03:04:05Z\n");
    assert_eq!(call(&["--json", "get", t, "/todo/task"], "").1, "{\"title\":\"buy\",\"done\":false,\"due\":{\"$case\":\"some\",\"$payload\":1767323045000}}\n");
    // a write is validated against the schema (exit 5) and paths use names
    assert_eq!(call(&["set", t, "/todo/task", "{title: 1}"], "").0, 5);
    assert_eq!(call(&["set", t, "/todo/task", ".done", "true"], "").0, 0);
    assert_eq!(call(&["op", t, "/todo/task", ".due", "set-case", "none"], "").0, 0);
    assert_eq!(call(&["get", t, "/todo/task"], "").1, "{title: \"buy\", done: true, due: #none}\n");
    // edit: only what changed since --base
    let base = "{title: \"buy\", done: true, due: #none}";
    let (c, _, e) = call(&["edit", t, "/todo/task", "--base", base], "{title: \"buy milk\", done: true, due: #none}");
    assert_eq!(c, 0, "{e}");
    assert!(call(&["get", t, "/todo/task"], "").1.contains("\"buy milk\""));
    // typed list ops
    assert_eq!(call(&["set", t, "/todo/list", "[]"], "").0, 0);
    let (c, _, e) = call(&["op", t, "/todo/list", "", "insert", "0", "{title: \"a\", done: false, due: #none}", "{title: \"b\", done: false, due: #none}"], "");
    assert_eq!(c, 0, "{e}");
    assert_eq!(call(&["get", t, "/todo/list", "[1].title"], "").1, "\"b\"\n");
    assert_eq!(call(&["op", t, "/todo/list", "", "delete", "0..1"], "").0, 0);
    assert_eq!(call(&["get", t, "/todo/list", "[0].title"], "").1, "\"b\"\n");
    assert_eq!(call(&["op", t, "/todo/count", "", "inc", "5"], "").0, 0);
    assert_eq!(call(&["op", t, "/todo/count", "", "inc", "-2"], "").0, 0);
    assert_eq!(call(&["get", t, "/todo/count"], "").1, "3\n");
    // signals reach local listeners only; sending is checked
    assert_eq!(call(&["signal", "send", t, "/todo/ping", "1"], "").0, 0);
    assert_eq!(call(&["schema", "check", f.to_str().unwrap()], "").1, "ok revision 1 no lock\n");
    // a schema that does not parse: exit 7
    let bad = d.join("bad.osis");
    std::fs::write(&bad, "schema nonsense").unwrap();
    assert_eq!(call(&["--schema", bad.to_str().unwrap(), "get", t, "/todo/task"], "").0, 7);
    assert_eq!(call(&["schema", "add", bad.to_str().unwrap()], "").0, 7);
    // with a schema, typed index writes work (untyped ones are refused)
    assert_eq!(call(&["set", t, "/todo/list", "[0].done", "true"], "").0, 0);
    assert_eq!(call(&["get", t, "/todo/list", "[0].done"], "").1, "true\n");
    assert_eq!(call(&["schema", "rm", f.to_str().unwrap()], "").0, 0);
    assert_eq!(call(&["get", t, "/todo/task"], "").1, "{0: \"buy milk\", 1: true, 2: #0}\n");
    let _ = std::fs::remove_dir_all(&d);
}

// plans/cli.md §4 Inspection (format not stable): runs over the engine.
#[test]
fn inspect_and_diag_plan_cli_4() {
    let s = S::mem();
    let t = s.ok(&["create", "--owner", "me", "--in", "home", "/a/b", "1"]).line().to_string();
    let o = s.ok(&["inspect", "thing", &t]).out;
    assert!(o.contains("aspect /a/b commits=1"), "{o}");
    assert!(s.ok(&["inspect", "group", "home"]).out.contains(&t));
    assert!(s.ok(&["inspect", "actor", "me"]).out.starts_with("actor osis://"));
    let id = s.ok(&["history", "--thing", &t]).out.split(' ').next().unwrap().to_string();
    assert!(s.ok(&["inspect", "commit", &id]).out.contains("Header"));
    s.ok(&["diag"]);
}

/// Public `Osis` methods (`pub fn` / `pub async fn` in `impl Osis` blocks of crates/osis/src).
fn osis_methods() -> Vec<String> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../osis/src");
    let mut out = Vec::new();
    for f in std::fs::read_dir(dir).unwrap() {
        let text = std::fs::read_to_string(f.unwrap().path()).unwrap();
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

// plans/cli.md Tests: every public `Osis` method appears in notes/cli.md's command table, so
// coverage cannot drift silently.
#[test]
fn every_api_method_has_a_command_plan_cli_tests() {
    let table = std::fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../notes/cli.md")).unwrap();
    let methods = osis_methods();
    assert!(methods.len() > 30, "{methods:?}");
    let missing: Vec<&String> = methods.iter().filter(|m| !table.contains(&format!("`{m}`"))).collect();
    assert!(missing.is_empty(), "API methods without a command (notes/cli.md table): {missing:?}");
}
