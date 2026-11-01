# CLI
> Summary: `osis-cli` (binary `osis`): one invocation opens the store, acts, closes; the command table over the `osis` API (which commands work, which report Unsupported for API pieces not built); the value syntax grammar (read back what it prints, numbered or named); the JSON mapping; exit codes; design decisions and deviations from the original plan.

## Design
- **Thin**: a command is one API call plus parsing and printing (`cli/src/cmd.rs`, `write.rs`). Missing API pieces surface as the API's `Unsupported` (exit 1, kind `Unsupported`), never as CLI workarounds. Commands whose API method does not exist yet (`ls`, `backlinks`, `group policy`, `op undelete`; issues/api-deferred.md) report Unsupported from the CLI with the method's name.
- **Store**: `-s DIR` / `OSIS_STORE` / `$XDG_DATA_HOME/osis/default`. Missing (`db.redb` absent) or locked: exit 8. The lock is redb's file lock; the CLI writes its pid to `<store>/pid` after opening so a second opener says `store in use by pid N`. `init` refuses a non-empty directory (exit 8). `<store>/cli.toml` holds registered schema paths (`schemas = [ "…", ]`, one quoted path per line; absolute). No other state.
- **Entry points**: `osis_cli::main_with(args, stdin, stdout, stderr) -> i32`; `osis_cli::run(args, Option<StoreSel>, Io)` also takes a memory store (tests) and the terminal flag (`edit` opens `$EDITOR` only on a terminal).
- **Futures** (`restore`, `demote`, `redeem`, `import_contact`, `remove_device`, `revoke_link`, `revoke_joiner`, `wait_synced`): polled on the calling thread by a park/unpark waker with the `--timeout` deadline (exit 6); sync runs on the API's own runtime. Each invocation ends with `Osis::close`, which waits until the store is free.
- **Streaming** (`watch` (signal aspects too), `roster --watch`, `diag --follow`, `serve`): until `--count`, `--timeout` or SIGINT (default action: the process dies; commits are already durable). Streaming commands have no default timeout; `--timeout` reached with `--count` unmet: exit 6, without `--count`: exit 0. Other waits default to 30 s. `--timeout 0` is no deadline (deadlines use checked arithmetic; the API's `Duration`-taking `wait_synced` gets a 100-year bound).
- **Named keys**: `db.key(ak)` types an AK by a registered schema (`schema add`, `--schema FILE`) or the core schema. Reads print named forms through the typed view (reader defaults filled); `--raw` uses the untyped key: stored value, numbered forms, ms. Writes through a typed key are validated (exit 5); `--raw` writes untyped.
- **Paths**: typed positions follow the type. `[n]` on an untyped position: `get` reads the saved value (a list: index; else map key). Writes (`set`, `replace`, `rm`, `op`, script lines) take it as a map key, and refuse it (exit 2) when the saved value there is a list (untyped lists take no index writes; register a schema) or when the same batch already wrote that aspect or created/deleted the thing (`write` scripts: the pending state is invisible to reads, so the saved state cannot decide). Never a silent map write over a list.
- **Commit ids** print as 64 lower-case hex digits (input for `revert`, `commits --reverts/--reverted-by/--after`, `inspect commit`).
- **`write` scripts**: lines are tokenized at whitespace outside quotes and brackets, so a value is one token with its quotes kept; a token wholly in single quotes loses them (`''` is the root path). `$NAME` (from `create --as NAME`) works as a tid argument and inside values. Errors from a line's arguments carry `line N`; rights and unknown things are checked at commit (no line). Output: the commit id (or `-`), then `NAME<TAB>tid` per bound name.
- **`edit` on a terminal**: the value goes to a new temp file (`create_new`, random name, mode 0600, in `$XDG_RUNTIME_DIR` when set), then `$EDITOR`; the file is removed whatever the editor does.
- **Delivering commands** (`grant`, `edge`, `leave`, `share-into`, `remove-edge-of`, `link make`, `card show`, `group sync`): their API call queues inbox deposits or a new label's first commits that the engine holds only in memory, so they open with sync on and end with `sync_now` + `wait_synced(All)` within `--timeout` (exit 6 "done locally, not yet at the hosts"); skipped for a store without hosts. Other writes stay local and go out with the next networked command.
- **Write output**: `create` prints the tid; other writes print the commit id (nothing when nothing changed).
- **Hosting**: `hosting show` prints `host.0^` (lines `listen URL`, `admit own|open`, `label ID`, `replicate ADDR`, `policy NAME N`, `cap ID ENTRIES BYTES`; one JSON object; exit 3 when not hosting), `hosting off` stops (`set_hosting(None)`), `hosting set FLAGS` writes it: `--listen URL`, `--admit own|open`, `--label GROUP|ID`, `--replicate ADDR`, `--policy NAME=N`, `--cap GROUP|ID=ENTRIES,BYTES`, each repeatable; a flag given replaces its whole field, the rest kept, and one `''` clears it; from off it starts with `own` and no listener. A label is 32 hex digits or a group synced here, standing for its current labels (`status` lists them per group: the owner of a group gives them to a host that does not read it); a label set by ID or group stops matching once the group's label is replaced. Policy knobs are osis-host `HostPolicy` field names (unknown: exit 7). These stay local (the host runs under `serve`).
- **`serve [HOSTING FLAGS]`**: the one long-running command. Flags given write `host.0^` first, as `hosting set`; then, while it hosts, the host address `<url>#<key>` is the first stdout line (`{"host": …}` with `--json`; exit 6 if it does not listen within 30 s); then sync and diagnostics until SIGINT or `--timeout`. Without `host.0^` it is a node that syncs and serves co-readers. A fresh box: `osis init`, then `osis serve --listen quic://0.0.0.0:7400 --admit open`. The host store is `<store>/host.redb`.
- **`inspect`** is `Debug` dumps over `osis::internals::Internals::engine` (commits per aspect, CRDT state, items of a group, pending commits, actor epochs, headers). Not stable.

## Deviations from the original design (the deleted CLI plan)
- `commits --limit N` is `--max N` (`--limit` is the global materialization bound).
- `same` false exits 3 (§6 table) rather than 1 (§4 text).
- `edit` takes the whole aspect: the API's `edit(base, new)` has no path form.
- `-v` is accepted and ignored (no engine log sink yet).
- `diag --since` dropped: there is no stored diagnostics log yet.
- `init --host`, `restore --host`, `pair join --host` seed `Config.hosts`. Commands that talk to other nodes (`init` with hosts, `restore`, `pair`, `device rm`, `demote`, `link redeem/revoke`, `card import`, `status`, `sync`, `wait`, `serve`, `signal`, `watch`, `roster --watch`, `diag --follow`) open the store with sync on `Runtime::Own` over QUIC; the others stay local (`Runtime::None`) and their writes go out with the next networked command.
- Pairing is two lines carried by the user (the API is transport-agnostic): `pair offer` prints the offer, reads the request on stdin, prints the reply and the new node; `pair join OFFER` prints the request and reads the reply on stdin.
- `roster T --watch` added for `watch_roster`.

## Command table
Every public `Osis` method appears here (checked by tests/it/cli.rs). Now = works; 2nd = Unsupported (API piece not built).

| command | API | state |
|---|---|---|
| `init [--host A]` | `create` (prints the recovery card first) | now |
| `restore CARD` (or `@FILE`, `-`) | `restore` | now |
| `whoami` | `me`, `node`, `home`, `hosts` | now |
| `pair offer` / `pair join OFFER` | `pair_offer`, `pair_accept` / `pair`, `Joining::finish` (the two devices exchange one line each over stdin/stdout: request, reply) | now |
| `device ls` / `device rm N` | `devices` / `remove_device` | now |
| `hosts ls/add/rm` | `hosts`, `add_host`, `remove_host` | now |
| `hosting show/set/off` | `hosting` / `set_hosting` (`--label GROUP`: `status`'s labels) / `set_hosting(None)` | now |
| `serve [hosting set flags]` | `hosting`, `set_hosting`, `host_address`, then as `diag --follow` | now |
| `create --owner A [--in G\|--in-all G,G] [--group] [AK V]…` (nothing durable: exit 2, the thing would vanish at exit; `--in`/`--group` alone are ephemeral writes) | `write`, `Write::create`, `place`, `make_group`, `set`, `commit` | now |
| `get T AK [PATH]` | `get`, `at().path().get_value()`; `--stream` / `--len`: `stream()` (raw bytes to stdout) / its `len` | now |
| `set` / `replace` / `rm T AK [PATH] [V]` | `AspectWrite::set/replace/remove`, path ops; `set --stream` (value on stdin): `set_stream` | now |
| `op T AK PATH OP ARGS` | `PathWrite` ops | now (`undelete` 2nd; untyped sequence ops fail in the crdt) |
| `edit T AK --base V` (stdin) | `write_with`, `edit` | now |
| (none: interactive editors only) | `edit_text` (text sessions) | |
| (none: a CLI process is not there to keep a value alive) | `keep_alive` | |
| `write` (stdin) | one `write` batch | now |
| `show T` | `aspects`, `get`, `knows` (`state present/deleted`), `groups_of`, `role_on`, `owner_of`, `created`, `changed` | now |
| `aspects T` / `delete T` | `aspects` / `Write::delete` | now |
| `ls G` / `backlinks T` | query / backlinks | 2nd (no API yet) |
| `watch T [AK]` | `at().on_change` / `watch_thing` | now |
| `commits [SCOPE] [--actor A] [--kind K] [--reverts C] [--reverted-by C] [--in-effect B] [--since/--until TS] [--after C] [--max N] [--next undo\|redo]` / `undo` / `redo` / `revert C` | `commits` / `undo` / `redo` / `revert` | now |
| `place` / `unplace` / `sub add/rm` / `groups` | `Write::place/unplace/add_subgroup/remove_subgroup`, `groups_of` (lines `item`/`subgroup`/`within` TAB group) | now |
| `roster T [--watch]` / `role T` / `via T HOLDER` | `roster`, `watch_roster` / `role_on` / `holder_path` | now |
| `now` | `now` | now |
| `grant` / `edge` / `demote` / `leave` | `grant` / `change_edge` / `demote` / `leave` | now |
| `share-into T G ROLE [--subgroup] [--place-anyway]` / `remove-edge-of G T` / `reach T` | `share_into` / `remove_edge_of` / `reach` | now |
| `link make/redeem` / `link ls/revoke [--joiner A]` | `make_link` / `redeem` / `links`, `revoke_link`, `revoke_joiner` | now |
| `card show/import/profile [PERSON]` | `contact_card` / `import_contact` / `profile`, `profile_of` | now |
| `invite ls/accept/decline` | `invite_requests` / `accept_invite` / `decline_invite` | 2nd (`InviteId` has no text form yet) |
| `move T OWNER (--in G…)` / `same A B` | `move_thing` / `same_thing` | now |
| `status [--watch]` / `sync` / `wait` | `status`, `watch_status` (lines `group state last_sync labels`, labels comma-separated, `-` for none) / `sync_now`, `wait_synced` | now |
| `group sync/unsync/policy` | `sync` / `unsync` / sync_policy | now (policy 2nd) |
| `bundle export/import` | `export_bundle` / `import_bundle` | now |
| `inspect thing/group/actor/commit` | `Internals::engine` (`osis::internals`, doc-hidden), `read`, `knows` | now |
| `diag [--follow]` | `on_diagnostic`, `settle` | now (no stored log yet) |
| `schema add/rm/ls` / `check` / `gen` | `register_schema_file` (each run) / osis-schema `check_lock` / `generate_file` | now |
| (internal) | `open`, `close`, `downgrade`, `key`, `at`, `write_with`, `materialize_limit` (`--limit`), `register_schema`, `register_schema_source`; test hooks `sync_engine`, `take_actions`, `feed`, `waiting` live on `osis::internals::Internals` | |

## Value syntax
CBOR diagnostic notation narrowed to one printed form per value. Printer: `cli/src/text.rs` `print`; parser `parse`; property test: `parse(print(v)) == v`, numbered and named.
```text
value  := string | blob | "true" | "false" | int | float | tid | list | map | set | enum | tag | alias
string := JSON string ("\u" escapes incl. surrogate pairs; printer escapes ", \, controls, DEL)
blob   := "h'" hex "'"  |  "b64'" base64 or base64url, padding optional "'"   (input only)
int    := "-"? digits                          (i64; no leading zeros)
float  := "-"? digits ("." digits)? (("e"|"E") ("+"|"-")? digits)?  with "." or exponent
        | "NaN" | "Infinity" | "-Infinity"     (printer: Rust's shortest round-trip form; -0.0)
tid    := "osis://" 20 base64url chars
list   := "[" (value ","?)* "]"                set := "#{" (value ","?)* "}"
map    := "{" (key ":" value ","?)* "}"        key := value | field-name (typed struct) | "name"
enum   := "#" (u64 | case-name) ("(" value ")")?
tag    := "tag(" u64 "," value ")"             (unknown tag; content as its value, or h'…' raw if undecodable)
alias  := "me" | "node" | "home" | "$" name   (input only)
typed  : timestamp := RFC 3339 (bare; `T` separator; real calendar dates; printed UTC, ms when nonzero; ints accepted)
         duration  := "-"? (digits ("d"|"h"|"m"|"s"|"ms"))+   (printed largest unit first; "0s")
```
- A struct prints as a map with field names (unknown ids numbered); untyped it is a map with int keys. Option is `#none` / `#some(v)`. Timestamps outside years 0..=9999 print as ints.
- Whitespace anywhere between tokens; trailing commas allowed; duplicate map keys or set elements are errors; `null` is not a value. JSON input works where it is unambiguous: string-keyed objects read as maps, or with a schema as the struct (quoted field names).
- Paths: `.name`/`.id` field, `#name`/`#id` case payload, `[i]` list index, `[value]` map key, `{value}` set element; concatenated; empty = the aspect.
- Flags: durations `30s`, `5m`, `1h30m`, `0`; timestamps RFC 3339 or ms; retention `by=NAME,at_least=DUR,at_least_abs=TS,at_most=DUR,at_most_abs=TS` over the key's default; roles `read`, `write`, `admin` (`remove` on `demote`). Arguments: literal, `@FILE`, or `-` (stdin).

## JSON mapping
One JSON document per command; streaming commands print JSON lines. int → number; float → number with `.` or exponent, `"NaN"`/`"Infinity"`/`"-Infinity"` strings; string → string; tid → `"osis://…"`; blob → `{"$blob": base64url}`; set → `{"$set": [...]}`; enum → `{"$case": name-or-id, "$payload": v}` (payload omitted when none); typed struct → object by field name (unknown ids as decimal strings); map with only string keys, none of them a marker (`$blob`, `$set`, `$case`, `$payload`, `$map`, `$tag`, `$bytes`) → object; every other map (untyped int keys included) → `{"$map": [[k, v], …]}`, so an object never reads as a marker form; unknown tag → `{"$tag": N, "$bytes": base64url of the content}`; timestamps and durations stay ms ints. Results name tids by API names (`tid`, `actor`, `node`, `me`, `home`, `commit`). Errors on stderr: `{"error": {"kind", "message", "tid", "needs"}}`; kind is the API `Error` variant, `Usage`, `Cli` or `Other`.

## Exit codes
| code | meaning |
|---|---|
| 0 | ok |
| 1 | other: `Storage`, `Closed`, `NotUndoable`, `Unsupported`, I/O |
| 2 | usage, unparsable argument or value |
| 3 | `UnknownThing`, `UnknownActor`, absent on `get`, `same` false, nothing to undo/redo |
| 4 | `Permission` |
| 5 | `TooLarge`, `Type` |
| 6 | `Network`, `Unsynced`, timeout |
| 7 | `Invalid` (also a schema that does not parse or check) |
| 8 | store missing, locked, or (on `init`) not empty |

## Tests
tests/it/syntax.rs (round trips as properties, printed forms, JSON mapping); tests/it/cli.rs (in-process runs on memory and temp-dir stores: commands, exit codes, lock, `write` atomicity, undo, schema forms, streams, the local sharing commands, Unsupported commands, the command-table coverage check). Tier 2: tests/it/localhost.rs runs the binary against a real `osis serve` with three store directories (notes/testing.md).

## Not built
A long-running process other invocations proxy to (so the CLI can inspect a store an app holds open; the lock is the answer for now); `edit_text` sessions (keystroke editing is a UI concern; `edit` covers scripts); shell completion, REPL, colour, paging; aliases beyond `me`/`node`/`home`; bearer read (`open_link`).
