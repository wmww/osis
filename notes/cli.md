# CLI
> Summary: `osis-cli` (binary `osis`): one invocation opens the store, acts, closes (or, while `osis serve` holds it, runs as that daemon's client over its unix socket); the command table over the `osis` API (which commands work, which report Unsupported for API pieces not built); the value syntax grammar (read back what it prints, numbered or named); the JSON mapping; exit codes; design decisions and deviations from the original plan.

## Design
- **Thin**: a command is one API call plus parsing and printing (`cli/src/cmd.rs`, `write.rs`). Missing API pieces surface as the API's `Unsupported` (exit 1, kind `Unsupported`), never as CLI workarounds. Commands whose API method does not exist yet (`ls`, `backlinks`, `group policy`, `op undelete`; issues/api-deferred.md) report Unsupported from the CLI with the method's name.
- **Store**: `-s DIR` / `OSIS_STORE` / `$XDG_DATA_HOME/osis/default`. Missing (`db.redb` absent): exit 8. Locked: if `<store>/sock` names a socket a daemon (`osis serve`) answers on, the invocation attaches to it (`Osis::attach`, Owner tier, notes/client-port.md) and runs the whole command there, same output and exit codes; else exit 8. `inspect` (needs the engine) and `serve` never attach (exit 8 while locked). Every other command runs through it, also those that wait on other nodes (`link redeem/revoke`, `demote`, `device rm`, `card import`, `chat join/kick`, `wait`: they wait at the node, notes/client-port.md §2; the node's own `wait_timeout` bounds each of its waits, `--timeout` only drops the call sooner), except `group source` (exit 1 saying so: its attachment and secret live in the process holding the store) and any call on a group the node routes elsewhere (exit 1 `Unsupported`, notes/client-port.md §8). One process per store holds only while no daemon runs. The lock is redb's file lock; the CLI writes its pid to `<store>/pid` after opening so a second opener says `store in use by pid N`. `init` refuses a non-empty directory (exit 8). `<store>/cli.toml` holds registered schema paths (`schemas = [ "…", ]`, one quoted path per line; absolute). No other state.
- **Entry points**: `osis_cli::main_with(args, stdin, stdout, stderr) -> i32`; `osis_cli::run(args, Option<StoreSel>, Io)` also takes a memory store (tests) and the terminal flag (`edit` opens `$EDITOR` only on a terminal).
- **Futures** (`restore`, `demote`, `redeem`, `import_contact`, `remove_device`, `revoke_link`, `revoke_joiner`, `wait_synced`): polled on the calling thread by a park/unpark waker with the `--timeout` deadline (exit 6; `wait_synced` on its own deadline, `wait_sync`: an `Unsynced` naming a `Refused` group says "host ADDR does not admit group URI (yet)" (`sync`, `wait`, delivering commands); `init --host` does not wait, so a refused home shows only in `status`); sync runs on the API's own runtime. Each invocation ends with `Osis::close`, which waits until the store is free.
- **Streaming** (`watch` (signal aspects too), `roster --watch`, `diag --follow`, `serve`): until `--count` changes (the initial lines of `watch` and `roster --watch` are printed, not counted), `--timeout` or SIGINT (default action: the process dies; commits are already durable). Streaming commands have no default timeout; `--timeout` reached with `--count` unmet: exit 6, without `--count`: exit 0. `diag --follow` and `serve` exit 6 once the sync driver died (after printing its `SyncStopped` line). Other waits default to 30 s. `--timeout 0` is no deadline (deadlines use checked arithmetic; the API's `Duration`-taking `wait_synced` gets a 100-year bound).
- **Named keys**: `db.key(ak)` types an AK by a registered schema (`schema add`, `--schema FILE`) or the core schema. Reads print named forms through the typed view (reader defaults filled); `--raw` uses the untyped key: stored value, numbered forms, ms. Writes through a typed key are validated (exit 5); `--raw` writes untyped.
- **Paths**: typed positions follow the type. `[n]` on an untyped position: `get` reads the saved value (a list: index; else map key). Writes (`set`, `replace`, `rm`, `op`, script lines) take it as a map key, and refuse it (exit 2) when the saved value there is a list (untyped lists take no index writes; register a schema) or when the same batch already wrote that aspect or created/deleted the thing (`write` scripts: the pending state is invisible to reads, so the saved state cannot decide). Never a silent map write over a list.
- **Commit ids** print as 64 lower-case hex digits (input for `revert`, `commits --reverts/--reverted-by/--after`, `inspect commit`).
- **`write` scripts**: lines are tokenized at whitespace outside quotes and brackets, so a value is one token with its quotes kept; a token wholly in single quotes loses them (`''` is the root path). `$NAME` (from `create --as NAME`) works as a tid argument and inside values. Errors from a line's arguments carry `line N`; rights and unknown things are checked at commit (no line). Output: the commit id (or `-`), then `NAME<TAB>tid` per bound name.
- **`edit` on a terminal**: the value goes to a new temp file (`create_new`, random name, mode 0600, in `$XDG_RUNTIME_DIR` when set), then `$EDITOR`; the file is removed whatever the editor does.
- **Delivering commands** (`grant`, `share`, `edge`, `leave`, `share-into`, `remove-edge-of`, `link make`, `card show`, `group sync`): their API call queues inbox deposits or a new label's first commits that the engine holds only in memory, so they open with sync on and end with `sync_now` + `wait_synced(All)` within `--timeout` (exit 6 "done locally, not yet at the hosts"); skipped for a store without hosts. The sharing ones (`grant`, `share`, `edge`, `share-into`, `link make`) first wait `Group(t)` of the shared thing, so one in a hostless group (or held by no synced group) exits 6: its holders can never fetch it. No in-process test: a memory store cannot hold a hostless group beside hosts (`hosts add` moves its own labels); the API side is `sync::wait_synced_all_waits_for_deliveries_without_hosted_groups`. Other writes stay local and go out with the next networked command.
- **Write output**: `create` prints the tid; other writes print the commit id (nothing when nothing changed).
- **Hosting**: `hosting show` prints `host.0^` (lines `listen URL`, `address URL#KEY` per listen URL once the host secret exists (made at the first `hosting set`, so without serving; `host_key`; none for a port 0, picked only when `serve` listens), `admit own|open`, `label ID`, `replicate ADDR`, `policy NAME N`, `cap ID ENTRIES BYTES`; one JSON object; exit 3 when not hosting), `hosting off` stops (`set_hosting(None)`), `hosting set FLAGS` writes it: `--listen URL`, `--admit own|open`, `--label GROUP|ID`, `--replicate ADDR`, `--policy NAME=N`, `--cap GROUP|ID=ENTRIES,BYTES`, each repeatable; a flag given replaces its whole field, the rest kept, and one `''` clears it; from off it starts with `own` and no listener. A label is 32 hex digits or a group synced here, standing for its current labels (`status` lists them per group: the owner of a group gives them to a host that does not read it); a label set by ID or group stops matching once the group's label is replaced. Policy knobs are osis-host `HostPolicy` field names (unknown: exit 7). These stay local (the host runs under `serve`); through a daemon the host starts, moves or stops at once, and a listen that fails (port in use) is only a line of the daemon's diagnostics: the command has exited 0 by then.
- **`serve [HOSTING FLAGS]`**: the one long-running command; it serves the client port on the store's unix socket (`osis::socket_path`: `$XDG_RUNTIME_DIR/osis/<hash>.sock`, else `/tmp/osis-<uid>/`, the directory 0700 and checked) and names it in `<store>/sock` (removed on a clean exit; a killed daemon's stays, stale: clients then exit 8 as for any lock, the next `serve` replaces it). A client follows `<store>/sock` only when it names the store's own `socket_path`. A socket directory refused (e.g. `/tmp/osis-<uid>` made first by another user) does not stop `serve`: it warns and serves without the socket (clients exit 8). Flags given write `host.0^` first, as `hosting set`; then, while it hosts, the host address `<url>#<key>` is the first stdout line (`{"host": …}` with `--json`; exit 6 if it does not listen within 30 s); then sync and diagnostics until SIGINT or `--timeout`, or exit 6 once the sync driver died (a `SyncStopped` diagnostic). The address line is a hard failure (exit 1 if it cannot be written); the diagnostic lines after it are best effort: a closed stdout (a caller that read only the address) does not end `serve` (Rust ignores SIGPIPE, so a write fails `EPIPE`; `serve` ignores it). Other streaming commands (`watch`, `diag --follow`) end on a closed stdout: their lines are what they run for. Without `host.0^` it is a node that syncs and serves co-readers. Hosting with no listen URL, it first writes `--listen quic://0.0.0.0:4040` (a `quic://` URL without a port means 4040). A fresh box: `osis init`, then `osis serve --admit open`. The host store is `<store>/host.redb`. A dedicated host device of one's own: `pair join` an empty store, `hosting set --listen quic://IP:PORT --admit own` (a fixed port), `hosting show` for the address, `hosts add ADDR` on it and the other devices, then `serve`; a group made afterwards syncs there after a back-off (about 5 s: the host device learns its label first).
- **`inspect`** is `Debug` dumps over `osis::internals::Internals::engine` (commits per aspect, CRDT state, items of a group, pending commits, actor epochs, headers). Not stable.

## Deviations from the original design (the deleted CLI plan)
- `commits --limit N` is `--max N` (`--limit` is the global materialization bound).
- `same` false exits 3 (§6 table) rather than 1 (§4 text).
- `edit` takes the whole aspect: the API's `edit(base, new)` has no path form.
- `-v` (any count) copies the node's diagnostics to stderr, formatted as `diag --follow` (`--json`: JSON lines), while a command that opens the store with sync on runs; best effort. A no-op for `serve` and `diag --follow` (they print them on stdout). Local commands print none: the diagnostics worth seeing come from sync.
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
| `hosting show/set/off` | `hosting`, `host_key` / `set_hosting` (`--label GROUP`: `status`'s labels) / `set_hosting(None)` | now |
| `clients add [--until T]` (prints `ACTOR SECRET`, once) / `clients ls` (`ACTOR UNTIL\|-`) / `clients rm ACTOR` (none: exit 3) / `clients rotate ACTOR` (prints the secret, once); through a daemon too | `add_client` / `clients` / `remove_client` / `rotate_client_secret` | now |
| (a thin client: `--node ADDR --client-secret FILE` on any command, 64 hex digits in the file; no store; commands holding a store: exit 2; process-wide ones `Unsupported`) | `attach_client` | now (end to end: `localhost::thin_cli_quic_localhost`) |
| `serve [hosting set flags] [--client-listen URL]…` (a line `client URL#KEY` per listener after the host address) | `hosting`, `set_hosting`, `host_address`, `client_listen`, then as `diag --follow` | now |
| `clients rotate-key` (prints the new addresses; through a daemon its listeners move at once) | `rotate_client_key` | now |
| `group source G local\|ADDR`, with `--remote ADDR --remote-secret FILE` on this and every later command on that store (no secret is stored; without it a routed group exits 1 `Network`); not through a daemon (exit 1) | `group_source`, `Config.remotes`, `attach_node`, `detach_node`, `await_remotes`, `routes`, `attach_remotes` | now |
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
| `history T AK [--oldest] [--before POS] [--after POS] [--max N]` (a line: `TS/COMMIT` place, time, actor, node, kind, validity, body; `--json` adds `more`, `complete`) | `AspectRef::history` | now |
| `purge T AK [--commit C \| --author A]` | `AspectWrite::purge`, `purge_commit`, `purge_author` | now |
| `commits [SCOPE] [--actor A] [--kind K] [--reverts C] [--reverted-by C] [--in-effect B] [--since/--until TS] [--after C] [--max N] [--next undo\|redo]` / `undo` / `redo` / `revert C` | `commits` / `undo` / `redo` / `revert` | now |
| `place` / `unplace` / `sub add/rm` / `groups` | `Write::place/unplace/add_subgroup/remove_subgroup`, `groups_of` (lines `item`/`subgroup`/`within` TAB group) | now |
| `roster T [--watch]` / `role T` / `via T HOLDER` | `roster`, `watch_roster` / `role_on` / `holder_path` | now |
| `now` | `now` | now |
| `grant` / `share` / `edge` / `demote [--keep B]` / `leave` / `keep-default T B` / `kept [--drop A]` | `grant` (the role alone) / `share` (`sync` when the holder has no route, then `grant`) / `change_edge` / `demote` / `leave` / `set_keep_default` / `kept_copies`, `drop_kept` | now |
| `share-into T G ROLE [--subgroup] [--place-anyway]` / `remove-edge-of G T` / `reach T` | `share_into` / `remove_edge_of` / `reach` | now |
| `link make/redeem` / `link ls/revoke [--joiner A]` | `make_link` / `redeem` / `links`, `revoke_link`, `revoke_joiner` | now |
| `chat create/add/link/join/kick/post/read/watch/edit/resend/delete/leave/members/disappear` (notes/chat.md; `read --after ID`, `watch --after ID --count N`; `--json` lines) | osis-chat over `create_ownerless`, `share`, `make_link`, `redeem`, `demote`, `history`, `on_history`, `purge_commit`, `purge_author`, `leave` | now (through a daemon too; `join` there waits a moment for the first messages, a `read` there does not pull) |
| `card show/import/profile [PERSON]` | `contact_card` / `import_contact` / `profile`, `profile_of` | now |
| `invite ls/accept/decline` | `invite_requests` / `accept_invite` / `decline_invite` | 2nd (`InviteId` has no text form yet) |
| `move T OWNER (--in G…)` / `same A B` | `move_thing` / `same_thing` | now |
| `ownerless ADMIN` (prints the tid) | `create_ownerless` | now |
| `status [--watch]` / `sync` / `wait` | `status`, `watch_status` (lines `group state last_sync labels`, labels comma-separated, `-` for none, then `thing split: writes refused`; `--json`: `{groups: [..], split: [..]}`) / `sync_now`, `wait_synced` (`All` leaves hostless labels out) | now |
| `group sync/unsync/policy` | `sync` / `unsync` / sync_policy | now (policy 2nd) |
| `bundle export/import` | `export_bundle` / `import_bundle` | now |
| `inspect thing/group/actor/commit` | `Internals::engine` (`osis::internals`, doc-hidden), `read`, `knows` | now |
| `diag [--follow]` | `on_diagnostic`, `settle` | now (no stored log yet) |
| `schema add/rm/ls` / `check` / `gen` | `register_schema_file` (each run) / osis-schema `check_lock` / `generate_file` | now |
| (any command while `serve` runs) | `attach`, `is_attached`, `listen_unix` (by `serve`), `node_epoch` (tests) | now |
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
Proxying through an app that holds the store (only `serve` listens); `edit_text` sessions (keystroke editing is a UI concern; `edit` covers scripts); shell completion, REPL, colour, paging; aliases beyond `me`/`node`/`home`; bearer read (`open_link`).
