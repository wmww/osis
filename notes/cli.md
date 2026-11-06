# CLI
> Summary: `osis-cli` (binary `osis`): one invocation opens the store, acts, closes (or, while `osis serve` holds it, runs as that daemon's client over its unix socket); the command table over the `osis` API (which commands work, which say "not built yet" for API pieces missing); the value syntax grammar (read back what it prints, numbered or named); the JSON mapping; exit codes; design decisions and deviations from the original plan.

## Design
- **One call**: a command is one API call plus parsing and printing (`cli/src/cmd.rs`, `write.rs`). Missing API pieces say "not built yet" (exit 1, kind `Cli`), never CLI workarounds. Commands whose API method does not exist yet (`ls`, `backlinks`, `op undelete`; issues/api-deferred.md) say so with the method's name.
- **Store**: `-s DIR` / `OSIS_STORE` / `$XDG_DATA_HOME/osis/default`. Missing (`db.redb` absent): exit 8. Locked: if a daemon (`osis serve`) answers on the store's socket, the invocation is its client (`Osis::connect_socket`, as the node's main actor, notes/client-port.md) and runs the whole command there, same output and exit codes; else exit 8. `inspect` (needs the engine) and `serve` never do (exit 8 while locked). Every other command runs through it, also those that wait on other nodes (`link redeem/revoke`, `set-role`, `node rm`, `card import`, `chat join/kick`, `wait`: they wait at the node, notes/client-port.md §2; `--timeout` is sent with each), except `group source` (exit 1 saying so: its connection and secret live in the process holding the store) and any call on a group the node routes elsewhere (exit 1 `Unsupported`, notes/client-port.md §8). One process per store holds only while no daemon runs. The lock is redb's file lock; the CLI writes its pid to `<store>/pid` after opening so a second opener says `store in use by pid N`. `init` refuses a non-empty directory (exit 8). `<store>/cli.toml` holds registered schema paths (`schemas = [ "…", ]`, one quoted path per line; absolute). No other state.
- **Entry points**: `osis_cli::main_with(args, stdin, stdout, stderr) -> i32`; `osis_cli::run(args, Option<StoreSel>, Io)` also takes a memory store (tests) and the terminal flag (`edit` opens `$EDITOR` only on a terminal).
- **Futures** (`set_role`, `redeem`, `import_contact`, `remove_node`, `revoke_link`, `wait_synced`): polled on the calling thread by a park/unpark waker and raced against `--timeout` (`cmd::within`, `0`: none): past it the future is dropped, `Network`, exit 6; connecting too (one attempt is at most `CONNECTION_WAIT`, whatever `--timeout` says). A call that catches up before writing (`set-role`, `node rm`, `link revoke`, `chat kick`) says past `--timeout` that nothing was written and that `--now` writes at once (`cmd::catching_up`); `--now` calls the API's `_now` call (`set_role_now`, `revoke_link_now`, `kick_now`; `node rm --now` is `set_role_now(me, N, None)` then `links`). `repudiate` has no `--now`. `Unsynced` is exit 6 as well (`wait_sync`: an `Unsynced`, or a timeout with a group `Refused`, says "ADDR does not admit group URI (yet)" (`sync`, `wait`, delivering commands); `init --peer` does not wait, so a refused home shows only in `status`); sync runs on the API's own runtime. Each invocation ends with `Osis::close`, which waits until the store is free. A link or card that cannot be judged within `--timeout` (`redeem`, `import_contact`, `chat join`) says "could not confirm this link yet; trying again is safe", exit 6.
- **Streaming** (`watch` (signal aspects too), `grants --watch`, `diag --follow`, `serve`): until `--count` changes (the initial lines of `watch` and `grants --watch` are printed, not counted), `--timeout` or SIGINT (default action: the process dies; commits are already durable). Streaming commands have no default timeout; `--timeout` reached with `--count` unmet: exit 6, without `--count`: exit 0. `diag --follow` and `serve` exit 6 once the sync driver died (after printing its `SyncStopped` line). Other waits default to 30 s. `--timeout 0` is no deadline (deadlines use checked arithmetic; the API's `Duration`-taking `wait_synced` gets a 100-year bound).
- **Named keys**: `db.aspect_key(ak)` types an AK by a registered schema (`schema add`, `--schema FILE`) or the core schema. Reads print named forms through the typed view (reader defaults filled); `--raw` uses the untyped key: stored value, numbered forms, ms. Writes through a typed key are validated (exit 5); `--raw` writes untyped.
- **Paths**: typed positions follow the type. `[n]` on an untyped position: `get` reads the saved value (a list: index; else map key). Writes (`set`, `overwrite`, `rm`, `op`, script lines) take it as a map key, and refuse it (exit 2) when the saved value there is a list (untyped lists take no index writes; register a schema) or when the same `write` script already wrote that aspect or created/deleted the thing (`write` scripts: the pending state is invisible to reads, so the saved state cannot decide). Never a silent map write over a list.
- **Commit ids** print as 64 lower-case hex digits (input for `revert`, `commits --reverts/--reverted-by/--after`, `inspect commit`).
- **`write` scripts**: lines are tokenized at whitespace outside quotes and brackets, so a value is one token with its quotes kept; a token wholly in single quotes loses them (`''` is the root path). `$NAME` (from `create --as NAME`) works as a tid argument and inside values. Errors from a line's arguments carry `line N`; rights and unknown things are checked at commit (no line). Output: the commit id (or `-`), then `NAME<TAB>tid` per bound name.
- **`edit` on a terminal**: the value goes to a new temp file (`create_new`, random name, mode 0600, in `$XDG_RUNTIME_DIR` when set), then `$EDITOR`; the file is removed whatever the editor does.
- **Delivering commands** (`grant`, `set-role` to a role (it may grant or raise), `leave`, `add-with-grant`, `link make`, `card show`, `group sync`): their API call queues inbox deposits or the first commits under a new sync ID that the engine holds only in memory, so they open with sync on and end with `nudge_sync` + `wait_synced(AllWithSavedPeers)` within `--timeout` (exit 6 "done locally, not yet at its peers"); skipped for a store without saved peers. `add-with-grant` and `link make` first wait on the shared thing's groups, so one in a group with no saved peer (or held by no synced group) exits 6: its holders can never fetch it. `grant` records the role, route or no route (`status` shows it). No in-process test: a memory store cannot hold a group with no peers beside one with some (`peers add` moves its own groups); the API side is `sync::wait_synced_waits_for_deliveries_without_peered_groups`. Other writes stay local and go out with the next networked command.
- **Write output**: `create` prints the tid; other writes print the commit id (nothing when nothing changed).
- **Serving** (a node storing and serving data for others, `Osis::serving`): `serving show` prints the terms (lines `listen URL`, `address URL#KEY` per listen URL once the serving key exists (made at the first `serving set`, so without running `serve`; `serving_key`; none for a port 0, picked only when `serve` listens), `admit own|open`, `admitted ID`, `replicate ADDR`, `policy NAME N`, `cap ID ENTRIES BYTES`; one JSON object; exit 3 when not serving), `serving off` stops (`set_serving(None)`), `serving set FLAGS` sets them: `--listen URL`, `--admit own|open`, `--admitted GROUP|ID`, `--replicate ADDR`, `--policy NAME=N` (`group_entries`, `group_bytes`, `groups`, `entries`, `bytes`, `connections`, or a tuning knob by the engine's name), `--cap GROUP|ID=ENTRIES,BYTES`, each repeatable; a flag given replaces its whole field, the rest kept, and one `''` clears it; from off it starts with `own` and no listener. A sync ID is 32 hex digits or a group synced here, standing for its current ones (`serving ids GROUP` lists them: a holder of a group gives them to a serving node that does not read it); an ID stops matching once the group's sync is replaced. These stay local (serving runs under `serve`); through a daemon it starts, moves or stops at once, and a listen that fails (port in use) is only a line of the daemon's diagnostics: the command has exited 0 by then.
- **`serve [SERVING FLAGS]`**: the one long-running command; it serves the client port on the store's unix socket (`Osis::listen_socket`: `$XDG_RUNTIME_DIR/osis/<hash>.sock`, else `/tmp/osis-<uid>/`, the directory 0700 and checked; a killed daemon's stays, stale: clients then exit 8 as for any lock, the next `serve` replaces it). A socket directory refused (e.g. `/tmp/osis-<uid>` made first by another user) does not stop `serve`: it warns and serves without the socket (clients exit 8). Flags given set the terms first, as `serving set`; then, while serving, the serving address `<url>#<key>` is the first stdout line (`{"address": …}` with `--json`; exit 6 if it does not listen within 30 s); then sync and diagnostics until SIGINT or `--timeout`, or exit 6 once the sync driver died (a `SyncStopped` diagnostic). The address line is a hard failure (exit 1 if it cannot be written); the diagnostic lines after it are best effort: a closed stdout (a caller that read only the address) does not end `serve` (Rust ignores SIGPIPE, so a write fails `EPIPE`; `serve` ignores it). Other streaming commands (`watch`, `diag --follow`) end on a closed stdout: their lines are what they run for. Without serving it is a node that syncs and answers those it shares groups with. Serving with no listen URL, it first sets `--listen quic://0.0.0.0:4040` (a `quic://` URL without a port means 4040). A fresh box taking anyone's data: `osis init`, then `osis serve --admit open`. What it stores for others is in `<store>/host.redb`. A machine of one's own that serves one's groups: `pair join` an empty store, `serving set --listen quic://IP:PORT --admit own` (a fixed port), `serving show` for the address, `peers add ADDR` on it and the other nodes, then `serve`; a group made afterwards syncs there after a back-off (about 5 s: it learns the group first).
- **`inspect`** is `Debug` dumps over `osis::internals::Internals::engine` (commits per aspect, CRDT state, items of a group, pending commits, actor epochs, headers). Not stable.

## Deviations from the original design (the deleted CLI plan)
- `commits --limit N` is `--max N` (`--limit` is the global materialization bound).
- `edit` takes the whole aspect: the API's `edit(base, new)` has no path form.
- `-v` (any count) copies the node's diagnostics to stderr, formatted as `diag --follow` (`--json`: JSON lines), while a command that opens the store with sync on runs; best effort. A no-op for `serve` and `diag --follow` (they print them on stdout). Local commands print none: the diagnostics worth seeing come from sync.
- `diag --since` dropped: there is no stored diagnostics log yet.
- `init --peer`, `pair join --peer` save the peers given. Commands that talk to other nodes (`init` with peers, `pair`, `node rm`, `set-role`, `link redeem/revoke`, `card import`, `status`, `sync`, `wait`, `serve`, `signal`, `watch`, `grants --watch`, `diag --follow`) open the store with sync on `Runtime::Own` over QUIC; the others stay local (`Runtime::None`) and their writes go out with the next networked command.
- Pairing is two lines carried by the user (the API is transport-agnostic): `pair offer` prints the offer, reads the request on stdin, prints the reply and the new node; `pair join OFFER` prints the request and reads the reply on stdin.
- `grants T --watch` added for `on_grants_change`.

## Command table
Every public `Osis` method appears here (checked by tests/it/cli.rs). Now = works; 2nd = "not built yet" (API piece not built).

| command | API | state |
|---|---|---|
| `init [--peer A]` | `create` | now |
| `whoami` | `me`, `node`, `saved_peers` | now |
| `pair offer` / `pair join OFFER` | `pair_offer`, `pair_accept` / `pair`, `Joining::finish` (the two nodes exchange one line each over stdin/stdout: request, reply) | now |
| `node ls` / `node rm N [--now] [--end-links]` | `nodes` / `remove_node`, then `revoke_link` each (`--now`: `set_role_now`, `revoke_link_now`) | now |
| `peers ls [--group G]/add/rm` | `saved_peers` (`--group`: `peers`), `add_peer`, `remove_peer` | now |
| `serving show/set/off`, `serving ids G` | `serving`, `serving_key` / `set_serving` (`--admitted GROUP`: its `sync_ids`) / `set_serving(None)`, `sync_ids` | now |
| `clients add [--until T]` (prints `ACTOR SECRET`, once) / `clients ls` (`ACTOR UNTIL\|-`) / `clients rm ACTOR` (none: exit 3) / `clients rotate ACTOR` (prints the secret, once); through a daemon too | `add_client` / `clients` / `remove_client` / `rotate_client_secret` | now |
| (a thin client: `--node ADDR --client-secret FILE` on any command, 64 hex digits in the file; no store; commands holding a store: exit 2; process-wide ones `Unsupported`) | `connect`, `AppConfig` | now (end to end: `localhost::thin_cli_quic_localhost`) |
| `serve [serving set flags] [--client-listen URL]…` (a line `client URL#KEY` per listener after the serving address) | `serving`, `set_serving`, `serving_address`, `client_listen`, then as `diag --follow` | now |
| `clients rotate-address` (prints the new addresses; through a daemon its listeners move at once) | `rotate_client_address` | now |
| `group source G local\|ADDR`, with `--connect ADDR --connect-secret FILE` on this and every later command on that store (no secret is stored; without it a group sourced there exits 1 `Network`); not through a daemon (exit 1) | `group_source`, `connect_node`, `disconnect_node`, `group_sources` | now |
| `create [--admin G] [--in G\|--in-all G,G] [AK V]…` (nothing durable: exit 2, the thing would vanish at exit; `--in` alone is an ephemeral write; `--admin` is `create_with_admin`: a thin client's way to create, and a thing a group's holders read with no grant) | `write`, `Write::create` or `create_with_admin`, `Write::group`, `set`, `commit` | now |
| `get T AK [PATH]` | `at().get()`, `at().path().get()`; `--stream` / `--len`: `path().stream()` (raw bytes to stdout) / its `byte_len` | now |
| `set` / `overwrite` / `rm T AK [PATH] [V]` | `PathWrite::set/overwrite/remove`; `set --stream` (value on stdin): `set_stream` | now |
| `op T AK PATH OP ARGS` | `PathWrite` ops | now (`undelete` 2nd; untyped sequence ops fail in the crdt) |
| `edit T AK --base V` (stdin) | `Write`, `edit` | now |
| (none: interactive editors only) | `edit_text` (text sessions) | |
| (none: a CLI process is not there to keep a value alive) | `keep_alive` | |
| `write` (stdin) | one `Write`, so one commit (a line's `--expires-*` is the commit's: two different ones exit 2; what else cannot share a commit exits 7) | now |
| `show T` | `aspects`, `get`, `has_content` (`state present/empty`: empty is deleted or never written, JSON `empty`), `groups_of`, `role_on`, `owner_of`, `created`, `changed` | now |
| `aspects T` / `delete T` | `aspects` / `Write::delete` | now |
| `ls G` / `backlinks T` | query / backlinks | 2nd (no API yet) |
| `watch T [AK]` | `at().on_change` / `on_thing_change` | now |
| `history T AK [--oldest] [--before POS] [--after POS] [--max N]` (a line: `TS/COMMIT` place, time, actor, node, kind, validity, body; `--json` adds `more`, `complete`) | `AspectRef::history` | now |
| `purge T AK [--commit C \| --author A]` | `AspectWrite::purge` (`Purge::All`, `Commit`, `Author`) | now |
| `commits [SCOPE] [--actor A] [--kind K] [--reverts C] [--reverted-by C] [--in-effect B] [--since/--until TS] [--after C] [--max N] [--next undo\|redo]` / `undo` / `redo` / `revert C` | `commits`, `undo_target`, `redo_target` (`--next`, taking only a scope) / `undo` / `redo` / `revert` | now |
| `group add G T [--subgroup] [--expires-in D\|--expires-at TS]` / `group rm G T [--subgroup]` / `groups` / `members G` | `Write::group`, `groups_of` (lines `item`/`subgroup`/`within` TAB group), `members` | now |
| `members G` (lines `item`/`subgroup` TAB thing) | `items`, `subgroups` | now |
| `grants T [--watch]` / `role T` / `holders T` | `grants`, `on_grants_change` / `role_on` / `holders` | now |
| `now` | `now` | now |
| `grant T H [ROLE] [--until] [--may-grant R]` (no ROLE: as it is) / `set-role T H ROLE\|none [--now] [--retain-copy B]` / `leave T [--holder A]` / `retained [--drop A]` | `grant` (the role alone) / `set_role` / `leave` / `retained_copies`, `drop_retained_copy` | now |
| `add-with-grant T G ROLE [--subgroup]` | `add_with_grant` | now |
| `link make/redeem` / `link ls [T]/revoke [--now]` | `make_link` / `redeem` / `links` (T filters by target), `revoke_link` (`revoke_link_now`); one joiner: `set-role T J none` | now |
| `chat create/add/link/join/kick/post/read/watch/edit/resend/delete/leave/participants/disappear` (notes/chat.md; `read --after ID`, `watch --after ID --count N`; `--json` lines) | osis-chat over `create_ownerless`, `grant`, `make_link`, `redeem`, `set_role`, `history`, `on_history`, `purge_commit`, `purge_author`, `leave` | now (through a daemon too; `join` there waits a moment for the first messages, a `read` there does not pull) |
| `card show/import/profile [ACCOUNT]` | `contact_card` / `import_contact` / `profile`, `profile_of` | now |
| `invite ls/accept/decline` | `invite_requests` / `accept_invite` / `decline_invite` | 2nd (`InviteId` has no text form yet) |
| `ownerless ADMIN` (prints the tid; transitional: `create` is this once owners go) | `create_ownerless` | now |
| `status [--watch]` / `sync` / `wait` | `status`, `on_status_change` (lines `connected N`, `group state last_sync`, then `thing two sources: writes refused`; `--json`: `{groups: [..], connected, two_sources: [..]}`) / `nudge_sync`, `wait_synced` (`AllWithSavedPeers` leaves groups with no saved peer out; `sync` and `wait` name those on stderr) | now |
| `group sync/unsync/policy [--share-address auto\|always\|never] [--mode full\|log-only]` | `sync` / `unsync` / `sync_options`, `set_sync_options` (prints `share_address X`, `mode X`) | now |
| `bundle export/import` | `export_bundle` / `import_bundle` | now |
| `inspect thing/group/actor/commit` | `Internals::engine` (`osis::internals`, doc-hidden), `read`, `has_content` | now |
| `diag [--follow]` | `on_diagnostic`, `settle` | now (no stored log yet) |
| `schema add/rm/ls` / `check` / `gen` | `register_schema` of each file (each run) / osis-schema `check_lock` / `generate_file` | now |
| (any command while `serve` runs) | `connect_socket`, `has_store`, `listen_socket` (by `serve`), `node_epoch` (tests) | now |
| (internal) | `open`, `close`, `downgrade`, `aspect_key`, `at`, `write`, `AppConfig::read_limit` (`--limit`), `register_schema`; test hooks `sync_engine`, `take_actions`, `feed`, `waiting` live on `osis::internals::Internals` | |

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
- Flags: durations `30s`, `5m`, `1h30m`, `0`; timestamps RFC 3339 or ms; retention `by=NAME,at_least=DUR,at_least_abs=TS,at_most=DUR,at_most_abs=TS` over the key's default; roles `read`, `write`, `admin` (`none` on `set-role`). Arguments: literal, `@FILE`, or `-` (stdin).

## JSON mapping
One JSON document per command; streaming commands print JSON lines. int → number; float → number with `.` or exponent, `"NaN"`/`"Infinity"`/`"-Infinity"` strings; string → string; tid → `"osis://…"`; blob → `{"$blob": base64url}`; set → `{"$set": [...]}`; enum → `{"$case": name-or-id, "$payload": v}` (payload omitted when none); typed struct → object by field name (unknown ids as decimal strings); map with only string keys, none of them a marker (`$blob`, `$set`, `$case`, `$payload`, `$map`, `$tag`, `$bytes`) → object; every other map (untyped int keys included) → `{"$map": [[k, v], …]}`, so an object never reads as a marker form; unknown tag → `{"$tag": N, "$bytes": base64url of the content}`; timestamps and durations stay ms ints. Results name tids by API names (`tid`, `actor`, `node`, `me`, `home`, `commit`). Errors on stderr: `{"error": {"kind", "message", "tid", "needs"}}`; kind is the API `Error` variant, `Usage`, `Cli` or `Other`.

## Exit codes
| code | meaning |
|---|---|
| 0 | ok |
| 1 | other: `Storage`, `Closed`, `NotUndoable`, `Unsupported`, a command not built yet (kind `Cli`), I/O |
| 2 | usage, unparsable argument or value |
| 3 | `UnknownThing`, `UnknownActor`, absent on `get`, nothing to undo/redo |
| 4 | `Permission`, `Refused` |
| 5 | `TooLarge`, `Type` |
| 6 | `Network`, `Unsynced`, timeout |
| 7 | `Invalid` (also a schema that does not parse or check) |
| 8 | store missing, locked, or (on `init`) not empty |

## Tests
tests/it/syntax.rs (round trips as properties, printed forms, JSON mapping); tests/it/cli.rs (in-process runs on memory and temp-dir stores: commands, exit codes, lock, `write` atomicity, undo, schema forms, streams, the local sharing commands, commands not built yet, the command-table coverage check). Tier 2: tests/it/localhost.rs runs the binary against a real `osis serve` with three store directories (notes/testing.md).

## Not built
Proxying through an app that holds the store (only `serve` listens); `edit_text` sessions (keystroke editing is a UI concern; `edit` covers scripts); shell completion, REPL, colour, paging; aliases beyond `me`/`node`/`home`; bearer read (`open_link`).
