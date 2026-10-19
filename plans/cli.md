# osis CLI
> Summary: Design and build `osis-cli` (binary `osis`): a plain command-line front for everything the `osis` crate does, for scripts, debugging and agents. One invocation opens the store, acts, closes; a textual value syntax that reads back in; `--json` for machines; named keys when a schema is registered, numbered otherwise; every API feature has a command; inspection commands expose the engine's innards; `serve` runs a blind server. Not a product UI.
> Tags: api, tests, cli

Crate: `crates/osis-cli`, binary `osis`. Depends on: osis (the API; nothing below it except where inspection needs osis-node diagnostics), osis-schema (DSL, codegen), osis-server (`serve`). Unblocks: apps-e2e (localhost e2e is driven through the CLI), hardening-signoff.
Reference: notes/api.md (every command maps onto one call there), spec/data-model.md §1, §3–§5 (text forms), plans/server.md (binary config). Spec trumps this plan. `anyhow` and `clap` are allowed here (notes/architecture.md §5).

## 1. Principles
- **One call per command.** A command is a thin wrapper over one API call (a few compose two). The CLI contains no logic of its own beyond parsing and printing; anything that feels like CLI logic belongs in the API.
- **Complete.** Every public operation of the `osis` crate is reachable. A feature without a command is a bug in this crate (file an issue).
- **One process at a time.** An invocation opens the store exclusively, acts, flushes and exits. Long-running commands (`watch`, `signal listen`, `ls --follow`, `status --watch`, `diag --follow`, `daemon`, `serve`, `pair offer`) hold it until stopped or `--timeout`. Sync happens while the store is open; `sync` and `wait` exist for scripts that need "everything is at a server".
- **Text in, text out.** Values, tids, paths, links and cards use one textual syntax for arguments and output, so output can be pasted back as input. `--json` gives a machine form of the same.
- **Honest about names.** Field and case names print only when a registered schema covers the AK; otherwise numbered keys, never guesses. `--raw` forces numbers.
- **No hidden state.** The store directory plus `<store>/cli.toml` (registered schema paths) is everything. No aliases, no caches.
- **Scriptable failure.** One line on stderr, exit code by error category (§6). `--json` errors are JSON on stderr.

## 2. Global flags and environment
- `-s, --store DIR`: the store (env `OSIS_STORE`; default `$XDG_DATA_HOME/osis/default`). One person per store; a second person is a second directory. Locked by the opening process; a second opener fails with `store in use by pid N` (exit 8).
- `--json`: machine output (§5). `--raw`: numbered keys and ms timestamps even with a schema. `--schema FILE` (repeatable): use this schema for this invocation in addition to registered ones.
- `--timeout DUR` (default `30s`, `0` = forever) for anything that waits: restore, pair, redeem, demote, wait, sync, watch, listen. `-q` only errors; `-v`/`-vv` engine logs on stderr.
- `--server ADDR` (repeatable) on `init`, `restore`, `pair join`: seed servers; otherwise the store's list.
- `--limit BYTES`: this invocation's materialization bound (default the API's 64 MiB).
- Argument values: a literal, `@FILE` (contents of a file), or `-` (stdin). Applies to values, links, cards, offers, bundles.

## 3. Text forms
- **Tid**: `osis://` + 20 base64url chars; bare accepted as input. Aliases as input: `me` (person actor), `node` (this device), `home` (the person's home group). Output always prefixed.
- **AK**: as the spec, `/note/body`. Core AKs single-segment.
- **Path** (steps of notes/api.md `Path`): `.title` or `.1` field (name needs a schema), `#some` or `#1` enum case payload, `[2]` list index, `["k"]` / `[3]` / `[<value>]` map key, `{<value>}` set element. Concatenated: `.tasks[2].done`, `.3[2].2`. Empty path = the whole aspect.
- **Value**: CBOR diagnostic notation (RFC 8949 §8) narrowed and extended so every osis value has exactly one printed form:
  | type | form |
  |---|---|
  | string | `"…"` with JSON escapes |
  | blob | `h'00ff'`, or `b64'…'` as input only |
  | bool, int | `true`, `-3` |
  | float | always with `.` or exponent: `1.0`, `2.5e-3`, `NaN`, `Infinity`, `-Infinity`, `-0.0` |
  | tid | `osis://…` bare in the value (no quotes) |
  | list | `[a, b]` |
  | map / struct | `{k: v, …}`; keys any value; a struct is a map with int keys; with a schema, field names unquoted: `{title: "x", done: true}` (names are rewritten to ids before encoding) |
  | set | `#{a, b}` |
  | enum | `#3` or `#3(payload)`; with a schema `#none`, `#some(5)` |
  | timestamp / duration (typed only) | RFC 3339 / `1d2h30m5s500ms`; raw: the int |
  | unknown tag | `tag(N, <bytes h'…'>)` (output only) |
  | link | never printed (the API materializes or fails `TooLarge`) |
  Whitespace and trailing commas allowed on input. JSON is accepted as input where it is unambiguous (string-keyed objects read as `map<string, _>`; with a schema, as the struct).
- **Durations** in flags: `30s`, `5m`, `2h`, `1d`, combinations. **Timestamps** in flags: RFC 3339 or ms since epoch.
- **Server address**: the API's `ServerAddr` string (URL + key). **Links, cards, pair offers**: the API's text form; `init` and `card show` print them as one line.
- **Scopes** (undo, history): `--thing T`, `--aspect T AK` (repeatable), `--group G`.
- **Roles**: `read`, `write`, `admin`; `remove` where a demotion allows it.

## 4. Commands
Each line: command → API call. Options not listed follow the API's parameters by the same names.

**Identity and devices**
- `init [--server ADDR]…` → `Osis::create`. Prints the recovery card (text) and the tids of `me`, `node`, `home`. Refuses a non-empty store.
- `restore CARD [--server ADDR]…` → `Osis::restore` (waits for the home group to sync).
- `whoami` → `me`, `node`, home group, servers, store path, software revision.
- `pair offer` → `pair_offer`: prints the offer, waits for `done`, prints the new node's tid. `pair join OFFER` (on a fresh store) → `Osis::pair`.
- `device ls` → `devices`. `device rm NODE [--sync required|try|skip] [--backdate TS]` → `remove_device`.

**Servers and serving**
- `server ls|add ADDR|rm ADDR` → `servers`, `add_server`, `remove_server`.
- `serve [--config FILE] [--listen ADDR] [--data DIR] [--key FILE]` → the osis-server binary's main (plans/server.md); prints its `ServerAddr` as the first stdout line so scripts can capture it; stops on SIGINT.

**Things and aspects**
- `create --owner ACTOR (--in G | --in-all G,G | --unsynced) [--group] [AK VALUE]…` → `Write::create` plus a `set` per given pair, one commit. `--group` adds an empty `/group`. Prints the tid.
- `get T AK [PATH] [--stream] [--len]` → `get` / `at().path().get_value()`; typed form when a schema covers the AK. `--len` prints the canonical size. `--stream` copies a large string or blob to stdout raw. Absent prints nothing and exits 3.
- `set T AK [PATH] VALUE` → `set` (structural diff); `replace T AK [PATH] VALUE` → `replace`; `rm T AK [PATH]` → `remove`. `--stream` on `set`/`replace` reads stdin into a `blob`/`string` position without materializing (`set_stream`). Write flags on all of them: `--expires-in DUR`, `--expires-at TS`, `--retention SPEC`.
- `op T AK PATH OP ARGS…` → the remaining path ops: `insert I V…`, `delete A..B`, `move A..B TO`, `splice A..B "s"`, `undelete A..B`, `add V`, `remove-elem V`, `put K V`, `remove-key K`, `inc N`, `observe V`, `set-case ID [V]`.
- `edit T AK [PATH]` → `edit(base, new)`. Interactive when stdin is a terminal: the current value opens in `$EDITOR`, the diff is written. Otherwise `--base VALUE` (what the script showed) and the new value from stdin, so a script never clobbers a concurrent change.
- `write < SCRIPT` → one `Write`, one commit. Each script line is a `create`/`set`/`replace`/`rm`/`op`/`place`/`unplace`/`sub`/`delete` line without the `osis` prefix; `create … --as NAME` binds `$NAME` for later lines. Prints the commit id and every bound tid.
- `show T` → every aspect with its value (truncated to `--width`, default one line each), `/groups`, `role`, `/moved`, `/was`. The first thing to run when debugging.
- `aspects T` → `aspects`. `delete T` → `Write::delete`.
- `ls G [--with AK] [--order time|PATH] [--page N] [--follow]` → `query`. `backlinks T [--follow]` → `backlinks`.

**Watching and signals**
- `watch T [AK] [--count N]` → `on_change` / `watch_thing`: one line per change (source, actor, node, ts, value), initial value first; ends on `--count`, `--timeout` or SIGINT.
- `signal send T KIND VALUE [--to NODE]` → `send_signal`. `signal listen T KIND [--count N]` → `on_signal`.

**History and undo**
- `history SCOPE [--limit N] [--before TS]` → `history`; `undo SCOPE`, `redo SCOPE` → `undo`/`redo`; `undo-commit ID` → `undo_commit`.

**Groups**
- `place T G`, `unplace T G`, `sub add G SUB`, `sub rm G SUB` → the `/group` path ops. `groups T` → `groups_of`.

**Sharing and membership**
- `roster ACTOR` → `roster`; `role T` → `role_on`.
- `grant T MEMBER ROLE [--until TS] [--invite ROLE]` → `grant`. `edge T MEMBER [--role R] [--until TS] [--invite R]` → `change_edge`.
- `demote T MEMBER ROLE|remove [--sync required|try|skip] [--backdate TS]` → `demote` (default `required`). `leave T` → `leave`.
- `link make T ROLE [--until TS] [--single-use]` → `make_link` (prints the link). `link redeem LINK` → `redeem` (prints the tid). `link ls T` → `links`. `link revoke ID [--sync …]` → `revoke_link`.
- `card show` → `contact_card`. `card import CARD` → `import_contact` (prints the actor tid).
- `move T NEW_OWNER (--in G | …)` → `move_thing` (prints the new tid). `same A B` → `same_thing` (exit 0 or 1).

**Sync**
- `status [--watch]` → `status` / `watch_status`: connectivity, then one line per synced group (state, pending uploads, last sync).
- `sync [--group G]` → `sync_now` then `wait_synced` (scope All or the group) within `--timeout`. `wait [--group G]` → `wait_synced` only.
- `group sync G [--server ADDR]…` → `sync` (default the store's servers). `group unsync G` → `unsync`. `group policy G [--publish-reach BOOL] [--heartbeats BOOL]` → `sync_policy`.
- `bundle export G… > FILE` → `export_bundle`. `bundle import < FILE` → `import_bundle`.

**Inspection and diagnostics** (engine-level, output format not stable, needs osis-node's diagnostic surface)
- `inspect thing T`: per aspect: held commits, fragments, retention, expiry, canonical size, chunking; placements; creation record check.
- `inspect group G`: labels with steps, servers, must-hold sets, what is held and missing, pending uploads, replaced labels.
- `inspect actor A`: keysets per role with epochs, roster timeline, tenures, which secrets this node holds.
- `inspect commit ID`: header, decoded deltas, signature and authorization result.
- `diag [--follow] [--since TS]` → `on_diagnostic` plus the store's recent diagnostics log.
- `daemon`: keep the store open: sync continuously, print diagnostics and status changes. For a device that has no app running.

**Schemas**
- `schema add FILE` / `rm FILE` / `ls`: register paths in `<store>/cli.toml`; files are parsed on every run, errors reported with file:line:col.
- `schema check FILE` → parse plus the additive checker against `FILE.lock`. `schema gen FILE -o DIR` → the osis-schema codegen.

## 5. Output
- Text mode: one value per line for `get`; aligned tables for lists (`ls`, `roster`, `device ls`, `status`); `show` prints `AK<TAB>value`. Tids prefixed. Nothing decorative.
- `--json`: one JSON document per command; streaming commands (`watch`, `signal listen`, `ls --follow`, `status --watch`, `diag --follow`, `daemon`) print JSON lines. Values map to JSON as: int → number without fraction, float → number with fraction or exponent (`NaN`/`±Infinity` as strings `"NaN"`…), tid → `"osis://…"`, blob → `{"$blob": "base64"}`, set → `{"$set": [...]}`, enum → `{"$case": id-or-name, "$payload": v}` (payload omitted when none), map with non-string keys → `{"$map": [[k, v], …]}`, string-keyed map and struct → object (field names with a schema, else decimal-string ids), unknown tag → `{"$tag": N, "$bytes": "base64"}`. Every result carries the tids it refers to as strings under their API names (`tid`, `actor`, `node`, `commit`).
- Errors: text `error: <message>` on stderr; `--json` `{"error": {"kind": "<Error category>", "message": …, "tid": …, "needs": …}}` on stderr.

## 6. Exit codes
| code | meaning | API error |
|---|---|---|
| 0 | ok | |
| 1 | other failure | `Storage`, `Closed`, anyhow |
| 2 | usage, unparsable argument | |
| 3 | not found or absent | `UnknownThing`, `UnknownActor`, absent aspect on `get`, `same` false |
| 4 | not allowed | `Permission` |
| 5 | data does not fit | `TooLarge`, `Type` |
| 6 | could not reach or sync in time | `Network`, `Unsynced`, timeout |
| 7 | invalid input | `Invalid` |
| 8 | store locked or missing | |

## 7. Not in this plan
- A daemon that other invocations proxy to over a local socket, so the CLI can inspect a store an app holds open. The lock is the MVP answer; an issue records the gap when it bites.
- `edit_text` sessions: keystroke-granular editing is a UI concern; `edit` covers the CLI's case (one diff per invocation).
- Shell completion, a REPL, colour, paging. Aliases beyond `me`/`node`/`home`. Bearer read (`open_link`) follows the API if it lands.

## Steps
- [ ] Skeleton: clap tree per §4 (every command parses, unimplemented ones fail "not yet"), store resolution and lock, global flags, error-to-exit mapping, `--json` plumbing; `init`, `whoami`, `server`, `create`, `get`, `set`, `replace`, `rm`, `show`, `aspects`, `delete`, `place`/`unplace`/`sub`/`groups`.
- [ ] Value syntax: parser and printer for `Value` (numbered) with the round-trip property test (`parse(print(v)) == v` over the osis-core generator) and the JSON mapping; paths; schema registration and named forms; `op`, `edit`, `write`.
- [ ] `watch`, `signal`, `history`/`undo`/`redo`/`undo-commit`, `ls`, `backlinks`, large values (`--stream`, `--len`, `--limit`).
- [ ] Sharing, devices, links, cards, `move`, `same`; sync commands, bundles; `serve`; `pair`, `restore`.
- [ ] `inspect`, `diag`, `daemon`, `schema`; the two-store localhost e2e (plans/apps-e2e.md) scripted entirely through `osis`; README with a ten-line session.

## Tests
Tier 1: value syntax round trip and JSON mapping (property); argument parsing for every command (clap's `debug_assert`); exit codes per error; `write` script atomicity in a memory store. Tier 2: a shell-level test running two stores and `osis serve` on localhost: init, pair, share by link, concurrent `set` and `edit`, `sync`, `status`, `undo`, `bundle` round trip, `inspect` on the result. A checklist test that every `Osis` public method name appears in the command table (grep over the API's rustdoc list), so coverage cannot silently drift.

## Done when
Every notes/api.md operation has a command; the localhost e2e runs through the CLI; a fresh agent given only `osis --help` and `osis show` can read and change data in a store. Delete this plan; §3, §5 and §6 move to notes/cli.md.

## Progress
