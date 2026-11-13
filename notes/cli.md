# CLI
> Summary: `osis-cli` (binary `osis`): design and reasons. One invocation opens the store, acts, closes (or, while `osis serve` holds it, runs as that daemon's client over its unix socket); a command is one API call; timeouts, streaming, delivery and serving behaviour; the value syntax, JSON mapping and exit codes. Commands themselves are documented once, in `cli/src/args.rs` (`osis --help`).

Commands, flags and output are documented in `cli/src/args.rs` doc comments (`osis --help`); notes keep no per-command reference. The value syntax, JSON mapping and exit codes below are to move into the help too (issues/cli-docs-in-code.md).

## Design
- **One call**: a command is one API call plus parsing and printing (`cli/src/cmd.rs`, `write.rs`). Missing API pieces say "not built yet: NAME" (exit 1, kind `Cli`; e.g. `ls`, `op undelete`, issues/api-deferred.md), never CLI workarounds. Process-local API calls (`keep_alive`, `edit_text`) have no command: a CLI process is not there to keep a value alive or hold a keystroke session.
- **Store**: `-s DIR` / `OSIS_STORE` / `$XDG_DATA_HOME/osis/default`. Missing (`db.redb` absent): exit 8. `init` refuses a non-empty directory (exit 8). `<store>/cli.toml` holds registered schema paths (absolute); no other CLI state.
- **Daemon**: a locked store (redb's file lock, `Error::InUse`; who holds it is not known) whose daemon (`osis serve`) answers on the store's socket makes the invocation its client (`Osis::connect_socket`, as the node's main actor, notes/client-port.md), running the whole command there with the same output and exit codes; else exit 8 (kind `InUse`, saying why no daemon answered). A failure other than "nothing answers" (a bad `--timeout`, a refused socket directory, a refusal) is reported as itself. One connection attempt: the holder may serve no socket (the app, another command), and a retry would make every such call wait out `--timeout`. `inspect` (needs the engine) and `serve` never use a daemon, nor do `init` and `pair join`, which make a store (exit 8 while locked). Waits on other nodes run at the node (notes/client-port.md §2; `--timeout` is sent with each). Exit 1: `group source` (its connection and secret live in the process holding the store) and any call on a group the node sources elsewhere (`Unsupported`, notes/client-port.md §8).
- **Entry points**: `osis_cli::main_with(args, stdin, stdout, stderr) -> i32`; `osis_cli::run(args, Option<osis::Store>, Io)` also takes a memory store (tests) and the terminal flag (`edit` opens `$EDITOR` only on a terminal).
- **Networked or local**: commands that talk to other nodes open the store with sync on (`Runtime::Own`, QUIC); the others stay local (`Runtime::None`) and their writes go out with the next networked command. Each invocation ends with `Osis::close`, which waits until the store is free.
- **Futures** (API calls that wait on other nodes): polled on the calling thread by a park/unpark waker and raced against `--timeout` (`cmd::within`): past it the future is dropped, `Network`, exit 6; one connection attempt is at most `CONNECTION_WAIT`. `set-role`, `node rm`, `link revoke` and `chat kick` write at once and wait for nothing. `Unsynced`, or a timeout with a group `Refused`, says "ADDR does not admit group URI (yet)", exit 6. `init --peer` does not wait, so a refused home shows only in `status`. A link or card that cannot be judged within `--timeout` says "could not confirm this link yet; trying again is safe", exit 6: nothing says it is bad.
- **Streaming** (`watch`, `writes --follow`, `fired --follow`, `grants --watch`, `diag --follow`, `serve`, `chat watch`): until `--count` changes (initial lines not counted), `--timeout` or SIGINT (the process dies; commits are already durable). No default timeout; `--timeout` reached with `--count` unmet: exit 6, without `--count`: exit 0. `diag --follow` and `serve` exit 6 once the sync driver died (after printing its `SyncStopped` line). A closed stdout ends a streaming command, except `serve` (below). Other waits default to 30 s. `--timeout 0` is no deadline (checked arithmetic; `wait_synced` gets a 100-year bound).
- **Named keys**: `db.aspect_key(ak)` types an AK by a registered schema (`schema add`, `--schema FILE`) or the core schema. Reads print named forms through the typed view (reader defaults filled); `--raw` uses the untyped key: stored value, numbered forms, ms. Writes through a typed key are validated (exit 5); `--raw` writes untyped.
- **Paths**: typed positions follow the type. `[n]` on an untyped position: `get` reads the saved value (a list: index; else map key). Writes take it as a map key, and refuse it (exit 2) when the saved value there is a list (untyped lists take no index writes; register a schema) or when the same `write` script already wrote that aspect or created/deleted the thing (a script's pending state is invisible to reads). Never a silent map write over a list.
- **`write` scripts**: one `Write`, so one commit. Lines are tokenized at whitespace outside quotes and brackets, so a value is one token with its quotes kept; a token wholly in single quotes loses them (`''` is the root path). `$NAME` (from `create --as NAME`) works as a tid argument and inside values. Errors from a line's arguments carry `line N`; rights and unknown things are checked at commit.
- **`edit` on a terminal**: the value goes to a new temp file (`create_new`, random name, mode 0600, in `$XDG_RUNTIME_DIR` when set), then `$EDITOR`; the file is removed whatever the editor does. `edit` takes the whole aspect: the API's `edit(base, new)` has no path form.
- **Delivering commands** (whose API call queues inbox deposits or the first commits under a new sync ID, held only in memory: `grant`, `set-role` to a role, `leave`, `add-with-grant`, `link make`, `card show`, `group sync`): open with sync on and end with `nudge_sync` + `wait_synced` within `--timeout` (`grant`, `set-role`: `Deliveries`; `add-with-grant`, `link make`, `leave`: `Thing`; `group sync`: `Thing(g)`; `card show`: the profile), else exit 6 "done locally, not yet at its peers"; skipped for a store without saved peers. `add-with-grant` and `link make` on a thing no synced group holds exit 6 (its holders could never fetch it). `sync` (alias `wait`) with no group waits on `All`, groups nobody is connected on included.
- **Serving** (`serving set/show/off`, the flags of `serve`): local commands, since serving runs under `serve`. A flag replaces its whole field, the rest kept; `''` clears it; from off it starts with `listed` (nothing for others but `--admitted`; the groups it reads it serves anyway). A sync ID is 32 hex digits or a group synced here, standing for its current ones (a holder gives them to a node keeping the group unread); an ID stops matching once the group's sync is replaced. Through a daemon the terms take effect at once; a failure is only a line of the daemon's diagnostics, the command having exited 0.
- **`serve`**: the one long-running command. It serves the client port on the store's unix socket (`Osis::listen_socket`: `$XDG_RUNTIME_DIR/osis/<hash>.sock`, else `/tmp/osis-<uid>/`, the directory 0700 and checked; a killed daemon's stale socket makes clients exit 8 as for any lock, and the next `serve` replaces it). A refused socket directory (e.g. one another user made first) warns and serves without the socket. `--listen URL` (repeatable) listens under the node's key (`Osis::listen`; default `quic://0.0.0.0:4040` when serving, also a `quic://` URL's default port): one `URL#KEY` line each comes first on stdout (exit 6 if a listen fails, 1 if a line cannot be written); the diagnostic lines after are best effort, and a closed stdout (a caller that read only the addresses) does not end `serve`. Without serving it is a node that syncs and answers those it shares groups with. What it stores for others is in `<store>/host.redb`. A fresh store keeping anyone's data unread: `osis init`, then `osis serve --admit open`. A machine of one's own: `pair join` an empty store, `serve --listen quic://IP:PORT`, `peers add ADDR` on the other nodes: it reads the account's groups, so serves them with no terms; a group made later syncs there after a back-off (about 5 s).
- **Network**: a local command has no runtime. A command that stays up (`serve`, `pair`, `watch`, `status --watch`, `--follow`/`--watch` forms; `stays_up`) runs the LAN loop unless `--no-lan`; every other command that syncs (`needs_net`) runs with `Lan::Off`, gone too soon to announce. `init` runs one only with `--peer`.
- **`-v`** copies the node's diagnostics to stderr, formatted as `diag --follow`, while a command with sync on runs; best effort; a no-op for `serve` and `diag --follow` (they print them on stdout). Local commands print none.
- **Pairing** is two lines carried by the user: `pair offer` prints the offer, reads the request on stdin, prints the reply; `pair join OFFER` prints the request and reads the reply.
- **Thin client**: `--node ADDR --client-secret FILE` on any command (no store; the file holds 64 hex digits); commands needing a store exit 2, process-wide ones are `Unsupported`. A thin client creates with `create --admin G` (`create_with_admin`): its own actor as first admin is refused, as it goes with the client.
- **`inspect`**: `Debug` dumps over `osis::internals::Internals::engine`. Not stable.

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
- `me` is the account and `home` its private synced group (both in `whoami`): a thing put only `--in me` stays on this node (the account is no synced group), so data meant for every node of the account goes `--in home`.
- A struct prints as a map with field names (unknown ids numbered); untyped it is a map with int keys. Option is `#none` / `#some(v)`. Timestamps outside years 0..=9999 print as ints.
- Whitespace anywhere between tokens; trailing commas allowed; duplicate map keys or set elements are errors; `null` is not a value. JSON input works where unambiguous: string-keyed objects read as maps, or with a schema as the struct.
- Paths: `.name`/`.id` field, `#name`/`#id` case payload, `[i]` list index, `[value]` map key, `{value}` set element; concatenated; empty = the aspect.
- Flags: durations `30s`, `5m`, `1h30m`, `0`; timestamps RFC 3339 or ms; retention `by=NAME` (admin, author_or_admin, writer) over the key's default (what history keeps is the thing's `retention^.0`); roles `read`, `write`, `admin` (`none` on `set-role`). Arguments: literal, `@FILE`, or `-` (stdin).

## JSON mapping
One JSON document per command; streaming commands print JSON lines. int → number; float → number with `.` or exponent, `"NaN"`/`"Infinity"`/`"-Infinity"` strings; string → string; tid → `"osis://…"`; blob → `{"$blob": base64url}`; set → `{"$set": [...]}`; enum → `{"$case": name-or-id, "$payload": v}` (payload omitted when none); typed struct → object by field name (unknown ids as decimal strings); map with only string keys, none a marker (`$blob`, `$set`, `$case`, `$payload`, `$map`, `$tag`, `$bytes`) → object; every other map → `{"$map": [[k, v], …]}`, so an object never reads as a marker form; unknown tag → `{"$tag": N, "$bytes": base64url of the content}`; timestamps and durations stay ms ints. Results name tids by API names (`tid`, `actor`, `node`, `me`, `home`, `commit`). Errors on stderr: `{"error": {"kind", "message", "tid", "needs"}}`; kind is the API `Error` variant, `Usage`, `Cli` or `Other`.

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
| 8 | store missing, `InUse`, or (on `init`) not empty |

Every non-zero exit prints why on stderr, absent on `get` included (`error: absent: AK of TID`).

## Tests
tests/it/syntax.rs (round trips as properties, printed forms, JSON mapping); tests/it/cli.rs (in-process runs on memory and temp-dir stores: commands, exit codes, lock, `write` atomicity, undo, schema forms, streams, the local sharing commands, commands not built yet). By hand: tests/it/localhost.rs runs the binary against a real `osis serve` with several store directories (notes/testing.md).

## Not built
Proxying through an app that holds the store (only `serve` listens); `edit_text` sessions (`edit` covers scripts); shell completion, REPL, colour, paging; aliases beyond `me`/`node`/`home`; bearer read (`Osis::open_link`, unbuilt in the API); `diag --since` (no stored diagnostics log).
