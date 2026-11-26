# CLI
> Summary: `osis-cli` (binary `osis`): design and reasons. One invocation opens the store, acts, closes (or, while `osis serve` holds it, runs as that daemon's client over its unix socket); a command is one API call; timeouts, streaming, delivery and serving behaviour; the value syntax, JSON mapping and exit codes. Commands themselves are documented once, in `cli/src/args.rs` (`osis --help`).

Commands, flags and output are documented in `cli/src/args.rs` doc comments (`osis --help`); notes keep no per-command reference. The value syntax, JSON mapping and exit codes below are to move into the help too (issues/cli-docs-in-code.md).

## Design
- **One call**: a command is one API call plus parsing and printing (`cli/src/cmd.rs`, `write.rs`). Missing API pieces say "not built yet: NAME" (exit 1, kind `Cli`; e.g. `ls`, `op undelete`, issues/api-deferred.md), never CLI workarounds. Process-local API calls (`keep_alive`, `edit_text`) have no command: a CLI process is not there to keep a value alive or hold a keystroke session.
- **Store**: `-s DIR` / `OSIS_STORE` / `$XDG_DATA_HOME/osis/default`. Missing (`db.redb` absent): exit 8. `init` refuses a non-empty directory (exit 8). `<store>/cli.toml` holds registered schema paths (absolute); no other CLI state.
- **Daemon**: a locked store (redb's file lock, `Error::InUse`; who holds it is not known) whose daemon (`osis serve`) answers on the store's socket makes the invocation its client (`Osis::connect_socket`, as the node itself, notes/client-port.md), running the whole command there with the same output and exit codes; else exit 8 (kind `InUse`, saying why no daemon answered). A failure other than "nothing answers" (a bad `--timeout`, a refused socket directory, a refusal) is reported as itself. One connection attempt: the holder may serve no socket (the app, another command), and a retry would make every such call wait out `--timeout`. `inspect` (needs the engine) and `serve` never use a daemon, nor do `init` and `pair join`, which make a store (exit 8 while locked). Waits on other nodes run at the node (notes/client-port.md §2; `--timeout` is sent with each). Exit 1: `source` (its connection and secret live in the process holding the store) and any call on a sync unit the node sources elsewhere (`Unsupported`, notes/client-port.md §8).
- **Entry point**: `osis_cli::run(args, Option<osis::Store>, Io) -> i32`: a store given (a memory store in tests) or the one the flags name, and the terminal flag (`edit` opens `$EDITOR` only on a terminal).
- **Networked or local**: commands that talk to or wait for other nodes (`needs_net`, the delivering commands included) open the store with sync on (`Runtime::Own`, QUIC); the others stay local (`Runtime::None`) and their writes go out with the next networked command. Each invocation ends with `Osis::close`, which waits until the store is free.
- **Futures** (API calls that wait on other nodes): polled on the calling thread by a park/unpark waker and raced against `--timeout` (`cmd::within`): past it the future is dropped, `Network`, exit 6; one dial is at most `DIAL_TIMEOUT_MS` (osis-sync). Delivering commands wait as below; the others that write (`set-role` to none, `node rm`, `link revoke`, `chat kick`) wait for nothing. `Stranded` exits 6. A link or card that cannot be judged within `--timeout` says "could not confirm this link yet; trying again is safe", exit 6: nothing says it is bad.
- **Streaming** (`watch`, `writes --follow`, `fired --follow`, `grants --watch`, `diag --follow`, `serve`, `chat watch`): until `--count` changes (initial lines not counted), `--timeout` or SIGINT (the process dies; commits are already durable). No default timeout; `--timeout` reached with `--count` unmet: exit 6, without `--count`: exit 0. `diag --follow` and `serve` exit 6 once the sync driver died (after printing its `SyncStopped` line). A closed stdout ends a streaming command, except `serve` (below). Other waits default to 30 s. `--timeout 0` is no deadline (checked arithmetic: a timeout too far to represent is none too).
- **Named keys**: `db.aspect_key(ak)` types an AK by a registered schema (`schema add`, `--schema FILE`) or the core schema. Reads print named forms through the typed view (reader defaults filled); `--raw` uses the untyped key: stored value, numbered forms, ms. Writes through a typed key are validated (exit 5); `--raw` writes untyped.
- **Paths**: typed positions follow the type. `[n]` on an untyped position: `get` reads the saved value (a list: index; else map key). Writes take it as a map key, and refuse it (exit 2) when the saved value there is a list (untyped lists take no index writes; register a schema) or when the same `write` script already wrote that aspect or created/deleted the thing (a script's pending state is invisible to reads). Never a silent map write over a list.
- **`write` scripts**: one `Write`, so one commit. Lines are tokenized at whitespace outside quotes and brackets, so a value is one token with its quotes kept; a token wholly in single quotes loses them (`''` is the root path). `$NAME` (from `create --as NAME`) works as a tid argument and inside values. Errors from a line's arguments carry `line N`; rights and unknown things are checked at commit.
- **`edit` on a terminal**: the value goes to a new temp file (`create_new`, random name, mode 0600, in `$XDG_RUNTIME_DIR` when set), then `$EDITOR`; the file is removed whatever the editor does. `edit` takes the whole aspect: the API's `edit(base, new)` has no path form.
- **Delivering commands**: a command that gives another account a way to a thing ends once that way works where the user can see it, `wait_synced` (`cmd::delivered`, the one wait, shared with `sync`; all its scopes within one `--timeout`): a grant (`grant`, `set-role` to a role, `chat add`, `chat relay`) on `Thing(t)` (its holders hold the grant); a link (`link make`, `chat link`) on `Thing(t)`; a contact card (`contact show`) or a public link (`link public`) on `Thing(profile)` or `Thing(t)`. Output comes first; past `--timeout` the command exits 6 (`Network`, "done here, not yet held where it goes"): what it wrote is durable and goes on as this node syncs. On a node alone a grant ends at once: what no other node may hold or take holds no wait; a link (`link make`, `link public`, `chat link`, `contact show`) runs to its `--timeout`, as whoever holds the link may take its thing (spec/sync-status.md §3): a link key and the public are no own things, and what the link reaches is not held elsewhere until a redeemer holds it, so the timeout's exit 6 says the truth: the link works only while this node runs. A removal (`set-role` to none, `node rm`, `link revoke`, `chat kick`) and `leave` give nobody anything and wait for nothing (a left thing is released here once the pass in flight ends, spec/sync-set.md §3). `sync` waits on `All`: a thing whose other holders never connect holds it to its `--timeout`. `sync` (alias `wait`) with no thing waits on `All`: a sync ID another node may hold waits until connected; one held by no other node holds nothing up. An account's profile is public, so on an account's lone node `sync` with no thing runs to its `--timeout` (anyone may hold the profile).
- **`serve`**: the one long-running command. It serves the client port on the store's unix socket (`Osis::listen_socket`: `$XDG_RUNTIME_DIR/osis/<hash>.sock`, else `/tmp/osis-<uid>/`, the directory 0700 and checked; a killed daemon's stale socket makes clients exit 8 as for any lock, and the next `serve` replaces it). A refused socket directory (e.g. one another user made first) warns and serves without the socket. `--listen URL` (repeatable) listens under the node's key (`Osis::listen`; default `quic://0.0.0.0:4040` when serving, also a `quic://` URL's default port): one `URL#KEY` line each comes first on stdout (exit 6 if a listen fails, 1 if a line cannot be written), then the socket's path once it takes clients (a script waits for that line: a command run before it opens the store itself, and the daemon's start fails `InUse`); the diagnostic lines after are best effort, and a closed stdout (a caller that read only the addresses) does not end `serve`. It is a node that syncs and answers those it shares sync IDs with.
- **Network**: a local command has no runtime. A command that stays up (`serve`, `pair`, `watch`, `status --watch`, `--follow`/`--watch` forms; `stays_up`) runs the LAN loop unless `--no-lan`; every other command that syncs (`needs_net`) runs with `Lan::Off`, gone too soon to announce. `--dial ADDR` (repeatable, global) adds dial candidates for the run, never stored.
- **`-v`** copies the node's diagnostics to stderr, formatted as `diag --follow`, while a command with sync on runs; best effort; a no-op for `serve` and `diag --follow` (they print them on stdout). Local commands print none.
- **Pairing** is two lines carried by the user: `pair offer` prints the offer, reads the request on stdin, prints the reply; `pair join OFFER` prints the request and reads the reply.
- **Thin client**: `--node ADDR --client-secret FILE` on any command (no store; the file holds 64 hex digits); commands needing a store exit 2, process-wide ones are `Unsupported`. A thin client creates with `create --admin G`: its own thing as mint admin is refused, as it goes with the client.
- **`inspect`**: `Debug` dumps over `osis::internals::Internals::engine`. Not stable.

## Value syntax
CBOR diagnostic notation narrowed to one printed form per value. Printer: `cli/src/text.rs` `print`; parser `parse`; property test: `parse(print(v)) == v`, numbered and named.
```text
value  := string | blob | "true" | "false" | int | float | ref | list | map | set | enum | tag
string := JSON string ("\u" escapes incl. surrogate pairs; printer escapes ", \, controls, DEL)
blob   := "h'" hex "'"  |  "b64'" base64 or base64url, padding optional "'"   (input only)
int    := "-"? digits                          (i64; no leading zeros)
float  := "-"? digits ("." digits)? (("e"|"E") ("+"|"-")? digits)?  with "." or exponent
        | "NaN" | "Infinity" | "-Infinity"     (printer: Rust's shortest round-trip form; -0.0)
ref    := ("strong" | "weak") "(" target ")"  |  target (input only, where the type is strong or weak)
target := tid | alias                          tid := "osis://" 20 base64url chars
list   := "[" (value ","?)* "]"                set := "#{" (value ","?)* "}"
map    := "{" (key ":" value ","?)* "}"        key := value | field-name (typed struct) | "name"
enum   := "#" (u64 | case-name) ("(" value ")")?
tag    := "tag(" u64 "," value ")"             (unknown tag; content as its value, or h'…' raw if undecodable)
alias  := "me" | "node" | "$" name   (input only)
typed  : timestamp := RFC 3339 (bare; `T` separator; real calendar dates; printed UTC, ms when nonzero; ints accepted)
         duration  := "-"? (digits ("d"|"h"|"m"|"s"|"ms"))+   (printed largest unit first; "0s")
```
- `me` is the person's account (osis-account; `whoami` prints it and `node`, the node thing): the default mint admin and holder of `create`, `leave`'s default holder, `link redeem`'s joiner. A client with a thing of its own: that thing; a node acting for no account: its node thing. `init` makes the node and its account.
- A struct prints as a map with field names (unknown ids numbered); untyped it is a map with int keys. Option is `#none` / `#some(v)`. Timestamps outside years 0..=9999 print as ints.
- Whitespace anywhere between tokens; trailing commas allowed; duplicate map keys or set elements are errors; `null` is not a value. JSON input works where unambiguous: string-keyed objects read as maps, or with a schema as the struct.
- Paths: `.name`/`.id` field, `#name`/`#id` case payload, `[i]` list index, `[value]` map key, `{value}` set element; concatenated; empty = the aspect.
- Flags: durations `30s`, `5m`, `1h30m`, `0`; timestamps RFC 3339 or ms; `--purge-by` admin, author_or_admin or writer over the key's default (what history keeps is the thing's `retention^.0`); roles `read`, `write`, `admin` (`none` on `set-role`). Arguments: literal, `@FILE`, or `-` (stdin).

## JSON mapping
One JSON document per command; streaming commands print JSON lines. int → number; float → number with `.` or exponent, `"NaN"`/`"Infinity"`/`"-Infinity"` strings; string → string; strong → `{"$strong": "osis://…"}`, weak → `{"$weak": …}`; blob → `{"$blob": base64url}`; set → `{"$set": [...]}`; enum → `{"$case": name-or-id, "$payload": v}` (payload omitted when none); typed struct → object by field name (unknown ids as decimal strings); map with only string keys, none a marker (`$blob`, `$set`, `$case`, `$payload`, `$map`, `$tag`, `$bytes`, `$strong`, `$weak`) → object; every other map → `{"$map": [[k, v], …]}`, so an object never reads as a marker form; unknown tag → `{"$tag": N, "$bytes": base64url of the content}`; timestamps and durations stay ms ints. Results name tids by API names (`tid`, `thing`, `holder`, `node`, `me`, `commit`). Errors on stderr: `{"error": {"kind", "message", "tid", "needs"}}`; kind is the API `Error` variant, `Usage`, `Cli` or `Other`.

## Exit codes
| code | meaning |
|---|---|
| 0 | ok |
| 1 | other: `Storage`, `Closed`, `NotUndoable`, `Unsupported`, a command not built yet (kind `Cli`), I/O |
| 2 | usage, unparsable argument or value |
| 3 | `UnknownThing`, `UnknownKeys`, absent on `get`, nothing to undo/redo |
| 4 | `Permission`, `NotEnabled`, `Refused` |
| 5 | `TooLarge`, `Type` |
| 6 | `Network`, `Stranded`, timeout |
| 7 | `Invalid`, `LeavesNoAdmin` (also a schema that does not parse or check) |
| 8 | store missing, `InUse`, or (on `init`) not empty |

Every non-zero exit prints why on stderr, absent on `get` included (`error: absent: AK of TID`).

## Tests
tests/it/syntax.rs (round trips as properties, printed forms, JSON mapping); tests/it/cli.rs (in-process runs on memory and temp-dir stores: commands, exit codes, lock, `write` atomicity, undo, schema forms, streams, the local sharing commands, commands not built yet).

## Not built
Proxying through an app that holds the store (only `serve` listens); `edit_text` sessions (`edit` covers scripts); shell completion, REPL, colour, paging; aliases beyond `me`/`node`; bearer read (`Osis::open_link`, unbuilt in the API); `diag --since` (no stored diagnostics log).
