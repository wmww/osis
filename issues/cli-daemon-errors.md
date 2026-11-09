# CLI reports any daemon failure as "store in use"
> Summary: `osis` turns every failure to reach a store's daemon into `store in use by pid N`, and detects the lock from a substring of redb's error; the pid file is stale; `status` output and the port's status differ from the API.
> Priority: normal
> Tags: cli, osis

Found by reading, not run. Seen in use: `osis -s STORE --timeout 10 status` beside a daemon printed `store in use by pid N`.

- cli/src/lib.rs `open`/`daemon`: `Osis::connect_socket` makes one attempt and `.ok()?` drops every failure, so a socket path that differs (`XDG_RUNTIME_DIR` set differently from the daemon's shell), a bad `--timeout`, or the window between `open` and `listen` in `serve` all read as the lock message. `daemon()` should return its error ("daemon at SOCK: why"). `connect_socket` could retry within the caller's timeout.
- cli/src/lib.rs detects the lock by `m.contains("already open")`, redb's wording: a change there turns daemon routing off (exit 8 everywhere). Match a typed error.
- `<store>/pid` is written by every one-shot command and never removed, and the app writes none, so the pid named can be long dead. Drop the file: the useful answer is the daemon's error or "locked by another process".
- core/osis/src/port/codec.rs: status over the port drops `node_connections` and encodes an unknown state as `STATES[0]`; a thin client's `status()` differs from in-process. One type, one encoding.
- cli/src/cmd.rs `status` omits `refused_by` and `leaving`, which notes/cli.md says it shows.
- cli/src/cmd.rs `diag_line`'s `other` arm uses `Box::leak` per unknown diagnostic: unbounded under `serve` if any variant reaches it.
