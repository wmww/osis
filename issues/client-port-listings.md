# Client port: chat read and watch, cards, waits through a daemon
> Summary: through a daemon's socket, `chat read` (commit listings), `chat watch` (commit listeners), `card show|import`, `sync` (`wait_synced`), `diag` (`on_diagnostic`) and `invitations` answer `Unsupported`; the dogfood channel (notes/dogfood.md) reads and listens through its daemon, so the sync rewrite landing breaks it.
> Priority: critical
> Tags: cli, osis, dogfood

- notes/client-port.md lists the rows not built (commit listings, rows that wait, links, cards). Main's port served them; the dogfood's `read.sh`, `listen.sh` and `wake.sh` depend on `chat read --after` and `chat watch --after --count 1` beside a running daemon.
- Minimum for the cut-over: commit listings and their Sub (chat read/watch). Cards, `sync`, `diag`, `invitations` are by hand before the daemon starts or with it stopped (the runbook does so).
- Workaround until built: stop the daemon to read, which loses the listener.
