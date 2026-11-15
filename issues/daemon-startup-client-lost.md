# A command right after `serve` starts once lost its daemon connection
> Summary: in the dogfood rehearsal a `chat post` run tens of ms after the member's daemon started (systemd-run returned) failed `store in use ...: connection to unix://...sock lost` (exit 8): it found the store locked, reached the daemon's socket, and the connection dropped. Not reproduced in 15 further start-then-post runs; cause unknown (a socket served before the node is ready, or a startup step that drops clients?).
> Priority: low
> Tags: cli, osis

Seen once: B's daemon unit started at .631, its dial up at .697, the post at about .66. Look at what `serve` does between taking the store lock and `listen_socket` being stable, and whether a client accepted then is ever closed. A retry of the socket connect in `cli/src/lib.rs` `daemon` would hide it, not explain it.

Related, seen in the same start-then-post loop: once the daemon unit itself exited 8 (`store in use`): the post, run before the daemon took the store lock, opened the store directly and the daemon lost the race. So a command right after `systemctl`/`systemd-run` starts `serve` can either run direct (and kill the daemon's start) or catch it mid-start. Callers today must wait for the daemon (e.g. its first journal line); a `serve` that waits for the lock, or a readiness signal (`systemd-run --wait`-style notify), would remove both.
