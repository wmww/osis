# A CLI command through the daemon sometimes panics on exit
> Summary: `osis chat read` through a running daemon once printed `thread 'osis-sync' panicked at tokio .../runtime/time/entry.rs: A Tokio 1.x context was found, but it is being shutdown` on stderr after its output; the output was whole. Seen once in the dogfood smoke pass.
> Priority: low
> Tags: osis, cli

A timer registered on the client's sync thread while its runtime shuts down. Look at the thin client's shutdown order (`Osis` drop with a remote: the sync thread still arming a timer).
