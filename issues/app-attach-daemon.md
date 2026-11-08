# The app opens its store itself, so it cannot run beside a daemon
> Summary: `libs/kit/src/store.rs` opens the store with `Osis::open`; a store already held by `osis serve` (the CLI daemon) is locked, so the app and the CLI cannot share one store. Connect through the daemon's socket instead (`Osis::connect_socket`). Not needed while Tess runs the app alone on its own store; needed when agents and the app share a store (the realm direction).
> Priority: low
> Tags: app, cli

Every CLI command but `group source` runs through the daemon (`chat join` and `kick` included), so connecting would lose nothing the app uses.
