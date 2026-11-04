# The app opens its store itself, so it cannot run beside a daemon
> Summary: `app/src/data.rs` opens the store with `Osis::open`; a store already held by `osis serve` (the CLI daemon) is locked, so the app and the CLI cannot share one store. Attach through the daemon's socket instead (Tiller, after port-rest). Not needed while Tess runs the app alone on its own store; needed when agents and the app share a store (the realm direction).
> Tags: app, cli

- port-rest made owner commands, `chat join` and `kick` run through the daemon, so attaching would lose nothing the app uses.
