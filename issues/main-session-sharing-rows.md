# A daemon's own CLI cannot grant, pair or manage nodes
> Summary: With `osis serve` up, CLI commands go through its socket as a main session, but the sharing writes and account calls have no client-port row: `grant`, `set-role`, `leave`, `chat add`, `chat relay`, `chat kick`, `pair offer` (fails at `take_keys`), `node ls`, `node rm` and `link ls` fail `Unsupported ... not through a connection`. The user must stop the daemon, run the command against the store, and start it again.
> Priority: normal
> Tags: osis, cli

Found in the dogfood smoke pass. notes/client-port.md §2 designs these as main-only rows ("sharing writes, process-wide calls"); `make link`, `locator`, `redeem` and `node root` are built.

Pairing is worst hit: `pair offer` must run with the daemon down, so it does not listen, and the joiner's `finish` needs the offering node after the offer command has exited. Without LAN discovery the joiner cannot reach the offerer at all; with it, the join completes only once the offering node's daemon is started again. A `take_keys` row (and the rest of the pairing calls) lets the offer run through the daemon, which listens.

Each row is its API call run on the session's handle (`serve::row`, `ReadOnly::forward`), main only (`method::for_client`); `GrantOpts` and `SetRoleOpts` need a `codec::Form`.
