# CLI delivering commands are not built
> Summary: notes/cli.md's delivering commands (`grant`, `set-role` to a role, `leave`, `add-with-grant`, `link make`, `card show` open with sync on and wait until delivered, else exit 6) are not built: they run local and exit at once; what they queue goes out with the next networked command or through the daemon. `verbose_prints_diagnostics_plan_cli_4` waits on it.
> Priority: normal
> Tags: cli

- `needs_net` (cli/src/cmd.rs) lists none of them, so they open with no runtime, and `-v` prints nothing for them (notes/cli.md `-v`: local commands print none). `cli/tests/it/cli.rs` `verbose_prints_diagnostics_plan_cli_4` expects `-v add-with-grant` to print its `NotSynced`, so it is ignored until this is settled.
- What is left of the reason: deliveries are durable (osis-sync inbox `I/d/` rows, notes/sync-inbox.md Durable), and so are a new sync ID's first commits, so nothing is lost by exiting; what a waiting command still gives is a user who knows it reached a peer.
- Either rebuild it on the new sync (`wait_synced` on `SyncScope::Deliveries` or the thing within `--timeout`, exit 6 "done locally, not yet at its peers"; whom a store with no daemon dials is discovery plus `--dial`), or drop the design: then notes/cli.md says these commands are local and the test moves to a networked command that writes a membership (or to another diagnostic).
