# A node test stalls when a node writes a group whose item is another group's first admin
> Summary: In osis-node's test net, `setup_reader` (destruction.rs), then a group h of a's (`group_seeded(a, &[(c, Role::Write)], .., 2)`), t created with first admin h and listed in h, x = `net.item(a, g, t, "x")`, `net.run()`, `net.grant(a, x, g, Role::Read)`: the next `net.advance(70_000)` never returns (one thread at full CPU for 10+ minutes, no "no quiescence" panic, so one delivery or pass runs on and on). Also with c `Admin`; not with `Read`. Reproduces on main.
> Priority: normal
> Tags: node-sync, tests

- Seen while writing the minting-witness tests; not narrowed further. The profile is ordinary engine work (crdt winners, signatures, memo table), so likely a pass or apply loop that keeps finding work, not a single hot function.
- First step: run the setup above with a pass counter or `OSIS_SYNC_TRACE` to see which node and pass repeats.
