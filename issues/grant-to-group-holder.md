# A grant on an item to a group never reaches the group's readers
> Summary: `grant(t, H)` with `t` not placed in H: the call succeeds and `t` gets a label, but a reader of H never knows `t`, and nothing says why. `share_into` works. Older than the label on grant.
> Tags: node-sync, osis

Repro: Alice's group H with its own label, Bob reads H; `alice.grant(plain, H, Read, ..)`, `w.run()`: `bob.knows(plain)` stays false. H's readers get H's secrets and so could open `t`'s, but the inbox blob goes to H's inbox, by default the nearest actor above H in its owner chain (spec/sync.md §2), which is Alice's; Bob reads only H's label, which does not carry `t`. Not traced further.

Choice: put the grant under H's label, refuse it, or say in `grant` that a group holder needs the placement (notes/api.md says so now).
