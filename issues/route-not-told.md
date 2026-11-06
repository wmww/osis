# A holder is not told of a route another admin made
> Summary: a thing's first `label.0` write is delivered to its holders by the node that makes it (spec/sync.md §3); a co-admin who never met a holder (holds no `keys.0` of it) seals nothing to it, and a holder whose inbox is unknown here (an ownerless group whose label the granter never saw) is never told, while `status` shows it routed once the label exists.
> Tags: node-sync, osis

Repro (first): Alice grants plain `t` to group H (Alice met H); Carol, co-admin of `t` who never read anything of H, runs `sync(t)`: `create_label` finds H on the roster but `recipient` has no keyset for H, so no inbox blob goes; H's admins learn `t`'s label only if a node of Alice's also syncs `t` (it does not re-deliver) or they read `t` through another label. `status` at every node says H is routed (a live label exists).

Repro (second): `sync::a_grant_to_a_holder_nothing_reaches`: Dave knows ownerless F's keys from a thing F held, not F's label; his grant to F records the role and nothing can carry it to F's admins; after Dave's `sync(t)` the label exists and `Engine::routed(F, t)` is true, but F's admins never hear of `t`.

Both verified on main. The first needs no group: Alice grants item `t` of her group G to Bob, Carol (G reader, `t` admin, never met Bob) runs `sync(t)`: Bob never hears, all `status` say routed, and passing time changes nothing.

Not a small fix, so left as a stated limit (spec/sync.md §3: its writer tells those it can seal to): no node can tell what the writer could seal to, so the fix below sends a redundant blob per admin per holder in the common case too, and needs a new hook where another node's `label.0` is applied. Nothing helps the second repro: no node knows F's inbox.

Rare (a holder the syncing admin never met). `status` is about labels, not about who was told; a grant again to that holder names the label. Options if it ever bites: every admin node that applies a `label.0` write giving a thing its first live label delivers it to the holders it can seal to (k admins send k blobs per holder, bounded by label creations); or accept and document.
