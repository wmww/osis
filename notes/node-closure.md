# The node closure (engine)
> Summary: How the engine holds spec/sync-set.md §1-§2: the node root, the closure as one spanning tree over (context, thing) vertices followed per edge, what sync units and the sync set read of it, the making rule, the roots' kept strongs, and the work counts of edits.

Spec: spec/sync-set.md. Model: notes/closure-model.md (held-model `closure`). Code: core/engine/src/sync/units.rs, flows/roots.rs, sync/set.rs, retention/release.rs.

**Principle:** a node holds exactly what its node root reaches by strongs, sync unit by sync unit; the structure is kept by edits, each costing what it changed.

## Roots
- The node root is made at the node's first start (`Engine::make_node_root`, local record `records::NODE_ROOT`), first admin the node; the node writes it as itself (`Core::nodes_own`, as its node thing).
- The account's creation writes D's strongs to the profile, the inbox and the node thing, and the node root's to D, in its transaction; pairing writes the new node's strong to D (`Engine::paired`).
- A local write that removes the node root's strong to D, or D's to the profile or the inbox (a remove of it, a whole set or reset not naming it), is refused (`roots::keeps_root_strongs`, in `commit_in`).

## The structure (`Closure`, an index: journaled, built again by an open)
- A vertex is (context, thing). A context is `Local` (the node root's local part), `Read(T)` or `Unread(T)` (T's sync unit entered read or kept unread). The root is (Local, node root).
- A vertex's edge to each target of its thing's strongs gives (`given_by`): in Local, a plain target; in `Read(T)`, a target T's keys open (`Core::keys_open`: on the record chain of its secret actor, or T's role there read or above); from either, a target with own keys the context does not follow enters `Read(y)`/`Unread(y)` by the secrets the node holds of it (`Core::enter`), and so does a target with own keys inside a read unit (its unit is part of the one it is in: holds nothing more, but `units_holding` names every sync ID carrying a thing). Kept unread is its root alone (the node cannot read what it holds). A key actor gives nothing.
- So `sync_unit(T)` is the members of `Read(T)`; `units_holding(t)` the `Read` contexts holding t; the node closure every thing of any context.
- Followed per edge: an `Effects` key per (held vertex, strong target) records what `given_by` read (own keys, roles, secrets, records); the reference index tells strong rows appearing or going (`Closure::note_row` from `refs::note`), since store table reads stamp a whole table. A settle at each transaction's end (`units::settle`) applies due edges and noted rows. A rollback resets the follower (`Follow::reset`): every held vertex's edges followed afresh, O(closure), rare.
- Removing a tree edge runs two searches in step (the target's other referrers up their tree paths; the target's subtree), stopping at the first answer; a subtree found whole re-attaches what a held referrer outside reaches and drops the rest (`detach`). A dropped thing is noted in `left` with its contexts until `released`.
- Work counts (`closure:` costs), engine `closure::removal_costs_what_it_held_spec_sync_set_2` at n = 6 and 60: a non-tree referrer of a target with fan-in n, 1 / 1; that target's tree edge with referrers outside, 1 / 1; a tree edge with a shallow alternative over a subtree of n, 7 / 7; one whose alternative is n deep, 5 / 5; a subtree of n released, 3n (edges, steps, drops).
- Not yet incremental: `sync_things` folds the closure whole when a thing enters or leaves (a memo, as the sync set rows fold per thing anyway), and a cut (things sourced elsewhere) walks it from scratch (`Closure::uncut`).

## Making a thing
- Not enforced yet (spec/sync-set.md §2 Making a thing): the check after the settle (each non-key-actor thing a transaction's own commits make held at its end, else refused) refuses about 700 engine tests whose helpers make things under the account with no strong. It lands with the planned test set (issues/reference-graph.md Execution step 6).

## Left for others
- Tickets entering a thing (`Engine::ticket_for`, lane (c)): `enter` reads held secrets only until then.
- D's `tickets.0` (spec/sync-set.md §1 The account's tickets): lane (c).
