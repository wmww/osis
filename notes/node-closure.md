# The node closure (engine)
> Summary: How the engine holds spec/sync-set.md §1-§2: the node root, the closure as one spanning tree over (context, thing) vertices followed per edge, what sync units and the sync set read of it, the making rule, the roots' kept strongs, and the work counts of edits.

Spec: spec/sync-set.md. Model: notes/closure-model.md (held-model `closure`). Code: core/engine/src/sync/units.rs, flows/roots.rs, sync/set.rs, retention/release.rs.

**Principle:** a node holds exactly what its node root reaches by strongs, sync unit by sync unit; the structure is kept by edits, each costing what it changed.

## Roots
- The node root is made at the node's first start (`Engine::make_node_root`, local record `records::NODE_ROOT`), first admin the node; the node writes it as itself (`Core::nodes_own`, as its node thing).
- The account's creation writes D's strongs to the profile, the inbox and the node thing, and the node root's to D, in its transaction; pairing writes the new node's strong to D (`Engine::paired`).
- A local commit after which the node root no longer strongly references D, or D the profile or the inbox, is refused, however it was written (a remove, a whole set, a removed aspect, an undo, a purge): `commit_in` compares those strongs in the index before and after (`roots::kept`, `still_kept`), O(1).

## The structure (`Closure`, an index: journaled, built again by an open)
- A vertex is (context, thing). A context is `Local` (the node root's local part), `Read(T)` or `Unread(T)` (T's sync unit entered read or kept unread). The root is (Local, node root).
- A vertex's edge to each target of its thing's strongs gives (`given_by`): in Local, a plain target; in `Read(T)`, a target T's keys open (`Core::keys_open`: on the record chain of its secret actor, or T's role there read or above); from either, a target with own keys the context does not follow enters `Read(y)`/`Unread(y)` by the secrets the node holds of it (`Core::enter`), and so does a target with own keys inside a read unit (its unit is part of the one it is in: holds nothing more, but `units_holding` names every sync ID carrying a thing). Kept unread is its root alone (the node cannot read what it holds). A key actor gives nothing.
- So `sync_unit(T)` is the members of `Read(T)`; `units_holding(t)` the `Read` contexts holding t; the node closure every thing of any context.
- Followed per edge: an `Effects` key per (held vertex, strong target) records what `given_by` read (own keys, roles, secrets, records); the reference index tells strong rows appearing or going (`Closure::note_row` from `refs::note`), since store table reads stamp a whole table. A settle at each transaction's end (`units::settle`) applies due edges and noted rows; an open's reload settles it. Only a rollback of a transaction whose settle ran (a failure past it) resets the follower (`Follow::rolled_back`: every held vertex's edges followed afresh, O(closure)); a step or write refused before the settle leaves it right, since what a rollback restores stamps what it read.
- Removing a tree edge runs two searches in step (the target's other referrers up their tree paths; the target's subtree), stopping at the first answer; a subtree found whole re-attaches what a held referrer outside reaches and drops the rest (`detach`). A thing out of the node closure at a settle's end is noted in `left`, with every context it was dropped from in that transaction (the sync units that carried it when it left), until `released`.
- Work counts (`closure:` costs), engine `closure::removal_costs_what_it_held_spec_sync_set_2` at n = 6 and 60: a non-tree referrer of a target with fan-in n, 1 / 1; that target's tree edge with referrers outside, 1 / 1; a tree edge with a shallow alternative over a subtree of n, 7 / 7; one whose alternative is n deep, 5 / 5; a subtree of n released, 3n (edges, steps, drops).
- Checked: `units::check_whole` walks the node closure afresh by `given_by` and compares the held vertices and the tree (`Engine::check_closure`; in `check_index`, so sampled in debug builds; the closure tests run it after every edit). It shares `given_by`, so `given_by`'s own rules need behaviour tests (`units_holding`, `not_carried`).
- Not yet incremental: `sync_things` folds the closure whole when a thing enters or leaves (a memo, as the sync set rows fold per thing anyway), and a cut (things sourced elsewhere) walks it from scratch (`Closure::uncut`).

## Making a thing
- A thing a local commit makes under an account is due own keys (`Core::own_keys_due`): before the first content write on it (`write::keyed_first`, as `Engine::mint_actor` mints: its record alone, `rotation::own_secrets`, then the rest of the commit under its own keys), else at its creating transaction's end (`rotation::own_keys_due`). Role writes go first as they are, so a maker keying it itself (a link's K, its sync ID listing L) is not keyed twice. Content under derived keys would be re-encrypted, chunks and all, by the first write after the rotation.
- Cost per such thing (engine `facade::a_thing_made_under_an_account_has_own_keys_spec_permissions_3`): 3 commits and about 28 KB stored against 1 commit and 1.6 KB for a plain thing under the account root; the same as any thing pays at its first grant. Things an app keeps account-wide and plain go under the account root.
- Not enforced yet (spec/sync-set.md §2 Making a thing): the check after the settle (each non-key-actor thing a transaction's own commits make held at its end, else refused) refuses about 700 engine tests whose helpers make things under the account with no strong. It lands with the planned test set (issues/reference-graph.md Execution step 6).

## Not carried
- The write path's warning reads the strongs the write's ops name (`osis_engine::strongs_in`, `Engine::not_carried_among`): O(the write), never the written thing's other strongs. `Engine::not_carried` lists the whole node closure's, O(its strongs).

## Left for others
- Tickets entering a thing (`Engine::ticket_for`, lane (c)): `enter` reads held secrets only until then.
- D's `tickets.0` (spec/sync-set.md §1 The account's tickets): lane (c).
