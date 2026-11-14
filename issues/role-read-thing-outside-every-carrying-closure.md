# A thing read by role reaches no reader once its only carrying group loses read on it
> Summary: X (secrets derived from group Y, no sync ID of its own) filed only in group G, which read Y by role: once G is removed from Y, no sync ID carries X's writes to a node that reads X through its own read on Y; a stale copy under G gives nothing and nothing replaces it.
> Priority: normal
> Tags: sync, engine

Reproducer: `core/sync/tests/it/flows.rs` `repro_a_part_a_stale_copy_leaves_out_arrives_spec_sync_judgement_1` (ignored). Node 1's account reads G and Y; X is in Y's tree but not Y's closure, filed in G. After the removal, X's write made before it (a per-sync-ID copy under G, stale at node 1, `Engine::copy_stale`) and every later write of X stay at node 0: `thing_sync(X)` is `Plain`, Y's sync ID carries only Y's closure, G's carries nothing of X (G's actor reads it no more, spec/sync-judgement.md §1).

The copy-stale wake was deleted on the condition that a node syncs a sync ID carrying a thing whenever it reads the thing (spec/permissions.md §3 Lost access: "its parts come from a body under their own thing's sync ID"). That condition does not hold here: a thing reaches a node through the closures it is filed in, and a role read on the actor its secrets derive from does not make it travel under that actor's sync ID.

Directions (needs a spec rule, Fathom's call): a thing whose secrets derive from an actor A travels under A's sync IDs too (A's readers read it); or, with no closure whose actor reads it, a node files it nowhere and reads it no more through sync (state that limit instead).
