# Handed grant commits enter the thing
> Summary: a node handed a grant's commits directly (no signal, no unit it syncs carrying the thing) enters the thing once its node root strongs it, against spec/sync-set.md §2 First entry (Entry is founded); a correct rule needs a durable record of the stubs a node logged in its local part. Engine tests rely on it through `LocalPeer::share`.
> Priority: normal
> Tags: engine, sync, tests

Decided (Sheave): being handed role commits is not entry.

Reproducer (engine `tests/it/closure.rs`, fails today): `LocalPeer::fresh(2, T0)`, `sync_all`; peer 0 makes t (`new_thing` with its node thing, a value), grants peer 1's node thing read on t, delivers the grant's packages to peer 1 (`deliver`), then `hold_at(1, t)` and `sync_all`: peer 1 `closure_holds(&t)`, and reads t.

Why: the grant's edge part on t applies at peer 1 as evidence (its node thing is named holder, spec/commits.md §5 What a held thing needs), and the local part's carriage (`sync::units::edge_carries`: `keys_open` over the roster held) reads those grants whatever brought them. The spec judges carriage "as the role entries the node holds show it (X's stub, or X whole)": evidence is neither, so the root's strong carries nothing.

The obvious gate (count a thing's grants for carriage only while it is held as a stub or whole by another route) drops a thing held by a signal then a reference once the signal goes, which held-model and the spec keep (the node logged the stub in its local part, `entry_a_signal_then_a_reference_outlives_the_signal`). The engine keeps no such log: the local part's logged stubs would be new durable rows, judged like a unit's carried stubs (carriage outlives its carrier while the rule carries it).

Options:
- **Local-part log**: rows of the stubs the node logged under its local part (written when it holds the thing's role entries by a founded route: a signal, a unit, a whole thing), and carriage judged from them; handed commits log nothing.
- **Gate on arrival**: role parts outside the node closure that no synced sync ID carries wait (as content does); LocalPeer delivers without sync IDs, so its delivery would have to name them.

Then rewrite `LocalPeer::share`'s users (15 engine tests) to enter by a signal (as `fresh_reader` does) or a reference.
