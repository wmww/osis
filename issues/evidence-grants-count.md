# Grants held only as evidence count for carriage
> Summary: the engine judges a unit's carriage (keys open, roles, chain holders) from every grant it holds, evidence included, where the spec counts only role entries held as the thing's stub or whole: handed grant commits enter a thing (against First entry), and a chain is counted through a hop only evidence shows (full-size seed 59). A correct rule needs to know which role entries a unit carries, the local part's logged stubs among them. Engine tests rely on the first through `LocalPeer::share`.
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

## A chain hop only evidence shows (full-size seed 59)
`New(1), Give(1, 0, Holder::Node(0), Syncs), Give(1, 0, Holder::Public, Reads), New(1), NewIn(1, 0), NewIn(1, 0), Give(1, 3, Holder::Node(0), Syncs), Give(1, 3, Holder::Thing(2), Syncs)` (world 0): node 0's account holds sync on thing 3 directly and through things 0 and 2 (0 public, the mint admin of 2; 2 holds sync on 3). Node 0 holds thing 2's record edge only as evidence, yet `sync::units::chain_holders` counts the hop and node 0 holds thing 2 as a chain stub; held-model counts only grants on things the unit carries, so holds nothing of thing 2. Filtering chain holders to things already held is circular (a chain holder is held for being one: `stubs::a_two_hop_chain_*` fails): the rule is the unit's carried role entries, as above.
