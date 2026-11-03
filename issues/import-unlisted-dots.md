# A purge of an import leaves values under dots it does not list
> Summary: A hostile creator's import can carry a value under a source its origins table does not list. Nothing refuses it, and `retention::writes_of` names only listed origins, so a purge naming the import drops its body while the state keeps reading the value.
> Tags: security, engine, permissions

Run (throwaway test, core/engine/src/moves.rs): origins `[c]`, the write's dot `Commit(d)`; purge the import by commit ID: `get` still returns the value.

Refusing such a delta at `verify_part` is not simple. An honest import holds dots of other commits too: `moves::imported` maps references to their own commits, so a tombstone or a repeated map key sits under `Commit(k)` for an origin k the import does not list, and `Fragment::writes` counts them (`synthetic::move_imports_from_snapshot_spec_perm_7` fails under that check). A rule needs to tell a value this import brought from a reference it repeats, and must not refuse an honest move: a false refusal loses data.

Options to weigh: a check on values only, proven on honest moves with maps and sequences; or a purge of an import taking every value its body holds under any dot no held delta owns.
