# A purge of an import leaves its values
> Summary: `Owned::of` of an import owns its own (empty) range or commit ID, not the origin dots its writes carry, so a purge request naming an import drops its body only: the state keeps reading the value and snapshots carrying it stay. Conflicts with spec/commits.md §5 and requirements (Purge is prompt, granularity one edit).
> Tags: security, engine, permissions

Rule: spec/commits.md §5: "from then on it holds their value-carrying writes value-less ... and drops every body carrying their values, snapshots included"; spec/requirements.md: "no honest node keeps purged content once it has seen the deletion". Against it the same section's "A snapshot or import part has no values of its own", which is what the code does: `make_valueless` filters on `has_own_writes` (core/engine/src/retention/mod.rs:550), and `drop_carrying` strips by `Owned::of` (mod.rs:1059, :1104; engine/mod.rs:352), which never owns a `Commit(origin)` dot. `apply::invalid_of` already maps an import to its origins.

Run (throwaway test, deletion module): b writes under `writer`; a moves the thing; a snapshots the copy; a purges the import by commit ID with no reset. The import's body drops, the snapshot stays, the copy still reads the value. Control with a plain delta: body and snapshot drop, read `None`.

An aspect-wide purge with its reset (`osis` `purge()`, the only API path) hides this in the state and names snapshots stamped before the request, but a snapshot stamped after it (a concurrent compaction) that carries the import's values stays: `drop_purged_snapshot` misses it.

Fix to weigh: own an import's delta by its origins for purge (own dots of other imports listing one origin need thought, spec/permissions.md §7), keep a residue for it, and reword §5's "no values of its own" to snapshots. The origin thing's bodies are out of scope (a move is a copy).
