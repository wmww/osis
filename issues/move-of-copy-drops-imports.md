# Moving a copy drops what its imports gave it
> Summary: `moves::import_one` takes only content commits and snapshots as origins, never imports (spec/permissions.md §7 lists the same). A copy M moved on before any snapshot of M exists gives its new copy none of M's imported content: the new copy reads empty where M reads the moved history.
> Tags: engine, permissions

Seen (review of import-dots): `review::honest_moves_after_compaction_apply_spec_perm_7` without its snapshots of the copy: the second copy's `t:text.0` reads `None`, the first's `"3a2a1a0a"`.

Options: `move_thing` snapshots each aspect of the source first where imports hold writes not covered by a held snapshot (needs the snapshot right, spec/permissions.md §8), or an import may list an import as origin (its writes re-sourced again: `Commit(I)` dots ranked like a snapshot's carried writes).
