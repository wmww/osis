# Chained writes and chain certificates still built
> Summary: spec/permissions.md §4 judges by evidence along stated paths (every edge write on a stated path's edges, E1) and has no chained writes or chain certificates; the engine still builds both, each site marked `Interim (issues/chains-retired.md)`. Stage A2 brief 3 (the switch, notes/a2-spec/README.md) deletes them.
> Priority: normal
> Tags: engine, sync, permissions

What stands in:
- osis-perm `paths`' chained pass (`Paths::is_chained`, `timeline`'s chained set): the writes chain certificates and the evidence derivation's `chained` input read; nothing of the judgement needs it once evidence is derived.
- `sync/certified.rs` (certificates over chains), `sync_ids/certs.rs`'s any-path search, `author_chain`: what a sync ID carries beside its bodies, built over any path of chained writes.
- Their tests (osis-perm `paths::chained`, the certified tests citing chains) go with them; the models' chained sets (roles-model `paths`, held-model `evidence`) stay only while the differential compares against the old build.
