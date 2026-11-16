# roles-model epochs still models merges that name forks
> Summary: roles-model `epochs` (3.4k lines, the largest module) generates and judges merges that name the forks they accept and supersede beside them; the spec's merge is only the join of its tips (spec/crypto.md §9, the `custody` model). osis-perm's `epochs_model_agrees` skips every world with such a merge (about 40% of random worlds) and every observer of P in worlds with a re-add (about 30%).
> Priority: low
> Tags: tests, roles-model

- What the differential still uses: the epoch rule's layer 2 at the account (per-thing lists, listings, witnesses' addenda, the cutoff `World::ends`, part bounds, sync IDs), judged at observers outside P and in worlds without named merges.
- What is stale: `Kind::Rotation { names, supersedes }`, `World::stands`, `Builder::forked` and the merge-signing rules (AMBIGUITIES.md entries 1c, 10, 11), the "removal stands" check built on them, and the re-add as a grant at the granter's newest epoch (custody's roster rule differs).
- Fix: rebuild the module from spec/permissions.md §5.4-§5.5 with custody's chain (merges as joins, D's roster from the chain), keeping its layer-2 checks, so the differential checks every world; or fold its layer-2 checks into `custody`, which already models listings and t's writes. Either removes the skips in core/perm/tests/it/epochs.rs.
