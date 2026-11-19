# What perm reads of a role commit's other role-class parts goes stale
> Summary: `Held`'s per-commit `RoleParts` (role-class parts other than edge writes, with the role each needs) is computed from state outside the commit (`rotation_role`, records held via `too_deep`) and not re-derived when that state moves, so the live set differs from an open's: a vouch's verdict can change across a restart. The index check does not compare it.
> Priority: normal
> Tags: engine, security

`validity::vouching_parts` builds `RoleParts` from the header's role-class aspects, filtered by `too_deep(core, tid)` (records held now) and with each part's role read from `ix.rotation_role`. `add_role_commit` runs at apply and again only on late parts, drops, destroys and releases; an open runs it once with the records as they stand.

Example (engine `apply::tests::tree_created_in_one_commit_spec_perm_1`, peer 0): peer 1's account commit has `keys.0`/`secrets.0`/`sync.0` parts on its own thing and on a second thing S. A pass end (`retention::needed::settle`) releases S: it re-derives the commit while S's record is still held (parts on S kept, needing Write/Admin), then forgets S's record. Live, perm reads the commit as needing roles on S; reopened, S has no record (`too_deep`), so the commit needs a role on its own thing alone. Other modes: a record arriving after a commit with a part on its thing (live lacks the part, an open has it).

Observable: perm reads `RoleParts` when judging a vouch entry ("could its author write each listed commit", spec/permissions.md §5.1). Where a removed author's listed commit has a part on such a thing, the live node can judge the entry failing (no role on S) and, after a restart, holding: the vouched grant or rotation falls before the restart and stands after it. Not yet built end to end.

Repro: give `Held` a `pub(crate) fn vouching(&self) -> &BTreeMap<CommitId, Vouching>` (make `Vouching` `pub(crate)`) and add `("held vouching", ix.held.vouching())` to `tables` in `engine/testing.rs`: `cargo test -p osis-engine --lib` fails most tests (any LocalPeer world whose settle forgets a record) at the index check.

Fix (recommended): keep in `Held` only what the commit's held parts say (thing, the role its own bodies require: `rotation_required`, else `required_role`) and apply the depth rule where perm reads them, from `Held`'s own records: no outside input left to track. The other way, re-deriving each role commit whenever a record on one of its things comes or goes, adds an invalidation path per input. Edge writes share the `too_deep` input (`edge_ops`): check them with it. Then add the table to the index check.
