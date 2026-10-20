# Lost read access erases only secrets, not content
> Summary: A removed node drops the role secrets it lost but keeps the plaintext aspect states, commit records, wraps and sync records of the things it can no longer read, so a later compromise of that device yields them (spec/permissions.md §3 MUST; spec/requirements.md, Deletion: forward secure).
> Tags: security, node, store, permissions

Scenario: A grants B read on D and writes D. B syncs, then A removes B. B's `drop_lost_secrets` returns D and drops D's secrets (`k/`, shredded), but `get(D, ak)` still returns the value; the `c/` commit records, aspect units, wraps under D's labels and `y/` records stay in the store under live keys.

Test: `crates/osis-node/tests/flows.rs::removal_erases_lost_content_spec_perm_3` (ignored; fails today).

Recommendation: a node-core "forget thing" in the `drop_lost` transaction: for each thing whose reader actor (the thing if it has own secrets, else its owner, transitively) is now lost and not readable by another path (another held actor in its closure), `drop_aspect` every aspect (shredded), rewrite its commit records without its deltas (`osis_commit::rewrite`, `Shred::Yes`, or drop the record when nothing readable remains; headers stay, spec/commits.md §5), drop its wraps and blob records under the lost labels, drop its `y/` entries, rebuild the indexes (`drop_indexes`), and evict it from `Core` (states, by-aspect index). Keep the `/created` record and membership-class state the node still needs to judge others' writes only while it is readable by another path. Things the node owns or its person owns are never lost. A re-grant re-syncs (notes/permissions.md). Also clears undo buffers of those aspects (they go with the unit).
