# Tenure ledger places a later audit at the tenure's end
> Summary: A tenure ended by `until` or self-removal and audited later carries the later demotion's frontier but only the ending key, so a roster snapshot replays that audit at the end; and a tenure of an actor ended by its own admin's explicit demotion exempts nobody when replayed, though the walk exempted that admin. Either way a re-snapshot can change an answer (about 1 snapshot in 10^3 in random histories).
> Tags: permissions

Repro: `cargo test --release -p osis-perm -- --ignored resnapshot_neutral_large --nocapture` counts the cases.

spec/permissions.md §6: a tenure's `until` is the key of the demotion that ended it and its frontier is that of the explicit demotion "that ended or last audited it". When the end was an `until` or a self-removal and an explicit demotion of that edge audited it later (§5.1, "as if the member still held the role"), the ledger keeps the end key and the auditor's frontier but not the auditor's position. osis-perm replays the audit at the end key. If the member's standing through another path changed between the end and the audit (a second self-removal, a removal elsewhere), the class falls and layer-2 demotion points computed at the end differ from the walk's. Also two commits of one node at one `ts` (holders of one link key) are not ordered against a tenure end keyed `(ts, node)`.

Second case (since the review decision that removing a member actor one is admin of, while holding authority on the target, is an explicit demotion, spec §2): the walk exempts the demoter from its own demotion (it reaches the member) and keeps its standing for the next explicit write; the ledger records only the ending node, which for a late-audited tenure is the self-remover who must not be exempt, so a replayed tenure end exempts nobody. `RosterState::own_demotions` and `late_audits` count both.

Measured by `crates/osis-perm/tests/roster.rs` (neutrality runs, counted): about 30 of 30k edges-model histories, 38 of 20k joint, 5 of 30k snapshot-model; every other re-snapshot is neutral, compacted or not.

Options: (a) accept (the requirement only promises that writes a snapshot did not include are lost); (b) add the auditing demotion's key to `tenure` (a wire field, spec/data-model.md §9) and replay the audit there. Recommended: (a) unless a sim scenario shows a user-visible loss.
