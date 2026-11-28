# Sync rewrite: what it owes
> Summary: What the sync rewrite still owes and its rulings for the review. What it built is in the area notes: notes/node-closure.md (grants with the thing granted), notes/evidence-derivation.md and notes/sync-facade.md (copies per (commit, thing), the kept derivation), notes/delete-keys.md (the delete-key check), notes/sync.md.

Spec it rebuilt from: spec/permissions.md §4, spec/sync-set.md §2, spec/sync-inbox.md §2 and §5, spec/sync-judgement.md, spec/crypto.md §7. When each item is taken up: notes/handoff.md, The route.

## Next
- **A copy's parts as exactly what S names**: a copy on one thing holding more parts than S names now (keys alone after the roles were named) stays S's log of it.
- **Acting only after a complete pass.**
- **Storage under a fork under F6** (issues/disputes-storage-under-f6.md).
- **A reproducer of the wanted-blob handover** (issues/fixture-seed-luck.md).
- **Untested**: whether a node keeping the target unread needs its own grant's grant write for the lost-access rule; what osis-sync's promotion does with a sealed fire that opens pending for drift (`Opened::Commit(_, Pending(_, Reason::Drift))`: the spec says it waits as any commit; whether it is stamped before it applies is open).

## For review
Rulings the rewrite made that the review should check:
- `sync.0` is a role part: a holder of a floor sees the steps from below its floor (step keys), as a node keeping S unread is registered already (spec/sync-ids.md §5 Path); any holder encrypts a `sync.0` part under a roles secret it holds.
- A miskeyed part never drops as invalid: a writer of S listing made-up keys leaves parts its readers hold unapplied for good (bounded as any content it may write; an entry not stamped under S's head write key counts against the bounds on unvouched input, spec/commits.md §4 Pending storage). A permanent fork's other side reads so too.
- An arrival outside a sealed fire that no pass brought (a record or commit by a live stream after the last pass ended) waits in `Core::pass_due` for the next pass end, held unneeded until then. Judging every arrival with no pass in flight judges hand-carried deliveries midway (14 tests of `osis`, the app and chat hold a delivered thing nothing needs).
- Copies are keyed per thing, so a thing's record reaches a reader only by the record rule (`certblobs::minting_opens`) or an account's public record (`current_keys`), never by a copy made for another reason; state a reader lacks that way shows as a must-hold body a caught-up reader lacks (the harness's quiet check) or a commit pending on a record.
- Two `three`-fixture tests assert the result, not the run's order: `pieces::a_small_edit_to_a_large_value_costs_its_new_pieces` asserts nodes decoded = twice the nodes the edit wrote, at both sizes (a chunk tree's levels follow its links' hashes, keyed by the seed's dedup secret, spec/wire.md §6); `growth::several_writers_grow_nothing_spec_commits_5` ages twice and asserts no `w/` row (after one aging the rows are deletes seen at a source, `tag::SEEN`, kept a tombstone lifetime).
- `keep::a_head_move_restamps_own_entries_and_readers_deposit_nothing_spec_sync_judgement_3` does not assert that node 2 deposits no rotation: a reader holding a rotation from its offer before S's stream shows it logs an encryption of its own, and of two equal blobs the lower ID stands (`blob_loses`).
- The `parts::` hand-carried harness takes `order::judge_at`'s node, made before the history: made at the history's end, its inbox step was stamped after the fires offered it.
