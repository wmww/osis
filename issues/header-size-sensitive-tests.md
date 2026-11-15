# Two tests break when every commit header grows a byte
> Summary: Adding one byte to every header (a mandatory trailing bool) made osis-sync `driver::a_sibling_rotation_proves_again_spec_sync_opens_1` and osis `scale::a_new_thing_judges_the_bodies_it_changes` fail deterministically; changing only commit IDs (header blind) does not. Something reads byte sizes it should not, or the sync one hides a real race.
> Priority: normal
> Tags: sync, tests

## Seen
- Sync: after node 1 rotates the account, node 0 holds two connections from sibling node 2 and neither carries a proven account (`proven_at(0, 2, new)` false); node 0 holds the rotation. A sibling's Prove at the new epoch never lands, or a duplicate connection keeps the unproven one.
- Scale: after 10 things, one of the next 8 that writes no snapshot judges 4 bodies, not 2 (one more body synced and read through the `Stamped<CommitId, Set<Tid>>` memo, right after a snapshot round); after 100 things all judge 2. The compaction trigger weighs bytes, so its rounds move with header size; the test's "same count" holds only for the sizes it was tuned at.

## Repro
In `osis_commit::Header::encode_into`, emit a 17-item array with a trailing `false` and accept it in `read` (what the own-cover marker first did; it now rides only on own covers, spec/wire.md §4 field 16). Perturbing only `engine::write::draw_blind` (IDs move, sizes don't) passes both.

## Next
Find what in the sync path depends on message or header size (the sim's per-byte delivery time racing the re-prove after a rotation is the first suspect); make the scale test state its property without a size-tuned trigger.
