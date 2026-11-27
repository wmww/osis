# A record blob its sealer drops before a store shows it stays at that store for good
> Summary: A writer logs a record blob, a store pulls it, and before the store's stream shows it back the writer judges it a loser, drops it from its own store and forgets its row (neither held nor shown); nobody else fetched it (only winners are fetched), so no node ever deletes it at the store. Timing-dependent: three osis-sync tests that pass on luck fail when blob bytes or delivery order move.
> Priority: normal
> Tags: sync, tests

Traced in `growth::record_blobs_at_a_store_stay_flat_spec_sync_ids_6`: writer 3's record blob of a round is held at node 1's store and named by no engine afterwards; writer 3's `cert_blobs_missing` (`read/live.rs`) saw it held and losing (`unneeded`) while the store had not shown it (`blob_shown` false, so no delete), then, held nowhere and not shown, dropped its row (`gone`). Losers are deleted only by a node holding their row and seeing them shown at the store.

The same family, not traced to the line: `first::a_new_reader_logs_no_copy_of_what_its_source_holds_spec_sync_judgement_3` and `first::what_a_reader_fetches_and_drops_does_not_grow_spec_permissions_4` (at 5n the maker fetches 2 blobs from the reader and keeps neither; their rows are gone at the end). See also issues/record-blob-settle-order.md (two readers settle by arrival).

The test seeds collided too: `round * 3 + i` over writers {0, 2, 3} gave writer 3 at round r and writer 0 at r+1 one rng, so one blob; `round * 4 + i` now.

Direction: a blob this node logged keeps its row while a store source may hold it unshown (until S is heard out at each store source after the drop), so the delete follows once the store shows it; or the drop of an own losing blob sends the Delete itself to each store source that pulled it. Then a hand-built test: one writer, one store, the loser dropped before the store's stream event, asserting the store ends without it.
