# No default test fails with the wanted-blob handover undone
> Summary: `Engine::take_wanted` and `store::Follow::settle` hand a blob sync's store holds unopened to a commit that comes to want it (a header list's chunk fetched ahead of the node above it); the only test reaching the chunk-first order is the `three` fixture at other seeds (1, 2, 5, 6), so the default suite passes without it.
> Priority: normal
> Tags: tests, sync

Without the handover a reader's commit whose aspect list goes by link pends `WaitBlobs` for good when the list's chunk arrives before its node: the chunk is kept as an unopened entry parked under S's read secrets, and nothing opens it again when the walk reaches it. `delete_keys::nothing_deletes_a_header_lists_chunks_by_level_2_spec_crypto_7` asserts the reader applies the write, but at the fixture's seed the node arrives first.

The harness's quiet check (`wanted_blobs_in_reach`) fails the handover undone on such a world ("commits waiting at quiet for a blob in reach", checked on the `three` fixture's world of seed 1 with the `take_wanted` loop emptied), so a test reaching the order needs no assertion of its own.

Wanted: a constructed test, seed 0, that reaches the order by construction: a store holding a pending commit's list chunk as an unopened entry before the node above it arrives (a `Follow` over a fake ground, or a scripted peer serving the chunk first), asserting the commit applies; checked to fail with the `take_wanted` loop removed. What decides the fetch order of two blobs announced in one event batch is not known (not the blob ID order).
