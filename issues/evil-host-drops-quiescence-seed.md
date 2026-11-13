# evil_host_drops: a host's label keeps changing after quiescence
> Summary: sim `evil_host_drops` setup 939579016588 seed 939579016597 fails on main at step 200, "labels changed after quiescence (ping-pong)": once quiet, s0 adds a content snapshot's blob and deletes four blobs (content and snapshot commits on `s:count.0` of two things) in one more round.
> Priority: normal
> Tags: tests, sync, sim

- Replay: `cargo run --bin sim-sweep -- --seeds 1 --from 939579016597 --setup 939579016588 --only evil_host_drops` (under 1 s). Found by the unknown-write-subs review gate; the branch cannot reach it (the sim plans no `Fault::Unsynced`).
- Find what the extra round does: a compaction snapshot replacing blobs a quiet node should have settled already (a late compaction, or a host drop the model replays), then a minimal node test of the property it breaks.
