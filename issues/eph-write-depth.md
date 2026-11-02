# Remote ephemeral writes skip the full-chain depth check
> Summary: `eph_write_valid` checks `MAX_OWNER_DEPTH` only on the durable part of an ephemeral thing's chain (and not at all when an ephemeral owner is the author), while the local writer's `within_depth` checks the whole chain: a remote node accepts writes the writer itself refuses and spec/permissions.md §1 calls invalid.
> Tags: engine, permissions

spec/permissions.md §1: a delta on a thing more than `MAX_OWNER_DEPTH` owner links below its top is invalid, ephemeral things included. Local writes go through `write::within_depth` over the whole chain (ephemeral records, then held ones). Remote ephemeral parts go through `ephemeral/remote.rs` `eph_write_valid`, which walks the ephemeral records up to the nearest durable thing `cur` and then checks `validity::too_deep(cur)`: the links below `cur` are not counted, so ephemeral things stacked under a durable thing near the limit pass. The `owner == node` return (an ephemeral owner that is the author) skips the depth check entirely.

Fix shape: require `owner_chain(tid, record_of).end()` to be a top before the walk (then `too_deep(cur)` is implied). Check what re-judges a remote part when a missing record above the author arrives: today such a part is valid without that record. Needs a test with an ephemeral chain over a durable chain at depth 60.
