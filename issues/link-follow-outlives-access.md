# A followed direct link's sharer stays dialed after the redeemer loses access
> Summary: A redeemer keeps the link follow (`y/l`) after its redemption and drops it only when a redemption fails (`forget_link`). `wanted_hosts` dials every followed sharer key whatever labels `link_routes` gives it, so a joiner that left, was kicked or whose link K was removed keeps dialing the sharer for good, for no label. The sharer's key no longer rotates when a link ends (notes/peers.md, No automatic rotation), so these dials connect: an ex-joiner holds a session at the sharer that opens nothing (until `max_served` evicts it, then redials every `peer_retry_ms`).
> Priority: normal
> Tags: node-sync, transport

- Where: `core/node/src/sync/conn.rs` `wanted_hosts` (takes every `link_routes` entry, empty label set included) and `close_unwanted` (same); `peers.rs` `link_routes`. `status.rs` already keeps only routes sharing a label.
- Likely fix: a link route is wanted only while its label set is non-empty (the hinted label during redemption, then K's or the target's synced labels); maybe drop the follow once neither K nor the target is held. Check a leaver who kept the text and redeems again (`follow_link_peer` sets it anew).
- Test: a joiner by direct link is kicked (or leaves); its node stops dialing the sharer (a sim or osis-node count of dials or served sessions).
