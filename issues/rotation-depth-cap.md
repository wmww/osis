# Departures deeper than 8 member actors are not rotated
> Summary: `engine/rotation/mod.rs` `MAX_DEPTH` 8 stops `collect` (departures inside members) and `ensure_rotated` at 8 actors, so a device removed 9+ actors below a group (org → team → … → person → device) keeps the group's secrets; spec/crypto.md §4 has no such bound.
> Tags: security, engine, permissions

Found by the arbitrary-values audit. `path.contains(a)` already stops cycles, so the cap only exists to bound work: `collect` enumerates paths without memoization, and a `Departure` carries its `via` path, so a DAG with diamonds is exponential in depth even under the cap (fanout 10 at depth 8 is 10^8 paths). Fix needs both: no depth cap, and work polynomial in the actor graph (memoize per actor; represent departures without enumerating every path, or dedupe by (actor, member) where the path does not change the rotation needed). Test: a 10-deep member chain whose bottom device is removed; every level above rotates.
