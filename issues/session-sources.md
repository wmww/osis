# Durable headers are never forgotten
> Summary: Content commits write in session form, demotion frontiers list commit IDs only, and snapshot frontiers list only traced sessions (built; spec/crdt.md §2.1, §8, spec/permissions.md §5.1). Left: step 6, a node forgetting a durable content commit's header once its held parts are all gone as covered, expired or purged (spec/commits.md §5 still says "never headers"; memory commits already forget, spec/sync.md §9). The demoter compacting first is issues/drop-rejoin-robust.md item 7.
> Tags: engine, node, spec, design

Tess's direction: nothing grows permanently by the number of app launches or sessions. Today every durable commit's header, meta, ranges and void mark stay for good (about 690 B per overwrite row in the growth probe, notes/growth.md), so a long-lived register grows with its overwrites even when compacted.

## Rule to build
A node forgets a content commit's header, meta, ranges and void mark once both hold:
- every part of it the node held is dropped as covered, expired, or purged;
- node-sync tracks no entry of its blobs at any host.

Kept: the value-less list (`v/`) and leftovers (`w/`) of expired or purged parts (they, not the header, strip late valued copies); role commits (the timeline, certificates and epoch introductions read them); a thing's first commit (its `created.0` part is never covered); a lasting commit (spec/commits.md §5, `retention::lasting`: a purged permanent delta's, its purge commit's).

**Replays.** A forgotten commit that arrives again is indexed and joined again: join idempotence keeps the state right, a demotion that did not list it keeps it invalid (frontiers are by commit ID), and the snapshot that covered it vouches for its live writes. Node-sync's entry rows stop the node fetching it again. No drop-on-arrival check.

## Build
- Use `apply/free.rs` `unindex_commit`; node-sync reports when a commit's entries are gone.
- Test: like `free_equals_never_indexed`, forgetting equals never having held the commit, beyond the kept rows. Differential: a node that forgot vs one that kept, after replaying every forgotten commit, reads the same.
- Re-measure the growth probe.
- Spec: spec/commits.md §5 "never headers" replaced; spec/sync.md §7.

## Decided (Tess)
- Demotion frontiers by commit ID (32 B per uncompacted commit of the removed node), with the double-removal residual: accepted. A frontier past `MAX_LIST_BYTES` (about 1.9 million commits) cannot be written: a stated limit (spec/requirements.md Cost; issues/long-aspect-cost.md).
- The demoter compacting before an explicit demotion: not built for now (nothing blinks out, frontiers stay bounded by compaction cadence); revisit if demotion frontiers measure large. It is drop-rejoin-robust item 7.

## Open from step 1
- A removed admin's rotation covered by a role snapshot loses its record of which commit started the key epoch: an extra safe rotation, not a hole. Simplest fix: always list role commits in a frontier.
- A commit whose held parts are covered is left out of a frontier even if it also touches a thing the demoter does not hold; spec/permissions.md §5.1 says it should be listed. notes/frontier-study.md's rule ("lists every received commit of X in scope that is not droppable now", heads per (aspect, node) for permanent aspects) would settle both.
