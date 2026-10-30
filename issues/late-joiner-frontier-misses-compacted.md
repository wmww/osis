# A late joiner's demotion frontier misses writes it got only through snapshots
> Summary: a snapshot's frontier and `Absorbed` count as received only where the receiver holds the commits' headers (spec/crdt.md §8), so an admin that joined after compaction removes X with a frontier missing X's compacted writes; nodes still holding those deltas turn them invalid (observed: X's old rotation un-merged at its holder).
> Tags: perm, engine

Cause: the fix for inflated snapshot claims (a writer claiming `X: 2^60` or listing commits it signed ahead, which a demotion copied and so covered X's later writes forever). A late joiner cannot tell a real compacted commit from a pre-signed future one without its header.

Effect: at a node holding X's original delta (not yet dropped as covered), the delta is not covered by the late joiner's frontier and is un-merged; nodes holding only the snapshot keep the write (vouched). Test: `flows::late_joiner_lists_no_unheld_absorbed_spec_crdt_8` (Alice un-merges X's rotation of `/secrets`/`/keys` on Bob's removal of X). Same for node-form content writes of X that the joiner holds only through another writer's snapshot.

Options:
- Accept (spec/permissions.md §5.3 already loses what the demoter could not sync), and have holders drop such deltas as covered sooner.
- For admin-only aspects (`/secrets`, `/keys`, `/label`, ...): trust claims of snapshots whose author is not among the demoted nodes (a hostile admin is out of scope, notes/permissions.md); content claims stay header-bound since a colluding writer is in scope.
- Ship the headers of compacted commits with the snapshot (header-only blobs kept at the label), so joiners can justify claims.
