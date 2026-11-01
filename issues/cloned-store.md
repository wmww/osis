# Two live copies of one store void each other's commits
> Summary: two devices running copies of one store (both restored from one backup, or an old phone kept in use after migrating) sign with one key and one counter sequence, so their node-form commits overlap and spec/commits.md §4 voids both, silently. The restore gate (spec/crdt.md §2.1) only covers a copy that runs after the original stopped.
> Tags: engine, node, spec

Fixed by issues/session-sources.md step 2 (each copy draws its own session nonce). Left after that: both copies answer for one dialable key (`reach.0`) and LAN tag, a connectivity flap, not a correctness problem; move that to notes/node.md when deleting this issue.

Each copy passes its labels after opening, adopts the other's counters, then both write node form again from the same next counter until the next sync. The engine sees it: an `OverlappingCounters` diagnostic on an own-authored commit (`apply::atomic::apply_verified`), or an own header raising the counter while the node is already sure (`apply::examine`).

Options: on that signal, write commit form for good (costly: an `Absorbed` entry per commit in every later snapshot); or treat the node as compromised and have the person enroll a fresh device identity, retiring the shared one (the old key keeps signing on two devices otherwise). Needs an owner call on how far to go; a platform that never restores app data onto two live devices never hits it.
