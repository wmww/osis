# A snapshot body dropped at its bound takes its receipts with it
> Summary: since snapshot-receipts, a held snapshot's frontiers and `Absorbed` count as received only while its body is held (`receipt::received` reads `Core::snapshots`, which `forget_snapshot` empties on drop). Writes that reached a node only through a snapshot dropped at its keep-at-most bound or by a purge (they stay in its state) are then left out of its demotion frontiers (removed everywhere: honest pre-demotion writes lost) and stop counting for delta waits. Unexamined: needs a call.
> Tags: node, perm, retention

Covered drops are fine: a covering snapshot's frontiers reach the dropped one's (spec/commits.md §5). Bound and purge drops are not covered by anything, and a re-snapshot (`retention` writing one before a live body's drop) takes its frontiers from held commits' ranges (`ix.ranges`), not from held snapshots' frontiers, so it does not carry them on either.

Effects:
- Demotion frontier: node X holds Bob's writes only through Carol's snapshot S, S drops at its bound (writes stay live in X's state), X removes Bob: the frontier omits them and every node un-merges them. Convergent, but it loses writes X had.
- Delta waits: a commit arriving after S dropped waits for a delta S's frontier reached (and that may be gone everywhere); one arriving before applied with the part missing. Same family as issues/cover-deleted-part-pends.md (option (a) there would close it).

Before this branch the receipt record kept a snapshot's frontiers forever (also after it turned invalid, the bug fixed). Options: (a) persist a dropped snapshot part's frontiers and `Absorbed` (counters and IDs, no content) and keep counting them while the commit is valid; spec/commits.md §5 says every index entry derived from a dropped body goes, so the spec would name this exception. (b) a snapshot's written frontiers also take held valid snapshots' frontiers where its state reflects them, so the re-snapshot before a bound drop carries them (needs the covering rule to accept it). (c) accept: spec/crdt.md §8 now says "while it holds the snapshot's body".
