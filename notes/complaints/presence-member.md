# presence-member
- The issue this branch solves lived only on an unmerged review branch (invalid-leak-rv); the brief's base did not have it, so its deletion has to happen at that merge.
- A 4-node world (needed for a removal that leaves a reader and a store) costs about 10 s to build the first time in a process; the head-move count test pays it unless flows' 4-node test ran first.
- `rotate_boxing_only(.., [Read, Sync], ..)` strands a node keeping S unread (it never gets the new sync secret), so a probe built on it measured nothing after the first move: use the Remove flow for head moves.
