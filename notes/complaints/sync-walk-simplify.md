# sync-walk-simplify
- `git checkout <file>` to undo a mutation probe also undid that file's uncommitted work; commit a wip before mutating.
- The scratchpad lives on tmpfs (`/tmp`), which tools/tla/net/README says TLC state must not use; small netopen runs fit, bigger ones need a disk TMPDIR.
- The product's stream never shows an entry again after the store's head moves (spec/sync-streams.md §4 Refused: "a moved head shows the entry again"); an open before a head exists would lose the entries refused with no head, so the reader's genesis Register must reach the store before its first PullReply.
- (review) The rebase onto the split notes was a delete/modify conflict on notes/sync-boundary.md: the branch's edits had to be carried into three module notes by hand.
- (review) A re-grant probe looked like a walk bug for a while: it fails because no admin issues steps yet and the reader tests only recorded steps' keys; neither gap was written down anywhere.
