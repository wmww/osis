# Opening a sync ID: by role and by secret both carry weight today
> Summary: Checked against spec and code. An old secret alone opens nothing: a reader that is behind gets back in only by a peer opening on its role (J, ByRole), and a holder that only stores gets every new sync secret from a fresh ticket fired on its inbox. So by-role cannot simply go. The simplification on offer: every key change leaves a sealed copy of the new secrets for each holder in the sync ID's own steps, as link keys get today; then an old secret catches up, tickets never go stale, and by-role opening and fresh tickets on key changes can go.
> Priority: low
> Tags: sync, tess-call

What holds today:
- **A holder that only stores** follows no step by itself: entry boxes go to link keys only ("Other readers get none", spec/sync-ids.md §3). When its head moves past its keys it stops, and only a box of the new sync secret restarts it (spec/sync-judgement.md §6 Stops), delivered as a fresh ticket on its inbox (spec/sync-inbox.md §5 Key changes). It can be behind by zero changes of the sync key.
- **A reader with an old read secret** matches no credential an up-to-date peer shows (spec/sync-opens.md §4 Admissible: read secrets at a current epoch), and a claim on a newer step needs that step's claim set, which Behind answers do not carry (spec/wire.md §11.2). Once S is open it reads forward (a rotation is wrapped under the epoch it supersedes), unless a rotation was compacted away.
- **Only by-role** opens: a first sync with no secret; a reader behind, at a reading peer. It does not help a holder that only stores (a store judges J unknown). A holder granted again after a gap opens by role but cannot read its boxes there: a fresh ticket delivers them.
- The Departed rule (§4) refuses by roster and needs no opening by role.

What the simplification takes (not costed): an entry box of the read and sync secrets for every reader and sync holder in each step; a way to open at a reading peer by the newest step's claim; or claim sets in Behind answers (helps at storing peers only). Costs to weigh: bytes per key change in proportion to holders, and a node that only stores seeing how many holders there are (spec/requirements.md, what such a node must not learn).

Both ways are built (spec/sync-opens.md §4, spec/sync-inbox.md §5 Key changes).
