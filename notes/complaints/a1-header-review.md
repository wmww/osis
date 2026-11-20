# a1-header-review
- Scale tests asserting on store bytes written counted whole encrypted units (4-11 KB): a header change that moved commit IDs flipped two tests by one unit. Byte bounds now read bytes handed to the store, with one page of slack.
- `tools/bin-at` checks REV out in the worktree for minutes: no edits possible meanwhile; reading the branch through `git show` filled the wait.
- A new `osis_base::costs` count is read by every test that compares all spans (168 `costs::take` sites; osis `making::`, engine `closure::` exact equality): a scale-only counter belongs outside the shared table (`osis_store::bytes_handed`). Only the gate showed it.
