# fathom-rebuild-review-8
- Role-at-now reads take their ts from the HLC's wall (`now_ts`, `core.now()`), not the memo clock they stamp against (`Core::time`); the two agree only right after a `run`/`read`/`set_now`. A memo computed between them can hold an answer judged at a later wall than the clock it waits on (ms windows; a debug comparison could flag it).
- `git stash list` is denied by the harness even read-only; fine, but a rebase over a dirty tree then needs a wip commit first.
