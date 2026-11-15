# fathom-invalid-headers
- `wt claim` ran before the forget-invalid commits reached origin, so the issue file and the engine change the brief named were missing; I rebuilt the engine side, then merged onto them at rebase (conflicts in 8 files). A brief naming new upstream work should name its commit.
- The old own-store keep of invalid bodies masked a real bug: `Engine::load` judged validity before `take_account`, so `me()` was `None` and a restart dropped the node's own invalid parts. Found only because unlogging removed the mask.
- `git checkout core` in a planted-fault script reverts uncommitted test edits under `core/sync/tests` too: commit before running fault loops.
- Review: the engine's `Meta::valid` folds "unjudged" (thing record away) into "invalid", so a rule for missing invalid parts cannot be stated plainly; it had to go on parts once held (`reopen_to_fetch`).
