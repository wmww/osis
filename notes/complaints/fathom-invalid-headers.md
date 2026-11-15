# fathom-invalid-headers
- The brief named `issues/invalid-headers-kept.md` on the rebuild branch; no such file exists on any branch, so the problem was rebuilt from the brief and the code.
- The brief said the engine already forgot a commit kept only for an invalid part; it did not (`forgettable` had no such branch, the spec said "kept").
- The old own-store keep of invalid bodies masked a real bug: `Engine::load` judged validity before `take_account`, so `me()` was `None` and a restart dropped the node's own invalid parts. Found only because unlogging removed the mask.
- `git checkout core` in a planted-fault script reverts uncommitted test edits under `core/sync/tests` too: commit before running fault loops.
