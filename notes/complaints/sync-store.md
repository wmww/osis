# sync-store complaints
- The foundation branch was rebased away mid-task (sync-foundation → sync-rebuild with renamed proto codes and `read_log`'s shape): one rebase, a few renames; cheap only because the store had no callers yet.
- `tools/policy.py`'s dead-pub check forces an allowlist line per store operation no other module calls yet; easy to strip live lines by a loop and then re-add the deferred ones.
- `osis_store::Faults` counts writes across every device sharing it, so a crash test must rebuild the whole prefix of operations per crash point: quadratic, but small at 8 steps.
- Review: the rebase onto sync-rebuild pulled in the engine's restored scale tests, and the branch's new `store rows read` counter made one fail (`all_flat` checks every counter, so a new counter anywhere in osis-store can fail an engine scale test). Only the full four-crate run showed it; the worker's per-crate runs predated the rebase.
- Review: a crash test that reopens the store cannot observe connection-only state (a start drops it), so `closed`-style operations need a record-backed variant to be tested at all.
