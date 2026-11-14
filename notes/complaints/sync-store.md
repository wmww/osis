# sync-store complaints
- The foundation branch was rebased away mid-task (sync-foundation → sync-rebuild with renamed proto codes and `read_log`'s shape): one rebase, a few renames; cheap only because the store had no callers yet.
- `tools/policy.py`'s dead-pub check forces an allowlist line per store operation no other module calls yet; easy to strip live lines by a loop and then re-add the deferred ones.
- `osis_store::Faults` counts writes across every device sharing it, so a crash test must rebuild the whole prefix of operations per crash point: quadratic, but small at 8 steps.
