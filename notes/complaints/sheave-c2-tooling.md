# sheave-c2-tooling
> Summary: Snags from the differential tooling job: a half-stale small-items entry; a shrink that silently does not shrink.

- notes/test-design.md's shrinker item said the shrinker accepts any panic, while `testenv::shrink_failure` had kept to the original's kind (`failure_class`) for a while and sync-test-harness.md said so. Reading the code first caught it; a list entry should be trimmed when part of it lands.
- `testenv::shrinking` silently skips shrinking (it re-raises the panic) when the panic came after the run's `Script` was dropped, since no steps were recorded. A check placed after `holds_on` returned looked like a broken shrinker for one run. A one-line "not shrunk: no script recorded" on stderr would have said it at once.
