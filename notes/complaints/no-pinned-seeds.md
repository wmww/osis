# no-pinned-seeds
- Most seed-pinned sync reproducers had stopped reaching the fix they were written for: switching each fix off failed none of them (issues/sync-unreached-rules.md). A pinned seed decays silently; only a mutation check shows it.
- A made-up `OSIS_*` variable on a test command fails every test (testenv's unknown-variable check): an easy way to waste a full-binary mutation run.
- Reaching a re-send corner by hand needed a failed durable write at an exact count (`disk_fault(i, n, Fail)`); the tests loop over n rather than name the write, since nothing says which write is the take.
