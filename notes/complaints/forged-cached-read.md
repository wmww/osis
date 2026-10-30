# forged-cached-read
> Summary: re-review mishaps on the forged-copy placement branch.

- A previous re-reviewer ran 4 hours and was stopped mid-change, leaving a wip commit; the next re-review had to judge and finish it.
- The seq fuzz (fuzz_seq, merged joins included, 4800 scripts) does not catch a `Sibs::key` that ignores `sits`; only the two unit tests do. The undo lower-key and forged-copy cases are rare in random scripts.
