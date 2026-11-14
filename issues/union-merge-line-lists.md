# Line lists every branch edits conflict on each rebase
> Summary: tools/dead_pub_allow.txt (and core/base/testenv-known.txt) take lines from many concurrent branches and conflicted on most rebases of the sync rewrite's module branches; give them git's union merge, as tools/known_failures.txt has, with a duplicate-line check in tools/policy.py.
> Priority: normal
> Tags: tools

The sync rewrite's module branches each added `deferred:` lines to tools/dead_pub_allow.txt beside each other's: 17 rebase conflicts there against 6 in the next file. Each was resolved by hand (keep both, keep one, or drop both: policy.py catches a missing line, nothing catches a duplicate).

Fix: `tools/dead_pub_allow.txt merge=union` and `core/base/testenv-known.txt merge=union` in .gitattributes, beside known_failures.txt's line (its comment says what union does to a removed line: policy.py already refuses an allow line whose item is used). policy.py refuses a duplicate line in each union file, so a line both sides added fails the next check instead of staying twice. Keep each list one item per line (sorting adds nothing: union does not care where lines go).
