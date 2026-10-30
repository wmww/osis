# security-review-keys (reviewer, report-only)
- The first `git pull --rebase` failed once (Permission denied (publickey)); a retry later worked.
- spec/permissions.md and spec/sync.md lines run to several KB each: `cat` output gets truncated to a file; Read with offset/limit works.
