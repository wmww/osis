# flow-control-2
- Restoring a file after a temporary test edit with `git checkout <file>` reverted all uncommitted work in it (saved only by a scratch copy). Wip-commit before any temporary edit.
- Node tests that drop the actions of a local call (`let (new, _) = replace_label(..)`) passed only because `RESEND_MS` resent the lost requests; once unanswered requests stopped being resent they failed. Fixed in replaced_chunks and sync_more; `net.lose_uploads` now answers rate-limited instead of leaving requests unanswered.
