# first-admin-d
- Tier 1 took 23 min wall (load 30-36, kit tests building beside it); clippy's check artifacts did not help the test build.
- The brief's "chat: `create()` plus a durable write" costs joiners pending re-reads (`scale::joiner_reads_each_pending_commit_few_times`: 23 against 11 when the chat's record is in its rules commit); the record-alone order (draft, `sync`, rules) loses a link joiner's posts in `link_joiner_leaves_spec_perm_7`. Both in issues/chat-record-in-content-commit.md.
- Stated limits in chat docs ("`admit own` does not take a chat") had gone stale when chats got a first admin; nothing tests chat admission by `admit own`.
