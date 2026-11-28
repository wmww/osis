# A kept copy reads nothing
> Summary: A node removed saying retain lists the thing in `kept_copies()` (`retained_copies`), but its values read `None`: a direct removal (chat's default kick) and a way through a kept holder alike. The engine alone keeps the copy; the node's sync drops its bodies.
> Priority: normal
> Tags: engine, sync, retention

Ignored on it (osis-sync `holding::`, spec/permissions.md §3 Retain):
- `a_direct_removal_saying_retain_keeps_a_copy_that_reads_spec_permissions_3`, the plainest: Bob grants Alice read on T, she holds it, Bob removes her saying retain.
- `a_keyed_live_grant_from_a_kept_holder_keeps_a_copy_spec_permissions_3` (a way alive with key access keeps) and `an_ended_keyed_grant_keeps_a_copy_spec_permissions_3` (Bob removes T1's grant on T0 saying retain): Alice reads T0 only through T1.

In each, `why_role` says "kept copy: yes, of T (a held path reads it: false)" and `get` is `None`. The engine-only test `closure::a_retained_copy_stays_once_released_spec_commits_5` passes: with a sync node, `osis_base::trace` shows the copy's bodies at T's sync ID go `Must -> Unjudged (no body meta at S: outside, waiting for a complete pass)` as the secrets drop ("read-only copy kept via ..."), and the engine then lacks the value's commit (only the record's commits stay, `why_kept`). So the bodies leave with S's entries: nothing keeps a copy's bodies once the node no longer reads S, and once the way ends nothing carries T into the node closure (spec/sync-set.md §2 First entry). Which rule should hold a copy's bodies, and which reader reads it (spec/permissions.md §3 The copy), is unsettled against the stub model.

Seen in the dogfood smoke pass: `osis chat kick` (the chat's default keeps a read-only copy) left the kicked member a chat with its record and roster but no messages and no `retention^.0`.
