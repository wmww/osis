# sync-oddities-review3 complaints
> Summary: Mishaps met in the third review of sync-oddities.

- The review's rebase hit node.md conflicts in single-line paragraphs of 5 KB: three commits, each resolved by a script diffing sentences. One long line per bullet makes every parallel note edit a conflict.
- Picked a task ID with `ls -t` on the shared tasks directory and waited 110 s on another agent's task: use the ID the Bash result printed.
- Blocked: after the rebase, the gate fails on `keep_clients::a_client_reads_through_a_kept_holder` and `a_member_of_the_holder_reads_no_copy` (see the report). The hold in `names_label_opening` delays Bob's read by 8 s of clock; about 40 min of tracing did not find why.
