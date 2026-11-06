# A chat's record in a content commit
> Summary: Chat creates C in its rules commit (`create()`, `required.0^`, settings, then `sync`), so C's record travels in a content commit and a joiner re-reads each pending role commit on C about twice as often as with a record-alone role commit. Accepted until issues/link-leave-splits-thing.md is fixed: the record-alone order hits that bug.
> Tags: chat, engine, sync, performance

Joiners fetch role commits first (spec/commits.md §2); one per earlier member waits on C's record. Made by a record-alone role commit, a joiner at m=5 members reads pending commits 11 times (`scale::joiner_reads_each_pending_commit_few_times`, bound 2m+1); with C's record inside libs/chat's rules commit, 23. The sim test makes its chat record-alone so it keeps measuring members' records; chat itself pays the 23. The public API has no record-alone create: a draft persists by a content commit (`Write`), or by records alone only inside `sync`/`grant`/`make_link` (`Osis::persist`), all of which label C before the rules commit can follow, and `required.0^` first set after `sync` splits the chat at a link joiner's leave (issues/link-leave-splits-thing.md).

Options: fix that bug, then make chat create record-alone first (draft, `sync`, then the rules); or make `apply::waits` cheap for a record arriving in a content commit (then any app's shared thing benefits).
