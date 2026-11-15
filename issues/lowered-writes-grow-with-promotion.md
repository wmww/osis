# Lowered writes grow by a commit with promotion and link-join-held combined
> Summary: osis-sync `growth::a_lowered_writers_invalid_writes_leave_nothing_and_return_on_regrant_spec_commits_5` grows by one `c/` row and one `bp/` row at node 0's engine from 10 to 20 lowered writes when link-join-held and promote-leave are combined; it passes with either alone. Ignored until fixed.
> Priority: normal
> Tags: sync, tests

Seen when link-join-held landed on promote-leave: the test fails every run there, and passes on promote-leave alone and on link-join-held alone. Find which commit node 0 keeps at 20 writes and not at 10, fix, and un-ignore the test.
