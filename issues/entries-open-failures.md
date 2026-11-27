# Tests failing since opening by entries landed
> Summary: 3 osis-sync tests still fail since the entries design: a re-granted public not read, and a stub fetching a record blob again once raised to read.
> Priority: critical
> Tags: sync, engine, tests

Each is in tools/known_failures.txt against this issue.
- `differential::the_public_granted_again_is_read_again_*` (no quiet run between the public's removal and its re-grant): node 0 reads thing 1 (made in thing 0, made independent by a grant to node 0) and through it thing 0 by the public; after the public's revoke and re-grant on thing 0 it sees the public's read and the admin on thing 0 but reads no value of it. Not traced past that.
- `first::a_blob_is_fetched_once_*`, `first::what_a_reader_fetches_and_drops_does_not_grow_*`: a grantee follows its signal as a stub first, fetches the maker's losing record blob, drops it as a stub needs it not, then raised to read pulls S anew and fetches it again. Options: keep what a stub fetched until judged as a reader after the raise; or the tests count fetches per holding.
