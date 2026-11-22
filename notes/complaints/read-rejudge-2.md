# read-rejudge-2
- `tools/claim <name> --from REF` on a fresh name reset a local branch that already held another task's commits (the worktree's previous HEAD): harmless here (they live on their own branch), but the message reads like data loss.
- Finding who reads a stamp key inside a judgement needed a scratch backtrace dump keyed by the key's name; profile `optimized + debuginfo` inlines most facade calls into `judge::body`, so only `at file:line` frames tell the readers apart.
- A sync-level count test for "a part arriving moves only the bodies carrying it" was hard to build: most commits' entries are shared blobs carrying every part, so the blob's strip check reads them all; the case the facets cut (an account's certificate copies at a grantee) needs the grant rounds' world.
- Wall time was useless (load 34 while measuring): compare instructions.
