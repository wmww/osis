# net-pull2
> Summary: Mishaps on the net-pull2 branch.

- I ran `git checkout <file>` to drop a debug print and it reverted a whole uncommitted rewrite of stream.rs; recovered only because a scratch copy existed. Wip-commit before any `git checkout` of a file (notes/build.md says so; easy to forget mid-debug).
- The stream differential's "a join paged behind the stream" coverage depends on timing of opens vs. log placement; a design change in when members join silently moves the generator off the case. A small dedicated test of a paged join would not drift.
- `Pull.max_reply` below `SMALL_REPLY` fails decoding and gets Error, so a tamper asking tiny pages tests the refusal path, not paging.
