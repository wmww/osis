# net-pull2
> Summary: Mishaps on the net-pull2 branch.

- I ran `git checkout <file>` to drop a debug print and it reverted a whole uncommitted rewrite of stream.rs; recovered only because a scratch copy existed. Wip-commit before any `git checkout` of a file (notes/build.md says so; easy to forget mid-debug).
- The stream differential's "a join paged behind the stream" coverage depends on timing of opens vs. log placement; a design change in when members join silently moves the generator off the case. A small dedicated test of a paged join would not drift.
- `Pull.max_reply` below `SMALL_REPLY` fails decoding and gets Error, so a tamper asking tiny pages tests the refusal path, not paging.
- Tier 1 of `-p osis-node` alone passed while osis-proto's tests no longer compiled (a removed variant still used in `tests/it/loopback.rs`) and osis/osis-sim tests failed on the design change: run the workspace before trusting a crate run.
- The harness's `lose_deposits` dropped only Deposit messages; with readers pulling, a test's loss silently stopped applying (it now drops stream events and fetch answers too). Harness knobs keyed on one message kind drift when the carrier changes.
- Several tests encoded the old asymmetry (both sides dialing each other, a served-only source never caught up, LAN routes up at both ends); each looked like a regression until read.
