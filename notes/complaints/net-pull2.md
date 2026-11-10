# net-pull2
> Summary: Mishaps on the net-pull2 branch.

- I ran `git checkout <file>` to drop a debug print and it reverted a whole uncommitted rewrite of stream.rs; recovered only because a scratch copy existed. Wip-commit before any `git checkout` of a file (notes/build.md says so; easy to forget mid-debug).
- The stream differential's "a join paged behind the stream" coverage depends on timing of opens vs. log placement; a design change in when members join silently moves the generator off the case. A small dedicated test of a paged join would not drift.
- `Pull.max_reply` below `SMALL_REPLY` fails decoding and gets Error, so a tamper asking tiny pages tests the refusal path, not paging.
- Tier 1 of `-p osis-node` alone passed while osis-proto's tests no longer compiled (a removed variant still used in `tests/it/loopback.rs`) and osis/osis-sim tests failed on the design change: run the workspace before trusting a crate run.
- The harness's `lose_deposits` dropped only Deposit messages; with readers pulling, a test's loss silently stopped applying (it now drops stream events and fetch answers too). Harness knobs keyed on one message kind drift when the carrier changes.
- Several tests encoded the old asymmetry (both sides dialing each other, a served-only source never caught up, LAN routes up at both ends); each looked like a regression until read.
- `label_state` ignored `opening`, so a connection still finding its shared set never held `Synced` back, while waits and `complete` did count it: two readings of "caught up" in one API. Hidden until served sessions could be caught up.
- A listener's shared set began (and sent Beacons) before its Resumed answer went out; the dialer answered Error 14 and an Error to Beacons is ignored, so both sides waited for good with the connection otherwise working. Nothing reported it; it showed only as a label stuck `Syncing` once status counted opening connections.
- `stream::a_refused_pull_is_asked_again` refused "the first PullReply" without knowing which side it went to; message order shifts moved it to the other side.
- The sim's divergence detail "at []" lists host copies only (`check.rs gap`); in a no-host scenario it is always empty, and the issue read it as "the writer has no entry". Read what a diagnostic field means before building a theory on it.
- The sim trace prints a peer message when it is sent, not delivered (one delivery per step, in random order): a FetchReply printed early may never arrive. Debug prints per delivery (`Event::Bytes`) showed it.
- The node `Net` harness delivers everything at each `run()`, so restarts and outages only hit quiescent nodes: a fetch is never in flight across a crash. Tests of in-flight windows need `net.step()` with a condition (stream.rs `fetch_in_flight`).
