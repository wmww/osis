# A waiting part applied past its expiry before a tick is held as a leftover
> Summary: A part that waits when its expiry T passes must go as never received (spec/commits.md §5), but the engine drops it only when its expiry timer fires (`Engine::tick`) or a reload re-examines it. Woken and applied between T and the next tick, it joins as a value-less leftover, so the read depends on whether a tick ran. Found by `order::reopen_after_each_commit_reads_alike_large_spec_commits_5` (general) seed 167395, on main too.
> Priority: normal
> Tags: engine, retention

Replay: `OSIS_ORDER_SEED=167395 cargo test -p osis-node --test it -- --ignored --exact order::reopen_after_each_commit_reads_alike_large_spec_commits_5` (4 s; the general history, `history(167395, 30, LARGE)`, fails).

Minimal order (5 of its 34 packs, thing S, `t:reg.0`):
- #24: 2 writes S's register with an expiry 1 s after its ts (T = now0 + 3 ms). It arrives first and waits (`MissingChain` of 2's identity).
- #20: 2's creation of S (`"top"`), #0 and #4 (1's identity and keys), waiting too.
- #2: 2's identity, arriving past T: both apply.

The plain node (no tick between ingests) holds #24's leftover: its value-less write beats `"top"` and S reads absent. The node reopened after each ingest drops #24 at the reload past T (`pending_drops`) and reads `"top"`; so does the plain node given an `Engine::tick` after each ingest. `"top"` is what §5 gives ("a part that waits when its expiry passes goes at T ... counts as never received"; the node may read what came before it).

Where: `apply/mod.rs` `ingest_class` and `late_parts` merge the stored pending copy (`with_pending`) and, on `Exam::Ready`, join it without dropping parts whose T passed; only the `Pending`/`Parked` arms run `retention::pending_drops`. The `T_EXPIRY` timer does it at the next tick. Likely fix: drop a waiting part past T where the stored pending copy is read for examination (as the timer would have), so the outcome is a function of the arrivals and the clock, not of tick timing; a tier-1 test with three commits as above.

The arrival-order oracle does not see this: its excuse `waited_at_expiry` spares every aspect a part may have waited at its expiry on. The reopen test compares two nodes under test with no excuse, so it does.
