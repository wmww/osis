# Work sets vs full passes part at two seeds since whole-2b
> Summary: osis-sim `work_sets::work_sets_match_full_passes` parts at `revocation_bob` seed 9461 (the work-sets run makes 30 writes and 50 commits, the full-passes run 29 and 49; host 0 holds, node 0 commits, reads and sync state end apart) and `member_churn` seed 9473 (`held_checked` 378 vs 384 only). Both pass on 02be71d2e (main before whole-2b, item 276). Not triaged.
> Tags: sync, sim, tests

Repro: `OSIS_SIM_FROM=9461 OSIS_SIM_SEEDS=1 OSIS_SIM_ONLY=revocation_bob cargo test -p osis-sim --test it -- --ignored --exact work_sets::work_sets_match_full_passes` (1 s); the same with `OSIS_SIM_FROM=9473 OSIS_SIM_ONLY=member_churn` (7 s). Found in periodic run 15 (whole tier-2 set, `OSIS_SIM_FROM=9460`, 1040 runs, 2 parted).

9461 is a real difference (notes/testing.md: a parted run is to be read): a write lands in one run and not the other, so the two ends differ in reads. 9473 differs only in how many held checks ran; may be whole-2b's must-carry judging per blob being pass-scoped differently in work sets (a missed trigger would show as a later arrival, which it does not).
