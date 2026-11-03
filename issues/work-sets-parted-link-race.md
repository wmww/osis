# `work_sets_match_full_passes` tolerance hides most of link_race
> Summary: since 39cdf0c1 (d53, labels-cost) link_race parts between work sets and full passes on 12-30% of seeds, so the 1% tolerance is nearly used up by one scenario and a missed trigger there would not show; the oracle's narrowed form fails outright.
> Tags: tests, sim, node-sync

Measured, main f90e2b90 and earlier:
- `OSIS_SIM_ONLY=link_race OSIS_SIM_SEEDS=60` (seeds 0..60): 7 parted (3, 7, 21, 23, 24, 51, 55), so the test fails (`7 of 60 runs parted`, limit 2). Same 7 at 5130bd82^; none at 39cdf0c1^ or feb9adf6^.
- Whole set, 20 seeds: from 231700000, 7 of 1060 parted (link_race 231700002, 06, 10, 14, 16, 18; grant_to_group 231700016); from 231730000, 1 (link_race 231730001). notes/testing.md says about 3 in 1000.

Reading: benign as far as checked. The parted reports differ in `writes` and the random dice follow (seed 3: 4 against 5 writes; grant_to_group 231700016: 7 against 6), matching notes/testing.md's "a pass goes a few messages later". Only link_race seed 3 was traced to its end (labels-cost review, notes/sync.md); the others are assumed alike. `parted` lines print only under `--nocapture`: a passing run shows none of this.

Possible fix: separate the sim's fault dice from what a pass sends, so a pass left out cannot move the random writes; then lower the tolerance to zero. `honest_flows_wait_for_no_resync` has no dice and stays clean (seeds 231690000+6).
