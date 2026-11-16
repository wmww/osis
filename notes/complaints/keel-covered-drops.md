# keel-covered-drops
- The issue's suspect explained only part of the cost: skipping the rebuild saved 9% of the tracking test and nothing of the commits test (that one is `may_log`/`header_passes`). An env-gated skip of the suspect under `tools/icount` settles attribution in one build; do that before designing.
- The debug rebuild check (`check_rebuilt`) re-rebuilt every aspect whose part status changed, so in debug a per-drop rebuild cost twice its own: fixing the product path alone saved little until the check sampled covered drops.
