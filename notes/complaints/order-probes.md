# order-probes
- The named order tests print no tallies, so "outputs identical" needed a throwaway probe dumping each `check`'s `Seen` (work counters zeroed) and the judgment files, built on both revisions: two extra debug builds of engine `it`.
- `tools/icount BIN -q order::` reports the module total only; per-test counts took a hand-written xargs loop (`tools/pertest.py` runs every binary under heavy).
