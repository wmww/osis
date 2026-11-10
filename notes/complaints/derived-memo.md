# derived-memo
> Summary: Mishaps while moving the engine's caches onto memos.

- The gate draws new property seeds per run: one run stopped on a seed that fails on main (`retention::deaths_never_early_random_large` 987589575840, the replaced-at dating class), a second passed. Checking that it was main's took a `tools/bin-at` build of an older commit; rerunning only the selected properties and the sweep without the known seed (as coordinators do) is cheaper than a second full gate.
- Gate wall time moves by a minute or more with the seeds and the box's load (one selected-properties phase: 168 s, then 247 s), so it cannot show a 10% gain; `tools/icount` on one test and the default-tests phase's CPU seconds can.
- A background chat watch wakes the session for every message of anyone; reading the chat at merge points was enough.
