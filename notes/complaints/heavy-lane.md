# heavy-lane
- A mutant of tools/heavy's tree kill left two spinning orphans holding heavy_test's capture pipe: the test hung until killed by PID. The lane tests now write to files and kill survivors.
- The heavy lock's log showed short runs (under 300 CPU-s) waiting 136 min for 26 min of holds over 48 h, and 1,177 s for one 94 CPU-s held-model run: fixed by the short lane (notes/build.md, Heavy lock).
