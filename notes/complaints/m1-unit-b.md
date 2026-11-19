# m1-unit-b
> Summary: Workflow notes from the M1 brief 1b model run.

- Sampling an exhaustive family by `step_by(threads * 8)` aligned with the 8-bit strong mask and silently dropped three strongs from every sampled world; a step coprime with the mask (7) samples it. Check what a sampled family still contains.
- The same default test suite took 3 s to 16 s depending on box load (load average 26 from other agents); budget test time by counting work, not by one wall-time reading.
