# tooling-2
> Summary: workflow notes from the tooling fixes (gate CPU table, probe --dead, vouches shrink, policy untracked).

- A tools test fixture naming an `OSIS_*` variable (`OSIS_A_START` in a fabricated log) fails policy's `env_vars` check, which reads tools/ too: fixtures use a listed name.
- Three properties of an engine gate (tombstone, forged parts, unmerge) run no seed runner, so the gate's CPU table shows them as `(no CPU line)`; a per-property figure for them still needs a run alone.
