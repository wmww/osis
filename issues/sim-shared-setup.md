# Share a sim scenario's setup across a sweep's seeds?
> Summary: A third of the gate's sim CPU is each seed's calm setup (accounts, groups, grants, quiet rounds) before its first faulty `run`; building it once per sweep and copying it per seed would cut about 30% of the stage (about 550 CPU-s, 35 s wall at 15 seeds), at the price of every seed of a scenario sharing one draw of setup keys, tids and clock skews per sweep.
> Priority: low
> Tags: tess-call, tests, osis-sim, performance

## The numbers
`sim-sweep --seeds 2 --from 7000` (every scenario, CPU per job until the scenario's first `NetSim::run`): 88 of 266 CPU-s (33%); scenarios that never call `run` count 0, so this is a floor. `team_reads_member_thing` 7.0 of 16.7, `snapshot_rights` 5.3 of 7.0, `ephemeral` 3.4 of 7.0. The setup is real node-sync work (grants, pairing, label creation reaching every node), not idle rounds: the rounds that only confirm quiescence are 3% of the stage.

## The option
Each scenario's setup built once per sweep from a setup seed drawn from the sweep's offset (each gate a fresh one), every seed a copy (`NetSim` over the node and hub hooks of notes/testing.md, Copied worlds) whose dice and node rngs are reseeded from the seed before the faulty part. What seeds would no longer vary within one sweep: the setup's keys and so tids, label and blob IDs (which tie-breaks and orders fire: first admin, tid order), and the nodes' clock skews and drifts. Across gates they still vary. notes/testing.md (Copied worlds, Not copied) records not doing this for that reason.

## The question for Tess
Is one setup draw per scenario per gate (15 seeds of faults and schedules over it) enough, given release checks would do the same at 150 seeds unless they keep per-seed setups?
