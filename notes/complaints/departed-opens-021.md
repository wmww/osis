# departed-opens-021
> Summary: Workflow notes from tracing rotation_holds seed 636429853021.

- `rotation_holds` failures print the step log but no rosters or box routes; tracing needed a throwaway patch dumping `key_holders` per step, first-held keys and the final boxes (names as p<i>/a<i>). A built-in trace (env-gated) would have saved a round.
