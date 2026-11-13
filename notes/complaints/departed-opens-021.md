# departed-opens-021
> Summary: Workflow notes from tracing rotation_holds seed 636429853021.

- `rotation_holds` failures print the step log but no rosters or box routes; tracing needed a throwaway patch dumping `key_holders` per step, first-held keys and the final boxes (names as p<i>/a<i>). A built-in trace (env-gated) would have saved a round.
- Review: a scripted `Run` (now `Run::new` + `step`) reproduces a seed's shape in a few lines; a crude Seal plant (always the oldest keyset) only made `rotation_holds` seeds churn to "no fixpoint", hiding the leak; a scripted plant under one flag around one rotation was the useful one. `handed` and `first` compare log indices, so a scripted step must push its log line before `note` or a handed secret counts as held before its grant.
