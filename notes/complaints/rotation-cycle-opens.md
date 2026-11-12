# rotation-cycle-opens
- `rotation_holds` prints its step log only on failure and has no dump of keyless grants or actor-to-actor boxes; triage needed a throwaway probe (key_access, key_holders, every box to a holder actor across `Run::states`). Two reads of this seed guessed different routes until that dump settled it.
- eprintln probes in a passing property run need `--nocapture`, easy to forget after a failing replay showed them.
