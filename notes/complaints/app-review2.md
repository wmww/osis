# app-review2
> Summary: Workflow notes from reviewing app milestones 2 and 3.
- No two-person harness for the GUI workspace (osis-sim lives in core's tests): hand-delivering every commit plaintext between two `Osis::create` stores (ignoring ingest errors) is enough for rosters, roles and grants, not for testing what the other person can actually decrypt.
- A background command redirecting into a scratchpad subdir that does not exist yet fails silently until you check; `mkdir -p` the log dir first.
