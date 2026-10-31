# rotation-cycles
> Summary: worker complaints from the rotation-cycles branch.

- `walks::open_equals_rebuild_random_secrets_compactions` reads `OSIS_WALKS_SECRETS_START`, not `OSIS_WALKS_START`; the latter is a known variable, so setting it ran the default seeds silently ("5 seeds from 0"). Briefs naming "from N" for a walks test should name the variable.
- A stranded node cannot grant on the stranded actor (granting boxes under its epoch), so a test that lifts stranding by a grant from the stranded admin fails: the lift has to come from a node that already may rotate the whole cycle.
- (leave-out rework) The node test harness's groups are owned by bare nodes with no inbox, so a re-seal to an actor member has no inbox to go to: a design that relies on re-seal delivery to nested readers cannot be exercised there (found via `revokes::nested_departure_revoke_placed`).
- Python string surgery on a 2000-line file: a non-greedy regex to drop a debug `eprintln!` stopped at the first `}` inside its format string and mangled the line; grep for leftovers after any regex cleanup.
