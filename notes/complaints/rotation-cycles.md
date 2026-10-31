# rotation-cycles
> Summary: worker complaints from the rotation-cycles branch.

- `walks::open_equals_rebuild_random_secrets_compactions` reads `OSIS_WALKS_SECRETS_START`, not `OSIS_WALKS_START`; the latter is a known variable, so setting it ran the default seeds silently ("5 seeds from 0"). Briefs naming "from N" for a walks test should name the variable.
- A stranded node cannot grant on the stranded actor (granting boxes under its epoch), so a test that lifts stranding by a grant from the stranded admin fails: the lift has to come from a node that already may rotate the whole cycle.
