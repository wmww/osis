# unread-retainer
- A node test thing made by `new_thing` and given read by `net.grant` gets a label with no host: node-sync never hears it out, so a lifetimes repro silently judges nothing (held forever) and passes with the bug in. Give it a hosted label first (`give_own_secrets_on(&d, &home)`); worth a `Net` helper.
- Observed with the bug in (not chased, the fix removes the path): the release b wrote after losing f destroyed d at b but never reached the host under d's own label, and b listed no group labels afterwards; an explicit `release` in the same setup does reach a.
- Review: the gate's policy check fails on a dangling `issues/` pointer only after it starts; deleting an issue needs a grep of every note and issue first (`tools/policy.py` alone, seconds, catches it).
