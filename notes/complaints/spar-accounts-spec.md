# spar-accounts-spec
> Summary: A spec-only job could not land: policy refuses every code and note pointer into the spec sections it deletes.

- Briefed as "spec only, land on main, policy passes"; deleting spec sections breaks ~440 pointers (code comments, test anchor names, notes, issues), ~290 in files the next piece deletes. notes/coordination.md already says no spec-first job lands alone; the brief contradicted it. Found only at the end by running policy.
- Would have prevented it: a brief for a spec rewrite that deletes sections either includes the delete piece or says "push the branch, land with piece 2"; or run `tools/policy.py --baseline` after the first deletion.
