# A role through holders works only where the node syncs the holders
> Summary: Tess decided "a role counts wherever its grants are held; syncing is a separate choice" (account write on A, A admin of B, B admin of C, the account syncing only C writes on C). Not built: a node gets a thing's secrets only through a ticket or a holder's sync ID it syncs. Direction decided (notes/holder-access-study.md, The direction), lands with A2: tickets are a bootstrap offer only; roles never feed what syncs; every grant A takes sits under A's sync ID; no accepting (a grant from outside A's writers is an external signal A's admins enable); a node syncing C holds for keys every holder on every path giving its account a role on C (own boxes only), found by following taken grants down through holders' key parts. spec/requirements.md stays as it is until the direction proves practical.
> Priority: normal
> Tags: sync, engine, spec

## Measured
Alice's A, B, C, all independent; Bob write on A, A admin of B, B admin of C; Bob writes on C (a sync `holding` probe):

| Bob's strongs | role on C | C's secrets | write on C |
|---|---|---|---|
| C | none | none | refused |
| A, C | write | none | refused (C not held) |
| B, C | none | none | refused |
| A, B, C | write | held | applies |

The same with `rotation::lost::reached` forced true (clause 3 switched off): the same table.
1. Bob's grant on A reaches his nodes only as a ticket fire, taken at a strong to A (spec/sync-inbox.md §5 Carried commits). With no strong to A the node holds no evidence of its first hop.
2. With A synced, C's boxes to B still travel only under B's own sync ID (spec/sync-judgement.md §2: a grant naming a holder travels under the holder's sync ID, with the target's boxes). Role commits go down the keys-open chain, boxes do not: the node shows write on C and holds no secret of it. This gap is today's design, whatever is decided.

Evidence: C's sync unit carries chain certificates only for bodies already under it (their authors' paths), so nothing carries A -> B -> C to a node that has not written there; C's own sync ID cannot carry C's secrets (opening it needs C's sync secret). A2 (notes/redesign-plan.md) changes the evidence, not where secrets travel.

## Why roles counting over every held role commit fails
That was the rule before clause 3. What a node holds outside its closure is incidental (other authors' chain certificates, records kept while needed, commits fires carry), so the role hung on what happened to arrive and stay: a never-taken grant on T1 counted through T2's certificates (T2 minted with admin T1, full-size seeds 138, 183); a dropped grant kept counting, and once D's sync ticket echoed it, forever (notes/node-closure.md clause 8); lost access dropped secrets by one role and kept content by another (seed 180). Clause 3 matches the role to the carriage: role commits naming a holder go under the sync ID of each thing whose keys open it, so a path whose first holder is synced has all its evidence.

## The obstacle
For a node syncing only C, C's secrets come through A's and B's key material, under their sync IDs. Which holders' sync IDs to fetch can only be found from the account's grants (C is opaque without its secrets). Followed over every grant naming the account, a stranger granting the account a role on X would make the node fetch X's sync ID and follow X's grants onward, so nodes would sync on a stranger's say.

## Direction
notes/holder-access-study.md (The direction, Finding the paths, The model). What a node fetches comes from what it syncs and the real holder chains of those things, found down from the account's grants over taken grants only: grants by a holder's writers, or external grants its admins enabled. A stranger's grant A's admins did not enable is not taken, so it changes no role, fetch or list read. Planned in notes/redesign-plan.md A2 (external grants as an external signal at A5).
