# A role through holders works only where the node syncs the holders
> Summary: Tess decided "a role counts wherever its grants are held; syncing is a separate choice" (account write on A, A admin of B, B admin of C, the account syncing only C writes on C). Not built: the role filter (notes/node-closure.md Roles taken up, clause 3) is not what blocks it. A node gets a thing's secrets only through a ticket or a holder's sync ID it syncs, and only the account's grants could point it at holders to fetch, which a stranger controls. Needs Tess's choice among the options below.
> Priority: normal
> Tags: sync, engine, spec, tess-call

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
For a node syncing only C, C's secrets come through A's and B's key material, under their sync IDs. Which holders' sync IDs to fetch can only be found from the account's grants (C is opaque without its secrets). A stranger granting the account a role on X would then make the node fetch X's sync ID and follow X's grants onward, so nodes would sync on a stranger's say. Taking grant fires as they arrive is also a rejected rule (a declined grant's records stay: sync `growth::a_declined_grant_returns_storage_to_a_fresh_worlds_*`).

## Options
1. The strong stays the choice, stated as syncing (no "accepting"): a role through holder H is usable where the node syncs H, since grants naming H and boxes to H travel under H's sync ID. Close gap 2: boxes to a holder travel down the keys-open chain as its role commits do, so syncing the first holder is enough (A -> B -> C works with strongs to A and C). Cheap for a realm that references its contents by weaks (notes/realms.md); a holder's sync ID then carries the boxes of everything below it by roles.
2. A lighter choice than a strong: the account marks a holder to act through, and the node syncs that sync ID's role commits and boxes only, not its sync unit. A new holding mode and a sync filter by entry kind; still a choice per holder.
3. Roles decide which key material is fetched (every holder on the account's paths). Nodes sync on a stranger's say.
4. Clause 3 dropped alone: changes nothing in the measured world and brings back the class above.
