# Design coherence: three areas without a principle
> Summary: Carve-out audit of spec/ (Tess: carve-outs are a design smell). Worst areas: retention × validity × dropped bodies (~30 carve-outs, 14+ seed-fix patches), key epochs/rotation (9 limits, 4 exceptions, 6 open stuck-state issues), ephemeral data (its stated principle contradicted by its own rules). Candidate principles below each need Tess (requirements touched). Also 8 spec contradictions.
> Tags: spec, design, tess-call

## A. Retention: "every drop is vouched"
Decided (Tess): three history modes, each keeping its property: default (no promise, not exposed, kept as convenient), keep history (promised, exposed), keep no history (gone once replaced); plus expiry and purgeable-by. Absolute keep-at-most T goes: it was misread as "compact by T"; its point was always that content is gone, which is expiry. Design study running.
Keep bounds act only through a right holder's valid compaction snapshot; only expiry acts unattended. Readers drop on that snapshot. Removes: "never received" for keep-bound drops, per-node death dates (only the compactor dates), carrier rules (the snapshot is the carrier), waiting parts kept past bounds, most suspect flags, the "moves no date" rule. Requirements: Deletion "by the bound every node MUST drop" weakens (a reader keeps a gone-once-replaced body until a writer syncs; privacy).

## B. Keys: "rotating needs only the right to rotate"
A rotation never needs a prior secret; history is a separate box any holder of the old secret may add. Removes: wait-for-re-seal, the lockout-recovery predicate, "removal goes alone while Seal waits", the stuck states (lockout-vandal-left, removal-without-possession, fork-held-by-non-rotators). Also state once in requirements: "secrets cannot be un-shared" (about 6 crypto limits become consequences). Cost: new holders read old content only once someone holding the old secrets adds history.

## C. Ephemeral: "durable semantics, held in memory, no exceptions"
Expiry goes value-less and resets stay; ordinary retention (keep at most 0 after replaced replaces "Superseded commits"); paging allowed; drafts gone (built on branch drop-drafts). Removes vanish-whole, the six-condition supersede rule, "expiring never coalesced", never-paged, the forced retention shape. Cost: memory holds tombstones of expired fast writes until compaction.

## Contradictions found
1. commits §3: a shared key actor must use commit form, but ephemeral content must use session form (issues/shared-key-actor-ephemeral).
2. crdt §4.7: an expired ephemeral delta's resets vanish (removed data shows again) vs requirements "a removal is final".
3. commits §5 keeps waiting parts' bodies and purged values "for good" vs requirements "purge is prompt", "peer input never causes unbounded storage".
4. commits §5 death dates depend on arrival order vs requirements Deterministic "never of arrival order".
5. sync §5 a co-reader serving a hostless label drops a body with live writes without a carrier vs sync §7 / commits §5 "live state is never lost".
6. permissions §5.1 cuts purge requests from an oversized frontier vs requirements Cost "such a removal fails".
7. permissions §5.1 step 4 grants that audit get an empty frontier (issues/grant-audits-without-frontier); expired grant counts as none vs invite grant refused over an ended grant.
8. commits §6 "one exception" to one write = one commit (fixed on branch drop-drafts).
