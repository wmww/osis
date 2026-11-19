# Sync unit: one independent thing and its dependents
> Summary: Decided by Tess (notes/sync-unit-scope.md): a sync unit stops being a root's readable closure and becomes one independent thing with its dependents; a closure is synced unit by unit, by readers and by nodes keeping it unread alike. Designed in notes/sync-unit-design.md (argued from the spec and counted, not modelled); open: five questions for Tess, the model, then the staged build.
> Priority: normal
> Tags: sync, engine, spec, tess-call

Fixed (Tess): sharing a root gives its closure; promoting a thing to independent has no behavioural cost; the old model, its trade-offs and the reason for the change stay recorded (notes/sync-unit-scope.md).

## Settled in notes/sync-unit-design.md (to be modelled before building)
- **What goes, shrinks or stays** of the built model, each with spec section, code and issues: §1.
- **The unit's list of direct independent members**: member blobs, derived data in the unit's required set, sealed under its sync secret; the member's keys reach a holder from the member's own steps (claims and entry boxes for holder things): §2.
- **A node keeping a closure unread**: the walk, dropping, cycles, caps, and exactly what it learns: §3. **Readers**: §4.
- **Promotion**: the promotion commit stays in the former unit, bodies move by entries, and leave the former unit only once carried in the new: §5.
- **Attach, detach, several closures, a referrer that cannot enter its target, release**: §6. **Removal**: §7.
- **Costs counted**: §8 and issues/many-sync-ids-cost.md. **Status over a closure**: §9. **Wins**: §10. **Stages**: §11.

## Questions for Tess
1. **A strong from outside to a dependent thing** (design §6). G references X, a dependent of H, and reads H. Today X rides under G's sync ID. X cannot be a unit of its own without an admin of X promoting it, and H's readers cannot see G's strong, so H's unit cannot be told to keep X for G. Options: (a) the strong is followed into H's unit: G's holders sync all of H's unit, a node keeping G unread keeps H's whole closure, and X is kept only while H's own tree reaches it; (b) a node that administers X promotes it in the transaction writing the strong, else (a); (c) G's sync ID keeps carrying foreign dependents, which keeps retag, deposits and copies alive for this case. In (a) and (b) what happens depends on whether X is independent, against spec/requirements.md API. Recommendation: (b), with the requirement's "a thing takes with it the part of its closure it can itself read" stated for independent targets and for dependents of the referrer; and a separate look at whether a writer, not only an admin, could promote.
2. **At a promotion, the same blobs under the new sync ID or fresh ones** (design §5). The same blobs cost one entry each and show a node keeping both units unread which earlier entries were the promoted thing's; fresh encryptions hide that and send the thing's bytes again. Recommendation: the same blobs (the thing's size and activity are visible under its own sync ID from then on anyway).
3. **How a holder thing gets a member's secrets** (design §2). Recommended: the member's steps list every holder thing and carry the sync secret for each, so nothing is written in a referrer when a member's keys change. Two sub-choices: the sync secret sealed by the step's X25519 exchange (about 48 B per holder per step, not quantum-resistant; it protects the member list and the right to fetch ciphertext, never content) or sealed to the holder's KEM key (about 1.2 KB); recommendation: the first. And whether the read secret moves into the steps too, which would end the last carriage of one thing's role parts under another's sync ID (a holder's boxes under the holder's sync ID); recommendation: not in this change, studied with the account redesign's evidence.
4. **A referrer holding only sync on its target** (design §2): the member blob is written and both readers of the referrer and nodes keeping it unread keep the target unread and walk on below it. spec/requirements.md says a thing takes "the part of its closure it can itself read". Recommendation: sync suffices (one rule: a secret held for it), and the requirement says "can itself sync".
5. **A unit the remover does not administer keeps serving a removed holder its ciphertext** until one of its admins issues a step (design §7). True today for each inner thing's own sync ID; with the bag gone it is the whole story. Recommendation: accept; reading new content is cut by the key rule as now.

## Open
- **Model first** (design §11 stage 1): held-model `closure` with the new unit, member blobs, the unread walk, and promotion in every arrival order; the cases the design lists as unmodelled (a promotion judged invalid, forked promotions, a mixed commit, a hostile writer deleting a member blob).
- **Not established by the study**: why an idle reconnect sends a join per shared sync ID; what a reader sends back at a first sync (23 KB per unit); whether issues/differential-full-size-classes.md's five seeds all go with multi-unit carriage; deposit and promotion code paths were read in the spec, not traced in code.
- **spec/requirements.md**: Data a node cannot read already states what such a node learns; edits wait on questions 1 and 4.
- **With the account redesign**: what this design assumes of it is listed in the design note (Assumed of the account design).
- The staged build (design §11); stage 0 (the cost defects) and stage 1 (the model) need no answer above.
