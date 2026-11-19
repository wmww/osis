# Sync unit: one independent thing and its dependents
> Summary: Decided by Tess (notes/sync-unit-scope.md): a sync unit stops being a root's readable closure and becomes one independent thing with its dependents; a closure is synced unit by unit, by readers and by nodes keeping it unread alike. Designed in notes/sync-unit-design.md (argued from the spec and counted, not modelled); open: four questions for Tess (notes/redesign-plan.md), the model, then the staged build.
> Priority: normal
> Tags: sync, engine, spec, tess-call

Fixed (Tess): sharing a root gives its closure; promoting a thing to independent has no behavioural cost; the old model, its trade-offs and the reason for the change stay recorded (notes/sync-unit-scope.md).

## Settled in notes/sync-unit-design.md (to be modelled before building)
- **What goes, shrinks or stays** of the built model, each with spec section, code and issues: §1.
- **The unit's list of direct independent members**: member blobs, derived data in the unit's required set, sealed under its sync secret; the member's keys reach a holder from the member's own steps (claims and entry boxes for holder things): §2.
- **A node keeping a closure unread**: the walk, dropping, cycles, caps, and exactly what it learns: §3. **Readers**: §4.
- **Promotion**: the promotion commit stays in the former unit, bodies move by entries, and leave the former unit only once carried in the new: §5.
- **Attach, detach, several closures, a referrer that cannot enter its target, release**: §6. **Removal**: §7.
- **Costs counted**: §8 and issues/many-sync-ids-cost.md. **Status over a closure**: §9. **Wins**: §10. **Cases crossing the account design** (a stated path's evidence, a removal's units, hearing a unit out, a public profile, an externally grantable thing, promotion under a removal, the account as a unit): §12.

## Questions for Tess
1. Answered (Tess): **a strong to a dependent thing is a reference into its independent's unit and brings that unit, always** (design §6, option (a) alone; no promotion on reference). Whoever can read the dependent thing can read its independent's whole unit already (its keys derive from that unit's; a grant on the thing alone makes it independent), so nothing new is shown. Whether the target is independent then changes cost, never behaviour: referring to one small dependent thing brings its whole unit, and a node keeping the referrer unread keeps that unit and all it lists; the cheap route is making the thing independent, which sharing it does, and the API and apps steer there. It survives a later promotion by someone who cannot write the referrer: the promotion's commit and member blob stay in the former unit (design §5), so the path from the referrer still reaches the thing.

Answered (Tess): at a promotion the thing's blobs go under the new sync ID as they are, provided that is the easy build. A holder thing gets a member's sync secret from the member's steps in the X25519 form. A referrer holding only sync on its target still brings it. A unit the remover does not administer goes on serving a removed holder its ciphertext until one of its admins issues a step: accepted, and worth closing if an easy way is seen.

## Open
- **Model** (notes/redesign-plan.md, M1): the unit, member blobs, the unread walk, release and hostile member blobs are modelled (held-model `unit`), with four findings against the design to settle before B1: notes/closure-model.md, The unit model, Findings. Promotion and its open cases (judged invalid, forked, a mixed commit) are M1 brief 2.
- **Not established by the study**: why an idle reconnect sends a join per shared sync ID; what a reader sends back at a first sync (23 KB per unit); whether issues/differential-full-size-classes.md's five seeds all go with multi-unit carriage; deposit and promotion code paths were read in the spec, not traced in code.
- **spec/requirements.md**: Data a node cannot read already states what such a node learns; an edit waits on the referrer holding only sync (notes/redesign-plan.md, Q7).
- **With the account redesign**: what this design assumes of it is listed in the design note (Assumed of the account design).
- The staged build: notes/redesign-plan.md, stages S1, M1, B1 to B3; S1 (the cost defects) and M1 (the model) need no answer.
