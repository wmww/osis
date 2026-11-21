# Handoff
> Summary: For the next coordinator (from Mizzen): the one decision A1 waits on (the walk rebuild's shape), the open Tess questions, the latent items worth knowing, osprey's base unit, and the drafts' answered questions. Delete once its items are taken.

The design is notes/write-path-design.md (Decided, the lettered rules); the plan notes/redesign-plan.md (stages P and D done; A1's spec written: spec/permissions.md §1-§2, §5.1-§5.2, §6); what runs beside it notes/priorities.md.

## Waiting on Tess
- **The walk rebuild's shape (blocks A1)**: issues/perm-eval-cost.md (tess-call, critical). Checkpoint replay misses the requirement "every operation costs in proportion to what it changes" for backdated or late-arriving role writes (a count test on main: `core/perm/tests/it/paths/counts.rs`). Options: (A) re-step only what a change reaches, designed as verdicts that are functions of the hops they read with changes carried by the memo system (the coordinator's lean), or (B) checkpoint replay with a weaker cost requirement (a requirements change). Until answered, osis-perm's old walk trails the model and its differentials carry `rate:` known failures (issues/perm-walk-trails-model.md).
- **Requirements wording**: spec/requirements.md line 15 says a write's actors start at "the key that signs it"; under owner keys the actors are all things (a key signs as a thing). Not contradicted by the spec, but stale: offered to Tess, not yet answered.
- **The first owner key** (issues/owner-key-first-attach.md): built as option 1, one clause (`Rules::attach_on_path`), option 2 the variant `-attach-kept`.
- Small: CLAUDE.md's GUI test command lacks `--no-fail-fast` (app's known failure stops kit's tests); a smaller fixed setting for the KNOWN story search is hers to allow; the gate.checks CPU share raise (notes/time-limits.md) is hers to review.

## Left to take
- **osprey**: the box has no base unit in notes/time-limits.md, so `tools/limits.py` checks nothing there: `tools/heavy tools/limits.py unit`, then add its row, before a gate runs on it.
- **The drafts' questions**: notes/a1-spec is now an Open list and code-brief order (the spec holds the rules); a2-spec and a3-spec are recut when A2/A3 are specified, from their To recut sections and the list below.

## Every other question the drafts held for Tess
Read with her; none needs a design decision:
- **Within the requirements as written**: how long a far thing shows a removed key's writes (now the counted lazy-delivery gap, issues/removed-key-writes-show-far.md), a write shown valid then invalid, hostile writers keeping a removal away (a node missing data reads as if it never had it; removal binds nodes that receive it). A stolen key's backdated delete is undone and deletes in the theft window are accepted (a removed key erases nothing; no bin).
- **The coordinator's to settle**: a delete is content, so a witness's vouch keeps one a removed node made (notes/purge-model.md For Tess 1). An evidence copy should show only the role change it is evidence of: a design task, back to Tess only if not simple. Not visible to users: a write through a step giving too little waits, the 64-thing path bound, the sealed form's size and padding (notes/path-form.md).
- **Requirements, approved and written**: growth "or on what its writers act through"; a removed writer's role changes kept only where the removal names them; a node granted sync learns the thing's identifier and who granted it.
- **Standing choices Windlass made, seen by Tess**: a hop to a far mint ancestor is marked direct; the engine prefers a far ancestor's direct grant to the chain through what holds the thing; a removal's result shows only what the removed party lowered; one commit's role parts on a thing fall together; removal copies that let a reader open through another thing are kept for good; the custody differential runs by hand, not in the gate.

## Coordinator habits that cost time this session
- Land a branch only after checking whether main moved since its gate (`git merge-base --is-ancestor origin/main HEAD`); if it moved, `tools/land` lists files both sides changed: run those crates' tests first.
- Never chain a `cd` fallback into a worktree path: name the claimed worktree explicitly.
- A model change (roles-model, held-model) runs its consumers' differentials (osis-perm `paths::`, engine `evidence::`) before its gate.
