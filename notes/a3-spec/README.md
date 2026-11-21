# A3 spec draft: the map
> Summary: Stage A3 (notes/redesign-plan.md, A3: a removal as evidence) after the design was restated: a removal's list stays inside the removal, as built, so the per-thing leaf form these drafts specify is not the design; which draft sections stand and which go, far delivery as decided (lazy, with the reader's deposit to be modelled), the open points left, the two parked leaks, the code briefs.

Design: notes/write-path-design.md §2 (E4: the list in the removal; How a removal reaches a far thing). Draft files: notes/a3-spec/permissions.md, wire.md, sync-judgement.md, crypto.md, commits.md, written over A2's draft (notes/a2-spec/) for a list split into a root and per-thing leaves. Model: held-model `evidence` (`Stage::A2`, lists whole), findings notes/evidence-model-findings.md.

## Verdict
**To recut.** The leaf form is not built on: a removal carried down by key rotations two grants below arrives without the leaf for the thing it lands on (finding 35), and every rule tried for where leaves live either placed them once or kept every leaf with its removal for good (findings 30, 34). With the list in the removal whoever holds a removal holds what it keeps, and no reader waits on a part of a list. Cost and what a reader learns: notes/write-path-design.md §2, E4.

## To recut
By draft section, what the design changes. Spec text is rewritten from this after stage D2 cuts held-model (notes/redesign-plan.md, D1 result).
| draft section | under the design |
|---|---|
| permissions §5.1 Frontier (root and per-thing leaves), Reading a list, Leaves travel as evidence; §4 the leaf clause | go: spec/permissions.md §5.1 Frontier stands as one list in the commit |
| permissions §5.1 The list, per form | stands as the writers' rule, with its second clause (notes/write-path-design.md §1, L3: the remover's own path) |
| permissions §5.1 A remover that does not hold a thing | stands (it lists nothing there; no hear-out) |
| permissions §5.2 Content, second sentence (a cut keeps only from its own list) | stands |
| permissions §4 Role changes travel whole, no `ROLE_KEEP` for a removal | stands: a removal stays where it is evidence |
| sync-judgement §1 leaf blobs, §2 the leaf clause | go; §2's removal clause stands (in the required set while the unit holds a write it judges) |
| crypto §4 Carried demotions placed by the required set | stands, each demotion whole with its list (Open 8) |
| commits §4 Unjudgeable's leaf clause | goes (nothing waits on a leaf) |
| commits §4 Provisional, last sentence | stands |
| wire §4 field 12 as a list root, the leaf, the leaf blob | go: field 12 stands as built |

Goes with the leaf form outside the drafts: the engine's leaves derivation (notes/evidence-derivation.md, Leaves; built unused, its tests ignored), osis-commit's unused leaf encoding if any landed.

## Far delivery
A removal reaches a thing other than its own as today (decided, Tess: no eager delivery): with that thing's next key rotation by a writer holding it (its keyset carries the demotion: spec/crypto.md §4 Carried demotions), and wherever a node holds both the removal and a write it judges (the removal is on the write's path, so in the evidence of the write's sync IDs). Nothing logs a removal anywhere for its own sake. Where neither happens (a thing no remaining member writes, its readers served only by stores), its readers show the removed key's later writes there: an open bug in an issue, not something to build around.
- **The reader's deposit on sight** (wanted if simple and good; nothing built): notes/write-path-design.md §2, D4, with what would make it trouble. Model it first in held-model.
- **The model**: held-model `evidence` models lazy delivery (`Stage::A2`, the engine differential's oracle too) and lists whole in every copy; each reader is judged against a reference holding every removal some honest node syncing its sync ID holds, and the gap is counted (notes/evidence-model-findings.md 38; issues/removed-key-writes-show-far.md).

## What users observe
Within spec/requirements.md as written (Tess): how long a far thing shows a removed key's writes (a node missing data reads as if it never had it); a write shown valid then invalid; hostile writers keeping a removal away (a removal binds the nodes that receive it); invitations by a removed member showing until the removal arrives. spec/requirements.md Scale reads "on it, or on what its writers act through", which a removal carried as evidence falls under.

## Open
<!-- registry -->
Numbers kept: other notes cite them. 3, 4, 5, 7 and 10 were questions of the leaf form and went with it.
- **8.** **The carried-demotion seed** (Far delivery; notes/evidence-derivation.md, Carried demotions): the demotions a keyset S requires carries are a seed of S's required set, each whole with its list. Modelled (held-model `World::rotate`, `Rule::keysets`, P11: notes/evidence-model-findings.md 40): holds; the engine derivation lacks the seed until brief 3.
- **11.** **Role changes travel's keys-open half** stays whole (finding 31): read access through a holder thing reads it (spec/sync-set.md §2 T's keys open; osis-sync `holding::a_removal_reaches_a_reader_opening_the_holder_through_a_second_thing_spec_permissions_4`), as do the removal notices a node applying such a removal owes (spec/sync-inbox.md §5). Only its `ROLE_KEEP` clause for removals goes.
- **12.** **Drops and deletes resting on a provisional verdict** (finding 33; Tess, notes/handoff.md). (a) A body judged invalid is dropped at once, as built (spec/commits.md §5 Invalid), and nothing is kept aside for it: where every holder dropped it and its writer is gone, a write turning valid is lost though the node holding everything shows it. A delete at a store resting on a verdict waits for a complete pass, and is still wrong where an earlier-ordered removal voiding the cut had not reached the sync ID's sources: accepted, stated (notes/a3-spec/commits.md Provisional).

## The two parked leaks
Both wait for the account redesign (notes/priorities.md item 3); A3 closes neither.
- **A removed device reads later grants' role parts** (issues/removed-device-reads-later-grants.md): unchanged by A3, which wraps its copies and leaves as any certificate copy (under the sync ID's current wrap), so they show a removed party nothing it lacks. Smallest scenario after A3: X removed from S at the rotation minting e; Y's grant of read to Z on S, wrapped under the epoch e supersedes; X, still opening S at a store that has not taken S's new step, opens the grant's role parts (Z's name, the box keys). Re-judged at A5: its candidate "the plain rule with inbox delivery" fails today because a recipient may hold only an older epoch and have no inbox (a link left out of a profile rotation); A5 gives every enabled thing an inbox as a card aspect and publishes KEM keys only for holders and enabled things, which is what that candidate lacks [assumed: whether a link becomes such a thing is A5's spec].
- **A departed party reads the fresh deposit seed** (issues/fresh-deposit-seed-readable-by-departed.md): A2 closes its third route (a thing's current `keys.0` no longer travels as evidence); A3 closes nothing more (the rotation commit's wrap, as above, and keysets carried as keys stay; A3's keyset seed moves only demotions, no `keys.0`). Smallest scenario after A3: X removed from M; M's rotation writes a fresh seed in M's `keys.0`; A's next rotation, sealing M at its new keyset, logs M's rotation commit (seed included) under A's sync IDs, which X still reads as a direct holder of A. Re-judged at A5: the issue's only clean fix moves the seed out of certificate-visible `keys.0`, and A5 replaces `keys.0`'s inbox field by the card aspect and the admin-only aspect naming a thing's inbox and cards (notes/redesign-plan.md A5 Changes), where the seed can live sealed under the new epoch.

## What A3 removes from spec
- spec/permissions.md §4 Role changes travel: "a removal goes there for `ROLE_KEEP` after its `ts`, as a replaced grant does"; spec/sync-judgement.md §2: the removal's `ROLE_KEEP` reading.
- spec/crypto.md §4 Carried demotions: "Whoever places a keyset under a sync ID (Carried, Reported, chain certificates, spec/permissions.md §4) places with it the `roles.0` deltas of the commits it carries, with their authors' chain certificates."
- notes/a2-spec: every **(A3)** sentence.
Not added: a hear-out operation (Tess: core removes when told).

## Order of the code briefs
After D2 and A2's switch (notes/a2-spec/README.md, Order of the code briefs).
1. **Spec**, recut as above.
2. **A removal's copy by the required set**: placed and leaving by the derivation, the `ROLE_KEEP` clause deleted. Checked by the engine evidence differential against held-model recut.
3. **Carried demotions as a seed** (after Open 8): the derivation's keyset seed; the placing rule in engine rotation deleted. Checked by the rotation and deep-departure properties unchanged.
4. **Acting after a complete pass**: A2 brief 4 (a deposit's promotion and a delete at a store wait; a drop does not: Open 12).
5. **Sim and counting**: a stolen node's write in a unit, judged at a reader holding the unit's evidence; bytes a unit stores and a reader fetches per removal at n and 10n listed commits.
