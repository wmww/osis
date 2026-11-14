# A withdrawn epoch's content stays with its box holders
> Summary: Study done, recommendation A built on branch `withdrawn-epoch` (requirements Limit, compaction gate names aside, tests, Withdrawn.tla). Content written under an epoch whose named removal is later voided by its author's concurrent demotion reaches only that epoch's box holders; no rule closes it (a two-world argument, checked in TLC). Delete this issue when the branch merges: notes/crypto.md (Unsuperseded and withdraw) carries the result.
> Priority: normal
> Tags: keys, rotation

Shape (`rotation::tests::unmet_epoch_withdrawn_by_its_maker_spec_crypto_4`): A demotes admin a2 (D); a2, unaware, removes reader M (W); R, holding W but not D, rotates read (e_R, boxes no M) and writes under it. Wherever D is held W applies nothing, M reads on, e_R's names are unmet at every holder of its secret, R withdraws it, and e_R's secret goes in no history box.

## (1) Extent
- **Who loses**: everyone e_R did not box, not only M: holders granted later and any holder R had not yet seen (checked: `withdrawn_epoch_content_reaches_its_box_holders_only_spec_crypto_4`; a later explicit re-grant of M changes nothing). The content is not lost: e_R's box holders read it, and it stays unreadable to everyone else for good.
- **What is lost**: what writers that had seen W but not D wrote in that window (R, and any node that established e_R before D reached it). After D arrives nothing more is written under e_R.
- **Who can trigger it**: only an admin fight: an admin demotes another (or removes its admin path through a holder actor) while that one removes or demotes a holder. Both writes need admin authority. The other triggers are harmless: a finalize voided by a renewal is handled by "stands" (no refutation); a device of M's own account removed while it wrote M's self-removal hurts only M, who was leaving.
- **Deliberate denial**: an admin can remove M outright, so no gain. A non-admin cannot make D or W. A host that delays D to the writers lengthens the window (more content lost), but only once an admin fight exists; this turns a delay into a lasting read loss, which plain withholding cannot.
- **Deliberate leak**: none under A. Under B (pass it on) a removed member with a host withholding G gets content written after its removal, and ongoing content too (below), given an admin dispute.

## (2) Simpler
A is the status quo plus a requirements Limit and a compaction fix. B reverses R9 for refuted epochs and turns the existing leak tests (`applied_name_void_elsewhere_through_holder_actor_spec_crypto_4`, `departs_mark_void_elsewhere_through_holder_actor_spec_crypto_4`) into stated limits.

## (3) Better
A. B leaks in the world where a re-grant G of a2, ordered between D and W, sits with an absent admin: nodes lacking G hand M e_R, while nodes holding G see e_R current (W applies, e_R covers M) and keep writing under it until the withdraw reaches them, so M reads new content written by writers that know it was removed (planted: names counted met fails both tests above and the new content test). A loses only window content of a rare admin fight and never leaks.

## (4) Closing it completely
Impossible. While the admin holding G (or an unseen demotion X of A, which voids D) is away, A, a2, R and M hold the same commits in a world where M is entitled and one where M was removed; any rule that hands M e_R without that admin does so in both. Waiting for the re-granter is not enough (X), and the set of possible writers is not closed, so waiting for everyone stalls on any device gone for good. core/test/tla/rotation/Withdrawn.tla checks it: `met` safe, not live; `refuted` leaks; `wait` leaks; `waitall` stalls; `regrant` (an explicit re-grant of M unlocks e_R) safe within the existing invalid-grant limit but not live; `joiners` (box e_R to later holders, M kept out by names) safe and live for later holders only.

## (5) Higher-level cause
The cause is that a removal's validity can flip any number of times as earlier writes arrive: a demotion voids the demoted admin's writes its author had not received, and a re-grant or a counter-demotion voids that again. This comes from "admins are equals / a removal voided by writes its author had not received" plus determinism over held data with no consensus. The voiding is the only cut a backdating admin cannot forge, so it is not a requirement of dubious value: nothing goes back to Tess. Candidates examined:
- Voiding concurrent removals: needed against backdating. Letting addenda vouch for edge writes (other admins that had seen W) shrinks the case but does not close it (R may receive W after D's `ts`) and puts addenda into the role walk.
- History boxes carry established epochs only (R9): this is the protection itself; dropping it for refuted epochs is B.
- Trust set: W is no dispute (D is not a seed of W), and a trust set is local.
- The writer re-keying at the withdraw: R holds no more than A does; it leaks in the G world like B.
- The left-out member's own nodes: they hold no secret, so they decide nothing.

## Recommendation
A: state the Limit, fix compaction. Built: spec/requirements.md Permissions Limit; spec/crypto.md §4 compaction gate names aside (`may_compact_secrets` over `RoleEpochs::established_names_aside`); tests above plus `withdrawn_epoch_compacts_judged_alike_spec_crypto_4` (randomized compactor, aspects, clock, restarts, arrival order; a newcomer judges every `secrets.0` part and the current epochs as the compactor does). Planted: the names-gated compaction fails the compaction test; a gate passing everything fails `established::r9_reseal_before_rotation_commit`; names counted met fails the content test and the two leak tests.

Optional later, if Tess wants the gap smaller: the `joiners` rule (later holders get e_R, M kept out by its names). Safe in the model, but it needs a box class at superseded epochs that every grant and re-seal consults by names, the hearsay pattern notes/crypto.md rejects.

Related, found here: issues/reseal-under-own-epoch-leaks.md (a fresh encryption of another's commit re-seals its sections under the sealer's epoch, which hands e_R's content to M in this shape and leaks in plain removals); issues/reader-history-entry-blocks-compaction.md.
