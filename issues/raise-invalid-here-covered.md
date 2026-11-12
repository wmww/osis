# A raise applied elsewhere but invalid here leaves the lowering's epoch covering
> Summary: An epoch covers a departure when its names hold the holder's newest lowering (or, from `Departure::later`, a later write lowering it), on the reading that its rotator then boxed the holder at none of the roles it left. False when the rotator, or a granter, applied a write raising the holder again that applies nothing here: one ordered after a demotion of its author that the author had not seen (plain invalid, not audited, so no drop event). A removed reader keeps reading. Tests `rotation::tests::regrant_invalid_here_boxes_removed_reader_spec_crypto_4` (main's rule, no rotator needed) and `later_removal_named_by_reraising_rotator_spec_crypto_4` (later writes), both `#[ignore]` until fixed.
> Priority: critical
> Tags: security, keys, rotation

## Shapes
Peers A (first admin), a2 (admin), M (reader), R (admin). A removes M (L, rotating to e_L), then demotes a2 to write (D). a2 has not seen D; its later writes on G's edges apply nowhere D is held.
- a2 holds L, re-grants M (G), boxing M at e_L. At A, G applies nothing; M's departure is attributed to L; e_L names L: covered. A encrypts under e_L, which M opens. The audited twin (D ordered after G) is handled: the drop is an event named by D (`newest_event_names_departure_spec_crypto_4`).
- R holds L and G, not D: R rotates naming L and boxing M. At A, R's epoch covers M's departure (same hole, through a rotation).
- a2 holds neither L nor D: removes M (W) and re-grants it (G); R holds W and G and rotates naming W, boxing M. At A, W is a later write of M's departure, so R's epoch covers it. Without `later` R named nothing A attributes it to; the later-writes rule widens the hole to rotators that never held L.

## Direction
Principle: a name stands for "my rotator boxed this holder at none of those roles" only if every raise the namer applied after it applies here too. Candidates: (1) treat a held raising write on the holder's edge, ordered after its newest lowering and applied nothing here, as an event like an audit drop, named by what took its author's right (the drop rule's demotion is one case), later writes counting only after it; (2) names list also the raising writes the rotator held unapplied, and an epoch covers only when it names every such write held here after the name. Rejected: an epoch boxing the holder covers nothing (box removals by a superseding rotation not yet established here hide it; boxes decide nothing). Cover.tla has no raising writes after a removal; add one by an admin demoted concurrently.
