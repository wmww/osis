# A forged half-valid rotation of a holder actor leaks to its removed forger
> Summary: A writer of holder actor M whose role on M runs through another holder actor can publish a rotation of M whose `keys.0` part is valid and whose `secrets.0` part fails Authority. Its keyset is a held valid keyset (an anchor, a Seal target) but its epoch is established nowhere, so no knowing rotation of M ever lists it: A's admins keep sealing M at it, and the forger opens A's new content after its removal, for good. The fix needs a decision on validity layering. The rotation property fails on about 1.2% of seeds on it.
> Priority: critical
> Tags: security, keys, engine, tess-call

Replay: `OSIS_ROTATION_START=<seed> OSIS_ROTATION_SEEDS=1 cargo test -p osis-engine --lib -- --ignored --exact rotation::tests_property::rotation_holds_tier2_spec_crypto_4`. Seeds 0..1000 failing when filed: 75, 107, 130, 147, 319, 331, 450, 482, 531, 607, 631, 875 (stale once the generator or wire changes). Each holds such a half-valid rotation; 607 fails the "made by a rotator that saw it depart" check, the others the "encrypts under" check; all have holder actors and forgers.

## Shape (seed 482)
- Peer F is first admin of actor S; S holds a role on actor M; F reaches M only through S.
- F leaves M by a self-removal that also rotates M (`tests_departs::Forge::Rotating`). Its `keys.0` part on M is valid (judged by role at the commit's key); its `secrets.0` part fails Authority (F shows no possession of S). So M's keyset k_F is held valid everywhere, while k_F's epoch is established nowhere (`EpochInfo::rotations` takes valid `secrets.0` parts only).
- A box of A to M names k_F, so k_F is an anchor of M for A.
- M's honest admin removes F and rotates M knowingly. That keyset lists M's current epochs, never k_F's (not established), so it does not descend from k_F, and k_F is not stale (no held valid keyset lists it, its body is valid).
- A's admin then seals M at k_F (newest keyset descending from the anchor). It cannot judge k_F (it lacks its secret: the stated limit), so the departure from M blocks nothing. F holds k_F's secret and opens A's new epochs. The spec limit says this lasts "until A is sealed at a keyset of M descending from a rotation of M that knows"; here no such keyset can exist.

## The property and the options
Property: a keyset counts (held valid, anchor, Seal target) exactly when its rotation counts. Today "held valid keyset" is the `keys.0` body's validity, and "established" is the rotation commit's (its `secrets.0` part), so they can split.
- **A. Authority judges the whole rotation**: a rotation failing Authority makes its `keys.0` delta on M invalid too (spec/crypto.md §4 Authority, spec/permissions.md §5.2). Then k_F is held invalid, A's boxes naming it are stale, A rotates. Cost: a validity cycle. Authority reads the possession keys of held valid keysets of A's holder actors, and those keysets' validity would now depend on their own rotations' Authority, which reads keysets of their holder actors, and so on around a holder-actor cycle. The fixpoint must be shown unique and arrival-order independent, or Authority must read possession keys from keysets valid by role rules alone (a second notion of "valid keyset").
- **B. Keep validity, widen staleness and Seal**: a keyset whose every rotation body sits in a commit whose `secrets.0` part on M is invalid counts as held invalid for Seal, anchors and Stale (rule 2), while Possession keeps reading every role-valid keyset's keys. No cycle (Seal and Stale feed no validity), but two notions of a valid keyset.
- Either needs a Depth0 run: the model has no rotation that fails Authority (Possess is a precondition of every honest rotation, and Forge makes epochs only after the forger's removal), so a `D0_*` config with a half-valid forged rotation should come first.

Related: issues/keys-depth0-rethink.md, issues/blocked-walk-stops-at-readers.md, issues/keys-depth0-removed-member-rotates.md.
