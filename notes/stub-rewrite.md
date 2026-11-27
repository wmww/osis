# Stub rewrite: owed and open
> Summary: What the stub rewrite (design: notes/stubs.md; rules: the spec) still owes, and its open questions for Tess, each with options and the working answer as built.

## Status
On main: spec, engine, osis-sync and the models. Tess approved the shape and took the working answers below; she may revise any. A decision is recorded by changing the spec and deleting its question here.

## Decided (Tess), to build
- **Sync ID fixed at minting** (job sheave-r12-genesis): a deterministic genesis step from a seed g(T) = kdf("sync genesis", g(mint admin), tid), carried in admin history boxes; concurrent promotions are concurrent rotations of one sync ID. Accepted: a party removed from a mint admin up X's record chain before X became independent can block a store holding none of X's steps.
- **Opening by entries** (notes/opening-design.md; build after r12 lands): every commit that boxes a holder carries its entry (a claim from the sync epoch's claim key, plus the commit's blob key sealed to the holder; a sync-only holder's own boxes), signed by the sync key; one open rule (a credential of the head opens S; an older step's sync proof is served up to that step's end); `Head(S)` answered to anyone naming S. Deletes proof by role as an open, ByRole, notices, claim sets and entry boxes, static and public entries, lapsed secrets, departed serving, sync copies, Behind. Measure filter size at n and 10n holders (every head claim is shown).
- **A stub is a starting point**: a node holding X's stub follows X's sync ID (any stub, sync-only included); a new node syncing a unit catches up from the stub it carries. One rule, no mixed following.
- **Holders a node reads through** (accounts, realms on a chain) are synced for their role entries: the node's permissions depend on them.
- **Stores may learn a padded holder count**: spec/requirements.md privacy line to change (Tess: not worried); wording owed for her sign-off, with "the grant's notice" → the grant signal.
- **Settled without her**: pairing hands over no trust records (each node sides by its own trust set); the test model's `Rule::BUILT` becomes its rule (access by the node's own grants); the public's role from one source, not grant and head listing.
- **Later (Tess)**: a pass over dependent and independent things, a weak to a dependent thing its independent's unit does not hold among them.

## Owed
- **Tests**: a departed stub holder told of its removal (`stubs::a_two_hop_chain_*` asserts only that nothing written since is read); stopped-store ByRole on its own (`grants::a_stopped_sync_holder_catches_up_by_role_*` passes by the resumed member's notice): a store meeting a reader that keeps no record of it.
- **Ignored, cause not sorted**: `public::removing_the_public_ends_*` and the rest `tools/ignores.py "stub rewrite: "` lists (engine 8, osis-sync 15).
- **Full-size differential classes**: issues/differential-full-size-classes.md.
- An external signal on a dependent thing: issues/behaviour-depends-on-own-keys.md. Each stub one more followed sync ID: issues/many-sync-ids-cost.md.
