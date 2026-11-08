# A derived write after the own-secrets switch is never merged
> Summary: a write under a derived epoch made after its thing got secrets of its own (its writer not yet holding them) is read only by holders of the base actor's secrets (spec/crypto.md §4 Current, a stated limit); the modelled fix: such an epoch counts as current until a rotation lists it, so its writer merges.
> Priority: normal
> Tags: keys, engine, security

Rule to add to spec/crypto.md §4 Current when built: "A derived epoch (§3) of a thing with secrets of its own that some held commit encrypts under is current too unless a rotation lists it (its history box carries it): its writer, which wrote before it held the thing's own epochs, merges (Merger). Other derived epochs of the base actor's later epochs are none of the thing's." Its limit replaces today's: "such a write concurrent with its writer's removal from the thing is read only by holders of the base actor's secrets, as the writer may no longer merge (one stamped after the removal is invalid anyway)."

Model: core/test/tla/rotation Depth0.tla has the rule; `D0_fa_dmerge` passes with it (without it `ReadsAll` failed; with the writer's removal learned first it fails, the stated limit).

Case: T plain, deriving from F. t1 gives T secrets of its own (its first grant). f1, a writer of T through F that has not received that rotation, rotates F and writes T under the derived secret of F's new epoch. The switch rotation's history carries only the derived epochs t1 held, so t1 (no member of F) never reads f1's write. Holds for every plain thing.

What building it needs:
- the writer remembers the derived epochs it wrote a thing under while it was plain to it (new local data per thing, cleared once a rotation of the thing lists them; notes/growth.md);
- on holding the thing's own epochs, such an epoch no current epoch's history carries counts as a current epoch of the thing (`Core::epochs` of a thing with secrets of its own today returns its own epochs only), so the ordinary merge rule fires with the writer as merger;
- the merge's history boxes carry that derived secret (osis-keys `rotation_into` takes it from the held epochs).
Only an epoch actually written under counts: counting every derived epoch of the base actor's later epochs would rotate the thing on every rotation of the base actor.
