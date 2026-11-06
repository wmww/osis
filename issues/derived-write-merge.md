# A derived write after the own-secrets switch is never merged
> Summary: spec/crypto.md §4 Current says a derived epoch some held commit encrypts under counts as current until a rotation lists it, so its writer merges the thing; the engine does not do this: holders that hold no secret of the base actor never read such a write.
> Tags: keys, engine, security

Model: core/test/tla/rotation `D0_fa_derive` (fails `ReadsAll` without the rule), `D0_fa_dmerge` (passes with it), `D0_fa_dmerge_rm` (the stated limit).

Case: T plain, deriving from F. t1 gives T secrets of its own (its first grant). f1, a writer of T through F that has not received that rotation, rotates F and writes T under the derived secret of F's new epoch. The switch rotation's history carries only the derived epochs t1 held, so t1 (no member of F) never reads f1's write. Holds for owned and ownerless plain things alike.

What building it needs:
- the writer remembers the derived epochs it wrote a thing under while it was plain to it (new local data per thing, cleared once a rotation of the thing lists them; notes/growth.md);
- on holding the thing's own epochs, such an epoch no current epoch's history carries counts as a current epoch of the thing (`Core::epochs` of a thing with secrets of its own today returns its own epochs only), so the ordinary merge rule fires with the writer as merger;
- the merge's history boxes carry that derived secret (osis-keys `rotation_into` takes it from the held epochs).
Only an epoch actually written under counts: counting every derived epoch of the base actor's later epochs would rotate the thing on every rotation of the base actor.
