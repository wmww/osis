# An ignored box to the public blocks its re-seal
> Summary: A box to the public of another form than open, or an open box whose secret does not name its key's epoch, is ignored (spec/crypto.md §4 Boxes), but the re-seal trigger counts it present, so a writer's junk box keeps every public-only reader off that epoch until an unrelated rotation; the public has no Stranded report to ask for one.
> Priority: low
> Tags: security, keys, engine

**Property** (spec/permissions.md §3 Re-seal; crypto §4 Boxes): a re-sealer re-seals a current holder without a box at a current epoch; an ignored box is no box.

**Code**: `osis_keys::covers::reseal_missing` and `produce::reseal_holder` test `boxes.contains_key` only; `rotation::reseal_scan`/`reseal_one_into` read them.

**World**: A grants the public read on X. Writer W writes, beside any write, a sealed-form box (or an open box with garbage) keyed (public, read, e) at X's current read epoch. No node re-seals the public at e; readers through the public alone read nothing under e until X's read rotates (removing W does it).

**Why low**: a hostile writer can lock out any holder (notes/keys.md Lockouts) and removing it heals; for a node holder a Stranded report heals it sooner. The public's box is checkable by anyone, so the trigger can read an ignored box as missing (and the re-seal write over it): small change in the two functions. Test in `rotation::tests_public`.
