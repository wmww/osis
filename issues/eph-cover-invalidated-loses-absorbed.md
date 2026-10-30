# A cover turning invalid loses the commits it dropped, at some holders only
> Summary: validity is judged at the commit's stamp, so a writer revoked at T between an own commit X (valid) and its later cover C (invalid once T is known) splits holders: one holding C before learning of T dropped X (`drop_absorbed`, or `eph_containers` on a later arrival) and reads without it once C turns invalid; one that learned T first keeps X. Pre-existing for listed commits; `eph_containers` extends it to older unlisted commits C contains.
> Tags: engine, ephemeral, security

Order A: X, C (valid), revocation -> X dropped, C invalid: X's writes gone. Order B: revocation, X, C (invalid) -> C absorbs nothing, X held. Reads differ until restart. Also the writer's own deletes under C remove X from servers, so X cannot come back by reconcile.

Fix direction (owner-call family of issues/cover-deleted-part-pends.md): a dropped commit's writes stay through the cover only while the cover is valid, so either keep a dropped commit's parts (memory) until the cover's author can no longer be revoked before it (never ends), or count a part of an invalid cover that a valid earlier commit of its author would have carried (judge the cover's writes per original commit stamp, the `Authors` session stamps already in `HeldPart::authors`).
