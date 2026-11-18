# rotation_holds: a sync holder opens an epoch an admin encrypts under
> Summary: osis-engine `rotation::tests_property::rotation_holds_large_spec_crypto_4` fails on main: a peer now holding sync opens the read epoch an admin encrypts under.
> Priority: normal
> Tags: tests, engine, security

Fails on main at 26f8e7280 with `OSIS_ROTATION_START=874943289279 OSIS_ROTATION_SEEDS=1` (`cargo test -p osis-engine --lib -- --ignored --exact rotation::tests_property::rotation_holds_large_spec_crypto_4`): `peer 1 (now Some(Sync)) opens Tid(..) Read epoch Epoch { n: 1, .. } peer 0 (Admin) encrypts under` (core/engine/src/rotation/tests_property.rs:758). A holder lowered to sync can read what is written after: either the rotation that should shut it out is missing, or the property's reading of "opens" is wrong for this history. Found by the gate of gimbal-terms-code (a pure rename), then replayed on main's own binary.
