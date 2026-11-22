# A peer with no role on an actor opens an epoch a writer encrypts under
> Summary: `rotation_holds_large_spec_crypto_4` seed 214919900839 fails on main: peer 1, holding no role on actor 0 any more, can open a Read epoch of it that peer 4 (Write) encrypts under (spec/crypto.md §4).
> Priority: normal
> Tags: security, engine, tests

Replay: `OSIS_ROTATION_START=214919900839 OSIS_ROTATION_SEEDS=1 cargo test -p osis-engine --lib -- --ignored --exact rotation::tests_property::rotation_holds_large_spec_crypto_4` (fails alike on main at 800ca0810 and on the refused-deposit branch). The history forges a Mark at peer 0, withholds 18 commits at peer 0, then peer 0 makes new Sync/Read/Admin epochs of actors 0 and 1; the assertion is the removed-member check in `rotation/tests_property.rs` (`opens` against each direct holder's newest held epoch). Not yet minimized or studied: the property is a security one (a departed member reads content written after), so the first step is a hand-built reproducer.
