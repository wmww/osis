# An outsider follows another honest merge than the custody model
> Summary: The custody differential (`rotation::tests_custody`, large) fails seed 570 (`OSIS_CUSTODY_START=570 OSIS_CUSTODY_SEEDS=1 cargo test -p osis-engine --lib -- --ignored --exact rotation::tests_custody::engine_agrees_with_custody_model_large_spec_permissions_5_4`): with no move by X, reader R2 holding several of P's rotations and certificates in one millisecond counts A and C's merge line ({1,4}, {1,4,8}) where the model counts B's ({1,8}, {1,8,21}). Honest lines only: no thief reads or writes anything.
> Priority: normal
> Tags: engine, tests

- Shape: A removes X (#4 at {1}); C, unaware, removes T (#8 at the first epoch); B certifies the merge {1}+{8} (#18) and rotates on it (#21); C and A certify {1,4}+{8} (#23, #27). R2 holds #8 first, then #1, #4, #18, #21 and #23 in one millisecond, so the placement ties (depth, then ID; a merge by its merge ID, `merge_tie` in the mirror) decide which line it follows. Find where the engine's placement (`AccountView::received`, `osis_perm::Chain`) and the model's (`custody::judge`, outside) order these, and build the hand test from it.
- None of the world's commits is a re-seal; the world depends on the engine's RNG draws, so a change in how many seed boxes a node seals moves which seeds reach it.
