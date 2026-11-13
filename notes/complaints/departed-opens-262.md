# departed-opens-262
- The rotation checker notes states between engine calls: a call that writes two rotations of one role hides the first's boxes. A removal's cascade did that (boxing the removed party, then dropping the box); the engine now rotates none of the removal's roles in the cascade. A new multi-rotation call path would reopen the blind spot.
- `Engine::get_typed` takes `&mut self`, so a dump helper reading state cannot take `&Run` while the check holds borrows of `run.made`: collect, then dump after the loop.
- Reproducing the shape by hand: G seals a holder actor at its *newest* keyset, so a fork of M picks a branch by nonce; rotate the ignorant side twice to make it the one sealed.
- Review 2: tools/gate_select_test.sh failed the gate's instant stage on this box (git 2.43, no init.defaultBranch): its bare origin's HEAD was `master`, so the clone had no `main` to push. Fixed with `git init --bare -b main`.
- Review 3: the rebase onto no-merger conflicted in four commits, two of them designs the third rewrote; squashed the branch onto main instead of replaying intermediate states.
