# engine-it-tests
> Summary: footguns met consolidating the engine's largest integration test files.

- A module's instruction count moved after `git rebase origin/main` with no test change of mine (main's engine and schema edits: shred's `past_expiry_and_purge_alike` +0.4 G). Compare against a binary built from the rebased main's test files (`git checkout origin/main -- core/engine/tests/it`, build, copy the binary aside, `git checkout HEAD -- core/engine/tests/it`), never against the pre-rebase baseline.
- `lp.hold_at(i, d)` right after pushing `lp.fresh_reader(0, d, ..)` is a no-op (the reader already holds `d`); validity.rs did both at a dozen sites.
- A scripted rewrite to a helper taking `&mut LocalPeer` writes `&mut lp` everywhere; inside a helper whose `lp` is already `&mut LocalPeer` that fails to build (E0596). Looping the build and rewriting each reported line to `lp` fixed them all in a few rounds.
- `tools/mutate.py` needs OLD unique in the file; a short expression (`m.valid_at(ai)`) is not, so widen it to the whole line.
