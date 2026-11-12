# rotation-storm
- `git rebase main` refused with uncommitted notes edits while a build ran in the same command: the test binary built was the old base; measure only after checking the rebase line.
- TLA `run.sh` takes the module name (`cover`), not the directory and module (`rotation Cover`); the wrong form queued for the heavy lock before failing.
- The heavy lock queue (another gate, then two by-hand runs) cost more wall time than the model runs themselves.
- Cover.tla's `Rotate` let a node rotate after its own removal; a Dup shape with the audit drop "leaked" through that until rotators had to hold admin in their own view.
- Review: the Cover.tla model has no raising write after a removal, so a rule whose safety rests on "nothing raises the holder after its lowering" passes it vacuously; the hole showed only in a hand-built Rust shape.
