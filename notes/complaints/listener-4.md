# listener-4
> Summary: Footguns met building key types (listener-design step 4).

- `git checkout <file>` to undo a probe edit threw away the whole uncommitted change to that file; a scratch copy saved it. Wip-commit before any probe, as notes/coordination.md says, even a one-line sed.
- `compile_fail,E0599` doctests do not check the error code on stable rustdoc (a wrong code still passed), so each compile-fail test shares its setup with one passing doctest that takes every allowed call: that is what proves each fails on its one forbidden line.
- Tier 1 took 12 min at load 37 (2.5 min quiet).
- Review: `tools/gate.sh --all` took 645 s and 491 s at load ~50 (4 min quiet).
