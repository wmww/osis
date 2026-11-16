# keel-roles-model-trim
> Summary: Mishaps while slimming roles-model.

- The digest (`roles-model -- N digest`) hashes `{:?}` of the walk outputs, so removing a field that is always constant (edges `cycled`) changes it although no verdict does. Comparing needed a one-off patch stripping the field from the old side. A digest over named verdict fields would survive such refactors.
- `tools/bin-at` builds test binaries only; comparing search output of the `roles-model` bin before and after needed a wip commit, `git checkout HEAD~1 -- core/test/roles-model`, a build and a copy by hand.
- `tools/deprecated_probe.py roles-model` is little use on a model crate: modules use each other through `pub` items and the name matching ties `World`, `Kind`, `Item` of different modules together (custody's `World` "used" by osis-perm's epochs differential).
- The custody differential (`cargo test -p osis-engine --lib rotation::`) panics on the reference-graph `todo!()`s on main, so the one engine consumer of the model could not be checked before or after; custody.rs was not changed beyond its search runner.
