# Complaints: wait-order
> Summary: footguns met bringing the stated-path wait to the ordered rule: role commits refuse act_as and a purge index other than 0, and a cargo filter can't AND module and size word.

- A role commit can't `act_as` (`Misuse`) and `Path::through` sets purge index 1, which a role commit refuses at build: forging a role commit along a path takes `forge_by` with a `Path { purge: 0, .. }` built by hand.
- `cargo test -- --ignored paths::` runs every ignored test in the module, `_large` included; filters OR, so a module's `_plain` properties need each name spelled out.
