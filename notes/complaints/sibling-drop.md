# sibling-drop
> Summary: Mishaps met on the sibling-drop task.

- The issue and brief blamed the newly landed sibling rule (Open 23); the failing world's two removals were on different things and the cause was path-model-findings Open 6 (vouch counting without the resting condition). A failing world's trace (`tiny_trace`) prints edge writes without their thing; printing `w.commits` with `{:?}` showed it at once. Worth having the content property print the thing per part.
- `paths::dump::paths_dump_readings` is `#[ignore]` under `paths::`, so `--ignored paths::` (the brief's property command) always fails it without `OSIS_DUMP`.
