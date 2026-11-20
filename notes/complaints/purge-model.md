# purge-model
> Summary: Workflow notes from the purge-model task (roles-model purge worlds).

- The story cannot carry new commit kinds: osis-perm's differential replays story and `tiny` worlds under `Rules::fixed`, and maps each kind to a walk input (`tests/it/paths/mod.rs`, `unreachable!` for the rest). New purge kinds went into a separate generator (`paths-purge`); any kind added to the story needs the walk first.
- roles-model is edition 2021: `if let ... &&` chains do not compile there though the rest of the tree uses them.
