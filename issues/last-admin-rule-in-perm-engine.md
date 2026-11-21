# The every-node last-admin rule is still in osis-perm, the engine and the wire
> Summary: The models have no last-admin rule every node judges (notes/write-path-design.md §5 A2; notes/path-model-findings.md 46); osis-perm's walk, the engine's evidence and writing, and the header still carry it, and two test sites switch it off against the models meanwhile.
> Priority: normal
> Tags: perm, engine, tests

Still carrying the rule: osis-perm `paths` walk (`Walk::remains`, `Accept::Standing`, `EdgeWrite::remains` and `adminless`), engine `evidence` (`Write::relies`) and `write::remains_of`, the header's `remains` (spec/wire.md §4 field 17).

Interim sites (each marked `// Interim (issues/last-admin-rule-in-perm-engine.md)`):
- `core/perm/tests/it/paths/mod.rs` `input`: every model write marked adminless, `remains: None`, so the walk's rule is off in its differentials against roles-model `paths`. The mark reaches only `Walk::remains` (with the mark off, `paths_tiny_agree_plain` and `paths_story_agree_plain` fail).
- `core/engine/tests/it/evidence/mod.rs` `part`: `relies: None`, so the engine's remaining-admin evidence edge goes untested.

Replaced by: the walk's rebuild (notes/redesign-plan.md, osis-perm `paths`: rebuild the walk) with no `remains` or mark read, and the engine's evidence and writing cut to match; then both sites pass the model's write as it is and lose the fields.
