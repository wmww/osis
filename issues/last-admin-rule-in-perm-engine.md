# The every-node last-admin rule is still in the engine and the wire
> Summary: The models and osis-perm's `paths` walk have no last-admin rule every node judges (notes/write-path-design.md §5 A2; notes/path-model-findings.md 46); the engine's evidence and writing and the header still carry it, and one test site switches it off against the model meanwhile.
> Priority: normal
> Tags: engine, tests

Still carrying the rule: engine `evidence` (`Write::relies`) and `write::remains_of`, the header's `remains` (spec/wire.md §4 field 17).

Interim site (marked `// Interim (issues/last-admin-rule-in-perm-engine.md)`): `core/engine/tests/it/evidence/mod.rs` `part`: `relies: None`, so the engine's remaining-admin evidence edge goes untested.

Replaced by: the engine's evidence and writing cut to match the walk, which reads no remaining admin and no mark; the site then passes the model's write as it is and loses the field.
