# notes-audit
- `tools/spec_map.py --uncited --gaps` exits with a usage error: it takes one flag per call; briefs name both together.
- Code comments cite note sections that no longer exist (`expiry-creation-design.md §6 step 6` in held-model `spec_fetch.rs`, "fast-design Scale" in osis `tracking.rs`, "Model results, committed" in roles-model `lib.rs`): nothing checks `notes/X.md (Heading)` citations.
