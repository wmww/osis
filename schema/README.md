# Schemas

Every production schema, one `.osis` file each: `core.osis` (the core aspects every node knows), `meta.osis` (the schema of schemas), `contact.osis`, `event.osis`, `chat.osis`, and `app.osis` (the first-party app's own data). Notes and tags use only core aspects. Test-only schemas live with their tests.

Apps take the schema files from here. Typed keys are generated with `osis_schema::generate_file(path)` (crate osis-schema), usually from a build script writing the returned `code` into `OUT_DIR` and `include!`-ing it in a module that has `use osis::schema as osis_schema;` (core/osis/build.rs does this for the scenario tests). `osis schema check FILE` parses a file and checks it against `FILE.lock`; the merge gate runs it on every file here.

Style: every struct and enum one field or case per line, a blank line between top-level items, and in a long file `// ---- Section ----` headers saying what each group of items is for. Docs (`///`, `//!`) should make sense to someone who doesn't know how osis works inside.
