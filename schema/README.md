# First-party schemas

The standard data shapes over the core (notes/std.md): one `.osis` file per schema (`contact.osis` contacts and profiles, `event.osis` calendar events). Notes and tags need only core aspects.

Apps take the schema files from here. Typed keys are generated with `osis_schema::generate_file(path)` (crate osis-schema), usually from a build script writing the returned `code` into `OUT_DIR` and `include!`-ing it in a module that has `use osis::schema as osis_schema;` (core/osis/build.rs does this for the scenario tests). `osis schema check FILE` parses a file and checks it against `FILE.lock`; the merge gate runs it on every file here.
