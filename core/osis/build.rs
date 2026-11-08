//! Generates the typed keys of every schema in schema/ and of osis-schema's test fixture
//! (core/schema/tests/example.osis) with osis-schema codegen, for the integration tests
//! (tests/it/main.rs `schemas`). Compiling them is the check that codegen output builds.
#![allow(clippy::panic)]

fn main() {
    let out = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap_or_default());
    for (name, src) in [
        ("contact", "../../schema/contact.osis"),
        ("event", "../../schema/event.osis"),
        ("core", "../../schema/core.osis"),
        ("meta", "../../schema/meta.osis"),
        ("example", "../schema/tests/example.osis"),
    ] {
        println!("cargo::rerun-if-changed={src}");
        let g = osis_schema::generate_file(std::path::Path::new(src)).unwrap_or_else(|e| panic!("{src}: {e}"));
        // the fixture's one warning is osis-schema's own test (codegen.rs `list_struct_warning`)
        if name != "example" {
            for w in &g.warnings {
                println!("cargo::warning={w}");
            }
        }
        let dst = out.join(format!("{name}.rs"));
        std::fs::write(&dst, g.code).unwrap_or_else(|e| panic!("{}: {e}", dst.display()));
    }
}
