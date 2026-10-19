//! Generates the typed keys of notes.osis (osis-schema codegen).
#![allow(clippy::panic)]

fn main() {
    println!("cargo::rerun-if-changed=notes.osis");
    let g = osis_schema::generate_file(std::path::Path::new("notes.osis")).unwrap_or_else(|e| panic!("notes.osis: {e}"));
    for w in &g.warnings {
        println!("cargo::warning={w}");
    }
    let out = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap_or_default()).join("notes.rs");
    std::fs::write(&out, g.code).unwrap_or_else(|e| panic!("{}: {e}", out.display()));
}
