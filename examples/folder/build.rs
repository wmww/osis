//! Generates the typed keys of folder.osis (osis-schema codegen).
#![allow(clippy::panic)]

fn main() {
    println!("cargo::rerun-if-changed=folder.osis");
    let g = osis_schema::generate_file(std::path::Path::new("folder.osis")).unwrap_or_else(|e| panic!("folder.osis: {e}"));
    for w in &g.warnings {
        println!("cargo::warning={w}");
    }
    let out = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap_or_default()).join("folder.rs");
    std::fs::write(&out, g.code).unwrap_or_else(|e| panic!("{}: {e}", out.display()));
}
