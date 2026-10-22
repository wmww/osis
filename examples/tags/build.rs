//! Generates the typed keys of tags.osis (osis-schema codegen).
#![allow(clippy::panic)]

fn main() {
    println!("cargo::rerun-if-changed=tags.osis");
    let g = osis_schema::generate_file(std::path::Path::new("tags.osis")).unwrap_or_else(|e| panic!("tags.osis: {e}"));
    for w in &g.warnings {
        println!("cargo::warning={w}");
    }
    let out = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap_or_default()).join("tags.rs");
    std::fs::write(&out, g.code).unwrap_or_else(|e| panic!("{}: {e}", out.display()));
}
