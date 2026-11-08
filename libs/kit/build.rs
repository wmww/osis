//! Typed keys of schema/ui.osis, for src/lib.rs.
#![allow(clippy::panic)]

fn main() {
    let out = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap_or_default());
    let src = "../../schema/ui.osis";
    println!("cargo::rerun-if-changed={src}");
    let g = osis_schema::generate_file(std::path::Path::new(src)).unwrap_or_else(|e| panic!("{src}: {e}"));
    for w in &g.warnings {
        println!("cargo::warning={w}");
    }
    let path = out.join("ui.rs");
    std::fs::write(&path, g.code).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
}
