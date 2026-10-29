//! Typed keys of the app's schema (schema/osis-app.osis), for src/lib.rs `schema`.
#![allow(clippy::panic)]

fn main() {
    let src = "schema/osis-app.osis";
    println!("cargo::rerun-if-changed={src}");
    let g = osis_schema::generate_file(std::path::Path::new(src)).unwrap_or_else(|e| panic!("{src}: {e}"));
    for w in &g.warnings {
        println!("cargo::warning={w}");
    }
    let out = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap_or_default()).join("osis_app.rs");
    std::fs::write(&out, g.code).unwrap_or_else(|e| panic!("{}: {e}", out.display()));
}
