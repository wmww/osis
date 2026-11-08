//! Typed keys of schema/chat.osis, for src/lib.rs.
#![allow(clippy::panic)]

fn main() {
    let src = "../../schema/chat.osis";
    println!("cargo::rerun-if-changed={src}");
    let g = osis_schema::generate_file(std::path::Path::new(src)).unwrap_or_else(|e| panic!("{src}: {e}"));
    for w in &g.warnings {
        println!("cargo::warning={w}");
    }
    let out = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap_or_default()).join("chat.rs");
    std::fs::write(&out, g.code).unwrap_or_else(|e| panic!("{}: {e}", out.display()));
}
