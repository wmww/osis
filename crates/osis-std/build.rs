//! Generates the typed keys of every schema in schemas/ (osis-schema codegen).
#![allow(clippy::panic)]

fn main() {
    let out = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap_or_default());
    for name in ["contact", "event"] {
        let src = format!("schemas/{name}.osis");
        println!("cargo::rerun-if-changed={src}");
        let g = osis_schema::generate_file(std::path::Path::new(&src)).unwrap_or_else(|e| panic!("{src}: {e}"));
        for w in &g.warnings {
            println!("cargo::warning={w}");
        }
        let dst = out.join(format!("{name}.rs"));
        std::fs::write(&dst, g.code).unwrap_or_else(|e| panic!("{}: {e}", dst.display()));
    }
}
