//! Tags the persisted index (`engine::index`) with a hash of the sources its judgments may
//! follow from: every workspace crate's `src` (the node and all its path dependencies, so a
//! change anywhere that could change a judgment re-judges everything once at open).

use std::path::{Path, PathBuf};

fn files(p: &Path, out: &mut Vec<PathBuf>) {
    if p.is_dir() {
        let Ok(rd) = std::fs::read_dir(p) else {
            println!("cargo:warning=index tag: cannot read {}", p.display());
            return;
        };
        for e in rd.flatten() {
            files(&e.path(), out);
        }
    } else if p.extension().is_some_and(|x| x == "rs") {
        out.push(p.to_path_buf());
    }
}

fn main() {
    // Relative to the package (a build script's working dir): absolute paths in
    // rerun-if-changed would make every checkout's fingerprint differ (tools/seed-target.py).
    let crates = PathBuf::from("..");
    let mut roots: Vec<PathBuf> = match std::fs::read_dir(&crates) {
        Ok(rd) => rd.flatten().map(|e| e.path().join("src")).filter(|p| p.is_dir()).collect(),
        Err(_) => {
            println!("cargo:warning=index tag: cannot read {}", crates.display());
            vec![PathBuf::from("src")]
        }
    };
    roots.sort();
    let mut all = Vec::new();
    for r in &roots {
        println!("cargo:rerun-if-changed={}", r.display());
        files(r, &mut all);
    }
    all.sort();
    // FNV-1a, 64 bits: names relative to the crates directory, and contents
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for f in &all {
        let name = f.strip_prefix(&crates).unwrap_or(f).to_string_lossy().into_owned();
        let body = std::fs::read(f).unwrap_or_else(|_| {
            println!("cargo:warning=index tag: cannot read {}", f.display());
            Vec::new()
        });
        for b in name.bytes().chain([0]).chain(body).chain([0]) {
            h = (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3);
        }
    }
    println!("cargo:rustc-env=OSIS_INDEX_RULES={h:016x}");
}
