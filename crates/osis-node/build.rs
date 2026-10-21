//! Tags the persisted index (`engine::index`) with a hash of the sources its judgments follow
//! from: perm, the node's apply rules and the index itself. A build with other rules re-judges
//! everything once at open.

use std::path::{Path, PathBuf};

fn files(p: &Path, out: &mut Vec<PathBuf>) {
    if p.is_dir() {
        let Ok(rd) = std::fs::read_dir(p) else { return };
        for e in rd.flatten() {
            files(&e.path(), out);
        }
    } else if p.extension().is_some_and(|x| x == "rs") {
        out.push(p.to_path_buf());
    }
}

fn main() {
    let dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default());
    let roots = [dir.join("../osis-perm/src"), dir.join("src/apply"), dir.join("src/engine/index.rs")];
    let mut all = Vec::new();
    for r in &roots {
        println!("cargo:rerun-if-changed={}", r.display());
        files(r, &mut all);
    }
    all.sort();
    // FNV-1a, 64 bits: names and contents
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for f in &all {
        let name = f.strip_prefix(&dir).unwrap_or(f).to_string_lossy().into_owned();
        for b in name.bytes().chain([0]).chain(std::fs::read(f).unwrap_or_default()).chain([0]) {
            h = (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3);
        }
    }
    println!("cargo:rustc-env=OSIS_INDEX_RULES={h:016x}");
}
