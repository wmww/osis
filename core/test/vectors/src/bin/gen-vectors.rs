//! gen-vectors: writes every provisional generated vector file from the implementation; never
//! touches frozen or pending ones. `gen-vectors freeze <path> <FC-n>` freezes a file at its
//! current bytes. `gen-vectors list` prints the manifest with case counts. `gen-vectors corpus`
//! writes the fuzz seed corpora (core/test/fuzz/README.md).
#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use osis_vectors::manifest::{self, Status};
use osis_vectors::{root, subjects};
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let r = match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        [] => generate(),
        ["freeze", path, change] => manifest::freeze(path, change),
        ["list"] => list(),
        ["corpus"] => osis_vectors::corpus::write().map(|n| println!("wrote {n} seeds")),
        _ => Err("usage: gen-vectors [list | corpus | freeze <path> <FC-n>]".into()),
    };
    match r {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("gen-vectors: {e}");
            ExitCode::FAILURE
        }
    }
}

fn generate() -> Result<(), String> {
    for e in manifest::load()? {
        let Some(generate) = subjects::get(&e.path).and_then(|s| s.generate) else { continue };
        if e.status != Status::Provisional {
            continue;
        }
        let path = root().join(&e.path);
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|err| err.to_string())?;
        }
        std::fs::write(&path, generate().render()).map_err(|err| format!("{}: {err}", e.path))?;
        println!("wrote {}", e.path);
    }
    Ok(())
}

fn list() -> Result<(), String> {
    for e in manifest::load()? {
        let state = match &e.status {
            Status::Pending(why) => format!("pending ({why})"),
            Status::Provisional => "provisional".into(),
            Status::Frozen { change, .. } => format!("frozen ({change})"),
        };
        let counts = match e.status {
            Status::Pending(_) => String::new(),
            _ => match subjects::run(&e.path) {
                Ok(r) => format!(": {} live, {} pending cases", r.live, r.pending),
                Err(err) => format!(": FAIL {err}"),
            },
        };
        println!("{} {state}{counts}", e.path);
    }
    Ok(())
}
