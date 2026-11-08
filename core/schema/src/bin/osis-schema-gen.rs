//! `osis-schema-gen <file.osis> [-o out.rs]`: parses and validates a schema and generates Rust
//! (stdout or `-o`).
#![forbid(unsafe_code)]

use osis_schema::{Error, generate_file};
use std::process::ExitCode;

fn run() -> Result<(), Error> {
    let mut args = std::env::args().skip(1);
    let (mut input, mut output) = (None, None);
    while let Some(a) = args.next() {
        match a.as_str() {
            "-o" => output = args.next(),
            _ if input.is_none() && !a.starts_with('-') => input = Some(a),
            _ => return Err(Error::Io(format!("unexpected argument {a}"))),
        }
    }
    let input = input.ok_or_else(|| Error::Io("usage: osis-schema-gen <file.osis> [-o out.rs]".into()))?;
    let g = generate_file(std::path::Path::new(&input))?;
    for w in &g.warnings {
        eprintln!("warning: {w}");
    }
    match output {
        Some(o) => std::fs::write(&o, &g.code).map_err(|e| Error::Io(format!("{o}: {e}")))?,
        None => print!("{}", g.code),
    }
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
