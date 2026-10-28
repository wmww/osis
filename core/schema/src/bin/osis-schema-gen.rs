//! `osis-schema-gen <file.osis> [-o out.rs] [--publish] [--allow <at>]...`: checks a schema
//! against `<file.osis>.lock` (spec/versioning.md §4), generates Rust (stdout or `-o`), and with
//! `--publish` rewrites the lock. `--allow` marks an intended `DefaultAdded` location.
#![forbid(unsafe_code)]

use osis_schema::{Error, Lock, LockStatus, check_lock, generate, parse};
use std::process::ExitCode;

fn run() -> Result<(), Error> {
    let mut args = std::env::args().skip(1);
    let (mut input, mut output, mut publish, mut allow) = (None, None, false, Vec::new());
    while let Some(a) = args.next() {
        match a.as_str() {
            "-o" => output = args.next(),
            "--publish" => publish = true,
            "--allow" => allow.extend(args.next()),
            _ if input.is_none() && !a.starts_with('-') => input = Some(a),
            _ => return Err(Error::Io(format!("unexpected argument {a}"))),
        }
    }
    let input = input.ok_or_else(|| Error::Io("usage: osis-schema-gen <file.osis> [-o out.rs] [--publish] [--allow <at>]...".into()))?;
    let path = std::path::Path::new(&input);
    let src = std::fs::read_to_string(path).map_err(|e| Error::Io(format!("{input}: {e}")))?;
    let file = path.file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or_default();
    let schema = parse(&file, &src)?;
    let lock_path = path.with_file_name(format!("{file}.lock"));
    let allow: Vec<&str> = allow.iter().map(String::as_str).collect();
    let status = match std::fs::read_to_string(&lock_path) {
        Ok(text) => Some(check_lock(&schema, &Lock::parse(&text)?, &allow)?),
        Err(_) => None,
    };
    if publish && status != Some(LockStatus::Published) {
        std::fs::write(&lock_path, Lock::of(&schema).to_text()).map_err(|e| Error::Io(format!("{}: {e}", lock_path.display())))?;
        eprintln!("published revision {} to {}", schema.revision, lock_path.display());
    } else if status == Some(LockStatus::Unpublished) {
        eprintln!("note: {file} differs from its lock (unpublished revision {})", schema.revision);
    }
    let g = generate(&schema, &file, &src)?;
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
