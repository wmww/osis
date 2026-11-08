//! fuzz-seeds: writes the fuzz seed corpora to core/test/fuzz/corpus/ (core/test/fuzz/README.md).
#![forbid(unsafe_code)]

use std::process::ExitCode;

fn main() -> ExitCode {
    match osis_vectors::corpus::write() {
        Ok(n) => {
            println!("wrote {n} seeds");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("fuzz-seeds: {e}");
            ExitCode::FAILURE
        }
    }
}
