//! `osis-server <config file>`: a blind node (spec/sync.md §4-§9) on the redb file backend.
//! Serves QUIC (`listen = quic://host:port`). Config format: `osis_server::config`. Logs to
//! stderr, starting with `address <url>#<key>` (the static key, base64url); Ctrl-C (SIGINT) shuts
//! down gracefully. Body: `osis_server::serve`.
#![forbid(unsafe_code)]

use osis_server::{Log, config, serve};
use std::process::ExitCode;
use std::sync::Arc;

fn log(msg: &str) {
    eprintln!("osis-server: {msg}");
}

fn start() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let (Some(path), None) = (args.next(), args.next()) else { return Err("usage: osis-server <config file>".into()) };
    let text = std::fs::read_to_string(&path).map_err(|e| format!("{path}: {e}"))?;
    let cfg = config::parse(&text).map_err(|e| format!("{path}: {e}"))?;
    let l: Log = Arc::new(log);
    serve::run(cfg, l, |a| log(&format!("address {a}")))
}

fn main() -> ExitCode {
    match start() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            log(&e);
            ExitCode::FAILURE
        }
    }
}
