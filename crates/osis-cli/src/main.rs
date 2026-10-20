//! The `osis` binary (notes/cli.md): `osis_cli::run` over the process's streams.
#![forbid(unsafe_code)]

use std::io::IsTerminal;

fn main() {
    let (stdin, stdout, stderr) = (std::io::stdin(), std::io::stdout(), std::io::stderr());
    let tty = stdin.is_terminal();
    // stdout and stderr unlocked: other threads (serve's log) print to stderr too.
    let io = osis_cli::Io { stdin: &mut stdin.lock(), stdout: &mut &stdout, stderr: &mut &stderr, tty };
    std::process::exit(osis_cli::run(std::env::args_os(), None, io));
}
