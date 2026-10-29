//! `osis-app DIR [--server ADDR]...`: opens the store in DIR (creating it, with its home group on
//! the servers, when DIR holds none) and shows the notes window.
#![forbid(unsafe_code)]

use osis_app::notes::{self, Notes};
use osis_app::ui::{Msg, Ui, tree};
use osis_kit::marshal::mailbox;
use osis_kit::theme::Theme;
use osis_kit::window::App;
use std::process::ExitCode;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("osis-app: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let mut dir = None;
    let mut servers = Vec::new();
    while let Some(a) = args.next() {
        match a.as_str() {
            "--server" => {
                let s = args.next().ok_or("--server needs an address")?;
                servers.push(s.parse().map_err(|e| format!("--server {s}: {e}"))?);
            }
            _ if dir.is_none() && !a.starts_with('-') => dir = Some(std::path::PathBuf::from(a)),
            _ => return Err(format!("usage: osis-app DIR [--server ADDR]... (unexpected {a})")),
        }
    }
    let dir = dir.ok_or("usage: osis-app DIR [--server ADDR]...")?;
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let db = notes::open(&dir, servers).map_err(|e| format!("{}: {e}", dir.display()))?;
    let notes = Notes::new(db);
    let app = App::new().map_err(|e| e.to_string())?;
    let (mb, inbox) = mailbox::<Msg>(app.waker());
    let theme = Theme::default();
    let (root, ids) = tree(&theme);
    // the first refresh: the home watch's initial call
    let ui = Ui::new(notes, app.window(), mb, inbox, theme.clone(), ids);
    app.run("osis notes", (900.0, 600.0), root, ui, &theme).map_err(|e| e.to_string())
}
