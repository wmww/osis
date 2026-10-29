//! `osis-app DIR [--server ADDR]... [--demo] [--theme ID] [--light|--dark]`: opens the store in
//! DIR (creating it, with its home group on the servers, when DIR holds none) and shows the app.
//! `--demo` adds demo data once.
#![forbid(unsafe_code)]

use osis_app::data::{self, Data};
use osis_app::ui::{Msg, Ui, tree};
use osis_kit::marshal::mailbox;
use osis_kit::theme::{Mode, Theme};
use osis_kit::window::App;
use std::process::ExitCode;

const USAGE: &str = "usage: osis-app DIR [--server ADDR]... [--demo] [--theme ID] [--light|--dark]";

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
    let (mut dir, mut servers, mut demo, mut theme, mut mode) = (None, Vec::new(), false, "frost".to_string(), Mode::Auto);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--server" => {
                let s = args.next().ok_or("--server needs an address")?;
                servers.push(s.parse().map_err(|e| format!("--server {s}: {e}"))?);
            }
            "--demo" => demo = true,
            "--theme" => theme = args.next().ok_or("--theme needs an id")?,
            "--light" => mode = Mode::Light,
            "--dark" => mode = Mode::Dark,
            _ if dir.is_none() && !a.starts_with('-') => dir = Some(std::path::PathBuf::from(a)),
            _ => return Err(format!("{USAGE} (unexpected {a})")),
        }
    }
    let dir = dir.ok_or(USAGE)?;
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let db = data::open(&dir, servers).map_err(|e| format!("{}: {e}", dir.display()))?;
    let data = Data::new(db);
    data.main_group().map_err(|e| e.to_string())?;
    if demo {
        osis_app::demo::add(&data).map_err(|e| format!("demo data: {e}"))?;
    }
    let app = App::new().map_err(|e| e.to_string())?;
    let (mb, inbox) = mailbox::<Msg>(app.waker());
    let ui = Ui::new(data, app.window(), mb, inbox, Theme::named(&theme), mode);
    let look = ui.look();
    let root = tree(look.clone());
    app.run("osis", (1100.0, 720.0), root, ui, look.bg).map_err(|e| e.to_string())
}
