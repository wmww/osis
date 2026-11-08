//! `osis-app DIR [--peer ADDR]... [--demo] [--theme ID] [--auto|--light|--dark]`: opens the store
//! in DIR (creating it, with its home group syncing with those peers, when DIR holds none) and shows the app.
//! `--demo` adds demo data once; the look flags set the account's theme and mode (as the app's
//! own picker does).
#![forbid(unsafe_code)]

use osis_app::store as app_store;
use osis_kit::render::{Msg, Ui, tree};
use osis_kit::store as data;
use osis_kit::marshal::mailbox;
use osis_kit::schema::Mode;
use osis_kit::theme::Theme;
use osis_kit::window::App;
use std::process::ExitCode;

const USAGE: &str = "usage: osis-app DIR [--peer ADDR]... [--demo] [--theme ID] [--auto|--light|--dark]";

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
    let (mut dir, mut peers, mut demo, mut theme, mut mode) = (None, Vec::new(), false, None, None);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--peer" => {
                let s = args.next().ok_or("--peer needs an address")?;
                peers.push(s.parse().map_err(|e| format!("--peer {s}: {e}"))?);
            }
            "--demo" => demo = true,
            "--theme" => theme = Some(args.next().ok_or("--theme needs an id")?),
            "--auto" => mode = Some(Mode::Auto),
            "--light" => mode = Some(Mode::Light),
            "--dark" => mode = Some(Mode::Dark),
            _ if dir.is_none() && !a.starts_with('-') => dir = Some(std::path::PathBuf::from(a)),
            _ => return Err(format!("{USAGE} (unexpected {a})")),
        }
    }
    let dir = dir.ok_or(USAGE)?;
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let db = data::open(&dir, peers).map_err(|e| format!("{}: {e}", dir.display()))?;
    let data = app_store::data(db);
    data.main_group().map_err(|e| e.to_string())?;
    if let Some(t) = theme {
        if !Theme::defaults().iter().any(|x| x.id == t) {
            return Err(format!("no theme {t}: {}", Theme::defaults().iter().map(|x| x.id).collect::<Vec<_>>().join(", ")));
        }
        data.set_theme(&t).map_err(|e| e.to_string())?;
    }
    if let Some(m) = mode {
        data.set_mode(m).map_err(|e| e.to_string())?;
    }
    if demo {
        osis_app::demo::add(&data).map_err(|e| format!("demo data: {e}"))?;
    }
    let app = App::new().map_err(|e| e.to_string())?;
    let (mb, inbox) = mailbox::<Msg>(app.waker());
    let ui = Ui::new(data, app.window(), mb, inbox).map_err(|e| e.to_string())?;
    let look = ui.look();
    let root = tree(look.clone());
    app.run("osis", (1100.0, 720.0), root, ui, look.bg).map_err(|e| e.to_string())
}
