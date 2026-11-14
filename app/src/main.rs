//! `osis-app DIR [--dial ADDR]... [--demo] [--theme ID] [--auto|--light|--dark]`: opens the store
//! in DIR (creating it when DIR holds none), dialing those nodes, and shows the app;
//! a store that cannot open shows why, in the window and on stderr.
//! `--demo` adds demo data once; the look flags set the account's theme and mode (as the app's
//! own picker does).
#![forbid(unsafe_code)]

use osis_app::store as app_store;
use osis_kit::render::{Start, tree};
use osis_kit::schema::Mode;
use osis_kit::theme::Theme;
use osis_kit::window::App;
use std::process::ExitCode;

const USAGE: &str = "usage: osis-app DIR [--dial ADDR]... [--demo] [--theme ID] [--auto|--light|--dark]";

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
    let (mut dir, mut dial, mut demo, mut theme, mut mode) = (None, Vec::new(), false, None, None);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--dial" => {
                let s = args.next().ok_or("--dial needs an address")?;
                dial.push(s.parse().map_err(|e| format!("--dial {s}: {e}"))?);
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
    if let Some(t) = &theme
        && !Theme::defaults().iter().any(|x| x.id == t)
    {
        return Err(format!("no theme {t}: {}", Theme::defaults().iter().map(|x| x.id).collect::<Vec<_>>().join(", ")));
    }
    let app = App::new().map_err(|e| e.to_string())?;
    // the look flags and demo data go into whichever store opens: this one, or a fresh one
    let data = move |db| {
        let data = app_store::data(db);
        if let Some(t) = &theme {
            data.set_theme(t).map_err(|e| e.to_string())?;
        }
        if let Some(m) = &mode {
            data.set_mode(m.clone()).map_err(|e| e.to_string())?;
        }
        if demo {
            osis_app::demo::add(&data).map_err(|e| format!("demo data: {e}"))?;
        }
        Ok(data)
    };
    let ui = Start { dir, dial, waker: app.waker(), data: Box::new(data) }.open();
    // from a terminal the error shows there too; the window offers to start fresh
    if let Some(e) = ui.error() {
        eprintln!("osis-app: {e}");
    }
    let root = tree(ui.look());
    app.run("osis", (1100.0, 720.0), root, ui).map_err(|e| e.to_string())
}
