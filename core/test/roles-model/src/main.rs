//! Search driver for the roles model: `[samples] [edges|joint|disputes|disputes-random|digest|addenda|addenda-exh|addenda-covers|forget|epochs|epochs-no-cutoff|epochs-own-only|epochs-void-uncounted|epochs-no-own-cover|epochs-open-carried|epochs-no-reanswer|custody|custody-exh|custody-judged|custody-roster-bare|custody-merge-random|custody-stale-shut|custody-merge-carries|custody-readd-beside]`.

use roles_model::{edges, joint};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let samples = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(2_000_000);
    match args.get(2).map(String::as_str) {
        Some("digest") => {
            for (name, d) in roles_model::digest(samples, 0x5eed) {
                println!("{name} {d:016x}");
            }
        }
        Some(m) if m.starts_with("epochs") => {
            use roles_model::epochs::{run, Control};
            let control = match m {
                "epochs-no-cutoff" => Control::NoCutoff,
                "epochs-own-only" => Control::OwnOnly,
                "epochs-void-uncounted" => Control::VoidUncounted,
                "epochs-no-own-cover" => Control::NoOwnCover,
                "epochs-open-carried" => Control::OpenCarried,
                "epochs-no-reanswer" => Control::NoReanswer,
                _ => Control::None,
            };
            if run(samples, control) > 0 {
                std::process::exit(1);
            }
        }
        Some(m) if m.starts_with("custody") => {
            use roles_model::custody::{run, Control};
            let (mode, control) = match m {
                "custody-exh" => ("exh", Control::None),
                "custody-judged" => ("random", Control::CustodyJudged),
                "custody-roster-bare" => ("random", Control::RosterBare),
                "custody-merge-random" => ("random", Control::MergeRandom),
                "custody-stale-shut" => ("random", Control::StaleShut),
                "custody-merge-carries" => ("random", Control::MergeCarries),
                "custody-readd-beside" => ("random", Control::ReaddBeside),
                _ => ("random", Control::None),
            };
            if run(samples, mode, control) > 0 {
                std::process::exit(1);
            }
        }
        Some("disputes") => roles_model::trust::run(samples, false),
        Some("disputes-random") => roles_model::trust::run(samples, true),
        Some("forget") => {
            if roles_model::forget::search() > 0 {
                std::process::exit(1);
            }
        }
        Some("addenda") => roles_model::addenda::random(samples, 0x5eed).print(),
        Some("addenda-exh") => roles_model::addenda::exhaustive(false).print(),
        Some("addenda-covers") => roles_model::addenda::exhaustive(true).print(),
        Some("joint") => joint::random(samples, 0x5eed).print(),
        Some("edges") => edges::run(samples),
        m => {
            eprintln!("unknown mode {m:?}");
            std::process::exit(2);
        }
    }
}
