//! Search driver for the roles model: `[samples] [forks|forks-stand|forks-blind|forks-anyone|forks-first-grants|forks-no-takes|forks-every-answer|as|exempt|strat|stratw|frontier|edges|edges-prov|joint|disputes|disputes-random|digest|addenda|addenda-exh|addenda-covers|addenda-cost|epochs|epochs-exh|epochs-exh-c|custody|custody-exh|custody-judged|custody-roster-bare|custody-merge-random|custody-stale-shut|custody-merge-carries]`.

use roles_model::{edges, joint, single};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let samples = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(2_000_000);
    match args.get(2).map(String::as_str) {
        Some("digest") => {
            for (name, d) in roles_model::digest(samples, 0x5eed) {
                println!("{name} {d:016x}");
            }
        }
        Some(m @ ("epochs" | "epochs-exh" | "epochs-exh-c")) => {
            if roles_model::epochs::run(samples, m) > 0 {
                std::process::exit(1);
            }
        }
        Some(m @ ("forks" | "forks-stand" | "forks-blind" | "forks-anyone" | "forks-first-grants" | "forks-no-takes" | "forks-every-answer")) => {
            let c = match m { "forks-stand" => 1, "forks-blind" => 2, "forks-anyone" => 3, "forks-first-grants" => 4, "forks-no-takes" => 5, "forks-every-answer" => 6, _ => 0 };
            roles_model::forks::CONTROL.store(c, std::sync::atomic::Ordering::Relaxed);
            if roles_model::forks::run(samples) > 0 {
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
                _ => ("random", Control::None),
            };
            if run(samples, mode, control) > 0 {
                std::process::exit(1);
            }
        }
        Some("disputes") => roles_model::trust::run(samples, false),
        Some("disputes-random") => roles_model::trust::run(samples, true),
        Some("forget") => roles_model::forget::exhaustive(),
        Some("forget-min") => roles_model::forget::minimal(),
        Some("forget-prev") => roles_model::forget::prev_search(),
        Some("forget-any") => roles_model::forget::any_search(),
        Some("forget-costs") => roles_model::forget::costs(),
        Some("forget-account") => roles_model::forget_account::exhaustive(),
        Some("addenda") => roles_model::addenda::random(samples, 0x5eed).print(),
        Some("addenda-cost") => roles_model::addenda::cost_sweep(samples),
        Some("addenda-exh") => roles_model::addenda::exhaustive(false).print(),
        Some("addenda-covers") => roles_model::addenda::exhaustive(true).print(),
        Some("joint") => joint::random(samples, 0x5eed).print(),
        Some("edges") => edges::run(samples, edges::Drops::Sticky),
        Some("edges-prov") => edges::run(samples, edges::Drops::Provenance),
        rule => single::run(samples, rule),
    }
}
