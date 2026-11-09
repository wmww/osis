//! Search driver for the roles model: `[samples] [as|exempt|strat|stratw|frontier|edges|edges-prov|joint|disputes|disputes-random|digest|addenda|addenda-exh|addenda-covers|addenda-cost|epochs|epochs-exh]`.

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
        Some(m @ ("epochs" | "epochs-exh")) => {
            if roles_model::epochs::run(samples, m == "epochs-exh") > 0 {
                std::process::exit(1);
            }
        }
        Some("disputes") => roles_model::trust::run(samples, false),
        Some("disputes-random") => roles_model::trust::run(samples, true),
        Some("forget") => roles_model::forget::exhaustive(),
        Some("forget-min") => roles_model::forget::minimal(),
        Some("forget-prev") => roles_model::forget::prev_search(),
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
