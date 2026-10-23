//! Search driver for the membership model: `[samples] [as|exempt|strat|stratw|frontier|snapshot|edges|edges-prov|joint|digest]`.

use membership_model::{edges, joint, single, snapshot};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let samples = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(2_000_000);
    match args.get(2).map(String::as_str) {
        Some("digest") => {
            for (name, d) in membership_model::digest(samples, 0x5eed) {
                println!("{name} {d:016x}");
            }
        }
        Some("joint") => joint::random(samples, 0x5eed).print(),
        Some("snapshot") => snapshot::random(samples, 0x5eed).print(),
        Some("edges") => edges::run(samples, edges::Drops::Sticky),
        Some("edges-prov") => edges::run(samples, edges::Drops::Provenance),
        rule => single::run(samples, rule),
    }
}
