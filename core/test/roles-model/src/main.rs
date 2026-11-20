<<<<<<< HEAD
//! Search driver for the roles model: `[samples] [edges|joint|disputes|disputes-random|digest|addenda|addenda-exh|addenda-covers|addenda-gaps|addenda-gaps-exh|addenda-gaps-no-admin|addenda-gaps-no-rewrite|forget|forget-entries|epochs|epochs-no-cutoff|epochs-own-only|epochs-void-uncounted|epochs-no-own-cover|epochs-open-carried|epochs-no-reanswer|custody|custody-exh|custody-judged|custody-roster-bare|custody-merge-random|custody-stale-shut|custody-merge-carries|custody-readd-beside|paths[-exh|-tiny[-invites][-honest]][-control] [--from K | --only K] (paths::mode_rules)|vouches|vouches-exh|vouches-off|vouches-no-rewrite|vouches-held|vouches-state|vouches-stands|vouches-state-stands|vouches-exh-off|vouches-exh-no-rewrite|vouches-exh-held|vouches-exh-state|vouches-exh-stands]`.
=======
//! Search driver for the roles model: `[samples] [edges|joint|disputes|disputes-random|digest|addenda|addenda-exh|addenda-covers|addenda-gaps|addenda-gaps-exh|addenda-gaps-no-admin|addenda-gaps-no-rewrite|forget|forget-entries|epochs|epochs-no-cutoff|epochs-own-only|epochs-void-uncounted|epochs-no-own-cover|epochs-open-carried|epochs-no-reanswer|custody|custody-exh|custody-judged|custody-roster-bare|custody-merge-random|custody-stale-shut|custody-merge-carries|custody-readd-beside|paths[-exh|-tiny[-invites][-honest]][-control|-remake] [--from K] (paths::mode_rules)|paths[-exh]-replay[-control|-remake] (world `samples` alone, traced)|paths-compare [--from K]|vouches|vouches-exh|vouches-off|vouches-no-rewrite|vouches-held|vouches-state|vouches-stands|vouches-state-stands|vouches-exh-off|vouches-exh-no-rewrite|vouches-exh-held|vouches-exh-state|vouches-exh-stands]`.
>>>>>>> f933a319a (roles-model paths: Rules::remake, the proposal for role writes a removed party made unreceived (no vouch; a witness holding the right makes the write again as its own), beside Rules::fixed. Rule set as definitions (README Paths, Making again; Sim::remake_at); generator moves 53-60 and Setup::n5 4 lowering witnesses (N5's key, X backdated, cancelling vouches, counter-making); -- I paths-replay, -- N paths-compare, failing world indices per check; honest re-grants written in tick order. Results at 400,000 + family sample under both: today's rule fails safety/removal/liveness wherever a key X lowered unreceived fights a witness or the remover; remake fails where witnesses race or only the victim saw a lowering. Hand worlds: the pair under both, the contested witness shown, finding 39 under remake, each loss users take, content addenda contested only through the witness's role, a removed key's backdated drop of a witness's write (issues/removed-key-backdated-drop.md). notes/role-remake-model.md, issues/role-vouch-contested.md, KNOWN entries for the four paths _large properties, complaints)

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
        Some(m) if m.starts_with("vouches") => {
            if roles_model::vouches::run(samples, m) > 0 {
                std::process::exit(1);
            }
        }
        Some(m) if m.starts_with("paths") => {
            // `-- N paths-exh`: every Nth family world (paths::run)
            if let Some(why) = m.starts_with("paths-exh").then(|| roles_model::stride_refusal(samples.max(1) as usize, roles_model::paths::FAMILY)).flatten() {
                eprintln!("{why}");
                std::process::exit(2);
            }
            let index = |flag: &str| args.iter().position(|a| a == flag).and_then(|k| args.get(k + 1)).map(|v| v.parse::<u64>().unwrap_or_else(|_| panic!("{flag} takes a world index")));
            // `--only K`: world K alone, printed whole with what each check found (`only`)
            if let Some(k) = index("--only") {
                std::process::exit(only(m, k));
            }
            // `--from K`: random or small worlds K.. (a large sample split across runs)
            let from = index("--from").unwrap_or(0);
            if roles_model::paths::run(samples, from, m) > 0 {
                std::process::exit(1);
            }
        }
        Some("disputes") => roles_model::trust::run(samples, false),
        Some("disputes-random") => roles_model::trust::run(samples, true),
        Some("forget-entries") => {
            if roles_model::forget::entries_search() > 0 {
                std::process::exit(1);
            }
        }
        Some("forget") => {
            if roles_model::forget::search() > 0 {
                std::process::exit(1);
            }
        }
        Some(m) if m.starts_with("addenda-gaps") => {
            if roles_model::addenda::run_gaps(samples, m) > 0 {
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

/// `-- 0 paths[-exh|-tiny...][-control] --only K`: world K of the mode's worlds (random world K,
/// family world K, or small world K), checked under the mode's rules: its trace, its commits in
/// full (vouches, content and covers included), the checks made and what failed. Exit 1 when a
/// check fails.
fn only(mode: &str, k: u64) -> i32 {
    use roles_model::paths::*;
    let Some(rules) = mode_rules(mode) else {
        eprintln!("unknown mode {mode}");
        return 2;
    };
    if mode.starts_with("paths-tiny") {
        let invites = mode.starts_with("paths-tiny-invites");
        let rest = mode.strip_prefix(if invites { "paths-tiny-invites" } else { "paths-tiny" }).unwrap_or("");
        let honest = if rest.starts_with("-honest-writers") { Honesty::Writers } else if rest.starts_with("-honest") { Honesty::Lists } else { Honesty::None };
        let t = tiny_world(k, TinyMode { invites, honest }, &rules);
        let mut st = TinyStats::default();
        tiny_check(k, &t, &rules, &mut st);
        println!("{mode} world {k}: trust {:?}, received {:?}\n{}commits:\n{}checks {:?}, noted {:?}, failing {:?}", t.v.trust, t.recv, tiny_trace(&t.w), whole(&t.w), st.checked, st.noted, st.fails);
        for (prop, (_, _, what)) in &st.first {
            println!("{prop}: {what}");
        }
        return i32::from(st.failures() > 0);
    }
    let family_world = mode.starts_with("paths-exh");
    if family_world && k as usize >= FAMILY {
        eprintln!("family worlds are 0..{FAMILY}");
        return 2;
    }
    let m = if family_world { family(k as usize, &rules) } else { random_world(k, &rules) };
    let mut st = Stats::default();
    check(&m, &rules, &mut st);
    println!("{mode} world {k}: {:?}\n{}commits:\n{}checks {:?}, noted {:?}, failing {:?}", m.spec, trace(&m), whole(&m.w), st.checked, st.noted, st.fails);
    for (prop, (what, _)) in &st.first {
        println!("{prop}: {what}");
    }
    i32::from(st.failures() > 0)
}

/// A world's commits whole, one a line (`tiny_trace` shows only edge writes).
fn whole(w: &roles_model::paths::World) -> String {
    w.commits.iter().enumerate().map(|(i, c)| format!("  {i}: {c:?}\n")).collect()
}
