//! Search driver for the roles model: `[samples] [proofs[-exh][-control] | leave[-exh][-control] | told[-exh][-control] | paths[-exh|-tiny[-flags|-detached][-honest[-writers]]][-control] [--from K | --only K] (paths::mode_rules)|paths-purge[-variant] (paths::purge_rules)]`.

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let samples = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(2_000_000);
    match args.get(2).map(String::as_str) {
        Some(m) if m.starts_with("leave") => {
            if roles_model::leave::leave_run(samples, m) > 0 {
                std::process::exit(1);
            }
        }
        Some(m) if m.starts_with("told") => {
            if roles_model::told::told_run(samples, m) > 0 {
                std::process::exit(1);
            }
        }
        Some(m) if m.starts_with("proofs") => {
            let from = args.iter().position(|a| a == "--from").and_then(|k| args.get(k + 1)).and_then(|v| v.parse().ok()).unwrap_or(0);
            if roles_model::paths::proofs::proofs_run(samples, from, m) > 0 {
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
        m => {
            eprintln!("unknown mode {m:?}");
            std::process::exit(2);
        }
    }
}

/// `-- 0 paths[-exh|-tiny...][-control] --only K`: world K of the mode's worlds (random world K,
/// family world K, or small world K), checked under the mode's rules: its trace, its commits in
/// full (content and covers included), the checks made and what failed. Exit 1 when a
/// check fails.
fn only(mode: &str, k: u64) -> i32 {
    use roles_model::paths::*;
    if let Some(rules) = purge_rules(mode) {
        let m = purge_world(k, &rules);
        let mut st = PStats::default();
        purge_check(&m, &rules, &mut st);
        println!("{mode} world {k}:\n{}", purge_trace(&m));
        st.print(mode);
        return i32::from(st.failures() > 0);
    }
    let Some(rules) = mode_rules(mode) else {
        eprintln!("unknown mode {mode}");
        return 2;
    };
    if mode.starts_with("paths-tiny") {
        let t = tiny_world(k, TinyMode::named(mode), &rules);
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
