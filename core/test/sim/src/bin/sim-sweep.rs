//! `sim-sweep`: runs many seeds of every simulator scenario (notes/testing.md, Simulator), in
//! parallel, within a time budget; prints each failing seed with its replay call and exits 1 if
//! any failed. Blocked scenarios (`osis_sim::BLOCKED`, a known engine bug each) are skipped
//! unless `--blocked`.
//!
//! sim-sweep [--seeds N] [--from S] [--only a,b] [--blocked] [--budget-secs T] [--jobs J]
//!           [--out DIR] [--list]
#![forbid(unsafe_code)]

use osis_sim::{SCENARIOS, blocked, run};
use std::collections::{BTreeMap, VecDeque};
use std::io::Write;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

struct Args {
    seeds: u64,
    from: u64,
    only: Option<Vec<String>>,
    blocked: bool,
    budget: Option<Duration>,
    jobs: usize,
    out: Option<String>,
    list: bool,
}

const USAGE: &str = "usage: sim-sweep [--seeds N] [--from S] [--only a,b] [--blocked] [--budget-secs T] [--jobs J] [--out DIR] [--list]
  --seeds N        seeds per scenario (default 100)
  --from S         first seed (default 0)
  --only a,b       only these scenarios (default: all but blocked ones)
  --blocked        include blocked scenarios (a known engine bug each)
  --budget-secs T  stop starting seeds after T s (seed-major, so scenarios get about as many each)
  --jobs J         parallel jobs (default: a thread per core)
  --out DIR        write DIR/failing-seeds.txt when any fail
  --list           print every scenario (blocked ones marked) and exit
Exits 1 if any seed failed, 2 on bad arguments. Replay a failure: osis_sim::replay(name, seed);
OSIS_SIM_TRACE=1 traces it.";

/// `Ok(None)`: `--help` asked.
fn parse() -> Result<Option<Args>, String> {
    let mut a = Args { seeds: 100, from: 0, only: None, blocked: false, budget: None, jobs: std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1), out: None, list: false };
    let mut it = std::env::args().skip(1);
    while let Some(k) = it.next() {
        let mut val = || it.next().ok_or(format!("{k} needs a value"));
        let num = |v: String| v.parse::<u64>().map_err(|_| format!("bad number {v}"));
        match k.as_str() {
            "--seeds" => a.seeds = num(val()?)?,
            "--from" => a.from = num(val()?)?,
            "--only" => a.only = Some(val()?.split(',').map(str::to_string).collect()),
            "--blocked" => a.blocked = true,
            "--budget-secs" => a.budget = Some(Duration::from_secs(num(val()?)?)),
            "--jobs" => a.jobs = usize::try_from(num(val()?)?).unwrap_or(1).max(1),
            "--out" => a.out = Some(val()?),
            "--list" => a.list = true,
            "-h" | "--help" => return Ok(None),
            _ => return Err(format!("unknown argument {k}\n{USAGE}")),
        }
    }
    Ok(Some(a))
}

#[derive(Default)]
struct Tally {
    ran: u64,
    failed: Vec<(u64, String)>,
}

fn main() -> ExitCode {
    let args = match parse() {
        Ok(Some(a)) => a,
        Ok(None) => {
            println!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Err(e) => {
            eprintln!("sim-sweep: {e}");
            return ExitCode::from(2);
        }
    };
    let chosen: Vec<&'static str> = SCENARIOS
        .iter()
        .map(|s| s.0)
        .filter(|n| match &args.only {
            Some(o) => o.iter().any(|x| x == n),
            None => args.blocked || blocked(n).is_none(),
        })
        .collect();
    if args.list {
        for (n, _) in SCENARIOS {
            println!("{n}{}", blocked(n).map(|i| format!("  (blocked: {i})")).unwrap_or_default());
        }
        return ExitCode::SUCCESS;
    }
    if let Some(o) = &args.only
        && let Some(x) = o.iter().find(|x| !SCENARIOS.iter().any(|s| s.0 == x.as_str()))
    {
        eprintln!("sim-sweep: no scenario {x}");
        return ExitCode::from(2);
    }
    // seed-major order, so a budget cut leaves every scenario about as many seeds
    let mut work: VecDeque<(&'static str, u64)> = VecDeque::new();
    for k in 0..args.seeds {
        for n in &chosen {
            work.push_back((n, args.from.saturating_add(k)));
        }
    }
    eprintln!("sim-sweep: {} scenarios, seeds {}..{}, {} jobs{}", chosen.len(), args.from, args.from.saturating_add(args.seeds), args.jobs, args.budget.map(|b| format!(", budget {} s", b.as_secs())).unwrap_or_default());
    // failures carry the panic text; the default hook would print every one twice
    std::panic::set_hook(Box::new(|_| {}));
    let work = Arc::new(Mutex::new(work));
    let tally: Arc<Mutex<BTreeMap<&'static str, Tally>>> = Arc::new(Mutex::new(BTreeMap::new()));
    let start = Instant::now();
    let mut handles = Vec::new();
    for _ in 0..args.jobs {
        let (work, tally, budget) = (work.clone(), tally.clone(), args.budget);
        handles.push(std::thread::spawn(move || {
            loop {
                if budget.is_some_and(|b| start.elapsed() > b) {
                    return;
                }
                let next = work.lock().ok().and_then(|mut w| w.pop_front());
                let Some((name, seed)) = next else { return };
                let Some(f) = SCENARIOS.iter().find(|s| s.0 == name).map(|s| s.1) else { continue };
                let r = run(name, seed, f);
                if let Err(e) = &r {
                    eprintln!("FAIL {e}");
                }
                if let Ok(mut t) = tally.lock() {
                    let t = t.entry(name).or_default();
                    t.ran += 1;
                    if let Err(e) = r {
                        t.failed.push((seed, e.what.chars().take(300).collect()));
                    }
                }
            }
        }));
    }
    for h in handles {
        let _ = h.join();
    }
    let tally = tally.lock().map(|mut t| std::mem::take(&mut *t)).unwrap_or_default();
    let mut lines = Vec::new();
    let mut any = false;
    println!("scenario seeds failed");
    for n in &chosen {
        let t = tally.get(n);
        let (ran, failed) = t.map_or((0, 0), |t| (t.ran, t.failed.len()));
        println!("{n} {ran} {failed}");
        for (seed, what) in t.map(|t| t.failed.clone()).unwrap_or_default() {
            any = true;
            lines.push(format!("{n} {seed} {what}"));
        }
    }
    lines.sort();
    for l in &lines {
        let mut p = l.splitn(3, ' ');
        let (n, s) = (p.next().unwrap_or(""), p.next().unwrap_or(""));
        println!("failing: osis_sim::replay(\"{n}\", {s})");
    }
    println!("elapsed {} s", start.elapsed().as_secs());
    if let Some(dir) = &args.out
        && any
    {
        let w = std::fs::create_dir_all(dir).and_then(|_| std::fs::File::create(format!("{dir}/failing-seeds.txt"))).and_then(|mut f| f.write_all(lines.join("\n").as_bytes()));
        if let Err(e) = w {
            eprintln!("sim-sweep: writing {dir}: {e}");
        }
    }
    if any { ExitCode::FAILURE } else { ExitCode::SUCCESS }
}
