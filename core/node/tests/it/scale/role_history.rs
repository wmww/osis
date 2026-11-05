//! Role history a joiner fetches with and without roster snapshots (notes/owner-removal-plan.md
//! step 1; spec/requirements.md, Scale). By hand, release, one shape and size at a time:
//! `OSIS_SCALE_SHAPE=chat OSIS_SCALE_N=10000 cargo test --release -p osis-node --test it -- --ignored --nocapture --test-threads 1 scale::role_history::cost`.
//! Shapes: `chat` (1000 writers, n/4 below 4000 writes, joining and leaving), `readers` (the same at read), `devices`
//! (3 persons' devices churning, each removal listing 10 commits), `invites` (links made and
//! revoked, joiners granted), `kicks` (`chat` whose leaves are kicks listing 1..10^3 commits,
//! log-uniform). One node writes every edge on one thing its person owns, raw edge writes (no
//! boxes or rotations: those are other aspects); holders are bare tids. A joiner gets the
//! setup, then either every role commit or the one roster snapshot written at the end.

use super::{peak_kib, reset_peak};
use crate::common::set_edge;
use crate::flows::{hosts, thing_of};
use osis_base::{CommitId, Role, Tid, Value, WallMs};
use osis_node::local_peer::{LocalPeer, Package};
use osis_schema::Codec;
use osis_schema::core_types as ct;
use std::collections::BTreeSet;
use std::time::Instant;

/// This process's user plus system CPU seconds.
fn cpu_s() -> f64 {
    let s = std::fs::read_to_string("/proc/self/stat").unwrap_or_default();
    let rest = s.rsplit(')').next().unwrap_or("");
    let f: Vec<i64> = rest.split_whitespace().skip(1).filter_map(|x| x.parse().ok()).collect();
    // fields 14 and 15 of stat; `rest` starts at field 3 (state, skipped)
    (f.get(10).copied().unwrap_or(0) + f.get(11).copied().unwrap_or(0)) as f64 / 100.0
}

fn holder(i: usize) -> Tid {
    let mut b = [0xa0u8; 15];
    b[..8].copy_from_slice(&(i as u64).to_le_bytes());
    Tid::from_bytes(b)
}

fn size(pk: &Package) -> usize {
    pk.bytes.len() + pk.blobs.iter().map(|b| b.1.len()).sum::<usize>()
}

struct Rng(u64);
impl Rng {
    fn below(&mut self, k: u64) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0 % k
    }
}

/// A frontier listing `k` made-up commit IDs, as a value, and its canonical bytes.
fn frontier(k: usize, rng: &mut Rng) -> (Value, usize) {
    let commits: BTreeSet<CommitId> = (0..k)
        .map(|_| {
            let mut c = [0u8; 32];
            for x in c.chunks_mut(8) {
                x.copy_from_slice(&rng.below(u64::MAX).to_le_bytes());
            }
            CommitId(c)
        })
        .collect();
    let v = ct::Frontier { commits }.to_value();
    let n = osis_base::encode(&v).len();
    (v, n)
}

fn edge(role: Role, invite: Option<Role>) -> ct::Edge {
    ct::Edge { role, until: None, invite, since: None, tied: None, keyset: None }
}

/// Joiner `j` gets `base`, then `pks`: CPU s, wall s, peak resident growth (KiB).
fn join(lp: &mut LocalPeer, j: usize, base: &[Package], pks: &[Package]) -> (f64, f64, u64) {
    for p in base {
        let _ = lp.deliver(j, p);
    }
    for p in base {
        let _ = lp.deliver(j, p);
    }
    reset_peak();
    let before = peak_kib();
    osis_node::costs::take();
    let (c0, t0) = (cpu_s(), Instant::now());
    for p in pks {
        lp.deliver(j, p).unwrap();
    }
    (cpu_s() - c0, t0.elapsed().as_secs_f64(), peak_kib().saturating_sub(before))
}

/// Prints the engine's cost spans since the last take (`OSIS_SCALE_SPANS=1`).
fn spans(what: &str) {
    let all = osis_node::costs::take();
    if std::env::var("OSIS_SCALE_SPANS").is_ok() {
        for (k, d, c) in all.iter().filter(|x| x.1.as_millis() >= 10) {
            println!("    {what}: {k}: {d:?} ({c})");
        }
    }
}

// spec: none (cost measurement)
#[test]
#[ignore = "tier 2"]
fn cost() {
    let shape = std::env::var("OSIS_SCALE_SHAPE").unwrap_or_else(|_| "chat".into());
    let n: usize = std::env::var("OSIS_SCALE_N").ok().and_then(|v| v.parse().ok()).unwrap_or(1_000);
    let mut lp = LocalPeer::new(3, 91, WallMs(1_700_000_000_000)).unwrap();
    let pa = lp.peers[0].engine.create_person(&hosts()).unwrap().0.person;
    let things: Vec<Tid> = (0..if shape == "devices" { 3 } else { 1 }).map(|_| thing_of(&mut lp, 0, pa)).collect();
    let base = lp.packages(0).unwrap();
    let mut rng = Rng(0x5eed_1234);
    let (mut ids, mut fr_total, mut fr_max, mut fr_n) = (Vec::new(), 0usize, 0usize, 0usize);
    let mut next = 0usize;
    // members the chat shapes keep: 1000, or n/4 at small n so leaves happen
    let members = (n / 4).min(1000);
    // live holders per thing, oldest first
    let mut live: Vec<Vec<Tid>> = vec![Vec::new(); things.len()];
    let (c0, t0) = (cpu_s(), Instant::now());
    for i in 0..n {
        if i % 50 == 0 {
            lp.advance(1_000);
        }
        let ti = i % things.len();
        let t = things[ti];
        let mut add = |live: &mut Vec<Vec<Tid>>, e: ct::Edge, lp: &mut LocalPeer| {
            let h = holder(next);
            next += 1;
            live[ti].push(h);
            set_edge(&mut lp.peers[0].engine, t, h, Some(e), None)
        };
        let id = match shape.as_str() {
            "chat" | "readers" | "kicks" => {
                let role = if shape == "readers" { Role::Read } else { Role::Write };
                if live[ti].len() < members || rng.below(2) == 0 {
                    add(&mut live, edge(role, None), &mut lp)
                } else {
                    let k = rng.below(live[ti].len() as u64) as usize;
                    let h = live[ti].swap_remove(k);
                    let f = (shape == "kicks").then(|| {
                        // log-uniform 1..10^3 commits
                        let c = 10f64.powf(rng.below(3001) as f64 / 1000.0) as usize;
                        let (v, b) = frontier(c, &mut rng);
                        fr_total += b;
                        fr_max = fr_max.max(b);
                        fr_n += 1;
                        v
                    });
                    set_edge(&mut lp.peers[0].engine, t, h, None, f)
                }
            }
            "devices" => {
                if live[ti].len() < 5 || rng.below(2) == 0 {
                    add(&mut live, edge(Role::Admin, None), &mut lp)
                } else {
                    let h = live[ti].remove(0);
                    let (v, b) = frontier(10, &mut rng);
                    fr_total += b;
                    fr_max = fr_max.max(b);
                    fr_n += 1;
                    set_edge(&mut lp.peers[0].engine, t, h, None, Some(v))
                }
            }
            "invites" => match i % 4 {
                0 => add(&mut live, edge(Role::Write, Some(Role::Write)), &mut lp),
                1 | 2 => {
                    let h = holder(next);
                    next += 1;
                    set_edge(&mut lp.peers[0].engine, t, h, Some(edge(Role::Write, None)), None)
                }
                _ => {
                    let h = live[ti].remove(0);
                    set_edge(&mut lp.peers[0].engine, t, h, None, None)
                }
            },
            s => panic!("unknown shape {s}"),
        };
        ids.push(id);
    }
    let (write_cpu, write_wall) = (cpu_s() - c0, t0.elapsed().as_secs_f64());
    let pks: Vec<Package> = ids.iter().map(|id| lp.peers[0].engine.package(id).unwrap().unwrap()).collect();
    let bytes: usize = pks.iter().map(size).sum();
    let per_thing = bytes / things.len();
    println!("{shape} n={n}: {n} role commits written in {write_cpu:.1} CPU-s ({write_wall:.1} s); role history {bytes} B ({} B per write), {per_thing} B per thing", bytes / n.max(1));
    if fr_n > 0 {
        println!("  frontiers: {fr_n} removals, total {fr_total} B, largest {fr_max} B");
    }
    // snapshots off: a joiner of thing 0 gets every role commit on it
    let mine: Vec<Package> = pks.iter().enumerate().filter(|(i, _)| i % things.len() == 0).map(|(_, p)| p.clone()).collect();
    let (c, w, peak) = join(&mut lp, 1, &base, &mine);
    spans("history ingest");
    println!("  off: joiner ingests {} commits, {} B: {c:.2} CPU-s ({w:.2} s), peak +{} MiB", mine.len(), mine.iter().map(size).sum::<usize>(), peak / 1024);
    let roster = lp.peers[1].engine.roster(&things[0]);
    assert_eq!(roster, lp.peers[0].engine.roster(&things[0]));
    // from scratch: the joiner's open with its saved walks gone
    lp.peers[1].engine.damage_walks(0).unwrap();
    reset_peak();
    let before = peak_kib();
    let (c0, t0) = (cpu_s(), Instant::now());
    lp.peers[1].restart(7).unwrap();
    println!("  off: open evaluating anew {:.2} CPU-s ({:.2} s), peak +{} MiB ({} restored)", cpu_s() - c0, t0.elapsed().as_secs_f64(), peak_kib().saturating_sub(before) / 1024, lp.peers[1].engine.walks_restored());
    assert_eq!(lp.peers[1].engine.roster(&things[0]), roster);
    // snapshots on: one roster snapshot after every write; a joiner gets it alone
    osis_node::costs::take();
    let (c0, t0) = (cpu_s(), Instant::now());
    let done = lp.peers[0].engine.roster_snapshot(&things[0], None);
    let done = match done {
        Ok(d) => d,
        Err(e) => {
            println!("  on: no roster snapshot: {e:?}");
            return;
        }
    };
    let snap_cpu = cpu_s() - c0;
    spans("snapshot write");
    let snap_wall = t0.elapsed().as_secs_f64();
    let spks: Vec<Package> = done.commits.iter().map(|id| lp.peers[0].engine.package(id).unwrap().unwrap()).collect();
    let sbytes: usize = spks.iter().map(size).sum();
    println!("  on: snapshot written in {snap_cpu:.2} CPU-s ({snap_wall:.2} s): {} commits, {sbytes} B ({} blobs)", spks.len(), spks.iter().map(|p| p.blobs.len()).sum::<usize>());
    let (c, w, peak) = join(&mut lp, 2, &base, &spks);
    spans("snapshot ingest");
    println!("  on: joiner ingests the snapshot: {c:.2} CPU-s ({w:.2} s), peak +{} MiB", peak / 1024);
    let r2 = lp.peers[2].engine.roster(&things[0]);
    if r2 != roster {
        println!("  on: joiner's roster differs: {} holders against {}", r2.len(), roster.len());
    }
    lp.peers[2].engine.damage_walks(0).unwrap();
    let (c0, t0) = (cpu_s(), Instant::now());
    lp.peers[2].restart(8).unwrap();
    println!("  on: open evaluating anew {:.2} CPU-s ({:.2} s)", cpu_s() - c0, t0.elapsed().as_secs_f64());
}
