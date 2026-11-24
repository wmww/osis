//! A by-hand comparison of two builds of the walk: every reading and every update's `Changed`
//! over the differential worlds and soups (arrival in a shuffled order, half forgotten one at a
//! time, an edge write trusted and put aside, disputes), written one line per world to
//! `OSIS_DUMP`, so a build before a rewrite of the walk and the build after it can be diffed; the
//! purged deltas, and the other purge readings, hash in columns of their own.
//! spec: none (test infrastructure: a comparison of two builds).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use super::incremental::reading;
use super::{input, rules, MODES};
use osis_base::Tid;
use osis_perm::paths::{Changed, Commit, Paths};
use osis_perm::WriteId;
use roles_model::paths as m;
use roles_model::Rng;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::hash::{DefaultHasher, Hash, Hasher};

/// A reading, as three strings: every reading but the purged deltas and the purge readings; the
/// purged deltas; the purge readings (purged copies, requests' rights).
fn full(p: &mut Paths, disputes: bool) -> [String; 3] {
    let (st, h, f, c, cp, pu, ch, more) = reading(p);
    let mut s = format!("{st:?}|{h:?}|{f:?}|{c:?}|{cp:?}|{ch:?}|{:?}", p.void_trusted());
    if disputes {
        let _ = write!(s, "|{:?}", p.disputes());
    }
    [s, format!("{pu:?}"), format!("{more:?}")]
}

/// What an update reported: of the readings `full` hashes first, and of purges.
fn changed(c: &Changed) -> [String; 3] {
    [format!("{:?}{:?}{:?}{:?}{:?}", c.parts, c.edges, c.cuts, c.regrant, c.named.union(&c.carried).collect::<Vec<_>>()), String::new(), format!("{:?}", c.purges)]
}

fn trace(records: &BTreeMap<Tid, Tid>, trust: &BTreeSet<WriteId>, commits: &[Commit], seed: u64, disputes: bool) -> [String; 3] {
    let mut out: [String; 3] = Default::default();
    let mut take = |x: [String; 3]| {
        for (o, x) in out.iter_mut().zip(x) {
            *o += &x;
        }
    };
    let mut p = Paths::new(records, trust.clone());
    take(changed(&p.add(commits)));
    take(full(&mut p, false));
    let mut rng = Rng(seed);
    let order = rng.perm(commits.len());
    let mut p = Paths::new(records, trust.clone());
    for &k in &order {
        take(changed(&p.add(std::slice::from_ref(&commits[k]))));
    }
    take(full(&mut p, false));
    for &k in order.iter().filter(|&&k| k % 2 == seed as usize % 2) {
        take(changed(&p.forget(&[commits[k].id])));
    }
    take(full(&mut p, false));
    if let Some(id) = p.statuses().into_keys().nth(rng.below(4)) {
        let mut more = trust.clone();
        more.insert(id);
        take(changed(&p.set_trust(more)));
        take(changed(&p.set_trust(trust.clone())));
    }
    take(full(&mut p, disputes));
    out
}

/// One world's line: its name, the hash of every reading and `Changed` but the purge readings,
/// the hash of the purged deltas, the hash of the other purge readings (and what `Changed` says
/// of them).
fn line(out: &mut String, what: String, t: [String; 3]) {
    let hash = |x: &str| {
        let mut h = DefaultHasher::new();
        x.hash(&mut h);
        h.finish()
    };
    let _ = writeln!(out, "{what} {:016x} {:016x} {:016x}", hash(&t[0]), hash(&t[1]), hash(&t[2]));
}

// Writes the dump (OSIS_DUMP: the file; OSIS_DUMP_N: worlds per kind, default 300).
#[test]
#[ignore]
fn paths_dump_readings() {
    // by hand: without a file to write, nothing to do
    let Ok(path) = std::env::var("OSIS_DUMP") else { return };
    let n: u64 = std::env::var("OSIS_DUMP_N").ok().and_then(|x| x.parse().ok()).unwrap_or(300);
    let mut out = String::new();
    for mode in MODES {
        for i in 0..n {
            let t = m::tiny_world(i, mode, &rules());
            let inp = input(&t.w, &t.v);
            line(&mut out, format!("tiny {mode:?} {i}"), trace(&inp.records, &inp.trust, &inp.commits, i, i % 4 == 0));
        }
    }
    for i in 0..n {
        let (w, v) = super::content::world(i);
        let w = super::as_known(&w, &v);
        let inp = input(&w, &v);
        line(&mut out, format!("content {i}"), trace(&inp.records, &inp.trust, &inp.commits, i, i % 4 == 0));
        let (records, commits) = super::shapes::soup(i);
        line(&mut out, format!("soup {i}"), trace(&records, &BTreeSet::new(), &commits, i, true));
        let p = Paths::evaluate(&records, BTreeSet::new(), &commits);
        if let Some(id) = p.statuses().into_keys().next() {
            line(&mut out, format!("soup trusted {i}"), trace(&records, &BTreeSet::from([id]), &commits, i, false));
        }
    }
    for i in 0..n.div_ceil(20) {
        let s = m::random_world(i, &m::Rules::fixed());
        for node in s.honest().into_iter().chain(s.untrusting()) {
            if !s.sync.contains_key(&node) {
                continue;
            }
            let v = s.view(node, &m::Rules::fixed());
            let w = super::as_known(&s.w, &v);
            let inp = input(&w, &v);
            line(&mut out, format!("story {i} {node}"), trace(&inp.records, &inp.trust, &inp.commits, i, false));
        }
    }
    for i in 0..n.div_ceil(4) {
        let pw = m::purge_world(i, &rules());
        let node = pw.nodes()[i as usize % pw.nodes().len()];
        let v = pw.view_at(node, None);
        let w = super::as_known(&pw.w, &v);
        let inp = input(&w, &v);
        line(&mut out, format!("purge {i} {node}"), trace(&inp.records, &inp.trust, &inp.commits, i, i % 4 == 0));
    }
    std::fs::write(path, out).unwrap();
}
