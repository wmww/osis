//! Quiescent invariants of phase B (each returns the violated rule with the seed through the
//! harness; none panics):
//! - spec/requirements.md (convergence): nodes holding the same commits read the same; the
//!   members of a labeled group read the same values of its items.
//! - spec/sync.md §6 (convergence): every body a writer judges must-hold at a label is in a live
//!   entry at every server of the label it reaches; no entry a node judges must-not-hold (and may
//!   delete) stays live there; a writer promotes the deposited entries it verified (§5).
//! - spec/sync.md §4, §5: no live entry is tombstoned, and a blob seen tombstoned never comes
//!   back while the server keeps its data.
//! - spec/commits.md §5: a purged body is at no server and no honest node keeps its key or
//!   ciphertext.
//! - spec/sync.md §6 (no ping-pong): once quiescent, further resync passes add and delete
//!   nothing at any server.
//! - spec/commits.md §4: nothing pends at quiescence (every reason resolved).

use super::{NetSim, Party};
use crate::harness::Res;
use osis_core::{BlobId, LabelId, Role, Tid};
use osis_node::Engine;
use osis_proto::{LabelStore, LogRecord};
use std::collections::{BTreeMap, BTreeSet};

/// Resync rounds the no-ping-pong check watches.
const IDLE_ROUNDS: u64 = 3;

pub fn quiescent(sim: &mut NetSim) -> Res<()> {
    convergence(sim)?;
    pending(sim)?;
    labels(sim)?;
    groups(sim)?;
    purged(sim)?;
    no_ping_pong(sim)
}

/// spec/requirements.md (convergence) over up nodes.
fn convergence(sim: &mut NetSim) -> Res<()> {
    let mut es: Vec<(usize, &mut Engine)> = sim.nodes.iter_mut().enumerate().filter_map(|(i, n)| n.sync.as_mut().map(|s| (i, s.engine_mut()))).collect();
    let r = crate::check::convergence(&mut es);
    r.map_err(|w| sim.fail(w))
}

fn pending(sim: &mut NetSim) -> Res<()> {
    for n in 0..sim.nodes.len() {
        if sim.excused.contains(&n) {
            continue;
        }
        let Some(s) = sim.nodes.get(n).and_then(|x| x.sync.as_ref()) else { continue };
        let p = s.engine().pending();
        if !p.is_empty() {
            return Err(sim.fail(format!("node {n}: {} commits pending at quiescence: {p:?}", p.len())));
        }
    }
    Ok(())
}

/// Liveness and agreement: every node of a current member (by an admin's roster, the owner's
/// devices included) reads the group, and all read the same items.
fn groups(sim: &mut NetSim) -> Res<()> {
    let gs = sim.groups.clone();
    for g in gs {
        let mut roster: Option<BTreeSet<Tid>> = None;
        for n in 0..sim.nodes.len() {
            if sim.excused.contains(&n) {
                continue;
            }
            let Some(s) = sim.nodes.get(n).and_then(|x| x.sync.as_ref()) else { continue };
            if s.engine().role_on(&g.g) == Some(Role::Admin) {
                roster = Some(s.engine().roster(&g.g).into_iter().filter(|(_, e)| e.role >= Role::Read).map(|(t, _)| t).collect());
                break;
            }
        }
        let roster = roster.unwrap_or_default();
        let mut first: Option<(usize, Vec<String>)> = None;
        for n in 0..sim.nodes.len() {
            if sim.excused.contains(&n) {
                continue;
            }
            let tid = sim.tid(n)?;
            let person = sim.person_of.get(&n).copied();
            let expected = roster.contains(&tid) || person.is_some_and(|p| roster.contains(&p) || p == g.owner);
            let Some(s) = sim.nodes.get_mut(n).and_then(|x| x.sync.as_mut()) else { continue };
            let e = s.engine_mut();
            if e.role_on(&g.g).is_none_or(|r| r < Role::Read) {
                if expected {
                    return Err(sim.fail(format!("node {n}, a member of group {}, cannot read it at quiescence (liveness)", g.g)));
                }
                continue;
            }
            let mut reads = Vec::new();
            for t in &g.items {
                let aks = e.aspects(t).unwrap_or_default();
                for ak in aks {
                    let v = e.get(t, &ak).map_err(|x| x.to_string());
                    reads.push(format!("{t} {} {v:?}", ak.as_str()));
                }
            }
            match &first {
                None => first = Some((n, reads)),
                Some((m, f)) if *f != reads => {
                    let d = f.iter().zip(reads.iter()).find(|(a, b)| a != b).map(|(a, b)| format!("{a} vs {b}")).unwrap_or_else(|| format!("{} vs {} reads", f.len(), reads.len()));
                    let (m, items) = (*m, g.items.clone());
                    let gap = gap(sim, m, n, &items);
                    return Err(sim.fail(format!("members {m} and {n} of group {} read differently at quiescence: {d}; {gap}", g.g)));
                }
                Some(_) => {}
            }
        }
    }
    Ok(())
}

/// The item commits one node holds and the other lacks, with where they are (failure detail).
fn gap(sim: &NetSim, m: usize, n: usize, items: &[Tid]) -> String {
    let held = |i: usize| -> BTreeSet<osis_core::CommitId> {
        let Some(e) = sim.nodes.get(i).and_then(|x| x.sync.as_ref()).map(|s| s.engine()) else { return BTreeSet::new() };
        e.commit_ids().into_iter().filter(|c| e.header(c).is_some_and(|h| h.aspects.iter().any(|a| items.contains(&a.tid)))).collect()
    };
    let (hm, hn) = (held(m), held(n));
    let at = |c: &osis_core::CommitId| -> Vec<String> {
        let mut v = Vec::new();
        for ((l, b), (kc, kp)) in &sim.known {
            if kc != c {
                continue;
            }
            for s in 0..sim.servers.len() {
                if sim.hub(s).is_some_and(|h| h.store().live_ids(l).unwrap_or_default().contains(b)) {
                    v.push(format!("s{s} {kp:?}"));
                }
            }
        }
        v
    };
    let pend = |i: usize, c: &osis_core::CommitId| sim.nodes.get(i).and_then(|x| x.sync.as_ref()).and_then(|s| s.engine().pending().into_iter().find(|p| p.0 == *c)).map(|p| format!("{:?}", p.1));
    let only = |a: &BTreeSet<osis_core::CommitId>, b: &BTreeSet<osis_core::CommitId>, lacks: usize| -> Vec<String> {
        a.difference(b).take(4).map(|c| format!("{c:?} at {:?} pending there {:?}", at(c), pend(lacks, c))).collect()
    };
    format!("only {m}: {:?}; only {n}: {:?}", only(&hm, &hn, n), only(&hn, &hm, m))
}

/// spec/sync.md §4-§6 at every up server and every label it holds.
fn labels(sim: &mut NetSim) -> Res<()> {
    for s in 0..sim.servers.len() {
        let Some(hub) = sim.hub(s) else { continue };
        let st = hub.store();
        let ls = st.labels_after(None, 4096).map_err(|e| sim.fail(e.to_string()))?;
        let mut lives: BTreeMap<LabelId, BTreeSet<BlobId>> = BTreeMap::new();
        let mut deposited: Vec<(LabelId, BlobId)> = Vec::new();
        let mut newly_tombed = Vec::new();
        for l in &ls {
            let live: BTreeSet<BlobId> = st.live_ids(l).map_err(|e| sim.fail(e.to_string()))?.into_iter().collect();
            for b in &live {
                if st.tombstoned(l, b).unwrap_or(false) {
                    return Err(sim.fail(format!("server {s}: live entry {b:?} under {l:?} is tombstoned")));
                }
                if sim.tombs.get(&s).is_some_and(|t| t.contains(&(*l, *b))) {
                    return Err(sim.fail(format!("server {s}: blob {b:?} under {l:?} came back after its tombstone")));
                }
                if st.entry(l, b).ok().flatten().is_some_and(|e| e.stamp.is_none()) {
                    deposited.push((*l, *b));
                }
            }
            for (kl, kb) in sim.known.keys() {
                if kl == l && !live.contains(kb) && st.tombstoned(l, kb).unwrap_or(false) {
                    newly_tombed.push((*l, *kb));
                }
            }
            lives.insert(*l, live);
        }
        sim.tombs.entry(s).or_default().extend(newly_tombed);
        let key = sim.servers.get(s).map(|x| x.key).unwrap_or([0; 32]);
        for n in 0..sim.nodes.len() {
            if sim.excused.contains(&n) || sim.is_blocked(Party::N(n), Party::S(s)) {
                continue;
            }
            let Some(sync) = sim.nodes.get_mut(n).and_then(|x| x.sync.as_mut()) else { continue };
            let mine: Vec<(Tid, LabelId)> = sync.labels().into_iter().filter(|(_, gl)| gl.servers.iter().any(|a| a.key == key)).map(|(g, gl)| (g, gl.id)).collect();
            for (g, l) in mine {
                let Some(live) = lives.get(&l) else {
                    return Err(sim.fail(format!("node {n}: its label {l:?} of group {g} is not at server {s}")));
                };
                let v = sim.nodes.get_mut(n).and_then(|x| x.sync.as_mut()).map(|x| x.verdicts(&key, &l));
                let v = match v {
                    Some(Ok(v)) => v,
                    Some(Err(e)) => return Err(sim.fail(format!("node {n} verdicts: {e}"))),
                    None => None,
                };
                let Some(v) = v else {
                    let d = sim.nodes.get(n).and_then(|x| x.sync.as_ref()).map(|x| x.describe()).unwrap_or_default();
                    return Err(sim.fail(format!("node {n}: label {l:?} of group {g} not open at server {s} at quiescence: {d:?}")));
                };
                if v.writer {
                    for (c, parts) in &v.must_hold {
                        let held = live.iter().any(|b| sim.known.get(&(l, *b)).is_some_and(|(kc, kp)| kc == c && parts.iter().all(|p| kp.contains(p))));
                        sim.report.held_checked = sim.report.held_checked.saturating_add(1);
                        if !held {
                            return Err(sim.fail(format!("server {s}: label {l:?} lacks body {c:?} {parts:?} that writer node {n} judges must-hold")));
                        }
                    }
                }
                for (b, why) in &v.must_not {
                    if live.contains(b) {
                        return Err(sim.fail(format!("server {s}: label {l:?} still holds {b:?}, must-not-hold ({why}) for node {n}")));
                    }
                }
                // spec/sync.md §5: a writer re-uploads stamped the deposited commits it verified
                if v.writer {
                    for (dl, db) in &deposited {
                        if *dl != l {
                            continue;
                        }
                        let Some((c, _)) = sim.known.get(&(l, *db)).cloned() else { continue };
                        let Some(sync) = sim.nodes.get(n).and_then(|x| x.sync.as_ref()) else { continue };
                        let Some(h) = sync.engine().header(&c) else { continue };
                        if h.aspects.iter().any(|a| a.ak.as_str() == "/seen") || !sync.entries(&l).iter().any(|(x, _)| x == db) {
                            continue;
                        }
                        return Err(sim.fail(format!("server {s}: deposited {db:?} (commit {c:?}) under {l:?} not promoted by writer node {n}")));
                    }
                }
            }
        }
    }
    Ok(())
}

/// spec/commits.md §5: purged bodies are gone from servers and honest nodes.
fn purged(sim: &mut NetSim) -> Res<()> {
    let purged = sim.purged.clone();
    for (c, t, ak) in purged {
        let mut ai = None;
        for n in &sim.nodes {
            if let Some(h) = n.sync.as_ref().and_then(|s| s.engine().header(&c)) {
                ai = h.aspects.iter().position(|a| a.tid == t && a.ak == ak);
                break;
            }
        }
        let Some(ai) = ai else { continue };
        let blobs: Vec<(LabelId, BlobId)> = sim.known.iter().filter(|(_, (kc, kp))| *kc == c && kp.iter().any(|p| p.0 == ai)).map(|(k, _)| *k).collect();
        for s in 0..sim.servers.len() {
            let Some(hub) = sim.hub(s) else { continue };
            for (l, b) in &blobs {
                if hub.store().live_ids(l).unwrap_or_default().contains(b) {
                    return Err(sim.fail(format!("server {s}: purged body {b:?} of {c:?} still live under {l:?}")));
                }
            }
        }
        for n in 0..sim.nodes.len() {
            let Some(sync) = sim.nodes.get_mut(n).and_then(|x| x.sync.as_mut()) else { continue };
            for (_, b) in &blobs {
                if sync.holds_blob(b) {
                    return Err(sim.fail(format!("node {n} still holds the purged body {b:?} of {c:?}")));
                }
            }
        }
    }
    Ok(())
}

/// spec/sync.md §6: after quiescence, resync passes change nothing at any server.
fn no_ping_pong(sim: &mut NetSim) -> Res<()> {
    let heads = log_heads(sim);
    for _ in 0..IDLE_ROUNDS {
        sim.advance(61_000)?;
        sim.settle()?;
    }
    for ((s, l), (log, seq)) in heads {
        let Some(hub) = sim.hub(s) else { continue };
        let Ok((log2, _)) = hub.store().log_head(&l) else { continue };
        if log2 != log {
            continue;
        }
        let recs = hub.store().log_after(&l, seq, 64).ok().flatten().unwrap_or_default();
        let churn: Vec<String> = recs.iter().filter(|(_, r)| matches!(r, LogRecord::Added(_) | LogRecord::Deleted(_))).map(|(_, r)| format!("{r:?}")).collect();
        if !churn.is_empty() {
            return Err(sim.fail(format!("server {s}: label {l:?} changed after quiescence (ping-pong): {churn:?}")));
        }
    }
    Ok(())
}

fn log_heads(sim: &NetSim) -> BTreeMap<(usize, LabelId), ([u8; 16], u64)> {
    let mut m = BTreeMap::new();
    for s in 0..sim.servers.len() {
        let Some(hub) = sim.hub(s) else { continue };
        for l in hub.store().labels_after(None, 4096).unwrap_or_default() {
            if let Ok(h) = hub.store().log_head(&l) {
                m.insert((s, l), h);
            }
        }
    }
    m
}
