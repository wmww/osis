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

/// Per aspect: the deltas a node holds of it (commit, delta index) and its read.
type AspectView = BTreeMap<(Tid, String), (BTreeSet<(osis_core::CommitId, usize)>, String)>;

fn aspect_view(e: &mut Engine) -> Result<AspectView, String> {
    let mut deltas: BTreeMap<(Tid, String), BTreeSet<(osis_core::CommitId, usize)>> = BTreeMap::new();
    for c in e.commit_ids() {
        let Some(bytes) = e.commit_bytes(&c).map_err(|x| x.to_string())? else { continue };
        let Ok(b) = osis_commit::CommitBlob::decode(&bytes) else { continue };
        for p in &b.parts {
            if let Some(a) = b.header.aspects.get(p.ai) {
                deltas.entry((a.tid, a.ak.as_str().to_string())).or_default().insert((c, p.di));
            }
        }
    }
    let mut out = AspectView::new();
    for (t, a) in e.all_aspects().map_err(|x| x.to_string())? {
        let v = e.get(&t, &a).map_err(|x| x.to_string())?;
        let k = (t, a.as_str().to_string());
        out.insert(k.clone(), (deltas.remove(&k).unwrap_or_default(), format!("{v:?}")));
    }
    Ok(out)
}

/// spec/requirements.md (convergence) over up nodes that may hold different parts of a commit
/// (projections): two nodes holding the same deltas of an aspect read it the same (removed
/// members excused).
fn convergence(sim: &mut NetSim) -> Res<()> {
    let mut views: Vec<(usize, AspectView)> = Vec::new();
    for n in 0..sim.nodes.len() {
        // a removed member's membership view stops at its removal: its validity judgments may differ
        if sim.excused.contains(&n) {
            continue;
        }
        let Some(s) = sim.nodes.get_mut(n).and_then(|x| x.sync.as_mut()) else { continue };
        let v = aspect_view(s.engine_mut()).map_err(|w| format!("node {n}: read failed: {w}"));
        let v = v.map_err(|w| sim.fail(w))?;
        views.push((n, v));
    }
    for (i, (m, vm)) in views.iter().enumerate() {
        for (n, vn) in views.iter().skip(i + 1) {
            for (k, (dm, rm)) in vm {
                if let Some((dn, rn)) = vn.get(k)
                    && dm == dn
                    && rm != rn
                {
                    let (rm, rn): (String, String) = (rm.chars().take(200).collect(), rn.chars().take(200).collect());
                    return Err(sim.fail(format!("divergence: nodes {m} and {n} hold the same {} deltas of {} {} but read {rm} vs {rn}", dm.len(), k.0, k.1)));
                }
            }
        }
    }
    Ok(())
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
                    let (knows, pending) = (e.knows(&g.g), e.pending());
                    let labels: Vec<_> = s.labels().into_iter().map(|(t, l)| (t, l.id)).collect();
                    let d = format!("knows it {knows}, pending {pending:?}, labels {labels:?}, conns {:?}", s.describe());
                    return Err(sim.fail(format!("node {n}, a member of group {}, cannot read it at quiescence (liveness): {d}", g.g)));
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
                    let views = views(sim, &g.g);
                    return Err(sim.fail(format!("members {m} and {n} of group {} read differently at quiescence: {d}; {gap}; views {views:?}", g.g)));
                }
                Some(_) => {}
            }
        }
    }
    Ok(())
}

/// Each node's verdicts on the group's labels at each server (failure detail): writer, number of
/// must-hold bodies, unsettled aspects.
fn views(sim: &mut NetSim, g: &Tid) -> Vec<String> {
    let mut out = Vec::new();
    let keys: Vec<[u8; 32]> = sim.servers.iter().map(|s| s.key).collect();
    for n in 0..sim.nodes.len() {
        let Some(s) = sim.nodes.get_mut(n).and_then(|x| x.sync.as_mut()) else { continue };
        let ls: Vec<LabelId> = s.labels().into_iter().filter(|(x, _)| x == g).map(|(_, l)| l.id).collect();
        for l in ls {
            for (i, k) in keys.iter().enumerate() {
                if let Ok(Some(v)) = s.verdicts(k, &l) {
                    out.push(format!("node {n} at s{i}: writer {} must-hold {} unsettled {:?}", v.writer, v.must_hold.len(), v.unsettled));
                    if let Some(h) = sim.servers.get(i).and_then(|x| x.hub.as_ref()).and_then(|h| h.store().head(&l).ok().flatten()) {
                        out.push(format!("s{i} head {}", h.0[0]));
                        out.push(format!("{:?}", s.describe()));
                    }
                }
            }
        }
    }
    out
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
            if sim.excused.contains(&n) {
                continue;
            }
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

/// spec/sync.md §6: after quiescence, resync passes add and delete nothing at any server.
fn no_ping_pong(sim: &mut NetSim) -> Res<()> {
    let heads = log_heads(sim);
    for _ in 0..IDLE_ROUNDS {
        sim.advance(61_000)?;
        sim.settle()?;
    }
    sim.observe()?;
    let churn = churn(sim, &heads);
    if !churn.is_empty() {
        return Err(sim.fail(format!("labels changed after quiescence (ping-pong): {churn:?}")));
    }
    Ok(())
}

pub type Heads = BTreeMap<(usize, LabelId), ([u8; 16], u64)>;

/// Every label's log head at every up server.
pub fn log_heads(sim: &NetSim) -> Heads {
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

/// Log records since `heads` (a label not in it, or with another log instance, from its start;
/// the last 40 records at most), with what the entries hold.
pub fn churn(sim: &NetSim, heads: &Heads) -> Vec<String> {
    let mut out = Vec::new();
    for (s, l) in log_heads(sim).into_keys() {
        let Some(hub) = sim.hub(s) else { continue };
        let Ok((log, top)) = hub.store().log_head(&l) else { continue };
        let seq = heads.get(&(s, l)).filter(|h| h.0 == log).map_or(0, |h| h.1);
        let recs = hub.store().log_after(&l, seq.max(top.saturating_sub(40)), 64);
        for (_, r) in recs.ok().flatten().unwrap_or_default() {
            let (what, b) = match r {
                LogRecord::Added(b) => ("added", b),
                LogRecord::Deleted(b) => ("deleted", b),
                LogRecord::Pending(b, _) => ("timed delete", b),
                LogRecord::Head(st) => {
                    out.push(format!("s{s} {l:?} head {:?}", st.id().0.first()));
                    continue;
                }
            };
            let kind = sim.known.get(&(l, b)).map(|(c, p)| {
                let h = sim.nodes.iter().find_map(|n| n.sync.as_ref().and_then(|s| s.engine().header(c)));
                let aks: Vec<String> = h.as_ref().map(|h| p.iter().filter_map(|(ai, _)| h.aspects.get(*ai).map(|a| format!("{} {}", a.tid, a.ak.as_str()))).collect()).unwrap_or_default();
                format!("{c:?} {p:?} {aks:?} kind {:?}", h.map(|h| h.kind))
            });
            out.push(format!("s{s} {l:?} {what} {b:?}: {}", kind.unwrap_or_else(|| "unknown".into())));
        }
    }
    out
}
