//! Registering steps at sources keeping S unread (spec/sync-ids.md §6 Steps, Register).
//!
//! A node reading S registers, at each connection where a source keeping S unread is open (a
//! member of class `Store`), the steps its `sync.0` records after the source's step (the head its
//! stream names), in order, one Register out at a time; each only once the source's stream showed
//! every role commit the step waits on (`Engine::step_needs`, a blob of each present by
//! `Net::present`), but at once at a source that takes nothing: one on a step past its keys (S
//! open there by the proof of a sync key its step does not bear: a store granted after S's epochs
//! moved on stands at genesis holding a later key) until it stands at a step bearing that key. At a source whose step is not known (its stream named no head yet) the
//! genesis step goes first, at once: a source holding no step takes it before anything it pulls
//! (it can take no entry of S without a head), one holding a step refuses it (9) and waits for
//! its head event, which comes with its first Pull reply. Ok moves on to the
//! next; refused for now (4, 12) backs off (`offers::backoff_ms`) and registers again; any other
//! refusal waits for the source's step to move (a refused Register changes no view; the next head
//! event does). At a source on a step `sync.0` records off the recorded path (a sibling branch),
//! one Register carries the recorded steps after the deepest step the two paths share, through
//! the first deeper than the source's step, when the shared step's delete key is the source's
//! step's, else through the first deeper than it that `sync.0` records endorsed by that key, with
//! the endorsement (a store takes nothing else: `store::path::register`); nothing at a source on
//! a step `sync.0` does not record (past it), on an equal-depth or deeper branch, or with
//! neither.  Endorsements are written by the admins holding the key (`Engine::endorse_due`).
//!
//! Steps are issued by the engine with the rotations that make them (spec/sync-ids.md §6
//! Steps); this module only registers recorded ones.
//!
//! Work follows change: one `Effects` key per (record, S) open as a store source, followed
//! across the record's connections until S leaves the record (a record kept nowhere: until its
//! connection ends), judged again when what it read moved (the recorded path, the step's needs,
//! their presence at the source, this module's own progress there, and only where a step is to
//! go, whether a connection holds the record), so a reconnect judges nothing again.

use super::offers::backoff_ms;
use super::{Here, Net};
use crate::session::RequestId;
use crate::store::Source;
use crate::types::{ConnId, Credential, Result, SourceClass};
use osis_base::memo::{Effects, Stamped};
use osis_base::{Mono, SyncId};
use osis_engine::Engine;
use osis_crypto::Signature;
use osis_engine::sync::{OwnedSyncId, Path};
use osis_blob::{Step, StepId};
use osis_proto::{Code, Msg};
use std::collections::{BTreeMap, BTreeSet};

type Key = (Source, SyncId);

/// What to do at one source of S.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Plan {
    Nothing,
    Wait,
    /// Refused while the source stood at its step: nothing goes until it moves, nothing owed.
    Stuck,
    /// The steps of one Register, in order, and the endorsement of the last by the source's
    /// step's delete key when it needs one.
    Send(Vec<Step>, Option<Signature>),
}

/// This node's registering at one source of S.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Progress {
    /// The last step registered there (answered Ok).
    pub at: Option<StepId>,
    pub out: bool,
    /// Refused for now: until when, how many times in a row.
    pub backoff: Option<(Mono, u32)>,
    /// Refused while the source stood at this step: nothing more until it moves.
    pub stuck: Option<Option<StepId>>,
}

#[derive(Clone)]
pub(super) struct Register {
    plans: Effects<Key, Plan>,
    /// The keys `plans` follows (store members open), by record: what a record going lets go.
    followed: BTreeSet<Key>,
    /// Each key judged since the last `take_owed`, with whether a Register is owed there: an
    /// ended member at a store source stays open while one is (spec/sync-opens.md §6).
    owed: Vec<(Source, SyncId, bool)>,
    progress: Stamped<Key, Progress>,
    /// Register requests out: their key, last step and the source's step when sent.
    out: BTreeMap<(ConnId, RequestId), (Key, StepId, Option<StepId>)>,
    wakes: BTreeSet<(Mono, Key)>,
}

impl Default for Register {
    fn default() -> Self {
        Register { plans: Effects::new("inbox: register"), followed: BTreeSet::new(), owed: Vec::new(), progress: Stamped::default(), out: BTreeMap::new(), wakes: BTreeSet::new() }
    }
}

impl Register {
    /// S became a store member of the record at `src`.
    pub(super) fn joined(&mut self, src: Source, s: SyncId) {
        self.plans.want((src, s));
        self.followed.insert((src, s));
    }

    /// S left the record at `src`.
    pub(super) fn left(&mut self, src: Source, s: &SyncId) {
        let k = (src, *s);
        self.plans.unwant(&k);
        self.followed.remove(&k);
        self.progress.remove(&k);
        self.wakes.retain(|(_, x)| *x != k);
    }

    /// A connection ended: its Registers out are answered never; a record kept nowhere goes.
    pub(super) fn closed(&mut self, conn: ConnId) {
        let out: Vec<Key> = self.out.iter().filter(|((c, _), _)| *c == conn).map(|(_, (k, ..))| *k).collect();
        self.out.retain(|(c, _), _| *c != conn);
        for k in out {
            if let Some(mut p) = self.progress.get(&k).copied() {
                p.out = false;
                self.progress.insert(k, p);
            }
        }
        self.gone(Source::Conn(conn));
    }

    /// The record at `src` went (evicted, dropped, or kept nowhere and its connection ended).
    pub(super) fn gone(&mut self, src: Source) {
        let keys: Vec<Key> = self.followed.range((src, SyncId([0; 16]))..=(src, SyncId([0xff; 16]))).copied().collect();
        for (src, s) in keys {
            self.left(src, &s);
        }
    }

    pub(super) fn settle(&mut self, h: &mut Here<'_>, net: &mut impl Net) -> Result<bool> {
        let mut acted = false;
        while let Some(&(t, k)) = self.wakes.first() {
            if t > h.mono {
                break;
            }
            self.wakes.remove(&(t, k));
            if let Some(mut p) = self.progress.get(&k).copied()
                && p.backoff.is_some_and(|(at, _)| at == t)
            {
                p.backoff = None;
                self.progress.insert(k, p);
            }
        }
        for k in self.plans.due() {
            let (engine, progress) = (&mut *h.engine, &self.progress);
            if !self.followed.contains(&k) {
                continue;
            }
            let mut judged = None;
            let moved = self.plans.try_settle(&k, || {
                let p = judge(engine, &*net, progress, &k)?;
                judged = Some(matches!(p, Plan::Send(..) | Plan::Wait));
                Ok::<_, crate::types::Error>(p)
            })?;
            if let Some(owed) = judged {
                self.owed.push((k.0, k.1, owed));
            }
            let Some((_, plan)) = moved else { continue };
            let Plan::Send(steps, endorsement) = plan else { continue };
            let Some(last) = steps.last().map(Step::id) else { continue };
            let (src, s) = k;
            // a Send judged reads the connection holding the record: one is up
            let Some(conn) = net.conn_of(src) else { continue };
            let source = net.head(src, &s);
            let Some(id) = net.request(conn, Msg::Register { id: 0, sync_id: s, steps, endorsement }) else { continue };
            osis_base::costs::count("inbox: registered", 1);
            self.out.insert((conn, id), (k, last, source));
            let mut p = self.progress.get(&k).copied().unwrap_or_default();
            p.out = true;
            self.progress.insert(k, p);
            acted = true;
        }
        Ok(acted)
    }

    /// A Register's answer: whether it was one of ours.
    pub(super) fn answered(&mut self, now: Mono, conn: ConnId, id: RequestId, m: &Msg) -> bool {
        let Some((k, step, source)) = self.out.remove(&(conn, id)) else { return false };
        let Some(mut p) = self.progress.get(&k).copied() else { return true };
        p.out = false;
        match m {
            Msg::Ok { .. } => {
                p.at = Some(step);
                p.backoff = None;
                p.stuck = None;
            }
            Msg::Error { code: Code::RATE_LIMITED | Code::STORAGE_CAP, .. } => {
                let n = p.backoff.map_or(0, |(_, n)| n.saturating_add(1));
                let at = now.after(backoff_ms(n));
                p.backoff = Some((at, n));
                self.wakes.insert((at, k));
            }
            _ => p.stuck = Some(source),
        }
        self.progress.insert(k, p);
        true
    }

    pub(super) fn next_wake(&self) -> Option<Mono> {
        self.wakes.first().map(|(t, _)| *t)
    }

    /// The keys judged since the last call, each with whether a Register is owed there.
    pub(super) fn take_owed(&mut self) -> Vec<(Source, SyncId, bool)> {
        std::mem::take(&mut self.owed)
    }
}

fn judge(engine: &mut Engine, net: &impl Net, progress: &Stamped<Key, Progress>, k: &Key) -> Result<Plan> {
    osis_base::costs::count("inbox: register judged", 1);
    let (src, s) = k;
    // open there as a store (spec/sync-ids.md §6 Walk, Moving it)
    let key = match net.member_at(*src, s) {
        Some(m) if m.class == SourceClass::Store => match m.by {
            Credential::SyncProof(k) => Some(k),
            Credential::ClaimKey(_) => None,
        },
        _ => return Ok(Plan::Nothing),
    };
    // S's recorded path and tree: a sync ID only a hint names records none
    let mut owned = None;
    for t in engine.sync_owners(s)? {
        owned = owned.or_else(|| engine.sync_ids(&t).ok()?.iter().find(|o| o.id == *s && !o.hint).cloned());
    }
    let Some(o) = owned else { return Ok(Plan::Nothing) };
    let p = progress.get(k).copied().unwrap_or_default();
    let mut needs_held = |step: &StepId| -> Result<bool> {
        for c in engine.step_needs(s, step)?.iter() {
            if !engine.commit_blobs(c)?.iter().any(|b| net.present(*src, s, b)) {
                return Ok(false);
            }
        }
        Ok(true)
    };
    let plan = plan(net.head(*src, s), &o, &p, key, &mut needs_held)?;
    // the connection is read only where a step is to go: up again, it goes
    Ok(match plan {
        Plan::Send(..) if net.conn_of(*src).is_none() => Plan::Wait,
        x => x,
    })
}

/// spec/sync-ids.md §6 Steps (Register), Walk (Moving it): at a source keeping S unread standing
/// at step `source` (its head event's), given this node's sync ID `o` as its `sync.0` records it
/// (the recorded path, every step, the endorsements) and its progress there, the next Register,
/// once `held` says the source holds the role commits each of its steps depends on: on the
/// recorded path, the next recorded step; on a branch off it, the recorded steps after the
/// deepest step the two share through the first deeper than the source's step when the shared
/// step's delete key is the source's step's, else through the first deeper recorded step
/// endorsed by that key, with the endorsement; at a source whose step is not known, its genesis
/// step, at once. Nothing goes when the steps do not fit `MAX_MESSAGE`.
pub fn plan(source: Option<StepId>, o: &OwnedSyncId, p: &Progress, key: Option<[u8; 32]>, held: &mut dyn FnMut(&StepId) -> Result<bool>) -> Result<Plan> {
    let (path, tree): (&Path, &BTreeMap<StepId, Step>) = (&o.path, &o.tree);
    // refused before the source's step was known (the genesis sent at once): its head is waited
    // for, a Register still owed (spec/sync-opens.md §6: its ended member stays)
    if p.stuck == Some(None) && source.is_none() {
        return Ok(Plan::Wait);
    }
    if p.stuck.is_some_and(|x| x == source) {
        return Ok(Plan::Stuck);
    }
    if p.out || p.backoff.is_some() {
        return Ok(Plan::Wait);
    }
    let index = |id: &Option<StepId>| id.and_then(|id| path.steps.iter().position(|st| st.id() == id));
    // a source on a step past its keys: S opened there by a sync key that step does not bear
    let past = |st: &Step| key.is_some_and(|k| st.keys.sync.to_bytes() != k);
    // the recorded steps `from..=to`, once the source holds what each depends on; at once from a
    // step past its keys, where it takes nothing, so holds nothing they depend on
    let mut send = |from: usize, to: usize, endorsement: Option<Signature>, at_once: bool| -> Result<Plan> {
        let Some(steps) = path.steps.get(from..=to) else { return Ok(Plan::Nothing) };
        for st in steps {
            if !at_once && !held(&st.id())? {
                return Ok(Plan::Wait);
            }
        }
        Ok(fit(steps.to_vec(), endorsement))
    };
    // the source's step: its head event's, or a later one this node registered there
    if let Some(i) = index(&source).max(index(&p.at)) {
        let at_once = path.steps.get(i).is_some_and(past);
        return send(i + 1, i + 1, None, at_once);
    }
    let Some(at) = source else {
        return Ok(match path.steps.first() {
            Some(genesis) if p.at.is_none() => fit(vec![genesis.clone()], None),
            _ => Plan::Nothing,
        });
    };
    // off the recorded path: up the source's path in the tree to its deepest recorded-path step
    // `fork`, `up` steps above the source's
    let Some(source_step) = tree.get(&at) else { return Ok(Plan::Nothing) };
    let (mut cur, mut up) = (source_step, 1);
    let fork = loop {
        let Some(prev) = cur.prev else { return Ok(Plan::Nothing) };
        if let Some(j) = index(&Some(prev)) {
            break j;
        }
        let Some(next) = tree.get(&prev).filter(|_| up <= tree.len()) else { return Ok(Plan::Nothing) };
        (cur, up) = (next, up + 1);
    };
    // a store moves off a step bearing its head's delete key, or to a step that key endorsed
    let d = source_step.keys.delete;
    match path.steps.get(fork) {
        Some(f) if f.keys.delete == d => send(fork + 1, fork + up + 1, None, past(source_step)),
        Some(_) => {
            let endorsed = path.steps.iter().enumerate().skip(fork + up + 1).find_map(|(j, st)| o.endorsed.get(&st.id()).and_then(|e| e.get(&d.to_bytes())).map(|e| (j, *e)));
            match endorsed {
                Some((j, e)) => send(fork + 1, j, Some(e), past(source_step)),
                None => Ok(Plan::Nothing),
            }
        }
        None => Ok(Plan::Nothing),
    }
}

/// A Register of `steps` while its body fits `MAX_MESSAGE`; nothing when it does not.
fn fit(steps: Vec<Step>, endorsement: Option<Signature>) -> Plan {
    if (Msg::Register { id: u32::MAX, sync_id: SyncId([0; 16]), steps: steps.clone(), endorsement }).encode().len() > osis_base::format::MAX_MESSAGE {
        return Plan::Nothing;
    }
    Plan::Send(steps, endorsement)
}
