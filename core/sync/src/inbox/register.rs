//! Registering steps at sources keeping S unread (spec/sync-ids.md §6 Steps, Register).
//!
//! A node reading S registers, at each connection where a source keeping S unread is open (a
//! member of class `Store`), the steps its `sync.0` records after the source's step (the head its
//! stream names), in order, one Register out at a time; each only once the source's stream showed
//! every role commit the step's epochs depend on (`Engine::step_needs`, a blob of each present by
//! `Net::present`). At a source whose step is not known (its stream named no head yet) the
//! genesis step goes first, at once: a source holding no step takes it before anything it pulls
//! (it can take no entry of S without a head), one holding a step refuses it (9) and waits for
//! its head event, which comes with its first Pull reply. Ok moves on to the
//! next; refused for now (4, 12) backs off (`offers::backoff_ms`) and registers again; any other
//! refusal waits for the source's step to move (a refused Register changes no view; the next head
//! event does). Nothing is registered at a source on a step `sync.0` does not record (a sibling,
//! or a step past it).
//!
//! Work follows change: one `Effects` key per (connection, S) open by a store credential, judged
//! again when what it read moved (the recorded path, the step's needs, their presence at the
//! source, this module's own progress there).

use super::offers::backoff_ms;
use super::{Here, Net};
use crate::session::RequestId;
use crate::types::{ConnId, Result, SourceClass};
use osis_base::memo::{Effects, Stamped};
use osis_base::{SyncId, WallMs};
use osis_engine::Engine;
use osis_engine::sync::Path;
use osis_label::{ClaimSet, Step, StepId};
use osis_proto::{Code, Msg};
use std::collections::{BTreeMap, BTreeSet};

type Key = (ConnId, SyncId);

/// What to do at one source of S.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Plan {
    Nothing,
    Wait,
    Send(Box<Step>, Option<ClaimSet>),
}

/// This node's registering at one source of S.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Progress {
    /// The last step registered there (answered Ok).
    pub at: Option<StepId>,
    pub out: bool,
    /// Refused for now: until when, how many times in a row.
    pub backoff: Option<(WallMs, u32)>,
    /// Refused while the source stood at this step: nothing more until it moves.
    pub stuck: Option<Option<StepId>>,
}

#[derive(Clone)]
pub(super) struct Register {
    plans: Effects<Key, Plan>,
    progress: Stamped<Key, Progress>,
    /// Register requests out: their sync ID, step and the source's step when sent.
    out: BTreeMap<(ConnId, RequestId), (SyncId, StepId, Option<StepId>)>,
    wakes: BTreeSet<(WallMs, Key)>,
}

impl Default for Register {
    fn default() -> Self {
        Register { plans: Effects::new("inbox: register"), progress: Stamped::default(), out: BTreeMap::new(), wakes: BTreeSet::new() }
    }
}

impl Register {
    pub(super) fn joined(&mut self, conn: ConnId, s: SyncId) {
        self.plans.want((conn, s));
    }

    pub(super) fn left(&mut self, conn: ConnId, s: &SyncId) {
        let k = (conn, *s);
        self.plans.unwant(&k);
        if self.progress.contains_key(&k) {
            self.progress.remove(&k);
        }
    }

    pub(super) fn closed(&mut self, conn: ConnId) {
        let keys: Vec<Key> = self.progress.keys().filter(|(c, _)| *c == conn).copied().collect();
        for k in keys {
            self.left(conn, &k.1);
        }
        self.out.retain(|(c, _), _| *c != conn);
        self.wakes.retain(|(_, (c, _))| *c != conn);
    }

    pub(super) fn settle(&mut self, h: &mut Here<'_>, net: &mut impl Net) -> Result<bool> {
        let mut acted = false;
        while let Some(&(t, k)) = self.wakes.first() {
            if t > h.now {
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
            let Some((_, plan)) = self.plans.try_settle(&k, || judge(engine, &*net, progress, &k))? else { continue };
            let Plan::Send(step, claims) = plan else { continue };
            let (conn, s) = k;
            let source = net.head(conn, &s);
            let Some(id) = net.request(conn, Msg::Register { id: 0, sync_id: s, step: (*step).clone(), claim_set: claims }) else { continue };
            osis_base::costs::count("inbox: registered", 1);
            self.out.insert((conn, id), (s, step.id(), source));
            let mut p = self.progress.get(&k).copied().unwrap_or_default();
            p.out = true;
            self.progress.insert(k, p);
            acted = true;
        }
        Ok(acted)
    }

    /// A Register's answer: whether it was one of ours.
    pub(super) fn answered(&mut self, now: WallMs, conn: ConnId, id: RequestId, m: &Msg) -> bool {
        let Some((s, step, source)) = self.out.remove(&(conn, id)) else { return false };
        let k = (conn, s);
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
                let at = WallMs(now.0.saturating_add(backoff_ms(n)));
                p.backoff = Some((at, n));
                self.wakes.insert((at, k));
            }
            _ => p.stuck = Some(source),
        }
        self.progress.insert(k, p);
        true
    }

    pub(super) fn next_wake(&self) -> Option<WallMs> {
        self.wakes.first().map(|(t, _)| *t)
    }
}

fn judge(engine: &mut Engine, net: &impl Net, progress: &Stamped<Key, Progress>, k: &Key) -> Result<Plan> {
    osis_base::costs::count("inbox: register judged", 1);
    let (conn, s) = k;
    if net.member(*conn, s).is_none_or(|m| m.class != SourceClass::Store) {
        return Ok(Plan::Nothing);
    }
    let Some(t) = engine.sync_owner(s)? else { return Ok(Plan::Nothing) };
    let Some(path) = engine.sync_ids(&t)?.iter().find(|o| o.id == *s && !o.hint).map(|o| o.path.clone()) else { return Ok(Plan::Nothing) };
    let p = progress.get(k).copied().unwrap_or_default();
    let mut needs_held = |step: &StepId| -> Result<bool> {
        for c in engine.step_needs(s, step)?.iter() {
            if !engine.commit_blobs(c)?.iter().any(|b| net.present(*conn, s, b)) {
                return Ok(false);
            }
        }
        Ok(true)
    };
    plan(net.head(*conn, s), &path, &p, &mut needs_held)
}

/// spec/sync-ids.md §6 Steps (Register), Walk (Moving it): at a source keeping S unread standing
/// at step `source` (its head event's), given this node's recorded `path` and its progress
/// there, the next recorded step to register, once `held` says the source holds the role
/// commits it depends on; at a source whose step is not known, its genesis step, at once.
pub fn plan(source: Option<StepId>, path: &Path, p: &Progress, held: &mut dyn FnMut(&StepId) -> Result<bool>) -> Result<Plan> {
    if p.out || p.backoff.is_some() || p.stuck.is_some_and(|x| x == source) {
        return Ok(Plan::Wait);
    }
    let index = |id: &Option<StepId>| id.and_then(|id| path.steps.iter().position(|(st, _)| st.id() == id));
    // the source's step: its head event's, or a later one this node registered there
    let Some(i) = index(&source).max(index(&p.at)) else {
        return Ok(match path.steps.first() {
            Some((genesis, claims)) if source.is_none() && p.at.is_none() => Plan::Send(Box::new(genesis.clone()), claims.clone()),
            _ => Plan::Nothing,
        });
    };
    let Some((next, claims)) = path.steps.get(i + 1) else { return Ok(Plan::Nothing) };
    if held(&next.id())? { Ok(Plan::Send(Box::new(next.clone()), claims.clone())) } else { Ok(Plan::Wait) }
}
