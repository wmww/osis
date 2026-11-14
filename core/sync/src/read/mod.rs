//! Judgement for read sync IDs (spec/sync-judgement.md §1-§5, spec/sync-compaction.md §1,
//! spec/sync-set.md §3).
//!
//! Principle: a reader's store of S holds what its own judgement says S needs; a body leaves it
//! only for a reason every holder sees after one exchange; a node acts at a peer only over what
//! that peer's stream showed (`known`), deletes there only by a Delete signed for the right, and
//! every delete and every logging again is bounded by a change of ground (the peer's head, or a
//! held part falling here). Models: core/test/tla/net/NetHold.tla, NetDestroy.tla.
//!
//! Per (S, commit) a judgement (`judge::body`) gives the body's `Verdict` (must-hold, may-hold,
//! must-not-hold, unjudged) and the acts it calls for now: the own store logs what S must hold and
//! drops what is must-not-hold or covered and dropped (no delete key needed); toward each source
//! keeping S unread it deletes (carriers in that source's `known`, role entries first), deposits
//! (not a writer), or logs again once past a delete, its stand durable in the source's record.
//! Between readers nothing but streams. Per S a destruction judgement (`judge::doom`): told,
//! emptying (the destroying requests kept until their expiry), forgetting, or leaving untold.
//!
//! Work follows change: each judgement is an `Effects` key over the ground's per-key memo
//! values and stamped rows (`Ground`), and read acts only on what a new value adds; nothing
//! re-judges every commit of S per step. A membership change of S re-judges S's followed commits
//! once (every source's view of S moved). State: the effects and three stamped maps (own role
//! commits S must hold, S told destroyed, S left); nothing durable of its own (stands live in the
//! store's record rows), so a start judges every held commit once.

pub mod ground;
mod judge;
mod live;

pub use ground::{Facts, Ground, Seen, SrcView};
pub use live::Live;

use crate::opens::Opens;
use crate::session::{Incoming, Sessions};
use crate::store::Stand;
use crate::streams::Streams;
use crate::types::{ConnId, Cx, Error, Result};
use judge::{Act, Doom, Judged, Mine};
use osis_base::memo::{Effects, Stamped, StampedSet};
use osis_base::{CommitId, SyncId, WallMs};
use osis_engine::sync::BodyMeta;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// A body's verdict at S (spec/sync-judgement.md §2).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Verdict {
    Must,
    May,
    MustNot(Why),
    Unjudged,
}

/// Why a body is must-not-hold (spec/sync-judgement.md §2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Why {
    Purged,
    Expired,
    OutsideRequired,
    StrictSubset,
    CardSuperseded,
    CardEnded,
    /// A destroyed thing's sync ID being emptied (§5).
    Emptied,
}

#[derive(Clone)]
pub struct Read {
    bodies: Effects<CommitId, Arc<BTreeMap<SyncId, BodyMeta>>>,
    judged: Effects<(SyncId, CommitId), Judged>,
    dooms: Effects<SyncId, (Doom, BTreeSet<Act>)>,
    verdicts: Stamped<(SyncId, CommitId), Verdict>,
    /// Own role commits S must hold (§3 Role entries first).
    roles: Stamped<SyncId, BTreeSet<CommitId>>,
    /// S told destroyed, and its destroying requests (kept until their expiry).
    told: Stamped<SyncId, Arc<BTreeSet<CommitId>>>,
    /// S forgotten or left untold.
    left: StampedSet<SyncId>,
}

impl Default for Read {
    fn default() -> Self {
        Read {
            bodies: Effects::new("read: bodies"),
            judged: Effects::new("read: judged"),
            dooms: Effects::new("read: doom"),
            verdicts: Stamped::default(),
            roles: Stamped::default(),
            told: Stamped::default(),
            left: StampedSet::default(),
        }
    }
}

impl std::fmt::Debug for Read {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Read").field("verdicts", &self.verdicts.len()).finish_non_exhaustive()
    }
}

impl Read {
    /// The product's step: over the engine, store, opens' members and streams' `known`.
    pub fn settle(&mut self, cx: &mut Cx, sessions: &mut Sessions, opens: &Opens, streams: &Streams) -> Result<bool> {
        self.settle_on(&mut Live { cx, sessions, opens, streams })
    }

    /// One settle over `g`: whether anything acted.
    pub fn settle_on(&mut self, g: &mut impl Ground) -> Result<bool> {
        let added = match g.commits_added() {
            Err(e) if not_built(&e) => return Ok(false),
            r => r?,
        };
        for c in added {
            self.bodies.want(c);
        }
        let mut acted = false;
        for c in self.bodies.due() {
            let Some((_, now)) = run(&mut self.bodies, &c, || g.bodies(&c))? else { continue };
            for s in now.keys() {
                self.judged.want((*s, c));
                self.dooms.want(*s);
            }
            // a sync ID no longer carrying it stays followed until nothing of it is left there
        }
        for s in self.dooms.due() {
            let told_before = self.told.contains_key(&s);
            let Some((was, (doom, acts))) = run(&mut self.dooms, &s, || judge::doom(g, told_before, &s))? else { continue };
            let before = was.map(|(_, a)| a).unwrap_or_default();
            acted = true;
            match &doom {
                Doom::Told { requests } => {
                    if self.told.get(&s) != Some(requests) {
                        self.told.insert(s, requests.clone());
                    }
                }
                _ => {
                    if self.told.contains_key(&s) {
                        self.told.remove(&s);
                    }
                }
            }
            for a in acts.difference(&before).cloned().collect::<Vec<_>>() {
                self.act(g, &s, None, a)?;
            }
        }
        for k in self.judged.due() {
            let (s, c) = k;
            let mine = Mine { roles: &self.roles, told: &self.told, left: &self.left };
            let moved = run(&mut self.judged, &k, || judge::body(g, &mine, &s, &c))?;
            let Some((was, now)) = moved else { continue };
            acted = true;
            if self.verdicts.get(&k) != Some(&now.verdict) {
                self.verdicts.insert(k, now.verdict.clone());
            }
            self.set_role(&s, &c, now.role);
            let before = was.map(|w| w.acts).unwrap_or_default();
            for a in now.acts.difference(&before).cloned().collect::<Vec<_>>() {
                self.act(g, &s, Some(&c), a)?;
            }
            if now.idle {
                self.judged.unwant(&k);
                self.verdicts.remove(&k);
                self.set_role(&s, &c, false);
            }
        }
        Ok(acted)
    }

    /// Answers to its own requests: a Delete's codes reach `known` through the source's stream,
    /// so nothing is taken from them here.
    pub fn on_message(&mut self, cx: &mut Cx, sessions: &mut Sessions, conn: ConnId, m: Incoming) {
        let _ = (cx, sessions, conn, m);
    }

    /// For status and inbox (stamped read).
    pub fn verdict(&self, s: &SyncId, c: &CommitId) -> Option<Verdict> {
        self.verdicts.get(&(*s, *c)).cloned()
    }

    pub fn next_wake(&self) -> Option<WallMs> {
        None
    }

    fn set_role(&mut self, s: &SyncId, c: &CommitId, on: bool) {
        let has = self.roles.get(s).is_some_and(|r| r.contains(c));
        if has == on {
            return;
        }
        let mut r = self.roles.get(s).cloned().unwrap_or_default();
        if on {
            r.insert(*c);
        } else {
            r.remove(c);
        }
        if r.is_empty() {
            self.roles.remove(s);
        } else {
            self.roles.insert(*s, r);
        }
    }

    fn act(&mut self, g: &mut impl Ground, s: &SyncId, c: Option<&CommitId>, a: Act) -> Result<()> {
        osis_base::costs::count("read: acts", 1);
        match (a, c) {
            (Act::Log, Some(c)) => {
                g.log_own(s, c)?;
            }
            (Act::DropOwn(b), Some(c)) => g.drop_own(s, &b, c)?,
            (Act::Lift(b), _) => g.lift(s, &b)?,
            (Act::Delete { at, conn, head, blob }, _) => {
                let Some(src) = g.sources(s)?.iter().find(|x| x.at == at && x.conn == conn).cloned() else { return Ok(()) };
                let key = g.credentials(s)?.and_then(|cr| cr.keys.get(&head).and_then(|k| k.delete.clone()));
                if let Some(key) = key {
                    g.delete(&src, s, &blob, &key)?;
                }
            }
            (Act::Deposit { at, conn, blob }, _) => {
                if let Some(src) = g.sources(s)?.iter().find(|x| x.at == at && x.conn == conn).cloned() {
                    g.deposit(&src, s, &blob)?;
                }
            }
            (Act::Again { at, head, ground, old, .. }, Some(c)) => {
                // a fresh encryption under this sync ID alone; its stand first, durably
                if let Some(logged) = g.log_own(s, c)? {
                    g.set_stand(&at, s, c, &Stand { at: g.now(), logged, head, deleted: false, ground: judge::ground_bytes(ground) })?;
                    for b in old {
                        g.drop_own(s, &b, c)?;
                    }
                }
            }
            (Act::Forget, _) => {
                g.forget(s)?;
                self.left.insert(*s);
            }
            (Act::Leave, _) => {
                g.leave(s)?;
                self.left.insert(*s);
            }
            (_, None) => {}
        }
        Ok(())
    }
}

/// Settles `k` with `f`; a failure leaves `k` due and is returned.
fn run<K: std::hash::Hash + Eq + Clone, V: Clone + PartialEq + Default>(fx: &mut Effects<K, V>, k: &K, f: impl FnOnce() -> Result<V>) -> Result<Option<(Option<V>, V)>> {
    let mut failed = None;
    let moved = fx.settle(k, || {
        f().unwrap_or_else(|e| {
            failed = Some(e);
            V::default()
        })
    });
    if let Some(e) = failed {
        fx.unwant(k);
        fx.want(k.clone());
        return Err(e);
    }
    Ok(moved)
}

/// A part of the facade or of another module read needs is not built: read does nothing until
/// it is.
fn not_built(e: &Error) -> bool {
    matches!(e, Error::NotBuilt(_) | Error::Engine(osis_engine::Error::NotBuilt(_)))
}

impl Default for Judged {
    fn default() -> Self {
        Judged { verdict: Verdict::Unjudged, role: false, acts: BTreeSet::new(), idle: false }
    }
}
