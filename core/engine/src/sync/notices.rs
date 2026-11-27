//! Notices (spec/permissions.md §4 Notices): how a role commit on a thing X tells a holder M
//! its departure or a box M cannot open by the commit's wrap. A notice is never logged: a reader
//! of X opening X's sync ID toward M by role, or ending M's member for its departure, seals it
//! there and then (`notices_for`, `seal_notice`) and sends it on that connection alone
//! (spec/wire.md §11.2 Notice), so a store keeping X unread holds nothing per holder or grant.
//! M takes one by its own read KEM key (`take_notice`).
//!
//! Who writes the input: c and the giving write are applied edge writes (X's admins); M's keysets
//! are M's rotators'. The sender is any reader of X: a notice counts as the copy it carries
//! is judged (`Engine::open_notice`), so a forged one gives nothing.

use crate::engine::Engine;
use crate::error::Result;
use osis_base::{CommitId, Role, SyncId, Tid};
use osis_crypto::Epoch;
use std::collections::{BTreeMap, BTreeSet};

/// What a notice is: role commit `commit` on `thing` telling `holder` its departure (`departs`)
/// or its boxes, sealed to `holder`'s read keyset at `epoch`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Notice {
    pub thing: Tid,
    pub commit: CommitId,
    pub holder: Tid,
    pub epoch: Epoch,
    pub departs: bool,
}

impl Notice {
    /// Its content key: one notice of each sent per connection.
    pub fn content(&self) -> [u8; 32] {
        let e = [self.epoch.n().to_be_bytes().as_slice(), self.epoch.nonce()].concat();
        osis_base::hash::hash(&[b"notice".as_slice(), self.thing.as_bytes(), &self.commit.0, self.holder.as_bytes(), &e].concat())
    }
}

impl Engine {
    /// The notices a peer proving `proven` is told under sync ID `s` (spec/permissions.md §4
    /// Notices), per independent thing X reading `s`: per holder of X the peer reaches
    /// (`departed_reaches`) that departed X, the commit taking its read, and the public's edge
    /// (`public_told`); per current holder it reaches,
    /// the newest held commit telling it its boxes (`boxed_unopened`): every later box of it opens
    /// by its wrap from there; and, where an older one, the newest such commit writing its edge
    /// (its role, which no later box carries). Each to the holder's read keyset this node seals to
    /// (`rotation::members::notice_keyset`). None of an own thing's.
    /// Cost: `boxed_unopened` per thing, on each open by role or departure judged.
    pub fn notices_for(&mut self, s: &SyncId, proven: &BTreeSet<Tid>) -> Result<Vec<Notice>> {
        let mut out = Vec::new();
        for t in self.read_things_of(s)? {
            if self.core.secret_actor(&t) != Some(t) {
                continue;
            }
            let deps = self.read(|tx| crate::rotation::departures::departures(tx, &t))?;
            let mut told: Vec<(CommitId, Tid, bool)> = Vec::new();
            for d in deps.iter().filter(|d| d.concerns(Role::Read) && !self.core.is_own(&d.holder)) {
                let Some(c) = d.edge.as_ref().and_then(|l| taking(l, Role::Read)) else { continue };
                if self.core.ix.commits.contains_key(&c) && self.departed_reaches(&t, &c, &d.holder, proven) {
                    told.push((c, d.holder, true));
                }
            }
            // the public's edge, to each proven thing that left `t` (J's departed, `judge_peer`):
            // the public's role is every party's, that thing's too, whatever epochs it can open
            let gone: BTreeSet<Tid> = proven.iter().filter(|p| !self.core.is_own(p) && self.core.role_now(p, &t).is_none() && self.core.timelines().get(p).is_some_and(|tl| tl.roles_ever(p).contains_key(&t))).copied().collect();
            if !gone.is_empty() {
                for c in self.public_told(&t) {
                    told.extend(gone.iter().map(|m| (c, *m, true)));
                }
            }
            // per holder, the newest box and the newest edge write on it (its role), which a later
            // box need not carry
            let mut newest: BTreeMap<(Tid, bool), (osis_base::Ts, CommitId)> = BTreeMap::new();
            for (c, m) in self.boxed_unopened(&t)? {
                let Some(h) = self.header(&c) else { continue };
                let (ts, edges): (osis_base::Ts, Vec<usize>) = (h.ts, h.aspect_parts(&t, "roles.0").collect());
                if !self.current_reaches(&m, proven) {
                    continue;
                }
                let named = self.holders_named(&c);
                let writes_edge = edges.iter().any(|ai| named.get(ai).is_some_and(|hs| hs.contains(&m)));
                for k in std::iter::once(false).chain(writes_edge.then_some(true)) {
                    if newest.get(&(m, k)).is_none_or(|(x, _)| ts > *x) {
                        newest.insert((m, k), (ts, c));
                    }
                }
            }
            let mut seen = BTreeSet::new();
            told.extend(newest.into_iter().filter(|((m, _), (_, c))| seen.insert((*m, *c))).map(|((m, _), (_, c))| (c, m, false)));
            for (c, holder, departs) in told {
                let Some((epoch, _)) = self.read(|tx| crate::rotation::members::notice_keyset(tx, &t, &holder))? else { continue };
                out.push(Notice { thing: t, commit: c, holder, epoch, departs });
            }
        }
        Ok(out)
    }

    /// Notice `n` sealed afresh (spec/wire.md §9 Notice) under a fresh blob key: `None` while its
    /// commit is not applied here or no notice keyset of its holder is held.
    pub fn seal_notice(&mut self, n: &Notice, rng: &mut dyn osis_crypto::NodeRng) -> Result<Option<Vec<u8>>> {
        let Some((epoch, kem)) = self.read(|tx| crate::rotation::members::notice_keyset(tx, &n.thing, &n.holder))? else { return Ok(None) };
        if epoch != n.epoch {
            return Ok(None);
        }
        let blob_key = osis_crypto::Secret32::random(rng);
        self.sealed_notice(n, &kem, &blob_key)
    }

    /// Takes notice `bytes` sent under `s` to `holder`, sealed to its read keyset at `epoch`
    /// (spec/permissions.md §4 Notices, spec/wire.md §11.2 Notice): opened by that keyset's read
    /// KEM secret where held here, its copy taken on its own thing, one of `s`'s things (held, or
    /// followed by a locator or signal). Whether it gave anything.
    ///
    /// Invariant (cost): a notice costs at most one decapsulation, and none unless `s` is held or
    /// followed here and the keyset it names is held. Who writes each input: `s`, `holder`,
    /// `epoch` and `bytes` are the sending peer's (any connected peer, proving nothing); the
    /// keysets held are this node's, by its own roles; `s`'s things, this node's sync set. So a
    /// peer's junk costs one decapsulation per message whatever this node holds, and the same
    /// path serves a notice on a fresh connection and after a restart (nothing of it is kept).
    pub fn take_notice(&mut self, s: &SyncId, holder: &Tid, epoch: &Epoch, bytes: &[u8]) -> Result<bool> {
        let things = self.sync_things_of(s)?;
        if things.is_empty() {
            return Ok(false);
        }
        use crate::sync::Opened;
        Ok(!matches!(self.open_notice(&things, holder, epoch, bytes)?, Opened::NotOpen | Opened::Bad | Opened::Commit(_, crate::Ingested::Duplicate(_))))
    }

    /// Whether removal `c` of `holder` from `t` reaches a peer proving `proven`: `holder` is among
    /// `proven`, or a proven thing held read or above on it just before `c`.
    /// Invariant (privacy; spec/sync-hostile.md): a departed peer is told no removal past its own:
    /// one it read the thing through when made, never one of a holder it had left by then.
    fn departed_reaches(&self, t: &Tid, c: &CommitId, holder: &Tid, proven: &BTreeSet<Tid>) -> bool {
        let Some(tl) = self.core.timelines().get(t) else { return false };
        let removes = |o: &osis_perm::EdgeOp| o.holder.thing() == Some(*holder) && o.edge.as_ref().is_none_or(|e| e.role < Role::Read);
        let Some(at) = tl.applied_on(t).find(|(mc, o)| mc.id == *c && removes(o)).map(|(mc, _)| osis_perm::At::before(mc.point())) else { return false };
        proven.contains(holder) || tl.roles_on(holder, at).iter().any(|(p, r)| proven.contains(p) && *r >= Role::Read)
    }

    /// What a departed holder is told of the public's edge on `t` (spec/permissions.md §4
    /// Notices): the newest held commit boxing the public and, where older, the newest writing its
    /// edge (its role, which no later box carries).
    fn public_told(&mut self, t: &Tid) -> BTreeSet<CommitId> {
        let mut newest: BTreeMap<&str, (osis_base::Ts, CommitId)> = BTreeMap::new();
        for c in self.edge_on(&Tid::PUBLIC, t) {
            let Some(h) = self.header(&c) else { continue };
            let (ts, named) = (h.ts, self.holders_named(&c));
            for ak in ["secrets.0", "roles.0"] {
                let names = h.aspect_parts(t, ak).any(|ai| named.get(&ai).is_some_and(|hs| hs.contains(&Tid::PUBLIC)));
                if names && newest.get(ak).is_none_or(|(x, _)| ts > *x) {
                    newest.insert(ak, (ts, c));
                }
            }
        }
        newest.into_values().map(|(_, c)| c).collect()
    }

    /// Whether current holder `m` of `t` reaches a peer proving `proven`: `m` is among `proven`,
    /// or a proven thing holds read or above on `m` now.
    fn current_reaches(&self, m: &Tid, proven: &BTreeSet<Tid>) -> bool {
        proven.contains(m) || self.core.key_holders(m).iter().any(|(p, r)| proven.contains(p) && *r >= Role::Read)
    }

    /// The held role commits on independent thing `t` with each current holder of `t` they box
    /// that cannot open them by their wrap as this node wraps them (`wrapped_at`): one that no
    /// other held commit boxes at read at that epoch (a grantee, a re-sealed holder left out
    /// before, a sync-only holder, one a rotation boxes after leaving it out of the epoch it
    /// supersedes; `t`'s mint admin reads an epoch derived from its own), where no commit boxes
    /// the public there (its box is every party's). Never the public nor an own thing.
    /// Cost: every `secrets.0` piece of `t` held, read once per call.
    fn boxed_unopened(&mut self, t: &Tid) -> Result<Vec<(CommitId, Tid)>> {
        let mut out = Vec::new();
        let current: BTreeSet<Tid> = self.core.key_holders(t).into_iter().map(|(m, _)| m).filter(|m| !m.is_public() && m != t && !self.core.is_own(m)).collect();
        if current.is_empty() {
            return Ok(out);
        }
        let Ok(ak) = osis_base::Ak::new("secrets.0") else { return Ok(out) };
        let cs: Vec<CommitId> = self.core.ix.by_aspect.get(&(*t, ak)).into_iter().flatten().map(|(_, c)| *c).collect();
        // per commit, the read epochs it boxes each holder at
        let mut boxes: BTreeMap<CommitId, BTreeMap<Tid, BTreeSet<Epoch>>> = BTreeMap::new();
        for c in &cs {
            let Some(h) = self.header(c) else { continue };
            let pieces: Vec<usize> = h.aspect_parts(t, "secrets.0").collect();
            let id = *c;
            let at = self.read(|tx| {
                let mut w: BTreeMap<Tid, BTreeSet<Epoch>> = BTreeMap::new();
                for ai in &pieces {
                    let Some(f) = crate::apply::held_fragment(tx, &id, *ai)? else { continue };
                    for k in crate::apply::keys::secrets_write(&f).boxes.keys() {
                        let e = osis_keys::aspects::from_schema(&k.epoch);
                        if let (Role::Read, Ok(e)) = (k.role, e) {
                            w.entry(k.holder.0).or_default().insert(e);
                        }
                    }
                }
                Ok(w)
            })?;
            boxes.insert(id, at);
        }
        // per holder, the newest removal of it from `t` here (its `ts`): a box written before it is
        // no secret it holds (it dropped what the removal took)
        let mut removed: BTreeMap<Tid, osis_base::Ts> = BTreeMap::new();
        if let Some(tl) = self.core.timelines().get(t) {
            for (mc, o) in tl.applied_on(t) {
                if let (Some(h), true) = (o.holder.thing(), o.edge.as_ref().is_none_or(|e| e.role < Role::Read)) {
                    let ts = self.header(&mc.id).map(|x| x.ts);
                    if let Some(ts) = ts {
                        let e = removed.entry(h).or_insert(ts);
                        *e = (*e).max(ts);
                    }
                }
            }
        }
        let ts_of: BTreeMap<CommitId, osis_base::Ts> = boxes.keys().filter_map(|c| Some((*c, self.header(c)?.ts))).collect();
        let boxed_by_another = |c: &CommitId, m: &Tid, e: &Epoch| boxes.iter().any(|(o, w)| o != c && w.get(m).is_some_and(|es| es.contains(e)) && removed.get(m).is_none_or(|r| ts_of.get(o).is_some_and(|ts| ts > r)));
        for c in &cs {
            let named = self.holders_named(c);
            let Some(h) = self.header(c) else { continue };
            let boxed: BTreeSet<Tid> = h.aspect_parts(t, "secrets.0").filter_map(|ai| named.get(&ai)).flatten().filter(|m| current.contains(*m)).copied().collect();
            if boxed.is_empty() {
                continue;
            }
            let Some(e) = self.wrapped_at(t, c)? else { continue };
            // an epoch derived from the mint admin's is no epoch of `t`'s own: its holders read it
            // by derivation
            if boxed_by_another(c, &Tid::PUBLIC, &e) {
                continue;
            }
            // an epoch derived from the mint admin's: the mint admin reads it so
            let up = self.core.created(t).and_then(osis_base::CreationRecord::mint_admin);
            let derived = up.and_then(|up| self.epochs(&up)).is_some_and(|x| osis_keys::ActorEpochs::derived(&x, t).read.secret(&e).is_some());
            out.extend(boxed.into_iter().filter(|m| !boxed_by_another(c, m, &e) && !(derived && Some(*m) == up)).map(|m| (*c, m)));
        }
        Ok(out)
    }
}

/// On a holder's edge log, the commit taking role `r` from it: the first applied write leaving it
/// below `r` after the newest giving it `r` or above (or after its start).
fn taking(log: &osis_keys::EdgeLog, r: Role) -> Option<CommitId> {
    let after = match log.writes.iter().rposition(|w| w.applied && w.role >= Some(r)) {
        Some(i) => log.writes.get(i + 1..)?,
        None if log.start >= Some(r) => log.writes.as_slice(),
        None => return None,
    };
    after.iter().find(|w| w.applied && w.role < Some(r)).map(|w| w.key.commit)
}
