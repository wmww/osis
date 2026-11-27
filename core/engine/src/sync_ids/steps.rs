//! The steps a thing's `sync.0` state records, as delete keys are listed from them and checked
//! against them (spec/crypto.md §7 Header list, Checked keys): per independent thing, each step
//! on a verified path from the genesis step of a sync ID its `sync.0` records, with the stamp from
//! which the whole path is recorded. An index derived from the state (`Tx::derive`), so from the
//! thing's held valid `sync.0` writes alone, and held in no store: a function of what is held.
//!
//! Invariant (what the check rests on): a level-1 or level-3 key a header lists is taken as right
//! only where it is a key this index places: the delete key (level 1) or write key (level 3) of a
//! step whose every ancestor verifies under its parent's delete key down to a genesis step whose
//! delete key hashes to its sync ID, each of them recorded by a valid `sync.0` write stamped
//! before the commit. Only an admin's write is valid on `sync.0`, a step verifies only under a
//! key an admin secret derives, and no secret this node holds is read: every node holding the
//! same writes places the same keys. A non-admin signer's own key is on no such path, so a part
//! listing it applies nowhere (unjudgeable, `Core::miskeyed`).
//!
//! Every sync ID entry counts, owned or not (ownership turns on the secrets a node holds,
//! spec/sync-ids.md §4, which a verdict must not): an admin recording a sync ID of its own making
//! places only keys of secrets it holds, as any step of the thing's own path it issued does.

use crate::engine::Core;
use osis_base::format::{DELETE_ADMIN, DELETE_AUTHOR, DELETE_WRITER};
use osis_base::{CommitId, SyncId, Tid, Ts, Value};
use osis_commit::Header;
use osis_blob::{Step, StepId};
use osis_crdt::{Fragment, PathSeg};
use osis_schema::core_types as ct;
use osis_schema::{Codec, RawKey};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// The step records a `sync.0` delta `f` writes, per sync ID: each step entry it writes whole
/// (its step bytes in it), in any sync ID's entry, created there or not. A step joins the entry
/// its sync ID's genesis made, so a read of the delta alone shows none of it (spec/crdt.md §5.6):
/// a commit is read for its steps by this, never by `read`.
pub(crate) fn written_steps(f: &Fragment) -> ct::SyncIds {
    use crate::apply::keys::{field, map};
    let mut out = ct::SyncIds::new();
    // map<sync ID, {0 steps: map<step ID, {0 step, ..}>}>, each map's entries live or not
    for (_, _, k, e) in map(Some(f)).into_iter().flat_map(|m| m.entries()) {
        let (Some(Ok(sync_id)), Some(e)) = (k.map(SyncId::from_value), e) else { continue };
        for (_, _, sk, r) in map(field(e, 0)).into_iter().flat_map(|m| m.entries()) {
            let (Some(Ok(id)), Some(Ok(rec))) = (sk.map(<[u8; 32]>::from_value), r.and_then(Fragment::read).map(|v| ct::StepRecord::from_value(&v))) else { continue };
            if rec.step.is_empty() {
                continue;
            }
            out.entry(sync_id).or_insert_with(|| ct::SyncEntry { steps: BTreeMap::new() }).steps.insert(id, rec);
        }
    }
    out
}

/// A step on a verified path from its sync ID's genesis step.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Placed {
    pub sync_id: SyncId,
    pub prev: Option<StepId>,
    pub sync: [u8; 32],
    pub write: [u8; 32],
    pub delete: [u8; 32],
    /// Steps from the genesis step, itself 0.
    pub depth: u32,
    /// The latest stamp among the writes recording it and its ancestors: from then on its path
    /// is recorded.
    pub since: Ts,
}

/// The placed steps of one thing's `sync.0` state.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Recorded {
    pub steps: BTreeMap<StepId, Placed>,
    /// Per (level, key), the earliest `since` of a step bearing it.
    keys: BTreeMap<(u8, [u8; 32]), Ts>,
}

/// The earliest write stamp at `path` in `f`, over every live record of each map key on the way:
/// when a write first put it. A step one promotion records and another records again
/// concurrently (the genesis step, spec/sync-ids.md §2) reads as the join of both writes, which
/// keeps the later stamp; it is recorded from the earlier (spec/crypto.md §7 Checked keys).
fn earliest_stamp(f: &Fragment, path: &[PathSeg]) -> Option<Ts> {
    use osis_crdt::{Encoding, SlotRef};
    let Some((seg, rest)) = path.split_first() else { return f.write_stamp().map(|s| s.ts) };
    match seg {
        PathSeg::Field(id) => match f.slot(Encoding::Struct) {
            Some(SlotRef::Frag(Fragment::Struct(st))) => earliest_stamp(st.field(*id)?, rest),
            _ => None,
        },
        PathSeg::Key(k) => match f.slot(Encoding::Map) {
            Some(SlotRef::Frag(Fragment::Map(m))) => m.live(k).into_iter().filter_map(|(_, r)| earliest_stamp(r, rest)).min(),
            _ => None,
        },
        _ => earliest_stamp(&f.at(std::slice::from_ref(seg))?, rest),
    }
}

impl Recorded {
    /// The steps `f`, a `sync.0` state, places. `before`: the thing's placed steps so far, whose
    /// signatures are not verified again (a step's ID commits to its bytes and its parent's ID).
    pub(crate) fn of(f: &Fragment, before: Option<&Recorded>) -> Recorded {
        let ids = f.read().and_then(|v| ct::SYNC.decode(&v).ok()).unwrap_or_default();
        let mut out = Recorded::default();
        for (sync_id, entry) in &ids {
            // the steps that parse under their own ID, with the stamp of the write recording each
            let mut steps: BTreeMap<StepId, (Step, Ts)> = BTreeMap::new();
            for (id, r) in &entry.steps {
                let Ok(s) = Step::parse(&r.step) else { continue };
                if s.id().0 != *id || s.sync_id != *sync_id {
                    continue;
                }
                let path = [PathSeg::Key(sync_id.to_value()), PathSeg::Field(0), PathSeg::Key(Value::Bytes(id.to_vec())), PathSeg::Field(0)];
                let Some(ts) = earliest_stamp(f, &path) else { continue };
                steps.insert(StepId(*id), (s, ts));
            }
            // from the genesis steps down, each child placed once its parent is
            let mut children: BTreeMap<StepId, Vec<StepId>> = BTreeMap::new();
            let mut todo: Vec<StepId> = Vec::new();
            for (id, (s, _)) in &steps {
                match s.prev {
                    Some(p) => children.entry(p).or_default().push(*id),
                    None => todo.push(*id),
                }
            }
            while let Some(id) = todo.pop() {
                let Some((s, ts)) = steps.get(&id) else { continue };
                let parent = s.prev.and_then(|p| Some((steps.get(&p)?, out.steps.get(&p)?)));
                let known = before.is_some_and(|b| b.steps.get(&id).is_some_and(|x| x.sync_id == *sync_id));
                let (depth, since) = match (s.prev, parent) {
                    (None, _) if known || s.verify_genesis().is_ok() => (0, *ts),
                    (Some(_), Some(((p, _), at))) if known || s.verify_child(p).is_ok() => (at.depth.saturating_add(1), (*ts).max(at.since)),
                    _ => continue,
                };
                let placed = Placed { sync_id: *sync_id, prev: s.prev, sync: s.keys.sync.to_bytes(), write: s.keys.write.to_bytes(), delete: s.keys.delete.to_bytes(), depth, since };
                for k in [(DELETE_ADMIN, placed.delete), (DELETE_WRITER, placed.write)] {
                    out.keys.entry(k).and_modify(|t| *t = (*t).min(since)).or_insert(since);
                }
                out.steps.insert(id, placed);
                todo.extend(children.remove(&id).unwrap_or_default());
            }
        }
        out
    }

    /// Whether a step bears `key` at `level` (1 its delete key, 3 its write key) with its path
    /// recorded before `ts`.
    pub(crate) fn places(&self, level: u8, key: &[u8; 32], ts: Ts) -> bool {
        self.keys.get(&(level, *key)).is_some_and(|since| *since < ts)
    }

    /// Whether a step is recorded before `ts`.
    fn any_before(&self, ts: Ts) -> bool {
        self.keys.values().any(|since| *since < ts)
    }

    /// Whether a step bears sync key `key`.
    pub(crate) fn bears_sync(&self, key: &[u8; 32]) -> bool {
        self.steps.values().any(|s| s.sync == *key)
    }

    /// Whether a step bears `key` at `level`, whenever recorded.
    pub(crate) fn bears(&self, level: u8, key: &[u8; 32]) -> bool {
        self.keys.contains_key(&(level, *key))
    }

    /// The newest step of sync ID `id`: the deepest, ties by lowest step ID (spec/sync-ids.md §3
    /// head, as `sync_ids::actors::head_of` reads a forked tree).
    fn head(&self, id: &SyncId) -> Option<(&StepId, &Placed)> {
        self.steps.iter().filter(|(_, s)| s.sync_id == *id).min_by_key(|(k, s)| (std::cmp::Reverse(s.depth), **k))
    }
}

impl Core {
    /// Keeps `Indexes::steps` at `t`'s `sync.0` state `f` (`Tx::derive`). Where the placed
    /// steps moved, every held part on a thing whose record chain holds `t` is judged again:
    /// the keys it lists are checked against them (`key_right`).
    pub(crate) fn steps_recorded(&mut self, t: &Tid, f: Option<&Fragment>) {
        let before = self.ix.steps.get(t).cloned();
        let after = f.map(|f| Recorded::of(f, before.as_deref())).filter(|r| !r.steps.is_empty());
        if before.as_deref() == after.as_ref() {
            return;
        }
        // keys only placed, or placed earlier: no key held as right turns wrong, but on a minting
        // of `t` read as recording its first steps (`first_steps`: a key-minted thing's chain is
        // itself alone), which a step placed before it turns to the check
        let grew = before.as_ref().is_none_or(|b| b.keys.iter().all(|(k, since)| after.as_ref().is_some_and(|a| a.keys.get(k).is_some_and(|s| s <= since))));
        match after {
            Some(r) => self.ix.steps.insert(*t, Arc::new(r)),
            None => self.ix.steps.remove(t),
        };
        // what pends on a key these steps may place is examined again (`Wake::Steps`)
        self.waits.steps_moved.insert(*t);
        let again: BTreeSet<CommitId> = match grew {
            // the usual move (a step issued): only a commit held as wrong may turn, O(those)
            true => self.ix.miskeyed.iter().filter(|(_, x)| self.record_chain(x).any(|s| s.thing() == Some(*t))).map(|(c, _)| *c).chain(self.mintings(t).map(|(c, _)| c)).collect(),
            // a `sync.0` write fell or went: every commit on a thing under `t`, O(those)
            false => self.ix.held.below(&BTreeSet::from([*t])).iter().flat_map(|x| self.on_thing(x)).collect(),
        };
        for c in again {
            self.rekey(&c);
        }
    }

    /// The things for which header `h` lists a wrong key: each with a delta listing a level-1 or
    /// level-3 key that is not right (`key_right`). Level 2 is not checked (spec/crypto.md §7).
    /// A thing whose record chain is not known up to its top here is not judged: nothing
    /// written on it applies meanwhile (spec/commits.md §4 Unjudgeable), and a commit judged on
    /// missing evidence is never judged invalid for it. Nor is a thing whose first steps the
    /// commit records itself (`first_steps`).
    pub(crate) fn wrong_keys(&self, h: &Header) -> BTreeSet<Tid> {
        // a commit's deltas mostly share a thing and its keys: each (thing, key) checked once
        let mut seen: BTreeSet<(Tid, usize)> = BTreeSet::new();
        let mut out = BTreeSet::new();
        for a in &h.aspects {
            if out.contains(&a.tid) || self.first_steps(h, &a.tid) {
                continue;
            }
            let wrong = a.keys.iter().filter(|k| seen.insert((a.tid, **k))).filter_map(|k| h.keys.get(*k)).any(|k| k.level != DELETE_AUTHOR && !self.key_right(&a.tid, k.level, &k.key, h.ts));
            if wrong && matches!(self.record_chain(&a.tid).end(), osis_base::ChainStep::Key(_)) {
                out.insert(a.tid);
            }
        }
        out
    }

    /// Whether `h` records `t`'s first steps (spec/crypto.md §7 Checked keys, First steps): no
    /// step on `t`'s record chain is recorded before it, and it is `t`'s minting by its record's
    /// key (it carries `t`'s `created.0`, `t`'s record holds a key, and it is signed by that key
    /// as `t`). It lists the keys of the first step (the genesis step's child) its own `sync.0`
    /// delta records, which nothing before it places.
    ///
    /// Invariant: a key so taken is one `t`'s admin from the start listed. Only the record's key
    /// signs as `t` in the first form, and before any step is recorded nothing ordered before the
    /// commit can have lowered it (every edge write on `t` is its admin's, after its minting).
    /// A later commit of that key, once lowered, carrying `created.0` again is checked as any:
    /// the steps recorded before it place its keys or it is unjudgeable.
    fn first_steps(&self, h: &Header, t: &Tid) -> bool {
        h.signer == *t
            && h.key.is_none()
            && h.aspects.iter().any(|x| x.tid == *t && x.ak.as_str() == osis_commit::retention::CREATED)
            && self.created(t).is_some_and(|r| r.key().is_some())
            && !self.record_chain(t).filter_map(|s| s.thing()).any(|x| self.ix.steps.get(&x).is_some_and(|r| r.any_before(h.ts)))
    }

    /// What the key check reads of header `h`, for a failing check's message: per delta listing
    /// a level-1 or level-3 key, its thing, the level, and the base bearing the key.
    pub(crate) fn explain_keys(&self, h: &Header) -> String {
        let per = |a: &osis_commit::AspectEntry| {
            let keys: Vec<String> = a.keys.iter().filter_map(|k| h.keys.get(*k)).filter(|k| k.level != DELETE_AUTHOR).map(|k| format!("{}:{:?}", k.level, self.key_base(&a.tid, k.level, &k.key, Some(h.ts)))).collect();
            let chain: Vec<String> = self.record_chain(&a.tid).map(|s| format!("{s:?} steps {:?} independent {}", s.thing().and_then(|t| self.ix.steps.get(&t).map(|r| r.steps.values().map(|p| p.since).collect::<Vec<_>>())), s.thing().is_some_and(|t| self.ix.independent.contains(&t)))).collect();
            format!("{} {} [{}] chain {chain:?}", a.tid, a.ak.as_str(), keys.join(" "))
        };
        h.aspects.iter().map(per).collect::<Vec<_>>().join("; ")
    }

    /// Whether commit `id` lists a wrong key for `t`, as verdicts read it.
    pub(crate) fn miskeyed(&self, id: &CommitId, t: &Tid) -> bool {
        self.ix.miskeyed.contains(&(*id, *t))
    }

    /// Takes the key verdict of commit `id` about to apply, header `h` (`Indexes::miskeyed`).
    pub(crate) fn note_keys_of(&mut self, id: &CommitId, h: &Header) {
        let wrong = self.wrong_keys(h);
        for a in &h.aspects {
            match wrong.contains(&a.tid) {
                true => self.ix.miskeyed.insert((*id, a.tid)),
                false => self.ix.miskeyed.remove(&(*id, a.tid)),
            };
        }
    }

    /// Judges held commit `id`'s listed keys again. Where the verdict moved the commit is judged
    /// again whole, and a role commit's edge writes are read again (`Indexes::rekeyed`).
    pub(crate) fn rekey(&mut self, id: &CommitId) {
        let Some(m) = self.ix.commits.get(id) else { return };
        let h = m.header.clone();
        let role = m.view.kind.is_role();
        let wrong = self.wrong_keys(&h);
        if h.aspects.iter().all(|a| self.ix.miskeyed.contains(&(*id, a.tid)) == wrong.contains(&a.tid)) {
            return;
        }
        self.note_keys_of(id, &h);
        self.stale_commits.insert(*id);
        if role {
            self.ix.rekeyed.insert(*id);
        }
    }

    /// The step whose keys a write lists for delete base `b` (spec/crypto.md §7 Header list): the
    /// newest step of `b`'s sync ID (spec/sync-ids.md §4 Owner, `Core::named_sync_id`) its
    /// `sync.0` records here. `None`: none recorded, and this node cannot write under `b`.
    pub(crate) fn listed_step(&self, b: &Tid) -> Option<Placed> {
        let (id, _) = self.named_sync_id(b).flatten()?;
        self.ix.steps.get(b)?.head(&id).map(|(_, s)| s.clone())
    }

    /// The admin and write delete keys of `listed_step(b)`, parsed (`memo`: every write on a
    /// thing of `b` lists them).
    pub(crate) fn listed_keys(&self, b: &Tid) -> Option<[Option<osis_crypto::VerifyingKey>; 2]> {
        self.listed_keys.get(b, || self.listed_step(b).map(|s| [&s.delete, &s.write].map(|k| osis_crypto::VerifyingKey::from_slice(k).ok())))
    }

    /// Whether `key`, listed at level 1 or 3 by a commit stamped `ts` for a delta on `t`, is
    /// right (spec/crypto.md §7 Checked keys): a thing on `t`'s record chain, itself first,
    /// places it before `ts` (`Recorded::places`).
    ///
    /// Any base up the chain, not the nearest alone: a write made while `t` derived its secrets
    /// lists its former base's step, and so does a writer that has not yet received the commit
    /// making `t` independent; no header says which the writer knew. A key so accepted is
    /// still one only an admin (level 1) or writer (level 3) of a thing up `t`'s record chain held.
    pub(crate) fn key_right(&self, t: &Tid, level: u8, key: &[u8; 32], ts: Ts) -> bool {
        self.key_base(t, level, key, Some(ts)).is_some()
    }

    /// The thing on `t`'s record chain whose steps bear `key` at `level` (recorded before `ts`,
    /// when given).
    pub(crate) fn key_base(&self, t: &Tid, level: u8, key: &[u8; 32], ts: Option<Ts>) -> Option<Tid> {
        for step in self.record_chain(t) {
            let cur = step.thing()?;
            if let Some(r) = self.ix.steps.get(&cur)
                && ts.map_or_else(|| r.bears(level, key), |ts| r.places(level, key, ts))
            {
                return Some(cur);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::Mutation;
    use crate::local_peer::LocalPeer;
    use osis_base::{Role, WallMs};

    /// Alice's thing `g`, made independent with its sync ID by a grant to bob, and `t`
    /// minted with admin `g` (dependent: `g` is its delete base).
    fn world() -> (LocalPeer, Tid, Tid) {
        let mut lp = LocalPeer::fresh(2, WallMs(1_700_000_000_000));
        lp.sync_all().unwrap();
        let (alice, bob) = (lp.peers[0].engine.tid(), lp.peers[1].engine.tid());
        let mut m = Mutation::new();
        let g = lp.peers[0].engine.new_thing(&mut m, alice);
        lp.peers[0].commit(m).unwrap();
        lp.hold(g);
        lp.peers[0].engine.grant(&g, &bob, &ct::Edge { role: Role::Write, until: None, may_grant: false, retain: false, floor: None }).unwrap();
        let mut m = Mutation::new();
        let t = lp.peers[0].engine.new_thing(&mut m, g);
        lp.peers[0].commit(m).unwrap();
        lp.hold(t);
        lp.sync_all().unwrap();
        (lp, g, t)
    }

    // spec/crypto.md §7 (Header list; Checked keys), spec/sync-ids.md §2: a write lists the
    // delete and write keys of the newest step its base's `sync.0` records, which are the step
    // keys of the base's admin and write secrets; a reader takes a key as right only from the
    // stamp its step is recorded at, for a thing whose record chain holds the base, at its own
    // level; a writer holding no admin secret lists the same level-1 key.
    #[test]
    fn a_write_lists_its_bases_newest_step_and_a_reader_places_it_spec_crypto_7() {
        let (lp, g, t) = world();
        for p in &lp.peers {
            let core = &p.engine.core;
            let s = core.listed_step(&g).expect("g's sync.0 records its genesis step and the first");
            assert_eq!(s.depth, 1);
            let r = core.ix.steps.get(&g).unwrap();
            for (level, key) in [(DELETE_ADMIN, s.delete), (DELETE_WRITER, s.write)] {
                assert!(core.key_right(&t, level, &key, Ts::MAX), "a thing under g lists g's step");
                assert!(core.key_right(&g, level, &key, Ts::MAX));
                assert!(!core.key_right(&t, level, &key, s.since), "not before the write recording the step");
                assert!(r.places(level, &key, Ts::MAX) && !r.places(level, &key, s.since));
                assert_eq!(core.key_base(&t, level, &key, None), Some(g));
            }
            // each key at its own level alone, and no other key
            assert!(!core.key_right(&t, DELETE_ADMIN, &s.write, Ts::MAX) && !core.key_right(&t, DELETE_WRITER, &s.delete, Ts::MAX));
            assert!(!core.key_right(&t, DELETE_ADMIN, &[7; 32], Ts::MAX));
            // a thing not under g finds nothing in g's steps
            let me = core.tid();
            assert!(!core.key_right(&me, DELETE_ADMIN, &s.delete, Ts::MAX));
        }
        // the step keys are the role keys of g's secrets (alice holds admin; bob, a writer, the
        // write secret alone)
        let s = lp.peers[0].engine.core.listed_step(&g).unwrap();
        let e = lp.peers[0].engine.core.epochs(&g).unwrap();
        assert_eq!(s.delete, osis_crypto::DeleteSecret::admin(e.admin.newest_held().unwrap().1).verifying_key().to_bytes());
        assert_eq!(s.write, osis_crypto::DeleteSecret::write(e.write.newest_held().unwrap().1).verifying_key().to_bytes());
        assert_eq!(lp.peers[1].engine.core.listed_step(&g), Some(s), "bob lists the same step");
        assert!(lp.peers[1].engine.core.epochs(&g).unwrap().admin.newest_held().is_none());
    }

    // spec/crypto.md §7 (Checked keys): the commits a node writes by the flow list right keys
    // wherever they are held (`Indexes::miskeyed` empty), and a header listing another key for
    // a thing is wrong for that thing alone.
    #[test]
    fn written_commits_list_right_keys_and_a_made_up_key_is_wrong_for_its_thing_spec_crypto_7() {
        let (mut lp, _, t) = world();
        let x = osis_base::Ak::new("x:v.0").unwrap();
        let mut m = Mutation::new();
        m.set(t, &x, &osis_base::Value::Int(1)).unwrap();
        let c = lp.peers[1].commit(m).unwrap().unwrap();
        lp.sync_all().unwrap();
        for p in &lp.peers {
            assert!(p.engine.core.ix.miskeyed.is_empty(), "{:?}", p.engine.core.ix.miskeyed);
        }
        let core = &lp.peers[0].engine.core;
        let mut h = (*core.ix.commits.get(&c).unwrap().header).clone();
        assert!(core.wrong_keys(&h).is_empty());
        let listed = h.keys.iter().position(|k| k.level != DELETE_AUTHOR).unwrap();
        h.keys[listed].key = [7; 32];
        assert_eq!(core.wrong_keys(&h), BTreeSet::from([t]));
    }

    // spec/crypto.md §7 (Checked keys; First steps): a thing minted with a key lists, in its
    // minting, keys no step recorded before places, and they count there alone: the same header
    // after a step is recorded (a re-minting by its key, which may since be lowered), or signed
    // by another key, is checked as any, and a key no step places is wrong.
    #[test]
    fn only_a_things_first_steps_are_listed_unchecked_spec_crypto_7() {
        let (lp, _, _) = world();
        let core = &lp.peers[0].engine.core;
        let n = core.tid();
        assert!(core.created(&n).is_some_and(|r| r.key().is_some()), "the node thing is minted with a key");
        let (c, _) = core.mintings(&n).next().unwrap();
        let minting = (*core.ix.commits.get(&c).unwrap().header).clone();
        assert!(core.wrong_keys(&minting).is_empty(), "its minting lists its first steps' keys");
        let listed = minting.keys.iter().position(|k| k.level != DELETE_AUTHOR).unwrap();
        let since = core.ix.steps.get(&n).unwrap().steps.values().map(|s| s.since).min().unwrap();
        assert_eq!(since, minting.ts, "its minting records its first step");
        let mut later = minting.clone();
        later.ts = Ts::from_u64(minting.ts.to_u64() + 1).unwrap();
        assert!(core.wrong_keys(&later).is_empty(), "the keys it lists are placed before a later one");
        later.keys[listed].key = [7; 32];
        assert_eq!(core.wrong_keys(&later), BTreeSet::from([n]), "a re-minting after a step is checked");
        let mut other = minting.clone();
        other.keys[listed].key = [7; 32];
        assert!(core.wrong_keys(&other).is_empty(), "before any step, the record's key lists unchecked");
        other.key = Some(osis_base::SignKey([3; 32]));
        assert_eq!(core.wrong_keys(&other), BTreeSet::from([n]), "another key signing as n is checked");
    }

    // spec/crypto.md §7 (Header list; Checked keys): a may-grant writer's grant lists the step
    // keys of g's `sync.0`, right everywhere; listing instead a key of its own (the step's write
    // key at the admin level, or a key its write secret derives for that level) is wrong for g.
    #[test]
    fn a_may_grant_writers_grant_listing_its_own_key_is_wrong_spec_crypto_7() {
        let (mut lp, g, _) = world();
        let bob = lp.peers[1].engine.tid();
        lp.peers[0].engine.grant(&g, &bob, &ct::Edge { role: Role::Write, until: None, may_grant: true, retain: false, floor: None }).unwrap();
        lp.sync_all().unwrap();
        let mut m = Mutation::new();
        let to = lp.peers[1].engine.new_thing(&mut m, bob);
        lp.peers[1].commit(m).unwrap();
        let before = lp.commit_ids(1);
        lp.peers[1].engine.grant(&g, &to, &ct::Edge { role: Role::Read, until: None, may_grant: false, retain: false, floor: None }).unwrap();
        lp.sync_all().unwrap();
        let roles = osis_base::Ak::new("roles.0").unwrap();
        let core = &lp.peers[0].engine.core;
        let c = *lp.commit_ids(1).difference(&before).find(|c| core.ix.commits.get(c).is_some_and(|m| m.header.aspects.iter().any(|a| a.tid == g && a.ak == roles))).expect("the grant");
        for p in &lp.peers {
            assert!(p.engine.core.ix.miskeyed.is_empty(), "the flow's grant lists right keys");
        }
        let core = &lp.peers[0].engine.core;
        let h = (*core.ix.commits.get(&c).unwrap().header).clone();
        let s = core.listed_step(&g).unwrap();
        let write = lp.peers[1].engine.core.epochs(&g).unwrap().write.newest_held().unwrap().1.clone();
        assert!(lp.peers[1].engine.core.epochs(&g).unwrap().admin.newest_held().is_none(), "bob holds no admin secret");
        let own = [s.write, osis_crypto::DeleteSecret::admin(&write).verifying_key().to_bytes()];
        let on_g = h.aspects.iter().find(|a| a.tid == g).expect("the grant writes g");
        let at = on_g.keys.iter().copied().find(|k| h.keys[*k].level == DELETE_ADMIN).expect("its edge write lists the admin level");
        for key in own {
            let mut forged = h.clone();
            forged.keys[at].key = key;
            assert_eq!(core.wrong_keys(&forged), BTreeSet::from([g]), "bob's own key at the admin level");
        }
    }

    // spec/crypto.md §7 (Checked keys), spec/commits.md §4 (Unjudgeable): a write listing a step
    // a reader does not hold pends there, and applies once the `sync.0` write recording the step
    // arrives after it (`Wake::Steps`). Alice rotates g's admin and issues the step registering it, then
    // writes under it; bob's node gets the rotation, her write, and only then the step.
    #[test]
    fn a_write_applies_once_the_step_it_lists_arrives_after_it_spec_crypto_7() {
        let (mut lp, g, _) = world();
        let x = osis_base::Ak::new("x:v.0").unwrap();
        let sync_id = lp.peers[0].engine.core.listed_step(&g).unwrap().sync_id;
        let rot = lp.peers[0].engine.rotate_leaving_out(&g, &[Role::Admin], &[]).unwrap().expect("rotated");
        lp.advance(1_000);
        let before = lp.commit_ids(0);
        lp.peers[0].engine.issue_step(&g, &sync_id).unwrap().expect("the step is due");
        let step = *lp.commit_ids(0).difference(&before).next().expect("the step's commit");
        lp.advance(1_000);
        let mut m = Mutation::new();
        m.set(g, &x, &osis_base::Value::Int(1)).unwrap();
        let c = lp.peers[0].commit(m).unwrap().unwrap();
        let listed = lp.peers[0].engine.core.listed_step(&g).unwrap();
        for id in [rot, c] {
            let pk = lp.peers[0].engine.package(&id).unwrap().unwrap();
            lp.deliver(1, &pk).unwrap();
        }
        let e = &mut lp.peers[1].engine;
        assert!(!e.core.ix.steps.get(&g).unwrap().bears(DELETE_ADMIN, &listed.delete), "bob holds no step bearing the key");
        assert!(e.pends(&c) && !e.holds_commit(&c), "unjudgeable while the step is not here: it pends");
        assert_ne!(e.get(&g, &x).unwrap(), Some(osis_base::Value::Int(1)));
        let pk = lp.peers[0].engine.package(&step).unwrap().unwrap();
        lp.deliver(1, &pk).unwrap();
        let e = &mut lp.peers[1].engine;
        assert!(e.holds_commit(&c) && !e.core.miskeyed(&c, &g), "right once the step is recorded");
        assert_eq!(e.get(&g, &x).unwrap(), Some(osis_base::Value::Int(1)));
    }

    // spec/commits.md §4 (Unjudgeable; Apply: a waiting part waits alone), spec/crypto.md §7
    // (Checked keys: the commit's deltas on other things are judged by their own keys): a commit
    // whose part on g lists a step bob does not hold yet applies its part on h, under a base bob
    // holds the steps of; the part on g waits, the commit pending for it, and applies once the
    // step arrives (`Wake::Steps` of an applied commit's waiting part), with no wake left for a
    // full scan, and bob opened again reads the same.
    #[test]
    fn a_part_listing_a_step_not_here_waits_alone_spec_commits_4() {
        let (mut lp, g, _) = world();
        let (alice, bob) = (lp.peers[0].engine.tid(), lp.peers[1].engine.tid());
        let mut m = Mutation::new();
        let h = lp.peers[0].engine.new_thing(&mut m, alice);
        lp.peers[0].commit(m).unwrap();
        lp.hold(h);
        lp.peers[0].engine.grant(&h, &bob, &ct::Edge { role: Role::Read, until: None, may_grant: false, retain: false, floor: None }).unwrap();
        lp.sync_all().unwrap();
        let x = osis_base::Ak::new("x:v.0").unwrap();
        let sync_id = lp.peers[0].engine.core.listed_step(&g).unwrap().sync_id;
        let rot = lp.peers[0].engine.rotate_leaving_out(&g, &[Role::Admin], &[]).unwrap().expect("rotated");
        lp.advance(1_000);
        let before = lp.commit_ids(0);
        lp.peers[0].engine.issue_step(&g, &sync_id).unwrap().expect("the step is due");
        let step = *lp.commit_ids(0).difference(&before).next().expect("the step's commit");
        lp.advance(1_000);
        let mut m = Mutation::new();
        m.set(g, &x, &osis_base::Value::Int(1)).unwrap();
        m.set(h, &x, &osis_base::Value::Int(2)).unwrap();
        let c = lp.peers[0].commit(m).unwrap().unwrap();
        for id in [rot, c] {
            let pk = lp.peers[0].engine.package(&id).unwrap().unwrap();
            lp.deliver(1, &pk).unwrap();
        }
        let e = &mut lp.peers[1].engine;
        assert!(e.holds_commit(&c) && e.pends(&c), "applied, its part on g waiting");
        assert_eq!(e.get(&h, &x).unwrap(), Some(osis_base::Value::Int(2)), "the part on h is judged by h's keys");
        assert_ne!(e.get(&g, &x).unwrap(), Some(osis_base::Value::Int(1)));
        let pk = lp.peers[0].engine.package(&step).unwrap().unwrap();
        lp.deliver(1, &pk).unwrap();
        let e = &mut lp.peers[1].engine;
        assert_eq!(e.get(&g, &x).unwrap(), Some(osis_base::Value::Int(1)), "applies once the step is recorded");
        assert!(!e.pends(&c) && !e.core.miskeyed(&c, &g));
        assert_eq!(e.lost_wakes().unwrap(), Vec::new());
        lp.peers[1].restart(7).unwrap();
        let e = &mut lp.peers[1].engine;
        assert_eq!((e.get(&g, &x).unwrap(), e.get(&h, &x).unwrap()), (Some(osis_base::Value::Int(1)), Some(osis_base::Value::Int(2))), "opened again alike");
        assert!(!e.pends(&c));
    }
}
