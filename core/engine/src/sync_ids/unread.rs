//! What a node keeping a thing unread holds of it (spec/sync.md §3 Kept unread, Kept sync IDs):
//! its sync secrets and the sync IDs it keeps for it, with their steps, and nothing else (no
//! roster, chain, `keys.0` or commit). Filled from the sync copies it takes (spec/wire.md §4
//! `SyncCopyPlaintext`: a holder's `secrets.0` piece and the `sync.0` delta, no header) and, for a
//! node that holds role commits of the thing too (a lowering from read, a certificate copy under
//! another sync ID), from what those gave (`Indexes::secrets`, `Indexes::steps`). One derivation
//! (`Core::unread`) over what is held, live and at an open alike: the copies are rows, read again
//! by `load`.
//!
//! Invariant (security; spec/sync.md §3 "only a step on the node's own path bearing the sync key
//! of a held secret keeps S's entries"): a sync copy is anyone's word who may log under its
//! holder's sync ID (a writer of the holder, or a depositor) or seal to its holder's read key, and
//! is judged by nothing but its bytes: a box keyed with another holder, or a history entry, makes
//! it bad input (`parse`); a secret it gives is kept only where a step on a path verified from its
//! sync ID's genesis (each step signed by its parent's delete key, the genesis by its own, whose
//! delete key the sync ID commits to) bears the secret's sync key: the thing's `sync.0` state as
//! judged (an admin's word), and the copies' own steps only where the node holds no record of the
//! thing (a genesis is anyone's making: with the record, a copy's step would make a dependent
//! thing count independent, or put a forged sync ID in a reader's place), for what the walk and
//! ownership read (`Unread::secrets`), the steps
//! registered with this node for what it shows at peers (`Unread::candidates`, judged by
//! osis-sync's unread judgement against its stored path). A forger may still make a sync
//! ID of its own (its own genesis, its own secret): that one is kept beside the real one and never
//! displaces it (a node keeping a thing unread syncs every sync ID it keeps for it,
//! `Engine::thing_sync_now`), costing only what its deposit budget lets it log.

use crate::engine::{Core, Tx};
use crate::error::{Error, Result};
use osis_base::{BlobId, CommitId, Role, Tid};
use osis_crypto::{Epoch, Secret32};
use osis_schema::core_types as ct;
use osis_schema::core_types::{BoxKey, SecretBox};
use osis_schema::RawKey;
use osis_store::Shred;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// `su/` + thing + blob ID: a sync copy taken here (`HeldSyncCopy`): its holder (15 bytes), then
/// its `SyncCopyPlaintext` bytes.
pub(crate) const SYNC_COPIES: &[u8] = b"su/";

/// A sync copy as taken here: the holder whose copy it is (the thing whose sync ID it came under,
/// or that it was sealed to), the copy, and what its deltas say: its boxes and its steps.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeldSyncCopy {
    pub holder: Tid,
    pub copy: osis_commit::SyncCopy,
    pub boxes: BTreeMap<BoxKey, SecretBox>,
    pub steps: ct::SyncIds,
}

/// Per thing, the sync copies on it taken here, by blob.
pub type SyncCopies = BTreeMap<BlobId, Arc<HeldSyncCopy>>;

/// A delta of a sync copy read without its header: its values alone (its stamps are no one's:
/// nothing of it applies, spec/wire.md §4). Pages are bad input (a holder's piece and a
/// `sync.0` delta fit a blob).
fn read_headerless(bytes: &[u8], commit: &CommitId) -> Option<osis_crdt::Fragment> {
    let mut interner = osis_crdt::Interner::new();
    let own = interner.commit(*commit);
    let cx = osis_crdt::DeltaCtx { ts: osis_base::Ts::default(), own, range: osis_crdt::CounterRange { lo: 0, hi: u64::MAX }, kind: osis_crdt::DeltaKind::Writer };
    osis_crdt::decode_delta(bytes, &cx, &mut interner, None).ok().map(|d| d.fragment)
}

/// Reads sync copy `plain` as `holder`'s: `None` when it is bad input (spec/wire.md §4: not a
/// sync copy; its piece holding a record keyed with another holder, or one keyed with none: a
/// history box, a removal of another's; a delta that does not decode).
pub(crate) fn parse(holder: Tid, plain: &[u8]) -> Option<HeldSyncCopy> {
    let copy = osis_commit::SyncCopy::decode(plain).ok().filter(|c| c.thing != holder)?;
    let mut boxes = BTreeMap::new();
    if let Some(p) = &copy.piece {
        let w = crate::apply::keys::secrets_write(&read_headerless(p, &copy.commit)?);
        if !w.history.is_empty() || w.boxes.keys().chain(&w.removed).any(|k| k.holder.0 != holder) {
            return None;
        }
        boxes = w.boxes;
    }
    let steps = match &copy.sync {
        Some(s) => ct::SYNC.decode(&read_headerless(s, &copy.commit)?.read()?).ok()?,
        None => ct::SyncIds::default(),
    };
    Some(HeldSyncCopy { holder, copy, boxes, steps })
}

/// Loads the sync copies taken (an open or reload).
pub(crate) fn load(tx: &mut Tx<'_>) -> Result<()> {
    let bad = || Error::Corrupt("sync copy row");
    let mut rows: BTreeMap<Tid, SyncCopies> = BTreeMap::new();
    tx.scan(SYNC_COPIES, |k, v| {
        let t = Tid::from_bytes(k.get(..15).ok_or_else(bad)?.try_into().map_err(|_| bad())?);
        let b = BlobId(k.get(15..).ok_or_else(bad)?.try_into().map_err(|_| bad())?);
        let (h, plain) = v.split_at_checked(15).ok_or_else(bad)?;
        let c = parse(Tid::from_bytes(h.try_into().map_err(|_| bad())?), plain).ok_or_else(bad)?;
        rows.entry(t).or_default().insert(b, Arc::new(c));
        Ok(())
    })?;
    for (t, m) in rows {
        tx.core.ix.sync_copies.insert(t, Arc::new(m));
    }
    Ok(())
}

/// Takes sync copy `c`, blob `b` (one taken already changes nothing).
pub(crate) fn note(tx: &mut Tx<'_>, b: &BlobId, c: HeldSyncCopy) -> Result<()> {
    let t = c.copy.thing;
    let mut m = tx.core.ix.sync_copies.get(&t).map(|x| (**x).clone()).unwrap_or_default();
    if m.contains_key(b) {
        return Ok(());
    }
    tx.txn.put_local(&[SYNC_COPIES, t.as_bytes(), &b.0].concat(), &[c.holder.as_bytes().as_slice(), &c.copy.encode()].concat(), Shred::No)?;
    m.insert(*b, Arc::new(c));
    tx.core.ix.sync_copies.insert(t, Arc::new(m));
    Ok(())
}

/// The sync copies on `t` go (it is forgotten whole).
pub(crate) fn forget(tx: &mut Tx<'_>, t: &Tid) -> Result<()> {
    let Some(m) = tx.core.ix.sync_copies.get(t).cloned() else { return Ok(()) };
    for b in m.keys() {
        tx.txn.remove_local(&[SYNC_COPIES, t.as_bytes(), &b.0].concat(), Shred::No)?;
    }
    tx.core.ix.sync_copies.remove(t);
    Ok(())
}

/// What this node keeps of thing `t` unread (spec/sync.md §3): the sync secrets it holds that a
/// step bears, the steps its sync copies carry, and which copies count (spec/permissions.md §4
/// Logging certificates: a sync copy counts once its box opens to a secret whose sync key a step
/// bears, or, boxing nothing, once each step it carries verifies from its sync ID's genesis).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Unread {
    /// The secrets held that a step of the thing's `sync.0` state bears, or, with no record of
    /// the thing held, a step of the copies'.
    pub secrets: BTreeMap<Epoch, Secret32>,
    /// Every sync secret held of the thing (`secrets` and those no such step bears yet): what
    /// is judged against the steps registered with this node (its stored path, osis-sync's;
    /// spec/crypto.md §4 Established: a step of its stored path bearing the secret's sync key).
    pub candidates: BTreeMap<Epoch, Secret32>,
    /// The steps of every sync copy on `t`, joined, where no record of `t` is held (else none):
    /// what `owned_sync_ids` judges.
    pub steps: ct::SyncIds,
    pub counted: BTreeSet<BlobId>,
    /// The holders of counted copies: things holding sync or above on `t` as this node knows it
    /// from them (`stubs_of`).
    pub holders: BTreeSet<Tid>,
}

impl Unread {
    pub(crate) fn holds_any(&self) -> bool {
        !self.secrets.is_empty()
    }
}

/// A sync copy's blob, holder and the sync secrets its box gave.
type Given = (BlobId, Tid, Vec<(Epoch, Secret32)>);

/// The sync key of sync secret `s` (spec/sync-ids.md §2).
pub(crate) fn sync_key(s: &Secret32) -> [u8; 32] {
    osis_crypto::role_key(osis_crypto::RoleKey::Sync, s).verifying_key().to_bytes()
}

/// The sync keys of the steps of `steps` on a path verified from their sync ID's genesis.
fn borne(steps: &ct::SyncIds) -> BTreeSet<[u8; 32]> {
    let mut out = BTreeSet::new();
    for (id, e) in steps {
        let Ok(st) = osis_blob::sync_steps(e) else { continue };
        let plain: BTreeMap<osis_blob::StepId, osis_blob::Step> = st.iter().map(|(k, (s, _))| (*k, s.clone())).collect();
        for (k, (s, _)) in &st {
            if osis_blob::path_to(&plain, k).is_ok_and(|p| p.first().is_some_and(|g| g.sync_id == *id)) {
                out.insert(s.keys.sync.to_bytes());
            }
        }
    }
    out
}

/// The verified step IDs of `steps` per sync ID (`borne`'s paths).
fn verified(steps: &ct::SyncIds) -> BTreeSet<[u8; 32]> {
    let mut out = BTreeSet::new();
    for (id, e) in steps {
        let Ok(st) = osis_blob::sync_steps(e) else { continue };
        let plain: BTreeMap<osis_blob::StepId, osis_blob::Step> = st.iter().map(|(k, (s, _))| (*k, s.clone())).collect();
        out.extend(st.keys().filter(|k| osis_blob::path_to(&plain, k).is_ok_and(|p| p.first().is_some_and(|g| g.sync_id == *id))).map(|k| k.0));
    }
    out
}

/// `a` joined with `b`: per sync ID, the step records of both (one per step ID: its bytes
/// commit to it, `sync_steps` checks).
fn join_steps(a: &mut ct::SyncIds, b: &ct::SyncIds) {
    for (id, e) in b {
        let at = a.entry(*id).or_insert_with(|| ct::SyncEntry { steps: BTreeMap::new() });
        for (k, r) in &e.steps {
            at.steps.entry(*k).or_insert_with(|| r.clone());
        }
    }
}

impl Core {
    /// `t` as this node keeps it unread (`Unread`; `memo`: every walk entering `t` and every
    /// sync ID judgement of it asks).
    pub(crate) fn unread(&self, t: &Tid) -> Arc<Unread> {
        self.unread_of.get(t, || Arc::new(self.unread_derived(t)))
    }

    fn unread_derived(&self, t: &Tid) -> Unread {
        let mut out = Unread::default();
        let copies = self.ix.sync_copies.get(t).cloned().unwrap_or_default();
        // a copy's own steps verify only to a genesis of anyone's making: they speak for `t` only
        // where this node holds no record of it, having nothing else to judge by. With its record,
        // `t`'s steps are its admins' word alone (`Indexes::steps`, from `sync.0` as judged), so a
        // forged genesis neither makes a dependent thing independent nor gives a reader of `t` a
        // sync ID in place of its own (`tests_delivery::a_forged_*`)
        let unknown = self.created(t).is_none();
        // what each copy's box gives, opened by its holder's keys held here
        let mut given: Vec<Given> = Vec::new();
        for (b, c) in copies.iter() {
            if unknown {
                join_steps(&mut out.steps, &c.steps);
            }
            let mut opened = Vec::new();
            if !c.boxes.is_empty()
                // the holder's own secrets as held (an independent thing: its keysets are its
                // own), never a derivation that could ask this thing again
                && let Some(e) = self.ix.secrets.get(&c.holder)
            {
                let s = ct::Secrets { boxes: c.boxes.clone(), history: BTreeMap::new() };
                let (o, _) = osis_keys::open_boxes(t, &s, &osis_keys::Opener { holder: c.holder, epochs: e });
                opened.extend(o.into_iter().filter(|o| o.role == Role::Sync).map(|o| (o.epoch, o.secret)));
            }
            given.push((*b, c.holder, opened));
        }
        // what role commits gave (a box applied, a lowering, an entry box), where they make `t`
        // independent here (`own_record`: a held keyset part decides), judged alike
        let mut candidates: BTreeMap<Epoch, Secret32> = self.own_record(t).map(|e| e.role(Role::Sync).held().map(|(e, s)| (e, s.clone())).collect()).unwrap_or_default();
        for (_, _, o) in &given {
            candidates.extend(o.iter().cloned());
        }
        let bearing = borne(&out.steps);
        let recorded = self.ix.steps.get(t);
        let bears = |s: &Secret32| {
            let k = sync_key(s);
            bearing.contains(&k) || recorded.as_ref().is_some_and(|r| r.bears_sync(&k))
        };
        out.secrets = candidates.iter().filter(|(_, s)| bears(s)).map(|(e, s)| (*e, s.clone())).collect();
        out.candidates = candidates;
        let ok = match unknown {
            true => verified(&out.steps),
            false => recorded.iter().flat_map(|r| r.steps.keys().map(|k| k.0)).collect(),
        };
        for (b, h, o) in given {
            let c = copies.get(&b);
            let boxes = c.is_some_and(|c| !c.boxes.is_empty());
            let counts = match boxes {
                true => o.iter().any(|(e, _)| out.secrets.contains_key(e)),
                // boxing nothing: each step it carries verified (with `t`'s record, placed)
                false => c.is_some_and(|c| !c.steps.is_empty() && c.steps.values().all(|e| e.steps.keys().all(|k| ok.contains(k)))),
            };
            if counts {
                out.counted.insert(b);
                out.holders.insert(h);
            }
        }
        out
    }
}

impl crate::engine::Engine {
    /// Holder `h`'s sync copy of held commit `c` on `x` (spec/wire.md §4; spec/permissions.md §4
    /// Key part: where `h` holds sync alone on `x`): `h`'s `secrets.0` piece and the `sync.0`
    /// delta, each as held, with the part indices they are (what its prefix commits to, spec/wire.md
    /// §5). `None` where `c` is not held or holds neither for `h`.
    pub(crate) fn sync_copy(&mut self, c: &CommitId, x: &Tid, h: &Tid) -> Result<Option<(osis_commit::SyncCopy, Vec<usize>)>> {
        let id = *c;
        let Some(full) = self.read(|tx| tx.get_commit(&id))? else { return Ok(None) };
        let on = BTreeSet::from([*x]);
        let named = self.holders_named(c);
        let piece = self.parts_of(c, &on, &["secrets.0"]).into_iter().find(|ai| named.get(ai).is_some_and(|hs| hs.len() == 1 && hs.contains(h)));
        let sync = self.parts_of(c, &on, &["sync.0"]).into_iter().next();
        let delta = |ai: Option<usize>| ai.and_then(|ai| full.part(ai)).map(|p| p.delta.clone());
        let copy = osis_commit::SyncCopy { commit: id, thing: *x, piece: delta(piece), sync: delta(sync) };
        if copy.piece.is_none() && copy.sync.is_none() {
            return Ok(None);
        }
        let ais = [piece.filter(|_| copy.piece.is_some()), sync.filter(|_| copy.sync.is_some())].into_iter().flatten().collect();
        Ok(Some((copy, ais)))
    }

    /// Takes sync copy `plain` as `holder`'s, blob `b` (`parse`; `note`): `false` when it is bad
    /// input.
    pub(crate) fn take_sync_copy(&mut self, holder: &Tid, b: &BlobId, plain: &[u8]) -> Result<bool> {
        let Some(c) = parse(*holder, plain) else { return Ok(false) };
        let b = *b;
        self.run(|tx| note(tx, &b, c))?;
        Ok(true)
    }

    /// The sync copies of `t` taken here, each with whether it counts (`Unread::counted`): tests.
    #[doc(hidden)]
    pub fn sync_copies_of(&self, t: &Tid) -> Vec<(BlobId, Arc<HeldSyncCopy>, bool)> {
        let u = self.core.unread(t);
        self.core.ix.sync_copies.get(t).map(|m| m.iter().map(|(b, c)| (*b, c.clone(), u.counted.contains(b))).collect()).unwrap_or_default()
    }
}
