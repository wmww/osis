//! Accounts (spec/permissions.md §1, spec/crypto.md §3, §9): creating one (the account, its
//! devices actor D, its profile), holding its epoch seeds from D's `account.0`, and what signing
//! as it and sealing to it read from the held signing chain.

use super::labels::{ReaderKey, new_label};
use super::{Delivery, Done, put_edge};
use crate::engine::{Core, Engine, Tx, records};
use crate::error::{Error, Result};
use crate::identity::thing_record;
use crate::rotation;
use crate::Mutation;
use osis_base::{CommitId, CreationRecord, Role, Tid, SIGNING_KEY_ED25519};
use osis_commit::{CommitBlob, FIRST_EPOCH};
use osis_crypto::{AccountEpochKeys, Epoch, KemPublicKey, Secret32, VerifyingKey, open_inner, verify_inner};
use osis_keys::{ActorEpochs, HolderKeys, Keysets, ROLES, Recipient, account_epoch, account_keysets};
use osis_label::Address;
use osis_store::Shred;
use osis_perm::Point;
use osis_perm::chain::Rotation;
use osis_perm::{EpochStanding, Epochs};
use osis_schema::core_types::{self as ct, Edge, KemKey, Keys, SigningKey};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// An account this node signs as (`Engine::hold_account`).
#[derive(Clone, Debug)]
pub struct HeldAccount {
    pub devices: Tid,
    /// The first epoch's signing key (the creation record's).
    pub first: [u8; 32],
    /// Epoch seeds held, by signing public key.
    pub seeds: BTreeMap<[u8; 32], Secret32>,
}

/// An account this node created.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreatedAccount {
    pub account: Tid,
    pub devices: Tid,
    pub profile: Tid,
}

struct EpochPublic {
    /// `None` while an epoch it supersedes is not held: its name is not known yet.
    height: Option<u64>,
    signing: VerifyingKey,
    kem: Option<KemPublicKey>,
    supersedes: Vec<CommitId>,
    /// Its rotation's key (`None`: the first epoch, standing since the account's creation).
    at: Option<Point>,
}

/// An account's signing chain as this node holds it.
pub(crate) struct AccountView {
    /// The epoch rule over the held rotations (spec/permissions.md §5.4, §5.5) with no word
    /// naming a commit: what a commit no list or listing names stands as. Names are
    /// `refresh_epochs`'s, per commit.
    rule: Epochs<CommitId, Tid>,
    /// The held rotations as the chain reads them.
    rotations: Vec<Rotation<CommitId>>,
    epochs: BTreeMap<CommitId, EpochPublic>,
    /// The counting epochs by name, and the open ones: what a write or seal reads, so neither
    /// walks the chain (its length is the account's to choose).
    by_name: BTreeMap<Epoch, CommitId>,
    open: Vec<CommitId>,
}

impl AccountView {
    fn name(&self, e: &EpochPublic) -> Option<Epoch> {
        account_epoch(e.height?, &e.signing).ok()
    }

    /// The counting epoch named `name` and its ID.
    fn named(&self, name: &Epoch) -> Option<(&CommitId, &EpochPublic)> {
        let id = self.by_name.get(name)?;
        Some((id, self.epochs.get(id)?))
    }

    /// The rotation minting the counting epoch named `name` (`None`: the first epoch, which no
    /// rotation mints, or one not held).
    pub(crate) fn rotation_named(&self, name: &Epoch) -> Option<CommitId> {
        self.by_name.get(name).copied().filter(|id| *id != FIRST_EPOCH)
    }

    /// The possession key of the epoch named `name` (spec/crypto.md §4: its signing key), where
    /// that epoch's rotation is ordered before `point` (a keyset counts by a body before the
    /// commit's key).
    pub(crate) fn possession_key(&self, name: &Epoch, point: &Point) -> Option<VerifyingKey> {
        let (_, e) = self.named(name)?;
        e.at.as_ref().is_none_or(|a| a < point).then_some(e.signing)
    }

    /// Whether the counting epoch named `name` was minted before `point` (the first epoch stands
    /// since the account's creation): a node removed from the account after that held its seed.
    pub(crate) fn minted_before(&self, name: &Epoch, point: &Point) -> bool {
        self.named(name).is_some_and(|(_, e)| e.at.as_ref().is_none_or(|a| a < point))
    }

    /// The account's keysets as the seal and stale rules read them (spec/crypto.md §4).
    pub(crate) fn keysets(&self) -> Keysets {
        let named = self.epochs.iter().filter_map(|(id, e)| Some((*id, self.name(e)?))).collect();
        account_keysets(self.rule.chain(), &named)
    }

    /// Whether `key` is the signing key of an open epoch.
    pub(crate) fn open_key(&self, key: &[u8; 32]) -> bool {
        self.open.iter().filter_map(|id| self.epochs.get(id)).any(|e| e.signing.to_bytes() == *key)
    }

    /// The newest open epoch that `held` admits, ties by the greater signing key.
    fn newest_open(&self, held: impl Fn(&EpochPublic) -> bool) -> Option<(&CommitId, &EpochPublic)> {
        self.open.iter().filter_map(|id| self.epochs.get_key_value(id)).filter(|(_, e)| held(e)).max_by_key(|(_, e)| (e.height, e.signing.to_bytes()))
    }

    /// The newest epoch that counts, open or not (concurrent rotations close each other's).
    fn newest_counting(&self) -> Option<&EpochPublic> {
        self.epochs.iter().filter(|(id, _)| self.rule.chain().epoch_counts(id)).map(|(_, e)| e).max_by_key(|e| (e.height, e.signing.to_bytes()))
    }

    /// What the epoch rule says per held epoch (`JudgedEpochs::epochs`).
    fn judged(&self) -> BTreeMap<CommitId, (EpochStanding<CommitId>, Option<bool>)> {
        let c = self.rule.chain();
        self.epochs.keys().map(|e| (*e, (self.rule.unnamed(e), (*e != FIRST_EPOCH && c.holds(e)).then(|| c.counts(e))))).collect()
    }

    /// The heads: counting epochs no counting rotation descends from (signed at it, or a merge
    /// accepting it), ascending. By descent, never by a supersedes list, which its rotator
    /// writes as it likes (a removed node's fork superseding the epoch that closed it would
    /// hide that epoch from the merge).
    pub(crate) fn heads(&self) -> Vec<CommitId> {
        let c = self.rule.chain();
        let below: BTreeSet<CommitId> = self.rotations.iter().filter(|r| c.holds(&r.id) && c.counts(&r.id)).flat_map(|r| std::iter::once(r.at).chain(r.names.intersection(&r.signed).copied())).collect();
        self.epochs.keys().filter(|e| c.epoch_counts(e) && !below.contains(*e)).copied().collect()
    }

    /// The seed of held epoch `e` among `held`'s.
    pub(crate) fn seed_of(&self, e: &CommitId, held: &HeldAccount) -> Option<Secret32> {
        held.seeds.get(&self.epochs.get(e)?.signing.to_bytes()).cloned()
    }

    /// The held rotations.
    pub(crate) fn rotation_ids(&self) -> Vec<CommitId> {
        self.rotations.iter().map(|r| r.id).collect()
    }

    /// Whether `c` is a held rotation.
    pub(crate) fn is_rotation(&self, c: &CommitId) -> bool {
        *c != FIRST_EPOCH && self.epochs.contains_key(c)
    }

    /// The epochs open here.
    pub(crate) fn open(&self) -> &[CommitId] {
        &self.open
    }

    /// Whether rotation `r` is held with its chain.
    pub(crate) fn holds(&self, r: &CommitId) -> bool {
        self.rule.chain().holds(r)
    }

    /// The held epochs counting rotation `r` closes.
    pub(crate) fn closed_by(&self, r: &CommitId) -> Vec<CommitId> {
        self.epochs.keys().filter(|e| self.closers(e).contains(r)).copied().collect()
    }

    /// Whether held rotation `r` counts.
    pub(crate) fn rotation_counts(&self, r: &CommitId) -> bool {
        self.rule.chain().holds(r) && self.rule.chain().counts(r)
    }

    /// The counting rotations closing epoch `e`.
    pub(crate) fn closers(&self, e: &CommitId) -> BTreeSet<CommitId> {
        match self.rule.unnamed(e) {
            EpochStanding::Closed(c) => c,
            EpochStanding::Counts => BTreeSet::new(),
        }
    }
}

/// What the epoch rule (spec/permissions.md §5.4, §5.5) says of an account's held commits, as
/// last judged (`refresh_epochs`) and persisted with the index, so an open builds no signing
/// chain and reads no list: per held epoch, what a commit signed at it that no word names stands
/// as, and for a rotation held with its chain whether it counts; and the held commits at closed
/// epochs that a counting thing list or listing names. An addendum's saving is §5.2's fixpoint
/// (`Timeline::vouching`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JudgedEpochs {
    epochs: BTreeMap<CommitId, (EpochStanding<CommitId>, Option<bool>)>,
    named: BTreeSet<CommitId>,
}

impl JudgedEpochs {
    /// What the rule says of commit `id` signed at `epoch` (`standing_in`).
    fn standing(&self, id: &CommitId, epoch: &CommitId) -> EpochStanding<CommitId> {
        if let Some((_, Some(counts))) = self.epochs.get(id) {
            return if *counts { EpochStanding::Counts } else { EpochStanding::Closed(BTreeSet::new()) };
        }
        if self.named.contains(id) {
            return EpochStanding::Counts;
        }
        self.epochs.get(epoch).map_or(EpochStanding::Closed(BTreeSet::new()), |x| x.0.clone())
    }

    /// What a commit at `epoch` no word names stands as.
    pub(crate) fn unnamed_at(&self, epoch: &CommitId) -> EpochStanding<CommitId> {
        self.epochs.get(epoch).map_or(EpochStanding::Closed(BTreeSet::new()), |x| x.0.clone())
    }

    /// Without `id` among the named (it is held no more).
    pub(crate) fn unnamed(&self, id: &CommitId) -> Option<JudgedEpochs> {
        self.named.contains(id).then(|| {
            let mut j = self.clone();
            j.named.remove(id);
            j
        })
    }

    pub(crate) fn to_value(&self) -> osis_base::Value {
        use osis_base::Value;
        let id = |c: &CommitId| Value::bytes(&c.0);
        let epochs = Value::List(self.epochs.iter().map(|(e, (s, r))| {
            let s = match s {
                EpochStanding::Counts => Value::Bool(true),
                EpochStanding::Closed(c) => Value::List(c.iter().map(id).collect()),
            };
            Value::List(vec![id(e), s, Value::uint(r.map_or(0, |c| 1 + u64::from(c)))])
        }).collect());
        Value::List(vec![epochs, Value::List(self.named.iter().map(id).collect())])
    }

    pub(crate) fn from_value(v: &osis_base::Value) -> Option<JudgedEpochs> {
        use osis_base::Value;
        let id = |v: &Value| match v {
            Value::Bytes(b) => Some(CommitId(b.as_slice().try_into().ok()?)),
            _ => None,
        };
        let Value::List(top) = v else { return None };
        let [Value::List(xs), Value::List(named)] = top.as_slice() else { return None };
        let named = named.iter().map(id).collect::<Option<BTreeSet<CommitId>>>()?;
        let mut epochs = BTreeMap::new();
        for x in xs {
            let Value::List(f) = x else { return None };
            let [e, s, r] = f.as_slice() else { return None };
            let s = match s {
                Value::Bool(true) => EpochStanding::Counts,
                Value::List(c) => EpochStanding::Closed(c.iter().map(id).collect::<Option<_>>()?),
                _ => return None,
            };
            let r = match r {
                Value::Int(0) => None,
                Value::Int(1) => Some(false),
                Value::Int(2) => Some(true),
                _ => return None,
            };
            epochs.insert(id(e)?, (s, r));
        }
        Some(JudgedEpochs { epochs, named })
    }
}

/// What the epoch rule says of account commit `id` signed at `epoch` under `judged` (`None`: no
/// rotation of the account judged yet, its first epoch alone open).
fn standing_in(judged: Option<&JudgedEpochs>, id: &CommitId, epoch: &CommitId) -> EpochStanding<CommitId> {
    match judged {
        Some(j) => j.standing(id, epoch),
        None if *epoch == FIRST_EPOCH => EpochStanding::Counts,
        None => EpochStanding::Closed(BTreeSet::new()),
    }
}

/// Heights of the held rotations (spec/crypto.md §3): the first epoch 0, a rotation 1 plus the
/// greatest height of what it supersedes, `None` where one of those is not held. Iterative: the
/// chain's length is the account's to choose. IDs are hashes over `supersedes`, so no cycles.
fn heights(supersedes: &BTreeMap<CommitId, Vec<CommitId>>) -> BTreeMap<CommitId, Option<u64>> {
    let mut memo: BTreeMap<CommitId, Option<u64>> = [(FIRST_EPOCH, Some(0))].into();
    for id in supersedes.keys() {
        let mut stack = vec![*id];
        while let Some(&x) = stack.last() {
            if memo.contains_key(&x) {
                stack.pop();
                continue;
            }
            let Some(sup) = supersedes.get(&x) else {
                memo.insert(x, None);
                stack.pop();
                continue;
            };
            let unseen: Vec<CommitId> = sup.iter().filter(|s| !memo.contains_key(s)).copied().collect();
            if !unseen.is_empty() {
                stack.extend(unseen);
                continue;
            }
            let height = sup.iter().try_fold(0, |h: u64, s| memo.get(s).copied().flatten().map(|m| h.max(m.saturating_add(1))));
            memo.insert(x, height);
            stack.pop();
        }
    }
    memo
}

impl Core {
    /// The actor `g` is the home of: the account whose devices actor it is, else `g` itself.
    pub fn home_owner(&self, g: &Tid) -> Tid {
        self.accounts.iter().find(|(_, a)| a.devices == *g).map_or(*g, |(p, _)| *p)
    }

    /// Whether boxes of `a` go to its holder `m`: all but a devices actor's to its account. D's
    /// `account.0` holds the account's seeds, so a box to it on D would open with what it
    /// opens, and every holder of them is a node on D's roster (spec/permissions.md §1, §3).
    pub(crate) fn seals_to(&self, a: &Tid, m: &Tid) -> bool {
        self.devices_of(a) != Some(*m)
    }

    /// The account `d` is the devices actor of: its first admin, an account, when `d` holds its
    /// seeds (`account.0`).
    pub(crate) fn devices_of(&self, d: &Tid) -> Option<Tid> {
        let p = self.first_admin(d).filter(|p| self.is_account(p))?;
        let ak = osis_base::Ak::new("account.0").ok()?;
        self.ix.by_aspect.contains_key(&(*d, ak)).then_some(p)
    }

    /// Whether this node is a node of the account `d` is the devices actor of: a current holder on
    /// `d` (spec/permissions.md §1). Only such a node takes up the account's seeds and writes as
    /// it.
    pub(crate) fn of_devices(&self, d: &Tid) -> bool {
        let me = self.id.tid();
        self.key_holders(d).iter().any(|(m, _)| *m == me)
    }

    pub fn is_account(&self, t: &Tid) -> bool {
        self.created(t).is_some_and(CreationRecord::is_account)
    }

    /// Whether `m` is a holder actor with keysets held (spec/crypto.md §4): an account, or an
    /// actor other than a key actor with a keyset of its own.
    pub(crate) fn is_holder_actor(&self, m: &Tid) -> bool {
        self.is_account(m) || (!self.is_key_actor(m) && self.keysets_of(m).next().is_some())
    }

    /// This node's account and its devices actor, when it holds the account.
    pub fn account_devices(&self) -> Option<(Tid, Tid)> {
        let p = self.account?;
        Some((p, self.accounts.get(&p)?.devices))
    }

    /// The signing chain of account `p` from the rotations held (`None`: `p` is not known as an
    /// account here). Built only when the account's rotations held changed (`rotation_seq`), so a
    /// write does not cost O(its rotations). A merge's forks stand unaccepted until merges are
    /// written: the chain is given no verified merge signature.
    pub(crate) fn account_view(&self, p: &Tid) -> Option<Arc<AccountView>> {
        let seq = self.ix.rotations.get(p).copied().unwrap_or(0);
        if let Some(v) = self.account_views.borrow().get(p).filter(|x| x.0 == seq) {
            return Some(v.1.clone());
        }
        let v = Arc::new(self.build_account_view(p)?);
        self.account_views.borrow_mut().insert(*p, (seq, v.clone()));
        self.account_view_builds.set(self.account_view_builds.get().saturating_add(1));
        Some(v)
    }

    fn build_account_view(&self, p: &Tid) -> Option<AccountView> {
        let first = match self.created(p) {
            Some(CreationRecord::KeyActor { public_key, account: true, .. }) => VerifyingKey::from_slice(public_key).ok()?,
            Some(_) => return None,
            None => VerifyingKey::from_bytes(&self.accounts.get(p)?.first).ok()?,
        };
        let ak = osis_base::Ak::new("keys.0").ok()?;
        let rots: Vec<(CommitId, CommitId, osis_commit::RotationHeader, Point)> = self.ix.by_aspect.get(&(*p, ak)).into_iter().flatten().filter_map(|(_, c)| {
            let m = self.ix.commits.get(c).filter(|m| m.view.author == *p)?;
            Some((*c, m.header.epoch?, m.header.rotation.clone()?, Point { ts: m.header.ts, node: *p, commit: *c }))
        }).collect();
        let sup: BTreeMap<CommitId, Vec<CommitId>> = rots.iter().map(|(id, _, r, _)| (*id, r.supersedes.clone())).collect();
        let heights = heights(&sup);
        let mut epochs = BTreeMap::new();
        epochs.insert(FIRST_EPOCH, EpochPublic { height: Some(0), signing: first, kem: None, supersedes: Vec::new(), at: None });
        for (id, _, r, point) in &rots {
            epochs.insert(*id, EpochPublic { height: heights.get(id).copied().flatten(), signing: r.signing_key, kem: Some(r.kem_key.clone()), supersedes: r.supersedes.clone(), at: Some(*point) });
        }
        // a merge accepts a named fork only by that fork's signature (spec/crypto.md §9)
        let signed = |id: &CommitId, r: &osis_commit::RotationHeader| -> BTreeSet<CommitId> {
            let Some(sigs) = self.ix.merge_sigs.get(id) else { return BTreeSet::new() };
            r.names.iter().zip(sigs.iter()).filter(|(n, s)| epochs.get(*n).is_some_and(|e: &EpochPublic| osis_commit::verify_merge(id, s, &e.signing))).map(|(n, _)| *n).collect()
        };
        let rotations: Vec<Rotation<CommitId>> = rots.iter().map(|(id, at, r, _)| Rotation { id: *id, at: *at, supersedes: r.supersedes.iter().copied().collect(), names: r.names.iter().copied().collect(), signed: signed(id, r) }).collect();
        let rule = Epochs::new(FIRST_EPOCH, rotations.clone(), None, &[], &[]);
        let mut v = AccountView { rule, rotations, epochs, by_name: BTreeMap::new(), open: Vec::new() };
        v.open = v.epochs.keys().filter(|id| v.rule.chain().open(id)).copied().collect();
        // a name repeated (two rotations minting one key) is read as its lowest ID
        for (id, e) in v.epochs.iter().filter(|(id, _)| v.rule.chain().epoch_counts(id)) {
            if let Some(name) = v.name(e) {
                v.by_name.entry(name).or_insert(*id);
            }
        }
        Some(v)
    }

    /// What the epoch rule (spec/permissions.md §5.5) says of held commit `id` (`view` its view):
    /// `Counts` for every commit of an author other than an account.
    pub(crate) fn standing(&self, id: &CommitId, view: &crate::engine::View) -> EpochStanding<CommitId> {
        self.standing_by(id, &view.author, view.epoch)
    }

    /// `standing` from commit `id`'s header (one not indexed yet).
    pub(crate) fn standing_of(&self, id: &CommitId, h: &osis_commit::Header) -> EpochStanding<CommitId> {
        self.standing_by(id, &h.author, h.epoch)
    }

    /// Whether commit `id` of `author` signed at `epoch` counts whole by the epoch rule (one held
    /// nowhere, such as a request, is never saved by an addendum).
    pub fn counts_at_epoch(&self, id: &CommitId, author: &Tid, epoch: Option<CommitId>) -> bool {
        self.standing_by(id, author, epoch) == EpochStanding::Counts
    }

    fn standing_by(&self, id: &CommitId, author: &Tid, epoch: Option<CommitId>) -> EpochStanding<CommitId> {
        let Some(e) = epoch else { return EpochStanding::Counts };
        standing_in(self.ix.epochs.get(author).map(|j| &**j), id, &e)
    }

    /// The epoch this node signs as `p` at and its keys: the newest open one it holds a seed of
    /// (spec/permissions.md §5.5). `None` when `p` is no account held here.
    pub(crate) fn account_signing(&self, p: &Tid) -> Result<Option<(CommitId, AccountEpochKeys)>> {
        let Some(a) = self.accounts.get(p) else { return Ok(None) };
        let v = self.account_view(p).ok_or(Error::Misuse("no signing chain for the account"))?;
        let (id, e) = v.newest_open(|e| a.seeds.contains_key(&e.signing.to_bytes())).ok_or(Error::Misuse("no open epoch of the account held"))?;
        let seed = a.seeds.get(&e.signing.to_bytes()).ok_or(Error::Misuse("no open epoch of the account held"))?;
        Ok(Some((*id, AccountEpochKeys::from_seed(seed))))
    }

    /// The role epochs of account `p` this node holds seeds of (spec/crypto.md §3), internal to
    /// its nodes.
    pub(crate) fn account_epochs(&self, p: &Tid) -> Option<ActorEpochs> {
        let a = self.accounts.get(p)?;
        let v = self.account_view(p)?;
        let seed = |e: &EpochPublic| a.seeds.get(&e.signing.to_bytes()).cloned();
        let held: Vec<_> = v.epochs.values().filter_map(|e| {
            let sup = e.supersedes.iter().filter_map(|s| v.epochs.get(s)).filter_map(|x| Some((x.height?, seed(x)?))).collect();
            Some((e.height?, seed(e)?, sup))
        }).collect();
        ActorEpochs::account(p, &held).ok()
    }

    /// The seeds of `p` held, by epoch name (spec/crypto.md §3).
    pub(crate) fn account_seeds_by_name(&self, p: &Tid) -> BTreeMap<Epoch, Secret32> {
        let (Some(a), Some(v)) = (self.accounts.get(p), self.account_view(p)) else { return BTreeMap::new() };
        v.epochs.values().filter_map(|e| Some((v.name(e)?, a.seeds.get(&e.signing.to_bytes())?.clone()))).collect()
    }

    /// An account's delete key (spec/crypto.md §7): the signing key of its newest open epoch
    /// held, else of its newest open epoch, else (a fork leaves none open) of its newest counting
    /// one.
    pub(crate) fn account_delete_key(&self, p: &Tid) -> Option<VerifyingKey> {
        let v = self.account_view(p)?;
        let held = self.accounts.get(p);
        let newest = v.newest_open(|e| held.is_some_and(|a| a.seeds.contains_key(&e.signing.to_bytes()))).or_else(|| v.newest_open(|_| true));
        Some(newest.map(|n| n.1).or_else(|| v.newest_counting())?.signing)
    }
}

/// The things commit view `v` names words on: those it has a delta on, and the actor it acts for.
pub(crate) fn things_of(v: &crate::engine::View) -> BTreeSet<Tid> {
    let mut t: BTreeSet<Tid> = v.aspects.iter().map(|a| a.tid).collect();
    if v.actor != v.author {
        t.insert(v.actor);
    }
    t
}

/// Judges again what moved in the epochs of the accounts due (`Indexes::epochs_due`): those whose
/// rotations held changed, and those with a held commit a word may name otherwise
/// (`Indexes::names_due`). The commits whose standing may have moved are found from what moved:
/// those signed at an epoch whose standing moved, the rotation minting it, those a rotation whose
/// count moved lists, and the commits due; with the listings among their names and what those
/// name, until nothing is added. They are judged by the epoch rule over the held rotations and
/// their names alone, go to `stale_commits`, and a role commit among them counts in the timeline
/// or not as the rule now says (`Held::set_counted`). So a rotation or a list costs the commits it
/// moves, never the account's history. Returns whether a role commit's count moved.
pub(crate) fn refresh_epochs(tx: &mut Tx<'_>) -> Result<bool> {
    let mut by_account: BTreeMap<Tid, BTreeSet<CommitId>> = BTreeMap::new();
    for c in tx.core.ix.names_due.iter().copied().collect::<Vec<_>>() {
        tx.core.ix.names_due.remove(&c);
        if let Some(m) = tx.core.ix.commits.get(&c) {
            by_account.entry(m.view.author).or_default().insert(c);
        }
    }
    for p in tx.core.ix.epochs_due.iter().copied().collect::<Vec<_>>() {
        tx.core.ix.epochs_due.remove(&p);
        by_account.entry(p).or_default();
    }
    let mut moved_roles = false;
    for (p, due) in by_account {
        let Some(v) = tx.core.account_view(&p) else { continue };
        let now = v.judged();
        let was = tx.core.ix.epochs.get(&p).cloned();
        let get = |j: &Option<Arc<JudgedEpochs>>, e: &CommitId| match j {
            Some(j) => j.epochs.get(e).cloned(),
            None => (*e == FIRST_EPOCH).then_some((EpochStanding::Counts, None)),
        };
        let old: BTreeSet<CommitId> = was.as_ref().map_or_else(|| [FIRST_EPOCH].into(), |j| j.epochs.keys().copied().collect());
        let moved: BTreeSet<CommitId> = now.keys().copied().chain(old).filter(|e| now.get(e).cloned() != get(&was, e)).collect();
        let mut cands: BTreeSet<CommitId> = due;
        for e in &moved {
            cands.extend(tx.core.ix.by_epoch.get(&(p, *e)).into_iter().flatten().copied());
            cands.insert(*e);
            // a rotation whose count moved: what its lists name
            if now.get(e).map(|x| x.1) != get(&was, e).map(|x| x.1) {
                cands.extend(super::lists::named_by(tx, e)?.into_iter().map(|(c, _)| c));
            }
        }
        // the names of the candidates, with the listings among their sources and among them, and
        // what those name
        let mut names: BTreeMap<CommitId, Vec<(Tid, CommitId)>> = BTreeMap::new();
        let mut work: Vec<CommitId> = cands.iter().copied().collect();
        while let Some(c) = work.pop() {
            if names.contains_key(&c) {
                continue;
            }
            // a candidate that is a listing: what it names stands or falls with it
            if tx.core.ix.commits.get(&c).is_some_and(|m| m.view.author == p && m.view.epoch.is_some() && m.view.kind.is_role()) && !now.contains_key(&c) {
                for (n, _) in super::lists::named_by(tx, &c)? {
                    if cands.insert(n) {
                        work.push(n);
                    }
                }
            }
            let ns = super::lists::names_of(tx, &c)?;
            for (_, s) in &ns {
                let listing = tx.core.ix.commits.get(s).is_some_and(|m| m.view.author == p && m.view.epoch.is_some()) && !now.contains_key(s);
                if listing && !names.contains_key(s) {
                    cands.insert(*s);
                    work.push(*s);
                    for (n, _) in super::lists::named_by(tx, s)? {
                        if cands.insert(n) {
                            work.push(n);
                        }
                    }
                }
            }
            names.insert(c, ns);
        }
        let commit_of = |c: &CommitId| -> Option<osis_perm::AccountCommit<CommitId, Tid>> {
            let m = tx.core.ix.commits.get(c).filter(|m| m.view.author == p)?;
            Some(osis_perm::AccountCommit { id: *c, epoch: m.view.epoch?, things: things_of(&m.view) })
        };
        let mut lists: Vec<osis_perm::ThingList<CommitId, Tid>> = Vec::new();
        let mut listings: BTreeMap<(CommitId, Tid), BTreeSet<CommitId>> = BTreeMap::new();
        for (c, ns) in &names {
            for (t, s) in ns {
                if now.contains_key(s) {
                    lists.push(osis_perm::ThingList { rotation: *s, thing: *t, commits: [*c].into() });
                } else if commit_of(s).is_some() {
                    listings.entry((*s, *t)).or_default().insert(*c);
                }
            }
        }
        let listings: Vec<osis_perm::Listing<CommitId, Tid>> = listings.into_iter().filter_map(|((s, t), commits)| Some(osis_perm::Listing { listing: commit_of(&s)?, thing: t, commits })).collect();
        let rule = Epochs::new(FIRST_EPOCH, v.rotations.iter().cloned(), None, &lists, &listings);
        let mut named: BTreeSet<CommitId> = was.as_ref().map(|j| j.named.clone()).unwrap_or_default();
        for c in &cands {
            named.remove(c);
            if let Some(ac) = commit_of(c)
                && !now.contains_key(c)
                && rule.unnamed(&ac.epoch) != EpochStanding::Counts
                && rule.counts(&ac)
            {
                named.insert(*c);
            }
        }
        let judged = Arc::new(JudgedEpochs { epochs: now, named });
        if was.as_deref() == Some(&*judged) {
            continue;
        }
        // the first epoch alone, open, named nothing, is what no entry says: the index is a
        // function of what is held, a rotation dropped included
        if judged.epochs.len() == 1 && judged.named.is_empty() && get(&None, &FIRST_EPOCH) == judged.epochs.get(&FIRST_EPOCH).cloned() {
            tx.core.ix.epochs.remove(&p);
        } else {
            tx.core.ix.epochs.insert(p, judged.clone());
        }
        for c in cands {
            let Some(m) = tx.core.ix.commits.get(&c) else { continue };
            if m.view.author != p {
                continue;
            }
            if m.view.kind.is_role() {
                let counts = m.view.epoch.is_some_and(|e| judged.standing(&c, &e) == EpochStanding::Counts);
                moved_roles |= tx.core.ix.held.edge_commit(&c).is_some();
                tx.core.ix.held.set_counted(c, counts);
            }
            tx.core.stale_commits.insert(c);
        }
    }
    Ok(moved_roles)
}

/// The KEM key of epoch `e` of account `p`: the first epoch's from `keys.0`, a rotation's from
/// its header (spec/crypto.md §3).
fn epoch_kem(tx: &mut Tx<'_>, p: &Tid, e: &EpochPublic) -> Result<Option<KemPublicKey>> {
    Ok(match &e.kem {
        Some(k) => Some(k.clone()),
        None => first_kem(Core::keys_in(tx, p)?, &e.signing),
    })
}

/// How a box to account `p` at its epoch `name` is sealed (spec/crypto.md §3, §4). `None`: that
/// epoch counts no more or its KEM key is not held here.
pub(crate) fn holder_keys_at(tx: &mut Tx<'_>, p: &Tid, name: &Epoch) -> Result<Option<HolderKeys>> {
    let v = tx.core.account_view(p).ok_or(Error::UnknownThing(*p))?;
    let Some((_, e)) = v.named(name) else { return Ok(None) };
    let Some(kem) = epoch_kem(tx, p, e)? else { return Ok(None) };
    let seed = tx.core.accounts.get(p).and_then(|a| a.seeds.get(&e.signing.to_bytes()).cloned());
    Ok(Some(HolderKeys::Account { epoch: *name, kem, seed }))
}

/// How a box to account `p` is sealed with no anchors to descend from: at its newest open epoch.
pub(crate) fn holder_keys(tx: &mut Tx<'_>, p: &Tid) -> Result<HolderKeys> {
    let v = tx.core.account_view(p).ok_or(Error::UnknownThing(*p))?;
    let (_, e) = v.newest_open(|_| true).ok_or(Error::Misuse("no open epoch of the account"))?;
    let name = v.name(e).ok_or(Error::Misuse("account epoch"))?;
    holder_keys_at(tx, p, &name)?.ok_or(Error::Misuse("no keys.0 of the account's epoch held"))
}

/// The reader key of a label for account `p` (spec/sync.md §2): the X25519 half of its newest open
/// epoch's KEM key. `None`: no open epoch or its KEM key held here.
pub(crate) fn reader_key(tx: &mut Tx<'_>, p: &Tid) -> Result<Option<ReaderKey>> {
    let Some(v) = tx.core.account_view(p) else { return Ok(None) };
    let Some((_, e)) = v.newest_open(|_| true) else { return Ok(None) };
    Ok(epoch_kem(tx, p, e)?.map(|kem| ReaderKey::Dh(kem.x25519())))
}

/// The KEM key of an account's first epoch: `keys.0`'s `key` when its `signing` is that epoch's.
fn first_kem(keys: Option<Keys>, signing: &VerifyingKey) -> Option<KemPublicKey> {
    let k = keys?;
    let SigningKey::Ed25519(s) = k.signing?;
    if s != signing.to_bytes() {
        return None;
    }
    let KemKey::X25519MlKem768(b) = k.key?;
    KemPublicKey::from_slice(&b).ok()
}

fn admin_edge() -> Edge {
    Edge { role: Role::Admin, until: None, invite: None, tied: None }
}

impl Engine {
    /// Creates an account (spec/permissions.md §1): the account at its first epoch, its devices
    /// actor D (secrets of its own boxed to this node, its home label on `hosts`, the epoch's
    /// seed in `account.0`) and its profile, one commit signed as the account.
    pub fn create_account(&mut self, hosts: &[Address]) -> Result<(CreatedAccount, Done)> {
        let (seed, nonce, nonce_d) = self.run(|tx| {
            let mut n = [0u8; 32];
            tx.rng.fill_bytes(&mut n);
            Ok((Secret32::random(&mut *tx.rng), n, thing_record(Tid::from_bytes([0; 15]), &mut *tx.rng)))
        })?;
        let keys = AccountEpochKeys::from_seed(&seed);
        let signing = keys.signing.verifying_key().to_bytes();
        let record = CreationRecord::KeyActor { alg: SIGNING_KEY_ED25519, public_key: signing.to_vec(), nonce, account: true };
        let p = record.tid();
        let d_record = CreationRecord::Thing { admin: p, nonce: *nonce_d.nonce(), link: false };
        let d = d_record.tid();
        self.core.account = Some(p);
        self.core.accounts.insert(p, Arc::new(HeldAccount { devices: d, first: signing, seeds: [(signing, seed.clone())].into() }));
        self.core.role_changed();
        let res = self.run(|tx| create_account_in(tx, record, d_record, &keys, &seed, hosts));
        if res.is_err() {
            self.core.account = None;
            self.core.accounts.remove(&p);
        }
        let (profile, c) = res?;
        self.save_account(&p, &d)?;
        let mut done = Done::default();
        done.add(c);
        Ok((CreatedAccount { account: p, devices: d, profile }, done))
    }

    /// Takes up account `p` from the seeds on its devices actor `d` (`account.0`, readable here
    /// as a node of the account): this node signs as it and its boxes open.
    pub fn hold_account(&mut self, p: &Tid, d: &Tid) -> Result<()> {
        let Some(CreationRecord::KeyActor { public_key, account: true, .. }) = self.core.created(p).cloned() else { return Err(Error::UnknownThing(*p)) };
        let first: [u8; 32] = public_key.as_slice().try_into().map_err(|_| Error::Misuse("account key"))?;
        let stored = self.get_typed(d, &ct::ACCOUNT)?.ok_or(Error::UnknownThing(*d))?;
        let mut seeds = BTreeMap::new();
        for (k, v) in stored.seeds {
            let (Ok(k), Ok(v)) = (<[u8; 32]>::try_from(k), <[u8; 32]>::try_from(v)) else { continue };
            let seed = Secret32::from_bytes(v);
            // an entry that is not its epoch's seed opens and signs nothing
            if AccountEpochKeys::from_seed(&seed).signing.verifying_key().to_bytes() == k {
                seeds.insert(k, seed);
            }
        }
        if seeds.is_empty() || !self.core.of_devices(d) {
            return Err(Error::Misuse("no seed of the account readable here"));
        }
        self.core.accounts.insert(*p, Arc::new(HeldAccount { devices: *d, first, seeds }));
        self.core.role_changed();
        self.run(super::reopen_all)
    }

    /// How a box to account `p` is sealed: at its newest open epoch.
    pub fn account_holder_keys(&mut self, p: &Tid) -> Result<HolderKeys> {
        let a = *p;
        self.run(|tx| holder_keys(tx, &a))
    }

    /// Sets `cb` up to be signed as this node's account (a node that joined no account signs as
    /// itself), returning the key to build it with: for tests forging a commit.
    #[doc(hidden)]
    pub fn sign_forged(&self, cb: &mut osis_commit::CommitBuilder) -> osis_crypto::SigningSecret {
        let held = self.core.me().and_then(|me| self.core.account_signing(&me).ok().flatten());
        let Some((epoch, k)) = held else { return self.core.id.keys().signing.clone() };
        cb.account = Some(osis_commit::AccountSigner { epoch, inner: k.inner.clone(), node: self.core.id.tid(), node_key: self.core.id.keys().signing.clone() });
        k.signing.clone()
    }

    /// Signs `blob`'s (changed) header as this node's account: for tests forging a commit.
    #[doc(hidden)]
    pub fn resign_forged(&self, blob: &mut CommitBlob) {
        let id = blob.header.id();
        let (key, inner) = match self.core.me().and_then(|me| self.core.account_signing(&me).ok().flatten()) {
            Some((_, k)) => (k.signing.clone(), Some(osis_crypto::seal_inner(&k.inner, &id.0, &self.core.id.tid(), &self.core.id.keys().signing))),
            None => (self.core.id.keys().signing.clone(), None),
        };
        blob.sigs = osis_commit::Sigs::signed(&id, &key, inner, Vec::new());
    }

    /// The KEM secrets of account `p`'s epochs held here: what opens an inbox blob sealed to it
    /// (spec/crypto.md §5).
    pub fn account_kems(&self, p: &Tid) -> Vec<osis_crypto::KemSecret> {
        self.core.accounts.get(p).map(|a| a.seeds.values().map(|s| AccountEpochKeys::from_seed(s).kem).collect()).unwrap_or_default()
    }

    /// The account this node belongs to and its devices actor, once it has joined one.
    pub fn account(&mut self) -> Result<Option<(Tid, Tid)>> {
        let Some(b) = self.run(|tx| Ok(tx.txn.get_local(records::ACCOUNT)?))? else { return Ok(None) };
        let pair = |r: std::ops::Range<usize>| b.get(r).and_then(|x| <[u8; 15]>::try_from(x).ok()).map(Tid::from_bytes);
        Ok(Some((pair(0..15).ok_or(Error::Corrupt("account record"))?, pair(15..30).ok_or(Error::Corrupt("account record"))?)))
    }

    fn save_account(&mut self, p: &Tid, d: &Tid) -> Result<()> {
        let v = [p.as_bytes().as_slice(), d.as_bytes().as_slice()].concat();
        self.run(|tx| Ok(tx.txn.put_local(records::ACCOUNT, &v, Shred::No)?))
    }

    /// Re-takes this node's account seeds at open (`hold_account`): seeds stay in the store's
    /// encrypted `account.0`, never in a local record. Seeds not readable (the node was removed):
    /// it stays the account's, unable to sign.
    pub(crate) fn take_account(&mut self) -> Result<()> {
        let Some((p, d)) = self.account()? else { return Ok(()) };
        self.core.account = Some(p);
        if self.hold_account(&p, &d).is_err() {
            self.core.accounts.remove(&p);
        }
        // removed before what it read as the account went: it goes now
        if !self.core.accounts.contains_key(&p) && !self.core.of_devices(&d) {
            self.run(|tx| super::signing::leave(tx, p, d))?;
        }
        Ok(())
    }

    /// Pairing, existing node side (spec/sync.md §2: the only way a node receives a grant):
    /// `node`'s card (`created.0`, `keys.0`) was received over the direct connection. A node
    /// that is not on the account's devices actor is granted admin there (spec/permissions.md
    /// §1: any grant on D makes a node of P); one that is (stranded) is re-sealed. Returns the
    /// commits to send it directly: the grant or re-seal, D's and P's certificates and D's
    /// `label.0` commits (the new node downloads the rest under the home label).
    pub fn pair(&mut self, node: &Tid) -> Result<Done> {
        let d = self.account()?.ok_or(Error::Misuse("not a node of an account"))?.1;
        let n = *node;
        if !self.knows(&n) {
            return Err(Error::UnknownThing(n));
        }
        let holder = self.roster(&d).get(&n).is_some_and(|e| e.alive_at(Some(osis_base::Ts::make(self.now(), 0).unwrap_or_default())));
        let mut done = if holder { self.reshare(&d, &n)? } else { self.grant(&d, &n, &admin_edge())? };
        let mut all: Vec<CommitId> = self.certificates(&d).into_keys().collect();
        let label = osis_base::Ak::new("label.0").map_err(|_| Error::Misuse("ak"))?;
        all.extend(self.core.ix.by_aspect.get(&(d, label)).into_iter().flatten().map(|(_, c)| *c));
        // the account's first commit: D's `account.0` and P's creation record; its rotations
        // (with their thing lists, `Package::lists`), so what they name counts at the new node
        let seeds = osis_base::Ak::new("account.0").map_err(|_| Error::Misuse("ak"))?;
        all.extend(self.core.ix.by_aspect.get(&(d, seeds)).into_iter().flatten().map(|(_, c)| *c));
        all.sort_by_key(|c| self.header(c).map(|h| h.ts));
        for x in &done.deliveries {
            if let Delivery::Direct { to, commits } = x
                && *to == n
            {
                all.extend(commits.iter().copied());
            }
        }
        // each commit once, in the order collected
        let mut seen = BTreeSet::new();
        all.retain(|c| seen.insert(*c));
        // the grant's own direct send is replaced (crash-safe like the grant: `flows::owe`)
        let (gone, kept): (Vec<Delivery>, Vec<Delivery>) = std::mem::take(&mut done.deliveries).into_iter().partition(|x| matches!(x, Delivery::Direct { to, .. } if *to == n));
        done.deliveries = kept;
        let x = self.run(|tx| {
            super::unowe(tx, &gone)?;
            super::owe(tx, Delivery::Direct { to: n, commits: all })
        })?;
        done.deliveries.push(x);
        Ok(done)
    }

    /// Pairing, new node side, after applying what `pair` sent: checks the grant put it on the
    /// account's devices actor, joins account `p` and returns the certificate copy of `grant` to place under D's home
    /// label (spec/sync.md §3).
    pub fn paired(&mut self, p: &Tid, grant: &CommitId) -> Result<Done> {
        let node = self.tid();
        let d = self.devices_held(p).ok_or(Error::UnknownThing(*p))?;
        if self.core.role_now(&node, &d) != Some(Role::Admin) {
            return Err(Error::Permission { tid: d });
        }
        self.hold_account(p, &d)?;
        self.core.account = Some(*p);
        self.save_account(p, &d)?;
        self.core.role_changed();
        let g = *grant;
        let x = self.run(|tx| super::owe(tx, Delivery::Certificate { commits: vec![g], under: d }))?;
        Ok(Done { deliveries: vec![x], ..Done::default() })
    }

    /// The devices actor of account `p` as held here: the thing with `account.0` whose first admin
    /// is `p`.
    pub fn devices_held(&self, p: &Tid) -> Option<Tid> {
        let ak = osis_base::Ak::new("account.0").ok()?;
        self.core.ix.by_aspect.keys().find(|(t, a)| *a == ak && self.core.first_admin(t) == Some(*p)).map(|(t, _)| *t)
    }

    /// The node whose inner signature `blob` carries, when this node holds the seed of the epoch
    /// it is signed at and the signature verifies under that node's key (spec/crypto.md §3).
    pub fn open_inner(&self, blob: &CommitBlob) -> Option<Tid> {
        self.core.inner_node(blob)
    }
}

impl Core {
    /// `Engine::open_inner`.
    pub(crate) fn inner_node(&self, blob: &CommitBlob) -> Option<Tid> {
        let (h, inner) = (&blob.header, blob.sigs.inner.as_ref()?);
        let a = self.accounts.get(&h.author)?;
        let v = self.account_view(&h.author)?;
        let e = v.epochs.get(&h.epoch?)?;
        let keys = AccountEpochKeys::from_seed(a.seeds.get(&e.signing.to_bytes())?);
        let id = h.id();
        let (node, sig) = open_inner(&keys.inner, &id.0, inner)?;
        let CreationRecord::KeyActor { public_key, .. } = self.created(&node)? else { return None };
        verify_inner(&VerifyingKey::from_slice(public_key).ok()?, &id.0, &sig).then_some(node)
    }
}

fn create_account_in(tx: &mut Tx<'_>, record: CreationRecord, d_record: CreationRecord, keys: &AccountEpochKeys, seed: &Secret32, hosts: &[Address]) -> Result<(Tid, Option<CommitId>)> {
    let p = record.tid();
    let me = tx.core.id.tid();
    let mut m = Mutation::new();
    m.create(record);
    let d = m.create(d_record);
    let profile = m.create(thing_record(p, &mut *tx.rng));
    m.sign_as(p);
    let held = ActorEpochs::derived(&tx.core.account_epochs(&p).ok_or(Error::Misuse("account not held"))?, &d);
    let node_kem = tx.core.id.keys().kem.public().clone();
    let holders = [Recipient { holder: me, role: Role::Admin, keys: HolderKeys::KeyActor { kem: node_kem.clone(), seed: None } }];
    let rot = rotation::rotation_into(tx, &mut m, d, &ROLES.into_iter().collect(), &held, &holders, false)?;
    let after = rot.preview(&held)?;
    let mut dep = [0u8; 32];
    tx.rng.fill_bytes(&mut dep);
    let label = new_label(tx, &mut m, d, &after, &[ReaderKey::Dh(node_kem.x25519())], &Secret32::from_bytes(dep), hosts)?;
    m.set(p, &ct::KEYS, &Keys { inbox: Some(ct::Inbox { label, hosts: hosts.to_vec() }), deposit_seed: Some(dep), ..osis_keys::aspects::account_keys(keys) })?;
    put_edge(&mut m, d, me, &admin_edge())?;
    let signing = keys.signing.verifying_key().to_bytes().to_vec();
    m.set(d, &ct::ACCOUNT, &ct::Account { seeds: [(signing, seed.expose().to_vec())].into() })?;
    let c = Engine::commit_tx(tx, m)?;
    rotation::record(tx, d, &rot)?;
    Ok((profile, c))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u32) -> CommitId {
        let mut c = [1; 32];
        c[..4].copy_from_slice(&n.to_le_bytes());
        CommitId(c)
    }

    // spec/crypto.md §3: height is 1 plus the greatest of what a rotation supersedes, unknown
    // while one of those is not held; a chain as long as the account likes costs no recursion
    #[test]
    fn heights_of_a_chain_spec_crypto_3() {
        let mut sup = BTreeMap::new();
        sup.insert(id(1), vec![FIRST_EPOCH]);
        sup.insert(id(2), vec![id(1)]);
        sup.insert(id(3), vec![FIRST_EPOCH, id(2)]);
        sup.insert(id(4), vec![id(1), id(9)]);
        let h = heights(&sup);
        assert_eq!((h[&id(1)], h[&id(2)], h[&id(3)], h[&id(4)]), (Some(1), Some(2), Some(3), None));
        let n = 100_000;
        let mut sup: BTreeMap<CommitId, Vec<CommitId>> = (1..n).map(|i| (id(i + 1), vec![id(i)])).collect();
        sup.insert(id(1), vec![FIRST_EPOCH]);
        assert_eq!(heights(&sup)[&id(n)], Some(u64::from(n)));
    }
}
