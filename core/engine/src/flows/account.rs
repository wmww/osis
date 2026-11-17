//! Accounts (spec/permissions.md §1, spec/crypto.md §3, §9): creating one (the account, its
//! account root D, its profile), holding its epoch seeds from D's `account.0`, and what signing
//! as it and sealing to it read from the held signing chain.

use super::sync_ids::{ReaderKey, new_sync_id};
use super::Done;
use crate::engine::{Core, Engine, Tx, records};
use crate::error::{Error, Result};
use crate::identity::thing_record;
use crate::rotation;
use crate::Mutation;
use osis_base::{CommitId, CreationRecord, Role, Tid, Value, SIGNING_KEY_ED25519};
use osis_crdt::{Op, PathOp};
use osis_commit::{CommitBlob, FIRST_EPOCH};
use osis_crypto::{AccountEpochKeys, Epoch, KemPublicKey, Secret32, VerifyingKey, open_inner, verify_inner};
use osis_keys::{ActorEpochs, HolderKeys, Keysets, ROLES, Recipient, account_epoch, account_keysets};
use osis_store::Shred;
use osis_perm::chain::Rotation;
use osis_perm::{EpochStanding, Epochs};
use osis_schema::core_types::{self as ct, KemKey, Keys, SigningKey};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// An account this node signs as (`Engine::hold_account`).
#[derive(Clone, Debug)]
pub struct HeldAccount {
    /// Its account root D.
    pub root: Tid,
    /// The first epoch's signing key (the creation record's).
    pub first: VerifyingKey,
    /// The keys of the epochs whose seeds are held, by signing public key.
    pub keys: BTreeMap<VerifyingKey, Arc<AccountEpochKeys>>,
}

/// An account this node created.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreatedAccount {
    pub account: Tid,
    pub root: Tid,
    pub profile: Tid,
}

#[derive(Debug, PartialEq)]
struct EpochPublic {
    /// `None` while an epoch it supersedes is not held: its name is not known yet.
    height: Option<u64>,
    signing: VerifyingKey,
    kem: Option<KemPublicKey>,
    supersedes: Vec<CommitId>,
}

/// What the chain of this node's account is read from besides the commits held
/// (`Core::judged_from`): its `Indexes::rotations` entry, the side chosen and the number of its
/// seeds held (which open who minted each rotation and its membership changes).
pub(crate) type JudgedFrom = (u64, Option<CommitId>, usize);

/// An account's signing chain as this node holds it.
#[derive(Debug, PartialEq)]
pub(crate) struct AccountView {
    /// The epoch rule over the held rotations (spec/permissions.md §5.4, §5.5) with no word
    /// naming a commit: what a commit no list or listing names stands as. Names are
    /// `refresh_epochs`'s, per commit.
    rule: Epochs<CommitId, Tid>,
    /// The held rotations as the chain reads them.
    rotations: Vec<Rotation<CommitId>>,
    /// The rotation this node's user chose (`Engine::choose_line`), if any.
    chosen: Option<CommitId>,
    /// The held rotations in receipt order, earliest first (one millisecond's by ID).
    received: Vec<CommitId>,
    /// This node's account: who minted each rotation and the membership changes each carries
    /// (`osis_perm::Devices`).
    pub(crate) devices: Option<osis_perm::Devices<CommitId, Tid>>,
    /// This node's account: D's roster, the nodes of its preferred head's line under the
    /// revocations it takes (spec/permissions.md §5.4, Roster).
    roster: BTreeSet<Tid>,
    epochs: BTreeMap<CommitId, EpochPublic>,
    /// The held merge certificates (verified: every tip's signature), each with the epoch it
    /// mints (spec/crypto.md §9, Merges).
    certs: BTreeMap<CommitId, CommitId>,
    /// The held certificates that stand here: at a node of the account, those whose maker is a
    /// node of the merge's line no taken removal hits (`osis_perm::Chain::standing_certifiers`);
    /// elsewhere every one. Another stands with nothing, whatever its epoch does: it counts not.
    standing_certs: BTreeSet<CommitId>,
    /// Per held epoch but the first, when this node came to hold it (a merge: its first
    /// certificate).
    held_at: BTreeMap<CommitId, osis_base::WallMs>,
    /// The counting epochs by name: what a write or seal reads, so neither walks the chain (its
    /// length is the account's to choose).
    by_name: BTreeMap<Epoch, CommitId>,
    /// The held rotations whose header says they remove a device: what revokes the epochs a
    /// counting one closes (spec/permissions.md §5.5 Revoked).
    carrying: BTreeSet<CommitId>,
    /// The signing keys of the revoked epochs (`revoked`).
    revoked: BTreeSet<[u8; 32]>,
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

    /// Whether the counting epoch named `name` is held and descends from counting rotation `s`:
    /// an account epoch covers a removal `s` carries (spec/crypto.md §4, Encrypting under).
    pub(crate) fn descends_counting(&self, name: &Epoch, s: &CommitId) -> bool {
        self.rotation_counts(s) && self.named(name).is_some_and(|(id, _)| self.rule.chain().on_line(s, id))
    }

    /// Whether a counting epoch named `name` is held.
    pub(crate) fn holds_name(&self, name: &Epoch) -> bool {
        self.named(name).is_some()
    }

    /// The account's keysets as the seal and stale rules read them (spec/crypto.md §4).
    pub(crate) fn keysets(&self) -> Keysets {
        let named = self.epochs.iter().filter_map(|(id, e)| Some((*id, self.name(e)?))).collect();
        account_keysets(self.rule.chain(), &named, |e| self.rule.revoked(e))
    }

    /// Whether `key` is an open epoch's (a head's) signing key.
    pub(crate) fn open_key(&self, key: &[u8; 32]) -> bool {
        self.rule.chain().heads().iter().any(|h| self.epochs.get(h).is_some_and(|e| e.signing.to_bytes() == *key))
    }

    /// The preferred head and its keys: where this node signs.
    fn open_epoch(&self) -> Option<(&CommitId, &EpochPublic)> {
        self.epochs.get_key_value(&self.preferred())
    }

    /// What the epoch rule says per held epoch (`JudgedEpochs::epochs`).
    /// A merge certificate counts as its epoch does.
    fn judged(&self) -> BTreeMap<CommitId, (EpochStanding<CommitId>, Option<bool>)> {
        let c = self.rule.chain();
        let certs = self.certs.iter().map(|(id, m)| (*id, (EpochStanding::Closed(BTreeSet::new()), c.holds(m).then(|| c.counts(m) && self.standing_certs.contains(id)))));
        self.epochs.keys().map(|e| (*e, (self.rule.unnamed(e), (*e != FIRST_EPOCH && c.holds(e)).then(|| c.counts(e))))).chain(certs).collect()
    }

    /// The heads: counting epochs no counting rotation descends from, ascending, every one open.
    /// By descent, never by a supersedes list, which its rotator writes as it likes (a removed
    /// node's fork superseding the epoch that closed it would hide that epoch from the next
    /// rotation). More than one (only at a node of the account) is owed a merge.
    pub(crate) fn heads(&self) -> Vec<CommitId> {
        self.rule.chain().heads().iter().copied().collect()
    }

    /// The chain as this node reads it when it tells its user the account has forked
    /// (`Chain::warning`: a line beside the followed one rejects it or is rejected by it): the
    /// versions (the preferred head, then the tips of those lines) and the one followed.
    pub(crate) fn doubt(&self) -> Option<(Vec<CommitId>, CommitId)> {
        let c = self.rule.chain();
        c.warning().then(|| (std::iter::once(c.preferred()).chain(c.contested().iter().copied()).collect(), c.preferred()))
    }

    /// The preferred head: where this node signs (spec/permissions.md §5.4).
    pub(crate) fn preferred(&self) -> CommitId {
        self.rule.chain().preferred()
    }

    /// Whether held epoch `e` is open: a head.
    pub(crate) fn is_open(&self, e: &CommitId) -> bool {
        self.rule.chain().open(e)
    }

    /// Held rotation `r`'s line: itself and every held rotation it descends from.
    pub(crate) fn line(&self, r: &CommitId) -> Option<BTreeSet<CommitId>> {
        self.rule.chain().line(r)
    }

    /// Whether held rotation `x` is on held rotation `r`'s line (`osis_perm::Chain::on_line`).
    pub(crate) fn on_line(&self, x: &CommitId, r: &CommitId) -> bool {
        self.rule.chain().on_line(x, r)
    }

    /// Of the held rotations `among` tells, those no other of them descends from
    /// (`osis_perm::Chain::tips`).
    pub(crate) fn tips(&self, among: impl Fn(&CommitId) -> bool) -> BTreeSet<CommitId> {
        self.rule.chain().tips(among)
    }

    /// This node's account: the revocations it takes, in the order taken (`osis_perm::Chain::taken`).
    pub(crate) fn taken(&self) -> &[CommitId] {
        self.rule.chain().taken()
    }

    /// Whether a counting rotation rejects held rotation `r`.
    pub(crate) fn rejected(&self, r: &CommitId) -> bool {
        self.rule.chain().rejected(r)
    }

    /// Whether held rotation `r` was placed in conflict with the line this node follows.
    pub(crate) fn disregarded(&self, r: &CommitId) -> bool {
        self.rule.chain().disregarded(r)
    }

    /// This node's account: D's roster on the line joining held epochs `heads` (a rotation's
    /// before it is made: `osis_perm::Chain::roster_joining`).
    pub(crate) fn roster_joining(&self, heads: &[CommitId]) -> BTreeSet<Tid> {
        self.devices.as_ref().map(|d| self.rule.chain().roster_joining(heads, d)).unwrap_or_default()
    }

    /// This node's account: whether held epoch `e`'s line keeps `node` a node, under the
    /// removals on it alone (`osis_perm::Chain::nodes_of`).
    pub(crate) fn keeps(&self, e: &CommitId, node: &Tid) -> bool {
        self.devices.as_ref().is_some_and(|d| self.rule.chain().nodes_of(e, d).contains(node))
    }

    /// This node's account: whether held rotation `r`'s line stands under the removals on it
    /// alone (`osis_perm::Chain::stands_alone`): one minted by no node of its line removes no one.
    pub(crate) fn stands_alone(&self, r: &CommitId) -> bool {
        self.rule.chain().stands_alone(r)
    }

    /// This node's account: D's roster (`roster`).
    pub(crate) fn roster(&self) -> &BTreeSet<Tid> {
        &self.roster
    }

    /// Whether the chain held here names `node` a device of this node's account: its creation
    /// device, or one a held rotation adds.
    pub(crate) fn named_device(&self, node: &Tid) -> bool {
        self.devices.as_ref().is_some_and(|d| d.first.contains(node) || d.adds.values().any(|a| a.contains(node)))
    }

    /// The revocations held rotation `r` takes (`osis_perm::Rotation::takes`).
    pub(crate) fn takes_of(&self, r: &CommitId) -> BTreeSet<CommitId> {
        self.rotations.iter().find(|x| x.id == *r).map(|x| x.takes.clone()).unwrap_or_default()
    }

    /// The nodes held rotation `r` removes (this node's account only).
    pub(crate) fn removes(&self, r: &CommitId) -> BTreeSet<Tid> {
        self.devices.as_ref().and_then(|d| d.removes.get(r)).cloned().unwrap_or_default()
    }

    /// Whether a held plain rotation minted by `node` (by its inner signature) answers held
    /// rotation `r`: supersedes it besides the epoch it is signed at (this node's account only).
    /// One signed at `r` answers nothing of it: `r` is on its line.
    pub(crate) fn answered_by(&self, r: &CommitId, node: &Tid) -> bool {
        let Some(d) = &self.devices else { return false };
        self.rotations.iter().any(|x| !x.is_merge() && x.at != *r && x.supersedes.contains(r) && d.minter.get(&x.id) == Some(node))
    }

    /// Whether a held plain rotation minted by `node` carries held revocation `t`: `t` is on its
    /// line or taken by a rotation on it (this node's account only).
    pub(crate) fn carried_by(&self, t: &CommitId, node: &Tid) -> bool {
        let Some(d) = &self.devices else { return false };
        self.rotations.iter().filter(|x| !x.is_merge() && d.minter.get(&x.id) == Some(node)).any(|x| self.carries(&x.id, t))
    }

    /// Whether held rotation `r`'s line carries revocation `t`: on it, or taken by a rotation on it.
    pub(crate) fn carries(&self, r: &CommitId, t: &CommitId) -> bool {
        self.line(r).is_some_and(|l| l.contains(t) || l.iter().any(|q| self.takes_of(q).contains(t)))
    }

    /// The node that minted counting rotation `r` (a merge: a certifier; this node's account
    /// only): what this node answers as its account's word, never what counts.
    pub(crate) fn authorized_by(&self, r: &CommitId) -> Option<Tid> {
        let d = self.devices.as_ref().filter(|_| self.rotation_counts(r))?;
        // a merge: the lowest of its certifiers
        d.minter.get(r).or_else(|| d.certifiers.get(r).and_then(|c| c.first())).copied()
    }

    /// The keys of held epoch `e` among `held`'s.
    pub(crate) fn keys_of(&self, e: &CommitId, held: &HeldAccount) -> Option<Arc<AccountEpochKeys>> {
        held.keys.get(&self.epochs.get(e)?.signing).cloned()
    }

    /// Whether the held epoch whose signing key is `key` is revoked (spec/permissions.md §5.5
    /// Revoked): a counting rotation closing it carries a removal. A
    /// key of no held epoch is not.
    pub(crate) fn revoked(&self, key: &[u8; 32]) -> bool {
        self.revoked.contains(key)
    }

    /// Whether held epoch `e` is revoked (`revoked`).
    #[cfg(test)]
    pub(crate) fn epoch_revoked(&self, e: &CommitId) -> bool {
        self.epochs.get(e).is_some_and(|x| self.revoked(&x.signing.to_bytes()))
    }

    /// Whether head `e` is revoked as soon as it closes: a counting rotation closing it carries a
    /// removal (a head beside a removal, spec/permissions.md §5.5 Carrying).
    pub(crate) fn head_revoked(&self, e: &CommitId) -> bool {
        self.is_open(e) && self.closers(e).iter().any(|r| self.carrying.contains(r))
    }

    /// The held rotations.
    pub(crate) fn rotation_ids(&self) -> Vec<CommitId> {
        self.rotations.iter().map(|r| r.id).collect()
    }

    /// What a verifier needs to hold the preferred head (spec/sync-opens.md §2): `needed` of it.
    /// A rotation beside it (a removed node's fork, a line not followed) is not among them.
    pub(crate) fn proving_chain(&self) -> Vec<CommitId> {
        self.needed([self.preferred()])
    }

    /// The held rotations `roots` need held (spec/permissions.md §5.4: the epoch each is signed
    /// at, a merge's tips, the revocations it takes, and what those need), roots included,
    /// each after what it needs.
    pub(crate) fn needed(&self, roots: impl IntoIterator<Item = CommitId>) -> Vec<CommitId> {
        let by: BTreeMap<CommitId, &osis_perm::Rotation<CommitId>> = self.rotations.iter().map(|r| (r.id, r)).collect();
        let needs = |r: &osis_perm::Rotation<CommitId>| -> Vec<CommitId> { std::iter::once(r.at).chain(r.names.iter().copied()).chain(r.takes.iter().copied()).collect() };
        let mut out = Vec::new();
        let mut seen = BTreeSet::new();
        // iterative post-order: a rotation is pushed once everything it needs is
        let mut stack: Vec<(CommitId, bool)> = roots.into_iter().map(|r| (r, false)).collect();
        stack.reverse();
        while let Some((id, expanded)) = stack.pop() {
            let Some(r) = by.get(&id) else { continue };
            if expanded {
                out.push(id);
                continue;
            }
            if !seen.insert(id) {
                continue;
            }
            stack.push((id, true));
            stack.extend(needs(r).into_iter().filter(|n| !seen.contains(n)).map(|n| (n, false)));
        }
        out
    }

    /// Whether held rotation `r` does not count and is in a rejection with a counting rotation
    /// (spec/permissions.md §5.4, Warning).
    pub(crate) fn contests(&self, r: &CommitId) -> bool {
        self.rule.chain().contests(r)
    }

    /// The tips of the held lines the Warning names (`osis_perm::Chain::contested`).
    pub(crate) fn contested(&self) -> &BTreeSet<CommitId> {
        self.rule.chain().contested()
    }

    /// Whether `c` is a held rotation commit: a plain rotation or a merge certificate.
    pub(crate) fn is_rotation(&self, c: &CommitId) -> bool {
        self.epoch_of(c).is_some()
    }

    /// The epoch held rotation commit or epoch `c` mints: a plain rotation's its own ID, a merge
    /// certificate's the merge's.
    pub(crate) fn epoch_of(&self, c: &CommitId) -> Option<CommitId> {
        self.certs.get(c).copied().or_else(|| (*c != FIRST_EPOCH && self.epochs.contains_key(c)).then_some(*c))
    }

    /// Whether held epoch `e` is a merge.
    pub(crate) fn is_merge(&self, e: &CommitId) -> bool {
        self.rotations.iter().any(|r| r.id == *e && r.is_merge())
    }

    /// A held merge epoch's tips, ascending.
    pub(crate) fn tips_of(&self, e: &CommitId) -> Vec<CommitId> {
        self.epochs.get(e).map(|x| x.supersedes.clone()).unwrap_or_default()
    }

    /// Held epoch `e`'s signing key.
    pub(crate) fn signing_key(&self, e: &CommitId) -> Option<VerifyingKey> {
        self.epochs.get(e).map(|x| x.signing)
    }

    /// When this node came to hold epoch `e` (a merge: its first certificate).
    pub(crate) fn held_at(&self, e: &CommitId) -> Option<osis_base::WallMs> {
        self.held_at.get(e).copied()
    }

    /// The held rotation commits minting epoch `e`: a plain rotation itself, a merge's
    /// certificates.
    pub(crate) fn minting(&self, e: &CommitId) -> Vec<CommitId> {
        if self.is_merge(e) {
            return self.certs.iter().filter(|(_, m)| *m == e).map(|(c, _)| *c).collect();
        }
        self.epochs.contains_key(e).then_some(*e).into_iter().filter(|e| *e != FIRST_EPOCH).collect()
    }

    /// Whether rotation `r` is held with its chain.
    pub(crate) fn holds(&self, r: &CommitId) -> bool {
        self.rule.chain().holds(r)
    }

    /// The held epochs counting rotation `r` closes.
    pub(crate) fn closed_by(&self, r: &CommitId) -> Vec<CommitId> {
        self.epochs.keys().filter(|e| self.closers(e).contains(r)).copied().collect()
    }

    /// Whether held rotation `r` (an epoch, or a rotation commit: a merge certificate counts as
    /// its epoch) counts.
    pub(crate) fn rotation_counts(&self, r: &CommitId) -> bool {
        if self.certs.contains_key(r) && !self.standing_certs.contains(r) {
            return false;
        }
        let r = self.certs.get(r).unwrap_or(r);
        self.rule.chain().holds(r) && self.rule.chain().counts(r)
    }

    /// The counting rotations closing held epoch `e`, void or not: every one it does not
    /// descend from (a head's are the other heads, which bound what a list names of it once it
    /// closes).
    pub(crate) fn closers(&self, e: &CommitId) -> BTreeSet<CommitId> {
        let c = self.rule.chain();
        if !c.holds(e) {
            return BTreeSet::new();
        }
        c.closers(e).into_iter().collect()
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
    /// The chain is read in doubt (`AccountView::doubt`), so the user was told.
    doubt: bool,
    /// At a node of the account: the signing keys of its epochs whose seeds are held here
    /// (`Core::account_keys`). One come to be held reopens the boxes sealed to the account
    /// (`refresh_epochs`).
    keyed: BTreeSet<[u8; 32]>,
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

    /// Whether epoch `e` is among those judged.
    pub(crate) fn holds(&self, e: &CommitId) -> bool {
        self.epochs.contains_key(e)
    }

    /// Whether held rotation `e` counted (tests: the custody-judged fault).
    #[cfg(test)]
    pub(crate) fn counts(&self, e: &CommitId) -> bool {
        self.epochs.get(e).is_some_and(|x| x.1 == Some(true))
    }

    /// Whether the chain was read in doubt (`AccountView::doubt`).
    pub(crate) fn doubt(&self) -> bool {
        self.doubt
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
        let keyed = Value::List(self.keyed.iter().map(|k| Value::bytes(k)).collect());
        Value::List(vec![epochs, Value::List(self.named.iter().map(id).collect()), Value::Bool(self.doubt), keyed])
    }

    pub(crate) fn from_value(v: &osis_base::Value) -> Option<JudgedEpochs> {
        use osis_base::Value;
        let id = |v: &Value| match v {
            Value::Bytes(b) => Some(CommitId(b.as_slice().try_into().ok()?)),
            _ => None,
        };
        let Value::List(top) = v else { return None };
        let [Value::List(xs), Value::List(named), Value::Bool(doubt), Value::List(keyed)] = top.as_slice() else { return None };
        let keyed = keyed.iter().map(|k| match k {
            Value::Bytes(b) => b.as_slice().try_into().ok(),
            _ => None,
        }).collect::<Option<BTreeSet<[u8; 32]>>>()?;
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
        Some(JudgedEpochs { epochs, named, doubt: *doubt, keyed })
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
    /// Every node account `p`'s chain names as this node reads it: each held rotation's minter or
    /// certifier, each device one adds or removes, the creation device. Empty but at a node of `p`.
    pub(crate) fn chain_nodes(&self, p: &Tid) -> BTreeSet<Tid> {
        let Some(d) = self.account_view(p).and_then(|v| v.devices.clone()) else { return BTreeSet::new() };
        d.minter.into_values().chain(d.certifiers.into_values().flatten()).chain(d.adds.into_values().flatten()).chain(d.removes.into_values().flatten()).chain(d.first).collect()
    }

    /// The account `d` is the account root of: its first admin, an account, when that account
    /// wrote `account.0` on it. Only a commit signed as the account counts:
    /// any signer's header can name the aspect, and an account root reads as its account wherever
    /// chains and lists are placed (`Engine::cert_reads_in`), so a thing another writer marked
    /// would carry the account's private lists to its own readers.
    pub(crate) fn account_of_root(&self, d: &Tid) -> Option<Tid> {
        let p = self.first_admin(d).filter(|p| self.is_account(p))?;
        let ak = osis_base::Ak::new("account.0").ok()?;
        let by_p = |(_, c): &(osis_base::Ts, CommitId)| self.ix.commits.get(c).is_some_and(|m| m.view.author == p);
        self.ix.by_aspect.get(&(*d, ak))?.iter().any(by_p).then_some(p)
    }

    /// Whether this node is on D's roster as it reads it, `d` its account root
    /// (`devices_roster`). Whom it boxes and lists for; never what it holds (custody,
    /// `flows::custody`) nor whether it leaves (`signing::leave_if_removed`).
    pub(crate) fn on_root_roster(&self, d: &Tid) -> bool {
        let me = self.id.tid();
        self.account_of_root(d).is_some_and(|p| self.devices_roster(&p).contains(&me))
    }

    /// D's roster of account `p` as this node reads it (`AccountView::roster`): empty but at a
    /// node holding `p`.
    pub(crate) fn devices_roster(&self, p: &Tid) -> BTreeSet<Tid> {
        if !self.accounts.contains_key(p) {
            return BTreeSet::new();
        }
        self.account_view(p).map(|v| v.roster().clone()).unwrap_or_default()
    }

    /// The account held here whose account root is `d`.
    pub(crate) fn held_account_of_root(&self, d: &Tid) -> Option<Tid> {
        self.accounts.iter().find(|(_, a)| a.root == *d).map(|(p, _)| *p)
    }

    /// Who holds a role on `d`, a held account root, and at what: D bears no edge
    /// write, so its roster is the chain's (spec/permissions.md §5.4, Roster), each device on it
    /// at admin, and the account at admin by its record. `None` when `d` is no such actor: its
    /// timeline says.
    pub(crate) fn root_holders(&self, d: &Tid) -> Option<BTreeMap<Tid, Role>> {
        let p = self.held_account_of_root(d)?;
        Some(self.devices_roster(&p).into_iter().chain([p]).map(|m| (m, Role::Admin)).collect())
    }

    pub fn is_account(&self, t: &Tid) -> bool {
        self.created(t).is_some_and(CreationRecord::is_account)
    }

    /// This node's account and its account root, when it holds the account.
    pub fn account_and_root(&self) -> Option<(Tid, Tid)> {
        let p = self.account.get()?;
        Some((p, self.accounts.get(&p)?.root))
    }

    /// The signing chain of account `p` from the rotations held (`None`: `p` is not known as an
    /// account here). A memo (`Core::account_views`): built again only when something it read
    /// changed, so a write does not cost O(its rotations).
    pub(crate) fn account_view(&self, p: &Tid) -> Option<Arc<AccountView>> {
        self.account_views.get(p, || self.build_account_view(p).map(Arc::new))
    }

    /// What `refresh_epochs` compares to judge this node's account `p` again when its chain may
    /// read otherwise (a seed taken up opens who minted a rotation, say). Read without building
    /// the chain: an open notes it and decodes no header.
    fn judged_from(&self, p: &Tid) -> JudgedFrom {
        let a = self.accounts.get(p);
        (self.ix.rotations.get(p).copied().unwrap_or(0), self.sides.account(p), a.map_or(0, |a| a.keys.len()))
    }

    /// The node that signed `id` (a commit of held account `a` signed at the epoch with signing
    /// key `at`) inside, read from its sealed inner signature `inner`.
    fn inner_signer(&self, a: &HeldAccount, at: &VerifyingKey, id: &CommitId, inner: &[u8; osis_crypto::INNER_LEN]) -> Option<Tid> {
        let (node, sig) = open_inner(&a.keys.get(at)?.inner, &id.0, inner)?;
        let CreationRecord::KeyActor { public_key, .. } = self.created(&node)? else { return None };
        verify_inner(&VerifyingKey::from_slice(public_key).ok()?, &id.0, &sig).then_some(node)
    }

    /// What this node reads of its account `p`'s chain as D's roster (spec/permissions.md §5.4,
    /// Following, at a node of P): who minted each held rotation (its inner signature; left out
    /// when it opens to no key actor here) and the membership changes it carries (its sealed
    /// devices field, opened with the seed of the epoch it is signed at; a rotation whose field
    /// does not open here, or whose `revokes` belies it, is left out: minted by no node it
    /// knows); and the account's creation device, read from the creation nonce with the first
    /// epoch's seed. `at`: each held rotation's epoch and header.
    fn devices_read(&self, p: &Tid, a: &HeldAccount, epochs: &BTreeMap<CommitId, EpochPublic>, at: &BTreeMap<CommitId, (CommitId, osis_commit::RotationHeader)>) -> (osis_perm::Devices<CommitId, Tid>, BTreeMap<CommitId, Tid>) {
        let mut d = osis_perm::Devices::default();
        let mut certifier = BTreeMap::new();
        // sealed under the epoch it is signed at, then (`Sigs::more`) a plain rotation's under the
        // epoch it mints, a certificate's under each tip it names, then the merge epoch: it opens
        // with any of those seeds held (spec/crypto.md §3)
        // tests, a fault: seeds of epochs the last judgment counted alone open anything (judgment
        // gates custody)
        #[cfg(test)]
        let gated = |e: &CommitId| !self.faults.custody_judged || *e == FIRST_EPOCH || self.ix.epochs.get(p).is_some_and(|j| j.counts(e));
        #[cfg(not(test))]
        let gated = |_: &CommitId| true;
        let signer = |c: &CommitId, e: &CommitId, r: &osis_commit::RotationHeader| -> Option<Tid> {
            let s = self.ix.role_sigs.get(c)?;
            let keys = std::iter::once(epochs.get(e).filter(|_| gated(e)).map(|x| x.signing)).chain(r.names.iter().map(|n| epochs.get(n).filter(|_| gated(n)).map(|x| x.signing))).chain([gated(&r.mints(c)).then_some(r.signing_key)]);
            let seals = s.inner.iter().chain(s.more.iter());
            keys.zip(seals).find_map(|(k, inner)| self.inner_signer(a, &k?, c, inner))
        };
        for (id, (e, r)) in at {
            let Some(m) = signer(id, e, r) else { continue };
            // a merge certificate: its maker certifies the merge, carrying nothing else
            if r.is_merge() {
                d.certifiers.entry(r.mints(id)).or_default().insert(m);
                certifier.insert(*id, m);
                continue;
            }
            let (adds, removes) = if r.devices.is_empty() {
                (Vec::new(), Vec::new())
            } else {
                let Some(k) = epochs.get(e).filter(|_| gated(e)).and_then(|x| a.keys.get(&x.signing)) else { continue };
                let Some(x) = osis_crypto::open_devices(&k.inner, &r.signing_key, &r.devices) else { continue };
                x
            };
            if r.revokes == removes.is_empty() {
                continue;
            }
            d.minter.insert(*id, m);
            if !adds.is_empty() {
                d.adds.insert(*id, adds.into_iter().collect());
            }
            if !removes.is_empty() {
                d.removes.insert(*id, removes.into_iter().collect());
            }
        }
        // the creation device: the account's creation nonce is `kdf("first device", first seed,
        // its tid)` (spec/crypto.md §3); a candidate is any device the chain names, and this node
        if let (Some(CreationRecord::KeyActor { nonce, .. }), Some(k)) = (self.created(p), a.keys.get(&a.first)) {
            let named = d.minter.values().chain(d.adds.values().flatten()).chain(d.removes.values().flatten()).copied().chain([self.id.tid()]);
            d.first = named.filter(|y| osis_crypto::first_device_nonce(k.seed(), y) == *nonce).collect();
        }
        (d, certifier)
    }

    fn build_account_view(&self, p: &Tid) -> Option<AccountView> {
        let first = match self.created(p) {
            Some(CreationRecord::KeyActor { public_key, account: true, .. }) => VerifyingKey::from_slice(public_key).ok()?,
            Some(_) => return None,
            None => self.accounts.get(p)?.first,
        };
        let ak = osis_base::Ak::new("keys.0").ok()?;
        let rots: Vec<(CommitId, CommitId, osis_commit::RotationHeader)> = self.ix.by_aspect.get(&(*p, ak)).into_iter().flatten().filter_map(|(_, c)| {
            let m = self.ix.commits.get(c).filter(|m| m.view.author == *p)?;
            Some((*c, m.header.epoch?, m.header.rotation.clone()?))
        }).collect();
        // per epoch (a merge's certificates are one): what it supersedes and its keys
        let mut sup: BTreeMap<CommitId, Vec<CommitId>> = BTreeMap::new();
        let mut keys: BTreeMap<CommitId, (VerifyingKey, KemPublicKey)> = BTreeMap::new();
        for (id, _, r) in &rots {
            let e = r.mints(id);
            sup.entry(e).or_insert_with(|| r.supersedes.clone());
            keys.entry(e).or_insert_with(|| (r.signing_key, r.kem_key.clone()));
        }
        let heights = heights(&sup);
        let mut epochs = BTreeMap::new();
        epochs.insert(FIRST_EPOCH, EpochPublic { height: Some(0), signing: first, kem: None, supersedes: Vec::new() });
        for (e, (signing, kem)) in &keys {
            epochs.insert(*e, EpochPublic { height: heights.get(e).copied().flatten(), signing: *signing, kem: Some(kem.clone()), supersedes: sup.get(e).cloned().unwrap_or_default() });
        }
        // a merge certificate is one only with every tip's signature over the epoch it mints
        // (spec/crypto.md §9, Merges); one without is no rotation
        let verified = |id: &CommitId, r: &osis_commit::RotationHeader| -> bool {
            let Some(sigs) = self.ix.role_sigs.get(id) else { return false };
            let e = r.mints(id);
            r.names.len() == sigs.merge.len() && r.names.iter().zip(sigs.merge.iter()).all(|(n, s)| epochs.get(n).is_some_and(|x: &EpochPublic| osis_commit::verify_merge(&e, s, &x.signing)))
        };
        let rots: Vec<(CommitId, CommitId, osis_commit::RotationHeader)> = rots.into_iter().filter(|(id, _, r)| !r.is_merge() || verified(id, r)).collect();
        let certs: BTreeMap<CommitId, CommitId> = rots.iter().filter(|(_, _, r)| r.is_merge()).map(|(id, _, r)| (*id, r.mints(id))).collect();
        epochs.retain(|e, _| *e == FIRST_EPOCH || rots.iter().any(|(id, _, r)| r.mints(id) == *e));
        let mut rotations: BTreeMap<CommitId, Rotation<CommitId>> = BTreeMap::new();
        for (id, at, r) in &rots {
            let e = r.mints(id);
            let rot = if r.is_merge() {
                // one record per merge, read from its tips alone: signed at the lowest
                let mut tips = r.supersedes.iter().copied();
                let at = tips.next().unwrap_or(*at);
                Rotation { id: e, at, supersedes: r.supersedes.iter().copied().collect(), names: tips.collect(), takes: BTreeSet::new() }
            } else {
                Rotation { id: e, at: *at, supersedes: r.supersedes.iter().copied().collect(), names: BTreeSet::new(), takes: r.takes.iter().copied().collect() }
            };
            rotations.entry(e).or_insert(rot);
        }
        let rotations: Vec<Rotation<CommitId>> = rotations.into_values().collect();
        // a node of the account reads the chain as D's roster: who minted each rotation and the
        // membership changes it carries (spec/permissions.md §5.4, Following, at a node of P)
        let read = self.accounts.get(p).map(|a| {
            let at: BTreeMap<CommitId, (CommitId, osis_commit::RotationHeader)> = rots.iter().map(|(id, at, r)| (*id, (*at, r.clone()))).collect();
            self.devices_read(p, a, &epochs, &at)
        });
        let (devices, certifier) = match read {
            Some((d, c)) => (Some(d), Some(c)),
            None => (None, None),
        };
        // the order this node came to hold the epochs in: by receipt (a merge's first
        // certificate's), one millisecond's by ID
        let mut held_at: BTreeMap<CommitId, osis_base::WallMs> = BTreeMap::new();
        for (id, _, r) in &rots {
            let Some(t) = self.ix.commits.get(id).map(|m| m.received) else { continue };
            held_at.entry(r.mints(id)).and_modify(|x| *x = (*x).min(t)).or_insert(t);
        }
        let mut order: Vec<(osis_base::WallMs, CommitId)> = held_at.iter().map(|(e, t)| (*t, *e)).collect();
        order.sort();
        let received: Vec<CommitId> = order.into_iter().map(|x| x.1).collect();
        let chosen = self.sides.account(p);
        // what revokes (spec/permissions.md §5.5 Revoked): the header's word, read alike at every
        // node, a node of P included (only a rotation counting here revokes)
        let carrying: BTreeSet<CommitId> = rots.iter().filter(|(_, _, r)| r.revokes).map(|(id, ..)| *id).collect();
        let rule = Epochs::new(FIRST_EPOCH, rotations.clone(), chosen, &received, devices.as_ref(), &carrying, &[], &[]);
        #[cfg_attr(not(test), allow(unused_mut))]
        let mut roster = devices.as_ref().map(|d| rule.chain().roster(&rule.chain().preferred(), d)).unwrap_or_default();
        // tests, a fault: a held revocation by a node on the roster removes from it, its rotation
        // followed or not
        #[cfg(test)]
        if self.faults.roster_bare
            && let Some(d) = &devices
        {
            let makers = roster.clone();
            for (r, ys) in &d.removes {
                if d.minter.get(r).is_some_and(|m| makers.contains(m)) {
                    for y in ys {
                        roster.remove(y);
                    }
                }
            }
        }
        let revoked = epochs.iter().filter(|(e, _)| rule.revoked(e)).map(|(_, e)| e.signing.to_bytes()).collect();
        let standing_certs = match (devices.as_ref(), certifier) {
            (Some(d), Some(by)) => {
                let ok = rule.chain().standing_certifiers(d);
                certs.iter().filter(|(c, m)| by.get(*c).is_some_and(|y| ok.get(*m).is_some_and(|ys| ys.contains(y)))).map(|(c, _)| *c).collect()
            }
            _ => certs.keys().copied().collect(),
        };
        let mut v = AccountView { rule, rotations, chosen, received, devices, roster, epochs, certs, standing_certs, held_at, by_name: BTreeMap::new(), carrying, revoked };
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

    /// The epoch this node signs as `p` at and its keys: the preferred head, when it holds its seed
    /// (spec/permissions.md §5.5). `None` when `p` is no account held here.
    pub(crate) fn account_signing(&self, p: &Tid) -> Result<Option<(CommitId, Arc<AccountEpochKeys>)>> {
        let Some(a) = self.accounts.get(p) else { return Ok(None) };
        let v = self.account_view(p).ok_or(Error::Misuse("no signing chain for the account"))?;
        let (id, keys) = v.open_epoch().and_then(|(id, e)| Some((*id, a.keys.get(&e.signing)?.clone()))).ok_or(Error::Misuse("the account's open epoch is not held"))?;
        Ok(Some((id, keys)))
    }

    /// The public signing key of account `p` at its open epoch while this node holds that
    /// epoch's seed (`account_signing` without deriving anything).
    pub(crate) fn account_open_key(&self, p: &Tid) -> Option<[u8; 32]> {
        let a = self.accounts.get(p)?;
        let v = self.account_view(p)?;
        let (_, e) = v.open_epoch()?;
        a.keys.contains_key(&e.signing).then(|| e.signing.to_bytes())
    }

    /// The role epochs of account `p` this node holds seeds of (spec/crypto.md §3), internal to
    /// its nodes.
    pub(crate) fn account_epochs(&self, p: &Tid) -> Option<ActorEpochs> {
        self.account_epochs_of.get(p, || {
            let a = self.accounts.get(p)?;
            let v = self.account_view(p)?;
            let seed = |e: &EpochPublic| a.keys.get(&e.signing).map(|k| k.seed().clone());
            let held: Vec<_> = v.epochs.values().filter_map(|e| {
                let sup = e.supersedes.iter().filter_map(|s| v.epochs.get(s)).filter_map(|x| Some((x.height?, seed(x)?))).collect();
                Some((e.height?, seed(e)?, sup))
            }).collect();
            ActorEpochs::account(p, &held).ok()
        })
    }

    /// The epoch keys of `p` held, by signing key (the key half of an epoch's name,
    /// spec/crypto.md §3): every seed in custody, whether or not its epoch counts, is open, is
    /// revoked or has a known name (custody follows holding: stale means not encrypted under,
    /// re-sealed or rotated from, never unread, spec/crypto.md §4 Account keysets).
    pub(crate) fn account_keys(&self, p: &Tid) -> BTreeMap<[u8; 32], Arc<AccountEpochKeys>> {
        let Some(a) = self.accounts.get(p) else { return BTreeMap::new() };
        #[cfg(test)]
        let shut = |k: &VerifyingKey| {
            self.faults.stale_shut
                && self.account_view(p).is_some_and(|v| v.epochs.iter().any(|(id, e)| e.signing == *k && (*id != FIRST_EPOCH && !v.rotation_counts(id) || v.revoked(&k.to_bytes()))))
        };
        #[cfg(not(test))]
        let shut = |_: &VerifyingKey| false;
        a.keys.iter().filter(|(k, _)| !shut(k)).map(|(k, e)| (k.to_bytes(), e.clone())).collect()
    }

    /// An account's delete key (spec/crypto.md §7): the signing key of its preferred head.
    pub(crate) fn account_delete_key(&self, p: &Tid) -> Option<VerifyingKey> {
        Some(self.account_view(p)?.open_epoch()?.1.signing)
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
/// those signed at an epoch whose standing moved (where only its closers moved, those an addendum
/// keyed by a closer joining or leaving lists: `Indexes::addenda_keyed`), the rotation minting
/// it, those a rotation whose
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
    // this node's account: what D says moves its chain (`osis_perm::Devices`) and what it
    // authorizes (`AccountView::authorized_by`)
    if let Some((p, from)) = tx.core.account.get().filter(|p| tx.core.accounts.contains_key(p)).map(|p| (p, tx.core.judged_from(&p))).filter(|(_, from)| tx.core.epochs_judged_from.as_ref() != Some(from)) {
        // after an open the persisted judgment stands: judged again, sealed to as before
        if tx.core.epochs_judged_from.replace(from).is_some() {
            tx.core.ix.epochs_due.insert(p);
        }
    }
    for p in tx.core.ix.epochs_due.iter().copied().collect::<Vec<_>>() {
        tx.core.ix.epochs_due.remove(&p);
        by_account.entry(p).or_default();
    }
    let mut moved_roles = false;
    for (p, due) in by_account {
        // this node's account: the merge seeds it derives first (a merge's tips are plain, so
        // one round), as they open who certified what
        if tx.core.account.get() == Some(p) && tx.core.accounts.contains_key(&p) {
            super::custody::derive_merges(tx, &p)?;
        }
        let Some(v) = tx.core.account_view(&p) else { continue };
        let now = v.judged();
        let was = tx.core.ix.epochs.get(&p).cloned();
        let get = |j: &Option<Arc<JudgedEpochs>>, e: &CommitId| match j {
            Some(j) => j.epochs.get(e).cloned(),
            None => (*e == FIRST_EPOCH).then_some((EpochStanding::Counts, None)),
        };
        let old: BTreeSet<CommitId> = was.as_ref().map_or_else(|| [FIRST_EPOCH].into(), |j| j.epochs.keys().copied().collect());
        let moved: BTreeSet<CommitId> = now.keys().copied().chain(old).filter(|e| now.get(e).cloned() != get(&was, e)).collect();
        // an epoch come to be held: what pends on it is examined again (`waits::Wake::Epoch`)
        tx.core.waits.epochs_held.extend(moved.iter().filter(|e| now.get(*e).is_some_and(|x| x.1.is_some()) && get(&was, e).is_none_or(|x| x.1.is_none())).copied());
        let mut cands: BTreeSet<CommitId> = due;
        for e in &moved {
            match (now.get(e), get(&was, e)) {
                // only its closers moved (a rotation joined or left them): what an addendum keyed
                // by one of those lists, the one thing a closer decides (`Vouching::saves`)
                (Some((EpochStanding::Closed(a), x)), Some((EpochStanding::Closed(b), y))) if *x == y => {
                    for r in a.symmetric_difference(&b) {
                        for (t, s) in tx.core.ix.addenda_keyed.get(r).into_iter().flatten() {
                            let listed = tx.core.ix.addenda.get(&(*t, *s)).into_iter().flat_map(|x| x.entries.iter()).filter(|(k, _)| k == r).flat_map(|(_, l)| l.iter());
                            cands.extend(listed.filter(|c| tx.core.ix.commits.get(*c).is_some_and(|m| m.view.author == p && m.view.epoch == Some(*e))));
                        }
                    }
                }
                _ => cands.extend(tx.core.ix.by_epoch.get(&(p, *e)).into_iter().flatten().copied()),
            }
            cands.insert(*e);
            // a rotation whose count moved: what its lists name
            if now.get(e).map(|x| x.1) != get(&was, e).map(|x| x.1) {
                cands.extend(super::lists::named_by(tx, e)?.into_iter().map(|(c, _)| c));
                // invariant: every rotation that counts here is due this node's answer once it
                // counts. One read as void when it arrived (its minter not known yet: the seed
                // its inner signature opens with still to come) was answered by nothing, and the
                // writes at the epochs it closes would wait on a listing never written
                // (`signing::answer_rotations`). A rotation first judged here was noted due as it
                // applied. A second answer names only what no word held names yet, so a rotation
                // counting again (a user's switch) writes nothing twice
                if now.get(e).and_then(|x| x.1) == Some(true) && get(&was, e).and_then(|x| x.1) == Some(false) {
                    super::signing::note_rotation_due(tx, e)?;
                }
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
            Some(osis_perm::AccountCommit { id: *c, epoch: m.view.epoch?, things: things_of(&m.view), role: m.view.kind.is_role() })
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
        let rule = Epochs::new(FIRST_EPOCH, v.rotations.iter().cloned(), v.chosen, &v.received, v.devices.as_ref(), &v.carrying, &lists, &listings);
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
        let doubt = v.doubt();
        let keyed: BTreeSet<[u8; 32]> = tx.core.account_keys(&p).into_keys().collect();
        let more_keyed = keyed.iter().any(|e| was.as_ref().is_none_or(|j| !j.keyed.contains(e)));
        let judged = Arc::new(JudgedEpochs { epochs: now, named, doubt: doubt.is_some(), keyed });
        if was.as_deref() == Some(&*judged) {
            continue;
        }

        if let Some((lines, side)) = doubt.filter(|_| !was.as_ref().is_some_and(|j| j.doubt)) {
            tx.core.events.queue(crate::events::Event::AccountDisputed { account: p, lines, side });
        }
        // the first epoch alone, open, named nothing, is what no entry says: the index is a
        // function of what is held, a rotation dropped included
        if judged.epochs.len() == 1 && judged.named.is_empty() && !judged.doubt && judged.keyed.is_empty() && get(&None, &FIRST_EPOCH) == judged.epochs.get(&FIRST_EPOCH).cloned() {
            tx.core.ix.epochs.remove(&p);
        } else {
            tx.core.ix.epochs.insert(p, judged.clone());
        }
        // a seed of the account come to be held: the boxes sealed to the account open now
        if more_keyed {
            super::reopen_dependents(tx, p)?;
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
            // a snapshot waiting for what it would carry to last (`signing::lasts`) is weighed again
            for t in things_of(&m.view) {
                crate::retention::replace::standing_moved(tx.core, &t);
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
    let keys = tx.core.accounts.get(p).and_then(|a| a.keys.get(&e.signing).cloned());
    Ok(Some(HolderKeys::Account { epoch: *name, kem, keys }))
}

/// How a box to account `p` is sealed with no anchors to descend from: at its preferred head.
pub(crate) fn holder_keys(tx: &mut Tx<'_>, p: &Tid) -> Result<HolderKeys> {
    let v = tx.core.account_view(p).ok_or(Error::UnknownThing(*p))?;
    let (_, e) = v.open_epoch().ok_or(Error::Corrupt("the account's open epoch"))?;
    let name = v.name(e).ok_or(Error::Misuse("account epoch"))?;
    holder_keys_at(tx, p, &name)?.ok_or(Error::Misuse("no keys.0 of the account's epoch held"))
}

/// The reader key of a sync ID for account `p` (spec/sync-ids.md §3): the X25519 half of its
/// preferred head's KEM key. `None`: its KEM key is not held here.
pub(crate) fn reader_key(tx: &mut Tx<'_>, p: &Tid) -> Result<Option<ReaderKey>> {
    let Some(v) = tx.core.account_view(p) else { return Ok(None) };
    let Some((_, e)) = v.open_epoch() else { return Ok(None) };
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

impl Engine {
    /// Creates an account (spec/permissions.md §1): the account at its first epoch (its creation
    /// nonce naming this node as its creation device, spec/crypto.md §3), its account root D
    /// (secrets of its own boxed to this node, its sync ID, `account.0`) and its profile, one
    /// commit signed as the account.
    pub fn create_account(&mut self) -> Result<(CreatedAccount, Done)> {
        let (seed, nonce_d) = self.run(|tx| Ok((Secret32::random(&mut *tx.rng), thing_record(Tid::from_bytes([0; 15]), &mut *tx.rng))))?;
        // the creation nonce names this node, the creation device, to holders of the first seed
        let nonce = osis_crypto::first_device_nonce(&seed, &self.core.id.tid());
        let keys = Arc::new(AccountEpochKeys::from_seed(&seed));
        let signing = keys.signing.verifying_key();
        let record = CreationRecord::KeyActor { alg: SIGNING_KEY_ED25519, public_key: signing.to_bytes().to_vec(), nonce, account: true };
        let p = record.tid();
        let d_record = CreationRecord::Thing { admin: p, nonce: *nonce_d.nonce(), link: None };
        let d = d_record.tid();
        self.core.account.set(Some(p));
        self.core.accounts.insert(p, Arc::new(HeldAccount { root: d, first: signing, keys: [(signing, keys.clone())].into() }));
        let res = self.run(|tx| create_account_in(tx, record, d_record, &keys));
        if res.is_err() {
            self.core.account.set(None);
            self.core.accounts.remove(&p);
        }
        let (profile, done) = res?;
        self.save_account(&p, &d)?;
        Ok((CreatedAccount { account: p, root: d, profile }, done))
    }

    /// Takes up account `p` from the seeds on its account root `d` (`account.0`, readable here
    /// as a node of the account): this node signs as it and its boxes open, and judges its chain
    /// as a node of it.
    pub fn hold_account(&mut self, p: &Tid, d: &Tid) -> Result<()> {
        self.take_up(p, d, true)
    }

    /// `hold_account`: this node becomes a node of `p` (`Core::member`: the account and its seeds
    /// held, both set before anything is judged or opened, as an open sets them), so every box
    /// opens by the roles the node holds as `p`, as a rebuild opens it. `judge`: the account's
    /// epochs judged again in the same transaction. The
    /// epoch rule reads D (`AccountView::devices`, and the seeds opening inner signatures) only
    /// at a node holding the account, so its judgment of the chain moves whenever the account is
    /// taken up or left (`signing::leave`), and the index is a function of what is held (a
    /// rebuild judges with the account as held now). Only the take-up at open (`take_account`)
    /// skips it: the persisted judgment was made with the account held.
    fn take_up(&mut self, p: &Tid, d: &Tid, judge: bool) -> Result<()> {
        let Some(CreationRecord::KeyActor { public_key, account: true, .. }) = self.core.created(p).cloned() else { return Err(Error::UnknownThing(*p)) };
        let first = VerifyingKey::from_slice(&public_key).map_err(|_| Error::Misuse("account key"))?;
        let p0 = *p;
        let keys = self.read(|tx| super::custody::seeds(tx, &p0))?;
        if keys.is_empty() {
            return Err(Error::Misuse("no seed of the account in custody here"));
        }
        let was = self.core.account.get();
        self.core.account.set(Some(*p));
        self.core.accounts.insert(*p, Arc::new(HeldAccount { root: *d, first, keys }));
        let (p, d) = (*p, *d);
        let r = self.run(|tx| {
            match judge {
                true => super::signing::judge_account_again(tx, p, d)?,
                false => super::reopen_all(tx)?,
            }
            super::take_up_opener(tx, p)
        });
        if r.is_err() {
            self.core.account.set(was);
            self.core.accounts.remove(&p);
        }
        r
    }

    /// How a box to account `p` is sealed: at its open epoch.
    pub fn account_holder_keys(&mut self, p: &Tid) -> Result<HolderKeys> {
        let a = *p;
        self.read(|tx| holder_keys(tx, &a))
    }

    /// Sets `cb` up to be signed as this node's account (a node that joined no account signs as
    /// itself), returning the key to build it with: for tests forging a commit.
    #[doc(hidden)]
    pub fn sign_forged(&self, cb: &mut osis_commit::CommitBuilder) -> osis_crypto::SigningSecret {
        let held = self.core.me().and_then(|me| self.core.account_signing(&me).ok().flatten());
        let Some((epoch, k)) = held else { return self.core.id.keys().signing.clone() };
        cb.account = Some(osis_commit::AccountSigner { epoch, inner: k.inner.clone(), node: self.core.id.tid(), node_key: self.core.id.keys().signing.clone(), more: Vec::new() });
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
        blob.sigs = osis_commit::Sigs::signed(&id, &key, inner, Vec::new(), Vec::new());
    }

    /// The KEM secrets of account `p`'s epochs held here: what opens what is sealed to it
    /// (spec/crypto.md §5).
    pub fn account_kems(&self, p: &Tid) -> Vec<osis_crypto::KemSecret> {
        self.core.accounts.get(p).map(|a| a.keys.values().map(|k| k.kem.clone()).collect()).unwrap_or_default()
    }

    /// The account this node belongs to and its account root, once it has joined one.
    pub fn account(&mut self) -> Result<Option<(Tid, Tid)>> {
        let Some(b) = self.read(|tx| Ok(tx.txn.get_local(records::ACCOUNT)?))? else { return Ok(None) };
        let pair = |r: std::ops::Range<usize>| b.get(r).and_then(|x| <[u8; 15]>::try_from(x).ok()).map(Tid::from_bytes);
        Ok(Some((pair(0..15).ok_or(Error::Corrupt("account record"))?, pair(15..30).ok_or(Error::Corrupt("account record"))?)))
    }

    fn save_account(&mut self, p: &Tid, d: &Tid) -> Result<()> {
        let v = [p.as_bytes().as_slice(), d.as_bytes().as_slice()].concat();
        self.run(|tx| Ok(tx.txn.put_local(records::ACCOUNT, &v, Shred::No)?))
    }

    /// Re-takes this node's account seeds at open (`hold_account`) from its custody records
    /// (`flows::custody`).
    pub(crate) fn take_account(&mut self) -> Result<()> {
        let Some((p, d)) = self.account()? else { return Ok(()) };
        self.core.account.set(Some(p));
        // a take-up that fails holds no seed of the account
        let _ = self.take_up(&p, &d, false);
        // no seed in custody (it left before what it read as the account went): it goes now
        if !self.core.accounts.contains_key(&p) {
            self.run(|tx| super::signing::leave(tx, p, d))?;
        }
        Ok(())
    }

    /// Pairing, existing node side (spec/sync-inbox.md §1: the only way a node joins an account):
    /// `node`'s card (`created.0`, `keys.0`) was received over the direct connection. A node
    /// not on D's roster is added by a rotation of the account (spec/permissions.md §1: the
    /// rotation's membership changes add it), boxing it every seed held here (its custody,
    /// spec/crypto.md §9) and D's new secrets; one on it (stranded) is re-sealed D's secrets, its
    /// seeds following by the seed re-seals. Returns the commits to send it directly: the
    /// rotation or re-seal, D's and P's certificates and D's `sync.0` commits (the new node
    /// downloads the rest under D's sync ID).
    pub fn pair(&mut self, node: &Tid) -> Result<(Done, Vec<CommitId>)> {
        let (p, d) = self.account()?.ok_or(Error::Misuse("not a node of an account"))?;
        let n = *node;
        if !self.knows(&n) {
            return Err(Error::UnknownThing(n));
        }
        let done = if self.core.devices_roster(&p).contains(&n) {
            self.reshare(&d, &n)?
        } else {
            // the rotation adding it: it boxes the node a new seed and every seed held here, its
            // custody of the account (spec/crypto.md §9, Custody)
            self.run(|tx| {
                let mut inner = Done::default();
                let r = super::signing::rotate_with(tx, p, &[], &super::signing::Members { adds: vec![n], removes: Vec::new() }, &mut inner)?.ok_or(Error::Misuse("the account's open epoch cannot be rotated here yet"))?;
                inner.add(Some(r));
                Ok(inner)
            })?
        };
        // D's certificates as this node logs them, and every roster node's card and record
        // (`own_piece`): the new node reads each rotation's minter by them, the creation device's
        // included; records travel as the commits minting them
        let mut certs = self.certificates(&d);
        certs.extend(self.own_piece(&d));
        let mut all: Vec<CommitId> = certs.commits.into_keys().chain(certs.headers).chain(certs.mintings.into_keys()).collect();
        let sync_id = osis_base::Ak::new("sync.0").map_err(|_| Error::Misuse("ak"))?;
        all.extend(self.core.ix.by_aspect.get(&(d, sync_id)).into_iter().flatten().map(|(_, c)| *c));
        // the account's seed-boxing commits on D (`account.0`): its creation, P's creation record
        // among it; its rotations (with their thing lists, `Package::lists`), so what they name
        // counts at the new node; its seed re-seals
        let seeds = osis_base::Ak::new("account.0").map_err(|_| Error::Misuse("ak"))?;
        all.extend(self.core.ix.by_aspect.get(&(d, seeds)).into_iter().flatten().map(|(_, c)| *c));
        all.sort_by_key(|c| self.header(c).map(|h| h.ts));
        // the rotation or re-seal last
        all.extend(done.commits.iter().copied());
        // each commit once, in the order collected
        let mut seen = BTreeSet::new();
        all.retain(|c| seen.insert(*c));
        Ok((done, all))
    }

    /// Removes device `node` from this node's account (spec/permissions.md §3): a rotation of the
    /// account carrying the removal, boxing the new seed and D's new secrets to every other device
    /// on D's roster. `node` holds no seed of the new epoch.
    pub fn remove_device(&mut self, node: &Tid) -> Result<Done> {
        let (p, _) = self.account()?.ok_or(Error::Misuse("not a node of an account"))?;
        if !self.core.devices_roster(&p).contains(node) {
            return Err(Error::Misuse("not a device on the account's roster"));
        }
        let n = *node;
        self.run(|tx| {
            let mut done = Done::default();
            let r = super::signing::rotate_with(tx, p, &[], &super::signing::Members { adds: Vec::new(), removes: vec![n] }, &mut done)?.ok_or(Error::Misuse("the account's open epoch cannot be rotated here yet"))?;
            done.add(Some(r));
            Ok(done)
        })
    }

    /// Pairing, new node side, after applying what `pair` sent, in the same hold of the engine
    /// (no pass ends between, so what arrived is still held, spec/commits.md §5 What a held thing
    /// needs): joins account `p`, checking the chain puts it on D's roster.
    pub fn paired(&mut self, p: &Tid) -> Result<()> {
        let node = self.tid();
        let d = self.root_held(p).ok_or(Error::UnknownThing(*p))?;
        self.hold_account(p, &d)?;
        if !self.core.devices_roster(p).contains(&node) {
            self.core.accounts.remove(p);
            self.core.account.set(None);
            return Err(Error::Permission { tid: d });
        }
        self.save_account(p, &d)?;
        // the node root's strong to the account root (spec/sync-set.md §1)
        self.hold(osis_base::Strong(d))
    }

    /// The account root of account `p` as held here: a thing with `account.0` that is `p`'s
    /// (`Core::account_of_root`).
    pub fn root_held(&self, p: &Tid) -> Option<Tid> {
        let ak = osis_base::Ak::new("account.0").ok()?;
        self.core.ix.aspect_things.get(&ak)?.iter().find(|t| self.core.account_of_root(t) == Some(*p)).copied()
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
        self.inner_signer(a, &e.signing, &h.id(), inner)
    }
}

fn create_account_in(tx: &mut Tx<'_>, record: CreationRecord, d_record: CreationRecord, keys: &AccountEpochKeys) -> Result<(Tid, Done)> {
    let p = record.tid();
    let me = tx.core.id.tid();
    let mut m = Mutation::new();
    m.create(record);
    let d = m.create(d_record);
    let profile = m.create(thing_record(p, &mut *tx.rng));
    let inbox = m.create(thing_record(p, &mut *tx.rng));
    m.sign_as(p);
    let held = ActorEpochs::derived(&tx.core.account_epochs(&p).ok_or(Error::Misuse("account not held"))?, &d);
    let node_kem = tx.core.id.keys().kem.public().clone();
    let holders = rotation::Boxing { holders: vec![Recipient { holder: me, role: Role::Admin, keys: HolderKeys::KeyActor { kem: node_kem.clone(), seed: None }, floor: 0 }], left_out: Default::default() };
    let rot = rotation::rotation_into(tx, &mut m, d, &ROLES.into_iter().collect(), &held, &holders, crate::rotation::Departs::No)?;
    let after = rot.preview(&held)?;
    // D's own deposit seed (spec/crypto.md §3), fresh with each of its sync rotations
    let dep = rotation::fresh_deposit_seed(tx, &mut m, d)?;
    new_sync_id(tx, &mut m, d, &after, &[ReaderKey::Dh(node_kem.x25519())], &dep)?;
    m.set(p, &ct::KEYS, &Keys { inbox: Some(osis_base::Weak(inbox)), ..osis_keys::aspects::account_keys(keys) })?;
    // this node is the creation device, fixed by the account's tid (`create_account`): D bears
    // no edge write, its roster is the chain's
    m.op(d, &ct::ACCOUNT, PathOp { path: vec![], op: Op::Add(Value::bytes(&keys.signing.verifying_key().to_bytes())) })?;
    super::custody::keep(tx, &p, keys.seed())?;
    let c = Engine::commit_tx(tx, m)?;
    rotation::record(tx, d, &rot)?;
    let mut done = Done::default();
    done.add(c);
    // the profile and the inbox have own keys from the account's creation (spec/sync-set.md §1)
    rotation::own_secrets(tx, profile, &mut done)?;
    super::inbox::make_inbox(tx, inbox, &mut done)?;
    // the account root strongly references the profile, the inbox and this node's node thing,
    // and the node root the account root (spec/sync-set.md §1)
    let mut m = Mutation::new();
    m.sign_as(p);
    for t in [profile, inbox, me] {
        m.op(d, &ct::HOLDS, PathOp { path: vec![], op: Op::Add(Value::Strong(t)) })?;
    }
    done.add(Engine::commit_tx(tx, m)?);
    super::roots::hold_in(tx, d)?;
    // the account's tickets for the profile and the inbox, which the walk now enters from D
    // (spec/sync-set.md §1 The account's tickets)
    crate::sync::units::settle(tx)?;
    for t in [profile, inbox] {
        done.add(super::inbox::write_account_ticket(tx, &t)?);
    }
    Ok((profile, done))
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
