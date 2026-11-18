//! What a node of account P writes of P's signing chain (spec/permissions.md §3, §5.5,
//! spec/crypto.md §9): the rotation a removal from P's account root D requires, with its thing
//! lists; its take-up of the seeds D's `account.0` holds.
//!
//! Principle: a revocation ends the standing of what was signed at the epochs it closes, so a
//! rotation names what its rotator holds there (its thing lists), as a demotion's frontier names
//! what its demoter holds; every rotation names, as a later removal revokes earlier epochs.

use super::account::things_of;
use super::Done;
use crate::engine::write::{writable_now, writable_split};
use crate::engine::{Engine, Step, Tx, records};
use crate::error::{Error, Result};
use crate::events::{Diagnostic, DiagnosticKind};
use crate::Mutation;
use osis_base::format::CHUNK_THRESHOLD;
use osis_base::{CommitId, Tid, Value};
use osis_crdt::{Op, PathOp, PathSeg};
use osis_store::Shred;
use osis_commit::RotationHeader;
use osis_commit::thing_list::{ListIds, ThingCert, ThingList};
use osis_crypto::{AccountEpochKeys, Secret32, SigningSecret};
use osis_perm::epochs::{fit_list, list_leaf, list_tree};
use osis_schema::Codec;
use osis_schema::core_types as ct;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// A rotation of the signing account's chain as its commit carries it: the header's rotation,
/// the key of each tip a merge certificate names (its merge signatures), and its thing lists by leaf (index,
/// sibling hashes), certs once its commit ID is known.
#[derive(Clone, Debug)]
pub(crate) struct AccountRotation {
    pub header: RotationHeader,
    pub merge_keys: Vec<SigningSecret>,
    /// The inner secret of each other epoch its inner signature is sealed under
    /// (`osis_commit::Sigs::more`): a plain rotation's new epoch; a merge's named tips, then its
    /// own.
    pub more: Vec<Secret32>,
    pub lists: Lists,
    /// A merge's: the head it is signed at and that epoch's keys (else the open epoch).
    pub at: Option<(CommitId, Arc<AccountEpochKeys>)>,
}

impl AccountRotation {
    pub(crate) fn certs(&self, rotation: CommitId) -> Vec<ThingCert> {
        self.lists.iter().map(|(index, siblings, list)| ThingCert { rotation, index: *index, siblings: siblings.clone(), list: list.clone() }).collect()
    }
}

/// A rotation's thing lists by leaf: index, sibling hashes, list.
pub(crate) type Lists = Vec<(u64, Vec<[u8; 32]>, ThingList)>;

/// A thing's listed commits: role-class and purge-request ones, then dependent ones by receipt.
type PerThing = (BTreeSet<CommitId>, Vec<(osis_base::WallMs, CommitId)>);

/// The membership changes of D a rotation carries (spec/permissions.md §1, §5.4): the devices it
/// adds (a pairing) and those it removes. No addition or removal exists apart from its rotation.
#[derive(Clone, Debug, Default)]
pub(crate) struct Members {
    pub adds: Vec<Tid>,
    pub removes: Vec<Tid>,
}

/// A plain rotation of account `p`'s epoch (spec/permissions.md §3, §5.5; spec/crypto.md §9): a
/// role commit signed at the preferred head, minting an epoch with a fresh random seed its header
/// boxes to each device on D's roster (`custody::seed_boxes`) and whose public keys go into P's
/// `keys.0`, re-keying D to that roster in the same commit. It names no fork: it supersedes the
/// preferred head and the held rotations a removed node minted that no rotation answers yet
/// (`unanswered`: superseded unnamed, so it rejects them), and takes the revocations this node
/// took off its line. Its thing lists name the commits of P this node holds at the epochs it
/// closes that no word names, by the cutoff (`nameable`: at an open epoch every one received),
/// cut per thing it has a delta on or acts for; within the bound, plain content past it left to
/// this node's listings. `None`: the preferred head's seed is not held here.
pub(crate) fn rotate_in(tx: &mut Tx<'_>, p: Tid, also: &[CommitId], done: &mut Done) -> Result<Option<CommitId>> {
    rotate_with(tx, p, also, &Members::default(), done)
}

/// `rotate_in` carrying membership changes `members`: its header seals them (spec/crypto.md §9,
/// Roster); a device it adds is boxed every seed this node holds besides the new one (Custody),
/// one it removes nothing.
pub(crate) fn rotate_with(tx: &mut Tx<'_>, p: Tid, also: &[CommitId], members: &Members, done: &mut Done) -> Result<Option<CommitId>> {
    let held = tx.core.accounts.get(&p).cloned().ok_or(Error::Misuse("not an account held here"))?;
    let v = tx.core.account_view(&p).ok_or(Error::Misuse("no signing chain for the account"))?;
    // an open epoch whose seed is not here yet: nothing to act at
    let Some((at, at_keys)) = tx.core.account_signing(&p).ok().flatten() else { return Ok(None) };
    let _ = done;
    // the revocations this node took that the new rotation's line does not carry (on it, or
    // taken by a rotation on it): it stands with them (spec/permissions.md §5.4), so a node that
    // took another revocation reads it as that side
    let line = v.line(&at).unwrap_or_default();
    let carried = |t: &CommitId| *t == at || line.contains(t) || line.iter().any(|q| v.takes_of(q).contains(t));
    let mut takes: Vec<CommitId> = v.taken().iter().copied().filter(|t| !carried(t)).collect();
    takes.sort();
    // a removed node's rotation no authorized one answers yet: superseded unnamed, rejected
    let mut supersedes = vec![at];
    for r in unanswered(&v, &tx.core.id.tid()) {
        if !supersedes.contains(&r) {
            supersedes.push(r);
        }
    }
    let own = own_covers(tx, &p, &supersedes)?;
    let also: Vec<CommitId> = also.iter().copied().chain(own).collect();
    let (root, lists) = thing_lists(tx, &p, &v, &supersedes, &also)?;
    let seed = Secret32::random(&mut *tx.rng);
    let keys = AccountEpochKeys::from_seed(&seed);
    let signing = keys.signing.verifying_key();
    // its roster: D's on its line, after its membership changes
    let base = v.roster_joining(&[at]);
    let mut roster = base.clone();
    roster.retain(|x| !members.removes.contains(x));
    roster.extend(members.adds.iter().copied());
    let newcomers: BTreeSet<Tid> = roster.iter().filter(|x| !base.contains(*x)).copied().collect();
    let seeds = super::custody::seed_boxes(tx, &p, &seed, &roster, &newcomers, &line)?;
    let (mut adds, mut removes) = (members.adds.clone(), members.removes.clone());
    adds.sort();
    removes.sort();
    let devices = if adds.is_empty() && removes.is_empty() { Vec::new() } else { osis_crypto::seal_devices(&at_keys.inner, &signing, &adds, &removes) };
    supersedes.sort();
    let header = RotationHeader { signing_key: signing, kem_key: keys.kem.public().clone(), supersedes, names: Vec::new(), takes, revokes: !removes.is_empty(), devices, list_root: root, seeds };
    let rotation = AccountRotation { header, merge_keys: Vec::new(), more: vec![keys.inner.clone()], lists, at: None };
    commit_rotation(tx, p, held.root, &keys, &roster, rotation)
}

/// The merge of every head of this node's account (spec/crypto.md §9, Merges): a certificate of
/// the epoch whose seed is `kdf("merge seed", tips' seeds)`, its tips the plain rotations maximal
/// on the heads' lines. It carries only the join: no lists, takes, answers or membership
/// changes; it boxes the seed to the roster devices this node does not see holding every tip's
/// seed (with every seed it holds, as to a newcomer). Signed at its lowest tip, each other tip
/// signing the epoch's ID. `None`: one head, a tip's seed not held here, or a certificate of
/// that epoch standing here held already (one that stands with nothing, by a certifier no node
/// of its line or hit by a taken removal, makes nothing: another node's certificate would
/// otherwise block the merge for good).
pub(crate) fn merge_heads(tx: &mut Tx<'_>, p: Tid) -> Result<Option<CommitId>> {
    let held = tx.core.accounts.get(&p).cloned().ok_or(Error::Misuse("not an account held here"))?;
    let v = tx.core.account_view(&p).ok_or(Error::Misuse("no signing chain for the account"))?;
    let heads = v.heads();
    let Some((tips, keys)) = merge_of(&v, &held, &heads) else { return Ok(None) };
    // tests, a fault: a merge mints its own epoch with a fresh seed, boxed to the whole roster
    #[cfg(test)]
    let keys = if tx.core.faults.merge_random { AccountEpochKeys::from_seed(&Secret32::random(&mut *tx.rng)) } else { keys };
    let epoch = osis_commit::merge_epoch(&keys.signing.verifying_key(), &tips);
    if v.minting(&epoch).iter().any(|c| v.rotation_counts(c)) {
        return Ok(None);
    }
    let tip_keys: Vec<Arc<AccountEpochKeys>> = tips.iter().filter_map(|t| v.keys_of(t, &held)).collect();
    let (Some(at), Some(at_keys)) = (tips.first().copied(), tip_keys.first().cloned()) else { return Ok(None) };
    let roster = v.roster_joining(&heads);
    let me = tx.core.id.tid();
    let derive = super::custody::derivers(tx.core, &v, &held.root, &tip_keys);
    #[cfg(test)]
    let derive = if tx.core.faults.merge_random { BTreeSet::new() } else { derive };
    let lacking: BTreeSet<Tid> = roster.iter().filter(|m| **m != me && !derive.contains(*m)).copied().collect();
    // at least one box (spec/wire.md §4): its maker's own when every device derives it
    let boxed: BTreeSet<Tid> = if lacking.is_empty() { [me].into() } else { lacking.clone() };
    let line: BTreeSet<CommitId> = tips.iter().filter_map(|t| v.line(t)).flatten().collect();
    let seeds = super::custody::seed_boxes(tx, &p, keys.seed(), &boxed, &lacking, &line)?;
    let rng = &mut *tx.rng;
    let (root, _) = list_tree(&[], || {
        let mut b = [0u8; 32];
        rng.fill_bytes(&mut b);
        b
    })
    .ok_or(Error::Misuse("list tree"))?;
    let header = RotationHeader { signing_key: keys.signing.verifying_key(), kem_key: keys.kem.public().clone(), supersedes: tips.clone(), names: tips.iter().skip(1).copied().collect(), takes: Vec::new(), revokes: false, devices: Vec::new(), list_root: root, seeds };
    let merge_keys = tip_keys.iter().skip(1).map(|k| k.signing.clone()).collect();
    let more = tip_keys.iter().skip(1).map(|k| k.inner.clone()).chain([keys.inner.clone()]).collect();
    let rotation = AccountRotation { header, merge_keys, more, lists: Vec::new(), at: Some((at, at_keys)) };
    commit_rotation(tx, p, held.root, &keys, &roster, rotation)
}

/// The merge of `heads` this node can make: its tips (ascending) and keys, when there are
/// several heads and every tip's seed is held (`held`).
pub(crate) fn merge_of(v: &super::account::AccountView, held: &super::account::HeldAccount, heads: &[CommitId]) -> Option<(Vec<CommitId>, AccountEpochKeys)> {
    if heads.len() < 2 {
        return None;
    }
    let tips: Vec<CommitId> = v.tips(|r| !v.is_merge(r) && heads.iter().any(|h| v.on_line(r, h))).into_iter().collect();
    if tips.len() < 2 {
        return None;
    }
    let seeds: Vec<Secret32> = tips.iter().map(|t| v.keys_of(t, held).map(|k| k.seed().clone())).collect::<Option<_>>()?;
    let refs: Vec<&Secret32> = seeds.iter().collect();
    Some((tips, AccountEpochKeys::from_seed(&osis_crypto::merge_seed(&refs))))
}

/// Writes rotation `rotation` of account `p` minting the epoch keyed `keys`: P's `keys.0`, the
/// epoch on D's (`d`) `account.0`, and D re-keyed to `roster` with a fresh deposit seed (its sync
/// role rotates, spec/crypto.md §3) in the same commit (spec/permissions.md §3: D's keys move only with the
/// account's; D's departures are the chain's, no edge write).
fn commit_rotation(tx: &mut Tx<'_>, p: Tid, d: Tid, keys: &AccountEpochKeys, roster: &BTreeSet<Tid>, rotation: AccountRotation) -> Result<Option<CommitId>> {
    let signing = keys.signing.verifying_key();
    let mut m = Mutation::new();
    m.sign_as(p);
    let mut k = crate::engine::Core::keys_in(tx, &p)?.unwrap_or_default();
    let fresh = osis_keys::aspects::account_keys(keys);
    (k.signing, k.key) = (fresh.signing, fresh.key);
    m.set(p, &ct::KEYS, &k)?;
    crate::rotation::fresh_deposit_seed(tx, &mut m, d)?;
    m.op(d, &ct::ACCOUNT, PathOp { path: vec![], op: Op::Add(Value::bytes(&signing.to_bytes())) })?;
    let skip: Vec<(Tid, Option<osis_base::Role>)> = tx.core.key_holders(&d).into_iter().map(|x| x.0).filter(|x| !roster.contains(x)).map(|x| (x, None)).collect();
    let mut boxing = crate::rotation::recipients(tx, &p, &d, &skip)?;
    for n in roster {
        if !boxing.holders.iter().any(|h| h.holder == *n) {
            boxing.holders.push(super::recipient(tx, *n, osis_base::Role::Admin)?);
        }
    }
    let held_d = tx.core.epochs(&d).map(Arc::unwrap_or_clone).ok_or(Error::Misuse("D's epochs not held"))?;
    let d_rot = crate::rotation::rotation_into(tx, &mut m, d, &osis_keys::ROLES.into_iter().collect(), &held_d, &boxing, crate::rotation::Departs::No)?;
    m.rotation = Some(rotation);
    // the new seed is kept as the commit applies: its box to this node opens
    // (`custody::take_boxes`), a merge's derived (`custody::derive_merges`)
    let c = Engine::commit_tx(tx, m)?;
    crate::rotation::record(tx, d, &d_rot)?;
    Ok(c)
}

/// The rotator's own covers before a plain rotation of `p` closing `closes` (spec/permissions.md
/// §5.5 Own cover): a list names only what its writer holds, so for each aspect where a live
/// write of `p` stamped since the oldest of `closes` opened stands here only through a cover
/// (forgotten under one, or never received), this node writes, signed at its open epoch, a
/// snapshot of the aspect from its whole state marked as its own cover; the rotation's lists
/// name them as its own commits. An aspect it may not snapshot gets none. Only aspects where a
/// cover stamped since then is held, or a commit stamped since then was forgotten, are read, so
/// a later rotation writes none for epochs closed already.
fn own_covers(tx: &mut Tx<'_>, p: &Tid, closes: &[CommitId]) -> Result<Vec<CommitId>> {
    use crate::retention::snapshot as sn;
    // the first epoch opened before anything; `None` sorts first
    let since = closes.iter().map(|e| if *e == osis_commit::FIRST_EPOCH { None } else { tx.core.ix.commits.get(e).map(|m| m.view.ts) }).min().flatten();
    let recent = |ts: &osis_base::Ts| since.is_none_or(|s| *ts >= s);
    let mut aspects: BTreeSet<(Tid, osis_base::Ak)> = tx.core.ix.forgotten.iter().filter(|(_, ts)| recent(ts)).map(|(k, _)| k.clone()).collect();
    aspects.extend(tx.core.ix.snapshots.iter().filter(|(_, ss)| ss.iter().any(|s| recent(&s.0))).map(|(k, _)| k.clone()));
    let mut out = Vec::new();
    for (t, ak) in aspects {
        if !sn::compacted(&ak) || ak.ephemeral() || !sn::carried_only(tx, &t, &ak, &|x| x == p, since)? {
            continue;
        }
        if sn::may_snapshot(tx, &t, &ak, false, tx.core.hlc.peek())? == crate::engine::write::MayWrite::Yes
            && let Some(s) = sn::write_own_cover(tx, &t, &ak)?
        {
            out.push(s);
        }
    }
    Ok(out)
}

/// A plain rotation's thing lists (spec/permissions.md §5.5): per thing, the commits of `p` at
/// the epochs it closes (`closes`) that no word held names, by the cutoff, and `also`; the list
/// tree's root and each list with its path.
fn thing_lists(tx: &mut Tx<'_>, p: &Tid, v: &super::account::AccountView, closes: &[CommitId], also: &[CommitId]) -> Result<([u8; 32], Lists)> {
    // per thing: role-class and purge-request commits, then dependent ones by receipt
    let mut per: BTreeMap<Tid, PerThing> = BTreeMap::new();
    let mut listed = nameable(tx, p, v, closes, true)?;
    for c in also {
        if !listed.iter().any(|x| x.0 == *c)
            && let Some(m) = tx.core.ix.commits.get(c).cloned()
        {
            listed.push((*c, m));
        }
    }
    for (c, m) in listed {
        let special = m.view.kind.is_role() || m.view.purges;
        for t in things_of(&m.view) {
            let x = per.entry(t).or_default();
            if special {
                x.0.insert(c);
            } else {
                x.1.push((m.received, c));
            }
        }
    }
    let mut leaves: Vec<(u64, ThingList)> = Vec::new();
    let mut used = BTreeSet::new();
    for (t, (special, mut plain)) in per {
        plain.sort();
        let plain: Vec<CommitId> = plain.into_iter().map(|x| x.1).collect();
        // inline lists only (linked thing lists are not written yet: issues/linked-thing-lists.md)
        let (ids, _) = fit_list(&special, &plain, CHUNK_THRESHOLD.min(tx.core.list_bound)).ok_or(Error::Misuse("the account's role and purge changes since its last rotation pass the list bound on a thing"))?;
        let index = loop {
            let i = u64::from(tx.rng.next_u32());
            if used.insert(i) {
                break i;
            }
        };
        let mut salt = [0u8; 16];
        tx.rng.fill_bytes(&mut salt);
        leaves.push((index, ThingList { thing: t, ids: ListIds::Inline(ids.into_iter().collect()), salt }));
    }
    let hashed: Vec<(u64, [u8; 32])> = leaves.iter().map(|(i, l)| (*i, list_leaf(&l.encode()))).collect();
    let rng = &mut *tx.rng;
    let (root, paths) = list_tree(&hashed, || {
        let mut b = [0u8; 32];
        rng.fill_bytes(&mut b);
        b
    })
    .ok_or(Error::Misuse("list tree"))?;
    Ok((root, leaves.into_iter().zip(paths).map(|((i, l), path)| (i, path.siblings, l)).collect()))
}

/// This node took up account `p` (`Engine::hold_account`: paired, a removed node paired again):
/// it answers again, as a node of `p`, each head's rotation (spec/permissions.md §5.5, Listings),
/// which closes every closed epoch but those descending from it, so its listings name all it
/// owes; as an outsider it answered with addenda alone, so its own commits at the epochs closed
/// meanwhile wait on its word.
pub(crate) fn answer_again(tx: &mut Tx<'_>, p: &Tid) -> Result<()> {
    let Some(v) = tx.core.account_view(p) else { return Ok(()) };
    for h in v.heads().into_iter().filter(|h| *h != osis_commit::FIRST_EPOCH) {
        note_rotation_due(tx, &h)?;
    }
    Ok(())
}

/// Rotation `r` of an account is due this node's answer, kept across restarts
/// (`records::ROTATIONS_DUE`).
pub(crate) fn note_rotation_due(tx: &mut Tx<'_>, r: &CommitId) -> Result<()> {
    if tx.core.ix.rotations_due.insert(*r) {
        tx.txn.put_local(&[records::ROTATIONS_DUE, &r.0[..]].concat(), &[], Shred::No)?;
    }
    Ok(())
}

/// Answers every account's rotation not yet answered (`Indexes::rotations_due`), each once: a
/// rotation of this node's account with its listing, another account's with its addenda as a
/// writer (spec/permissions.md §5.5, Listings, Addenda against a rotation). One waits while it is
/// pending, while the open epoch's seed is not here to sign at, or while a thing it writes on may
/// be written only later (`write::MayWrite::Later`: its minting or delete keys are not here); a
/// void one is answered by nothing, until it comes to count (`account::refresh_epochs` notes it
/// due again). Each answer is one step (`Tx::step`): one that fails leaves
/// nothing, is reported (`DiagnosticKind::OwnWriteFailed`) and stays due, and the transaction
/// goes on, so a receive never fails for this node's own answer.
pub(crate) fn answer_rotations(tx: &mut Tx<'_>) -> Result<()> {
    let due: Vec<CommitId> = tx.core.ix.rotations_due.iter().copied().collect();
    for r in due {
        let answered = tx.step(Step::Rotation, |tx| {
            if answer_rotation(tx, &r)? {
                tx.core.ix.rotations_due.remove(&r);
                tx.txn.remove_local(&[records::ROTATIONS_DUE, &r.0[..]].concat(), Shred::No)?;
            }
            Ok(())
        });
        if let Err(e) = answered {
            tx.core.events.diagnostic(Diagnostic { kind: DiagnosticKind::OwnWriteFailed, tids: Vec::new(), commit: Some(r), peer: None, detail: e.to_string() }, tx.core.hlc.mono());
        }
    }
    Ok(())
}

/// The commits of account `p` at `epochs` the cutoff lets this node name (spec/permissions.md
/// §5.5, Cutoff) that no word held names (`Cutoff::names`). Rotations count by the chain;
/// ephemeral commits are named as durable ones.
fn nameable(tx: &mut Tx<'_>, p: &Tid, v: &super::account::AccountView, epochs: &[CommitId], own: bool) -> Result<Vec<(CommitId, crate::engine::Meta)>> {
    let mut cut = Cutoff { me: tx.core.id.tid(), departures: own.then(|| departures(v)), earliest: BTreeMap::new(), judged: BTreeMap::new() };
    let mut out = Vec::new();
    for e in epochs {
        let open = v.is_open(e);
        let at: Vec<CommitId> = tx.core.ix.by_epoch.get(&(*p, *e)).into_iter().flatten().copied().collect();
        for c in at {
            let Some(m) = tx.core.ix.commits.get(&c).cloned() else { continue };
            // a word is owed whether or not the epoch is revoked yet (one counting unrevoked, or
            // only while it waits for D's list, may be revoked later): only a held word naming it
            // spares it
            if v.is_rotation(&c) || !open && named_by_a_word(tx, v, &c, &m.view)? {
                continue;
            }
            if cut.names(tx, v, &c, &m)? {
                out.push((c, m));
            }
        }
    }
    Ok(out)
}

/// The cutoff as this node applies it (spec/permissions.md §5.5, Cutoff): it names a commit it
/// received before the earliest closer of its epoch held that ends it (`ends`; at an epoch with
/// none, every one), receipts of one millisecond in exact order (`Received`), or (`departures`
/// set: a node of the account) one it made itself, per its inner signature, a word only where it
/// names each commit that word names. So a node's own word carries nothing its cutoff names no
/// longer (one written while it followed another side).
struct Cutoff {
    me: Tid,
    departures: Option<Departures>,
    /// Per epoch, the receipt of its earliest closer that ends it (`None`: none ends it).
    earliest: BTreeMap<CommitId, Option<Option<Received>>>,
    /// Per commit judged, whether it is named.
    judged: BTreeMap<CommitId, bool>,
}

/// When a commit was received, in exact order: its receipt's millisecond, then (`ts`, author,
/// commit ID) among one millisecond's (spec/permissions.md §5.5, Cutoff).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Received(osis_base::WallMs, osis_base::Ts, Tid, CommitId);

impl Received {
    fn of(c: &CommitId, m: &crate::engine::Meta) -> Received {
        Received(m.received, m.view.ts, m.view.author, *c)
    }
}

impl Cutoff {
    fn names(&mut self, tx: &mut Tx<'_>, v: &super::account::AccountView, c: &CommitId, m: &crate::engine::Meta) -> Result<bool> {
        if let Some(n) = self.judged.get(c) {
            return Ok(*n);
        }
        // a word names no rotation and no word naming itself: judged unnamed while it is judged
        self.judged.insert(*c, false);
        let n = self.judge(tx, v, c, m)?;
        self.judged.insert(*c, n);
        Ok(n)
    }

    fn judge(&mut self, tx: &mut Tx<'_>, v: &super::account::AccountView, c: &CommitId, m: &crate::engine::Meta) -> Result<bool> {
        let Some(e) = m.view.epoch else { return Ok(false) };
        if v.is_rotation(c) {
            return Ok(false);
        }
        let bound = match self.earliest.get(&e) {
            Some(x) => *x,
            None => {
                let ending: Vec<CommitId> = v.closers(&e).into_iter().filter(|r| ends(v, self.departures.as_ref(), &e, r)).collect();
                let x = (!ending.is_empty()).then(|| ending.iter().flat_map(|r| v.minting(r)).filter_map(|r| tx.core.ix.commits.get(&r).map(|rm| Received::of(&r, rm))).min());
                self.earliest.insert(e, x);
                x
            }
        };
        if bound.is_none_or(|x| x.is_some_and(|x| Received::of(c, m) < x)) {
            return Ok(true);
        }
        if self.departures.is_none() || tx.get_commit(c)?.as_ref().and_then(|b| tx.core.inner_node(b)) != Some(self.me) {
            return Ok(false);
        }
        for (k, _) in super::lists::named_by(tx, c)? {
            // what it no longer holds it cannot vouch for now
            let Some(km) = tx.core.ix.commits.get(&k).cloned() else { return Ok(false) };
            if !self.names(tx, v, &k, &km)? {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

/// Whether held commit `c` stands here as it will once every head closes (spec/permissions.md
/// §5.5 Carrying): a commit of an account at an open revoked epoch (a head beside a removal, as
/// an unaware sibling's boxed to the removed node) counts only while the head is open, unless a
/// counting word names it or this node's cutoff does (`Cutoff`, as for a list). A word that
/// carries others' writes (a snapshot) carries only what lasts so; the rest it waits for.
pub(crate) fn lasts(tx: &mut Tx<'_>, c: &CommitId) -> Result<bool> {
    let Some(m) = tx.core.ix.commits.get(c).cloned() else { return Ok(true) };
    let Some(e) = m.view.epoch else { return Ok(true) };
    let p = m.view.author;
    let Some(v) = tx.core.account_view(&p) else { return Ok(true) };
    if !v.head_revoked(&e) || named_by_a_word(tx, &v, c, &m.view)? {
        return Ok(true);
    }
    let own = tx.core.accounts.contains_key(&p);
    let mut cut = Cutoff { me: tx.core.id.tid(), departures: own.then(|| departures(&v)), earliest: BTreeMap::new(), judged: BTreeMap::new() };
    cut.names(tx, &v, c, &m)
}

/// Whether a counting word held here names account commit `c` (`view`, its view): a counting
/// rotation's thing list or a counting listing, on a thing `c` has a delta on or acts for
/// (spec/permissions.md §5.5, Epoch rule).
fn named_by_a_word(tx: &mut Tx<'_>, v: &super::account::AccountView, c: &CommitId, view: &crate::engine::View) -> Result<bool> {
    let things = things_of(view);
    for (t, s) in super::lists::names_of(tx, c)? {
        if !things.contains(&t) {
            continue;
        }
        let counts = match tx.core.ix.commits.get(&s) {
            _ if v.is_rotation(&s) => v.rotation_counts(&s),
            Some(m) => m.view.author == view.author && tx.core.standing(&s, &m.view) == osis_perm::EpochStanding::Counts,
            None => false,
        };
        if counts {
            return Ok(true);
        }
    }
    Ok(false)
}

/// This node's answer to rotation `r`; whether `r` is answered.
fn answer_rotation(tx: &mut Tx<'_>, r: &CommitId) -> Result<bool> {
    // a plain rotation is its commit; a merge epoch is no commit: its account is the one whose
    // judged epochs hold it
    let author = tx.core.ix.commits.get(r).map(|m| m.view.author);
    let Some(p) = author.or_else(|| tx.core.ix.epochs.iter().find(|(_, j)| j.holds(r)).map(|(p, _)| *p)) else { return Ok(true) };
    let Some(v) = tx.core.account_view(&p) else { return Ok(true) };
    // a merge certificate is answered as its epoch
    let r = &v.epoch_of(r).unwrap_or(*r);
    if !v.holds(r) {
        return Ok(false);
    }
    if !v.rotation_counts(r) {
        return Ok(true);
    }
    if tx.core.accounts.contains_key(&p) {
        // a rotation D's roster does not authorize (a removed node's fork) is answered by the
        // rotation superseding it, which closes all it closes: a removed node re-forking costs
        // no listing per fork
        if v.authorized_by(r).is_none() {
            return Ok(true);
        }
        return listing(tx, p, &v, r);
    }
    witness(tx, p, &v, r)
}

/// A node of account `p` answers its rotation `r` with a listing: per thing, the commits of `p`
/// at the epochs `r` closes that no word held names, this node's own (by inner signature, `Cutoff`) and
/// others' by the cutoff (spec/permissions.md §5.5, Listings), one commit per thing: a commit
/// goes whole under the sync IDs of every thing it touches, so one over every thing would ship
/// each thing's listing wherever any other thing goes. A listing needs no role on a thing; one
/// that is gone here is left out, one it may write on only later waits while the others go (what
/// a held listing names is not named again, `nameable`), the rotation owed until none waits.
///
/// A node writes only what it holds as the transaction leaves it (spec/sync-set.md §2 Writing),
/// and `r` may be what took a thing out of the node closure: its keys or its holding strong were
/// made at an epoch `r` closes, and count again once named. So a listing on a thing outside the
/// node closure goes where the node closure holds that thing once it is written, else it waits:
/// first those another listing written brings back, then each alone, in a step undone if its
/// thing stays out.
fn listing(tx: &mut Tx<'_>, p: Tid, v: &super::account::AccountView, r: &CommitId) -> Result<bool> {
    let Some(d) = tx.core.accounts.get(&p).map(|a| a.root) else { return Ok(true) };
    // off D's roster it writes nothing for the account: owed until it is on it again
    if !tx.core.on_root_roster(&d) {
        return Ok(false);
    }
    if tx.core.account_signing(&p).ok().flatten().is_none() {
        return Ok(false);
    }
    // an open epoch's commits count unnamed: they are named once a rotation closes it
    let closed: Vec<CommitId> = v.closed_by(r).into_iter().filter(|e| !v.is_open(e)).collect();
    let mut written: BTreeSet<Tid> = BTreeSet::new();
    loop {
        let mut names: BTreeMap<Tid, BTreeSet<CommitId>> = BTreeMap::new();
        for (c, m) in nameable(tx, &p, v, &closed, true)? {
            for t in things_of(&m.view).into_iter().filter(|t| !written.contains(t)) {
                names.entry(t).or_default().insert(c);
            }
        }
        let w = writable_split(tx, p, names, "listing.0", None)?;
        let wrote = !w.now.is_empty();
        for (t, ids) in w.now {
            write_listing(tx, p, r, t, &ids)?;
            written.insert(t);
        }
        if w.unheld.is_empty() {
            return Ok(!w.later);
        }
        if wrote {
            crate::sync::units::settle(tx)?;
            continue;
        }
        let mut kept = false;
        for (t, ids) in w.unheld {
            let tried = tx.step(Step::Rotation, |tx| {
                write_listing(tx, p, r, t, &ids)?;
                crate::sync::units::settle(tx)?;
                if tx.core.ix.closure.holds(&t) { Ok(()) } else { Err(Error::NotHeld(t)) }
            });
            match tried {
                Ok(()) => {
                    written.insert(t);
                    kept = true;
                }
                Err(Error::NotHeld(_)) => {}
                Err(e) => return Err(e),
            }
        }
        if !kept {
            return Ok(false);
        }
    }
}

/// Account `p`'s listings on thing `t` against rotation `r`, naming `ids`: as many as it takes
/// for each to name what fits the list bound (spec/permissions.md §5.5, Listings, Bound);
/// listings compose by union.
fn write_listing(tx: &mut Tx<'_>, p: Tid, r: &CommitId, t: Tid, ids: &BTreeSet<CommitId>) -> Result<()> {
    let room = (1..=ids.len()).take_while(|n| osis_perm::epochs::list_bytes(*n) <= tx.core.list_bound).last().unwrap_or(1);
    let ids: Vec<&CommitId> = ids.iter().collect();
    for part in ids.chunks(room) {
        let mut m = Mutation::new();
        m.sign_as(p);
        m.unchecked();
        let set = Value::Set(part.iter().map(|c| Value::bytes(&c.0)).collect());
        m.op(t, &ct::LISTING, PathOp { path: vec![PathSeg::Key(Value::bytes(&r.0))], op: Op::Put(set) })?;
        Engine::commit_tx(tx, m)?;
    }
    Ok(())
}

/// A writer of a thing answers another account's rotation `r` with an addendum on each thing it
/// writes: the account's plain-content commits there it names by the cutoff (spec/permissions.md
/// §5.5, Addenda against a rotation), one addendum per thing, so none crosses a sync ID. Waits whole
/// for a thing it may write on only later (`write::may_write`).
fn witness(tx: &mut Tx<'_>, p: Tid, v: &super::account::AccountView, r: &CommitId) -> Result<bool> {
    let Some(me) = tx.core.member().filter(|_| tx.core.addenda_on) else { return Ok(true) };
    let mut out: BTreeMap<Tid, BTreeSet<CommitId>> = BTreeMap::new();
    let closed: Vec<CommitId> = v.closed_by(r).into_iter().filter(|e| !v.is_open(e)).collect();
    for (c, m) in nameable(tx, &p, v, &closed, false)? {
        let w = &m.view;
        if w.purges || w.kind != osis_commit::Kind::Content {
            continue;
        }
        for t in w.aspects.iter().filter(|a| super::addenda::plain_ak(&a.ak)).map(|a| a.tid).chain((w.actor != w.author).then_some(w.actor)) {
            out.entry(t).or_default().insert(c);
        }
    }
    let Some(on) = writable_now(tx, me, out, ct::ADDENDA_AK, Some(osis_base::Role::Write))? else { return Ok(false) };
    for (n, lists) in on {
        let mut mu = Mutation::new();
        mu.op(n, &ct::ADDENDA, PathOp { path: vec![PathSeg::Key(Value::bytes(&r.0))], op: Op::Put(ct::Frontier { commits: lists }.to_value()) })?;
        Engine::commit_tx(tx, mu)?;
    }
    Ok(true)
}

/// Judges account `p` (account root `d`) again now that this node took it up or left it
/// (`Engine::take_up`): the epoch rule reads D only at a node holding the account, so every
/// standing may move (spec/permissions.md §5.4, Following, at a node of P and outside it), the
/// account's commits on D among them, whose standing may move with no epoch's (Waiting counts
/// them only at a node of P). Nothing else notes it: `Core::judged_from` tracks what moves while
/// the account is held, not holding it.
pub(crate) fn judge_account_again(tx: &mut Tx<'_>, p: Tid, d: Tid) -> Result<()> {
    tx.core.ix.epochs_due.insert(p);
    let on_d: Vec<CommitId> = tx.core.ix.role_on.get(&(d, p)).into_iter().flatten().copied().collect();
    tx.core.ix.names_due.extend(on_d);
    crate::apply::atomic::rejudged(tx, false).map(drop)
}

/// A node of account `p` leaves it only when no held line keeps it a node (spec/crypto.md §9,
/// Custody): of the held rotations that count here or whose seed it holds and whose line stands
/// under the removals on it alone, no tip (one on no other's line) has it among the nodes of its
/// line, under those removals (with none, the first epoch keeps it). So it leaves on a counting
/// removal of it past every line keeping it; a rotation that merely boxes it nothing (a forgery
/// boxing others) removes no one, nor one minted by no node of its line, and one it neither
/// follows nor holds the seed of (a line it disregards) moves nothing. Leaving, it drops the
/// account's seeds, so it signs and opens
/// nothing as it, and everything it read only as the account is lost (spec/permissions.md §3, Lost
/// access; an account's retain default does not reach its nodes, §2): every held actor is judged
/// again. D's roster decides nothing here: a grant unnamed at a node is no removal of it, and a
/// node a removal took off the line it follows stays while another held line keeps it, so its
/// user's switch to that line takes.
pub(crate) fn leave_if_removed(tx: &mut Tx<'_>) -> Result<()> {
    let Some((p, d)) = tx.core.account_and_root() else { return Ok(()) };
    let (Some(v), Some(held)) = (tx.core.account_view(&p), tx.core.accounts.get(&p).cloned()) else { return Ok(()) };
    if kept(&v, &held, &tx.core.id.tid()) {
        return Ok(());
    }
    leave(tx, p, d)
}

/// Whether some held line keeps this node a node of its account (`leave_if_removed`).
pub(crate) fn kept(v: &super::account::AccountView, held: &super::account::HeldAccount, me: &Tid) -> bool {
    let rots: Vec<CommitId> = v.rotation_ids().into_iter().filter(|r| v.holds(r) && v.stands_alone(r) && (v.rotation_counts(r) || v.keys_of(r, held).is_some())).collect();
    let set: BTreeSet<CommitId> = rots.into_iter().collect();
    let mut tips = v.tips(|r| set.contains(r)).into_iter().peekable();
    tips.peek().is_none() || tips.any(|t| v.keeps(&t, me))
}

/// `leave_if_removed` of account `p` with account root `d`.
pub(crate) fn leave(tx: &mut Tx<'_>, p: Tid, d: Tid) -> Result<()> {
    tx.core.accounts.remove(&p);
    super::custody::shred(tx, &p)?;
    tx.core.left.insert(p);
    judge_account_again(tx, p, d)?;
    let held: Vec<Tid> = tx.core.ix.secrets.keys().copied().chain([d]).collect();
    crate::rotation::touch_held(tx, held);
    Ok(())
}

/// The departures of this node's account that counting rotations carry: per such rotation, the
/// nodes it removes.
#[derive(Default)]
struct Departures {
    named: BTreeMap<CommitId, BTreeSet<Tid>>,
    /// Removed nodes D's roster holds again.
    back: BTreeSet<Tid>,
}

impl Departures {
    /// The nodes the rotations on held rotation `r`'s line remove that D's roster does not hold
    /// again (a re-added node's removal ends nothing); none for the first epoch.
    fn removed(&self, v: &super::account::AccountView, r: &CommitId) -> BTreeSet<Tid> {
        v.line(r).into_iter().flatten().filter_map(|s| self.named.get(&s)).flatten().filter(|n| !self.back.contains(n)).copied().collect()
    }
}

fn departures(v: &super::account::AccountView) -> Departures {
    let mut out = Departures::default();
    for r in v.rotation_ids().into_iter().filter(|r| v.rotation_counts(r)) {
        let ns = v.removes(&r);
        if ns.is_empty() {
            continue;
        }
        out.back.extend(ns.iter().filter(|n| v.roster().contains(*n)));
        out.named.insert(r, ns);
    }
    out
}

/// Whether closer `c` of held epoch `e` ends it for the cutoff (spec/permissions.md §5.5,
/// Cutoff): `c` descends from `e`, or (`departures`, a node of the account reading D's lists)
/// `c`'s line names the removal of a node `e`'s line names none of, so `e` may be boxed to it.
/// A rotation beside `e` naming no one more (a concurrent rotation of the same heads, or one
/// removing the same node) ends nothing, so writes at a head stay nameable until a merge. Without
/// D's lists (a witness) every closer ends it.
fn ends(v: &super::account::AccountView, departures: Option<&Departures>, e: &CommitId, c: &CommitId) -> bool {
    let Some(dep) = departures else { return true };
    if *e == osis_commit::FIRST_EPOCH || v.on_line(e, c) {
        return true;
    }
    let mine = dep.removed(v, e);
    dep.removed(v, c).iter().any(|x| !mine.contains(x))
}

/// The held rotations of this node's account this node disregards (placed in conflict with the
/// line it follows: a removed node's fork, one no node of the account minted, another side's)
/// on no line (descending from) a rotation a counting one rejects, a merge included, that no
/// rotation of this node's answers (supersedes besides the epoch it is signed at: one signed at it, made while this node
/// followed it, answers nothing): superseded unnamed by its next rotation, so every reader that followed one is told
/// (spec/permissions.md §5.4, Warning). Another node's rotation superseding it may reject nothing
/// (signed at its epoch: contested from below), so only a rejection answers it, and each node
/// answers once (its own answer may be so contested too). One answer per line: a reader following
/// it holds that rejection already, so two sides never answer each other's answers; a rotation
/// signed at the answer's epoch that puts the rejected one on a line through it ends that
/// rejection, and is answered in turn. A merge is owed an answer only where it joins a line not
/// followed: one whose tips all count joins the followed lines, and this node's certificate of
/// it makes it stand.
fn unanswered(v: &super::account::AccountView, me: &Tid) -> Vec<CommitId> {
    let ids = v.rotation_ids();
    let rejected: Vec<CommitId> = ids.iter().copied().filter(|q| v.rejected(q)).collect();
    ids.into_iter().filter(|r| !v.is_merge(r) || v.tips_of(r).iter().any(|t| !v.rotation_counts(t))).filter(|r| v.disregarded(r) && !v.answered_by(r, me) && !rejected.iter().any(|q| v.on_line(q, r))).collect()
}

/// What a node of the account owes its signing chain (spec/permissions.md §5.5), made now. Any
/// node of the account makes it, none designated. First a plain rotation (`rotate_in`) where one
/// is owed: a rotation it disregards stands unanswered (`unanswered`: superseded unnamed, so every
/// reader that followed it is told), or a revocation it took that no plain rotation of its own
/// carries is on no line of its preferred head (taken by no rotation on it) while it cannot make
/// the merge (which carries every taken revocation, a counting one being on some head's line).
/// So each event is owed once per node, as an answer is. A removal or addition is made with its
/// own rotation (`Engine::remove_device`, `Engine::pair`). Then, following several heads and
/// holding every tip's seed, the merge of them all (`merge_heads`): a function of the tips, so
/// two nodes making it at once make one epoch. Looked at at the end of a complete pass of D's sync
/// IDs (`Engine::signing_due`).
pub(crate) fn rotations_due(tx: &mut Tx<'_>, done: &mut Done) -> Result<Vec<CommitId>> {
    if !std::mem::take(&mut tx.core.signing_due) {
        return Ok(Vec::new());
    }
    let Some(p) = tx.core.member() else { return Ok(Vec::new()) };
    let Some(d) = tx.core.accounts.get(&p).map(|a| a.root) else { return Ok(Vec::new()) };
    let Some(v) = tx.core.account_view(&p) else { return Ok(Vec::new()) };
    if !signs_for(tx.core, &d) {
        return Ok(Vec::new());
    }
    let held = tx.core.accounts.get(&p).cloned().ok_or(Error::Misuse("not an account held here"))?;
    let mergeable = merge_of(&v, &held, &v.heads()).is_some();
    let (pref, me) = (v.preferred(), tx.core.id.tid());
    let untaken = !mergeable && v.taken().iter().any(|t| !v.carries(&pref, t) && !v.carried_by(t, &me));
    let mut out = Vec::new();
    if untaken || !unanswered(&v, &me).is_empty() {
        out.extend(rotate_in(tx, p, &[], done)?);
    }
    out.extend(merge_heads(tx, p)?);
    Ok(out)
}

/// Whether this node writes its account's chain (rotations, seed re-seals): it is on D's
/// roster (a node off it would mint a seed it boxes to none but itself). A revocation of itself
/// it took keeps it off unless the line re-adds it (`Chain::roster`).
pub(crate) fn signs_for(core: &crate::engine::Core, d: &Tid) -> bool {
    core.on_root_roster(d)
}

impl Engine {
    /// What this node owes its account's signing chain, decided at the end of a complete pass
    /// of its account root's sync IDs (node-sync), so two forks and the merge of another node
    /// are both in: the rotation due (`rotations_due`), then the seed re-seals of its heads
    /// (`custody::reseal_seeds`).
    pub fn signing_due(&mut self) -> Result<Done> {
        let mut done = Done::default();
        for c in self.run(|tx| rotations_due(tx, &mut done))? {
            done.add(Some(c));
        }
        done.commits.extend(self.run(super::custody::reseal_seeds)?);
        Ok(done)
    }
}
