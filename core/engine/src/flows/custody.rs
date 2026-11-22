//! Custody of an account's seeds (spec/crypto.md §9, Custody). Principle: custody follows
//! holding. A rotation boxes its new seed to each device on its maker's roster (its header's seed
//! boxes); a node holds a seed iff it opened a box to its own device key, whoever wrote the box
//! and whether or not its rotation counts. Judgment decides only where a node signs and what it
//! boxes, never what it holds, so the chain is a function of held commits alone.

use crate::engine::{Core, Tx, records};
use crate::error::{Error, Result};
use osis_base::{Role, Tid};
use osis_commit::{Header, SeedBox, SeedReseal};
use osis_schema::core_types as ct;
use osis_base::Value;
use osis_crdt::{Op, PathOp};
use super::account::AccountView;
use osis_crypto::{AccountEpochKeys, Secret32, VerifyingKey};
use osis_store::Shred;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// Every seed of account `p` in this node's custody, by epoch signing key.
pub(crate) type Seeds = BTreeMap<VerifyingKey, Arc<AccountEpochKeys>>;

fn row(p: &Tid, key: &VerifyingKey) -> Vec<u8> {
    [records::SEEDS, p.as_bytes().as_slice(), &key.to_bytes()].concat()
}

/// Opens the seed boxes of header `h` (a rotation's of the epoch it mints, a re-seal's of the
/// epoch it names) addressed to this node's device key, at a node holding the account or of no
/// account yet (a pairing hands a new node its seeds so), counting or not, and keeps every seed
/// found (`keep`).
pub(crate) fn take_boxes(tx: &mut Tx<'_>, h: &Header) -> Result<()> {
    let Some((key, boxes)) = seed_boxes_of(h) else { return Ok(()) };
    let p = h.signer;
    let ours = tx.core.accounts.contains_key(&p) || tx.core.account.get().is_none_or(|a| a == p);
    if !ours || held(tx, &p, key)? {
        return Ok(());
    }
    let kem = tx.core.id.keys().kem.clone();
    let Some(seeds) = boxes.iter().find_map(|b| osis_crypto::open_seeds(&kem, &p, key, &b.sealed)) else { return Ok(()) };
    for s in seeds {
        keep(tx, &p, &s)?;
    }
    Ok(())
}

/// Opens every seed box to this node held here of account `p` (with account root `d`), each by
/// `take_boxes`: its rotations' and re-seals', role commits of P on P or on D. A node taking `p`
/// up holds what every box to it it holds carries, those it opened before it last left among
/// them, so custody is a function of the held commits. O(P's role commits on P and D), at a
/// take-up alone.
pub(crate) fn take_held_boxes(tx: &mut Tx<'_>, p: &Tid, d: &Tid) -> Result<()> {
    let held: BTreeSet<osis_base::CommitId> = [(*p, *p), (*d, *p)].iter().filter_map(|k| tx.core.ix.role_on.get(k)).flatten().copied().collect();
    for c in held {
        if let Some(h) = tx.core.ix.commits.get(&c).and_then(|m| m.header.decoded()) {
            take_boxes(tx, &h)?;
        }
    }
    Ok(())
}

/// Header `h`'s seed boxes with the signing key of the epoch whose seed they carry: a rotation's
/// (the epoch it mints) or a re-seal's.
pub(crate) fn seed_boxes_of(h: &Header) -> Option<(&VerifyingKey, &[SeedBox])> {
    match (&h.rotation, &h.reseal) {
        (Some(r), _) => Some((&r.signing_key, &r.seeds)),
        (None, Some(r)) => Some((&r.signing_key, &r.seeds)),
        (None, None) => None,
    }
}

/// Whether the seed of account `p`'s epoch with signing key `key` is in custody here: recorded,
/// and taken up where the account is held. (Memory alone is not custody: a transaction rolled
/// back, a trial among them, keeps no record.)
fn held(tx: &mut Tx<'_>, p: &Tid, key: &VerifyingKey) -> Result<bool> {
    Ok(tx.txn.get_local(&row(p, key))?.is_some() && tx.core.accounts.get(p).is_none_or(|a| a.keys.contains_key(key)))
}

/// Keeps seed `s` of account `p` in custody: recorded, and taken up at once where the account is
/// held (its chain is judged again: inner signatures it opens may move what counts).
pub(crate) fn keep(tx: &mut Tx<'_>, p: &Tid, s: &Secret32) -> Result<()> {
    let keys = AccountEpochKeys::from_seed(s);
    let pk = keys.signing.verifying_key();
    tx.txn.put_local(&row(p, &pk), s.expose(), Shred::Yes)?;
    if let Some(a) = tx.core.accounts.get(p).filter(|a| !a.keys.contains_key(&pk)) {
        let mut n = (**a).clone();
        n.keys.insert(pk, Arc::new(keys));
        tx.core.account_changing(*p);
        tx.core.accounts.replace(*p, Arc::new(n));
        tx.core.ix.epochs_due.insert(*p);
        // a part on the account itself sealed under an epoch whose seed came only now opens now:
        // its stored entries are opened again
        let lacking: Vec<osis_base::CommitId> = tx.core.aspects_of(p).flat_map(|(_, cs)| cs.iter().map(|x| x.1)).filter(|c| tx.core.ix.commits.get(c).is_some_and(|m| m.view.aspects_on(p).any(|ai| m.missing(ai)))).collect();
        tx.core.redeliver.extend(lacking);
    }
    Ok(())
}

/// The seeds of account `p` in custody here.
pub(crate) fn seeds(tx: &mut Tx<'_>, p: &Tid) -> Result<Seeds> {
    let mut out = Seeds::new();
    let prefix = [records::SEEDS, p.as_bytes().as_slice()].concat();
    tx.scan(&prefix, |_, v| {
        let s = Secret32::from_bytes(v.as_slice().try_into().map_err(|_| Error::Corrupt("seed record"))?);
        let keys = AccountEpochKeys::from_seed(&s);
        out.insert(keys.signing.verifying_key(), Arc::new(keys));
        Ok(())
    })?;
    Ok(out)
}

/// Drops every seed of account `p` in custody here: the node left it.
pub(crate) fn shred(tx: &mut Tx<'_>, p: &Tid) -> Result<()> {
    tx.remove_scanned(&[records::SEEDS, p.as_bytes().as_slice()].concat(), |_| Ok(true))
}

/// The devices on D's roster as this node reads it (`Core::devices_roster`).
pub(crate) fn roster(core: &Core, d: &Tid) -> Vec<Tid> {
    core.account_of_root(d).map(|p| core.devices_roster(&p).into_iter().collect()).unwrap_or_default()
}

/// The seed boxes of a rotation of account `p` minting the epoch with seed `seed`: one to each
/// device on its roster (`devices`: D's roster on its line after its membership changes),
/// carrying the new seed, and to each device not on the roster of the epoch it is signed at
/// (`newcomers`: one it adds, one a fork it joins added) also the seeds this node holds of the
/// epochs on the line it makes (`line`), so it reads who minted each rotation there (spec/crypto.md
/// §9, Custody); no seed of a line beside it. Ascending by tag.
pub(crate) fn seed_boxes(tx: &mut Tx<'_>, p: &Tid, seed: &Secret32, devices: &BTreeSet<Tid>, newcomers: &BTreeSet<Tid>, line: &BTreeSet<osis_base::CommitId>) -> Result<Vec<SeedBox>> {
    let epoch = AccountEpochKeys::from_seed(seed).signing.verifying_key();
    let held: Vec<Secret32> = match (tx.core.account_view(p), tx.core.accounts.get(p)) {
        (Some(v), Some(a)) => line.iter().chain([&osis_commit::FIRST_EPOCH]).filter_map(|e| v.keys_of(e, a)).map(|k| k.seed().clone()).collect(),
        _ => Vec::new(),
    };
    let mut out = Vec::new();
    for m in devices {
        let mut payload: Vec<&Secret32> = vec![seed];
        if newcomers.contains(m) {
            payload.extend(held.iter().filter(|s| s.expose() != seed.expose()));
        }
        out.push(seed_box(tx, p, &epoch, m, &payload)?);
    }
    out.sort_by_key(|b| b.tag);
    Ok(out)
}

/// A seed box of account `p`'s epoch with signing key `epoch` to device `m`: `payload`, that
/// epoch's seed first, sealed to `m`'s KEM key, tagged by that seed and `m`.
fn seed_box(tx: &mut Tx<'_>, p: &Tid, epoch: &VerifyingKey, m: &Tid, payload: &[&Secret32]) -> Result<SeedBox> {
    let kem = match super::recipient(tx, *m, Role::Admin)?.keys {
        osis_keys::HolderKeys::KeyActor { kem, .. } => kem,
        _ => return Err(Error::Misuse("a device holds no key actor's KEM key")),
    };
    let first = payload.first().ok_or(Error::Misuse("an empty seed box"))?;
    let sealed = osis_crypto::seal_seeds(&kem, p, epoch, payload, &mut *tx.rng).map_err(|_| Error::Misuse("seed box"))?;
    Ok(SeedBox { tag: osis_crypto::seed_tag(first, m), sealed })
}

/// Seed re-seals (spec/crypto.md §9, Custody), at the end of a complete pass of D's sync IDs:
/// for each head of this node's account whose seed it holds, the
/// other devices on D's roster no counting box of that seed is tagged for (nor, a merge's, of
/// every tip's seed: they derive it) are boxed it, with the seeds
/// of its line held here, one commit per head. Bounded by structure: once held, a re-seal is a
/// counting box, so each (head, device) is re-sealed once per node that sees it lacking before it
/// holds another's. A box counts only in a commit that counts here, so a holder of an old seed (a
/// removed node) cannot hold a re-seal back with a tag over a box that opens for no one.
pub(crate) fn reseal_seeds(tx: &mut Tx<'_>) -> Result<Vec<osis_base::CommitId>> {
    let Some((p, d)) = tx.core.account_and_root() else { return Ok(Vec::new()) };
    let (Some(v), Some(held)) = (tx.core.account_view(&p), tx.core.accounts.get(&p).cloned()) else { return Ok(Vec::new()) };
    // a re-seal is signed at the preferred head: none while its seed is not here
    if !super::signing::signs_for(tx.core, &d) || tx.core.account_open_key(&p).is_none() {
        return Ok(Vec::new());
    }
    // this node holds every seed it re-seals
    let me = tx.core.id.tid();
    let roster: Vec<Tid> = roster(tx.core, &d).into_iter().filter(|m| *m != me).collect();
    let boxed = counting_tags(tx.core, &v, &d);
    let mut out = Vec::new();
    for h in v.heads() {
        let Some(keys) = v.keys_of(&h, &held) else { continue };
        let seed = keys.seed().clone();
        // a merge's seed: a device holding a counting box of every tip's derives it (Merges)
        let tips: Vec<Secret32> = if v.is_merge(&h) { v.tips_of(&h).iter().filter_map(|t| v.keys_of(t, &held)).map(|k| k.seed().clone()).collect() } else { Vec::new() };
        let derives = |m: &Tid| !tips.is_empty() && tips.iter().all(|t| boxed.contains(&osis_crypto::seed_tag(t, m)));
        let lacking: Vec<Tid> = roster.iter().filter(|m| !boxed.contains(&osis_crypto::seed_tag(&seed, m)) && !derives(m)).copied().collect();
        if lacking.is_empty() {
            continue;
        }
        let epoch = keys.signing.verifying_key();
        // the head's seed, then the seeds of its line held here: a device reads who minted each
        // rotation on the line with the seed of the epoch it is signed at
        let line: Vec<Secret32> = v.line(&h).into_iter().flatten().chain([osis_commit::FIRST_EPOCH]).filter(|r| *r != h).filter_map(|r| v.keys_of(&r, &held)).map(|k| k.seed().clone()).collect();
        let payload: Vec<&Secret32> = std::iter::once(&seed).chain(line.iter()).collect();
        let mut seeds = Vec::new();
        for m in &lacking {
            seeds.push(seed_box(tx, &p, &epoch, m, &payload)?);
        }
        seeds.sort_by_key(|b| b.tag);
        out.extend(crate::Engine::commit_tx(tx, reseal_commit(p, d, epoch, seeds)?)?);
    }
    Ok(out)
}

/// A seed re-seal of account `p` (account root `d`) of the epoch with signing key `epoch`:
/// boxes `seeds`, carried by the epoch's key added to D's `account.0` afresh (its live elements
/// removed in the same delta: an add of a key already there writes nothing, and a commit with no
/// delta is never made), so it travels under D's sync IDs to every device.
pub(crate) fn reseal_commit(p: Tid, d: Tid, epoch: VerifyingKey, seeds: Vec<SeedBox>) -> Result<crate::Mutation> {
    let key = Value::bytes(&epoch.to_bytes());
    let mut m = crate::Mutation::new();
    m.sign_as(p);
    m.op(d, &ct::ACCOUNT, PathOp { path: vec![], op: Op::Remove(key.clone()) })?;
    m.op(d, &ct::ACCOUNT, PathOp { path: vec![], op: Op::Add(key) })?;
    m.reseal = Some(SeedReseal { signing_key: epoch, seeds });
    Ok(m)
}

/// The roster devices this node sees holding every seed of `tips` (a merge's tip keys): a box of
/// each tagged for it in a commit counting here (spec/crypto.md §9, Merges: they derive the merge
/// seed, so its certificate boxes it them not).
pub(crate) fn derivers(core: &Core, v: &AccountView, d: &Tid, tips: &[Arc<AccountEpochKeys>]) -> BTreeSet<Tid> {
    let boxed = counting_tags(core, v, d);
    let roster = core.account_and_root().map(|(p, _)| core.devices_roster(&p)).unwrap_or_default();
    roster.into_iter().filter(|m| tips.iter().all(|k| boxed.contains(&osis_crypto::seed_tag(k.seed(), m)))).collect()
}

/// Derives the merge seeds of account `p` this node can (spec/crypto.md §9, Merges: a node
/// holds a merge epoch's seed iff it holds a box of it or every tip's seed) and keeps each
/// (`keep`). Run as the account's chain is judged; a merge's tips are plain rotations, whose
/// seeds are boxed, so one round derives every one.
pub(crate) fn derive_merges(tx: &mut Tx<'_>, p: &Tid) -> Result<()> {
    let (Some(v), Some(held)) = (tx.core.account_view(p), tx.core.accounts.get(p).cloned()) else { return Ok(()) };
    let mut found = Vec::new();
    for e in v.rotation_ids().into_iter().filter(|e| v.is_merge(e) && v.keys_of(e, &held).is_none()) {
        let tips = v.tips_of(&e);
        let Some(seeds) = tips.iter().map(|t| v.keys_of(t, &held).map(|k| k.seed().clone())).collect::<Option<Vec<Secret32>>>() else { continue };
        let refs: Vec<&Secret32> = seeds.iter().collect();
        let seed = osis_crypto::merge_seed(&refs);
        // a certificate claiming another key derives nothing (its epoch is not this one)
        if v.signing_key(&e) == Some(AccountEpochKeys::from_seed(&seed).signing.verifying_key()) {
            found.push(seed);
        }
    }
    for s in found {
        keep(tx, p, &s)?;
    }
    Ok(())
}

/// The tags of every seed box in a commit of the account that counts here: a counting rotation's
/// (a plain rotation, a certificate: its header), a counting re-seal's (on D's `account.0`).
fn counting_tags(core: &Core, v: &AccountView, d: &Tid) -> BTreeSet<[u8; osis_crypto::SEED_TAG_LEN]> {
    let mut out = BTreeSet::new();
    let mut take = |c: &osis_base::CommitId| {
        let Some(h) = core.ix.commits.get(c).map(|m| m.header.arc()) else { return };
        if let Some((_, boxes)) = seed_boxes_of(&h) {
            out.extend(boxes.iter().map(|b| b.tag));
        }
    };
    for e in v.rotation_ids() {
        for c in v.minting(&e).iter().filter(|c| v.rotation_counts(c)) {
            take(c);
        }
    }
    let Ok(ak) = osis_base::Ak::new("account.0") else { return out };
    for (_, c) in core.ix.by_aspect.get(&(*d, ak)).into_iter().flatten() {
        let Some(m) = core.ix.commits.get(c) else { continue };
        if !v.is_rotation(c) && m.header.reseal.is_some() && core.standing(c, &m.view) == osis_perm::EpochStanding::Counts {
            take(c);
        }
    }
    out
}

