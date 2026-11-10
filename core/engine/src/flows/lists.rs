//! Thing lists and listings held (spec/permissions.md §5.5): the words naming an account's
//! commits at closed epochs. A rotation's thing lists arrive as list blobs (spec/sync.md §3) and
//! are kept as certificates, permanently, like the role commits they name; a listing is a commit
//! whose `listing.0` deltas are read once, at apply. Both become name rows (`records::NAMES`:
//! commit, thing, source; `records::NAMED_BY`: the reverse), which `refresh_epochs` reads for
//! the commits whose standing may have moved, so a read or an open walks no list.

use crate::engine::{Engine, Tx, records};
use crate::error::{Error, Result};
use osis_base::{CommitId, Tid, Value};
use osis_commit::thing_list::{ListIds, ThingCert, decode_list_blob, encode_list_blob};
use osis_perm::epochs::{ListPath, list_leaf};
use osis_store::Shred;
use std::collections::BTreeSet;

/// What holding a list blob did (`Engine::hold_lists`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ListsHeld {
    /// Its thing lists verified against their rotation's list root and are kept.
    Held,
    /// Every one of them was held already.
    Known,
    /// Its rotation is not held: kept nowhere, to fetch again once it is.
    Awaits(CommitId),
    /// Not a list blob of one rotation, or a cert that does not verify: bad input.
    Bad,
}

/// A name row: `commit` named on `thing` by `source` (a rotation's thing list, or a listing).
fn name_key(commit: &CommitId, thing: &Tid, source: &CommitId) -> Vec<u8> {
    [records::NAMES, &commit.0[..], thing.as_bytes(), &source.0[..]].concat()
}

fn named_by_key(source: &CommitId, commit: &CommitId, thing: &Tid) -> Vec<u8> {
    [records::NAMED_BY, &source.0[..], &commit.0[..], thing.as_bytes()].concat()
}

fn list_key(rotation: &CommitId, thing: &Tid, index: u64) -> Vec<u8> {
    [records::LISTS, &rotation.0[..], thing.as_bytes(), &index.to_be_bytes()[..]].concat()
}

/// Records that `source` names `commits` on `thing`; each held one may stand otherwise now.
pub(crate) fn put_names(tx: &mut Tx<'_>, source: &CommitId, thing: &Tid, commits: impl IntoIterator<Item = CommitId>) -> Result<()> {
    for c in commits {
        tx.txn.put_local(&name_key(&c, thing, source), &[], Shred::No)?;
        tx.txn.put_local(&named_by_key(source, &c, thing), &[], Shred::No)?;
        due(tx, &c);
    }
    Ok(())
}

/// Held commit `c` of an account may be named otherwise: judged again (`refresh_epochs`).
pub(crate) fn due(tx: &mut Tx<'_>, c: &CommitId) {
    let Some(m) = tx.core.ix.commits.get(c) else { return };
    if m.view.epoch.is_some() {
        let author = m.view.author;
        tx.core.ix.names_due.insert(*c);
        tx.core.ix.epochs_due.insert(author);
    }
}

/// The names of `c`: (thing, source) per row.
pub(crate) fn names_of(tx: &mut Tx<'_>, c: &CommitId) -> Result<Vec<(Tid, CommitId)>> {
    let mut out = Vec::new();
    tx.scan(&[records::NAMES, &c.0[..]].concat(), |k, _| {
        let (t, s) = k.split_at_checked(15).ok_or(Error::Corrupt("name row"))?;
        out.push((Tid::from_bytes(t.try_into().map_err(|_| Error::Corrupt("name row"))?), CommitId(s.try_into().map_err(|_| Error::Corrupt("name row"))?)));
        Ok(())
    })?;
    Ok(out)
}

/// What `source` names: (commit, thing) per row.
pub(crate) fn named_by(tx: &mut Tx<'_>, source: &CommitId) -> Result<Vec<(CommitId, Tid)>> {
    let mut out = Vec::new();
    tx.scan(&[records::NAMED_BY, &source.0[..]].concat(), |k, _| {
        let (c, t) = k.split_at_checked(32).ok_or(Error::Corrupt("name row"))?;
        out.push((CommitId(c.try_into().map_err(|_| Error::Corrupt("name row"))?), Tid::from_bytes(t.try_into().map_err(|_| Error::Corrupt("name row"))?)));
        Ok(())
    })?;
    Ok(out)
}

/// Keeps verified thing certs of one rotation and their names (its rotator's own included);
/// whether any was new.
pub(crate) fn keep_certs(tx: &mut Tx<'_>, certs: &[ThingCert]) -> Result<bool> {
    let mut new = false;
    for c in certs {
        let key = list_key(&c.rotation, &c.list.thing, c.index);
        if tx.txn.get_local(&key)?.is_some() {
            continue;
        }
        new = true;
        tx.txn.put_local(&key, &encode_list_blob(std::slice::from_ref(c)), Shred::No)?;
        if let ListIds::Inline(ids) = &c.list.ids {
            put_names(tx, &c.rotation, &c.list.thing, ids.iter().copied())?;
        }
    }
    Ok(new)
}

/// The thing certs held of `rotation` whose thing is in `things` (all: `None`).
pub(crate) fn certs_of(tx: &mut Tx<'_>, rotation: &CommitId, things: Option<&BTreeSet<Tid>>) -> Result<Vec<ThingCert>> {
    let mut out = Vec::new();
    tx.scan(&[records::LISTS, &rotation.0[..]].concat(), |k, v| {
        let t = Tid::from_bytes(k.get(..15).and_then(|t| t.try_into().ok()).ok_or(Error::Corrupt("list row"))?);
        if things.is_none_or(|x| x.contains(&t)) {
            out.extend(decode_list_blob(&v).map_err(|_| Error::Corrupt("list row"))?);
        }
        Ok(())
    })?;
    Ok(out)
}

/// Whether `cert` sits under `root` (spec/wire.md §4, List tree).
pub(crate) fn verifies(cert: &ThingCert, root: &[u8; 32]) -> bool {
    ListPath { index: cert.index, siblings: cert.siblings.clone() }.verify(list_leaf(&cert.list.encode()), root)
}

impl Engine {
    /// What rotation `r`'s thing lists held here name: per thing, the commits (inline lists).
    /// From the name rows (`records::NAMED_BY`): no cert is decoded.
    pub fn rotation_lists(&mut self, r: &CommitId) -> Result<Vec<(Tid, Vec<CommitId>)>> {
        let r = *r;
        let rows = self.run(|tx| named_by(tx, &r))?;
        let mut by: std::collections::BTreeMap<Tid, Vec<CommitId>> = std::collections::BTreeMap::new();
        for (c, t) in rows {
            by.entry(t).or_default().push(c);
        }
        Ok(by.into_iter().collect())
    }

    /// The rotations of account `p` held here.
    pub fn account_rotations(&self, p: &Tid) -> Vec<CommitId> {
        self.core.account_view(p).map(|v| v.rotation_ids()).unwrap_or_default()
    }

    /// Holds list blob plaintext `plain` (spec/sync.md §3, List blobs): every cert of one
    /// rotation, each verified against that rotation's list root. A list whose IDs are linked
    /// is kept without its names (linked thing lists are not read yet: issues/account-signing.md).
    pub fn hold_lists(&mut self, plain: &[u8]) -> Result<ListsHeld> {
        let Ok(certs) = decode_list_blob(plain) else { return Ok(ListsHeld::Bad) };
        let Some(r) = certs.first().map(|c| c.rotation) else { return Ok(ListsHeld::Bad) };
        if certs.iter().any(|c| c.rotation != r) {
            return Ok(ListsHeld::Bad);
        }
        let Some(root) = self.header(&r).and_then(|h| h.rotation.as_ref().map(|x| x.list_root)) else {
            return Ok(if self.core.ix.commits.contains_key(&r) { ListsHeld::Bad } else { ListsHeld::Awaits(r) });
        };
        if !certs.iter().all(|c| verifies(c, &root)) {
            return Ok(ListsHeld::Bad);
        }
        let new = self.run(|tx| {
            let new = keep_certs(tx, &certs)?;
            crate::apply::atomic::rejudged(tx, false)?;
            Ok(new)
        })?;
        Ok(if new { ListsHeld::Held } else { ListsHeld::Known })
    }

    /// The list blob plaintext of rotation `r` for things in `things` (every held one: `None`),
    /// from its certs held here, or `None` when none is held: what a node of the rotation's
    /// account places under a label holding those things (spec/permissions.md §5.5, Chains
    /// travel).
    pub fn list_blob(&mut self, r: &CommitId, things: Option<&BTreeSet<Tid>>) -> Result<Option<Vec<u8>>> {
        let r = *r;
        let things = things.cloned();
        let certs = self.run(|tx| certs_of(tx, &r, things.as_ref()))?;
        Ok((!certs.is_empty()).then(|| encode_list_blob(&certs)))
    }
}

/// Notes the names a listing commit's `listing.0` parts give (spec/permissions.md §5.5): per
/// part on thing T, every commit ID an entry its delta puts lists, read from the delta, never
/// as state. Only an account's role commit lists; what it names counts by `refresh_epochs`.
pub(crate) fn note_listing(tx: &mut Tx<'_>, h: &osis_commit::Header, id: &CommitId, parts: &[(usize, osis_commit::Decoded)]) -> Result<()> {
    if h.epoch.is_none() || !h.kind.is_role() {
        return Ok(());
    }
    for (ai, d) in parts {
        let (Some(a), osis_commit::Decoded::Delta(d)) = (h.aspects.get(*ai), d) else { continue };
        if a.ak.as_str() != "listing.0" {
            continue;
        }
        let Some(Value::Map(m)) = d.fragment.read() else { continue };
        let mut ids = BTreeSet::new();
        for (_, v) in m.iter() {
            let set: Vec<&Value> = match v {
                Value::List(x) => x.iter().collect(),
                Value::Set(x) => x.iter().collect(),
                _ => continue,
            };
            ids.extend(set.into_iter().filter_map(|x| match x {
                Value::Bytes(b) => <[u8; 32]>::try_from(b.as_slice()).ok().map(CommitId),
                _ => None,
            }));
        }
        put_names(tx, id, &a.tid, ids)?;
    }
    Ok(())
}
