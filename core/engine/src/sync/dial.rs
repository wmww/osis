//! Whom a node dials and where (spec/sync-opens.md §1 Where to dial, Whom to dial): `dial_peers`
//! per sync ID, from the dial records it holds (its own nodes' `reach.0`, contacts' `dial^.0`),
//! and what this node publishes of itself
//! (`publish_reach`). For dialing only, never proof.

use super::{Holding, RosterHolders};
use crate::engine::{Core, Engine, Step, Tx};
use crate::error::Result;
use crate::Mutation;
use osis_base::{Address, SyncId, Tid, peer_url};
use osis_schema::core_types as ct;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// A node's URLs from its `reach.0` items: the one `peer://` URL listing them (what its `dial^.0`
/// entry and its grants' dial hints carry).
pub(crate) fn urls_of(items: &[String]) -> Vec<String> {
    vec![peer_url(items)]
}

/// The address a dial record gives: its key at its first URL (none: not dialable).
fn address(key: &[u8], urls: &[String]) -> Option<Address> {
    Some(Address { url: urls.first()?.clone(), key: key.try_into().ok()? })
}

/// Whether this node lists itself in its account's profile dial list (`dial^.0`), so its
/// account's contacts can dial it. Every node does: the reversible reading while which nodes a
/// profile lists is Tess's open question (issues/sync-tess-calls.md).
fn lists_on_profile() -> bool {
    true
}

impl Core {
    /// Account `a`'s profile (spec/permissions.md §1): the thing created with `a` (in the commit
    /// creating it, which `a` authors: a record needs no authority, so another author's commit
    /// carrying `a`'s record again creates no profile of `a`'s) whose mint admin is `a`, other
    /// than its account root and its inbox (`inbox`, as `a`'s `keys.0` names it). `None` until
    /// that commit is held here.
    pub(crate) fn profile_of(&self, a: &Tid, inbox: Option<Tid>) -> Option<Tid> {
        let created = ct::CREATED.name();
        let by = self.ix.by_aspect.get(&(*a, created.clone()))?;
        let meta = by.iter().filter_map(|(_, c)| self.ix.commits.get(c)).find(|m| m.header.signer == *a)?;
        meta.view.aspects.iter().filter(|x| x.ak == created && x.tid != *a && Some(x.tid) != inbox).map(|x| x.tid).find(|x| self.mint_admin(x) == Some(*a) && self.account_of_root(x).is_none())
    }
}

impl Engine {
    /// See `Engine::dial_peers`.
    pub(crate) fn dial_peers_now(&mut self, s: &SyncId) -> Result<Arc<Vec<Address>>> {
        let Some((things, holding)) = self.synced_things(s)? else { return Ok(Arc::default()) };
        let mut out: BTreeMap<[u8; 32], Address> = BTreeMap::new();
        let own = self.core.account_and_root();
        // own nodes, by their `reach.0`
        for n in self.own_nodes() {
            if let Some(r) = self.get_typed(&n, &ct::REACH)? {
                out.entry(r.dialable).or_insert(Address { url: peer_url(&r.items), key: r.dialable });
            }
        }
        match holding {
            // the listed nodes of the accounts holding sync or above on S's things
            Holding::Read => {
                let accounts: BTreeSet<Tid> = things.iter().flat_map(|t| self.holder_accounts(t)).collect();
                for a in accounts {
                    if own.is_some_and(|(p, _)| p == a) {
                        continue;
                    }
                    for (k, urls) in self.dial_list(&a)? {
                        if let Some(x) = address(&k, &urls) {
                            out.entry(x.key).or_insert(x);
                        }
                    }
                }
            }
            Holding::Unread => {}
        }
        // the issuer of each ticket for S's things held here, by its profile's dial list where
        // the profile is held (spec/sync-opens.md §1: a ticket carries no address)
        let mut profiles = BTreeSet::new();
        for t in &things {
            profiles.extend(self.held_tickets(t)?.into_iter().map(|k| k.profile));
        }
        for p in profiles {
            for (k, urls) in self.get_typed(&p, &ct::DIAL)?.unwrap_or_default() {
                if let Some(x) = address(&k, &urls) {
                    out.entry(x.key).or_insert(x);
                }
            }
        }
        Ok(Arc::new(out.into_values().collect()))
    }

    /// S's things and how this node holds S; a sync ID left that sync still syncs: as read while
    /// its things' read secrets are held.
    fn synced_things(&mut self, s: &SyncId) -> Result<Option<super::Held>> {
        Ok(match self.sync_holder(s)? {
            Some(x) => Some(x),
            None => {
                let things: BTreeSet<Tid> = self.opening_things(s)?.into_iter().collect();
                (!things.is_empty()).then_some((things, Holding::Read))
            }
        })
    }

    /// See `Engine::roster_holders`: the candidates `dial_peers_now` walks, by who they are, not
    /// where they are dialed.
    pub(crate) fn roster_holders_now(&mut self, s: &SyncId) -> Result<Arc<RosterHolders>> {
        let Some((things, holding)) = self.synced_things(s)? else { return Ok(Arc::default()) };
        // kept unread: kept for the accounts that granted it, which the rosters here do not name
        if holding == Holding::Unread {
            return Ok(Arc::new(RosterHolders { anyone: true, ..RosterHolders::default() }));
        }
        let nodes = self.own_nodes().into_iter().collect();
        let own = self.core.account_and_root().map(|(p, _)| p);
        let accounts = things.iter().flat_map(|t| self.holder_accounts(t)).filter(|a| Some(*a) != own).collect();
        Ok(Arc::new(RosterHolders { anyone: false, nodes, accounts }))
    }

    /// This account's other nodes (no node sees what a sibling holds: spec/sync.md).
    fn own_nodes(&self) -> Vec<Tid> {
        let Some((_, d)) = self.core.account_and_root() else { return Vec::new() };
        self.core.key_holders(&d).into_iter().map(|(n, _)| n).filter(|n| self.core.own_node(n)).collect()
    }

    /// The accounts holding a role on `t`'s independent, directly or through the actors holding
    /// it (every role is sync or above), by the rosters held here.
    fn holder_accounts(&self, t: &Tid) -> BTreeSet<Tid> {
        self.core.holder_accounts_of(self.core.reader_of(t))
    }


    /// See `Core::profile_of`.
    pub fn profile_of(&mut self, a: &Tid) -> Option<Tid> {
        let inbox = self.inbox_thing(a);
        self.core.profile_of(a, inbox)
    }

    /// Account `a`'s dial list: `dial^.0` on its profile, as held here.
    fn dial_list(&mut self, a: &Tid) -> Result<ct::DialList> {
        let Some(p) = self.profile_of(a) else { return Ok(ct::DialList::new()) };
        Ok(self.get_typed(&p, &ct::DIAL)?.unwrap_or_default())
    }

    /// Publishes where this node is dialed (spec/sync-transport.md §3, §5 Key change): its
    /// `reach.0` (dialable key `dialable`, the `peer://` items it listens at, its account), and
    /// its own entry in its account's profile dial list (`dial^.0`, spec/sync-set.md §1) in place
    /// of the one under its key before. Each only where it changed; the entry once the profile is
    /// held here (a node paired a moment ago writes it at a later call). A node of no account
    /// publishes nothing.
    pub fn publish_reach(&mut self, dialable: [u8; 32], items: Vec<String>) -> Result<()> {
        let Some((p, _)) = self.core.account_and_root() else { return Ok(()) };
        let me = self.core.id.tid();
        let reach = ct::Reach { dialable, items, account: Some(osis_base::Weak(p)) };
        let before = self.get_typed(&me, &ct::REACH)?;
        if before.as_ref() != Some(&reach) {
            // a commit of its own, touching nothing else (spec/permissions.md §4)
            let mut m = Mutation::new();
            m.set(me, &ct::REACH, &reach)?;
            self.commit(m)?;
        }
        let Some(profile) = self.profile_of(&p).filter(|x| self.core.writable(x) && self.closure_holds(x) && lists_on_profile()) else { return Ok(()) };
        let mut list = self.get_typed(&profile, &ct::DIAL)?.unwrap_or_default();
        let old = list.clone();
        if let Some(b) = before.filter(|b| b.dialable != dialable) {
            list.remove(b.dialable.as_slice());
        }
        list.insert(dialable.to_vec(), urls_of(&reach.items));
        if list != old {
            let mut m = Mutation::new();
            m.set(profile, &ct::DIAL, &list)?;
            self.commit(m)?;
        }
        Ok(())
    }
}

/// `departed`'s value: the profile and the dialable keys to drop from its dial list.
pub(crate) type Departed = Option<(Tid, BTreeSet<Vec<u8>>)>;

/// The entries of this node's account's dial list (`dial^.0` on its profile) of nodes removed
/// from its account root D (spec/sync-set.md §1 Dial list): the dialable keys of the `reach.0`
/// held of each node a counting removal took off D that holds no role there now, but for a key
/// some node on D's `reach.0` names (that node's own entry: a node about to be removed could
/// name another's key in its `reach.0`), with the profile; `None` when this node writes no
/// profile (no account, or the profile not held or not writable here).
fn departed(tx: &mut Tx<'_>) -> Result<Departed> {
    let Some((p, d)) = tx.core.account_and_root() else { return Ok(None) };
    let inbox = crate::flows::inbox::inbox_in(tx, &p)?;
    let Some(profile) = tx.core.profile_of(&p, inbox).filter(|x| tx.core.writable(x)) else { return Ok(None) };
    let list = typed(tx, &profile, &ct::DIAL)?.unwrap_or_default();
    if list.is_empty() {
        return Ok(Some((profile, BTreeSet::new())));
    }
    let current: BTreeSet<Tid> = tx.core.devices_roster(&p);
    let v = tx.core.account_view(&p);
    let gone: BTreeSet<Tid> = v.iter().flat_map(|v| v.rotation_ids().into_iter().filter(|r| v.rotation_counts(r)).flat_map(|r| v.removes(&r))).filter(|n| !current.contains(n)).collect();
    let _ = d;
    let mut out = BTreeSet::new();
    for n in gone {
        if let Some(r) = typed(tx, &n, &ct::REACH)?.filter(|r| list.contains_key(r.dialable.as_slice())) {
            out.insert(r.dialable.to_vec());
        }
    }
    if !out.is_empty() {
        for n in &current {
            if let Some(r) = typed(tx, n, &ct::REACH)? {
                out.remove(r.dialable.as_slice());
            }
        }
    }
    Ok(Some((profile, out)))
}

/// `key`'s value on `t` as held in this transaction.
fn typed<K: osis_schema::RawKey>(tx: &mut Tx<'_>, t: &Tid, key: &K) -> Result<Option<K::T>> {
    let ak = osis_base::Ak::new(key.ak()).map_err(|_| crate::Error::Misuse("invalid AK"))?;
    match tx.state(t, &ak)?.and_then(osis_crdt::Fragment::read) {
        Some(v) => Ok(Some(key.decode(&v)?)),
        None => Ok(None),
    }
}

/// A node removed from its account has no entry in the account's dial list (spec/sync-set.md §1
/// Dial list): at each transaction's end that moved what `departed` read, this node, writing its
/// account's profile, removes the entries of removed nodes it finds there, whoever wrote them
/// and whenever (a removed node's entry written beside its removal goes too), in one commit of
/// its own. A step (`Tx::step`): one that fails leaves nothing, is reported
/// (`DiagnosticKind::OwnWriteFailed`) and stays due.
pub(crate) fn drop_departed(tx: &mut Tx<'_>) -> Result<()> {
    let mut fx = std::mem::replace(&mut tx.core.dial_departed, osis_base::memo::Effects::new("sync: dial list departed"));
    fx.want(());
    let r = if fx.due().is_empty() { Ok(()) } else { drop_due(tx, &mut fx) };
    tx.core.dial_departed = fx;
    r
}

fn drop_due(tx: &mut Tx<'_>, fx: &mut osis_base::memo::Effects<(), Departed>) -> Result<()> {
    let mut now = None;
    fx.try_settle(&(), || {
        let v = departed(tx)?;
        now = v.clone();
        Ok::<_, crate::Error>(v)
    })?;
    let Some((profile, keys)) = now.filter(|(_, k)| !k.is_empty()) else { return Ok(()) };
    let wrote = tx.step(Step::Dial, |tx| {
        let mut m = Mutation::new();
        for k in &keys {
            m.op(profile, &ct::DIAL, osis_crdt::PathOp { path: Vec::new(), op: osis_crdt::Op::Remove(osis_base::Value::bytes(k)) })?;
        }
        Engine::commit_tx(tx, m).map(|_| ())
    });
    if let Err(e) = wrote {
        // due again at the next transaction's end
        fx.unwant(&());
        tx.core.events.diagnostic(crate::events::Diagnostic { kind: crate::events::DiagnosticKind::OwnWriteFailed, tids: vec![profile], commit: None, peer: None, detail: e.to_string() }, tx.core.hlc.mono());
    }
    Ok(())
}
