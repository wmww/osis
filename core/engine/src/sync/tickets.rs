//! Tickets held (spec/data-model.md §8 Tickets, spec/sync-inbox.md §5, spec/sync.md §3): found
//! among the known references by their target's tid, opened as a `secrets.0` box of the target
//! to its holder is, and the secrets they give.

use crate::engine::{Core, Engine, Tx};
use crate::error::Result;
use std::collections::BTreeSet;
use osis_base::{Role, SyncId, Tid, Ticket};
use osis_crypto::{Epoch, Secret32};
use osis_keys::{Opened, Opener};
use osis_schema::Codec;
use osis_schema::core_types::{self as ct, SecretBox, Secrets};

impl Core {
    /// The secret ticket `k` boxes, when this node holds a key its box opens under (spec/data-model.md
    /// §8 Tickets: as a `secrets.0` box of the target to the holder): its own, a held key actor's,
    /// an actor's whose secrets it holds, or its account's.
    pub(crate) fn open_ticket(&self, k: &Ticket) -> Option<Opened> {
        let b = SecretBox::from_value(&k.boxed).ok()?;
        let epoch = ct::Epoch { n: k.epoch.0, nonce: k.epoch.1 };
        let key = ct::BoxKey { holder: k.holder.into(), role: k.role, epoch };
        let secrets = Secrets { boxes: [(key, b)].into(), ..Secrets::default() };
        let try_with = |o: &Opener| osis_keys::open_boxes(&k.target, &secrets, o).0.into_iter().next();
        let h = k.holder;
        if h == self.id.tid() {
            return try_with(&Opener::KeyActor { holder: h, keys: self.id.keys() });
        }
        if let Some(a) = self.key_actors.get(&h) {
            return try_with(&Opener::KeyActor { holder: h, keys: a.keys() });
        }
        if self.accounts.contains_key(&h) {
            let keys = self.account_keys_by_name(&h);
            return try_with(&Opener::Account { holder: h, keys: &keys });
        }
        let e = self.ix.secrets.get(&h)?;
        try_with(&Opener::Actor { holder: h, epochs: e })
    }
}

/// The tickets for `t` among the known references (spec/data-model.md §8), as held now, read from
/// its ticket rows alone (`refs::tickets_to`: each row holds its tickets), never a source's state
/// or a signal's other fires.
pub(crate) fn held_in(tx: &mut Tx<'_>, t: &Tid) -> Result<Vec<Ticket>> {
    let mut out = Vec::new();
    for r in crate::engine::refs::tickets_to(tx, t)? {
        // a signal's references are its held valid fires' (spec/data-model.md §8 Known references)
        if let Some(c) = r.fire
            && !tx.core.ix.commits.get(&c).is_some_and(|m| m.aspect(&r.source, &r.ak).is_some_and(|ai| m.holds(ai) && m.valid_at(ai)))
        {
            continue;
        }
        out.extend(r.tickets);
    }
    out.sort();
    out.dedup();
    Ok(out)
}

/// The held tickets for `t` this node can open, each with what it opens to.
fn opened_in(tx: &mut Tx<'_>, t: &Tid) -> Result<Vec<(Ticket, Opened)>> {
    Ok(held_in(tx, t)?.into_iter().filter_map(|k| tx.core.open_ticket(&k).map(|o| (k, o))).collect())
}

/// The walk's ticket taking, at a strong to `t` whose read secret is
/// not established (spec/sync-set.md §2): each held ticket's secret taken, and the sync IDs and
/// roles of the tickets the node can open.
pub(crate) fn take_in(tx: &mut Tx<'_>, t: &Tid) -> Result<BTreeSet<(SyncId, Role)>> {
    let mut ids = BTreeSet::new();
    // the role commits held of `t` decide (spec/sync-set.md §2: a ticket whose holder holds no
    // role on `t` enters nothing); with none held, the ticket's word
    if tx.core.timelines.get(t).is_some() && !crate::rotation::may_take(tx.core, t) {
        return Ok(ids);
    }
    for (k, o) in opened_in(tx, t)? {
        crate::apply::keys::learn_secret_in(tx, &k.target, o.role, o.epoch, o.secret)?;
        ids.insert((k.sync_id, o.role.min(k.role)));
    }
    // the role commits a read ticket's fire carries are taken now the strong reaches `t`, while
    // it has no own keys here (`Engine::take_ticket_fires`); a node keeping `t` unread holds no
    // role commit of it (spec/sync.md §3)
    if ids.iter().any(|(_, r)| *r >= Role::Read) && !tx.core.keyed(t) {
        for r in crate::engine::refs::tickets_to(tx, t)? {
            if let Some(c) = r.fire.filter(|_| r.ak.as_str() == crate::flows::inbox::TICKET_FIRE) {
                tx.core.ix.closure.fires_due.insert(c);
            }
        }
    }
    Ok(ids)
}

impl Engine {
    /// Takes the role parts of each ticket fire whose ticket the walk took
    /// (`Engine::take_ticket_fire`); whether any was due.
    pub fn take_ticket_fires(&mut self) -> Result<bool> {
        let due: Vec<osis_base::CommitId> = self.core.ix.closure.fires_due.iter().copied().collect();
        if due.is_empty() {
            return Ok(false);
        }
        self.run(|tx| {
            for c in &due {
                tx.core.ix.closure.fires_due.remove(c);
            }
            Ok(())
        })?;
        for c in &due {
            self.take_ticket_fire(c)?;
        }
        Ok(true)
    }

    /// See `held_in`.
    pub fn held_tickets(&mut self, t: &Tid) -> Result<Vec<Ticket>> {
        let t = *t;
        self.read(|tx| held_in(tx, &t))
    }

    fn opened_tickets(&mut self, t: &Tid) -> Result<Vec<(Ticket, Opened)>> {
        let t = *t;
        self.read(|tx| opened_in(tx, &t))
    }
}

impl Engine {
    /// The held ticket for `t` this node can open (spec/data-model.md §8 Tickets, spec/sync-set.md
    /// §2): of the read role before the sync role, the newest epoch first.
    pub fn ticket_for(&mut self, t: &Tid) -> Result<Option<Ticket>> {
        let mut all = self.opened_tickets(t)?;
        all.sort_by_key(|(k, _)| (k.role == Role::Read, k.epoch.0));
        Ok(all.pop().map(|(k, _)| k))
    }

    /// The sync secrets of kept-unread `s`'s things that the tickets held here naming `s` give,
    /// by epoch: every one of its things alike (spec/sync.md §3 Kept sync IDs).
    pub fn ticket_sync_secrets(&mut self, s: &SyncId) -> Vec<(Epoch, Secret32)> {
        let Ok(things) = self.sync_things_of(s) else { return Vec::new() };
        let mut out = Vec::new();
        for t in things {
            let Ok(all) = self.opened_tickets(&t) else { continue };
            out.extend(all.into_iter().filter(|(k, o)| k.role == Role::Sync && o.role == Role::Sync && k.sync_id == *s).map(|(_, o)| (o.epoch, o.secret)));
        }
        out
    }
}
