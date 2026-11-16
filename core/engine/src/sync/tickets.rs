//! Tickets held (spec/data-model.md §8 Tickets, spec/sync-inbox.md §5, spec/sync.md §3): found
//! among the known references by their target's tid, opened as a `secrets.0` box of the target
//! to its holder is, and the secrets they give.

use crate::engine::{Core, Engine, Tx};
use crate::error::Result;
use osis_base::{Ak, RefKind, Role, SyncId, Tid, Ticket, Value};
use osis_crypto::{Epoch, Secret32};
use osis_keys::{Opened, Opener};
use osis_schema::Codec;
use osis_schema::core_types::{self as ct, SecretBox, Secrets};

/// Every ticket for `t` in `v`, at any depth.
fn tickets_in(v: &Value, t: &Tid, out: &mut Vec<Ticket>) {
    match v {
        Value::Ticket(x) if x.target == *t => out.push((**x).clone()),
        Value::Enum(_, Some(p)) => tickets_in(p, t, out),
        Value::Map(m) => m.iter().for_each(|(k, x)| {
            tickets_in(k, t, out);
            tickets_in(x, t, out);
        }),
        Value::List(x) => x.iter().for_each(|x| tickets_in(x, t, out)),
        Value::Set(x) => x.iter().for_each(|x| tickets_in(x, t, out)),
        _ => {}
    }
}

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

/// The tickets for `t` among the known references (spec/data-model.md §8), as held now.
pub(crate) fn held_in(tx: &mut Tx<'_>, t: &Tid) -> Result<Vec<Ticket>> {
    let rows = crate::engine::refs::to(tx, t)?;
    let mut out = Vec::new();
    let mut seen: Vec<(Tid, Ak)> = Vec::new();
    for r in rows.into_iter().filter(|r| r.kind == RefKind::Ticket) {
        if seen.contains(&(r.source, r.ak.clone())) {
            continue;
        }
        seen.push((r.source, r.ak.clone()));
        // a signal's references are its held valid fires' (spec/data-model.md §8 Known references)
        if r.ak.signal() {
            let held: Vec<osis_base::CommitId> = tx.core.ix.by_aspect.get(&(r.source, r.ak.clone())).into_iter().flatten().map(|x| x.1).collect();
            for c in held {
                let Some(ai) = tx.core.ix.commits.get(&c).and_then(|m| m.aspect(&r.source, &r.ak).filter(|ai| m.holds(*ai) && m.valid_at(*ai))) else { continue };
                crate::apply::each_held_piece(tx, &c, ai, &mut |_, f| {
                    if let Some(v) = f.read() {
                        tickets_in(&v, t, &mut out);
                    }
                    Ok(())
                })?;
            }
        } else if let Some(v) = tx.state(&r.source, &r.ak)?.and_then(osis_crdt::Fragment::read) {
            tickets_in(&v, t, &mut out);
        }
    }
    out.sort();
    out.dedup();
    Ok(out)
}

/// The held tickets for `t` this node can open, each with what it opens to.
fn opened_in(tx: &mut Tx<'_>, t: &Tid) -> Result<Vec<(Ticket, Opened)>> {
    Ok(held_in(tx, t)?.into_iter().filter_map(|k| tx.core.open_ticket(&k).map(|o| (k, o))).collect())
}

/// `Engine::take_ticket` in a transaction: the walk's, at a strong to `t` it cannot enter by
/// the secrets held (spec/sync-set.md §2).
pub(crate) fn take_in(tx: &mut Tx<'_>, t: &Tid) -> Result<bool> {
    let mut learned = false;
    for (k, o) in opened_in(tx, t)? {
        learned |= crate::apply::keys::learn_secret_in(tx, &k.target, o.role, o.epoch, o.secret)?;
    }
    Ok(learned)
}

impl Engine {
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

    /// Takes the secret of the held ticket for `t` (`ticket_for`) as its epoch's
    /// (`Engine::learn_secret`: only where the node's roles on `t` allow it, spec/permissions.md
    /// §3 No secret taken back). Whether one was learned.
    pub fn take_ticket(&mut self, t: &Tid) -> Result<bool> {
        let t = *t;
        self.run(|tx| take_in(tx, &t))
    }

    /// The sync secrets of kept-unread `s`'s thing that the tickets held here give, by epoch
    /// (spec/sync.md §3).
    pub fn ticket_sync_secrets(&mut self, s: &SyncId) -> Vec<(Epoch, Secret32)> {
        let Ok(Some(t)) = self.sync_owner_of(s) else { return Vec::new() };
        let Ok(all) = self.opened_tickets(&t) else { return Vec::new() };
        all.into_iter().filter(|(k, o)| k.role == Role::Sync && o.role == Role::Sync && k.sync_id == *s).map(|(_, o)| (o.epoch, o.secret)).collect()
    }
}
