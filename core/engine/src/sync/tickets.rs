//! Tickets held (Interim (issues/tickets-retired.md); spec/sync.md §3): found
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
            let keys = self.account_keys(&h);
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

/// The node's role on `t` now (spec/sync-set.md §2; held tickets: Interim (issues/tickets-retired.md)), the one judgement
/// both entering `t` by a ticket (`take_in`, `units::given_by`) and the lost-access trigger
/// (`rotation::lost`) read: the best its role commits show (`rotation::role_here`) and, while a
/// held strong reaches `t` with a ticket that opens here (`Closure::accepted`), a ticket's word
/// where the role commits cannot decide: a sync word (`t` kept unread: the node holds only the
/// role commits other things' certificates bring, which reach its holder through other holders
/// without its own grant), and a read word while no held role commit reaches its holder by any
/// path (`Held::upstream`: an edge of it on `t`, or on a thing such a commit names, and so on).
/// A ticket says how to sync, never caps the role: it supplies its secret and sync ID up to the
/// lower of its own role and this one.
pub(crate) fn role_on(core: &Core, t: &Tid) -> Option<Role> {
    let word = words_on(core, t).into_iter().filter(|(_, counts)| *counts).map(|((_, r), _)| r).max();
    crate::rotation::role_here(core, t).max(word)
}

/// The ticket words `role_on` reads on `t`, each (holder, role) with whether it counts: none
/// unless `t` is accepted; a sync word counts, a read word while no held role commit reaches its
/// holder.
pub(crate) fn words_on(core: &Core, t: &Tid) -> Vec<((Tid, Role), bool)> {
    let words = if core.ix.closure.accepted(t) { core.ix.closure.ticket_words(t) } else { BTreeSet::new() };
    let reached = if words.iter().any(|(_, r)| *r >= Role::Read) { core.ix.held.upstream(&BTreeSet::from([*t])) } else { BTreeSet::new() };
    words.into_iter().map(|(h, r)| ((h, r), r == Role::Sync || !reached.contains(&h))).collect()
}

/// What the walk's ticket step took of a thing's held tickets (`take_in`).
pub(crate) struct Taken {
    /// The sync IDs of the tickets that enter, each with the role it supplies (the lower of its own
    /// and `role_on`).
    pub(crate) ids: BTreeSet<(SyncId, Role)>,
    /// The holders every held ticket is boxed to, opened or not.
    pub(crate) openers: BTreeSet<Tid>,
    /// Whether any held ticket opens here (`Closure::accepted`).
    pub(crate) opened: bool,
}

/// The walk's ticket taking at a strong to `t` whose read secret is not established
/// (spec/sync-set.md §2): each held ticket the node can open supplies its sync ID and, where the
/// node's role (`role_on`) is the ticket's own role or above, its secret; and its openers, the holders every held ticket for
/// `t` is boxed to, which the step is judged again by as they can open more
/// (`Closure::opener_moved`). With a read ticket opening, the commits its ticket fires' `grant`
/// carry on `t` are due, and its removal notices are judged at the transaction's end
/// (`Core::removals_due`): what they show is what `role_on` judges by next. O(its tickets).
pub(crate) fn take_in(tx: &mut Tx<'_>, t: &Tid, v: crate::sync::units::Vx) -> Result<Taken> {
    let held = held_in(tx, t)?;
    let openers = held.iter().map(|k| k.holder).collect();
    let opened: Vec<(Ticket, Opened)> = held.into_iter().filter_map(|k| tx.core.open_ticket(&k).map(|o| (k, o))).collect();
    let any = !opened.is_empty();
    let reads = opened.iter().any(|(k, o)| k.role.min(o.role) == Role::Read);
    let words: BTreeSet<(Tid, Role)> = opened.iter().map(|(k, o)| (k.holder, k.role.min(o.role))).collect();
    // noted before any secret is taken: taking one asks the role (`role_on`) as the trigger does
    tx.core.ix.closure.set_ticket_words(*t, words);
    crate::sync::units::set_accepted(tx, *t, v, any);
    let role = role_on(tx.core, t);
    let mut ids = BTreeSet::new();
    for (k, o) in opened {
        let own = o.role.min(k.role);
        let Some(e) = role.map(|e| e.min(own)) else { continue };
        if e >= o.role {
            crate::apply::keys::learn_secret_in(tx, &k.target, o.role, o.epoch, o.secret)?;
        }
        ids.insert((k.sync_id, e));
    }
    // only a read ticket's: a sync ticket enters at sync at most, and a node keeping `t` unread
    // by its word reads no role commit of it (spec/sync.md §3)
    if reads {
        for r in crate::engine::refs::tickets_to(tx, t)? {
            if let Some(c) = r.fire
                && crate::flows::inbox::fire_untaken(tx, &c, r.ak.as_str())?
            {
                tx.core.ix.closure.fires_due.insert(c);
            }
        }
    }
    tx.core.removals_due.insert(*t);
    Ok(Taken { ids, openers, opened: any })
}

impl Engine {
    /// Takes the commit each due fire carries (`Closure::fires_due`, `Engine::take_fire`); whether any was
    /// due.
    pub fn take_carried(&mut self) -> Result<bool> {
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
            self.take_fire(c)?;
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
    /// The held ticket for `t` this node can open (Interim (issues/tickets-retired.md)): of the read role before the sync role, the newest epoch first.
    pub fn ticket_for(&mut self, t: &Tid) -> Result<Option<Ticket>> {
        let mut all = self.opened_tickets(t)?;
        all.sort_by_key(|(k, _)| (k.role == Role::Read, k.epoch.0));
        Ok(all.pop().map(|(k, _)| k))
    }

    /// The held sync secrets of kept-unread `s`'s things, by epoch: those the tickets held here
    /// naming `s` give, and those held from the node's own reading (a node lowered to sync keeps
    /// its sync secrets, `rotation::lost`); every one of its things alike (spec/sync.md §3 Kept
    /// sync IDs, Held sync secrets).
    pub fn kept_sync_secrets(&mut self, s: &SyncId) -> Vec<(Epoch, Secret32)> {
        let Ok(things) = self.sync_things_of(s) else { return Vec::new() };
        let mut out = Vec::new();
        for t in things {
            if let Some(e) = self.core.epochs(&t) {
                out.extend(e.role(Role::Sync).held_newest_first().into_iter().map(|(ep, x)| (ep, x.clone())));
            }
            let Ok(all) = self.opened_tickets(&t) else { continue };
            out.extend(all.into_iter().filter(|(k, o)| k.role == Role::Sync && o.role == Role::Sync && k.sync_id == *s).map(|(_, o)| (o.epoch, o.secret)));
        }
        out
    }
}
