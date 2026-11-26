//! Cards (spec/sync-inbox.md §1 Card, spec/data-model.md §9): A's card on any thing C is the
//! value of A's card aspect on C (`card_ak`), written whole along a path through A: A's and A's
//! inbox's current `keys.0` commits in the holder keys form. A's inbox is A's own: the `inbox`
//! field of A's `keys.0` (an admin's write, `Engine::set_inbox`), else A. A node reading C takes
//! those commits as holder keys (`Engine::take_cards`); at a pass's end a node that may write C
//! along a path through A rewrites the card when a rewrite would carry newer `keys.0` parts on A
//! or its inbox. A card aspect is retained, snapshotted and covered as any content aspect: its
//! snapshots, as its writes, state a path through A.
//!
//! Invariant: a card counts only written along a path through A (`apply::validity::note_cards`),
//! and what it carries counts only as judged here (`take_holder_keys`: what is on A's or the
//! inbox's authority chain, each commit judged valid). Who writes each input: a card, a writer of
//! C along a path through A (a writer of A: it reads A anyway); its commits, A's and the inbox's
//! admins (judged), so where grants to A go is chosen by A's admins alone (the inbox field needs
//! admin, `validity::rotation_required`); C's other writers may remove a card, never put one. A
//! removed writer of A writes no valid card once its removal applies; a stranger holding an old
//! card seals to A's keysets as of that card until a newer one reaches it (spec/sync-inbox.md §2:
//! what it seals is judged by A's readers). A card on a thing no node may write along a path
//! through A any longer stays as written.

use crate::engine::{Engine, Tx};
use crate::error::Result;
use crate::Mutation;
use osis_base::{Role, Tid, Value, Weak};
use osis_crdt::{Fragment, Op, PathOp, PathSeg};
use osis_perm::graph::Need;
use osis_schema::core_types::{self as ct, card_ak, card_of};
use osis_schema::Codec;
use std::collections::{BTreeMap, BTreeSet};

/// `a`'s card on `host` as its state holds it here: none where it does not read as a card.
pub(crate) fn card_on(tx: &mut Tx<'_>, host: &Tid, a: &Tid) -> Result<Option<ct::Card>> {
    let v = tx.state(host, &card_ak(a))?.and_then(Fragment::read);
    Ok(v.and_then(|v| ct::Card::from_value(&v).ok()))
}

/// The things whose `keys.0` held here names `t` their inbox: from the reference index (the
/// `inbox` field is a weak).
pub(crate) fn naming_inbox(tx: &mut Tx<'_>, t: &Tid) -> Result<BTreeSet<Tid>> {
    Ok(crate::engine::refs::to(tx, t)?.into_iter().filter(|r| r.ak.as_str() == "keys.0" && r.source != *t).map(|r| r.source).collect())
}

/// The cards of `a` held here, each with its host.
pub(crate) fn cards_of(tx: &mut Tx<'_>, a: &Tid) -> Result<Vec<(Tid, ct::Card)>> {
    let hosts: Vec<Tid> = tx.core.ix.aspect_things.get(&card_ak(a)).into_iter().flatten().copied().collect();
    let mut out = Vec::new();
    for h in hosts {
        if let Some(c) = card_on(tx, &h, a)? {
            out.push((h, c));
        }
    }
    Ok(out)
}

/// Whether a card of `a` stands here.
pub(crate) fn stands(tx: &mut Tx<'_>, a: &Tid) -> Result<bool> {
    Ok(!cards_of(tx, a)?.is_empty())
}

/// `a`'s inbox at this node (spec/sync-inbox.md §1): the `inbox` field of its `keys.0` state here,
/// else `a` itself; `None` where `a` is not independent here (no keys of it to fire by).
pub(crate) fn inbox_in(tx: &mut Tx<'_>, a: &Tid) -> Result<Option<Tid>> {
    if !tx.core.is_independent(a) {
        return Ok(None);
    }
    // the field alone: `keys.0` holds a box record per holder, paged
    let (ak, path) = (super::ak("keys.0")?, [PathSeg::Field(INBOX)]);
    tx.ensure_paths(a, &ak, &[path.to_vec()])?;
    let named = tx.cached(a, &ak).and_then(|f| f.read_at(&path)).and_then(|v| Option::<Weak>::from_value(&v).ok().flatten());
    Ok(Some(named.map_or(*a, Tid::from)))
}

/// Whether this node may write `host` along a path through `a` (spec/sync-inbox.md §1): a path
/// from it to `a`, then from `a` to `host`, each giving write.
pub(crate) fn may_write_through(core: &crate::engine::Core, a: &Tid, host: &Tid) -> bool {
    let me = core.tid();
    let ts = core.hlc.peek();
    let none: crate::engine::write::Records<'_> = &|_| None;
    crate::engine::write::path_with(core, me, none, a, Need::Role(Role::Write), ts).is_some() && crate::engine::write::path_with(core, *a, none, host, Need::Role(Role::Write), ts).is_some()
}

/// Writes `card` as `a`'s on `host` into a mutation of its own, acting as `a`, so its stated
/// path runs through `a` (spec/permissions.md §5.2): replaced whole, so no replaced list leaves
/// its elements behind in the state.
pub fn put(host: Tid, a: Tid, card: &ct::Card) -> Result<Mutation> {
    let mut m = Mutation::new();
    m.act_as(a);
    m.op(host, &card_ak(&a), PathOp { path: vec![], op: Op::Replace(card.to_value()) })?;
    Ok(m)
}

/// The `keys.0` write naming `inbox` (`None`: `a` itself) `a`'s inbox (an admin's,
/// spec/permissions.md §3).
pub fn put_inbox(m: &mut Mutation, a: Tid, inbox: Option<Tid>) -> Result<()> {
    m.op(a, &ct::KEYS, PathOp { path: vec![PathSeg::Field(INBOX)], op: Op::Set(inbox.map(Weak).to_value()) })?;
    Ok(())
}

/// `keys.0` field `inbox` (schema/core.osis).
const INBOX: u64 = 11;

/// The cards `t` is due a look at: those of `t` and those of the things naming `t` their inbox
/// (a card of it written, or its `keys.0` moved).
pub(crate) fn note_due(core: &mut crate::engine::Core, t: Tid) {
    core.ix.cards_due.insert(t);
}

/// `a`'s card aspect on `host` moved: `a` is due a look (`note_due`); with no card left there, a
/// need of `a` and of its inbox went (`retention::needed`).
pub(crate) fn state_moved(tx: &mut Tx<'_>, host: &Tid, a: &Tid) -> Result<()> {
    note_due(tx.core, *a);
    if card_on(tx, host, a)?.is_none() {
        tx.core.note_lost(*a);
        if let Some(i) = inbox_in(tx, a)? {
            tx.core.note_lost(i);
        }
    }
    Ok(())
}

/// An open: every card held is due a look (`cards_due` and `cards_stale` are kept in memory).
pub(crate) fn load(tx: &mut Tx<'_>) -> Result<()> {
    let held: Vec<(Tid, Tid)> = tx.core.ix.aspect_things.iter().filter_map(|(ak, hs)| card_of(ak.as_str()).map(|a| hs.iter().map(move |h| (*h, a)))).flatten().collect();
    for (h, a) in held {
        if card_on(tx, &h, &a)?.is_some() {
            note_due(tx.core, a);
        }
    }
    Ok(())
}

/// A card's `keys` and `records` (spec/wire.md §9 Holder keys).
type KeyLists = (Vec<Vec<u8>>, Vec<Vec<u8>>);

/// The commits a card carries, as holder keys (spec/wire.md §9).
fn certificates(keys: &[Vec<u8>], records: &[Vec<u8>]) -> Option<osis_blob::Certificates> {
    let limits = osis_base::Limits::new(osis_base::format::MAX_OBJECT_DEPTH, osis_base::format::MAX_BLOB);
    let values = |l: &[Vec<u8>]| l.iter().map(|b| osis_base::decode(b, &limits).ok()).collect::<Option<Vec<Value>>>();
    osis_blob::Certificates::from_values(&Value::List(values(keys)?), &Value::List(values(records)?), usize::MAX).ok()
}

/// Per thing, the newest `ts` of the `keys.0` parts on it among a card's commits (`keys`,
/// with its `records`).
fn carried(keys: &[Vec<u8>], records: &[Vec<u8>]) -> BTreeMap<Tid, osis_base::Ts> {
    let mut out: BTreeMap<Tid, osis_base::Ts> = BTreeMap::new();
    for v in certificates(keys, records).map(|k| k.commits).unwrap_or_default() {
        let Ok(b) = osis_commit::CommitBlob::decode(&osis_base::encode(&v)) else { continue };
        for a in b.parts.iter().filter_map(|p| b.header.aspects.get(p.ai)).filter(|a| a.ak.as_str() == "keys.0") {
            let e = out.entry(a.tid).or_insert(b.header.ts);
            *e = (*e).max(b.header.ts);
        }
    }
    out
}

impl Engine {
    /// Takes what the cards due a look carry (`Indexes::cards_due`; spec/sync-inbox.md §1 Card):
    /// for each card of a thing A or naming it, its commits taken as A's and its inbox's holder
    /// keys (each kept only as judged). Each is due a refresh then (`refresh_cards`). Whether any
    /// was due.
    pub fn take_cards(&mut self) -> Result<bool> {
        let due: Vec<Tid> = self.core.ix.cards_due.iter().copied().collect();
        if due.is_empty() {
            return Ok(false);
        }
        let cards = self.cards_naming(&due)?;
        for ((_, a), c) in &cards {
            if let Some(k) = certificates(&c.keys, &c.records) {
                self.take_holder_keys(a, &k, None)?;
                // A's inbox as A's keys just taken name it
                let a = *a;
                if let Some(inbox) = self.read(|tx| inbox_in(tx, &a))?.filter(|i| *i != a) {
                    self.take_holder_keys(&inbox, &k, None)?;
                }
            }
        }
        self.run(|tx| {
            for t in &due {
                tx.core.ix.cards_due.remove(t);
                tx.core.ix.cards_stale.insert(*t);
            }
            Ok(())
        })?;
        Ok(true)
    }

    /// The cards of each of `due` and of the things naming it their inbox: (host, card's thing)
    /// to card.
    fn cards_naming(&mut self, due: &[Tid]) -> Result<BTreeMap<(Tid, Tid), ct::Card>> {
        let mut cards = BTreeMap::new();
        for t in due {
            let t = *t;
            let found = self.read(|tx| {
                let mut out: Vec<(Tid, Tid, ct::Card)> = cards_of(tx, &t)?.into_iter().map(|(h, c)| (h, t, c)).collect();
                for a in naming_inbox(tx, &t)? {
                    out.extend(cards_of(tx, &a)?.into_iter().map(|(h, c)| (h, a, c)));
                }
                Ok(out)
            })?;
            cards.extend(found.into_iter().map(|(h, a, c)| ((h, a), c)));
        }
        Ok(cards)
    }

    /// At a pass's end, once this node holds what the pass brought (`settle_needs`): rewrites
    /// the cards due a refresh (`Indexes::cards_stale`) that are stale and this node may
    /// (spec/sync-inbox.md §1 Card): where it may write the card's host along a path through A
    /// and a rewrite would carry newer `keys.0` parts on A or A's inbox than the card does, the
    /// card written again with the holder keys of A and that inbox held here. Whether any card
    /// moved.
    pub fn refresh_cards(&mut self) -> Result<bool> {
        let mut moved = false;
        let mut guard = osis_base::loop_guard::LoopGuard::new("Engine::refresh_cards (rewritten cards due again)");
        loop {
            self.take_cards()?;
            let due: Vec<Tid> = self.core.ix.cards_stale.iter().copied().collect();
            if due.is_empty() {
                return Ok(moved);
            }
            self.run(|tx| {
                for t in &due {
                    tx.core.ix.cards_stale.remove(t);
                }
                Ok(())
            })?;
            let cards = self.cards_naming(&due)?;
            let n = cards.len() as u64;
            guard.round((), || (n + 2, format!("{n} cards")));
            for ((host, a), c) in &cards {
                moved |= self.refresh_card(host, a, c)?;
            }
        }
    }

    /// Writes `a`'s card on `host` (`card`, as held) again where it is stale and this node may
    /// (`take_cards`): whether it did. Stale by what a rewrite would carry (`card_keys`), never by
    /// what is merely known here, so a rewrite is not stale again by construction: a `keys.0`
    /// commit whose header is held but whose `keys.0` part is not cannot be carried.
    fn refresh_card(&mut self, host: &Tid, a: &Tid, card: &ct::Card) -> Result<bool> {
        if !self.core.ix.closure.holds(host) {
            return Ok(false);
        }
        let (a, host) = (*a, *host);
        let Some(inbox) = self.read(|tx| inbox_in(tx, &a))? else { return Ok(false) };
        if !may_write_through(&self.core, &a, &host) {
            return Ok(false);
        }
        // newer `keys.0` parts on `a` or its inbox among what a rewrite carries than the card's
        let Some((keys, records)) = self.card_keys(&a, &inbox)? else { return Ok(false) };
        let have = carried(&card.keys, &card.records);
        if !carried(&keys, &records).iter().any(|(t, ts)| (*t == a || *t == inbox) && have.get(t).is_none_or(|x| ts > x)) {
            return Ok(false);
        }
        self.write_card(host, a)
    }

    /// What a card of `a` naming `named` written here carries (spec/wire.md §9 Holder keys): the
    /// holder keys of `a` and of `named` held here, commits distinct, records ascending by tid
    /// and distinct. `None` with no `keys.0` of `a` held.
    fn card_keys(&mut self, a: &Tid, named: &Tid) -> Result<Option<KeyLists>> {
        let mut keys = self.holder_keys(a)?;
        if keys.commits.is_empty() {
            return Ok(None);
        }
        if named != a {
            let more = self.holder_keys(named)?;
            keys.commits.extend(more.commits);
            keys.records.extend(more.records);
        }
        let mut seen = BTreeSet::new();
        let commits: Vec<Vec<u8>> = keys.commits.iter().map(osis_base::encode).filter(|b| seen.insert(b.clone())).collect();
        let recs: BTreeMap<Tid, &osis_base::CreationRecord> = keys.records.iter().map(|r| (r.tid(), r)).collect();
        let records: Vec<Vec<u8>> = recs.values().map(|r| osis_base::encode(&r.to_value())).collect();
        Ok(Some((commits, records)))
    }

    /// Writes `a`'s card on `host` as of what this node holds (spec/sync-inbox.md §1 Card): the
    /// holder keys of `a` and of its inbox held here. Acting as `a`: refused where this node may
    /// not write `host` along a path through `a`. `a` and its inbox, where dependent and this node
    /// an admin of each, are made independent first (spec/permissions.md §3: a card carries keys
    /// of their own), `a`'s keysets carrying KEM keys for every role as its card stands. Whether it
    /// wrote (nothing to carry: no `keys.0` of `a` held).
    pub fn write_card(&mut self, host: Tid, a: Tid) -> Result<bool> {
        self.publish(a, true)?;
        let Some(named) = self.read(|tx| inbox_in(tx, &a))? else { return Ok(false) };
        if named != a {
            self.publish(named, false)?;
        }
        let Some((keys, records)) = self.card_keys(&a, &named)? else { return Ok(false) };
        self.run(|tx| {
            Engine::commit_tx(tx, put(host, a, &ct::Card { keys, records })?)?;
            Ok(true)
        })
    }

    /// Makes `t` independent where dependent and this node an admin of it (`carded`: its keysets
    /// carrying KEM keys for every role, as its card stands).
    fn publish(&mut self, t: Tid, carded: bool) -> Result<()> {
        if self.core.is_independent(&t) || self.role_on(&t) != Some(Role::Admin) {
            return Ok(());
        }
        self.run(|tx| {
            if carded {
                tx.publishing.push((t, Role::Admin));
            }
            crate::rotation::own_secrets(tx, t, &mut crate::flows::Done::default())
        })
    }

    /// Names `inbox` (`None`: `a` itself) `a`'s inbox, where grants to `a` from outside go
    /// (spec/sync-inbox.md §1): the `inbox` field of `a`'s `keys.0`, which needs admin on `a`
    /// (spec/permissions.md §3), so refused unless this node is one. `a` and the inbox are made
    /// independent first where this node is an admin of each (a card carries their keys). The
    /// cards of `a` held here that this node may write are rewritten with it at once; the others
    /// by the nodes that may, as they take it (`refresh_cards`).
    pub fn set_inbox(&mut self, a: Tid, inbox: Option<Tid>) -> Result<()> {
        if self.role_on(&a) != Some(Role::Admin) {
            return Err(crate::Error::Permission { tid: a, needs: Role::Admin });
        }
        let inbox = inbox.filter(|i| *i != a);
        let carded = self.read(|tx| stands(tx, &a))?;
        self.publish(a, carded)?;
        if let Some(i) = inbox {
            self.publish(i, false)?;
        }
        let mut m = Mutation::new();
        put_inbox(&mut m, a, inbox)?;
        self.commit(m)?;
        let hosts: Vec<Tid> = self.read(|tx| cards_of(tx, &a))?.into_iter().map(|x| x.0).collect();
        for host in hosts {
            if self.core.ix.closure.holds(&host) && may_write_through(&self.core, &a, &host) {
                self.write_card(host, a)?;
            }
        }
        Ok(())
    }

    /// Removes `a`'s card from `host`: any writer of `host` may (spec/sync-inbox.md §1 Card).
    pub fn remove_card(&mut self, host: Tid, a: Tid) -> Result<()> {
        let mut m = Mutation::new();
        m.op(host, &card_ak(&a), PathOp { path: vec![], op: Op::RemoveAspect })?;
        self.commit(m)?;
        Ok(())
    }

    /// `a`'s inbox at this node (spec/sync-inbox.md §1): the `inbox` field of its `keys.0` here,
    /// else `a` itself; `None` where `a` is not independent here.
    pub fn inbox_of(&mut self, a: &Tid) -> Result<Option<Tid>> {
        let a = *a;
        self.read(|tx| inbox_in(tx, &a))
    }

    /// The cards of `a` held here, each with its host.
    pub fn cards_of(&mut self, a: &Tid) -> Result<Vec<(Tid, ct::Card)>> {
        let a = *a;
        self.run(|tx| cards_of(tx, &a))
    }
}
