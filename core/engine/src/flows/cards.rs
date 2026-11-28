//! Cards (spec/sync-inbox.md §1 Card, spec/data-model.md §9): A's card on any thing C is the
//! value of A's card aspect on C (`card_ak`), written along a path through A: an entry per node,
//! keyed by its node thing, holding A's and A's inbox's holder keys as that node holds them. A's
//! inbox is a thing of its own: the one the `inbox` field of A's `keys.0` names (an admin's write,
//! `Engine::set_inbox`), never A; with none named A has no inbox and an entry carries A's keys
//! alone. A node reading C takes the commits of every entry together as holder keys
//! (`Engine::take_cards`); at a pass's end a node that may write C along a path through A keeps its
//! own entry (`refresh_card`: written where no entry carries what it holds, removed where another
//! does and its own falls short). A card aspect is retained, snapshotted and covered as any
//! content aspect: its snapshots, as its writes, state a path through A.
//!
//! Invariant: a card counts only written along a path through A, each entry by the node it names
//! (`apply::validity::note_cards`), and what it carries counts only as judged here
//! (`take_holder_keys`: what is on A's or the inbox's authority chain, each commit judged valid).
//! Who writes each input: an entry, its node, a writer of C along a path through A (a writer of
//! A: it reads A anyway), so no node rewrites another's and the sides of a fork keep an entry each,
//! each side's readers taking its own side's keys from the whole; its commits, A's and the inbox's
//! admins and writers (judged), so where grants to A go is chosen by A's admins alone (the inbox
//! field needs admin, `validity::rotation_required`), and an honest entry's keysets carry the
//! demotions of A's admins and writers (`holder_keys`), voiding a demoted party's later commits
//! another entry carries. C's other writers may remove a card, never put one. A removed writer of
//! A writes no valid entry once its removal applies; a stranger holding an old card seals to A's
//! keysets as of that card until a newer one reaches it (spec/sync-inbox.md §2: what it seals is
//! judged by A's readers). A card on a thing no node may write along a path through A any longer
//! stays as written.

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
/// `inbox` field is a weak), each read (a `keys.0` names its box records' holders too).
pub(crate) fn naming_inbox(tx: &mut Tx<'_>, t: &Tid) -> Result<BTreeSet<Tid>> {
    let mut out = BTreeSet::new();
    for r in crate::engine::refs::to(tx, t)? {
        if r.ak.as_str() == "keys.0" && inbox_in(tx, &r.source)? == Some(*t) {
            out.insert(r.source);
        }
    }
    Ok(out)
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

/// `a`'s inbox at this node (spec/sync-inbox.md §1): the thing the `inbox` field of its `keys.0`
/// state here names, never `a` itself; `None` where it names none (or `a`), or `a` is not
/// independent here (no keys of it to fire by).
pub(crate) fn inbox_in(tx: &mut Tx<'_>, a: &Tid) -> Result<Option<Tid>> {
    if !tx.core.is_independent(a) {
        return Ok(None);
    }
    // the field alone: `keys.0` holds a box record per holder, paged
    let (ak, path) = (super::ak("keys.0")?, [PathSeg::Field(INBOX)]);
    tx.ensure_paths(a, &ak, &[path.to_vec()])?;
    let named = tx.cached(a, &ak).and_then(|f| f.read_at(&path)).and_then(|v| Option::<Weak>::from_value(&v).ok().flatten());
    Ok(named.map(Tid::from).filter(|i| i != a))
}

/// Whether this node may write `host` along a path through `a` (spec/sync-inbox.md §1): a path
/// from it to `a`, then from `a` to `host`, each giving write.
pub(crate) fn may_write_through(core: &crate::engine::Core, a: &Tid, host: &Tid) -> bool {
    let me = core.tid();
    let ts = core.hlc.peek();
    let none: crate::engine::write::Records<'_> = &|_| None;
    crate::engine::write::path_with(core, me, none, a, Need::Role(Role::Write), ts).is_some() && crate::engine::write::path_with(core, *a, none, host, Need::Role(Role::Write), ts).is_some()
}

/// Puts `a`'s card on `host`, with no entry yet (its nodes write theirs, `refresh_card`), into a
/// mutation of its own, acting as `a`, so its stated path runs through `a` (spec/permissions.md
/// §5.2).
pub fn put(host: Tid, a: Tid) -> Result<Mutation> {
    let mut m = Mutation::new();
    m.act_as(a);
    m.op(host, &card_ak(&a), PathOp { path: vec![], op: Op::Replace(ct::Card::default().to_value()) })?;
    Ok(m)
}

/// Writes `entry` as node `node`'s in `a`'s card on `host` into a mutation of its own, acting as
/// `a`: replaced whole, so no replaced list leaves its elements behind in the state. Valid only
/// signed as `node` (spec/permissions.md §5.2).
pub fn put_entry(host: Tid, a: Tid, node: Tid, entry: &ct::CardEntry) -> Result<Mutation> {
    let mut m = Mutation::new();
    m.act_as(a);
    m.op(host, &card_ak(&a), PathOp { path: vec![PathSeg::Key(Value::Weak(node))], op: Op::Replace(entry.to_value()) })?;
    Ok(m)
}

/// What a party holding `card` takes as holder keys (spec/sync-inbox.md §1 Card): the commits and
/// records of every entry together, an entry not in the holder keys form counting for nothing.
pub fn holder_keys_of(card: &ct::Card) -> osis_blob::Certificates {
    let mut out = osis_blob::Certificates::default();
    let mut recs = BTreeSet::new();
    for e in card.values().filter_map(|e| certificates(&e.keys, &e.records)) {
        out.commits.extend(e.commits);
        out.records.extend(e.records.into_iter().filter(|r| recs.insert(r.tid())));
    }
    out
}

/// The `keys.0` write naming `inbox` `a`'s inbox (an admin's, spec/permissions.md §3).
pub fn put_inbox(m: &mut Mutation, a: Tid, inbox: Tid) -> Result<()> {
    m.op(a, &ct::KEYS, PathOp { path: vec![PathSeg::Field(INBOX)], op: Op::Set(Some(Weak(inbox)).to_value()) })?;
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

/// The commits a card entry carries, as holder keys (spec/wire.md §9).
fn certificates(keys: &[Vec<u8>], records: &[Vec<u8>]) -> Option<osis_blob::Certificates> {
    let limits = osis_base::Limits::new(osis_base::format::MAX_OBJECT_DEPTH, osis_base::format::MAX_BLOB);
    let values = |l: &[Vec<u8>]| l.iter().map(|b| osis_base::decode(b, &limits).ok()).collect::<Option<Vec<Value>>>();
    osis_blob::Certificates::from_values(&Value::List(values(keys)?), &Value::List(values(records)?), usize::MAX).ok()
}

/// Whether `entry` carries every commit and record of `mine` (byte for byte): an entry that does
/// gives a reader everything this node would.
fn carries(entry: &ct::CardEntry, mine: &ct::CardEntry) -> bool {
    let (keys, records): (BTreeSet<&Vec<u8>>, BTreeSet<&Vec<u8>>) = (entry.keys.iter().collect(), entry.records.iter().collect());
    mine.keys.iter().all(|k| keys.contains(k)) && mine.records.iter().all(|r| records.contains(r))
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
            let k = holder_keys_of(c);
            self.take_holder_keys(a, &k, None)?;
            // A's inbox as A's keys just taken name it
            let a = *a;
            if let Some(inbox) = self.read(|tx| inbox_in(tx, &a))? {
                self.take_holder_keys(&inbox, &k, None)?;
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

    /// At a pass's end, once this node holds what the pass brought (`settle_needs`): keeps this
    /// node's entry in the cards due a look (`Indexes::cards_stale`, `refresh_card`). Whether any
    /// entry moved.
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

    /// Keeps this node's entry in `a`'s card on `host` (`card`, as held; spec/sync-inbox.md §1
    /// Keeping an entry), where this node may write `host` along a path through `a`: written with
    /// the holder keys of `a` and its inbox held here where no entry carries them all, removed
    /// where its own falls short and another carries them. Whether it moved. Each node writes its
    /// own entry alone, so what it does rests on what it holds and never undoes another's.
    fn refresh_card(&mut self, host: &Tid, a: &Tid, card: &ct::Card) -> Result<bool> {
        if !self.core.ix.closure.holds(host) {
            return Ok(false);
        }
        let (a, host) = (*a, *host);
        if !may_write_through(&self.core, &a, &host) {
            return Ok(false);
        }
        let inbox = self.read(|tx| inbox_in(tx, &a))?;
        let Some(mine) = self.card_keys(&a, inbox)? else { return Ok(false) };
        let me = self.core.tid();
        let own = card.get(&Weak(me));
        if own.is_some_and(|e| carries(e, &mine)) {
            return Ok(false);
        }
        let other = card.iter().any(|(n, e)| n.0 != me && carries(e, &mine));
        let m = match (other, own) {
            (true, None) => return Ok(false),
            (true, Some(_)) => {
                let mut m = Mutation::new();
                m.act_as(a);
                m.op(host, &card_ak(&a), PathOp { path: vec![], op: Op::Remove(Value::Weak(me)) })?;
                m
            }
            (false, _) => put_entry(host, a, me, &mine)?,
        };
        self.run(|tx| Engine::commit_tx(tx, m).map(|_| true))
    }

    /// What an entry of `a`'s card with inbox `inbox` written here carries (spec/wire.md §9
    /// Holder keys): the holder keys of `a` and of `inbox` held here, commits distinct, records
    /// ascending by tid and distinct. `None` with no `keys.0` of `a` held.
    fn card_keys(&mut self, a: &Tid, inbox: Option<Tid>) -> Result<Option<ct::CardEntry>> {
        let mut keys = self.holder_keys(a)?;
        if keys.commits.is_empty() {
            return Ok(None);
        }
        if let Some(i) = inbox {
            let more = self.holder_keys(&i)?;
            keys.commits.extend(more.commits);
            keys.records.extend(more.records);
        }
        let mut seen = BTreeSet::new();
        let commits: Vec<Vec<u8>> = keys.commits.iter().map(osis_base::encode).filter(|b| seen.insert(b.clone())).collect();
        let recs: BTreeMap<Tid, &osis_base::CreationRecord> = keys.records.iter().map(|r| (r.tid(), r)).collect();
        let records: Vec<Vec<u8>> = recs.values().map(|r| osis_base::encode(&r.to_value())).collect();
        Ok(Some(ct::CardEntry { keys: commits, records }))
    }

    /// Writes this node's entry in `a`'s card on `host` as of what it holds (spec/sync-inbox.md
    /// §1 Card): the holder keys of `a` and of its inbox held here, putting the card where none
    /// stands. Acting as `a`: refused where this node may not write `host` along a path through
    /// `a`. `a` and its inbox, where dependent and this node an admin of each, are made
    /// independent first (spec/permissions.md §3: a card carries keys of their own), `a`'s
    /// keysets carrying KEM keys for every role as its card stands. Whether it wrote (nothing to
    /// carry: no `keys.0` of `a` held).
    pub fn write_card(&mut self, host: Tid, a: Tid) -> Result<bool> {
        self.publish(a, true)?;
        let inbox = self.read(|tx| inbox_in(tx, &a))?;
        if let Some(i) = inbox {
            self.publish(i, false)?;
        }
        let Some(entry) = self.card_keys(&a, inbox)? else { return Ok(false) };
        let me = self.core.tid();
        self.run(|tx| {
            Engine::commit_tx(tx, put_entry(host, a, me, &entry)?)?;
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

    /// Names `inbox`, a thing other than `a` (else `Misuse`), `a`'s inbox, where grants to `a`
    /// from outside go (spec/sync-inbox.md §1): the `inbox` field of `a`'s `keys.0`, which needs
    /// admin on `a` (spec/permissions.md §3), so refused unless this node is one. `a` and the inbox are minted
    /// independent first where this node is an admin of each (a card carries their keys). This
    /// node's entries in the cards of `a` held here that it may write are written with it at once;
    /// the others by the nodes that may, as they take it (`refresh_cards`).
    pub fn set_inbox(&mut self, a: Tid, inbox: Tid) -> Result<()> {
        if inbox == a {
            return Err(crate::Error::Misuse("a thing's inbox is a thing of its own"));
        }
        if self.role_on(&a) != Some(Role::Admin) {
            return Err(crate::Error::Permission { tid: a, needs: Role::Admin });
        }
        let carded = self.read(|tx| stands(tx, &a))?;
        self.publish(a, carded)?;
        self.publish(inbox, false)?;
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

    /// `a`'s inbox at this node (spec/sync-inbox.md §1): the thing the `inbox` field of its
    /// `keys.0` here names; `None` where it names none, or `a` is not independent here.
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
