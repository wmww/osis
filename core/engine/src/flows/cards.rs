//! Cards (spec/sync-inbox.md §1 Card, spec/data-model.md §9): A's card on any thing C is the
//! value of A's card aspect on C (`card_ak`), written whole along a path through A: A's inbox
//! where it is another thing, when that inbox was chosen (`since`), and A's and that inbox's
//! current `keys.0` commits in the holder keys form. A node reading C takes those commits as
//! holder keys (`Engine::take_cards`); at a pass's end a node that may write C along a path
//! through A rewrites the card when it holds newer `keys.0` commits of A or its inbox, or a card
//! of A with a greater `since`. A card aspect is retained, snapshotted and covered as any content
//! aspect: its snapshots, as its writes, state a path through A.
//!
//! Invariant: a card counts only written along a path through A (`apply::validity::note_cards`),
//! and what it carries counts only as judged here (`take_holder_keys`: what is on A's or the
//! inbox's authority chain, each commit judged valid). Who writes each input: a card, a writer of
//! C along a path through A (a writer of A: it reads A anyway; a hostile one may point offers at
//! an inbox it controls, a writer's power, as removing data is); its commits, A's and the inbox's
//! admins (judged); C's other writers may remove a card, never put one. A removed writer of A
//! writes no valid card once its removal applies; a stranger holding an old card seals to A's
//! keysets as of that card until a newer one reaches it (spec/sync-inbox.md §2: what it seals
//! is judged by A's readers). A card on a thing no node may write along a path through A any
//! longer stays as written.

use crate::engine::{Engine, Tx};
use crate::error::Result;
use crate::Mutation;
use osis_base::{Role, Tid, Value, WallMs, Weak};
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

/// The cards held here naming `t` their inbox, each by (host, the card's thing): from the
/// reference index (a card's inbox is a weak in its value).
fn naming_inbox(tx: &mut Tx<'_>, t: &Tid) -> Result<BTreeSet<(Tid, Tid)>> {
    Ok(crate::engine::refs::to(tx, t)?.into_iter().filter_map(|r| card_of(r.ak.as_str()).map(|a| (r.source, a))).collect())
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

/// The inbox a card names: its `inbox`, else its thing.
fn named(a: &Tid, c: &ct::Card) -> Tid {
    c.inbox.map_or(*a, Tid::from)
}

/// `a`'s inbox at this node by its cards and its `since` (spec/sync-inbox.md §1): the inbox named
/// by the card of `a` held here with the greatest `since`, ties by the inbox's tid; `None` with no
/// card held.
pub(crate) fn inbox_of(tx: &mut Tx<'_>, a: &Tid) -> Result<Option<(Tid, WallMs)>> {
    Ok(cards_of(tx, a)?.iter().map(|(_, c)| (c.since, named(a, c))).max().map(|(s, i)| (i, s)))
}

/// Where a grant from outside to `a` is fired at this node (spec/sync-inbox.md §1): its inbox by
/// the cards of it held here (`inbox_of`), else `a` itself where independent here.
pub(crate) fn inbox_in(tx: &mut Tx<'_>, a: &Tid) -> Result<Option<Tid>> {
    Ok(inbox_of(tx, a)?.map(|x| x.0).or_else(|| tx.core.is_independent(a).then_some(*a)))
}

/// The `since` a card of `a` naming `inbox` written now carries (spec/sync-inbox.md §1): the
/// `since` of `a`'s inbox here where it names that one; else (a move) above every card of `a`
/// held here, and no earlier than `now`.
fn since_for(tx: &mut Tx<'_>, a: &Tid, inbox: &Tid, now: WallMs) -> Result<WallMs> {
    let cards = cards_of(tx, a)?;
    let chosen = cards.iter().map(|(_, c)| (c.since, named(a, c))).max();
    Ok(match chosen {
        Some((s, i)) if i == *inbox => s,
        _ => cards.iter().map(|(_, c)| WallMs(c.since.0.saturating_add(1))).max().unwrap_or(WallMs(0)).max(now),
    })
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
/// path runs through `a` (spec/permissions.md §5.2). Field by field, so a refresh and a
/// concurrent move each write only what they change (neither undoes the other's `since`); its
/// lists of commits whole, so no replaced list leaves its elements behind in the state.
pub fn put(host: Tid, a: Tid, card: &ct::Card) -> Result<Mutation> {
    let mut m = Mutation::new();
    m.act_as(a);
    let ak = card_ak(&a);
    let Value::Map(fields) = card.to_value() else { return Err(crate::Error::Misuse("a card is a struct")) };
    for (k, v) in fields {
        let Value::Int(id) = k else { return Err(crate::Error::Misuse("a card is a struct")) };
        let op = if matches!(v, Value::List(_)) { Op::Replace(v) } else { Op::Set(v) };
        m.op(host, &ak, PathOp { path: vec![PathSeg::Field(id as u64)], op })?;
    }
    Ok(m)
}

/// A card of `a` naming `inbox` (`None`: `a` itself), carrying no keys yet: the node writing it
/// fills them in (`Engine::refresh_cards`) from the `keys.0` commits it holds.
pub fn naming(inbox: Option<Tid>, since: WallMs) -> ct::Card {
    ct::Card { inbox: inbox.map(Weak), since, ..ct::Card::default() }
}

/// The cards `t` is due a look at: those of `t` and those naming `t` their inbox (a card of it
/// written, or its `keys.0` moved).
pub(crate) fn note_due(core: &mut crate::engine::Core, t: Tid) {
    core.ix.cards_due.insert(t);
}

/// `a`'s card aspect on `host` moved: `a` and the inbox its card names are due a look
/// (`note_due`); with no card left there, a need of `a` went (`retention::needed`).
pub(crate) fn state_moved(tx: &mut Tx<'_>, host: &Tid, a: &Tid) -> Result<()> {
    note_due(tx.core, *a);
    match card_on(tx, host, a)? {
        Some(c) => note_due(tx.core, named(a, &c)),
        None => tx.core.note_lost(*a),
    }
    Ok(())
}

/// An open: every card held is due a look (`cards_due` and `cards_stale` are kept in memory).
pub(crate) fn load(tx: &mut Tx<'_>) -> Result<()> {
    let held: Vec<(Tid, Tid)> = tx.core.ix.aspect_things.iter().filter_map(|(ak, hs)| card_of(ak.as_str()).map(|a| hs.iter().map(move |h| (*h, a)))).flatten().collect();
    for (h, a) in held {
        if let Some(c) = card_on(tx, &h, &a)? {
            note_due(tx.core, a);
            note_due(tx.core, named(&a, &c));
        }
    }
    Ok(())
}

/// The commits a card carries, as holder keys (spec/wire.md §9).
fn certificates(c: &ct::Card) -> Option<osis_blob::Certificates> {
    let limits = osis_base::Limits::new(osis_base::format::MAX_OBJECT_DEPTH, osis_base::format::MAX_BLOB);
    let values = |l: &[Vec<u8>]| l.iter().map(|b| osis_base::decode(b, &limits).ok()).collect::<Option<Vec<Value>>>();
    osis_blob::Certificates::from_values(&Value::List(values(&c.keys)?), &Value::List(values(&c.records)?), usize::MAX).ok()
}

/// Per thing, the newest `ts` of the `keys.0` commits on it a card carries.
fn carried(c: &ct::Card) -> BTreeMap<Tid, osis_base::Ts> {
    let mut out: BTreeMap<Tid, osis_base::Ts> = BTreeMap::new();
    for v in certificates(c).map(|k| k.commits).unwrap_or_default() {
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
            if let Some(k) = certificates(c) {
                self.take_holder_keys(a, &k, None)?;
                let inbox = named(a, c);
                if inbox != *a {
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

    /// The cards of each of `due` or naming it: (host, card's thing) to card.
    fn cards_naming(&mut self, due: &[Tid]) -> Result<BTreeMap<(Tid, Tid), ct::Card>> {
        let mut cards = BTreeMap::new();
        for t in due {
            let t = *t;
            let found = self.read(|tx| {
                let mut out: Vec<(Tid, Tid, ct::Card)> = cards_of(tx, &t)?.into_iter().map(|(h, c)| (h, t, c)).collect();
                for (h, a) in naming_inbox(tx, &t)? {
                    out.extend(card_on(tx, &h, &a)?.filter(|c| named(&a, c) == t).map(|c| (h, a, c)));
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
    /// and holds `keys.0` commits of A or A's inbox newer than the card carries, or a card of A
    /// with a greater `since` and inbox, the card written again: A's inbox here with its
    /// `since`, and the holder keys of A and that inbox held here. Whether any card moved.
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
    /// (`take_cards`): whether it did.
    fn refresh_card(&mut self, host: &Tid, a: &Tid, card: &ct::Card) -> Result<bool> {
        if !self.core.ix.closure.holds(host) {
            return Ok(false);
        }
        let (a, host) = (*a, *host);
        let Some((inbox, since)) = self.read(|tx| inbox_of(tx, &a))? else { return Ok(false) };
        // newer `keys.0` commits held here than the card carries, of `a` or its inbox
        let carried = carried(card);
        let newer = |t: &Tid| self.current_keys(t).iter().filter_map(|c| self.header(c)).any(|h| carried.get(t).is_none_or(|x| h.ts > *x));
        let stale = (card.since, named(&a, card)) < (since, inbox) || newer(&a) || (inbox != a && newer(&inbox));
        if !stale || !may_write_through(&self.core, &a, &host) {
            return Ok(false);
        }
        self.write_card(host, a, (inbox != a).then_some(inbox), Some(since))
    }

    /// Writes `a`'s card on `host` naming `inbox` (`None`: `a` itself) as of what this node holds
    /// (spec/sync-inbox.md §1 Card): `since` as given, else kept where it names `a`'s inbox here
    /// and above every card of `a` held here where it moves it; the holder keys of `a` and of the
    /// inbox held here. Acting as `a`: refused where this node may not write `host` along a path
    /// through `a`. `a` and the inbox, where dependent and this node an admin of each, are made
    /// independent first (spec/permissions.md §3: a card carries keys of their own), `a`'s
    /// keysets carrying KEM keys for every role as its card stands. Whether it wrote (nothing to
    /// carry: no `keys.0` of `a` held).
    pub fn write_card(&mut self, host: Tid, a: Tid, inbox: Option<Tid>, since: Option<WallMs>) -> Result<bool> {
        let named = inbox.unwrap_or(a);
        for t in [a, named] {
            if !self.core.is_independent(&t) && self.role_on(&t) == Some(Role::Admin) {
                self.run(|tx| {
                    if t == a {
                        tx.publishing.push((a, Role::Admin));
                    }
                    crate::rotation::own_secrets(tx, t, &mut crate::flows::Done::default())
                })?;
            }
        }
        let mut keys = self.holder_keys(&a)?;
        if keys.commits.is_empty() {
            return Ok(false);
        }
        if named != a {
            let more = self.holder_keys(&named)?;
            keys.commits.extend(more.commits);
            keys.records.extend(more.records);
        }
        let mut seen = BTreeSet::new();
        let commits: Vec<Vec<u8>> = keys.commits.iter().map(osis_base::encode).filter(|b| seen.insert(b.clone())).collect();
        // ascending by tid, distinct (spec/wire.md §9 Holder keys)
        let recs: BTreeMap<Tid, &osis_base::CreationRecord> = keys.records.iter().map(|r| (r.tid(), r)).collect();
        let records: Vec<Vec<u8>> = recs.values().map(|r| osis_base::encode(&r.to_value())).collect();
        let now = self.now();
        self.run(|tx| {
            let since = match since {
                Some(s) => s,
                None => since_for(tx, &a, &named, now)?,
            };
            // a card's `since` is no later than its write's `ts` (`validity::note_cards`): the
            // clock runs ahead to it where a move goes past it
            if since > tx.core.hlc.peek().wall_ms()
                && let Some(ts) = osis_base::Ts::make(since, 0)
            {
                tx.core.hlc.observe(ts);
            }
            let card = ct::Card { inbox: inbox.map(Weak), keys: commits, records, since };
            Engine::commit_tx(tx, put(host, a, &card)?)?;
            Ok(true)
        })
    }

    /// Removes `a`'s card from `host`: any writer of `host` may (spec/sync-inbox.md §1 Card).
    pub fn remove_card(&mut self, host: Tid, a: Tid) -> Result<()> {
        let mut m = Mutation::new();
        m.op(host, &card_ak(&a), PathOp { path: vec![], op: Op::RemoveAspect })?;
        self.commit(m)?;
        Ok(())
    }

    /// `a`'s inbox at this node (spec/sync-inbox.md §1): the thing its card held here with the
    /// greatest `since` names, else `a` itself where independent here.
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
