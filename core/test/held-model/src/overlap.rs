//! The overlap rule (spec/commits.md §4: two commits of one session whose counter ranges on one
//! aspect overlap are both invalid) and S3's question (notes/redesign-plan.md S3, brief 7): may
//! it count only commits otherwise valid? `Overlap` names the rules; `void_among` is the one
//! judgment; `consistent` the verdicts a rule reading verdicts could settle on; `rule_inputs`
//! the session-form commits carrying what another judgment reads. Worlds: thing 10 (mint admin
//! node 0) with an admin X (node 1) later removed, a writer W (node 2) and a stranger (node 3);
//! hand worlds for each shape and random ones, any subset of whose events is a held set.
//! Plain and fire bodies are not held: the verdicts read headers and roles, and two bodies
//! under one dot are what the rule exists to keep out of a state.

use crate::gen::{creations, Rng, RECORDS};
use crate::types::*;
use std::collections::{BTreeMap, BTreeSet};

/// The commits void under a rule that counts the deltas `ok` accepts (`(commit, part index)`):
/// both commits of each pair of applied ones whose session-form ranges on one aspect intersect,
/// where both deltas on that aspect pass `ok`.
pub fn void_among(h: &Held, applied: &BTreeSet<CommitId>, ok: impl Fn(CommitId, usize) -> bool) -> BTreeSet<CommitId> {
    let part = |c: CommitId, t: ThingId, a: Aspect| h.commits.iter().find(|x| x.id == c).and_then(|x| x.parts.iter().position(|p| p.thing == t && p.aspect == a));
    let ok = |c: CommitId, t: ThingId, a: Aspect| part(c, t, a).is_some_and(|i| ok(c, i));
    let mut out = BTreeSet::new();
    for (k, r) in h.dots.iter().enumerate() {
        for s in &h.dots[k + 1..] {
            let same = matches!(r.source, Source::Session(_)) && r.source == s.source && (r.thing, r.aspect) == (s.thing, s.aspect);
            if same && r.commit != s.commit && r.lo < s.hi && s.lo < r.hi && applied.contains(&r.commit) && applied.contains(&s.commit) && ok(r.commit, r.thing, r.aspect) && ok(s.commit, s.thing, s.aspect) {
                out.extend([r.commit, s.commit]);
            }
        }
    }
    out
}

/// Every void set a rule reading verdicts could settle on: a set V such that, with V void for
/// every judgment, the pairs of deltas valid by every rule but their own overlap are exactly V's
/// (`Overlap::Given`). A rule with a well-founded definition has one; none or several mean the
/// verdict reads itself.
pub fn consistent(h: &Held) -> Vec<BTreeSet<CommitId>> {
    let cand: Vec<CommitId> = crate::model::evaluate_with(h, &Overlap::Held).void.into_iter().collect();
    assert!(cand.len() <= 12, "consistent: {} candidates", cand.len());
    let mut out = Vec::new();
    for m in 0..1u64 << cand.len() {
        let v: BTreeSet<CommitId> = cand.iter().enumerate().filter(|(k, _)| m >> k & 1 == 1).map(|(_, &c)| c).collect();
        let o = crate::model::evaluate_with(h, &Overlap::Given(v.clone()));
        if void_among(h, &o.applied, |c, i| o.otherwise.get(&(c, i)) == Some(&true)) == v {
            out.push(v);
        }
    }
    out
}

/// Session-form commits carrying what another judgment reads: an `addenda.0` delta (vouching),
/// a `retention^.0` delta (the current setting, which judges external fires) or a purge request
/// (a destruction makes parts never received).
pub fn rule_inputs(h: &Held) -> BTreeSet<CommitId> {
    let session: BTreeSet<CommitId> = h.dots.iter().filter(|r| matches!(r.source, Source::Session(_))).map(|r| r.commit).collect();
    h.commits.iter().filter(|c| session.contains(&c.id) && (!c.purge.is_empty() || c.parts.iter().any(|p| [Aspect::ADDENDA, Aspect::RETENTION].contains(&p.aspect)))).map(|c| c.id).collect()
}

pub const THING: ThingId = 10;
pub const ADMIN: NodeId = 0;
/// An admin, removed in most worlds; the one writing overlapping counters.
pub const X: NodeId = 1;
pub const W: NodeId = 2;
pub const STRANGER: NodeId = 3;
/// The plain aspect the sessions write.
pub const K: Aspect = Aspect::plain(1);
/// An external signal.
pub const EXT: Aspect = Aspect::external(14);
const FIRST: CommitId = 100;

/// Node `n`'s session `k`.
pub fn session(n: NodeId, k: u8) -> Source {
    let mut b = [0u8; 31];
    b[..4].copy_from_slice(&n.to_be_bytes());
    b[30] = k;
    Source::Session(b)
}

pub fn hour(h: u64) -> u64 {
    (crate::gen::START + h * HOUR) * MS
}

/// A commit with its dot ranges: `None` for commit form.
#[derive(Clone, Debug)]
pub struct Event {
    pub commit: Commit,
    pub dots: Vec<DotRange>,
}

fn commit(id: CommitId, author: NodeId, h: u64, kind: CommitKind, parts: Vec<Part>, frontier: Option<Vec<CommitId>>) -> Commit {
    Commit { id, signer: author, acting: author, ts: hour(h), expires: None, kind, parts, purge: vec![], frontier, undoes: None, boxes: vec![] }
}

fn part(aspect: Aspect, body: Body) -> Part {
    let retention = if aspect.fixed() || aspect == Aspect::RETENTION { Retention::ROLE } else { Retention::PLAIN };
    Part { thing: THING, aspect, retention, body, stripped: Default::default(), replaces: None }
}

/// A session-form content commit: per aspect its body and range in `src`.
pub fn sess(id: CommitId, author: NodeId, h: u64, src: &Source, parts: Vec<(Aspect, Body, u64, u64)>) -> Event {
    let dots = parts.iter().map(|&(a, _, lo, hi)| DotRange { source: src.clone(), thing: THING, aspect: a, lo, hi, commit: id }).collect();
    Event { commit: commit(id, author, h, CommitKind::Content, parts.into_iter().map(|(a, b, _, _)| part(a, b)).collect(), None), dots }
}

/// A commit-form content commit.
pub fn plain(id: CommitId, author: NodeId, h: u64, parts: Vec<(Aspect, Body)>) -> Event {
    Event { commit: commit(id, author, h, CommitKind::Content, parts.into_iter().map(|(a, b)| part(a, b)).collect(), None), dots: vec![] }
}

pub fn edge(id: CommitId, author: NodeId, h: u64, holder: NodeId, role: Option<Role>, frontier: Option<Vec<CommitId>>) -> Event {
    let p = part(Aspect::ROLES, Body::Held(Delta::Edge(EdgeWrite::role(holder, role))));
    Event { commit: commit(id, author, h, CommitKind::Role, vec![p], frontier), dots: vec![] }
}

/// An addendum body keyed by `removal` listing `listed`.
pub fn addendum(removal: CommitId, listed: Vec<CommitId>) -> Body {
    Body::Held(Delta::Addenda(vec![(removal, listed)]))
}

/// A setting naming `EXT` (enabling it) or not.
pub fn setting(enables: bool) -> Body {
    let keep = SettingEntry { history: Opt::Keep { after: 0, until: NEVER }, expires: None, purge_before: 0 };
    Body::Held(Delta::Retention(Setting { rules: if enables { vec![(EXT.name, keep)] } else { vec![] }, default: None, written: None }))
}

/// A world: the commits every held set has and the events, any subset of which is held.
#[derive(Clone, Debug)]
pub struct World {
    pub name: &'static str,
    pub base: Vec<Event>,
    pub events: Vec<Event>,
}

/// Creations, X granted admin and W write at hour 0.
pub fn base() -> Vec<Event> {
    let mut b: Vec<Event> = creations().into_iter().map(|commit| Event { commit, dots: vec![] }).collect();
    b.push(edge(FIRST - 2, ADMIN, 0, X, Some(Role::Admin), None));
    b.push(edge(FIRST - 1, ADMIN, 0, W, Some(Role::Write), None));
    b
}

impl World {
    /// What `me` holds of the events `mask` names (bit k: event k).
    pub fn held(&self, mask: u64, me: NodeId) -> Held {
        let es = self.base.iter().chain(self.events.iter().enumerate().filter(|(k, _)| mask >> k & 1 == 1).map(|(_, e)| e));
        let (commits, dots): (Vec<Commit>, Vec<Vec<DotRange>>) = es.map(|e| (e.commit.clone(), e.dots.clone())).unzip();
        Held { now: crate::gen::START + 20 * HOUR, me, records: RECORDS.to_vec(), commits, dots: dots.concat(), external_fires: ExternalFires::Enabled }
    }
    pub fn all(&self) -> u64 {
        (1u64 << self.events.len()) - 1
    }
    /// The event index of commit `c`.
    pub fn bit(&self, c: CommitId) -> u64 {
        1 << self.events.iter().position(|e| e.commit.id == c).expect("an event")
    }
}

const NONE: Body = Body::Missing;

/// X's listed write H1 and, after X's removal, X's unlisted write J on counters H1 used.
pub fn removed_junk() -> World {
    let s = session(X, 0);
    let events = vec![
        sess(FIRST, X, 1, &s, vec![(K, NONE, 1, 3)]),
        edge(FIRST + 1, ADMIN, 2, X, None, Some(vec![FIRST])),
        sess(FIRST + 2, X, 3, &s, vec![(K, NONE, 2, 4)]),
    ];
    World { name: "removed_junk", base: base(), events }
}

/// X's write H1 and a party holding no role writing in X's session on counters H1 used (in
/// osis the session binds the author, so this stands for a signer of X's key with no standing).
pub fn stranger_junk() -> World {
    let s = session(X, 0);
    let events = vec![sess(FIRST, X, 1, &s, vec![(K, NONE, 1, 3)]), sess(FIRST + 1, STRANGER, 2, &s, vec![(K, NONE, 2, 3)])];
    World { name: "stranger_junk", base: base(), events }
}

/// X writes H1 and H2 on shared counters; its removal lists H1 only; W's addendum then vouches
/// for H2, which makes it count.
pub fn vouched_later() -> World {
    let s = session(X, 0);
    let events = vec![
        sess(FIRST, X, 1, &s, vec![(K, NONE, 1, 3)]),
        sess(FIRST + 1, X, 2, &s, vec![(K, NONE, 2, 4)]),
        edge(FIRST + 2, ADMIN, 3, X, None, Some(vec![FIRST])),
        plain(FIRST + 3, W, 4, vec![(Aspect::ADDENDA, addendum(FIRST + 2, vec![FIRST + 1]))]),
    ];
    World { name: "vouched_later", base: base(), events }
}

/// X, an admin, writes a setting enabling `EXT` and a fire of it in one session-form commit S;
/// its removal lists S; X then fires F on S's counters, holding no write: F is valid iff S is
/// the current setting, and S is void iff F counts.
pub fn liar_setting() -> World {
    let s = session(X, 0);
    let events = vec![
        sess(FIRST, X, 1, &s, vec![(Aspect::RETENTION, setting(true), 1, 2), (EXT, NONE, 1, 2)]),
        edge(FIRST + 1, ADMIN, 2, X, None, Some(vec![FIRST])),
        sess(FIRST + 2, X, 3, &s, vec![(EXT, NONE, 1, 2)]),
    ];
    World { name: "liar_setting", base: base(), events }
}

/// C, X's write, counts only by W's addendum E; E (W removed after it) only by D, X's addendum
/// once granted again (and listed by X's second removal); D shares C's counters: D is void iff
/// C counts iff D counts.
pub fn liar_addenda() -> World {
    let s = session(X, 0);
    let (c, rx, e, rw, g, d) = (FIRST, FIRST + 1, FIRST + 2, FIRST + 3, FIRST + 4, FIRST + 5);
    let events = vec![
        sess(c, X, 1, &s, vec![(K, NONE, 1, 2)]),
        edge(rx, ADMIN, 2, X, None, Some(vec![])),
        plain(e, W, 3, vec![(Aspect::ADDENDA, addendum(rx, vec![c]))]),
        edge(rw, ADMIN, 4, W, None, Some(vec![])),
        edge(g, ADMIN, 5, X, Some(Role::Write), None),
        sess(d, X, 6, &s, vec![(K, NONE, 1, 2), (Aspect::ADDENDA, addendum(rw, vec![e]), 1, 2)]),
        // removed again, listing D: a re-grant standing would bring C back by itself
        edge(FIRST + 6, ADMIN, 7, X, None, Some(vec![d])),
    ];
    World { name: "liar_addenda", base: base(), events }
}

pub fn hand() -> Vec<World> {
    vec![removed_junk(), stranger_junk(), vouched_later(), liar_setting(), liar_addenda()]
}

/// A random world of `seed`, two to six events. `honest`: every session's counters on an aspect
/// run on without reuse in event order; else X and the stranger reuse X's counters at random.
/// `rule_inputs`: addenda and settings may be written in session form.
pub fn world(seed: u64, honest: bool, rule_inputs: bool) -> World {
    let mut r = Rng::new(seed ^ 0x0E1A);
    let n = 2 + r.below(5) as usize;
    let mut events: Vec<Event> = Vec::new();
    // per (source, aspect) the next counter
    let mut next: BTreeMap<(Source, Aspect), u64> = BTreeMap::new();
    let mut range = |r: &mut Rng, src: &Source, a: Aspect, own: bool| -> (u64, u64) {
        let len = 1 + r.below(2);
        let n = next.entry((src.clone(), a)).or_insert(1);
        let lo = if honest || own && r.chance(50) { *n } else { 1 + r.below(4) };
        *n = (*n).max(lo + len);
        (lo, lo + len)
    };
    let removals = |events: &[Event]| -> Vec<CommitId> { events.iter().filter(|e| e.commit.is_role() && e.commit.frontier.is_some()).map(|e| e.commit.id).collect() };
    while events.len() < n {
        let id = FIRST + events.len() as CommitId;
        let h = 1 + 2 * events.len() as u64 + r.below(2);
        let sx = session(X, 0);
        events.push(match r.below(10) {
            0..=2 => {
                let mut parts = vec![(K, NONE)];
                if r.chance(30) {
                    parts.push((EXT, NONE));
                }
                let parts = parts.into_iter().map(|(a, b)| { let (lo, hi) = range(&mut r, &sx, a, true); (a, b, lo, hi) }).collect();
                sess(id, X, h, &sx, parts)
            }
            3 => {
                let a = r.pick(&[K, EXT]);
                // in an honest world the stranger writes its own session
                let src = if honest { session(STRANGER, 0) } else { sx.clone() };
                let (lo, hi) = range(&mut r, &src, a, honest);
                sess(id, STRANGER, h, &src, vec![(a, NONE, lo, hi)])
            }
            4 => {
                let xs: Vec<CommitId> = events.iter().filter(|e| e.commit.signer == X && r.chance(50)).map(|e| e.commit.id).collect();
                edge(id, ADMIN, h, X, None, Some(xs))
            }
            5 => edge(id, ADMIN, h, X, Some(r.pick(&[Role::Write, Role::Admin])), None),
            6 => {
                let Some(&rm) = removals(&events).last() else { continue };
                let xs: Vec<CommitId> = events.iter().filter(|e| e.commit.signer == X && r.chance(60)).map(|e| e.commit.id).collect();
                let (author, src) = if r.chance(50) { (W, session(W, 0)) } else { (X, sx.clone()) };
                if rule_inputs && r.chance(60) {
                    let (lo, hi) = range(&mut r, &src, Aspect::ADDENDA, author == X);
                    let (klo, khi) = range(&mut r, &src, K, author == X);
                    sess(id, author, h, &src, vec![(Aspect::ADDENDA, addendum(rm, xs), lo, hi), (K, NONE, klo, khi)])
                } else {
                    plain(id, author, h, vec![(Aspect::ADDENDA, addendum(rm, xs))])
                }
            }
            7 => {
                let enables = r.chance(70);
                if rule_inputs && r.chance(60) {
                    let (lo, hi) = range(&mut r, &sx, Aspect::RETENTION, true);
                    let (elo, ehi) = range(&mut r, &sx, EXT, true);
                    sess(id, X, h, &sx, vec![(Aspect::RETENTION, setting(enables), lo, hi), (EXT, NONE, elo, ehi)])
                } else {
                    plain(id, r.pick(&[ADMIN, X]), h, vec![(Aspect::RETENTION, setting(enables))])
                }
            }
            _ => {
                let sw = session(W, 0);
                let (lo, hi) = range(&mut r, &sw, K, true);
                sess(id, W, h, &sw, vec![(K, NONE, lo, hi)])
            }
        });
    }
    World { name: "random", base: base(), events }
}
