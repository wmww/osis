//! held-model adapter (core/test/held-model, written from spec/ alone): what a node holds, as
//! the model's input, and the model's judgment compared with the node's (`compare`). The order
//! harness (`order.rs`, `Cfg::model`) runs it on every node it judges.
//!
//! Input: every commit the node holds (applied, and waiting with the parts its stored copy
//! holds), bodies as the node holds them (missing, dropped, held: a leftover's value-less carriers
//! as `stripped`), as own state the writes its state holds that no held body does, and every
//! creation record it holds of an actor or thing the input names. Ids, dots and values are
//! relabelled: commits ordered as their dots order (spec/crdt.md §2.2: source kind, source bytes,
//! then counter, a session's commits in `ts` order), values interned. Applied role commits
//! are given as the node's role input holds them (`ix.held`), one model part per edge write;
//! `required.0^` as its rules; undo, acting and purge
//! actors as headers name them.
//!
//! Scope (held-model ASSUMPTIONS.md): aspects of a register, a map of registers or a text (`IN`);
//! anything else is in the input as a placeholder (its parts carry nothing)
//! and is not compared. An in-scope aspect is not compared either (`Coverage::skipped`, by
//! reason) when a commit on it is outside the model (paged, ephemeral, waiting for blobs or
//! parked), a held body or its state has another shape (`Fragment::flat`), the node flags it
//! suspect (spec/requirements.md Deterministic: a flip after a drop), or a `required.0^` on its
//! thing names a prefix the model cannot (it matches some compared aspects, not all). No aspect
//! is compared when the role input is outside the model (`Scope::roles`: a role-class
//! compaction snapshot, a role commit with another aspect, a role frontier not inline, a role
//! commit outside the model as above): actors make every thing's roles depend on others'.
//!
//! Compared on in-scope aspects: which commits applied (role commits too, not the node's own from
//! outside the history), each content part's validity, reads (not where a body was dropped
//! for its bounds: `bounds_dropped`), no held body the model says must be
//! gone (`MustDrop`: a covered purge-on-replace body, a purged snapshot, a part gone at its expiry) or
//! counts as never received, no replaced purge-on-replace body held uncovered while the node holds the
//! right (`Outcome::owed`), no write in the state that no held body carries (the model's state is
//! the join of the held bodies), no forbidden value (expired or purged), and every body the node
//! dropped, given back as the order harness's keep-everything node holds it, one the model lets
//! go (`MayDrop`, `MustDrop`; a leftover is a held body, spec/crdt.md §4.7). Every difference is
//! tallied by kind (`Coverage::differs`); the first not awaiting a retention step
//! (`engine_retention`) is reported, none under `Coverage::survey`
//! (`order::held_model_retention_modes_survey_*`). The order harness also compares after every
//! ingest of its clocked deliveries, between ticks.
//!
//! Retention is fed as the model's history mode (`retention`): purge on replace is `PurgeOnReplace`, kept
//! is keep-at-least (an absolute T and/or D after replaced), no history convenient. A body the
//! node dropped for its bounds (`DropFor::Other`) is fed as missing; one dropped as covered as
//! `Body::Dropped(cover)`.
//!
//! Normalizations: a waiting commit's held parts carry no writes or edges (the model only needs
//! that they are held); a part an applied commit misses, or holds waiting alone (spec/commits.md
//! §4), is missing; a leftover's value-less carriers are taken as stripped by the node, also for
//! a value that arrived value-less; an edge's `tied` and `keyset` are dropped (carried,
//! never an authority).

use held_model as hm;
use osis_base::{Ak, CommitId, CreationRecord, Tid, Value};
use osis_commit::{CommitBlob, Form, Header, Kind};
use osis_crdt::{Flat, Fragment, Source};
use osis_node::Engine;
use osis_node::local_peer::Package;
use osis_schema::Codec;
use osis_schema::core_types as ct;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// The in-scope aspects and their kind.
const IN: [(&str, hm::AspectKind); 6] = [
    ("t:reg.0", hm::AspectKind::Register),
    ("t:gone.0", hm::AspectKind::Register),
    ("t:kept.0", hm::AspectKind::Register),
    ("t:brief.0", hm::AspectKind::Register),
    ("t:gonemap.0", hm::AspectKind::Map),
    ("t:text.0", hm::AspectKind::Text),
];

/// No actor: the holder of a waiting role part's placeholder edge write.
const NOBODY: hm::NodeId = u32::MAX;

/// How many nodes and aspects were compared, and the aspects left out by reason.
#[derive(Clone, Debug, Default)]
pub(crate) struct Coverage {
    pub(crate) nodes: u64,
    pub(crate) compared: u64,
    pub(crate) skipped: BTreeMap<&'static str, u64>,
    /// Of the compared aspects: reads present; parts invalid, purged, dropped, held as leftovers;
    /// value-less deltas. Of nodes with a compared aspect: the commits and edges fed of each
    /// feature (undo, acting, `required.0^`, invites, `until`, self-removals).
    pub(crate) reached: BTreeMap<&'static str, u64>,
    /// Every difference found, by kind (`compare` reports the first; under `survey` none).
    pub(crate) differs: BTreeMap<String, u64>,
    /// Survey mode (`Cfg::survey`): `compare` tallies every difference and reports none, so a
    /// harness run surveys where the node and the model disagree instead of stopping at the first.
    pub(crate) survey: bool,
    /// Under `survey`: the first difference of each kind, described.
    pub(crate) examples: BTreeMap<String, String>,
}

impl Coverage {
    pub(crate) fn add(&mut self, o: &Coverage) {
        self.nodes += o.nodes;
        self.compared += o.compared;
        for (k, n) in &o.skipped {
            *self.skipped.entry(k).or_default() += n;
        }
        for (k, n) in &o.reached {
            *self.reached.entry(k).or_default() += n;
        }
        for (k, n) in &o.differs {
            *self.differs.entry(k.clone()).or_default() += n;
        }
        for (k, d) in &o.examples {
            self.examples.entry(k.clone()).or_insert_with(|| d.clone());
        }
    }
}

/// A commit's counter range `[lo, hi)` on one aspect.
type Range = (u64, u64, CommitId);

/// Every commit of a history, by ID: its header, and who made which dots (spec/crdt.md §2.4:
/// the header's dot form and counter range per aspect).
pub(crate) struct History {
    headers: BTreeMap<CommitId, Arc<Header>>,
    /// Commit labels, in dot order.
    labels: BTreeMap<CommitId, u32>,
    ranges: BTreeMap<(Source, Tid, Ak), Vec<Range>>,
    /// Every AK a header names.
    aks: BTreeSet<String>,
}

impl History {
    pub(crate) fn new(packs: &[Package]) -> History {
        let headers: BTreeMap<CommitId, Arc<Header>> = packs.iter().filter_map(|pk| CommitBlob::decode_stored(&pk.bytes).ok()).map(|b| (b.id(), Arc::new(b.header))).collect();
        let mut order: Vec<(u8, Vec<u8>, u64, CommitId)> = headers
            .iter()
            .map(|(id, h)| match h.form {
                Form::Session(nonce) => (0, [&h.author.as_bytes()[..], &nonce[..]].concat(), h.ts.to_u64(), *id),
                Form::Commit => (1, id.0.to_vec(), 0, *id),
            })
            .collect();
        order.sort();
        let labels = order.iter().enumerate().map(|(i, x)| (x.3, i as u32 + 1)).collect();
        let mut ranges: BTreeMap<_, Vec<_>> = BTreeMap::new();
        let mut aks = BTreeSet::new();
        for (id, h) in &headers {
            for a in &h.aspects {
                ranges.entry((h.form.own_source(h.author, *id), a.tid, a.ak.clone())).or_default().push((a.lo, a.hi, *id));
                aks.insert(a.ak.as_str().to_string());
            }
        }
        History { headers, labels, ranges, aks }
    }
}

/// Labels and interned values of one conversion.
struct Conv<'h> {
    hist: &'h History,
    /// Actors and things: one id space.
    ids: BTreeMap<Tid, hm::NodeId>,
    /// Commits outside the history (a frontier or a dot naming one), and unknown dot sources.
    extra: BTreeMap<String, u32>,
    vals: BTreeMap<String, hm::Val>,
    aspects: BTreeMap<String, u32>,
}

impl Conv<'_> {
    fn id(&mut self, t: &Tid) -> hm::NodeId {
        let n = self.ids.len() as u32;
        *self.ids.entry(*t).or_insert(n)
    }
    fn extra(&mut self, k: String) -> u32 {
        let n = self.extra.len() as u32;
        *self.extra.entry(k).or_insert(1_000_000 + n)
    }
    fn commit(&mut self, c: &CommitId) -> hm::CommitId {
        match self.hist.labels.get(c) {
            Some(l) => *l,
            None => self.extra(format!("{c:?}")),
        }
    }
    /// Values apart from chars (text elements are their code points).
    fn val(&mut self, v: &Value) -> hm::Val {
        let n = self.vals.len() as u32;
        *self.vals.entry(format!("{v:?}")).or_insert((1 << 24) + n)
    }
    /// The model aspect of an AK: one name per AK, in or out of scope.
    fn aspect(&mut self, ak: &str) -> hm::Aspect {
        match ak {
            "roles.0" => return hm::Aspect::ROLES,
            "required.0^" => return hm::Aspect::REQUIRED,
            osis_commit::retention::PURGE => return hm::Aspect::reg(9),
            _ => {}
        }
        match IN.iter().position(|x| x.0 == ak) {
            Some(i) => hm::Aspect { name: i as u32 + 1, kind: IN[i].1, admin_only: false },
            None => {
                let n = self.aspects.len() as u32;
                let name = 100 + *self.aspects.entry(ak.to_string()).or_insert(n);
                hm::Aspect { name, kind: hm::AspectKind::Register, admin_only: ak.ends_with('^') }
            }
        }
    }
    /// The model dot of `d` on `(t, a)`: its carrying commit by the header ranges.
    fn dot(&mut self, d: &osis_crdt::Dot, t: &Tid, a: &Ak) -> hm::Dot {
        let d = d.origin();
        let origin = match d.src.kind() {
            osis_crdt::SourceKind::Commit(c) => Some(*c),
            _ => self.hist.ranges.get(&(d.src.clone(), *t, a.clone())).and_then(|v| v.iter().find(|x| x.0 <= d.ctr && d.ctr < x.1)).map(|x| x.2),
        };
        let commit = match origin {
            Some(c) => self.commit(&c),
            None => self.extra(format!("{:?}", d.src)),
        };
        hm::Dot { commit, ctr: d.ctr as u32 }
    }
    fn stamp(&mut self, s: &osis_crdt::Stamp, t: &Tid, a: &Ak) -> hm::Stamp {
        hm::Stamp { ts: s.ts.to_u64(), dot: self.dot(&s.dot, t, a) }
    }
    /// A fragment's writes, or why it is out of scope.
    fn writes(&mut self, f: &Fragment, t: &Tid, a: &Ak, kind: hm::AspectKind) -> Result<Vec<hm::Write>, &'static str> {
        let mut out = Vec::new();
        for x in f.flat()? {
            let (stamp, op) = match &x {
                Flat::Reset(s) => (self.stamp(s, t, a), hm::Op::Reset),
                Flat::Set(s, v) => (self.stamp(s, t, a), hm::Op::Set { value: v.as_ref().map(|v| self.val(v)) }),
                Flat::Create(s, k) => (self.stamp(s, t, a), hm::Op::Create { key: k.as_ref().map(|v| self.val(v)) }),
                Flat::SetIn { entry, key, at, value } => {
                    let op = hm::Op::SetIn { entry: self.dot(entry, t, a), key: key.as_ref().map(|v| self.val(v)), value: value.as_ref().map(|v| self.val(v)) };
                    (self.stamp(at, t, a), op)
                }
                Flat::Remove { entry, at } => (self.stamp(at, t, a), hm::Op::Remove { entry: self.dot(entry, t, a) }),
                Flat::Insert { at, anchor, ch } => {
                    let anchor = anchor.as_ref().map(|d| self.dot(d, t, a));
                    (self.stamp(at, t, a), hm::Op::Insert { anchor, ch: ch.map(|c| c as u32) })
                }
                Flat::Delete { elem, at } => (self.stamp(at, t, a), hm::Op::Delete { elem: self.dot(elem, t, a) }),
                Flat::Undelete { elem, at, ch } => (self.stamp(at, t, a), hm::Op::Undelete { elem: self.dot(elem, t, a), ch: ch.map(|c| c as u32) }),
                Flat::Anchor(d) => (hm::Stamp { ts: 0, dot: self.dot(d, t, a) }, hm::Op::Anchor),
            };
            let w = hm::Write { stamp, op };
            if !w.fits(kind) {
                return Err("write of another kind");
            }
            out.push(w);
        }
        Ok(out)
    }
    /// What the node reads, as the model reads.
    fn read(&mut self, v: Option<&Value>, kind: hm::AspectKind) -> hm::Read {
        match (v, kind) {
            (None, _) => hm::Read::Absent,
            (Some(Value::Map(m)), hm::AspectKind::Map) => hm::Read::Map(m.iter().map(|(k, x)| (self.val(k), self.val(x))).collect()),
            (Some(Value::Str(s)), hm::AspectKind::Text) => hm::Read::Text(s.chars().map(|c| c as u32).collect()),
            (Some(v), _) => hm::Read::Reg(self.val(v)),
        }
    }
    /// A role edge write (`tied`, `keyset` dropped: carried, never an authority).
    fn edge(&mut self, holder: &Tid, e: Option<&osis_perm::Edge>) -> hm::EdgeWrite {
        hm::EdgeWrite { holder: self.id(holder), role: e.map(|e| role_of(e.role)), invite: e.and_then(|e| e.invite).map(role_of), until: e.and_then(|e| e.until).map(|u| u.0) }
    }
    /// A `required.0^` setting as rules, or why the model cannot say it: an AK prefix is the
    /// model's empty prefix when it matches every compared AK, an AK name when it is one and
    /// prefixes no other, a name nothing has when it matches no compared AK.
    fn rules(&mut self, f: Option<&Fragment>) -> Result<Vec<hm::Rule>, &'static str> {
        let Some(v) = f.and_then(Fragment::read) else { return Ok(Vec::new()) };
        let rules = ct::required_rules(&v);
        if rules.retain {
            return Err("required retain");
        }
        let mut out: Vec<hm::Rule> = Vec::new();
        for (p, q) in &rules.rules {
            let matches = |ak: &str| ak.starts_with(p.as_str());
            let prefix = if IN.iter().all(|x| matches(x.0)) {
                None
            } else if self.hist.aks.contains(p) && self.hist.aks.iter().filter(|ak| matches(ak)).count() == 1 {
                Some(self.aspect(p).name)
            } else if !IN.iter().any(|x| matches(x.0)) {
                Some(99)
            } else {
                return Err("required prefix outside the model");
            };
            if out.iter().any(|r| r.prefix == prefix) {
                return Err("required prefixes alike in the model");
            }
            out.push(hm::Rule { prefix, retention: retention(&q.retention().canonical()), expiry: q.expires });
        }
        Ok(out)
    }
}

/// The model's history mode of a wire retention: purge on replace is `PurgeOnReplace`; kept is
/// keep-at-least (an absolute T and/or D after replaced); no history is convenient.
fn retention(r: &osis_schema::Retention) -> hm::Retention {
    use osis_base::PurgeBy as P;
    let by = match r.by {
        P::Nobody => hm::PurgeBy::Nobody,
        P::Admin => hm::PurgeBy::Admin,
        P::AuthorOrAdmin => hm::PurgeBy::AuthorOrAdmin,
        P::Writer => hm::PurgeBy::Writer,
        P::Author => hm::PurgeBy::Author,
    };
    let forever = |x: u64| if x == osis_commit::FOREVER { hm::FOREVER } else { x };
    let history = match r.history {
        Some(osis_schema::History::PurgeOnReplace) => hm::History::PurgeOnReplace,
        Some(osis_schema::History::Keep { until, after }) => hm::History::Keep { until: until.map(forever).unwrap_or(0), after: after.unwrap_or(0) },
        None => hm::History::CONVENIENT,
    };
    hm::Retention { by, history }
}

/// One node, converted.
struct Input {
    held: hm::Held,
    /// In-scope aspects by thing and AK, with their model keys.
    inside: BTreeMap<(Tid, Ak), (hm::ThingId, hm::Aspect)>,
    skipped: BTreeMap<(Tid, Ak), &'static str>,
    /// Held commits by label: ID, applied here.
    commits: BTreeMap<hm::CommitId, (CommitId, bool)>,
    /// The value and extra label tables, to convert more with the same labels.
    vals: BTreeMap<String, hm::Val>,
    extra: BTreeMap<String, u32>,
    /// Bodies the node dropped (not missing) on in-scope aspects: label, part, ID, thing, AK,
    /// and why (`DropFor`, with its coverers).
    dropped: Vec<(hm::CommitId, usize, CommitId, Tid, Ak, String)>,
    /// Per in-scope aspect: the writes the node's state holds that no held body does.
    own: BTreeMap<(hm::ThingId, hm::Aspect), Vec<hm::Write>>,
    /// Actors and things by model id.
    ids: BTreeMap<hm::NodeId, Tid>,
}

/// What of a node's held set is outside the model.
#[derive(Default)]
struct Scope {
    /// Aspects, with why.
    aspects: BTreeMap<(Tid, Ak), &'static str>,
    /// Things whose every aspect is out, with why.
    things: BTreeMap<Tid, &'static str>,
    /// Why the role input is out (then every aspect is).
    roles: Option<&'static str>,
}

impl Scope {
    fn out(&self, t: &Tid, a: &Ak) -> Option<&'static str> {
        self.roles.or_else(|| self.things.get(t).copied()).or_else(|| self.aspects.get(&(*t, a.clone())).copied())
    }
}

/// What of `e`'s held commits is outside the model (`Scope`).
fn scope(e: &mut Engine, held: &[(CommitId, Arc<Header>, bool)], waited: &BTreeSet<(Tid, Ak)>) -> Scope {
    use osis_node::Reason as R;
    let mut s = Scope::default();
    let role_out = |s: &mut Scope, why: &'static str| {
        s.roles.get_or_insert(why);
    };
    let pending: BTreeMap<CommitId, R> = e.pending().into_iter().collect();
    for (id, h, applied) in held {
        let commit_out = if h.kind == Kind::RoleSnapshot {
            Some("role snapshot")
        } else if !h.chunks.is_empty() {
            Some("paged")
        } else if h.ephemeral.is_some() {
            Some("ephemeral")
        } else if !applied && !matches!(pending.get(id), Some(R::Drift | R::MissingChain(_) | R::UnknownCreated(_))) {
            Some("waits for a reason outside the model")
        } else if h.frontier.as_ref().is_some_and(|f| ct::Frontier::from_value(f).is_err()) {
            Some("frontier not inline")
        } else if h.kind.is_role() && h.undoes.is_some() {
            Some("role undo")
        } else {
            None
        };
        if let Some(why) = commit_out {
            if h.kind.is_role() {
                role_out(&mut s, why);
            }
            for a in &h.aspects {
                s.aspects.entry((a.tid, a.ak.clone())).or_insert(why);
            }
        }
        // `keys.0` (sealed keys) changes no role: a placeholder
        if h.kind == Kind::Role && h.aspects.iter().any(|a| !matches!(a.ak.as_str(), "roles.0" | "keys.0")) {
            role_out(&mut s, "role commit beyond roles.0");
        }
    }
    // from the history (`order::waited_at_expiry`), never the node's own flags
    for (t, a) in waited {
        s.aspects.entry((*t, a.clone())).or_insert("waited at its expiry");
    }
    s
}

fn convert(e: &mut Engine, hist: &History, waited: &BTreeSet<(Tid, Ak)>) -> Input {
    // authors take ids in tid order: keys `(ts, author, commit)` order alike (spec/permissions.md §5.1)
    let authors: BTreeSet<Tid> = hist.headers.values().map(|h| h.author).chain([e.tid()]).collect();
    let ids = authors.into_iter().enumerate().map(|(i, t)| (t, i as u32)).collect();
    let mut cv = Conv { hist, ids, extra: BTreeMap::new(), vals: BTreeMap::new(), aspects: BTreeMap::new() };
    let applied: Vec<CommitId> = e.commit_ids();
    let mut held: Vec<(CommitId, Arc<Header>, bool)> = applied.iter().filter_map(|id| Some((*id, e.header(id)?, true))).collect();
    // an applied commit with a part waiting alone (spec/commits.md §4) is listed once, as applied:
    // the waiting part is missing from its record (fed as missing, below)
    for (id, _) in e.pending() {
        if let Some(h) = hist.headers.get(&id).filter(|_| !applied.contains(&id)) {
            held.push((id, h.clone(), false));
        }
    }
    let mut sc = scope(e, &held, waited);
    let is_in = |sc: &Scope, t: &Tid, a: &Ak| IN.iter().any(|x| x.0 == a.as_str()) && sc.out(t, a).is_none();
    // `required.0^` settings first: one the model cannot say takes its thing out
    let mut required: BTreeMap<(CommitId, usize), Vec<hm::Rule>> = BTreeMap::new();
    for (id, h, applied) in &held {
        for (ai, a) in h.aspects.iter().enumerate().filter(|(_, a)| a.ak.as_str() == "required.0^") {
            if !applied || !held_body(e, id, ai) {
                continue;
            }
            let f = e.body_fragment(id, &a.tid, &a.ak).unwrap();
            match cv.rules(f.as_ref()) {
                Ok(r) => {
                    required.insert((*id, ai), r);
                }
                Err(why) => {
                    sc.things.entry(a.tid).or_insert(why);
                }
            }
        }
    }
    // bodies next: a shape outside the model takes its aspect out before anything is built
    let mut bodies: BTreeMap<(CommitId, usize), Vec<hm::Write>> = BTreeMap::new();
    for (id, h, applied) in &held {
        if !applied || h.kind.is_role() {
            continue;
        }
        for (ai, a) in h.aspects.iter().enumerate() {
            if !is_in(&sc, &a.tid, &a.ak) || !held_body(e, id, ai) {
                continue;
            }
            let kind = cv.aspect(a.ak.as_str()).kind;
            if let Some(f) = e.body_fragment(id, &a.tid, &a.ak).unwrap() {
                match cv.writes(&f, &a.tid, &a.ak, kind) {
                    Ok(ws) => {
                        bodies.insert((*id, ai), ws);
                    }
                    Err(why) => {
                        sc.aspects.insert((a.tid, a.ak.clone()), why);
                    }
                }
            }
        }
    }
    let mut states: BTreeMap<(Tid, Ak), Vec<hm::Write>> = BTreeMap::new();
    for (t, a) in e.all_aspects().unwrap() {
        if !is_in(&sc, &t, &a) {
            continue;
        }
        let kind = cv.aspect(a.as_str()).kind;
        if let Some(f) = e.state(&t, &a).unwrap() {
            match cv.writes(&f, &t, &a, kind) {
                Ok(ws) => {
                    states.insert((t, a), ws);
                }
                Err(why) => {
                    sc.aspects.insert((t, a), why);
                }
            }
        }
    }
    let mut commits = Vec::new();
    let mut dropped = Vec::new();
    let mut labels = BTreeMap::new();
    let mut inside = BTreeMap::new();
    for (id, h, applied) in &held {
        let label = cv.commit(id);
        labels.insert(label, (*id, *applied));
        let meta = e.core.ix.commits.get(id).cloned();
        let waiting = if *applied { None } else { e.pending_parts(id).unwrap() };
        let edges = if *applied && h.kind == Kind::Role { e.core.ix.held.edge_commit(id).cloned() } else { None };
        let mut parts = Vec::new();
        for (ai, a) in h.aspects.iter().enumerate() {
            let thing = cv.id(&a.tid);
            let ok = is_in(&sc, &a.tid, &a.ak);
            let aspect = cv.aspect(a.ak.as_str());
            if ok {
                inside.insert((a.tid, a.ak.clone()), (thing, aspect));
            }
            let retention = retention(&a.retention);
            let part = |body| hm::Part { thing, aspect, retention, body, stripped: BTreeSet::new() };
            let state = match &meta {
                Some(m) if m.missing.contains(&ai) => Some(hm::Body::Missing),
                Some(m) if m.dropped.contains_key(&ai) => {
                    let d = &m.dropped[&ai];
                    if ok {
                        dropped.push((label, parts.len(), *id, a.tid, a.ak.clone(), format!("{:?} covered by {:?} live {}", d.why, d.covered_by, d.live)));
                    }
                    // dropped as covered: by its first coverer in the history; for its bounds:
                    // the model has no such drop, the body is fed as never received
                    let cover = (d.why == osis_node::engine::DropFor::Cover).then(|| d.covered_by.iter().find(|c| hist.headers.contains_key(c)).map(|c| cv.commit(c))).flatten();
                    Some(cover.map_or(hm::Body::Missing, hm::Body::Dropped))
                }
                Some(_) => None,
                None if waiting.as_ref().is_some_and(|p| p.contains(&ai)) => {
                    // a waiting part: held, its content unread
                    Some(hm::Body::Held(match h.kind {
                        Kind::Role => hm::Delta::Edge(hm::EdgeWrite::role(NOBODY, None)),
                        _ if aspect == hm::Aspect::REQUIRED => hm::Delta::Required(Vec::new()),
                        _ => hm::Delta::Writes(Vec::new()),
                    }))
                }
                None => Some(hm::Body::Missing),
            };
            if let Some(body) = state {
                parts.push(part(body));
                continue;
            }
            match h.kind {
                Kind::Role if a.ak.as_str() == "keys.0" => parts.push(part(hm::Body::Held(hm::Delta::Writes(Vec::new())))),
                Kind::Role => {
                    let ops: Vec<_> = edges.iter().flat_map(|c| c.ops.iter()).filter(|o| o.target == a.tid).collect();
                    if ops.is_empty() {
                        // a delta naming no holder (a reset of an entry whose creation is not held)
                        parts.push(part(hm::Body::Held(hm::Delta::Edge(hm::EdgeWrite::role(NOBODY, None)))));
                    }
                    for o in ops {
                        parts.push(part(hm::Body::Held(hm::Delta::Edge(cv.edge(&o.holder, o.edge.as_ref())))));
                    }
                }
                _ if aspect == hm::Aspect::REQUIRED => {
                    parts.push(part(hm::Body::Held(hm::Delta::Required(required.get(&(*id, ai)).cloned().unwrap_or_default()))));
                }
                _ => {
                    let ws = if ok { bodies.get(&(*id, ai)).cloned().unwrap_or_default() } else { Vec::new() };
                    let mut p = part(hm::Body::Held(hm::Delta::Writes(Vec::new())));
                    if meta.as_ref().is_some_and(|m| m.stripped.contains(&ai)) {
                        p.stripped = valueless_carriers(&ws);
                    }
                    p.body = hm::Body::Held(hm::Delta::Writes(ws));
                    parts.push(p);
                }
            }
        }
        let kind = match h.kind {
            Kind::Role => hm::CommitKind::Role,
            Kind::ContentSnapshot => hm::CommitKind::Snapshot,
            _ => hm::CommitKind::Content,
        };
        let frontier = h.frontier.as_ref().and_then(|f| ct::Frontier::from_value(f).ok()).map(|f| f.commits.iter().map(|c| cv.commit(c)).collect());
        let purge = h
            .purge
            .iter()
            .map(|p| {
                let (thing, aspect) = (cv.id(p.tid()), cv.aspect(p.ak().as_str()));
                match p {
                    osis_commit::PurgeItem::Commit { commit, .. } => hm::PurgeItem::Commit { commit: cv.commit(commit), thing, aspect },
                    osis_commit::PurgeItem::Aspect { .. } => hm::PurgeItem::Aspect { thing, aspect },
                    osis_commit::PurgeItem::Author { actor, .. } => hm::PurgeItem::Author { thing, aspect, author: cv.id(actor) },
                }
            })
            .collect();
        let (author, actor) = (cv.id(&h.author), cv.id(&h.actor));
        let undoes = h.undoes.as_ref().map(|c| cv.commit(c));
        commits.push(hm::Commit { id: label, author, actor, ts: h.ts.to_u64(), expires: h.expires, kind, parts, purge, frontier, undoes });
    }
    // own state: what the state holds that no held body of an applied commit does (the model has
    // none: its state is the join of the held bodies)
    let mut own: BTreeMap<(hm::ThingId, hm::Aspect), Vec<hm::Write>> = BTreeMap::new();
    for ((t, a), ws) in states {
        let Some(&(thing, aspect)) = inside.get(&(t, a.clone())) else { continue };
        let in_bodies: BTreeSet<hm::WriteId> = commits
            .iter()
            .flat_map(|c| c.parts.iter())
            .filter(|p| p.thing == thing && p.aspect == aspect)
            .filter_map(|p| match &p.body {
                hm::Body::Held(hm::Delta::Writes(ws)) => Some(ws.iter().map(hm::Write::id).collect::<Vec<_>>()),
                _ => None,
            })
            .flatten()
            .collect();
        let out: Vec<hm::Write> = ws.into_iter().filter(|w| !in_bodies.contains(&w.id())).collect();
        if !out.is_empty() {
            own.insert((thing, aspect), out);
        }
    }
    let me = cv.id(&e.tid());
    // every record the node holds of an id named, first admins naming more
    let mut things = Vec::new();
    let mut done = BTreeSet::new();
    loop {
        let todo: Vec<Tid> = cv.ids.keys().filter(|t| !done.contains(*t)).copied().collect();
        if todo.is_empty() {
            break;
        }
        for t in todo {
            done.insert(t);
            let link = match e.core.created(&t) {
                None => continue,
                Some(CreationRecord::KeyActor { .. }) => hm::RecordLink::Key,
                Some(CreationRecord::Thing { admin, .. }) => hm::RecordLink::Admin(cv.id(admin)),
            };
            things.push(hm::Thing { id: cv.id(&t), link });
        }
    }
    inside.retain(|k, _| sc.out(&k.0, &k.1).is_none());
    let mut skipped: BTreeMap<(Tid, Ak), &'static str> = BTreeMap::new();
    for (_, h, _) in &held {
        for a in h.aspects.iter().filter(|a| IN.iter().any(|x| x.0 == a.ak.as_str())) {
            if let Some(why) = sc.out(&a.tid, &a.ak) {
                skipped.insert((a.tid, a.ak.clone()), why);
            }
        }
    }
    let held = hm::Held { now: e.now().0, me, things, commits };
    let ids = cv.ids.iter().map(|(t, i)| (*i, *t)).collect();
    let mut input = Input { held, inside, skipped, commits: labels, vals: cv.vals, extra: cv.extra, dropped, own, ids };
    input.held.commits.sort_by_key(|c| c.id);
    input
}

fn role_of(r: osis_base::Role) -> hm::Role {
    match r {
        osis_base::Role::Read => hm::Role::Read,
        osis_base::Role::Write => hm::Role::Write,
        osis_base::Role::Admin => hm::Role::Admin,
    }
}

/// Converts what `e` holds, runs the model and compares (see the module doc); the first
/// difference, with the model's answer and the node's.
/// Every body a node holds on an in-scope aspect, as held.
pub(crate) type Bodies = BTreeMap<(CommitId, Tid, Ak), Fragment>;

/// `Bodies` of a node keeping every body (`Engine::keep_bodies`): what a node dropped, to judge.
pub(crate) fn bodies(e: &mut Engine) -> Bodies {
    let mut out = Bodies::new();
    for id in e.commit_ids() {
        let Some(h) = e.header(&id) else { continue };
        for a in h.aspects.iter().filter(|a| IN.iter().any(|x| x.0 == a.ak.as_str())) {
            if let Some(f) = e.body_fragment(&id, &a.tid, &a.ak).unwrap() {
                out.insert((id, a.tid, a.ak.clone()), f);
            }
        }
    }
    out
}

/// Whether the node holds part `ai` of applied commit `c`: whole or as its leftover (spec/crdt.md
/// §4.7: a leftover is a held body), neither dropped nor missing.
fn held_body(e: &Engine, c: &CommitId, ai: usize) -> bool {
    e.core.ix.commits.get(c).is_some_and(|m| !m.dropped.contains_key(&ai) && !m.missing.contains(&ai))
}

/// Value-less carriers of a held body: taken as what the node stripped (`Part::stripped`).
fn valueless_carriers(ws: &[hm::Write]) -> BTreeSet<hm::CommitId> {
    ws.iter().flat_map(|w| w.values()).filter(|x| x.1.is_none()).map(|x| x.0).collect()
}

/// `waited`: aspects (as `order::facts_text` prints them) a part may have waited at its expiry
/// on (`order::waited_at_expiry`), left out.
pub(crate) fn compare(e: &mut Engine, hist: &History, kept: &Bodies, cov: &mut Coverage, waited: &BTreeSet<(String, String)>) -> Option<String> {
    let waited: BTreeSet<(Tid, Ak)> = hist.headers.values().flat_map(|h| h.aspects.iter().map(|a| (a.tid, a.ak.clone()))).filter(|(t, a)| waited.contains(&(format!("{t:?}"), a.as_str().to_string()))).collect();
    let input = convert(e, hist, &waited);
    let o = hm::evaluate(&input.held);
    cov.nodes += 1;
    cov.compared += input.inside.len() as u64;
    for why in input.skipped.values() {
        *cov.skipped.entry(why).or_default() += 1;
    }
    let inside: BTreeSet<(hm::ThingId, hm::Aspect)> = input.inside.values().copied().collect();
    let mut reach = |k: &'static str, n: usize| *cov.reached.entry(k).or_default() += n as u64;
    reach("read present", inside.iter().filter(|k| o.reads.get(k).is_some_and(|r| *r != hm::Read::Absent)).count());
    let parts = || input.held.commits.iter().flat_map(|c| c.parts.iter().enumerate().map(move |(i, p)| ((c.id, i), p))).filter(|(_, p)| inside.contains(&(p.thing, p.aspect)));
    reach("invalid", parts().filter(|(k, _)| o.valid.get(k) == Some(&false)).count());
    reach("purged", parts().filter(|(k, _)| o.purged.contains_key(k)).count());
    reach("dropped", parts().filter(|(_, p)| matches!(p.body, hm::Body::Dropped(_))).count());
    reach("leftover", parts().filter(|(_, p)| !p.stripped.is_empty()).count());
    reach("value-less", o.valueless.iter().filter(|d| inside.contains(&(d.1, d.2))).count());
    reach("own state", input.own.values().map(Vec::len).sum());
    if !inside.is_empty() {
        let cs = &input.held.commits;
        let edges = || cs.iter().filter(|c| c.kind == hm::CommitKind::Role).flat_map(|c| c.parts.iter().map(move |p| (c, p))).filter_map(|(c, p)| match &p.body {
            hm::Body::Held(hm::Delta::Edge(e)) => Some((c, e)),
            _ => None,
        });
        reach("undo commits", cs.iter().filter(|c| c.undoes.is_some()).count());
        reach("acting commits", cs.iter().filter(|c| c.actor != c.author).count());
        reach("required settings", cs.iter().flat_map(|c| c.parts.iter()).filter(|p| matches!(&p.body, hm::Body::Held(hm::Delta::Required(r)) if !r.is_empty())).count());
        reach("invites", edges().filter(|(_, e)| e.invite.is_some()).count());
        reach("untils", edges().filter(|(_, e)| e.until.is_some()).count());
        reach("own edge writes", edges().filter(|(c, e)| e.holder == c.author).count());
        reach("removals with no frontier", edges().filter(|(c, e)| e.role.is_none() && e.holder != NOBODY && c.frontier.is_none()).count());
    }
    // the model's input on the things `what` is about: now, things, their commits, own state
    let differ = |what: String, things: &[hm::ThingId]| {
        let h = &input.held;
        let mut s = format!("held-model differs: {what}\nmodel input (things {things:?}): now {}, me {}, things {:?}", h.now, h.me, h.things);
        for c in h.commits.iter().filter(|c| c.is_role() || c.parts.iter().any(|p| things.contains(&p.thing))) {
            s.push_str(&format!("\n  {c:?}"));
        }
        Some(s)
    };
    let by_part: BTreeMap<(hm::ThingId, hm::Aspect), (Tid, Ak)> = input.inside.iter().map(|(k, v)| (*v, k.clone())).collect();
    // every difference, by kind; the first is reported (none under `survey`)
    let mut diffs: Vec<(String, Option<String>)> = Vec::new();
    for c in &input.held.commits {
        let (id, applied) = input.commits[&c.id];
        let touches = c.parts.iter().any(|p| by_part.contains_key(&(p.thing, p.aspect))) || (c.is_role() && !by_part.is_empty());
        // the node's own commits from outside the history (its creation, carriers) are its own
        // writes, never received: the order harness may set its clock back before them (no drift)
        let own = !hist.headers.contains_key(&id);
        if touches && !own && o.applied.contains(&c.id) != applied {
            let h = &hist.headers[&id];
            let parts: Vec<String> = h.aspects.iter().map(|a| format!("{:?} {} syncs {} first admin {:?}", a.tid, a.ak.as_str(), e.core.syncs(&a.tid), e.first_admin(&a.tid))).collect();
            let missing = e.core.ix.commits.get(&id).map(|m| m.missing.clone());
            diffs.push(("applied differs".into(), differ(format!("commit {id:?} (#{}) applied: model {}, node {applied}; parts {parts:?}, node misses {missing:?}", c.id, o.applied.contains(&c.id)), &c.parts.iter().map(|p| p.thing).collect::<Vec<_>>())));
            continue;
        }
        if !applied || c.is_role() {
            continue;
        }
        for (i, p) in c.parts.iter().enumerate() {
            let Some((t, a)) = by_part.get(&(p.thing, p.aspect)) else { continue };
            let node = e.body_valid(&id, t, a);
            let model = o.valid.get(&(c.id, i)).copied();
            if node != model {
                diffs.push(("validity differs".into(), differ(format!("validity of commit {id:?} (#{}) on {t:?} {}: model {model:?}, node {node:?}; node's roster {:?}, role commits {:?}", c.id, a.as_str(), e.roster(t), role_commits(e, t)), &[p.thing])));
                continue;
            }
            // a body the model says must be gone, or counts as never received, that the node holds
            if let Some(f) = o.fates.get(&(c.id, i))
                && matches!(f, hm::Fate::MustDrop(_) | hm::Fate::NeverReceived)
            {
                let kind = match f {
                    hm::Fate::MustDrop(hm::DropWhy::Covered { .. }) => "holds a covered purge-on-replace body".to_string(),
                    _ => format!("holds a body the model says is gone: {f:?}"),
                };
                diffs.push((kind, differ(format!("commit {id:?} (#{}) on {t:?} {}: the node holds its body, the model's fate is {f:?}", c.id, a.as_str()), &[p.thing])));
            }
            // a replaced purge-on-replace body the node, holding the right, has not covered
            if o.owed.contains(&(c.id, i)) {
                diffs.push(("writer holds an uncovered replaced purge-on-replace body".into(), differ(format!("commit {id:?} (#{}) on {t:?} {}: replaced purge-on-replace body, uncovered, the node holds the right", c.id, a.as_str()), &[p.thing])));
            }
        }
    }
    // the role input: which edge writes apply on each thing
    if !by_part.is_empty() {
        for c in input.held.commits.iter().filter(|c| c.is_role() && input.commits[&c.id].1) {
            let id = input.commits[&c.id].0;
            let mut on: BTreeMap<hm::ThingId, bool> = BTreeMap::new();
            for (i, p) in c.parts.iter().enumerate() {
                if matches!(&p.body, hm::Body::Held(hm::Delta::Edge(w)) if w.holder != NOBODY) {
                    *on.entry(p.thing).or_default() |= o.valid.get(&(c.id, i)) == Some(&true);
                }
            }
            for (th, model) in on {
                let t = input.ids[&th];
                let node = e.edge_write_applied(&t, &id);
                if node != model {
                    diffs.push(("role commit applies differs".into(), differ(format!("role commit {id:?} (#{}) on {t:?} applies: model {model}, node {node}; node's roster {:?}", c.id, e.roster(&t)), &[th])));
                }
            }
        }
    }
    if let Some(f) = o.forbidden.iter().find(|f| by_part.contains_key(&(f.1.1, f.1.2))) {
        diffs.push(("forbidden value held".into(), differ(format!("forbidden value held: {f:?}"), &[f.1.1])));
    }
    // the state is the join of the held bodies: nothing in it that no held body carries
    for ((thing, aspect), ws) in &input.own {
        let (t, a) = &by_part[&(*thing, *aspect)];
        diffs.push(("state holds writes no held body does".into(), differ(format!("{t:?} {}: the state holds {} write(s) no held body does: {ws:?}", a.as_str(), ws.len()), &[*thing])));
    }
    // a dropped body whose cover fell: the node fetches it again (a suspect aspect is skipped
    // above, so this names one the node reads without a flag)
    for &(c, i) in &o.uncovered {
        let p = &input.held.commits.iter().find(|x| x.id == c).unwrap().parts[i];
        if let Some((t, a)) = by_part.get(&(p.thing, p.aspect)) {
            diffs.push(("dropped body whose cover fell not fetched again".into(), differ(format!("commit #{c} on {t:?} {}: dropped as covered, its cover no longer stands", a.as_str()), &[p.thing])));
        }
    }
    // reads: the node's read through the conversion's value table. Not on an aspect where the
    // node dropped a body purged on replace other than as covered: fed as missing while the state
    // keeps its live writes (no such drop in the model, retention step 2);
    // `order::live_write_lost` compares that read with the keep-everything node's.
    let bounds_dropped: BTreeSet<(hm::ThingId, hm::Aspect)> = input
        .dropped
        .iter()
        .filter_map(|(label, i, ..)| input.held.commits.iter().find(|c| c.id == *label).map(|c| &c.parts[*i]))
        .filter(|p| p.body == hm::Body::Missing && p.retention.history == hm::History::PurgeOnReplace)
        .map(|p| (p.thing, p.aspect))
        .collect();
    let mut cv = Conv { hist, ids: BTreeMap::new(), extra: input.extra.clone(), vals: input.vals.clone(), aspects: BTreeMap::new() };
    for ((t, a), (thing, aspect)) in input.inside.iter().filter(|(_, k)| !bounds_dropped.contains(k)) {
        let model = o.reads.get(&(*thing, *aspect)).cloned().unwrap_or(hm::Read::Absent);
        let v = e.get(t, a).unwrap();
        let node = cv.read(v.as_ref(), aspect.kind);
        if node != model {
            diffs.push(("read differs".into(), differ(format!("{t:?} {} reads {v:?} ({node:?}) at the node, {model:?} in the model (state {:?})", a.as_str(), o.states.get(&(*thing, *aspect))), &[*thing])));
        }
    }
    // the bodies the node dropped, given back as a node keeping every body holds them: the model
    // lets each go (a purged or expired delta's own body is held as its leftover, spec/crdt.md §4.7)
    let mut back = input.held.clone();
    let mut given = Vec::new();
    for (label, i, id, t, a, why) in &input.dropped {
        let Some(f) = kept.get(&(*id, *t, a.clone())) else { continue };
        let Some(c) = back.commits.iter_mut().find(|c| c.id == *label) else { continue };
        let kind = c.parts[*i].aspect.kind;
        let Ok(ws) = cv.writes(f, t, a, kind) else { continue };
        c.parts[*i].stripped = valueless_carriers(&ws);
        c.parts[*i].body = hm::Body::Held(hm::Delta::Writes(ws));
        given.push((*label, *i, *id, *t, a.clone(), why.clone()));
    }
    reach_n(cov, "dropped judged", given.len());
    if !given.is_empty() {
        let ob = hm::evaluate(&back);
        for (label, i, id, t, a, why) in &given {
            let f = ob.fates.get(&(*label, *i));
            let dropped_for = e.core.ix.commits.get(id).and_then(|m| m.dropped.get(i)).map(|d| d.why);
            // a body dropped at its keep-at-most bound before a request naming it arrived stays
            // dropped (never received, spec/commits.md §5: the request strips what the node
            // holds); the model holds the set whole and cannot tell when the request came, so a
            // purged fate lets a body dropped for its bounds go. A body held when the request
            // and its kill are judged is its leftover (`kill_and_purge_in_one_commit_*`).
            let purged_after = matches!(f, Some(hm::Fate::Leftover(hm::LeftoverWhy::Purged))) && dropped_for == Some(osis_node::engine::DropFor::Other);
            let lets_go = matches!(f, Some(hm::Fate::MayDrop(_) | hm::Fate::MustDrop(_))) || purged_after;
            if !lets_go {
                let p = &back.commits.iter().find(|c| c.id == *label).unwrap().parts[*i];
                let mode = match p.retention.history {
                    hm::History::PurgeOnReplace => "purge on replace".to_string(),
                    hm::History::CONVENIENT => "convenient".to_string(),
                    hm::History::Keep { until: hm::FOREVER, .. } => "kept for good".to_string(),
                    hm::History::Keep { until: 0, .. } => "kept D after replaced".to_string(),
                    hm::History::Keep { .. } => "kept until T".to_string(),
                };
                let fate = match f {
                    Some(hm::Fate::Keep(hm::KeepWhy::Plain)) if ob.owed.contains(&(*label, *i)) => "owed a cover first".to_string(),
                    Some(hm::Fate::Keep(hm::KeepWhy::Plain)) => {
                        let c = back.commits.iter().find(|c| c.id == *label).unwrap();
                        let right = hm::timeline(&back).right(back.me, back.me, (u64::MAX, back.me, u32::MAX), u32::MAX, p.retention.by, c.actor, p.thing);
                        format!("Keep(Plain), replaced {}, node holds the right {right}", ob.replaced.contains(&(*label, *i)))
                    }
                    Some(f) => format!("{f:?}"),
                    None => "none".to_string(),
                };
                diffs.push((format!("dropped a body the model keeps: {mode}, model fate {fate}"), differ(format!("commit {id:?} (#{label}) on {t:?} {}: the node dropped its body ({why}), the model's fate for it is {f:?} (replaced {}, valid {:?} at the node {:?}; the node {:?} is model id {}, its roster of the thing {:?})", a.as_str(), ob.replaced.contains(&(*label, *i)), ob.valid.get(&(*label, *i)), e.body_valid(id, t, a), e.tid(), back.me, e.roster(t)), &[input.inside[&(*t, a.clone())].0])));
            }
        }
    }
    for (k, _) in &diffs {
        *cov.differs.entry(k.clone()).or_default() += 1;
    }
    if cov.survey {
        for (k, d) in &diffs {
            if let Some(d) = d {
                cov.examples.entry(k.clone()).or_insert_with(|| d.clone());
            }
        }
        return None;
    }
    diffs.into_iter().find(|(k, _)| engine_retention(k).is_none()).and_then(|(_, d)| d)
}

/// Differences that are today's engine retention (death-dated drops, own state)
/// against the model's history modes, by design until the retention step named replaces it
/// (issues/retention-modes.md): tallied for the survey, never reported. None is visible through
/// the API: which bodies a node holds purged on replace (no history promised, none exposed) and
/// state writes no held body carries change no read (the order harness compares reads with the
/// keep-everything node; the model's reads are still compared here).
fn engine_retention(kind: &str) -> Option<&'static str> {
    if kind == "holds a covered purge-on-replace body" || kind.starts_with("dropped a body the model keeps: purge on replace") {
        Some("step 2: purge on replace drops only as covered, no reader drops at the bound")
    } else if kind == "state holds writes no held body does" {
        Some("step 4: no own state")
    } else {
        None
    }
}

fn reach_n(cov: &mut Coverage, k: &'static str, n: usize) {
    *cov.reached.entry(k).or_default() += n as u64;
}

/// The node's applied role commits with a part on `t`: label-free, for a mismatch report.
fn role_commits(e: &mut Engine, t: &Tid) -> Vec<String> {
    let mut out = Vec::new();
    for id in e.commit_ids() {
        let Some(h) = e.header(&id) else { continue };
        if h.kind == Kind::Content || h.kind == Kind::ContentSnapshot || !h.aspects.iter().any(|a| a.tid == *t) {
            continue;
        }
        let parts: Vec<String> = h.aspects.iter().filter(|a| a.tid == *t).map(|a| format!("{} {:?}", a.ak.as_str(), e.body_fragment(&id, &a.tid, &a.ak).ok().flatten())).collect();
        out.push(format!("{id:?} {:?} by {:?} ts {:?} frontier {:?} {parts:?}", h.kind, h.author, h.ts, h.frontier));
    }
    out
}
