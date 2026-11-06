//! held-model adapter (core/test/held-model, written from spec/ alone): what a node holds, as
//! the model's input, and the model's judgment compared with the node's (`compare`). The order
//! harness (`order.rs`, `Cfg::model`) runs it on every node it judges.
//!
//! Input: every commit the node holds (applied, and waiting with the parts its stored copy
//! holds), bodies as the node holds them (missing, dropped, held: a leftover's value-less owners
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
//! outside the history), each content part's validity, reads, no held body the model says must be
//! gone (`MustDrop`; at keep at most only once the node has recomputed the aspect's deaths, which
//! it does at its next tick, before any read, and at a header's absolute bound only once its due
//! timer has run, at that tick, after any carrier) or counts as never received, no forbidden value
//! (expired or purged), and every body the node dropped, given back as the order harness's
//! keep-everything node holds it (a snapshot dropped while valid as `Held::dropped_valid`), one
//! the model lets go (`MayDrop`, `MustDrop`; a leftover is a held body, spec/crdt.md §4.7). The
//! order harness also compares after every ingest of its clocked deliveries, between ticks.
//!
//! Normalizations: a waiting commit's held parts carry no writes or edges (the model only needs
//! that they are held); a part an applied commit misses, or holds waiting alone (spec/commits.md
//! §4), is missing; a leftover's value-less owners are taken as stripped by the node, also for
//! a value that arrived value-less; an edge's `tied` and `keyset` are dropped (carried,
//! never an authority); a keep-at-most-0 snapshot body the node dropped with no live write
//! (`Dropped::live`) past a death is let go (liveness is judged at the drop, `compare`).

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
    /// The model dot of `d` on `(t, a)`: its owning commit by the header ranges.
    fn dot(&mut self, d: &osis_crdt::Dot, t: &Tid, a: &Ak) -> hm::Dot {
        let d = d.owner();
        let owner = match d.src.kind() {
            osis_crdt::SourceKind::Commit(c) => Some(*c),
            _ => self.hist.ranges.get(&(d.src.clone(), *t, a.clone())).and_then(|v| v.iter().find(|x| x.0 <= d.ctr && d.ctr < x.1)).map(|x| x.2),
        };
        let commit = match owner {
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
            let retention = retention(&q.retention()).map_err(|_| "required keep at most after replaced")?;
            out.push(hm::Rule { prefix, retention, expiry: q.expires });
        }
        Ok(out)
    }
}

fn retention(r: &osis_schema::Retention) -> Result<hm::Retention, &'static str> {
    use osis_base::PurgeBy as P;
    let by = match r.by {
        P::Nobody => hm::PurgeBy::Nobody,
        P::Admin => hm::PurgeBy::Admin,
        P::AuthorOrAdmin => hm::PurgeBy::AuthorOrAdmin,
        P::Writer => hm::PurgeBy::Writer,
        P::Author => hm::PurgeBy::Author,
    };
    if r.at_most.rel.is_some_and(|x| x > 0) {
        return Err("keep at most after replaced above 0");
    }
    let forever = |x: u64| if x == osis_commit::FOREVER { hm::FOREVER } else { x };
    Ok(hm::Retention { by, least_abs: r.at_least.abs.map(forever), least_rel: r.at_least.rel, most_abs: r.at_most.abs, most_zero: r.at_most.rel == Some(0) })
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
    /// Bodies the node dropped (not missing) on in-scope aspects: label, part, ID, thing, AK.
    dropped: Vec<(hm::CommitId, usize, CommitId, Tid, Ak)>,
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
fn scope(e: &mut Engine, held: &[(CommitId, Arc<Header>, bool)]) -> Scope {
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
        for a in &h.aspects {
            if retention(&a.retention).is_err() {
                s.aspects.entry((a.tid, a.ak.clone())).or_insert("keep at most after replaced above 0");
            }
        }
    }
    for (t, a, _, _) in e.suspects().unwrap() {
        s.aspects.entry((t, a)).or_insert("suspect");
    }
    s
}

fn convert(e: &mut Engine, hist: &History) -> Input {
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
    let mut sc = scope(e, &held);
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
    let mut gave = BTreeSet::new();
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
            let retention = retention(&a.retention).unwrap_or(hm::Retention::PLAIN);
            let part = |body| hm::Part { thing, aspect, retention, body, stripped: BTreeSet::new() };
            let state = match &meta {
                Some(m) if m.missing.contains(&ai) => Some(hm::Body::Missing),
                Some(m) if m.dropped.contains_key(&ai) => {
                    if ok {
                        dropped.push((label, parts.len(), *id, a.tid, a.ak.clone()));
                    }
                    if m.dropped[&ai].gave {
                        gave.insert((label, parts.len()));
                    }
                    Some(hm::Body::Dropped)
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
                        p.stripped = valueless_owners(&ws);
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
    // own state: what the state holds that no held body of an applied commit does
    let mut own_state = Vec::new();
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
        own_state.extend(ws.into_iter().filter(|w| !in_bodies.contains(&w.id())).map(|write| hm::StateWrite { thing, aspect, write }));
    }
    let me = cv.id(&e.tid());
    // every record the node holds of an id named, owners and first admins naming more
    let mut things = Vec::new();
    let mut done = BTreeSet::new();
    loop {
        let todo: Vec<Tid> = cv.ids.keys().filter(|t| !done.contains(*t)).copied().collect();
        if todo.is_empty() {
            break;
        }
        for t in todo {
            done.insert(t);
            let owner = match e.core.created(&t) {
                None => continue,
                Some(CreationRecord::KeyActor { .. }) => hm::Owner::Key,
                Some(CreationRecord::Thing { admin, .. }) => hm::Owner::Admin(cv.id(admin)),
            };
            things.push(hm::Thing { id: cv.id(&t), owner });
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
    let held = hm::Held { now: e.now().0, me, things, commits, own_state, dropped_valid: gave };
    let ids = cv.ids.iter().map(|(t, i)| (*i, *t)).collect();
    let mut input = Input { held, inside, skipped, commits: labels, vals: cv.vals, extra: cv.extra, dropped, ids };
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

/// Value-less owners of a held body: taken as what the node stripped (`Part::stripped`).
fn valueless_owners(ws: &[hm::Write]) -> BTreeSet<hm::CommitId> {
    ws.iter().flat_map(|w| w.values()).filter(|x| x.1.is_none()).map(|x| x.0).collect()
}

pub(crate) fn compare(e: &mut Engine, hist: &History, kept: &Bodies, cov: &mut Coverage) -> Option<String> {
    let input = convert(e, hist);
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
    reach("dropped", parts().filter(|(_, p)| p.body == hm::Body::Dropped).count());
    reach("leftover", parts().filter(|(_, p)| !p.stripped.is_empty()).count());
    reach("value-less", o.valueless.iter().filter(|d| inside.contains(&(d.1, d.2))).count());
    reach("own state", input.held.own_state.iter().filter(|w| inside.contains(&(w.thing, w.aspect))).count());
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
        for w in h.own_state.iter().filter(|w| things.contains(&w.thing)) {
            s.push_str(&format!("\n  own state {w:?}"));
        }
        Some(s)
    };
    let by_part: BTreeMap<(hm::ThingId, hm::Aspect), (Tid, Ak)> = input.inside.iter().map(|(k, v)| (*v, k.clone())).collect();
    for c in &input.held.commits {
        let (id, applied) = input.commits[&c.id];
        let touches = c.parts.iter().any(|p| by_part.contains_key(&(p.thing, p.aspect))) || (c.is_role() && !by_part.is_empty());
        // the node's own commits from outside the history (its creation, carriers) are its own
        // writes, never received: the order harness may set its clock back before them (no drift)
        let own = !hist.headers.contains_key(&id);
        if touches && !own && o.applied.contains(&c.id) != applied {
            let h = &hist.headers[&id];
            let parts: Vec<String> = h.aspects.iter().map(|a| format!("{:?} {} syncs {} owner {:?}", a.tid, a.ak.as_str(), e.core.syncs(&a.tid), e.first_admin(&a.tid))).collect();
            let missing = e.core.ix.commits.get(&id).map(|m| m.missing.clone());
            return differ(format!("commit {id:?} (#{}) applied: model {}, node {applied}; parts {parts:?}, node misses {missing:?}", c.id, o.applied.contains(&c.id)), &c.parts.iter().map(|p| p.thing).collect::<Vec<_>>());
        }
        if !applied || c.is_role() {
            continue;
        }
        for (i, p) in c.parts.iter().enumerate() {
            let Some((t, a)) = by_part.get(&(p.thing, p.aspect)) else { continue };
            let node = e.body_valid(&id, t, a);
            let model = o.valid.get(&(c.id, i)).copied();
            if node != model {
                return differ(format!("validity of commit {id:?} (#{}) on {t:?} {}: model {model:?}, node {node:?}; node's roster {:?}, role commits {:?}", c.id, a.as_str(), e.roster(t), role_commits(e, t)), &[p.thing]);
            }
            // deaths the node has yet to recompute (at its next tick, before any read) are not
            // learned: a bound they pass is not yet one it knows (spec/commits.md §5)
            // a header's absolute bound (T, or the purge floor over it) drops by the node's next
            // tick, even one past at the apply, so that a carrier can go first (spec/commits.md
            // §5: "drops a body applied at or past it only after its apply"); deathless parts
            // have no model bound but that one
            let hb = hist.headers[&id].aspects.iter().find(|x| x.tid == *t && x.ak == *a).filter(|x| x.retention.at_most.abs.is_some()).and_then(|x| osis_commit::retention::body_keep(&hist.headers[&id], &x.retention, None, None).at_most);
            let at_header = hb.is_some() && o.at_most.get(&(c.id, i)).copied().or(hb) == hb && e.timers_due();
            // a body with a live write goes by its timer, due at once, after a carrier
            let by_timer = |f: &hm::Fate| matches!(f, hm::Fate::MustDrop(hm::DropWhy::AtMost { carrier: true })) && e.timers_due();
            let unlearned = |f: &hm::Fate| matches!(f, hm::Fate::MustDrop(hm::DropWhy::AtMost { .. })) && (at_header || by_timer(f) || e.core.ix.deaths_due.contains(&(*t, a.clone())));
            if let Some(f) = o.fates.get(&(c.id, i))
                && matches!(f, hm::Fate::MustDrop(_) | hm::Fate::NeverReceived)
                && !unlearned(f)
            {
                return differ(format!("commit {id:?} (#{}) on {t:?} {}: the node holds its body, the model's fate is {f:?}", c.id, a.as_str()), &[p.thing]);
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
                    return differ(format!("role commit {id:?} (#{}) on {t:?} applies: model {model}, node {node}; node's roster {:?}", c.id, e.roster(&t)), &[th]);
                }
            }
        }
    }
    if let Some(f) = o.forbidden.iter().find(|f| by_part.contains_key(&(f.1.1, f.1.2))) {
        return differ(format!("forbidden value held: {f:?}"), &[f.1.1]);
    }
    // reads: the node's read through the conversion's value table
    let mut cv = Conv { hist, ids: BTreeMap::new(), extra: input.extra.clone(), vals: input.vals.clone(), aspects: BTreeMap::new() };
    for ((t, a), (thing, aspect)) in &input.inside {
        let model = o.reads.get(&(*thing, *aspect)).cloned().unwrap_or(hm::Read::Absent);
        let v = e.get(t, a).unwrap();
        let node = cv.read(v.as_ref(), aspect.kind);
        if node != model {
            return differ(format!("{t:?} {} reads {v:?} ({node:?}) at the node, {model:?} in the model (state {:?})", a.as_str(), o.states.get(&(*thing, *aspect))), &[*thing]);
        }
    }
    // the bodies the node dropped, given back as a node keeping every body holds them: the model
    // lets each go (a purged or expired delta's own body is held as its leftover, spec/crdt.md §4.7)
    let mut back = input.held.clone();
    let mut given = Vec::new();
    for (label, i, id, t, a) in &input.dropped {
        let Some(f) = kept.get(&(*id, *t, a.clone())) else { continue };
        let Some(c) = back.commits.iter_mut().find(|c| c.id == *label) else { continue };
        let kind = c.parts[*i].aspect.kind;
        let Ok(ws) = cv.writes(f, t, a, kind) else { continue };
        c.parts[*i].stripped = valueless_owners(&ws);
        c.parts[*i].body = hm::Body::Held(hm::Delta::Writes(ws));
        given.push((*label, *i, *id, *t, a.clone()));
    }
    reach_n(cov, "dropped judged", given.len());
    if !given.is_empty() {
        let ob = hm::evaluate(&back);
        for (label, i, id, t, a) in &given {
            let f = ob.fates.get(&(*label, *i));
            let lets_go = matches!(f, Some(hm::Fate::MayDrop(_) | hm::Fate::MustDrop(_)));
            if !lets_go {
                let bound = ob.at_most.get(&(*label, *i));
                let why = e.core.ix.commits.get(id).and_then(|m| m.dropped.get(i)).map(|d| (d.why, d.covered_by.clone(), d.live));
                return differ(format!("commit {id:?} (#{label}) on {t:?} {}: the node dropped its body ({why:?}), the model's fate for it is {f:?} (keep-at-most bound {bound:?}, deaths {:?}, valid {:?} at the node {:?})", a.as_str(), ob.deaths.get(&(*label, *i)), ob.valid.get(&(*label, *i)), e.body_valid(id, t, a)), &[input.inside[&(*t, a.clone())].0]);
            }
        }
    }
    None
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
