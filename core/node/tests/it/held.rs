//! held-model adapter (core/test/held-model, written from spec/ alone): what a node holds, as
//! the model's input, and the model's judgment compared with the node's (`compare`). The order
//! harness (`order.rs`, `Cfg::model`) runs it on every node it judges.
//!
//! Input: every commit the node holds (applied, and waiting with the parts its stored copy
//! holds), bodies as the node holds them (missing, dropped, held: a leftover's value-less owners
//! as `stripped`), and as own state the writes its state holds that no held body does. Ids,
//! dots and values are relabelled: commits ordered as their dots order (spec/crdt.md §2.2:
//! source kind, source bytes, then counter, a session's commits in `ts` order), values interned.
//!
//! Scope (held-model ASSUMPTIONS.md): aspects of a register, a map of registers or a text
//! (`IN`) on things a node owns; anything else is in the input as a placeholder (its parts keep
//! atomic apply, carry nothing) and is not compared. An in-scope aspect is not compared either
//! (`Coverage::skipped`, by reason) when a commit on it is outside the model (undo, acting for,
//! roster snapshots, paged, ephemeral), a held body or its state has another shape
//! (`Fragment::flat`), the node flags it suspect (spec/requirements.md Deterministic: a flip after
//! a drop), or a waiting commit on it waits for a reason the model has no notion of; a thing is
//! out when its roles are (a role commit editing anything but one holder's plain edge, a
//! self-removal, a removal with no frontier, a role commit waiting, `required.0^`).
//!
//! Compared on in-scope aspects: which commits applied, each content part's validity, reads, no
//! held body the model says must be gone (`MustDrop`) or counts as never received, no forbidden
//! value (expired or purged), and every body the node dropped, given back as the order harness's
//! keep-everything node holds it, one the model lets go (`MayDrop`, `MustDrop`; a leftover is a
//! held body, spec/crdt.md §4.7).
//!
//! Normalizations: a waiting commit's held parts carry no writes (the model only needs that they
//! are held); a part an applied commit misses counts as dropped (the model syncs everything, and
//! spec/commits.md §4 waits only for things synced when the commit came: whether the node applied
//! too early is not judged here, only too late); a leftover's value-less owners are taken as
//! stripped by the node, also for a value that arrived value-less; a thing's owner writing its
//! own edge is an edge write like another (the model's owner holds admin anyway).

use held_model as hm;
use osis_base::{Ak, CommitId, Tid, Value};
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

/// The node no role reaches: a thing out of scope is owned by it, a role part out of scope edits it.
const NOBODY: hm::NodeId = u32::MAX;

/// How many nodes and aspects were compared, and the aspects left out by reason.
#[derive(Clone, Debug, Default)]
pub(crate) struct Coverage {
    pub(crate) nodes: u64,
    pub(crate) compared: u64,
    pub(crate) skipped: BTreeMap<&'static str, u64>,
    /// Of the compared aspects: reads present; parts invalid, purged, dropped, held as leftovers;
    /// value-less deltas.
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
/// Why each aspect, and each thing, is out of scope.
type Out = (BTreeMap<(Tid, Ak), &'static str>, BTreeMap<Tid, &'static str>);

/// Every commit of a history, by ID: its header, and who made which dots (spec/crdt.md §2.4:
/// the header's dot form and counter range per aspect).
pub(crate) struct History {
    headers: BTreeMap<CommitId, Arc<Header>>,
    /// Commit labels, in dot order.
    labels: BTreeMap<CommitId, u32>,
    ranges: BTreeMap<(Source, Tid, Ak), Vec<Range>>,
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
        for (id, h) in &headers {
            for a in &h.aspects {
                ranges.entry((h.form.own_source(h.author, *id), a.tid, a.ak.clone())).or_default().push((a.lo, a.hi, *id));
            }
        }
        History { headers, labels, ranges }
    }
}

/// Labels and interned values of one conversion.
struct Conv<'h> {
    hist: &'h History,
    nodes: BTreeMap<Tid, hm::NodeId>,
    things: BTreeMap<Tid, hm::ThingId>,
    /// Commits outside the history (a frontier or a dot naming one), and unknown dot sources.
    extra: BTreeMap<String, u32>,
    vals: BTreeMap<String, hm::Val>,
    aspects: BTreeMap<String, u32>,
}

impl Conv<'_> {
    fn node(&mut self, t: &Tid) -> hm::NodeId {
        let n = self.nodes.len() as u32;
        *self.nodes.entry(*t).or_insert(n)
    }
    fn thing(&mut self, t: &Tid) -> hm::ThingId {
        let n = self.things.len() as u32 + 1;
        *self.things.entry(*t).or_insert(n)
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
    fn aspect(&mut self, ak: &Ak, inside: bool) -> hm::Aspect {
        if ak.as_str() == "roles.0" {
            return hm::Aspect::ROLES;
        }
        match IN.iter().position(|x| x.0 == ak.as_str()).filter(|_| inside) {
            Some(i) => hm::Aspect { name: i as u32 + 1, kind: IN[i].1, admin_only: false },
            None => {
                let n = self.aspects.len() as u32;
                hm::Aspect::reg(100 + *self.aspects.entry(ak.as_str().to_string()).or_insert(n))
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

/// A role commit's `roles.0` delta on thing `t` as one edge write: one holder with a plain edge
/// or none; the author's own edge only from the thing's owner (a self-removal is outside the
/// model). A reset of an entry whose creation `e` does not hold names no holder (spec/permissions.md
/// §2): a delta naming none is `None`.
fn edge_of(e: &Engine, f: &Fragment, author: &Tid, t: &Tid) -> Result<(Option<Tid>, Option<osis_base::Role>), &'static str> {
    let Fragment::Map(m) = f else { return Err("role delta shape") };
    let mut holder = None;
    let mut role = None;
    for (dot, _, key, frag) in m.entries() {
        let Some(Value::Tid(h)) = key else { return Err("role delta key") };
        let created = match dot.src.kind() {
            osis_crdt::SourceKind::Commit(c) => e.header(c).is_some(),
            _ => true,
        };
        if frag.is_none() && !created {
            continue;
        }
        if holder.is_some_and(|x| x != *h) {
            return Err("role delta on two holders");
        }
        holder = Some(*h);
        if let Some(v) = frag.and_then(Fragment::read) {
            let e = ct::Edge::from_value(&v).map_err(|_| "edge value")?;
            if e.until.is_some() || e.invite.is_some() || e.since.is_some() || e.tied.is_some() || e.keyset.is_some() {
                return Err("edge beyond a role");
            }
            role = Some(e.role);
        }
    }
    if holder == Some(*author) && e.owner(t) != Some(*author) {
        return Err("own edge");
    }
    Ok((holder, role))
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
}

/// The aspects of `e`'s commits and the reasons each is out of scope; the things out of scope.
fn scope(e: &mut Engine, hist: &History, held: &[(CommitId, Arc<Header>, bool)]) -> Out {
    let mut out: BTreeMap<(Tid, Ak), &'static str> = BTreeMap::new();
    let mut things: BTreeMap<Tid, &'static str> = BTreeMap::new();
    let nodes: BTreeSet<Tid> = hist.headers.values().map(|h| h.author).chain([e.tid()]).collect();
    let pending: BTreeMap<CommitId, osis_node::Reason> = e.pending().into_iter().collect();
    for (id, h, applied) in held {
        let commit_out = if h.undoes.is_some() {
            Some("undo")
        } else if h.actor != h.author {
            Some("acting for")
        } else if matches!(h.kind, Kind::RoleSnapshot | Kind::RosterSnapshot) {
            Some("roster snapshot")
        } else if !h.chunks.is_empty() {
            Some("paged")
        } else if h.ephemeral.is_some() {
            Some("ephemeral")
        } else if !applied && !matches!(pending.get(id), Some(osis_node::Reason::WaitDeltas | osis_node::Reason::Drift)) {
            Some("waits for a reason outside the model")
        } else if h.kind == Kind::Role && !applied {
            Some("role commit waiting")
        } else if h.frontier.as_ref().is_some_and(|f| ct::Frontier::from_value(f).is_err()) {
            Some("frontier not inline")
        } else {
            None
        };
        for a in &h.aspects {
            if let Some(why) = commit_out {
                out.entry((a.tid, a.ak.clone())).or_insert(why);
                if h.kind != Kind::Content && h.kind != Kind::ContentSnapshot {
                    things.entry(a.tid).or_insert(why);
                }
            }
            if a.ak.as_str() == "required.0^" {
                things.entry(a.tid).or_insert("required");
            }
            if h.kind == Kind::Role && a.ak.as_str() != "roles.0" {
                things.entry(a.tid).or_insert("role commit beyond roles.0");
            }
            if retention(&a.retention).is_err() {
                out.entry((a.tid, a.ak.clone())).or_insert("keep at most after replaced above 0");
            }
        }
        if h.kind == Kind::Role && *applied {
            for a in h.aspects.iter().filter(|a| a.ak.as_str() == "roles.0") {
                let f = e.body_fragment(id, &a.tid, &a.ak).unwrap();
                match f.as_ref().map(|f| edge_of(e, f, &h.author, &a.tid)) {
                    Some(Err(why)) => {
                        things.entry(a.tid).or_insert(why);
                    }
                    Some(Ok((_, None))) if h.frontier.is_none() => {
                        things.entry(a.tid).or_insert("removal with no frontier");
                    }
                    _ => {}
                }
            }
        }
    }
    for (t, a) in held.iter().flat_map(|x| x.1.aspects.iter().map(|a| (a.tid, a.ak.clone())).collect::<Vec<_>>()) {
        let owner = e.owner(&t);
        if !owner.is_some_and(|o| nodes.contains(&o)) {
            things.entry(t).or_insert("not owned by a node");
        }
        if !IN.iter().any(|x| x.0 == a.as_str()) {
            continue;
        }
        if let Some(why) = things.get(&t) {
            out.entry((t, a)).or_insert(why);
        }
    }
    for (t, a, _, _) in e.suspects().unwrap() {
        out.entry((t, a)).or_insert("suspect");
    }
    (out, things)
}

fn convert(e: &mut Engine, hist: &History) -> Input {
    let mut cv = Conv { hist, nodes: BTreeMap::new(), things: BTreeMap::new(), extra: BTreeMap::new(), vals: BTreeMap::new(), aspects: BTreeMap::new() };
    let applied: Vec<CommitId> = e.commit_ids();
    let mut held: Vec<(CommitId, Arc<Header>, bool)> = applied.iter().filter_map(|id| Some((*id, e.header(id)?, true))).collect();
    for (id, _) in e.pending() {
        if let Some(h) = hist.headers.get(&id) {
            held.push((id, h.clone(), false));
        }
    }
    let (mut skipped, out_things) = scope(e, hist, &held);
    let is_in = |skipped: &BTreeMap<(Tid, Ak), &'static str>, t: &Tid, a: &Ak| IN.iter().any(|x| x.0 == a.as_str()) && !skipped.contains_key(&(*t, a.clone()));
    // bodies first: a shape outside the model takes its aspect out before anything is built
    let mut bodies: BTreeMap<(CommitId, usize), Vec<hm::Write>> = BTreeMap::new();
    for (id, h, applied) in &held {
        if !applied || h.kind == Kind::Role {
            continue;
        }
        for (ai, a) in h.aspects.iter().enumerate() {
            if !is_in(&skipped, &a.tid, &a.ak) || !held_body(e, id, ai) {
                continue;
            }
            let kind = cv.aspect(&a.ak, true).kind;
            if let Some(f) = e.body_fragment(id, &a.tid, &a.ak).unwrap() {
                match cv.writes(&f, &a.tid, &a.ak, kind) {
                    Ok(ws) => {
                        bodies.insert((*id, ai), ws);
                    }
                    Err(why) => {
                        skipped.insert((a.tid, a.ak.clone()), why);
                    }
                }
            }
        }
    }
    let mut states: BTreeMap<(Tid, Ak), Vec<hm::Write>> = BTreeMap::new();
    for (t, a) in e.all_aspects().unwrap() {
        if !is_in(&skipped, &t, &a) {
            continue;
        }
        let kind = cv.aspect(&a, true).kind;
        if let Some(f) = e.state(&t, &a).unwrap() {
            match cv.writes(&f, &t, &a, kind) {
                Ok(ws) => {
                    states.insert((t, a), ws);
                }
                Err(why) => {
                    skipped.insert((t, a), why);
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
        let parked = if *applied { None } else { e.pending_parts(id).unwrap() };
        let mut parts = Vec::new();
        for (ai, a) in h.aspects.iter().enumerate() {
            let thing = cv.thing(&a.tid);
            let ok = is_in(&skipped, &a.tid, &a.ak) || (a.ak.as_str() == "roles.0" && !out_things.contains_key(&a.tid));
            let aspect = cv.aspect(&a.ak, ok);
            if ok && aspect != hm::Aspect::ROLES {
                inside.insert((a.tid, a.ak.clone()), (thing, aspect));
            }
            let retention = retention(&a.retention).unwrap_or(hm::Retention::PLAIN);
            let mut stripped = BTreeSet::new();
            let body = match &meta {
                Some(m) if m.missing.contains(&ai) => hm::Body::Dropped,
                Some(m) if m.dropped.contains_key(&ai) => {
                    if ok && h.kind != Kind::Role {
                        dropped.push((label, ai, *id, a.tid, a.ak.clone()));
                    }
                    hm::Body::Dropped
                }
                Some(_) if h.kind == Kind::Role => {
                    let f = e.body_fragment(id, &a.tid, &a.ak).unwrap();
                    let edge = match f.as_ref().map(|f| edge_of(e, f, &h.author, &a.tid)) {
                        Some(Ok((Some(holder), role))) if ok => hm::EdgeWrite { holder: cv.node(&holder), role: role.map(role_of) },
                        _ => hm::EdgeWrite { holder: NOBODY, role: None },
                    };
                    hm::Body::Held(hm::Delta::Edge(edge))
                }
                Some(m) => {
                    let ws = if ok { bodies.get(&(*id, ai)).cloned().unwrap_or_default() } else { Vec::new() };
                    if m.stripped.contains(&ai) {
                        stripped = valueless_owners(&ws);
                    }
                    hm::Body::Held(hm::Delta::Writes(ws))
                }
                None if parked.as_ref().is_some_and(|p| p.contains(&ai)) => {
                    if h.kind == Kind::Role {
                        hm::Body::Held(hm::Delta::Edge(hm::EdgeWrite { holder: NOBODY, role: None }))
                    } else {
                        hm::Body::Held(hm::Delta::Writes(Vec::new()))
                    }
                }
                None => hm::Body::Missing,
            };
            parts.push(hm::Part { thing, aspect, retention, body, stripped });
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
                let (t, a) = (*p.tid(), p.ak().clone());
                let ok = is_in(&skipped, &t, &a);
                let (thing, aspect) = (cv.thing(&t), cv.aspect(&a, ok));
                match p {
                    osis_commit::PurgeItem::Commit { commit, .. } => hm::PurgeItem::Commit { commit: cv.commit(commit), thing, aspect },
                    osis_commit::PurgeItem::Aspect { .. } => hm::PurgeItem::Aspect { thing, aspect },
                    osis_commit::PurgeItem::Author { actor, .. } => hm::PurgeItem::Author { thing, aspect, author: cv.node(actor) },
                }
            })
            .collect();
        commits.push(hm::Commit { id: label, author: cv.node(&h.author), ts: h.ts.to_u64(), expires: h.expires, kind, parts, purge, frontier });
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
    inside.retain(|k, _| !skipped.contains_key(k));
    let tids: Vec<Tid> = cv.things.keys().copied().collect();
    let things = tids
        .iter()
        .map(|t| {
            let owner = e.owner(t).filter(|_| !out_things.contains_key(t)).map_or(NOBODY, |o| cv.node(&o));
            hm::Thing { id: cv.thing(t), owner }
        })
        .collect();
    let me = cv.node(&e.tid());
    let held = hm::Held { now: e.now().0, me, things, commits, own_state };
    let skipped = skipped.into_iter().filter(|(k, _)| IN.iter().any(|x| x.0 == k.1.as_str())).collect();
    let mut input = Input { held, inside, skipped, commits: labels, vals: cv.vals, extra: cv.extra, dropped };
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
    // the model's input on the things `what` is about: now, things, their commits, own state
    let differ = |what: String, things: &[hm::ThingId]| {
        let h = &input.held;
        let mut s = format!("held-model differs: {what}\nmodel input (things {things:?}): now {}, me {}, things {:?}", h.now, h.me, h.things);
        for c in h.commits.iter().filter(|c| c.kind == hm::CommitKind::Role || c.parts.iter().any(|p| things.contains(&p.thing))) {
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
        let touches = c.parts.iter().any(|p| by_part.contains_key(&(p.thing, p.aspect)));
        if touches && o.applied.contains(&c.id) != applied {
            let h = &hist.headers[&id];
            let parts: Vec<String> = h.aspects.iter().map(|a| format!("{:?} {} syncs {} owner {:?}", a.tid, a.ak.as_str(), e.core.syncs(&a.tid), e.owner(&a.tid))).collect();
            let missing = e.core.ix.commits.get(&id).map(|m| m.missing.clone());
            return differ(format!("commit {id:?} (#{}) applied: model {}, node {applied}; parts {parts:?}, node misses {missing:?}", c.id, o.applied.contains(&c.id)), &c.parts.iter().map(|p| p.thing).collect::<Vec<_>>());
        }
        if !applied || c.kind == hm::CommitKind::Role {
            continue;
        }
        for (i, p) in c.parts.iter().enumerate() {
            let Some((t, a)) = by_part.get(&(p.thing, p.aspect)) else { continue };
            let node = e.body_valid(&id, t, a);
            let model = o.valid.get(&(c.id, i)).copied();
            if node != model {
                return differ(format!("validity of commit {id:?} (#{}) on {t:?} {}: model {model:?}, node {node:?}; node's roster {:?}, role commits {:?}", c.id, a.as_str(), e.roster(t), role_commits(e, t)), &[p.thing]);
            }
            if let Some(f) = o.fates.get(&(c.id, i))
                && matches!(f, hm::Fate::MustDrop(_) | hm::Fate::NeverReceived)
            {
                return differ(format!("commit {id:?} (#{}) on {t:?} {}: the node holds its body, the model's fate is {f:?}", c.id, a.as_str()), &[p.thing]);
            }
        }
    }
    if let Some(f) = o.forbidden.iter().find(|f| by_part.contains_key(&(f.1.1, f.1.2))) {
        return differ(format!("forbidden value held: {f:?}"), &[f.1.1]);
    }
    // reads: the node's read through the conversion's value table
    let mut cv = Conv { hist, nodes: BTreeMap::new(), things: BTreeMap::new(), extra: input.extra.clone(), vals: input.vals.clone(), aspects: BTreeMap::new() };
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
                return differ(format!("commit {id:?} (#{label}) on {t:?} {}: the node dropped its body, the model's fate for it is {f:?}", a.as_str()), &[input.inside[&(*t, a.clone())].0]);
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
