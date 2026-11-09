//! held-model adapter (core/test/held-model, written from spec/ alone): what a node holds, as
//! the model's input, and the model's judgment compared with the node's (`compare`). The order
//! harness (`order.rs`, `Cfg::model`) runs it on every node it judges.
//!
//! Input: every commit the node holds (applied, and waiting with the parts its stored copy
//! holds), bodies as the node holds them (missing, dropped, held: a leftover's value-less carriers
//! as `stripped`), and every creation record it holds of an actor or thing the input names.
//! Commits and ids are relabelled (commits ordered as their dots order, spec/crdt.md §2.2: source
//! kind, source bytes, then counter, a session's commits in `ts` order). Bodies and states are
//! crdt-model fragments decoded from the engine's wire bytes (`frag`), with every header's dot
//! form and counter ranges as `Held::dots`; reads are compared as values by their canonical
//! bytes. Applied role commits are given as the node's role input holds them (`ix.held`), one
//! model part per edge write; `required^.0` as its rules; `addenda.0` as its entries; undo,
//! acting and purge actors as headers name them.
//!
//! Scope (held-model ASSUMPTIONS.md): every content aspect (`core_types::is_content`), of every
//! encoding, and every known thing's roster; the others count through the validity and edges they
//! decide (`keys.0`, `secrets.0`, `label.0`: outside the model; `created.0`: its input;
//! `required^.0`, `addenda.0`: fed as rules and entries, issues/held-model-setting-reads.md). A content aspect is not compared
//! (`Coverage::skipped`, by reason) when a commit on it is outside the model (paged, ephemeral,
//! waiting for blobs or parked). No aspect is compared when the role input is
//! outside the model (`Scope::roles`: a role-class compaction snapshot, a role frontier not
//! inline, a role commit outside the model as above): actors make every thing's roles depend on
//! others'. A role commit's parts off `roles.0` change no role and are placeholders.
//!
//! Compared on in-scope aspects, what a user observes (and the purge promises): which commits applied (role commits
//! too, not the node's own from outside the history), each content part's validity, which edge
//! writes apply, every known thing's roster (`roles.0` as read), reads, no forbidden value held (expired or purged), no held purge-on-replace body
//! a right holder's held snapshot covers (the option's promise: the content is gone), and promised
//! history: every body the node dropped whose keep-at-least bound is an absolute time still ahead (kept until T,
//! or for good), given back as the order harness's keep-everything node holds it, one the model
//! lets go. Which other bodies a node holds, and when it dates a death, are its own. Every
//! difference is tallied by kind (`Coverage::differs`); the first is reported. The order harness also
//! compares after every ingest of its clocked deliveries, between ticks.
//!
//! Retention is fed as the model's history mode (`retention`): purge on replace is `PurgeOnReplace`, kept
//! is keep-at-least (an absolute T and/or D after replaced), no history convenient. A body the
//! node dropped other than as covered (a part missing when purged) is fed as missing; one
//! dropped as covered as `Body::Dropped(cover)`.
//!
//! Normalizations: a waiting commit's held parts carry no writes or edges (the model only needs
//! that they are held); a part an applied commit misses, or holds waiting alone (spec/commits.md
//! §4), is missing; a leftover's value-less carriers are taken as stripped by the node, also for
//! a value that arrived value-less; an edge's `tied` and `keyset` are dropped (carried,
//! never an authority).

use held_model as hm;
use osis_base::{Ak, CommitId, CreationRecord, Tid, Value};
use osis_commit::{CommitBlob, Form, Header, Kind};
use osis_crdt::{Fragment, Source};
use osis_node::Engine;
use osis_node::local_peer::Package;
use osis_schema::Codec;
use osis_schema::core_types as ct;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

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
    /// feature (undo, acting, `required^.0`, addenda, invites, `until`, self-removals).
    pub(crate) reached: BTreeMap<&'static str, u64>,
    /// Every difference found, by kind (`compare` reports the first).
    pub(crate) differs: BTreeMap<String, u64>,
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
    }
}

/// Every commit of a history, by ID: its header (spec/crdt.md §2.4: its dot form and counter
/// range per aspect say who made which dots).
pub(crate) struct History {
    headers: BTreeMap<CommitId, Arc<Header>>,
    /// Commit labels, in dot order.
    labels: BTreeMap<CommitId, u32>,
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
        let aks = headers.values().flat_map(|h| h.aspects.iter().map(|a| a.ak.as_str().to_string())).collect();
        History { headers, labels, aks }
    }
}

/// A dot source as crdt-model has it (its wire bytes).
fn source(s: &Source) -> hm::Source {
    match s.kind() {
        osis_crdt::SourceKind::Session(x) => hm::Source::Session(x.to_bytes()),
        osis_crdt::SourceKind::Commit(c) => hm::Source::Commit(c.0),
        osis_crdt::SourceKind::Derived(d) => hm::Source::Derived(Box::new(hm::Dot { source: source(&d.src), ctr: d.ctr })),
    }
}

/// A fragment as crdt-model decodes its wire bytes: encoded as a snapshot delta under a source and
/// `ts` nothing else has, so every write is carried under its own stamp (spec/crdt.md §8).
fn frag(f: &Fragment) -> Result<hm::Frag, String> {
    let ts = ((1u64 << 47) - 1) << 16;
    let own = crdt_model::stamp::Source::session(250, 0);
    let crdt_model::stamp::Source::Session(own_bytes) = &own else { unreachable!() };
    let cx = osis_crdt::DeltaCtx { ts: osis_base::Ts::from_u64(ts).unwrap(), own: Source::session(osis_crdt::Session::from_bytes(own_bytes)), range: osis_crdt::CounterRange::EMPTY, kind: osis_crdt::DeltaKind::Snapshot };
    let snap = osis_crdt::Snapshot { nonce: [0; 16], fragment: f.clone(), frontiers: Default::default(), absorbed: Default::default() };
    let bytes = osis_crdt::encode_snapshot(&snap, &cx, None).map_err(|e| format!("encode: {e:?}"))?;
    crdt_model::wire::decode_snapshot(&bytes, &mut crdt_model::wire::Ctx::new(ts, own, 1)).map(|x| x.0).map_err(|e| format!("crdt-model decode: {e:?}"))
}

/// A value as crdt-model has it (its canonical bytes).
fn value(v: &Value) -> hm::Value {
    let it = crdt_model::cbor::decode(&osis_base::encode(v)).expect("canonical bytes decode");
    hm::Value::from_item(&it).expect("a value")
}

/// The name of an encoding (spec/crdt.md §3.1), for the coverage tally.
fn enc_name(e: u8) -> &'static str {
    ["register", "counter", "max", "min", "struct", "enum", "set", "map", "list", "text", "slots"].get(e as usize).copied().unwrap_or("?")
}

/// Every encoding in `f` at any depth.
fn encodings(f: &hm::Frag, out: &mut BTreeSet<u8>) {
    use crdt_model::state::{Content, Frag as F};
    if !matches!(f, F::Slots { .. }) {
        out.insert(f.enc());
    }
    match f {
        F::Register { .. } => {}
        F::Slots { .. } => f.slots().into_iter().for_each(|x| encodings(x, out)),
        F::Bag { elems, .. } | F::Set { elems, .. } => elems.values().filter_map(|e| e.frag.as_deref()).for_each(|x| encodings(x, out)),
        F::Struct { fields, .. } | F::Enum { payloads: fields, .. } => fields.values().for_each(|x| encodings(x, out)),
        F::Map { entries, .. } => entries.values().filter_map(|e| e.frag.as_deref()).for_each(|x| encodings(x, out)),
        F::Seq { elems, .. } => elems.values().for_each(|e| if let Content::Frag(x) = &e.content { encodings(x, out) }),
    }
}

/// Removal shapes of a state, for the coverage tally (`order::Seen::floors` asks each of every
/// emphasis): a list element's reset, a write in a list element above its reset (hidden, §5.7),
/// a winning text undelete, a set element its own reset emptied.
pub(crate) const REMOVALS: [&str; 4] = ["list element reset", "list write above its reset", "text undelete", "set value removed"];

/// The `REMOVALS` shapes in `f` at any depth.
fn removals(f: &hm::Frag, out: &mut BTreeSet<&'static str>) {
    use crdt_model::state::{Content, Frag as F};
    match f {
        F::Register { .. } => {}
        F::Slots { .. } => f.slots().into_iter().for_each(|x| removals(x, out)),
        F::Bag { elems, .. } | F::Set { elems, .. } => {
            for el in elems.values() {
                if matches!(f, F::Set { .. }) && el.reset.is_some() && el.frag.is_none() {
                    out.insert(REMOVALS[3]);
                }
                if let Some(x) = &el.frag {
                    removals(x, out);
                }
            }
        }
        F::Struct { fields, .. } | F::Enum { payloads: fields, .. } => fields.values().for_each(|x| removals(x, out)),
        F::Map { entries, .. } => entries.values().filter_map(|e| e.frag.as_deref()).for_each(|x| removals(x, out)),
        F::Seq { text, elems, .. } => {
            for el in elems.values() {
                match (&el.deleted, *text) {
                    (Some((_, false)), true) if el.created.is_some() => {
                        out.insert(REMOVALS[2]);
                    }
                    (Some((r, _)), false) => {
                        out.insert(REMOVALS[0]);
                        if let Content::Frag(x) = &el.content
                            && crdt_model::writes::writes(x).iter().any(|(n, _)| crdt_model::death::stamp(n) > r)
                        {
                            out.insert(REMOVALS[1]);
                        }
                    }
                    _ => {}
                }
                if let Content::Frag(x) = &el.content {
                    removals(x, out);
                }
            }
        }
    }
}

/// Labels of one conversion.
struct Conv<'h> {
    hist: &'h History,
    /// Actors and things: one id space.
    ids: BTreeMap<Tid, hm::NodeId>,
    /// Commits outside the history (a frontier naming one).
    extra: BTreeMap<String, u32>,
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
    /// The model aspect of an AK: one name per AK.
    fn aspect(&mut self, ak: &str) -> hm::Aspect {
        match ak {
            "roles.0" => return hm::Aspect::ROLES,
            "required^.0" => return hm::Aspect::REQUIRED,
            "created.0" => return hm::Aspect::CREATED,
            ct::ADDENDA_AK => return hm::Aspect::ADDENDA,
            osis_commit::retention::PURGE => return hm::Aspect::plain(9),
            _ => {}
        }
        let n = self.aspects.len() as u32;
        let name = 100 + *self.aspects.entry(ak.to_string()).or_insert(n);
        let m = Ak::markers_of(ak);
        hm::Aspect { name, admin_only: m.admin_only, signal: m.signal }
    }
    /// Every header's dot form and counter range per aspect (spec/crdt.md §2.4).
    fn dots(&mut self) -> Vec<hm::DotRange> {
        let mut out = Vec::new();
        for (id, h) in &self.hist.headers {
            let src = source(&h.form.own_source(h.author, *id));
            let commit = self.commit(id);
            for a in &h.aspects {
                let (thing, aspect) = (self.id(&a.tid), self.aspect(a.ak.as_str()));
                out.push(hm::DotRange { source: src.clone(), thing, aspect, lo: a.lo, hi: a.hi, commit });
            }
        }
        out
    }
    /// A role edge write (`tied`, `keyset` dropped: carried, never an authority).
    fn edge(&mut self, holder: &Tid, e: Option<&osis_perm::Edge>) -> hm::EdgeWrite {
        hm::EdgeWrite { holder: self.id(holder), role: e.map(|e| role_of(e.role)), invite: e.and_then(|e| e.invite).map(role_of), until: e.and_then(|e| e.until).map(|u| u.0) }
    }
    /// An `addenda.0` body as its entries: per removal (a 32-byte commit ID key), the commits its
    /// `frontier` lists.
    fn addenda(&mut self, f: Option<&Fragment>) -> Vec<(hm::CommitId, Vec<hm::CommitId>)> {
        let Some(Value::Map(m)) = f.and_then(Fragment::read) else { return Vec::new() };
        let frontier = osis_schema::Type::Named("frontier".into(), Vec::new());
        m.iter()
            .filter_map(|(k, v)| {
                let Value::Bytes(r) = k else { return None };
                let r = CommitId(<[u8; 32]>::try_from(r.as_slice()).ok()?);
                let f = ct::Frontier::from_value(&osis_schema::typed_read(osis_schema::core_schema(), v, &frontier).ok()?).ok()?;
                Some((self.commit(&r), f.commits.iter().map(|c| self.commit(c)).collect()))
            })
            .collect()
    }
    /// A `required^.0` setting as rules, or why the model cannot say it: an AK the history has is
    /// its aspect name, any other a name nothing has; the default is the model's default.
    fn rules(&mut self, f: Option<&Fragment>) -> Result<Vec<hm::Rule>, &'static str> {
        let Some(v) = f.and_then(Fragment::read) else { return Ok(Vec::new()) };
        let rules = ct::required_rules(&v);
        if rules.retain {
            return Err("required retain");
        }
        let rule = |aspect, q: &ct::Required| hm::Rule { aspect, retention: retention(&q.retention().canonical()), expiry: q.expires };
        let mut out: Vec<hm::Rule> = rules.default.iter().map(|q| rule(None, q)).collect();
        for (a, q) in &rules.rules {
            let name = if self.hist.aks.contains(a.as_str()) { self.aspect(a.as_str()).name } else { 99 };
            out.push(rule(Some(name), q));
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
    /// Bodies the node dropped (not missing) on in-scope aspects: label, part, ID, thing, AK,
    /// and why (`DropFor`, with its coverers).
    dropped: Vec<(hm::CommitId, usize, CommitId, Tid, Ak, String)>,
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
        } else if !applied && !matches!(pending.get(id), Some(R::Drift)) {
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
    }
    s
}

fn convert(e: &mut Engine, hist: &History) -> Input {
    // authors take ids in tid order: keys `(ts, author, commit)` order alike (spec/permissions.md §5.1)
    let authors: BTreeSet<Tid> = hist.headers.values().map(|h| h.author).chain([e.tid()]).collect();
    let ids = authors.into_iter().enumerate().map(|(i, t)| (t, i as u32)).collect();
    let mut cv = Conv { hist, ids, extra: BTreeMap::new(), aspects: BTreeMap::new() };
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
    // the node's own writes from outside the history (its creation, its node info): never
    // received, so never parked, where the harness sets its clock back before them
    for (_, h, _) in held.iter().filter(|(id, _, _)| !hist.headers.contains_key(id)) {
        for a in &h.aspects {
            sc.aspects.entry((a.tid, a.ak.clone())).or_insert("the node's own writes from outside the history");
        }
    }
    let is_in = |sc: &Scope, t: &Tid, a: &Ak| sc.out(t, a).is_none();
    // `required^.0` settings first: one the model cannot say takes its thing out
    let mut required: BTreeMap<(CommitId, usize), Vec<hm::Rule>> = BTreeMap::new();
    for (id, h, applied) in &held {
        for (ai, a) in h.aspects.iter().enumerate().filter(|(_, a)| a.ak.as_str() == "required^.0") {
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
    // content and snapshot bodies as crdt-model fragments, by their wire bytes
    let mut bodies: BTreeMap<(CommitId, usize), hm::Frag> = BTreeMap::new();
    for (id, h, applied) in &held {
        if !applied || h.kind.is_role() {
            continue;
        }
        for (ai, a) in h.aspects.iter().enumerate() {
            if !is_in(&sc, &a.tid, &a.ak) || !held_body(e, id, ai) {
                continue;
            }
            if let Some(f) = e.body_fragment(id, &a.tid, &a.ak).unwrap() {
                bodies.insert((*id, ai), frag(&f).unwrap_or_else(|why| panic!("body of {id:?} on {:?} {}: {why}", a.tid, a.ak.as_str())));
            }
        }
    }
    let mut commits = Vec::new();
    let mut dropped = Vec::new();
    let mut labels = BTreeMap::new();
    let mut inside = BTreeMap::new();
    // held leftovers: their value-less carriers are taken as stripped once the input is whole
    let mut leftovers = Vec::new();
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
            if ok && ct::is_content(a.ak.as_str()) {
                inside.insert((a.tid, a.ak.clone()), (thing, aspect));
            }
            let retention = retention(&a.retention);
            let part = |body| hm::Part { thing, aspect, retention, body, stripped: BTreeSet::new(), replaces: None };
            let state = match &meta {
                Some(m) if m.missing.contains(&ai) => Some(hm::Body::Missing),
                Some(m) if m.dropped.contains_key(&ai) => {
                    let d = &m.dropped[&ai];
                    // one dropped other than as covered or invalid was missing when it expired
                    // or was purged: never received, nothing to give back
                    if ok && d.why != osis_node::engine::DropFor::Other {
                        dropped.push((label, parts.len(), *id, a.tid, a.ak.clone(), format!("{:?} covered by {:?}", d.why, d.covered_by)));
                    }
                    // dropped as covered: by its first coverer in the history; for its bounds:
                    // the model has no such drop, the body is fed as never received
                    let cover = (d.why == osis_node::engine::DropFor::Cover).then(|| d.covered_by.iter().find(|c| hist.headers.contains_key(c)).map(|c| cv.commit(c))).flatten();
                    Some(cover.map_or(hm::Body::Missing, hm::Body::Dropped))
                }
                Some(_) => None,
                None if aspect == hm::Aspect::CREATED && waiting.as_ref().is_some_and(|p| p.contains(&ai)) => Some(created(e, &mut cv, id, &a.tid)),
                None if waiting.as_ref().is_some_and(|p| p.contains(&ai)) => {
                    // a waiting part: held, its content unread
                    Some(hm::Body::Held(match h.kind {
                        Kind::Role => hm::Delta::Edge(hm::EdgeWrite::role(NOBODY, None)),
                        _ if aspect == hm::Aspect::REQUIRED => hm::Delta::Required(Vec::new()),
                        _ => hm::Delta::Writes(hm::Frag::empty(0)),
                    }))
                }
                None => Some(hm::Body::Missing),
            };
            if let Some(body) = state {
                parts.push(part(body));
                continue;
            }
            match h.kind {
                _ if aspect == hm::Aspect::CREATED => parts.push(part(created(e, &mut cv, id, &a.tid))),
                // a role commit's parts off `roles.0` (`keys.0`, `secrets.0`, `label.0`) change no
                // role: placeholders
                Kind::Role if a.ak.as_str() != "roles.0" => parts.push(part(hm::Body::Held(hm::Delta::Writes(hm::Frag::empty(0))))),
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
                // a stripped addendum lists nothing (spec/permissions.md §5.2 Addenda)
                _ if aspect == hm::Aspect::ADDENDA => {
                    let es = if meta.as_ref().is_some_and(|m| m.stripped.contains(&ai)) { Vec::new() } else { cv.addenda(e.body_fragment(id, &a.tid, &a.ak).unwrap().as_ref()) };
                    parts.push(part(hm::Body::Held(hm::Delta::Addenda(es))));
                }
                _ => {
                    let f = if ok { bodies.remove(&(*id, ai)).unwrap_or_else(|| hm::Frag::empty(0)) } else { hm::Frag::empty(0) };
                    if meta.as_ref().is_some_and(|m| m.stripped.contains(&ai)) {
                        leftovers.push((label, parts.len()));
                    }
                    parts.push(part(hm::Body::Held(hm::Delta::Writes(f))));
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
        commits.push(hm::Commit { id: label, author, actor, ts: h.ts.to_u64(), expires: h.expires, kind, parts, purge, frontier, undoes, boxes: vec![] });
    }
    let me = cv.id(&e.tid());
    // every record the node holds of an id named, first admins naming more
    let mut records = Vec::new();
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
            records.push(hm::Record { id: cv.id(&t), link });
        }
    }
    inside.retain(|k, _| sc.out(&k.0, &k.1).is_none());
    let mut skipped: BTreeMap<(Tid, Ak), &'static str> = BTreeMap::new();
    for (_, h, _) in &held {
        for a in h.aspects.iter().filter(|a| ct::is_content(a.ak.as_str())) {
            if let Some(why) = sc.out(&a.tid, &a.ak) {
                skipped.insert((a.tid, a.ak.clone()), why);
            }
        }
    }
    let dots = cv.dots();
    let mut held = hm::Held { now: e.now().0, me, records, commits, dots };
    let ds = hm::Dots::new(&held);
    for (label, i) in leftovers {
        let c = held.commits.iter_mut().find(|c| c.id == label).unwrap();
        let p = &mut c.parts[i];
        if let hm::Body::Held(hm::Delta::Writes(f)) = &p.body {
            p.stripped = ds.valueless(p.thing, p.aspect, f);
        }
    }
    held.commits.sort_by_key(|c| c.id);
    let ids = cv.ids.iter().map(|(t, i)| (*i, *t)).collect();
    Input { held, inside, skipped, commits: labels, dropped, ids }
}

/// A creation part of commit `c` as the record it mints, when the node holds it.
fn created(e: &mut Engine, cv: &mut Conv, c: &CommitId, t: &Tid) -> hm::Body {
    let _ = c;
    match e.core.created(t).cloned() {
        None => hm::Body::Missing,
        Some(CreationRecord::KeyActor { .. }) => hm::Body::Held(hm::Delta::Created(hm::RecordLink::Key)),
        Some(CreationRecord::Thing { admin, .. }) => hm::Body::Held(hm::Delta::Created(hm::RecordLink::Admin(cv.id(&admin)))),
    }
}

fn role_of(r: osis_base::Role) -> hm::Role {
    match r {
        osis_base::Role::Read => hm::Role::Read,
        osis_base::Role::Write => hm::Role::Write,
        osis_base::Role::Admin => hm::Role::Admin,
    }
}

/// Every body a node holds, as held.
pub(crate) type Bodies = BTreeMap<(CommitId, Tid, Ak), Fragment>;

/// `Bodies` of a node keeping every body (`Engine::keep_bodies`): what a node dropped, to judge.
pub(crate) fn bodies(e: &mut Engine) -> Bodies {
    let mut out = Bodies::new();
    for id in e.commit_ids() {
        let Some(h) = e.header(&id) else { continue };
        for a in &h.aspects {
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

/// Converts what `e` holds, runs the model and compares (see the module doc); the first
/// difference, with the model's answer and the node's.
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
    reach("read present", inside.iter().filter(|k| o.reads.get(k).is_some_and(|r| r.is_some())).count());
    // the compared aspects by each encoding their state holds at any depth
    for k in &inside {
        let (mut es, mut rs) = (BTreeSet::new(), BTreeSet::new());
        if let Some(st) = o.states.get(k).filter(|st| !st.is_empty()) {
            encodings(st, &mut es);
            removals(st, &mut rs);
        }
        for e in es {
            *cov.reached.entry(enc_name(e)).or_default() += 1;
        }
        for r in rs {
            *cov.reached.entry(r).or_default() += 1;
        }
    }
    let mut reach = |k: &'static str, n: usize| *cov.reached.entry(k).or_default() += n as u64;
    let parts = || input.held.commits.iter().flat_map(|c| c.parts.iter().enumerate().map(move |(i, p)| ((c.id, i), p))).filter(|(_, p)| inside.contains(&(p.thing, p.aspect)));
    reach("invalid", parts().filter(|(k, _)| o.valid.get(k) == Some(&false)).count());
    reach("purged", parts().filter(|(k, _)| o.purged.contains_key(k)).count());
    reach("dropped", parts().filter(|(_, p)| matches!(p.body, hm::Body::Dropped(_))).count());
    reach("leftover", parts().filter(|(_, p)| !p.stripped.is_empty()).count());
    reach("value-less", o.valueless.iter().filter(|d| inside.contains(&(d.1, d.2))).count());
    reach("signal parts", parts().filter(|(_, p)| p.aspect.signal).count());
    // replaced bodies (held or dropped) whose absolute keep-at-least is still ahead: a node must
    // keep them however a snapshot covers them
    reach("covered kept until T", parts().filter(|(k, p)| o.replaced.contains(k) && matches!(p.retention.history, hm::History::Keep { until, .. } if until > input.held.now)).count());
    if !inside.is_empty() {
        let cs = &input.held.commits;
        let edges = || cs.iter().filter(|c| c.kind == hm::CommitKind::Role).flat_map(|c| c.parts.iter().map(move |p| (c, p))).filter_map(|(c, p)| match &p.body {
            hm::Body::Held(hm::Delta::Edge(e)) => Some((c, e)),
            _ => None,
        });
        reach("undo commits", cs.iter().filter(|c| c.undoes.is_some()).count());
        reach("acting commits", cs.iter().filter(|c| c.actor != c.author).count());
        reach("required settings", cs.iter().flat_map(|c| c.parts.iter()).filter(|p| matches!(&p.body, hm::Body::Held(hm::Delta::Required(r)) if !r.is_empty())).count());
        let addenda = cs.iter().flat_map(|c| c.parts.iter()).filter(|p| matches!(&p.body, hm::Body::Held(hm::Delta::Addenda(es)) if !es.is_empty())).count();
        reach("addenda", addenda);
        if addenda > 0 {
            reach("counting addenda", hm::timeline(&input.held).counting.len());
        }
        reach("invites", edges().filter(|(_, e)| e.invite.is_some()).count());
        reach("untils", edges().filter(|(_, e)| e.until.is_some()).count());
        reach("own edge writes", edges().filter(|(c, e)| e.holder == c.author).count());
        reach("removals with no frontier", edges().filter(|(c, e)| e.role.is_none() && e.holder != NOBODY && c.frontier.is_none()).count());
    }
    // the model's input on the things `what` is about: now, things, their commits
    let differ = |what: String, things: &[hm::ThingId]| {
        let h = &input.held;
        let mut s = format!("held-model differs: {what}\nmodel input (things {things:?}): now {}, me {}, records {:?}", h.now, h.me, h.records);
        for c in h.commits.iter().filter(|c| c.is_role() || c.parts.iter().any(|p| things.contains(&p.thing))) {
            s.push_str(&format!("\n  {c:?}"));
        }
        Some(s)
    };
    let by_part: BTreeMap<(hm::ThingId, hm::Aspect), (Tid, Ak)> = input.inside.iter().map(|(k, v)| (*v, k.clone())).collect();
    // every difference, by kind; the first is reported
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
            // purge on replace promises the content gone once a right holder's snapshot covers
            // it (spec/commits.md §5), a held body nothing reads, like P3's
            if matches!(p.body, hm::Body::Held(_)) && matches!(o.fates.get(&(c.id, i)), Some(hm::Fate::MustDrop(hm::DropWhy::Covered { .. }))) {
                diffs.push(("holds a covered purge-on-replace body".into(), differ(format!("commit {id:?} (#{}) on {t:?} {}: the node holds its body, a held right holder's snapshot covers it", c.id, a.as_str()), &[p.thing])));
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
    // `roles.0` reads: each known thing's roster (its edges alive now, record edges included;
    // `tied` carried, never an authority) as the model's walk ends
    if !by_part.is_empty() {
        let tl = hm::timeline(&input.held);
        let last = tl.applied.last().map_or(&tl.initial, |a| &a.after);
        for th in input.held.records.iter().map(|t| t.id) {
            let model: BTreeMap<hm::NodeId, (hm::Role, Option<hm::Role>, Option<u64>)> = last.iter().filter(|((t, _), e)| *t == th && e.alive(input.held.now)).map(|((_, h), e)| (*h, (e.role, e.invite, e.until))).collect();
            let t = input.ids[&th];
            let node: BTreeMap<hm::NodeId, (hm::Role, Option<hm::Role>, Option<u64>)> = e.roster(&t).iter().map(|(h, x)| (input.ids.iter().find(|(_, v)| *v == h).map_or(NOBODY, |(k, _)| *k), (role_of(x.role), x.invite.map(role_of), x.until.map(|u| u.0)))).collect();
            reach_n(cov, "rosters", 1);
            if node != model {
                diffs.push(("roster differs".into(), differ(format!("{t:?} roster: model {model:?}, node {node:?}"), &[th])));
            }
        }
    }
    if let Some(f) = o.forbidden.iter().find(|f| by_part.contains_key(&(f.1.1, f.1.2))) {
        diffs.push(("forbidden value held".into(), differ(format!("forbidden value held: {f:?}"), &[f.1.1])));
    }
    // reads, as values by their canonical bytes
    for ((t, a), (thing, aspect)) in &input.inside {
        let model = o.reads.get(&(*thing, *aspect)).cloned().flatten();
        let v = e.get(t, a).unwrap();
        let node = v.as_ref().map(value);
        if node != model {
            diffs.push(("read differs".into(), differ(format!("{t:?} {} reads {v:?} at the node, {model:?} in the model (state {:?})", a.as_str(), o.states.get(&(*thing, *aspect))), &[*thing])));
        }
    }
    // kept until T (or for good, spec/commits.md §5 Keep at least): every body the node dropped
    // whose absolute bound is still ahead, given back as a node keeping every body holds it, is
    // one the model lets go
    let mut back = input.held.clone();
    let back_dots = hm::Dots::new(&back);
    let mut given = Vec::new();
    for (label, i, id, t, a, why) in &input.dropped {
        let Some(f) = kept.get(&(*id, *t, a.clone())) else { continue };
        let Some(c) = back.commits.iter_mut().find(|c| c.id == *label) else { continue };
        if !matches!(c.parts[*i].retention.history, hm::History::Keep { until, .. } if until > input.held.now) {
            continue;
        }
        let p = &mut c.parts[*i];
        let f = frag(f).unwrap_or_else(|why| panic!("kept body of {id:?}: {why}"));
        p.stripped = back_dots.valueless(p.thing, p.aspect, &f);
        p.body = hm::Body::Held(hm::Delta::Writes(f));
        given.push((*label, *i, *id, *t, a.clone(), why.clone()));
    }
    reach_n(cov, "kept until T judged", given.len());
    if !given.is_empty() {
        let ob = hm::evaluate(&back);
        for (label, i, id, t, a, why) in &given {
            let f = ob.fates.get(&(*label, *i));
            if !matches!(f, Some(hm::Fate::MayDrop(_) | hm::Fate::MustDrop(_))) {
                diffs.push(("dropped a body kept until T".to_string(), differ(format!("commit {id:?} (#{label}) on {t:?} {}: the node dropped its body ({why}), the model's fate for it is {f:?}", a.as_str()), &[input.inside[&(*t, a.clone())].0])));
            }
        }
    }
    for (k, _) in &diffs {
        *cov.differs.entry(k.clone()).or_default() += 1;
    }
    diffs.into_iter().next().and_then(|(_, d)| d)
}

/// Keep for D (spec/commits.md §5), for the scripted examples of its dating rule only (the order
/// oracle compares no death dates): on in-scope aspects, every applied content part of `e`
/// replaced as held-model dates it has a keep bound (`Engine::body_keeps`, what compaction drops
/// by) no earlier than that date plus D. How many were judged, how many the node dates later
/// than the model (it keeps them longer), and the first dated early.
pub(crate) fn keep_for_d(e: &mut Engine, hist: &History) -> (usize, usize, Option<String>) {
    let input = convert(e, hist);
    let o = hm::evaluate(&input.held);
    let by_part: BTreeMap<(hm::ThingId, hm::Aspect), (Tid, Ak)> = input.inside.iter().map(|(k, v)| (*v, k.clone())).collect();
    let (mut judged, mut later, mut early) = (0, 0, None);
    for c in input.held.commits.iter().filter(|c| !c.is_role() && input.commits[&c.id].1) {
        let id = input.commits[&c.id].0;
        for (i, p) in c.parts.iter().enumerate() {
            let Some((t, a)) = by_part.get(&(p.thing, p.aspect)) else { continue };
            let Some(Some(r)) = o.replaced_at.get(&(c.id, i)) else { continue };
            let Some(ai) = e.header(&id).and_then(|h| h.aspects.iter().position(|x| x.tid == *t && x.ak == *a)) else { continue };
            if p.retention.kept_after() == 0 {
                continue;
            }
            judged += 1;
            let want = r.saturating_add(p.retention.kept_after());
            let keep = e.body_keeps(&id).unwrap().get(ai).copied().unwrap_or(0);
            if e.replaced_at(&id, t, a).unwrap().is_none_or(|x| x.wall_ms().0 > *r) {
                later += 1;
            }
            if keep < want && early.is_none() {
                early = Some(format!("commit {id:?} (#{}) on {t:?} {}: the node keeps it to {keep}, the model's replacement {r} + D = {want}; node's replaced_at {:?}", c.id, a.as_str(), e.replaced_at(&id, t, a)));
            }
        }
    }
    (judged, later, early)
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
