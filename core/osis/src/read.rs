//! Reads and watches (notes/api.md Reads, Watching): synchronous reads of local state, large values materialized up to the bound, typed reads failing
//! with the path; watches and callbacks over the dispatcher.

use crate::error::{Error, Result};
use crate::handle::Osis;
use crate::port::method as m;
use crate::share::Member;
use crate::watch::{Callback, Change, Delivery, Filter, Msg, Origin, Subscription};
use crate::commit_id::{CommitId, HistoryPos};
use osis_base::{Ak, Role, Tid, Ts, Value, Time};
use osis_node::{Diagnostic, Engine};
use osis_schema::AspectKey;
use osis_schema::core_types::{GROUP, GROUP_EPHEMERAL};
use osis_schema::{Codec, Path, PathError, PathErrorKind, Schema, Step, Type, misplaced_link, type_at, typed_read, value_at};
use std::collections::BTreeMap;

/// A role granted to one holder (`Osis::grants`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Grant {
    /// The role.
    pub role: Role,
    /// The grant ends at this time.
    pub until: Option<Time>,
    /// The role this holder may grant others.
    pub may_grant: Option<Role>,
    /// The holder is a group and this grant goes when the thing stops being its member
    /// (`Osis::add_with_grant`). Not a member now (`Osis::groups_of`), it is on its way out.
    pub with_membership: bool,
}

/// A commit's author and time, as the commit itself signs them (a `CommitKind::Snapshot` is reported
/// as itself, never as the writes it stands in for): why a watch fired, a commit or history entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stamp {
    /// The commit.
    pub id: CommitId,
    /// The actor the author acted for.
    pub actor: Tid,
    /// The authoring node.
    pub node: Tid,
    /// When it was written, by the author's clock: the same on every node.
    pub written: Time,
    /// When this node received it (per node).
    pub received: Time,
    /// `written` with what orders commits of one moment.
    pub(crate) ts: Ts,
}

impl Stamp {
    pub(crate) fn new(id: CommitId, actor: Tid, node: Tid, ts: Ts, received: Time) -> Stamp {
        Stamp { id, actor, node, written: ts.wall_ms(), received, ts }
    }

    /// The time to show and sort by: the earlier of `written` and `received`, as an author's clock
    /// may run ahead.
    pub fn shown(&self) -> Time {
        self.written.min(self.received)
    }

    pub(crate) fn pos(&self) -> HistoryPos {
        HistoryPos::of(self.ts, self.id)
    }
}

/// When a thing was made or last changed (`Osis::created`, `Osis::changed`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ThingStamp {
    /// The commit; `None` when it is only the creation of a draft.
    pub id: Option<CommitId>,
    /// The actor the author acted for.
    pub actor: Tid,
    /// The authoring node.
    pub node: Tid,
    /// When it was written, by the author's clock: the same on every node.
    pub written: Time,
    /// When this node received it (per node).
    pub received: Time,
    /// `written` with what orders commits of one moment.
    pub(crate) ts: Ts,
}

impl ThingStamp {
    /// The time to show and sort by, as `Stamp::shown`.
    pub fn shown(&self) -> Time {
        self.written.min(self.received)
    }
}

fn stamp(c: osis_node::Creation) -> ThingStamp {
    ThingStamp { id: c.commit.map(CommitId::commit), written: c.ts.wall_ms(), ts: c.ts, node: c.node, actor: c.actor, received: c.received }
}

/// The groups a thing is in (`Osis::groups_of`), each list in tid order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GroupsOf {
    /// Groups it is an item of.
    pub item_of: Vec<Tid>,
    /// Groups it is a subgroup of (its items count as theirs).
    pub subgroup_of: Vec<Tid>,
    /// Every group holding it as an item, directly or through subgroups: what carries its own
    /// aspects when they sync. Not the groups it is only a subgroup of.
    pub within: Vec<Tid>,
}

/// The grants on a thing, by holder.
pub type Grants = BTreeMap<Tid, Grant>;

pub(crate) fn ak_of<K: AspectKey>(key: &K) -> Result<Ak> {
    Ak::new(key.ak()).map_err(|_| Error::Invalid(format!("bad AK {:?}", key.ak())))
}

/// A link's value, `None` when it cannot be read here (spec/data-model.md §6): a blob of its
/// tree is not held (not fetched yet, or named by no blob) or fails verification (another
/// thing's dedup secret, bad bytes, an unknown format). The bound and local storage failures
/// stay errors.
fn read_link(e: &mut Engine, tid: &Tid, l: &osis_base::Link, limit: usize, budget: &mut usize, bad: &mut Vec<osis_label::Error>) -> Result<Option<Value>> {
    use osis_base::{Classified, ErrorClass};
    let too_large = Error::TooLarge { limit };
    let x = match e.read_large_max(tid, l, *budget) {
        Ok(x) => x,
        Err(osis_node::Error::Label(osis_label::Error::TooLarge(_))) => return Err(too_large),
        Err(osis_node::Error::Label(err)) if err == osis_label::Error::Missing || err.class() != ErrorClass::Local => {
            bad.push(err);
            return Ok(None);
        }
        Err(other) => return Err(other.into()),
    };
    let n = osis_base::cbor::encode(&x).len();
    *budget = budget.checked_sub(n).ok_or(too_large)?;
    Ok(Some(x))
}

/// `v` with its links replaced; `None` when `v` itself is gone. An unreadable link (`read_link`)
/// is gone, and with it the list or set element, map entry (struct field) or enum it is in or
/// is; the rest stays.
fn materialize_in(e: &mut Engine, tid: &Tid, v: Value, limit: usize, budget: &mut usize, bad: &mut Vec<osis_label::Error>) -> Result<Option<Value>> {
    if let Value::Link(l) = v {
        return read_link(e, tid, &l, limit, budget, bad);
    }
    let mut m = |x: Value| materialize_in(e, tid, x, limit, budget, bad);
    Ok(Some(match v {
        Value::List(l) => Value::List(l.into_iter().filter_map(|x| m(x).transpose()).collect::<Result<_>>()?),
        Value::Set(s) => Value::Set(s.into_iter().filter_map(|x| m(x).transpose()).collect::<Result<_>>()?),
        Value::Map(map) => {
            // `collect`: a link's content sorts elsewhere than the link, so an insert per key is O(n)
            let mut out = Vec::with_capacity(map.len());
            for (k, x) in map {
                if let (Some(k), Some(x)) = (m(k)?, m(x)?) {
                    out.push((k, x));
                }
            }
            Value::Map(out.into_iter().collect())
        }
        Value::Enum(c, Some(p)) => match m(*p)? {
            Some(p) => Value::Enum(c, Some(Box::new(p))),
            None => return Ok(None),
        },
        v => v,
    }))
}

/// Replaces every link by its value, dropping unreadable ones into `bad` (`materialize_in`);
/// fails `TooLarge` past `limit` canonical bytes.
fn materialize(e: &mut Engine, tid: &Tid, v: Value, limit: usize, bad: &mut Vec<osis_label::Error>) -> Result<Option<Value>> {
    let mut budget = limit;
    let v = materialize_in(e, tid, v, limit, &mut budget, bad)?;
    if v.as_ref().is_some_and(|v| osis_base::cbor::encode(v).len() > limit) {
        return Err(Error::TooLarge { limit });
    }
    Ok(v)
}

/// The diagnostic for a stored value of `tid`'s `ak` that a typed read could not decode.
pub(crate) fn mismatch(tid: Tid, ak: &Ak, e: &PathError) -> Diagnostic {
    Diagnostic { kind: osis_node::DiagnosticKind::Mismatch, tids: vec![tid], commit: None, peer: None, detail: format!("{ak}: type error at {}: {}", e.path, e.kind) }
}

/// A typed decode of stored data (notes/api.md Typed reads): a value that does not match the
/// reader's type reads as absent and reports a `Mismatch` diagnostic. Stored data is others'
/// input; a caller cannot act on an error (the untyped read shows the value).
pub(crate) fn lenient<T>(tid: Tid, ak: &Ak, r: std::result::Result<T, PathError>, report: impl FnOnce(Diagnostic)) -> Option<T> {
    r.map_err(|e| report(mismatch(tid, ak, &e))).ok()
}

/// One locked view of the engine: what every single read uses.
pub(crate) struct Reader<'a> {
    pub(crate) e: &'a mut Engine,
    pub(crate) limit: usize,
    /// Reads as this actor (`Osis::act_as`): a thing it may not read answers exactly as a thing
    /// this node does not know, through every method below.
    pub(crate) actor: Option<Tid>,
}

/// `Reader::knows` on an engine already locked (a check inside a commit).
pub(crate) fn knows_in(e: &mut Engine, tid: Tid) -> Result<bool> {
    Reader { e, limit: 0, actor: None }.knows(tid)
}

impl Reader<'_> {
    /// Whether the acting actor may not read `t` (never without one).
    pub(crate) fn hidden(&self, t: Tid) -> bool {
        self.actor.is_some_and(|a| !self.e.readable_by(&a, &t))
    }

    /// The stored value of `tid` (its tid returned too), large values still links.
    pub(crate) fn raw(&mut self, tid: Tid, ak: &Ak) -> Result<(Tid, Option<Value>)> {
        if self.hidden(tid) {
            return Ok((tid, None));
        }
        let v = self.e.get(&tid, ak)?;
        // `groups.0`: the local index, shown as `groups_of` shows it
        if let (Some(_), "groups.0", Some(Value::Set(s))) = (self.actor, ak.as_str(), &v) {
            return Ok((tid, Some(Value::Set(s.iter().filter(|g| !matches!(g, Value::Tid(t) if self.hidden(*t))).cloned().collect()))));
        }
        Ok((tid, v))
    }

    /// `v` (of `tid`'s `ak`) materialized up to the bound; an unreadable link reads as absent at
    /// its position with an `Unreadable` diagnostic (spec/data-model.md §6), `None` when it is
    /// `v` itself or the enum `v` is. A blob not held is noted: its arrival re-delivers the aspect
    /// to watches (`Engine::missed_blob`).
    fn materialize(&mut self, tid: &Tid, ak: &Ak, v: Value) -> Result<Option<Value>> {
        let mut bad = Vec::new();
        let v = materialize(self.e, tid, v, self.limit, &mut bad)?;
        if bad.contains(&osis_label::Error::Missing) {
            self.e.missed_blob(*tid, ak.clone(), None);
        }
        if !bad.is_empty() {
            // each kind of failure once: the detail stays small however many links fail
            let why = bad.iter().map(|e| e.to_string()).collect::<std::collections::BTreeSet<_>>().into_iter().collect::<Vec<_>>().join("; ");
            self.e.report(Diagnostic { kind: osis_node::DiagnosticKind::Unreadable, tids: vec![*tid], commit: None, peer: None, detail: format!("{ak}: {} link(s) read as absent: {why}", bad.len()) });
        }
        Ok(v)
    }

    /// `v` (the body of `id`'s history entry on `tid`'s `ak`) with its links replaced, up to
    /// `limit` bytes; any unreadable link fails it whole. A blob not held is noted: its arrival
    /// re-delivers the entry to history watches (`Engine::missed_blob`).
    pub(crate) fn materialized(&mut self, tid: &Tid, ak: &Ak, id: osis_node::BatchId, v: Value, limit: usize) -> Result<Value> {
        let mut bad = Vec::new();
        let v = materialize(self.e, tid, v, limit, &mut bad)?;
        if bad.contains(&osis_label::Error::Missing) {
            self.e.missed_blob(*tid, ak.clone(), Some(id));
        }
        match (bad.into_iter().next(), v) {
            (None, Some(v)) => Ok(v),
            (err, _) => Err(Error::Invalid(err.map_or_else(|| "unreadable link".into(), |e| e.to_string()))),
        }
    }

    /// The whole value of an aspect, untyped, materialized up to the bound.
    pub fn value(&mut self, tid: Tid, ak: &Ak) -> Result<Option<Value>> {
        let (tid, v) = self.raw(tid, ak)?;
        Ok(match v {
            Some(v) => self.materialize(&tid, ak, v)?,
            None => None,
        })
    }

    /// A typed read: `None` when absent, and when the stored value
    /// does not match the key's type (a `Mismatch` diagnostic).
    pub fn get<K: AspectKey>(&mut self, tid: Tid, key: &K) -> Result<Option<K::T>> {
        let ak = ak_of(key)?;
        let (t, Some(raw)) = self.raw(tid, &ak)? else { return Ok(None) };
        let v = match (key.schema(), key.ty()) {
            (Some(s), Some(ty)) => match self.materialize_typed(t, &ak, s, raw, ty, false, &Path::root())? {
                Some(v) => v,
                None => return Ok(None),
            },
            _ => match self.materialize(&t, &ak, raw)? {
                Some(v) => v,
                None => return Ok(None),
            },
        };
        Ok(lenient(t, &ak, key.decode(&v), |d| self.e.report(d)))
    }

    /// `v`, of `tid`'s `ak` at `path` (type `ty`, `atomic` inside a set element or map key),
    /// materialized; `None` with a `Mismatch` diagnostic when it holds a link where the type takes
    /// none (spec/data-model.md §6): a mismatch like any other, never fetched. An unreadable link
    /// where the type takes one reads as absent at its position (`materialize`).
    #[allow(clippy::too_many_arguments)]
    fn materialize_typed(&mut self, tid: Tid, ak: &Ak, s: &Schema, v: Value, ty: &Type, atomic: bool, path: &Path) -> Result<Option<Value>> {
        if misplaced_link(s, &v, ty, atomic) {
            self.e.report(mismatch(tid, ak, &PathError::new(path.clone(), PathErrorKind::Mismatch { expected: "no link here" })));
            return Ok(None);
        }
        self.materialize(&tid, ak, v)
    }

    /// The value at `path` inside an aspect (typed projection through the key's schema when it
    /// has one); `None` when the path leads nowhere or the value there does not match the
    /// schema (a `Mismatch` diagnostic). A path the schema does not have fails `Type`. Only
    /// that position is materialized.
    pub fn get_path<K: AspectKey>(&mut self, tid: Tid, key: &K, path: &Path) -> Result<Option<Value>> {
        let ak = ak_of(key)?;
        let (tid, Some(raw)) = self.raw(tid, &ak)? else { return Ok(None) };
        let (Some(s), Some(ty)) = (key.schema(), key.ty()) else {
            let Some(sub) = value_at(&raw, path) else { return Ok(None) };
            return self.materialize(&tid, &ak, sub.clone());
        };
        let (t, atomic) = type_at(s, ty, path)?;
        if let Some(sub) = value_at(&raw, path) {
            let Some(sub) = self.materialize_typed(tid, &ak, s, sub.clone(), &t, atomic, path)? else { return Ok(None) };
            return Ok(lenient(tid, &ak, typed_read(s, &sub, &t), |d| self.e.report(d)));
        }
        // an absent struct field reads as its default (spec/versioning.md §5): project the parent
        let Some((Step::Field(id), parent)) = path.0.split_last() else { return Ok(None) };
        let parent = Path(parent.to_vec());
        let Some(sub) = value_at(&raw, &parent) else { return Ok(None) };
        let (pt, atomic) = type_at(s, ty, &parent)?;
        let Some(sub) = self.materialize_typed(tid, &ak, s, sub.clone(), &pt, atomic, &parent)? else { return Ok(None) };
        let Some(projected) = lenient(tid, &ak, typed_read(s, &sub, &pt), |d| self.e.report(d)) else { return Ok(None) };
        Ok(value_at(&projected, &Path(vec![Step::Field(*id)])).cloned())
    }

    /// AKs present on the thing.
    pub fn aspects(&mut self, tid: Tid) -> Result<Vec<Ak>> {
        if self.hidden(tid) {
            return Ok(Vec::new());
        }
        Ok(self.e.aspects(&tid)?)
    }

    /// The groups the thing is in: those listing it as an item or as a subgroup, and every
    /// group holding it transitively. Local indexes only.
    pub fn groups_of(&self, tid: Tid) -> GroupsOf {
        if self.hidden(tid) {
            return GroupsOf::default();
        }
        let (items, subs) = self.e.listed_in(&tid);
        let seen = |s: std::collections::BTreeSet<Tid>| s.into_iter().filter(|g| !self.hidden(*g)).collect();
        GroupsOf { item_of: seen(items), subgroup_of: seen(subs), within: seen(self.e.groups_of(&tid)) }
    }

    /// The grants on `thing`.
    pub fn grants(&self, thing: Tid) -> Grants {
        if self.hidden(thing) {
            return Grants::new();
        }
        self.e.roster(&thing).into_iter().map(|(m, e)| (m, Grant { role: e.role, until: e.until, may_grant: e.invite, with_membership: e.tied.is_some() })).collect()
    }

    /// This node's effective role on `tid` now (`None`: no access); the acting actor's when
    /// there is one.
    pub fn role_on(&self, tid: Tid) -> Option<Role> {
        match self.actor {
            Some(a) => self.e.actor_role(&a, &tid).filter(|_| !self.hidden(tid)),
            None => self.e.role_on(&tid),
        }
    }

    /// Whether the thing is here with content: its creation is held and some aspect a `Write`
    /// sets is present, or it is a draft here (or one again: its save undone) (content or
    /// not, unless an undo of its creation deleted it). `false` for an unknown thing and for one
    /// with no content: deleted, and equally never written (a thing just created and added to a group, an
    /// actor carrying only role data).
    pub fn knows(&mut self, tid: Tid) -> Result<bool> {
        if self.hidden(tid) {
            return Ok(false);
        }
        if self.e.ephemeral_thing(&tid).is_some_and(|x| !x.deleted) || self.e.is_draft_again(&tid) {
            return Ok(true);
        }
        Ok(self.e.knows(&tid) && self.e.has_content(&tid)?)
    }

    /// Whether the thing's creation is held or it is a draft here, deleted or not: what a
    /// write or grant needs.
    pub(crate) fn holds(&self, tid: Tid) -> bool {
        !self.hidden(tid) && self.e.knows(&tid)
    }

    /// The thing's owner (`None`: unknown, or a key actor).
    pub fn owner_of(&self, tid: Tid) -> Option<Tid> {
        if self.hidden(tid) {
            return None;
        }
        self.e.owner(&tid)
    }

    /// When the thing was created: the oldest valid commit carrying its `created.0` that is no
    /// snapshot (a draft's write); `None` while it is unknown or
    /// only a snapshot carrying its `created.0` is here.
    pub fn created(&self, tid: Tid) -> Option<ThingStamp> {
        if self.hidden(tid) {
            return None;
        }
        self.e.creation(&tid).map(stamp)
    }

    /// When the thing's content last changed: of the held commits and reverts writing its aspects (not `created.0`, `group.0` or role-class ones: membership and
    /// sharing are no content write; not ephemeral writes), the one with the latest
    /// `shown()`, else its creation. A delete is one. A commit known here only from a
    /// snapshot is not seen.
    pub fn changed(&self, tid: Tid) -> Option<ThingStamp> {
        if self.hidden(tid) {
            return None;
        }
        self.e.changed(&tid).map(stamp)
    }
}

impl Osis {
    /// Runs `f` on this process's engine (callers pick the source first).
    pub(crate) fn read_local<R>(&self, f: impl FnOnce(&mut Reader<'_>) -> R) -> R {
        let (limit, actor) = (self.inner.limit, self.acting);
        self.engine(|e| f(&mut Reader { e, limit, actor }))
    }

    /// An aspect, for reads (`None` when absent or the thing is unknown), paths and callbacks.
    pub fn at<K: AspectKey>(&self, tid: Tid, key: K) -> AspectRef<'_, K> {
        AspectRef { db: self, tid, key }
    }

    /// The aspects that read as present on the thing, core ones included (`created.0`). A register
    /// whose live write was purged reads absent, and is not listed.
    pub fn aspects(&self, tid: Tid) -> Result<Vec<Ak>> {
        if let crate::sources::Source::Node(r) = self.source(tid) {
            let v = r.call(m::ASPECTS, vec![Value::Tid(tid)])?;
            return crate::port::codec::Args::of(vec![v]).list()?.iter().map(crate::port::codec::ak).collect();
        }
        self.read_local(|r| r.aspects(tid))
    }

    /// The groups the thing is in: those listing it as an item or as a subgroup, and every group
    /// holding it transitively.
    pub fn groups_of(&self, tid: Tid) -> Result<GroupsOf> {
        if let crate::sources::Source::Node(r) = self.source(tid) {
            return crate::port::codec::groups(r.call(m::GROUPS_OF, vec![Value::Tid(tid)])?);
        }
        Ok(self.read_local(|r| r.groups_of(tid)))
    }

    /// What `group` contains: its items, then its subgroups, each in tid order (empty when it has
    /// never had a member). A thing both item and subgroup appears as both. Being in a group grants
    /// nothing: who holds a role on it is `grants`.
    pub fn members(&self, group: Tid) -> Result<Vec<Member>> {
        let (durable, eph) = match self.source(group) {
            crate::sources::Source::Node(_) => (self.at(group, GROUP).get()?, self.at(group, GROUP_EPHEMERAL).get()?),
            crate::sources::Source::Local => self.read_local(|r| Ok::<_, Error>((r.get(group, &GROUP)?, r.get(group, &GROUP_EPHEMERAL)?)))?,
        };
        let mut d = durable.unwrap_or_default();
        let p = eph.unwrap_or_default();
        d.items.extend(p.items);
        d.subgroups.extend(p.subgroups);
        Ok(d.items.into_iter().map(Member::Item).chain(d.subgroups.into_iter().map(Member::Subgroup)).collect())
    }

    /// The roles granted on `thing`, by holder. Whoever holds through those: `holders`.
    pub fn grants(&self, thing: Tid) -> Result<Grants> {
        if let crate::sources::Source::Node(r) = self.source(thing) {
            return crate::port::codec::grants(r.call(m::GRANTS, vec![Value::Tid(thing)])?);
        }
        Ok(self.read_local(|r| r.grants(thing)))
    }

    /// This node's effective role on `tid` now (`None`: no access).
    pub fn role_on(&self, tid: Tid) -> Result<Option<Role>> {
        if let crate::sources::Source::Node(r) = self.source(tid) {
            let v = r.call(m::ROLE_ON, vec![Value::Tid(tid)])?;
            return crate::port::codec::Args::of(vec![v]).opt()?.map(|r| crate::port::codec::role(&r)).transpose();
        }
        Ok(self.read_local(|r| r.role_on(tid)))
    }

    /// Whether the thing is here with content. `false` for an unknown thing and for one with no
    /// content, which is a deleted one and equally one never written: a thing just created, or
    /// only added to a group or granted. Its creation being here needs no content, and is all a write needs.
    pub fn has_content(&self, tid: Tid) -> Result<bool> {
        if let crate::sources::Source::Node(r) = self.source(tid) {
            let v = r.call(m::HAS_CONTENT, vec![Value::Tid(tid)])?;
            return crate::port::codec::Args::of(vec![v]).bool();
        }
        self.read_local(|r| r.knows(tid))
    }

    pub(crate) fn holds(&self, tid: Tid) -> bool {
        self.read_local(|r| r.holds(tid))
    }

    /// The thing's owner, fixed at creation (`None`: unknown, or a key actor).
    // Removed with owners (issues/api-after-owners.md).
    #[doc(hidden)]
    pub fn owner_of(&self, tid: Tid) -> Result<Option<Tid>> {
        if let crate::sources::Source::Node(r) = self.source(tid) {
            let v = r.call(m::OWNER_OF, vec![Value::Tid(tid)])?;
            return crate::port::codec::Args::of(vec![v]).opt()?.map(|t| crate::port::codec::tid(&t)).transpose();
        }
        Ok(self.read_local(|r| r.owner_of(tid)))
    }

    fn node_stamp(&self, r: &crate::port::client::Connection, m: u64, tid: Tid) -> Result<Option<ThingStamp>> {
        let v = r.call(m, vec![Value::Tid(tid)])?;
        crate::port::codec::Args::of(vec![v]).opt()?.map(crate::port::codec::thing_stamp).transpose()
    }

    /// When the thing was created: the oldest valid commit carrying its creation (a draft's: no
    /// commit); `None` while it is unknown here.
    pub fn created(&self, tid: Tid) -> Result<Option<ThingStamp>> {
        if let crate::sources::Source::Node(r) = self.source(tid) {
            return self.node_stamp(&r, m::CREATED, tid);
        }
        Ok(self.read_local(|r| r.created(tid)))
    }

    /// When the thing's content last changed (membership and sharing are no content write, a delete
    /// is); its creation if never since. A commit known here only from a `CommitKind::Snapshot` is
    /// not seen.
    pub fn changed(&self, tid: Tid) -> Result<Option<ThingStamp>> {
        if let crate::sources::Source::Node(r) = self.source(tid) {
            return self.node_stamp(&r, m::CHANGED, tid);
        }
        Ok(self.read_local(|r| r.changed(tid)))
    }

    /// The corrected wall clock: the time the node stamps commits with,
    /// for app timestamps. On a thin client, its node's: `Network` when it cannot be
    /// reached.
    pub fn now(&self) -> Result<Time> {
        if !self.has_store() {
            return self.rcall(m::NOW, vec![])?.as_uint().map(Time).ok_or_else(|| crate::port::codec::bad("time"));
        }
        Ok(self.engine(|e| e.now()))
    }

    /// Reads an aspect and runs `also` under the same engine lock (the dispatcher queues the
    /// events whose effect the read shows).
    pub(crate) fn value_with(&self, tid: Tid, ak: &Ak, also: impl FnOnce()) -> Result<Option<Value>> {
        let (limit, actor) = (self.inner.limit, self.acting);
        self.locked(|l| {
            let v = Reader { e: l.engine(), limit, actor }.value(tid, ak);
            also();
            v
        })
    }

    /// Registers a callback built by `make` under the engine lock (so whatever `make` reads is
    /// atomic with the registration: nothing committed after it is missed or seen twice);
    /// `initial` queues one `Delivery::Initial` call through the dispatcher.
    pub(crate) fn subscribe(&self, filter: Filter, initial: bool, make: impl FnOnce(&mut Reader<'_>) -> Callback) -> Subscription {
        let (limit, actor) = (self.inner.limit, self.acting);
        self.locked(|l| {
            let cb = make(&mut Reader { e: l.engine(), limit, actor });
            let d = &self.inner.dispatch;
            // the source was decided before this lock: a move since ends it at once
            let on = match &filter {
                Filter::Aspect(t, _) | Filter::Thing(t) | Filter::Grants(t) => Some(*t),
                Filter::History(t, _) => {
                    l.engine().watch_history();
                    Some(*t)
                }
                _ => None,
            };
            let gone = on.is_some_and(|t| actor.is_none() && !self.local_in(l, t));
            let sub = d.register(l.seq + 1, filter, cb);
            if initial && let Some(id) = sub.id() {
                l.seq += 1;
                d.send(l.seq, Msg::Initial(id));
            }
            if gone && let Some(id) = sub.id() {
                l.seq += 1;
                d.send(l.seq, Msg::Moved(id));
            }
            sub
        })
    }

    /// Calls `f` with every change of any aspect of `tid`, first
    /// once per present aspect (`Origin::Initial`, through the dispatcher). Like every
    /// callback, `f` gets the node handle, so it need not capture one (a captured clone in
    /// a detached callback keeps the node open; capture `Osis::downgrade()` instead).
    /// Fails `Network` when `tid` is at a node that cannot be reached now. A live watch hears a
    /// lost connection as an `Err` value, and the aspects again once it is back.
    pub fn on_thing_change(&self, tid: Tid, mut f: impl FnMut(&Osis, Change<Value>) + Send + 'static) -> Result<Subscription> {
        if let crate::sources::Source::Node(r) = self.source(tid) {
            return self.node_on_thing_change(&r, tid, Box::new(f));
        }
        let mut failed = None;
        let sub = self.subscribe(Filter::Thing(tid), true, |r| {
            let mut last: BTreeMap<Ak, Result<Option<Value>>> = BTreeMap::new();
            match r.aspects(tid) {
                Ok(aks) => {
                    for ak in aks {
                        let v = r.value(tid, &ak);
                        last.insert(ak, v);
                    }
                }
                Err(e) => failed = Some(e),
            }
            let mut first = Some(last.clone());
            Box::new(move |db, d| match d {
                Delivery::Initial => {
                    for (ak, v) in first.take().unwrap_or_default() {
                        f(db, Change { tid, ak, value: v, origin: Origin::Initial });
                    }
                }
                Delivery::Aspect { tid, ak, origin, value } if value.is_err() || last.get(&ak) != Some(&value) => {
                    last.insert(ak.clone(), value.clone());
                    f(db, Change { tid, ak, value, origin });
                }
                Delivery::Fired { tid, ak, origin, value } => f(db, Change { tid, ak, value: Ok(Some(value)), origin }),
                Delivery::Moved => {
                    if let Ok(ak) = Ak::new("tid.0") {
                        f(db, Change { tid, ak, value: Err(crate::sources::moved()), origin: Origin::Initial });
                    }
                }
                _ => {}
            })
        });
        match failed {
            Some(e) => Err(e),
            None => Ok(sub),
        }
    }

    /// Calls `f` with `grants(thing)` now (through the dispatcher) and on every change. Fails
    /// `Network` when `thing` is at a node that cannot be reached now; a live watch hears a lost
    /// connection as an `Err`, and the grants again once it is back.
    pub fn on_grants_change(&self, thing: Tid, mut f: impl FnMut(&Osis, Result<Grants>) + Send + 'static) -> Result<Subscription> {
        if let crate::sources::Source::Node(r) = self.source(thing) {
            return self.node_on_grants_change(&r, thing, Box::new(f));
        }
        Ok(self.subscribe(Filter::Grants(thing), true, move |r| {
            let mut last = r.grants(thing);
            Box::new(move |db, d| match d {
                Delivery::Initial => f(db, Ok(last.clone())),
                Delivery::Grants => match db.grants(thing) {
                    Ok(r) if r == last => {}
                    Ok(r) => {
                        last = r.clone();
                        f(db, Ok(r));
                    }
                    Err(e) => f(db, Err(e)),
                },
                Delivery::Moved => f(db, Err(crate::sources::moved())),
                _ => {}
            })
        }))
    }

    /// Calls `f` with every diagnostic (deduped and rate-limited). On a thin client, those
    /// of its node: while it cannot be reached none come, and
    /// `status` says so; a session the node has ended fails as its calls do.
    pub fn on_diagnostic(&self, mut f: impl FnMut(&Osis, crate::Diagnostic) + Send + 'static) -> Result<Subscription> {
        if !self.has_store() {
            return self.node_on_diagnostic(Box::new(f));
        }
        Ok(self.subscribe(Filter::Diagnostics, false, |_| {
            Box::new(move |db, d| {
                if let Delivery::Diagnostic(x) = d {
                    f(db, x.into())
                }
            })
        }))
    }
}

/// An aspect of a thing: reads, path reads, watches.
pub struct AspectRef<'d, K> {
    pub(crate) db: &'d Osis,
    pub(crate) tid: Tid,
    pub(crate) key: K,
}

impl<'d, K: AspectKey> AspectRef<'d, K> {
    /// The value now; `None` when it is absent or does not read as the key's type.
    pub fn get(&self) -> Result<Option<K::T>> {
        if let crate::sources::Source::Node(r) = self.db.source(self.tid) {
            let ak = ak_of(&self.key)?;
            let Some(v) = self.db.node_get(&r, self.tid, &ak, &Path::root())? else { return Ok(None) };
            let db = self.db;
            return Ok(lenient(self.tid, &ak, self.key.decode(&v), |d| db.engine(|e| e.report(d))));
        }
        self.db.read_local(|r| r.get(self.tid, &self.key))
    }

    /// A position inside the value.
    pub fn path(&self, path: Path) -> PathRef<'_, 'd, K> {
        PathRef { a: self, path }
    }
}

impl<K: AspectKey + Clone + Send + 'static> AspectRef<'_, K> {
    /// Calls `f` once with the value at registration (`Origin::Initial`, through the
    /// dispatcher like every later call), then on every change; `f` gets the node handle.
    /// Calls coalesce: one call may show several commits' effect and carries the newest one's
    /// origin; an unchanged value is not repeated, an error always is.
    ///
    /// For async code, forward to a channel of any runtime and await that: the first value and
    /// every later one arrive in order, with no gap between reading and subscribing.
    pub fn on_change(&self, mut f: impl FnMut(&Osis, Change<K::T>) + Send + 'static) -> Result<Subscription> {
        let ak = ak_of(&self.key)?;
        if let crate::sources::Source::Node(r) = self.db.source(self.tid) {
            let key = self.key.clone();
            let ak2 = ak.clone();
            let tid = self.tid;
            let decode = move |db: &Osis, v: Result<Option<Value>>| -> Result<Option<K::T>> { Ok(v?.and_then(|x| lenient(tid, &ak2, key.decode(&x), |d| db.engine(|e| e.report(d))))) };
            return self.db.node_on_change(&r, self.tid, ak, Box::new(move |db, ch: Change<Value>| f(db, Change { tid: ch.tid, ak: ch.ak, value: decode(db, ch.value), origin: ch.origin })));
        }
        let tid = self.tid;
        let key = self.key.clone();
        let ak2 = ak.clone();
        let decode = move |db: &Osis, v: Result<Option<Value>>| Ok(v?.and_then(|x| lenient(tid, &ak2, key.decode(&x), |d| db.engine(|e| e.report(d)))));
        Ok(self.db.subscribe(Filter::Aspect(tid, ak.clone()), true, move |r| {
            let mut last = r.value(tid, &ak);
            Box::new(move |db, d| match d {
                Delivery::Initial => f(db, Change { tid, ak: ak.clone(), value: decode(db, last.clone()), origin: Origin::Initial }),
                Delivery::Aspect { tid, origin, value, .. } if value.is_err() || value != last => {
                    last = value.clone();
                    f(db, Change { tid, ak: ak.clone(), value: decode(db, value), origin });
                }
                Delivery::Fired { tid, origin, value, .. } => f(db, Change { tid, ak: ak.clone(), value: decode(db, Ok(Some(value))), origin }),
                Delivery::Moved => f(db, Change { tid, ak: ak.clone(), value: Err(crate::sources::moved()), origin: Origin::Initial }),
                _ => {}
            })
        }))
    }
}

/// A position inside an aspect's value.
pub struct PathRef<'a, 'd, K> {
    a: &'a AspectRef<'d, K>,
    path: Path,
}

impl<'d, K: AspectKey> PathRef<'_, 'd, K> {
    pub(crate) fn parts(&self) -> (&'d Osis, Tid, &K, &Path) {
        (self.a.db, self.a.tid, &self.a.key, &self.path)
    }

    /// The untyped value at the path (typed projection when the key has a schema).
    fn value(&self) -> Result<Option<Value>> {
        if let crate::sources::Source::Node(r) = self.a.db.source(self.a.tid) {
            return self.a.db.node_get(&r, self.a.tid, &ak_of(&self.a.key)?, &self.path);
        }
        self.a.db.read_local(|r| r.get_path(self.a.tid, &self.a.key, &self.path))
    }

    /// The value at the path as `U`; one bad element of a large collection reads as absent
    /// alone (a `Mismatch` diagnostic).
    pub fn get<U: Codec>(&self) -> Result<Option<U>> {
        let Some(v) = self.value()? else { return Ok(None) };
        let db = self.a.db;
        let ak = ak_of(&self.a.key)?;
        Ok(lenient(self.a.tid, &ak, U::from_value(&v), |d| db.engine(|e| e.report(d))))
    }
}
