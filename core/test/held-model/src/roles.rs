//! Role timeline and validity (spec/permissions.md §5.1, §5.2, §6), judged by roles-model
//! `paths`: this module builds a `paths::World` from the joined commits (each part along the path
//! its commit states for its thing) and reads that judgment. No rule of the walk lives here; what
//! is this module's own is the translation (ids, times, a commit's parts in the walk's order) and
//! which paths the node itself could state (`Timeline::my_right`, a writer's choice).

use crate::types::*;
use roles_model::paths::{self, Id, Kind, Names, Rules, View};
use std::collections::{BTreeMap, BTreeSet};

/// A hop's edge: (holder, target).
pub type Hop = (NodeId, ThingId);

/// The creation records known: mint admins.
#[derive(Clone, Debug, Default)]
pub struct World {
    pub links: BTreeMap<ThingId, RecordLink>,
}

impl World {
    pub fn new(records: &[Record]) -> World {
        World { links: records.iter().map(|t| (t.id, t.link)).collect() }
    }
    pub fn known(&self, t: ThingId) -> bool {
        self.links.contains_key(&t)
    }
    pub fn mint_admin(&self, t: ThingId) -> Option<NodeId> {
        match self.links.get(&t) {
            Some(RecordLink::Admin(o)) => Some(*o),
            _ => None,
        }
    }
    /// A key actor: its record holds a key (spec/permissions.md §1).
    pub fn key_actor(&self, t: ThingId) -> bool {
        self.links.get(&t) == Some(&RecordLink::Key)
    }
    /// The record chain above `t`, nearest first (stops at a key actor, an unknown record or a
    /// cycle).
    pub fn chain_above(&self, t: ThingId) -> Vec<NodeId> {
        let mut v = Vec::new();
        let mut x = t;
        while let Some(o) = self.mint_admin(x) {
            if o == t || v.contains(&o) {
                break;
            }
            v.push(o);
            x = o;
        }
        v
    }
    /// The edges the path `signer` states for a part on `thing` uses (spec/permissions.md §1
    /// Path, Hops, the key hop left out), and which of them are record edges; `None` where its
    /// members name a thing twice or its marks are invalid. `holder`: the part's holder, for an
    /// edge write (a path ending at it is a self-removal's).
    pub fn hops(&self, signer: NodeId, path: &Path, thing: ThingId, holder: Option<NodeId>) -> Option<Vec<(Hop, bool)>> {
        let names = Interned::new(self.links.keys().copied().chain(self.links.values().filter_map(|l| l.mint_admin())).chain([signer, thing]).chain(path.things.iter().copied()).chain(holder));
        let mut w = paths::World::new(&self.record_edges(&names));
        let things: Vec<paths::Thing> = path.things.iter().map(|&t| names.thing(t)).collect();
        let kind = holder.map_or(Kind::Content, |h| Kind::set(names.thing(h), roles_model::Role::None));
        let i = w.push_marked(names.thing(signer), 0, &things, names.thing(thing), kind, &path.direct);
        w.well(i).then(|| w.hops(i).iter().map(|&e| ((names.id(e.0), names.id(e.1)), w.is_record(e))).collect())
    }
    /// The edges of the path `c` states for each thing it writes, that thing its last member: its
    /// edge writes on one come after its others (spec/permissions.md §5.1 step 1).
    pub fn stated(&self, c: &Commit) -> BTreeSet<Hop> {
        let empty = Path::default();
        let things: BTreeSet<ThingId> = c.parts.iter().map(|p| p.thing).collect();
        things.into_iter().flat_map(|t| self.hops(c.signer, c.paths.get(&t).unwrap_or(&empty), t, None).unwrap_or_default()).map(|x| x.0).collect()
    }
    fn record_edges(&self, names: &Interned) -> Vec<paths::Edge> {
        self.links.iter().filter_map(|(&t, l)| Some((names.thing(l.mint_admin()?), names.thing(t)))).collect()
    }
}

/// Things as roles-model numbers them: in id order, so keys order alike.
struct Interned(Vec<ThingId>);

impl Interned {
    fn new(ids: impl IntoIterator<Item = ThingId>) -> Interned {
        let v: Vec<ThingId> = ids.into_iter().collect::<BTreeSet<_>>().into_iter().collect();
        assert!(v.len() < paths::KEYS as usize, "roles-model `paths` numbers at most {} things", paths::KEYS);
        Interned(v)
    }
    fn thing(&self, t: ThingId) -> paths::Thing {
        self.0.binary_search(&t).expect("an interned thing") as paths::Thing
    }
    fn id(&self, t: paths::Thing) -> ThingId {
        self.0[t as usize]
    }
}

fn role(r: Option<Role>) -> roles_model::Role {
    match r {
        None => roles_model::Role::None,
        // sync and read judge alike (neither writes)
        Some(Role::Sync | Role::Read) => roles_model::Role::Read,
        Some(Role::Write) => roles_model::Role::Write,
        Some(Role::Admin) => roles_model::Role::Admin,
    }
}

/// The role a delta on `aspect` needs.
pub fn need(a: Aspect) -> Role {
    if a.admin_only {
        Role::Admin
    } else {
        Role::Write
    }
}

/// What the builder is given beside the commits.
pub struct Joined<'a> {
    /// Every held commit that is not parked.
    pub live: &'a [&'a Commit],
    /// The applied ones as joined: their waiting and thrown parts count as not received.
    pub view: &'a [Commit],
    /// Commits void for every judgment: their addenda list nothing.
    pub void: &'a BTreeSet<CommitId>,
    /// The commits a held snapshot body carries copies of, on its thing and aspect.
    pub carries: &'a dyn Fn(&Commit, &Part) -> BTreeSet<CommitId>,
    /// The node: which rights it holds now is read too (`Timeline::my_right`).
    pub me: NodeId,
}

/// What one world part stands for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Of {
    /// A commit's part, by its index.
    Part(CommitId, usize),
    /// A commit's purge request on a thing: a destruction (an item on `created.0`) or not.
    Request(CommitId, ThingId, bool),
    /// A request the node could write now along one path it could state.
    Probe(ThingId, usize),
}

/// The judgment of the joined commits: roles-model `paths` over the world built from them.
pub struct Timeline {
    pub world: World,
    w: paths::World,
    rd: paths::Reading,
    rights: BTreeMap<Id, paths::Right>,
    names: Interned,
    /// `ts` values in order: a commit's `ts`, an `until` in `ts` units.
    times: Vec<u64>,
    ids: BTreeMap<Of, Vec<Id>>,
    writes: BTreeMap<Id, EdgeWrite>,
    probes: BTreeMap<ThingId, Vec<(Id, Path)>>,
}

const RULES: fn() -> Rules = Rules::purging;

impl Timeline {
    /// The world of `j`'s commits, judged.
    pub fn judge(world: World, j: &Joined) -> Timeline {
        let commits = || j.live.iter().copied();
        let edges = |c: &Commit| c.parts.iter().filter_map(|p| match &p.body {
            Body::Held(Delta::Edge(e)) => Some(*e),
            _ => None,
        }).collect::<Vec<_>>();
        let names = Interned::new(
            world.links.keys().copied().chain(world.links.values().filter_map(|l| l.mint_admin())).chain([j.me]).chain(commits().flat_map(|c| {
                let parts = c.parts.iter().map(|p| p.thing);
                let paths = c.paths.values().flat_map(|p| p.things.iter().copied());
                let purge = c.purge.iter().map(|i| match *i {
                    PurgeItem::Commit { thing, .. } | PurgeItem::Aspect { thing, .. } | PurgeItem::Author { thing, .. } => thing,
                });
                [c.signer, c.author].into_iter().chain(parts).chain(paths).chain(purge).chain(edges(c).into_iter().map(|e| e.holder)).collect::<Vec<_>>()
            })),
        );
        let until = |u: u64| u.saturating_mul(MS);
        let times: Vec<u64> = commits().map(|c| c.ts).chain(commits().flat_map(|c| edges(c)).filter_map(|e| e.until).map(until)).chain([u64::MAX]).collect::<BTreeSet<_>>().into_iter().collect();
        let time = |t: u64| times.binary_search(&t).expect("a listed time") as u32 + 1;
        let mut tl = Timeline { w: paths::World::new(&world.record_edges(&names)), world, rd: Default::default(), rights: BTreeMap::new(), names, times: times.clone(), ids: BTreeMap::new(), writes: BTreeMap::new(), probes: BTreeMap::new() };

        // each commit as joined (a waiting or thrown part is not received), else as held, in id
        // order: world ids are given by the order pushed, and keys tie on `ts` and signer by id
        let viewed: BTreeMap<CommitId, &Commit> = j.view.iter().map(|c| (c.id, c)).collect();
        let mut sorted: Vec<&Commit> = commits().map(|c| viewed.get(&c.id).copied().unwrap_or(c)).collect();
        sorted.sort_by_key(|c| c.id);
        let by_id: BTreeMap<CommitId, &Commit> = sorted.iter().map(|c| (c.id, *c)).collect();
        // the edge writes a commit holds, by part
        let cuts = |c: CommitId| -> Vec<usize> { by_id.get(&c).filter(|x| x.is_role()).into_iter().flat_map(|x| x.parts.iter().enumerate()).filter(|(_, p)| matches!(p.body, Body::Held(Delta::Edge(_)))).map(|x| x.0).collect() };
        // each commit's world parts, in the walk's order within the commit, and the thing each is on
        let mut plan: Vec<(&Commit, Vec<Of>)> = Vec::new();
        let mut on: Vec<paths::Thing> = Vec::new();
        for c in &sorted {
            let ofs = tl.plan(c, j.void.contains(&c.id), &|r| cuts(r).len());
            for (of, thing, n) in &ofs {
                tl.ids.insert(*of, (on.len()..on.len() + n).collect());
                on.extend(std::iter::repeat_n(tl.names.thing(*thing), *n));
            }
            plan.push((c, ofs.into_iter().map(|x| x.0).collect()));
        }
        // every world part of a commit: what a list naming the commit names
        let all = |tl: &Timeline, c: CommitId| -> Vec<Id> { tl.ids.iter().filter(|(of, _)| matches!(of, Of::Part(x, _) | Of::Request(x, _, _) if *x == c)).flat_map(|(_, v)| v.clone()).collect() };
        let mut held = paths::Set::new();
        for (c, ofs) in plan {
            let joined = viewed.contains_key(&c.id);
            let (signer, ts) = (tl.names.thing(c.signer), time(c.ts));
            let mut ids = Vec::new();
            for of in ofs {
                let (thing, kinds, part): (ThingId, Vec<Kind>, Option<&Part>) = match of {
                    Of::Part(_, i) => {
                        let p = &c.parts[i];
                        let kinds = match &p.body {
                            Body::Held(Delta::Edge(e)) if c.is_role() => {
                                // one leaf per thing: an entry names its commit's parts on that thing
                                let mut frontier: BTreeMap<paths::Thing, paths::Set> = BTreeMap::new();
                                for x in c.frontier.iter().flatten().flat_map(|&x| all(&tl, x)) {
                                    frontier.entry(on[x]).or_default().insert(x);
                                }
                                // a removal carrying no frontier is a finalize, where it is no self-removal (the world reads that)
                                let removal = e.role.is_none() || e.until == Some(0);
                                vec![Kind::Edge { holder: tl.names.thing(e.holder), role: role(e.role), until: e.until.map(|u| time(until(u))), frontier, may_grant: e.may_grant, finalize: removal && c.frontier.is_none() }]
                            }
                            Body::Held(Delta::Addenda(es)) if c.kind == CommitKind::Content && p.aspect == Aspect::ADDENDA && !j.void.contains(&c.id) => {
                                let mut ks = Vec::new();
                                for (removal, list) in es {
                                    let list: paths::Set = list.iter().flat_map(|&x| all(&tl, x)).collect();
                                    // the entry is keyed by a commit: against each cut that commit makes
                                    ks.extend(cuts(*removal).into_iter().filter_map(|k| tl.id(Of::Part(*removal, k))).map(|removal| Kind::Addendum { removal, list: list.clone() }));
                                }
                                if ks.is_empty() {
                                    ks.push(Kind::Content);
                                }
                                ks
                            }
                            _ if c.kind == CommitKind::Snapshot => {
                                let t = &tl;
                                let on_aspect = |x: CommitId| by_id.get(&x).into_iter().flat_map(|k| k.parts.iter().enumerate()).filter(|(_, q)| q.thing == p.thing && q.aspect == p.aspect).filter_map(move |(n, _)| t.id(Of::Part(x, n))).collect::<Vec<_>>();
                                vec![Kind::Cover { carries: (j.carries)(c, p).into_iter().flat_map(on_aspect).collect() }]
                            }
                            _ => vec![Kind::Content],
                        };
                        (p.thing, kinds, Some(p))
                    }
                    Of::Request(_, thing, destroy) => (thing, vec![Kind::Purge { names: if destroy { Names::Destroy } else { Names::Aspect } }], None),
                    Of::Probe(..) => unreachable!(),
                };
                let empty = Path::default();
                let path = c.paths.get(&thing).unwrap_or(&empty);
                let things: Vec<paths::Thing> = path.things.iter().map(|&t| tl.names.thing(t)).collect();
                // the purge author: a member of the part's path (spec/permissions.md §6), by its index
                let members: Vec<ThingId> = [c.signer].into_iter().chain(path.things.iter().copied()).chain([thing]).collect();
                let author = members.iter().position(|&m| m == c.author);
                for kind in kinds {
                    let edge = matches!(kind, Kind::Edge { .. });
                    let i = tl.w.push_marked(signer, ts, &things, tl.names.thing(thing), kind, &path.direct);
                    assert!(tl.ids[&of].contains(&i), "a world part where it was planned");
                    ids.push(i);
                    if let Some(p) = part {
                        if let (true, Body::Held(Delta::Edge(e))) = (edge, &p.body) {
                            tl.writes.insert(i, *e);
                        }
                        let x = &mut tl.w.commits[i];
                        x.needs = role(Some(need(p.aspect)));
                        x.vouchable = c.kind == CommitKind::Content && c.purge.is_empty() && p.aspect != Aspect::ROLES;
                        x.own = c.kind == CommitKind::Snapshot && c.own_cover;
                        x.purge_by = match p.purge_by {
                            PurgeBy::Admin => paths::PurgeBy::Admin,
                            PurgeBy::AuthorOrAdmin => paths::PurgeBy::AuthorOrAdmin,
                            PurgeBy::Writer => paths::PurgeBy::Writer,
                        };
                    }
                    if let (Some(ix), false) = (author, edge) {
                        tl.w.authored(i, ix.min(path.things.len() + 1));
                    }
                    // held: a part of an applied commit; an edge write on a key actor applies
                    // nothing (spec/permissions.md §1 Interim), and a delta whose path leaves its
                    // commit's purge author out holds nothing (§6)
                    let refused = if edge { tl.world.key_actor(thing) } else { author.is_none() };
                    if joined && !refused {
                        held.insert(i);
                    }
                }
            }
            if ids.len() > 1 {
                tl.w.group(&ids);
            }
        }
        // what the node could state now: a request along each path giving it write in the end
        let first = paths::judge(&tl.w, &RULES(), &View { held: held.clone(), leaves: None, trust: paths::Set::new() });
        let end = time(u64::MAX);
        let things: BTreeSet<ThingId> = sorted.iter().flat_map(|c| c.parts.iter().map(|p| p.thing)).collect();
        if tl.world.known(j.me) {
            for t in things {
                for (n, path) in tl.my_paths(&first, j.me, t, end).into_iter().enumerate() {
                    let listed: Vec<paths::Thing> = path.things.iter().map(|&x| tl.names.thing(x)).collect();
                    let i = tl.w.push_marked(tl.names.thing(j.me), end, &listed, tl.names.thing(t), Kind::Purge { names: Names::Aspect }, &path.direct);
                    tl.ids.insert(Of::Probe(t, n), vec![i]);
                    tl.probes.entry(t).or_default().push((i, path));
                    held.insert(i);
                }
            }
        }
        (tl.rd, tl.rights) = paths::judge_rights(&tl.w, &RULES(), &View { held, leaves: None, trust: paths::Set::new() });
        tl
    }

    /// The world parts of commit `c` (as joined), in the walk's order within the commit
    /// (spec/permissions.md §5.1 step 1: its edge writes on no hop of a path it states first, then
    /// those on one; in each group by thing, then holder), then its deltas and its purge requests:
    /// each with its thing and how many parts it is in the world (an addendum is one per cut its
    /// entries are against, `cuts` giving a commit's).
    fn plan(&self, c: &Commit, void: bool, cuts: &dyn Fn(CommitId) -> usize) -> Vec<(Of, ThingId, usize)> {
        let mut edges: Vec<(bool, ThingId, NodeId, usize)> = Vec::new();
        let mut rest: Vec<(Of, ThingId, usize)> = Vec::new();
        let stated = self.world.stated(c);
        for (i, p) in c.parts.iter().enumerate() {
            match &p.body {
                Body::Held(Delta::Edge(e)) if c.is_role() => edges.push((stated.contains(&(e.holder, p.thing)), p.thing, e.holder, i)),
                // a role commit's part with no body held names no holder: nothing to walk
                _ if c.is_role() && p.aspect == Aspect::ROLES => {}
                Body::Held(Delta::Addenda(es)) if c.kind == CommitKind::Content && p.aspect == Aspect::ADDENDA && !void => rest.push((Of::Part(c.id, i), p.thing, es.iter().map(|(r, _)| cuts(*r)).sum::<usize>().max(1))),
                _ => rest.push((Of::Part(c.id, i), p.thing, 1)),
            }
        }
        edges.sort();
        let requests: BTreeSet<(ThingId, bool)> = c.purge.iter().map(|it| match *it {
            PurgeItem::Commit { thing, aspect, .. } | PurgeItem::Aspect { thing, aspect } | PurgeItem::Author { thing, aspect, .. } => (thing, aspect == Aspect::CREATED),
        }).collect();
        edges.into_iter().map(|e| (Of::Part(c.id, e.3), e.1, 1)).chain(rest).chain(requests.into_iter().map(|(t, d)| (Of::Request(c.id, t, d), t, 1))).collect()
    }

    /// Every path `me` could state for `t` whose edges each give write or above in the reading's
    /// final state at `end`: the simple paths over standing edges, every hop its direct edge (a
    /// hop the world would read as a descent is marked). A writer's choice, no judging rule: each
    /// is judged as stated (`judge`'s probes).
    fn my_paths(&self, rd: &paths::Reading, me: NodeId, t: ThingId, end: u32) -> Vec<Path> {
        let gives: BTreeSet<Hop> = rd.state.iter().filter(|(e, v)| !paths::is_key(e.0) && paths::alive(**v, end) >= roles_model::Role::Write).map(|(e, _)| (self.names.id(e.0), self.names.id(e.1))).collect();
        let mut out = Vec::new();
        let mut stack = vec![vec![me]];
        while let Some(at) = stack.pop() {
            let last = *at.last().expect("a path has its signer");
            for &(_, x) in gives.iter().filter(|e| e.0 == last) {
                if at.contains(&x) {
                    continue;
                }
                let mut more = at.clone();
                more.push(x);
                if x != t {
                    stack.push(more);
                    continue;
                }
                // a hop from a thing two or more record edges above the next is a descent unless marked
                let direct = more.windows(2).enumerate().filter(|(_, p)| self.world.chain_above(p[1]).iter().position(|&o| o == p[0]).is_some_and(|d| d >= 1)).map(|(k, _)| k).collect();
                out.push(Path { things: more[1..more.len() - 1].to_vec(), direct });
            }
        }
        if me == t {
            out.push(Path::default());
        }
        out.sort();
        out
    }

    fn id(&self, of: Of) -> Option<Id> {
        self.ids.get(&of).and_then(|v| v.first()).copied()
    }

    /// Whether the settled walk applies the edge write that is part `part` of role commit `c`.
    pub fn applied_part(&self, c: CommitId, part: usize) -> bool {
        self.id(Of::Part(c, part)).is_some_and(|i| self.rd.applied.contains(&i))
    }

    /// Whether the delta that is part `part` of commit `c` is valid along its stated path
    /// (spec/permissions.md §5.2: content, addenda, snapshots, each by the role its aspect needs).
    pub fn valid_part(&self, c: CommitId, part: usize) -> bool {
        self.id(Of::Part(c, part)).is_some_and(|i| self.rd.valid.contains(&i))
    }

    fn over(&self, q: Option<Id>, d: (CommitId, usize)) -> bool {
        match (q, self.id(Of::Part(d.0, d.1))) {
            (Some(q), Some(d)) => self.rights.get(&q).is_some_and(|r| r.over(&self.w, &RULES(), q, d)),
            _ => false,
        }
    }

    /// spec/permissions.md §6: whether commit `q`'s purge request on `thing` (a destruction where
    /// its item names `created.0`) holds a right over the delta that is part `d`.
    pub fn right(&self, q: CommitId, thing: ThingId, destroy: bool, d: (CommitId, usize)) -> bool {
        self.over(self.id(Of::Request(q, thing, destroy)), d)
    }

    /// Whether part `s` (a snapshot's delta), read as a request at its key along its path, holds a
    /// right over the delta that is part `d` (spec/permissions.md §6: the same right decides
    /// whether a snapshot may drop a body it covers).
    pub fn part_right(&self, s: (CommitId, usize), d: (CommitId, usize)) -> bool {
        self.over(self.id(Of::Part(s.0, s.1)), d)
    }

    /// A path along which the node, writing now, holds a right over the delta that is part `d`
    /// of a commit on `thing`; `None` where no path it could state gives one.
    pub fn my_right(&self, thing: ThingId, d: (CommitId, usize)) -> Option<Path> {
        self.probes.get(&thing).into_iter().flatten().find(|(q, _)| self.over(Some(*q), d)).map(|(_, p)| p.clone())
    }

    /// Per thing, the first path the node could state now along which a request of its own holds
    /// write (admin first).
    pub fn writes_along(&self) -> BTreeMap<ThingId, Path> {
        let pick = |v: &Vec<(Id, Path)>| {
            let holds = |f: fn(&paths::Right) -> bool| v.iter().find(|(q, _)| self.rights.get(q).is_some_and(f)).map(|x| x.1.clone());
            holds(|r| r.admin).or_else(|| holds(|r| r.write))
        };
        self.probes.iter().filter_map(|(&t, v)| Some((t, pick(v)?))).collect()
    }

    /// The roster of `thing` in the walk's final state: each holder's grant in force (its record
    /// edge reads as a standing admin grant), whatever its `until`.
    pub fn roster(&self, thing: ThingId) -> BTreeMap<NodeId, EdgeWrite> {
        let mut out: BTreeMap<NodeId, EdgeWrite> = self.world.mint_admin(thing).into_iter().map(|a| (a, EdgeWrite::role(a, Some(Role::Admin)))).collect();
        for (e, h) in self.rd.hist.iter().filter(|(e, _)| !paths::is_key(e.0) && self.names.id(e.1) == thing) {
            let holder = self.names.id(e.0);
            match h.last().and_then(|(k, _)| self.writes.get(&k.2)) {
                Some(w) if w.role.is_some() => out.insert(holder, *w),
                _ => out.remove(&holder),
            };
        }
        out
    }

    /// The addenda that vouch: valid, their path giving write at their key.
    pub fn vouching(&self) -> usize {
        self.rd.vouching.len()
    }

    /// The `ts` values the world orders (a commit's `ts`, an `until` in `ts` units).
    pub fn times(&self) -> &[u64] {
        &self.times
    }
}
