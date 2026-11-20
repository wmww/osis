//! Where the walk along stated paths and today's walk differ (notes/a1-spec/README.md step 3,
//! For the wiring): each difference the two walks give over a node's held commits, and the
//! designed classes, each a predicate over the node's world as narrow as the draft sentence that
//! makes the difference. The shadow walk (`walk::shadow`) and the by-hand `role_paths::
//! new_walk_differs_only_by_design` read the same predicates: a difference no class takes fails
//! the test it shows in. No test is excepted by name.

use crate::engine::Core;
use crate::walk::input::{Input, Origin};
use osis_base::{CommitId, Role, Tid};
use osis_perm::paths::{Content, DeltaClass, Key, PartKind, Paths, Status, Store};
use osis_perm::{At, WriteId};
use std::collections::{BTreeMap, BTreeSet};

/// One place the two walks read differently.
#[derive(Clone, Debug, PartialEq)]
pub enum Difference {
    /// An edge write today's walk applies or not where the new one does otherwise.
    Edge { id: WriteId, signer: Tid, holder: Tid, on: Tid, old: bool, new: Option<Status> },
    /// The final roles on a thing (every `until` counted removed).
    Roles { on: Tid, old: BTreeMap<Tid, Role>, new: BTreeMap<Tid, Role> },
    /// A delta (`id`: commit, aspect index; `part`: its part in the walk's input) valid by one
    /// walk and not the other.
    Delta { id: (CommitId, usize), part: u32, signer: Tid, on: Tid, aspect: osis_base::Ak, path: Vec<Tid>, old: bool, new: Option<Content> },
}

/// A designed class: its name and the draft sentence it follows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Class {
    pub name: &'static str,
    pub draft: &'static str,
}

/// What a predicate reads: the node's held commits as the walk reads them and both walks.
pub struct World<'a, S: Store> {
    pub core: &'a Core,
    pub inputs: &'a BTreeMap<CommitId, Input>,
    pub paths: &'a Paths<S>,
}

const fn class(name: &'static str, draft: &'static str) -> Class {
    Class { name, draft }
}

/// An edge write a counting entry keeps on its vouch's thing, applied in the walk, which today's
/// walk drops at its voucher's later leave.
pub const VOUCH_OUTLIVES_LEAVE: Class = class("a vouch outlives its voucher's own leave", "permissions.md §2 Self-removal: it audits nothing (today's walk ends an entry at each later lowering of its voucher)");
/// An edge write taking a standing admin edge, applied today, applying nowhere in the walk:
/// neither its path's last edge nor its named remaining admin's edge is a standing admin edge
/// just before it. What follows from the rule: a difference that goes when the walk reads every
/// edge write as carrying the adminless mark (`classify_all`).
pub const LAST_ADMIN: Class = class("the last-admin rule is a validity rule", "permissions.md §1 The last admin: With neither it does not apply (README What A1 removes: today it is the writer's check; Open 26: a backdated timed rewrite of the remover's own edge)");
/// An invite grant along a last edge giving admin with no invite named.
pub const ADMIN_INVITES: Class = class("an admin edge gives every invite", "permissions.md §2 Path's invite: every invite where it gives admin");
/// A write applied in the walk, dropped today by a lowering on its thing that is void in the
/// walk and rests on an edge the write sets.
pub const VOID_LOWERING: Class = class("a lowering whose drops take its own authority is void", "permissions.md §5.1 step 3, keeps");
/// A part, applied or valid today, one of whose stated path's hops that is no record edge gives
/// below its role just before it here: today's walk judges by any path the signer has. Among them
/// the Interim empty path a writer states where no path serves (hostile writers in tests), the
/// Interim `[X]` of a write acting for a thing, and a hop marked direct over a grant its writer
/// held and this node does not (yet).
pub const PATH_GIVES_NOTHING: Class = class("a stated path giving nothing", "permissions.md §1 Path: nothing but the stated path judges a part (README step 2: the Interim row, a commit no path serves)");
/// A delta on a thing other than its counting entry's vouch thing: today's entry keeps the
/// commit whole.
pub const VOUCH_THING: Class = class("a vouch keeps a commit's parts on its own thing alone", "permissions.md §5.1 Vouches (perm-paths.md, Draft spec corrections: an entry keeps c's parts on its vouch's thing alone)");
/// An edge write dropped in the walk by a lowering of an edge of its stated path, applied
/// today, where today's walk gives its signer admin on its thing at the end by another path.
pub const STATED_PATH: Class = class("losing a path while another keeps the class is a fall", "permissions.md §1 Path: nothing but the stated path judges a part (README What A1 removes: §5.1 step 4's \"is no fall\")");
/// A holder's rewrite of its own edge to the value it holds, applied in the walk and not today:
/// an unchanged rewrite is a self-removal that lowers (it raises nothing) and applies.
pub const UNCHANGED_SELF: Class = class("an unchanged rewrite of one's own edge applies", "permissions.md §2 Self-removal: it lowers where it sets no component above the grant's value (an unchanged rewrite)");
/// An edge write applied today, dropped in the walk, beside another edge-class part of its commit
/// on its thing that the walk drops and today's walk does not apply: the walk drops them together
/// (a forged later redemption's no-op leave beside its spent grant).
pub const SIBLINGS: Class = class("a commit's edge-class parts on a thing fall together", "permissions.md §5.1 step 3 and Seeds (README Open 23; today's walk drops a part alone)");
/// A delta valid today, cut in the walk: its stated path gave its role just before it, an applied
/// explicit write on one of its edges ordered after it takes that role (a cut) and names it in no
/// list, and today's walk put it in no question there, so today's writer listed it nowhere: its
/// signer keeps the role on its thing by another path (today's end), or the cut is its own
/// signer's (today a list names the lowered holder's writes alone), or a held addendum or vouch
/// names it against another removal (today's blames the one its signer falls at by the role,
/// not the one cutting what it needs). At the switch the remover
/// lists, and an addendum is owed for, what rests on the cut edge (step 5's lists).
pub const STATED_CUT: Class = class("content cut on its stated path that today's lists follow the role for", "permissions.md §5.2 Content: no cut of P below r is ordered after it, else a cut's list names it; §1 Path: nothing but the stated path judges a part");
/// A hop from a thing more than `MAX_CHAIN_DEPTH` record links up: no descent (the record chain
/// ends there), so the direct edge, which is none.
pub const DEPTH: Class = class("no descent past the record chain's depth", "permissions.md §1 Hops: p is on q's record chain (spec/permissions.md §1: within MAX_CHAIN_DEPTH links)");

/// A delta valid today, cut in the walk, that a held vouch against the cut lists where the vouch
/// applies nowhere in the walk (its path gives its signer no admin on its thing): today's entry
/// counts for a voucher who could write the commit.
pub const VOUCH_ADMIN: Class = class("a vouch needs admin on its thing", "README Where the model overrode the design notes 4: a vouch is an edge-class part, applying iff its path gives admin on its thing at its key");


/// Not designed: what a pending decision owes, accepted by the shadow so the suites stay green
/// and listed in notes/perm-paths.md (The switch) as what must be empty before the switch.
/// A write acting for a thing (`act_as`): the Interim form `[X]` (its purge author off its
/// signer).
pub const ACTING: Class = class("a write acting for a thing states the Interim [X]", "README Open 16 (Tess): act_as");

/// The classes, in the order a difference is matched against them.
pub const CLASSES: &[Class] = &[UNCHANGED_SELF, VOUCH_OUTLIVES_LEAVE, LAST_ADMIN, ADMIN_INVITES, VOID_LOWERING, PATH_GIVES_NOTHING, SIBLINGS, STATED_PATH, VOUCH_THING, STATED_CUT, DEPTH, VOUCH_ADMIN];
/// Owed classes, each to be made designed or gone before the switch.
pub const OPEN: &[Class] = &[ACTING];

fn mint(core: &Core, t: &Tid) -> Option<Tid> {
    core.ix.held.created(t).and_then(|r| r.mint_admin())
}

/// The edges joining consecutive members `p`, `q` (permissions.md §1 Hops; `paths::path::joins`):
/// the record edges from `p` down to `q` within `MAX_CHAIN_DEPTH` links, else their direct edge.
fn joins(core: &Core, p: Tid, q: Tid) -> Vec<(Tid, Tid)> {
    let mut down = vec![];
    let mut t = q;
    while let Some(m) = mint(core, &t) {
        down.push((m, t));
        if m == p {
            down.reverse();
            return down;
        }
        if down.len() >= osis_base::format::MAX_CHAIN_DEPTH {
            break;
        }
        t = m;
    }
    vec![(p, q)]
}

/// Whether `p` is up `q`'s record chain past `MAX_CHAIN_DEPTH` links (and not within).
fn past_depth(core: &Core, p: Tid, q: Tid) -> bool {
    let mut t = q;
    for n in 1..=4 * osis_base::format::MAX_CHAIN_DEPTH {
        let Some(m) = mint(core, &t) else { return false };
        if m == p {
            return n > osis_base::format::MAX_CHAIN_DEPTH;
        }
        t = m;
    }
    false
}

/// A part's members [S, A1..Ak, T] (T left out for a self-removal) and their hops, a hop marked
/// direct (bit j of `direct` for members j, j + 1) by its direct edge.
fn hops(core: &Core, signer: Tid, path: &[Tid], on: Tid, leave: bool, direct: osis_base::format::PathMarks) -> Vec<(Tid, Tid)> {
    let mut members = vec![signer];
    members.extend(path);
    if !leave {
        members.push(on);
    }
    (0u32..).zip(members.windows(2)).flat_map(|(j, x)| match x {
        [a, b] if direct >> j & 1 == 1 => vec![(*a, *b)],
        [a, b] => joins(core, *a, *b),
        _ => vec![],
    }).collect()
}

/// An edge whose value just before `key` is a standing admin (admin, no `until`).
fn standing<S: Store>(w: &World<'_, S>, e: (Tid, Tid), key: &Key) -> bool {
    w.paths.value_before(&e.0, &e.1, key).is_some_and(|v| v.role == Role::Admin && v.until.is_none())
}

fn applies(s: Option<Status>) -> bool {
    matches!(s, Some(Status::Applied | Status::Invited))
}

/// The edge-write part `id` names in the walk's input (`id` is today's `WriteId`).
fn edge_part<'a, S: Store>(w: &'a World<'_, S>, id: &WriteId) -> Option<(WriteId, &'a osis_perm::paths::Part, &'a osis_perm::paths::EdgeWrite)> {
    let input = w.inputs.get(&id.0)?;
    let ix = input.origins.iter().position(|o| *o == Origin::Edge(id.1))?;
    let part = input.commit.parts.get(ix)?;
    let PartKind::Edge(e) = &part.kind else { return None };
    Some((WriteId(id.0, u32::try_from(ix).ok()?), part, e))
}

/// What commit `c`'s signed header states for thing `on`: its path [A1..Ak], marks and named
/// remaining admin, read off the header, never off the adapted input, so an excuse is computed
/// from what was written (notes/principles.md: an excuse in an oracle is a carve-out). `None`
/// for the split form, whose entries the adapter opens.
fn stated(core: &Core, c: &CommitId, on: &Tid) -> Option<(Vec<Tid>, osis_base::format::PathMarks, Option<Tid>)> {
    let h = core.ix.commits.get(c)?.header.decoded()?;
    match &h.path {
        osis_commit::Paths::One(p) => Some((p.to(on).to_vec(), p.direct, h.remains)),
        osis_commit::Paths::Split(_) => None,
    }
}

/// Whether the walk's input `i` states what its commit's header states for each part (path,
/// marks, an edge write's named remaining admin; a split commit's entries as the adapter opened
/// them): the shadow checks each input it is given, so no class reads an adapter's misreading of
/// the path or `remains` as a designed difference.
pub(crate) fn as_written(core: &Core, i: &Input) -> bool {
    i.commit.parts.iter().all(|p| {
        stated(core, &i.commit.id, &p.on).is_none_or(|(path, direct, r)| path == p.path && direct == p.direct && !matches!(&p.kind, PartKind::Edge(e) if e.remains != r))
    })
}

/// Whether today's edge write `id` (applied today, applying nowhere in the walk) falls by the
/// last-admin rule: it takes a standing admin edge, carries no adminless mark, and neither its
/// path's last edge nor its named remaining admin's edge on its thing is standing just before it.
fn last_admin<S: Store>(w: &World<'_, S>, id: &WriteId, signer: &Tid) -> bool {
    let Some((nid, part, e)) = edge_part(w, id) else { return false };
    let Some(key) = w.paths.key(&nid) else { return false };
    let on = part.on;
    let takes = standing(w, (e.holder, on), &key) && e.value.is_none_or(|v| v.role < Role::Admin || v.until.is_some());
    if !takes || e.adminless || w.paths.status(&nid) != Some(Status::Unapplied) {
        return false;
    }
    let ak = part.path.last().copied().unwrap_or(*signer);
    let leave = e.holder == ak;
    let last = (!leave).then(|| hops(w.core, *signer, &part.path, on, false, part.direct).last().copied()).flatten().filter(|l| *l == (ak, on));
    let ok = |x: (Tid, Tid)| x != (e.holder, on) && standing(w, x, &key);
    !last.is_some_and(ok) && !e.remains.is_some_and(|r| ok((r, on)))
}

/// The class of an edge write's difference (`id`: today's `WriteId`).
fn edge_class<S: Store>(w: &World<'_, S>, id: &WriteId, signer: &Tid, on: &Tid, old: bool, new: Option<Status>) -> Option<Class> {
    let (nid, part, e) = edge_part(w, id)?;
    let key = w.paths.key(&nid)?;
    if !old && new == Some(Status::Applied) && e.holder == part.path.last().copied().unwrap_or(*signer) && e.value.is_some() && w.paths.value_before(&e.holder, on, &key) == e.value {
        return Some(UNCHANGED_SELF);
    }
    if !old && applies(new) && w.paths.counting().iter().any(|(_, c, t)| *c == id.0 && t == on) {
        return Some(VOUCH_OUTLIVES_LEAVE);
    }
    if old && new == Some(Status::Unapplied) && last_admin(w, id, signer) {
        return Some(LAST_ADMIN);
    }
    // a write today's walk drops by a lowering on its thing (`Timeline::dropped`) whose part
    // there `pred` takes
    let dropped_by = |pred: &dyn Fn(&WriteId, &Tid, Option<Status>) -> bool| {
        let Some(p) = w.core.timelines.get(on).and_then(|tl| tl.dropped().get(id).copied()) else { return false };
        let Some(input) = w.inputs.get(&p.commit) else { return false };
        input.commit.parts.iter().zip(&input.origins).zip(0u32..).any(|((x, o), ix)| match (o, &x.kind) {
            (Origin::Edge(i), PartKind::Edge(_)) if x.on == *on => pred(&WriteId(p.commit, *i), &input.commit.signer, w.paths.status(&WriteId(p.commit, ix))),
            _ => false,
        })
    };
    let last = part.path.last().copied().unwrap_or(*signer);
    if !old && new == Some(Status::Invited) && w.paths.value_before(&last, on, &key).is_some_and(|v| v.role == Role::Admin && v.invite.is_none()) {
        return Some(ADMIN_INVITES);
    }
    if !old && applies(new) && dropped_by(&|_, _, st| st == Some(Status::Void)) {
        return Some(VOID_LOWERING);
    }
    if old && new == Some(Status::Dropped) && siblings_dropped(w, &nid, on) {
        return Some(SIBLINGS);
    }
    if old && new == Some(Status::Dropped) && w.core.timelines.role(signer, on, At::END) == Some(Role::Admin) {
        let mine = hops(w.core, *signer, &part.path, *on, e.holder == last, part.direct);
        if mine.iter().any(|(a, b)| w.paths.writes(a, b).iter().any(|x| x.key > key && x.explicit && x.value.is_none_or(|v| v.role < Role::Admin))) {
            return Some(STATED_PATH);
        }
    }
    if old && !applies(new) && gives_nothing(w, &hops(w.core, *signer, &part.path, *on, e.holder == last, part.direct), &key, Role::Read) {
        return Some(PATH_GIVES_NOTHING);
    }
    None
}

/// `SIBLINGS`: another edge-class part of `nid`'s commit on `on` is dropped in the walk and not
/// applied today.
fn siblings_dropped<S: Store>(w: &World<'_, S>, nid: &WriteId, on: &Tid) -> bool {
    let Some(input) = w.inputs.get(&nid.0) else { return false };
    let today = |i: u32| w.core.timelines.get(on).is_some_and(|tl| tl.is_applied(&WriteId(nid.0, i)));
    (0u32..).zip(input.commit.parts.iter().zip(&input.origins)).any(|(x, (p, o))| x != nid.1 && p.on == *on && matches!(o, Origin::Edge(i) if !today(*i)) && w.paths.status(&WriteId(nid.0, x)) == Some(Status::Dropped))
}

/// Whether one of `hops` that is no record edge (a direct edge, a marked hop's among them) gives
/// below `r` just before `key`: today's walk judges by any path the signer has.
fn gives_nothing<S: Store>(w: &World<'_, S>, hops: &[(Tid, Tid)], key: &Key, r: Role) -> bool {
    hops.iter().any(|(a, b)| a != b && mint(w.core, b) != Some(*a) && w.paths.role_before(a, b, key) < Some(r))
}


/// Whether delta `nid` (needing `needs`) is cut in the walk where today's lists follow the role
/// (`STATED_CUT`): its hops each gave `needs` just before its position, an applied cut below
/// `needs` on one of them is ordered after it, and either today's walk gives its signer `needs` on
/// its thing at the end, or that cut is its own signer's.
fn stated_cut<S: Store>(w: &World<'_, S>, nid: &WriteId, signer: &Tid, on: &Tid, needs: Role) -> bool {
    let Some((hops, pos)) = w.paths.rests(nid) else { return false };
    if !hops.iter().all(|(a, b)| w.paths.role_before(a, b, &pos) >= Some(needs)) {
        return false;
    }
    let elsewhere = w.core.timelines.role(signer, on, At::END) >= Some(needs);
    // an addendum or vouch held names it against a removal other than the cut: today's lists
    // blame the removal its signer falls at by the role
    let blamed = |cut: &CommitId| {
        w.inputs.values().flat_map(|i| &i.commit.parts).any(|p| match &p.kind {
            PartKind::Delta(d) => matches!(&d.class, DeltaClass::Addendum { removal, list } if removal != cut && list.commits().contains(&nid.0)),
            PartKind::Vouch { removal, list } => removal != cut && list.commits().contains(&nid.0),
            PartKind::Edge(_) => false,
        })
    };
    hops.iter().any(|(a, b)| w.paths.writes(a, b).iter().any(|x| x.key >= pos && x.cuts(needs) && (elsewhere || x.key.signer == *signer || blamed(&x.key.commit))))
}

/// `VOUCH_ADMIN`: delta `nid`'s hops each gave `needs` just before it, and a cut below `needs`
/// ordered after it on one of them is the removal a held vouch lists its commit against, the
/// vouch unapplied in the walk.
fn vouch_admin<S: Store>(w: &World<'_, S>, nid: &WriteId, needs: Role) -> bool {
    let Some((hops, pos)) = w.paths.rests(nid) else { return false };
    if !hops.iter().all(|(a, b)| w.paths.role_before(a, b, &pos) >= Some(needs)) {
        return false;
    }
    let vouched = |cut: &CommitId| {
        w.inputs.values().any(|i| (0u32..).zip(&i.commit.parts).any(|(x, p)| matches!(&p.kind, PartKind::Vouch { removal, list } if removal == cut && list.commits().contains(&nid.0)) && w.paths.status(&WriteId(i.commit.id, x)) == Some(Status::Unapplied)))
    };
    hops.iter().any(|(a, b)| w.paths.writes(a, b).iter().any(|x| x.key >= pos && x.cuts(needs) && vouched(&x.key.commit)))
}

/// `VOUCH_THING`: a counting entry keeps commit `c` on its vouch's thing alone, where today's
/// keeps the commit whole or not at all: a delta of `c` on `on`, valid today with every entry for
/// `c` on another thing; or valid in the walk as listed with an entry for `c` on `on` and a part of
/// `c` on another thing.
fn vouch_thing<S: Store>(w: &World<'_, S>, c: &CommitId, on: &Tid, old: bool, new: Option<&Content>) -> bool {
    let things: BTreeSet<Tid> = w.paths.counting().iter().filter(|(_, x, _)| x == c).map(|x| x.2).collect();
    if old {
        return !things.is_empty() && !things.contains(on);
    }
    matches!(new, Some(Content::Valid(osis_perm::paths::By::Listed))) && things.contains(on) && w.core.ix.commits.get(c).is_some_and(|m| m.view.aspects.iter().any(|a| a.tid != *on))
}

/// The designed class `d` falls in, if any: an edge write's by its own predicate; a delta's or a
/// roster's by its own, else by a classified edge-write difference it follows (a delta: an edge
/// write of its own commit on its thing, or one on an edge of its stated path; a roster: per
/// holder whose role differs, one setting or signed by that holder on the thing).
pub fn classify<S: Store>(w: &World<'_, S>, d: &Difference, all: &[Difference]) -> Option<Class> {
    let edges = || {
        all.iter().filter_map(|x| match x {
            Difference::Edge { id, signer, holder, on, old, new } => Some((id, signer, holder, on, edge_class(w, id, signer, on, *old, *new))),
            _ => None,
        })
    };
    match d {
        Difference::Edge { id, signer, on, old, new, .. } => edge_class(w, id, signer, on, *old, *new).or_else(|| acting(w, &id.0)),
        Difference::Roles { on, old, new } => {
            let moved: BTreeSet<&Tid> = old.keys().chain(new.keys()).filter(|h| old.get(*h) != new.get(*h)).collect();
            let classed: Vec<_> = edges().filter(|(_, _, _, t, c)| *t == on && c.is_some()).collect();
            let first = classed.first().and_then(|x| x.4);
            moved.iter().all(|h| classed.iter().any(|(_, s, x, _, _)| *x == *h || *s == *h)).then_some(first).flatten()
        }
        Difference::Delta { id, part, signer, on, path, old, new, .. } => {
            let nid = WriteId(id.0, *part);
            let needs = match w.inputs.get(&id.0).and_then(|i| i.commit.parts.get(*part as usize)).map(|p| &p.kind) {
                Some(PartKind::Delta(x)) => x.needs,
                _ => Role::Write,
            };
            let hops: Vec<(Tid, Tid)> = w.paths.rests(&nid).map(|x| x.0).unwrap_or_default();
            let pos = w.paths.rests(&nid).map(|x| x.1);
            let followed = edges().find(|(e, _, h, t, c)| c.is_some() && ((e.0 == id.0 && *t == on) || hops.contains(&(**h, **t)))).and_then(|x| x.4);
            followed
                .or_else(|| (*old && std::iter::once(*signer).chain(path.iter().copied()).chain([*on]).collect::<Vec<_>>().windows(2).any(|x| matches!(x, [a, b] if past_depth(w.core, *a, *b)))).then_some(DEPTH))
                .or_else(|| (*old && pos.as_ref().is_some_and(|k| gives_nothing(w, &hops, k, needs))).then_some(PATH_GIVES_NOTHING))
                .or_else(|| vouch_thing(w, &id.0, on, *old, new.as_ref()).then_some(VOUCH_THING))
                .or_else(|| (*old && stated_cut(w, &nid, signer, on, needs)).then_some(STATED_CUT))
                .or_else(|| (*old && vouch_admin(w, &nid, needs)).then_some(VOUCH_ADMIN))
                .or_else(|| acting(w, &id.0))
        }
    }
}

/// Each difference's class (`classify`); where some stay unclassed, those that go when the walk
/// reads every edge write as carrying the adminless mark (the last-admin rule off, as today's walk
/// reads it: a walk from scratch over that input), or that a designed class takes there, follow
/// from the rule and take `LAST_ADMIN`: a write the rule stops in one pass changes what later
/// parts read, and a verdict given then stands (README Open 13); then what follows a classified
/// difference (`follow`).
pub fn classify_all<S: Store>(w: &World<'_, S>, all: &[Difference]) -> Vec<Option<Class>> {
    let mut out: Vec<Option<Class>> = all.iter().map(|d| classify(w, d, all)).collect();
    // the last-admin rule off: every edge write read as carrying the adminless mark
    counterfactual(w, all, &mut out, LAST_ADMIN, |_, p| {
        if let PartKind::Edge(e) = &mut p.kind {
            e.adminless = true;
        }
        true
    });
    follow(w, all, &mut out);
    out
}

fn is_edge(d: &Difference, f: &dyn Fn(&WriteId, &Tid, &Tid, &Tid) -> bool) -> bool {
    matches!(d, Difference::Edge { id, signer, holder, on, .. } if f(id, signer, holder, on))
}

/// What follows a classified difference takes its class, until nothing moves: an edge write
/// today's walk drops by a lowering whose own difference is classified, or along an edge a
/// classified edge write sets; a delta beside or along a
/// classified edge write (as `classify`); a roster whose every moved holder a classified edge
/// write on the thing sets or signs.
fn follow<S: Store>(w: &World<'_, S>, all: &[Difference], out: &mut [Option<Class>]) {
    loop {
        let mut moved = false;
        for i in 0..all.len() {
            if out.get(i).is_some_and(Option::is_some) {
                continue;
            }
            let classed = |pred: &dyn Fn(&Difference) -> bool| all.iter().zip(out.iter()).find(|(d, c)| c.is_some() && pred(d)).and_then(|x| *x.1);
            let c = match all.get(i) {
                Some(Difference::Edge { id, signer, on, .. }) => {
                    let dropper = w.core.timelines.get(on).and_then(|tl| tl.dropped().get(id).copied());
                    let hops = edge_part(w, id).map(|(_, p, e)| hops(w.core, *signer, &p.path, *on, e.holder == p.path.last().copied().unwrap_or(*signer), p.direct)).unwrap_or_default();
                    dropper.and_then(|p| classed(&|d| is_edge(d, &|l, _, _, t| l.0 == p.commit && t == on))).or_else(|| classed(&|d| is_edge(d, &|_, _, h, t| hops.contains(&(*h, *t)))))
                }
                Some(Difference::Delta { id, part, on, .. }) => {
                    let hops: Vec<(Tid, Tid)> = w.paths.rests(&WriteId(id.0, *part)).map(|x| x.0).unwrap_or_default();
                    classed(&|d| is_edge(d, &|e, _, h, t| (e.0 == id.0 && t == on) || hops.contains(&(*h, *t))))
                }
                Some(Difference::Roles { on, old, new }) => {
                    let moved: Vec<&Tid> = old.keys().chain(new.keys()).filter(|h| old.get(*h) != new.get(*h)).collect();
                    let first = classed(&|d| is_edge(d, &|_, _, _, t| t == on));
                    first.filter(|_| moved.iter().all(|m| classed(&|d| is_edge(d, &|_, s, h, t| t == on && (h == *m || s == *m))).is_some()))
                }
                None => None,
            };
            if let (Some(c), Some(slot)) = (c, out.get_mut(i)) {
                *slot = Some(c);
                moved = true;
            }
        }
        if !moved {
            return;
        }
    }
}

/// Where some of `all` stay unclassed in `out`: the walk from scratch over the input `keep`
/// rewrites (a part dropped where it answers false), and every unclassed difference that is not
/// among its differences, or that a designed class takes there, takes `class`. A delta's difference is compared without its part
/// index, which leaving parts out moves.
fn counterfactual<S: Store>(w: &World<'_, S>, all: &[Difference], out: &mut [Option<Class>], class: Class, keep: impl Fn(&WriteId, &mut osis_perm::paths::Part) -> bool) {
    if out.iter().all(Option::is_some) {
        return;
    }
    let mut inputs = w.inputs.clone();
    for i in inputs.values_mut() {
        let id = i.commit.id;
        let (mut parts, mut origins) = (Vec::new(), Vec::new());
        for ((x, mut p), o) in (0u32..).zip(std::mem::take(&mut i.commit.parts)).zip(std::mem::take(&mut i.origins)) {
            if keep(&WriteId(id, x), &mut p) {
                parts.push(p);
                origins.push(o);
            }
        }
        (i.commit.parts, i.origins) = (parts, origins);
    }
    inputs.retain(|_, i| !i.commit.parts.is_empty());
    let commits: Vec<_> = inputs.values().map(|i| i.commit.clone()).collect();
    let paths = Paths::evaluate(&crate::walk::input::records(w.core), crate::walk::input::trust(w.core, &inputs), &commits);
    let norm = |d: &Difference| match d {
        Difference::Delta { id, signer, on, aspect, path, old, new, .. } => Difference::Delta { id: *id, part: 0, signer: *signer, on: *on, aspect: aspect.clone(), path: path.clone(), old: *old, new: *new },
        x => x.clone(),
    };
    // what stays there is explained where a designed class takes it there
    let cw = World { core: w.core, inputs: &inputs, paths: &paths };
    let there = differences(w.core, &inputs, &paths);
    let mut classed: Vec<Option<Class>> = there.iter().map(|d| classify(&cw, d, &there)).collect();
    follow(&cw, &there, &mut classed);
    let left: Vec<Difference> = there.iter().zip(&classed).filter(|(_, c)| c.is_none()).map(|(d, _)| norm(d)).collect();
    let all_there: Vec<Difference> = there.iter().map(norm).collect();
    for (c, d) in out.iter_mut().zip(all) {
        if c.is_none() && (!all_there.contains(&norm(d)) || !left.contains(&norm(d))) {
            *c = Some(class);
        }
    }
}

/// `ACTING` (owed, Open 16): commit `c` acts for a thing (its purge author is not its signer).
fn acting<S: Store>(w: &World<'_, S>, c: &CommitId) -> Option<Class> {
    let m = w.core.ix.commits.get(c)?;
    (m.view.purge_author != m.view.signer).then_some(ACTING)
}

/// Every place today's walk at `core` and `paths` (the new walk over `inputs`) read differently:
/// per adapted edge write whether it applies, per thing written its final roles, per adapted
/// delta whether it is valid.
pub fn differences<S: Store>(core: &Core, inputs: &BTreeMap<CommitId, Input>, paths: &Paths<S>) -> Vec<Difference> {
    let mut out = Vec::new();
    let mut targets = std::collections::BTreeSet::new();
    for (id, input) in inputs {
        let meta = core.ix.commits.get(id);
        for ((ix, part), origin) in (0u32..).zip(&input.commit.parts).zip(&input.origins) {
            let nid = WriteId(*id, ix);
            match (origin, &part.kind) {
                (Origin::Edge(i), PartKind::Edge(e)) => {
                    targets.insert(part.on);
                    let old = core.timelines.get(&part.on).is_some_and(|tl| tl.is_applied(&WriteId(*id, *i)));
                    let new = paths.status(&nid);
                    if old != matches!(new, Some(Status::Applied | Status::Invited)) {
                        out.push(Difference::Edge { id: WriteId(*id, *i), signer: input.commit.signer, holder: e.holder, on: part.on, old, new });
                    }
                }
                (Origin::Delta(ai), PartKind::Delta(d)) => {
                    let old = meta.is_some_and(|m| m.valid.get(*ai).copied().unwrap_or(false));
                    let new = paths.content(&nid);
                    if old != crate::walk::verdict::delta_valid(core, paths, input, ix as usize) {
                        out.push(Difference::Delta { id: (*id, *ai), part: ix, signer: input.commit.signer, on: part.on, aspect: d.aspect.clone(), path: part.path.clone(), old, new });
                    }
                }
                _ => {}
            }
        }
    }
    let mut finals: BTreeMap<Tid, BTreeMap<Tid, Role>> = BTreeMap::new();
    for ((holder, target), (role, _)) in paths.finals() {
        targets.insert(target);
        if let Some(r) = role {
            finals.entry(target).or_default().insert(holder, r);
        }
    }
    for t in targets {
        let Some(tl) = core.timelines.get(&t) else { continue };
        let edges = tl.edges_at(None);
        let old: BTreeMap<Tid, Role> = edges.holders(&t).filter(|(_, x)| x.until.is_none()).map(|(m, x)| (*m, x.role)).collect();
        let new = finals.remove(&t).unwrap_or_default();
        if old != new {
            out.push(Difference::Roles { on: t, old, new });
        }
    }
    out
}
