//! Certificate copies cut per sync ID (spec/permissions.md §4 Copies): a copy of commit c on a
//! thing x outside S's sync unit holds c's header and S's cut of it, the parts of c on x that S's
//! readers read there (each whole), closed over the evidence of each; never a part they neither
//! open nor judge by. Greenfield, apart from `evaluate`: the question is only which parts a reader
//! of S holds, so the walk is cut down to what tells the parts apart (a grant write applies by
//! admin or as a may-grant grant; no lowering is judged; one key role, read, as Depth0.tla).
//!
//! The world: an account A (mint admin node 1) whose nodes 1..=k are granted on A, rotate their
//! own keysets and A; T, minted with admin A, is S's thing and its whole unit; nodes write T along
//! [node, A, T] and rotate T, boxing A at an epoch of A; X (mint admin XA) grants T read, T's unit
//! referencing X (X's stub there: T the holder on its chain), by XA or by H, a holder of read with the may-grant flag. The reader R of S
//! holds T's bodies, the copies S needs, and some of the nodes' keysets by another route (as a
//! node in the nodes' own world would).
//!
//! What R judges (`Seen`): each body's verdict, which of T's epochs it may encrypt under (blocked
//! where T's box to A names an epoch of A that is superseded or has a stale box at R: R holds
//! none of A's boxes, so by order alone; a rotation's box records are for Foreign, not modelled),
//! A's keysets it holds valid (what it seals T to A at), the epochs of X whose secret it takes
//! from boxes to T, and X's steps. `whole` is every role-class part of each commit a cut names;
//! `cut` is the rule (`Rule::Spec`) or a control.
use crate::gen::Rng;
use std::collections::{BTreeMap, BTreeSet};

pub type Id = u32;
pub type Cid = u32;

pub const A: Id = 10;
pub const T: Id = 20;
pub const X: Id = 30;
pub const XA: Id = 31;
pub const H: Id = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Role {
    Sync,
    Read,
    Write,
    Admin,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Ak {
    Roles,
    Secrets,
    Keys,
    Sync,
    Content,
}

pub const ROLE_CLASS: [Ak; 4] = [Ak::Roles, Ak::Secrets, Ak::Keys, Ak::Sync];

#[derive(Clone, Copy, Debug)]
pub struct Edge {
    pub holder: Id,
    pub role: Option<Role>,
    pub may_grant: bool,
}

/// A box of the commit's thing at `epoch`, role `role`, to `holder`, naming the holder's keyset
/// `keyset` (0 for a holder whose keysets are not modelled).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct BoxAt {
    pub holder: Id,
    pub role: Role,
    pub epoch: u32,
    pub keyset: u32,
}

#[derive(Clone, Debug)]
pub enum Delta {
    Roles(Vec<Edge>),
    Secrets(Vec<BoxAt>),
    /// A keyset of `epoch` (listing every earlier epoch).
    Keys { keyset: u32 },
    Sync,
    Content,
}

impl Delta {
    pub fn ak(&self) -> Ak {
        match self {
            Delta::Roles(_) => Ak::Roles,
            Delta::Secrets(_) => Ak::Secrets,
            Delta::Keys { .. } => Ak::Keys,
            Delta::Sync => Ak::Sync,
            Delta::Content => Ak::Content,
        }
    }
}

/// A commit writing one thing, along `hops` (its stated path's edges, (holder, target); empty for
/// a thing minted with a key writing itself).
#[derive(Clone, Debug)]
pub struct Commit {
    pub id: Cid,
    pub signer: Id,
    pub thing: Id,
    pub hops: Vec<(Id, Id)>,
    pub ts: u32,
    pub parts: Vec<Delta>,
}

impl Commit {
    fn part(&self, ak: Ak) -> Option<&Delta> {
        self.parts.iter().find(|d| d.ak() == ak)
    }
}

#[derive(Clone, Debug, Default)]
pub struct World {
    pub commits: Vec<Commit>,
    /// thing -> mint admin (record grants: admin, may grant)
    pub records: BTreeMap<Id, Id>,
    /// the nodes' keyset commits R holds by another route
    pub known: Vec<Cid>,
}

/// Which cut a reader of S holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rule {
    /// spec/permissions.md §4 Copies.
    Spec,
    /// Control: evidence closed over grant-class and `sync.0` parts only (a `keys.0` or `secrets.0`
    /// part brings none).
    NoPartEvidence,
}

pub type Held = BTreeSet<(Cid, Ak)>;

impl World {
    fn commit(&self, c: Cid) -> &Commit {
        self.commits.iter().find(|x| x.id == c).expect("commit")
    }

    fn record_edge(&self, h: Id, y: Id) -> bool {
        self.records.get(&y) == Some(&h)
    }

    /// The copies (part refs) evidence of `c` names: every grant write on each hop of its path that
    /// is no record grant (spec/permissions.md §4 Evidence of a commit).
    fn evidence_of(&self, c: &Commit) -> Vec<(Cid, Ak)> {
        let mut out = Vec::new();
        for &(h, y) in &c.hops {
            if self.record_edge(h, y) {
                continue;
            }
            for d in self.commits.iter().filter(|d| d.thing == y) {
                if let Some(Delta::Roles(es)) = d.part(Ak::Roles) {
                    if es.iter().any(|e| e.holder == h) {
                        out.push((d.id, Ak::Roles));
                    }
                }
            }
        }
        out
    }

    /// The parts of things outside the unit that S's required set names, as `rule` cuts them,
    /// with T's bodies and R's keysets from elsewhere.
    pub fn cut(&self, rule: Rule) -> Held {
        let mut need: Held = BTreeSet::new();
        // T's bodies (the unit) bring their evidence
        for c in self.commits.iter().filter(|c| c.thing == T) {
            need.extend(self.evidence_of(c));
        }
        // X's stub in T's unit: the grant writes naming T, the boxes to T, X's steps
        for c in self.commits.iter().filter(|c| c.thing == X) {
            for d in &c.parts {
                let named = match d {
                    Delta::Roles(es) => es.iter().any(|e| e.holder == T),
                    Delta::Secrets(bs) => bs.iter().any(|b| b.holder == T),
                    Delta::Sync => true,
                    _ => false,
                };
                if named {
                    need.insert((c.id, d.ak()));
                }
            }
        }
        // A's keys (A holds a role on T): its current `keys.0` commits (the newest keysets) and,
        // carried, those of the epochs T's boxes to A name
        let newest = self.commits.iter().filter(|c| c.thing == A).filter_map(|c| match c.part(Ak::Keys) {
            Some(Delta::Keys { keyset }) => Some(*keyset),
            _ => None,
        });
        let mut epochs: BTreeSet<u32> = newest.max().into_iter().collect();
        for c in self.commits.iter().filter(|c| c.thing == T) {
            if let Some(Delta::Secrets(bs)) = c.part(Ak::Secrets) {
                epochs.extend(bs.iter().filter(|b| b.holder == A).map(|b| b.keyset));
            }
        }
        for c in self.commits.iter().filter(|c| c.thing == A) {
            if let Some(Delta::Keys { keyset }) = c.part(Ak::Keys) {
                if epochs.contains(keyset) {
                    need.insert((c.id, Ak::Keys));
                }
            }
        }
        // a box travels with its commit's grant writes on the thing (the stub holds them already:
        // the `roles.0` part naming its holder)
        let deps: Vec<(Cid, Ak)> = need.iter().filter(|(c, ak)| *ak == Ak::Secrets && self.commit(*c).part(Ak::Roles).is_some()).map(|(c, _)| (*c, Ak::Roles)).collect();
        need.extend(deps);
        // closed over the evidence of each named part
        let mut work: Vec<(Cid, Ak)> = need.iter().copied().collect();
        while let Some((c, ak)) = work.pop() {
            if rule == Rule::NoPartEvidence && matches!(ak, Ak::Secrets | Ak::Keys) {
                continue;
            }
            for p in self.evidence_of(self.commit(c)) {
                if need.insert(p) {
                    work.push(p);
                }
            }
        }
        self.with_own(need)
    }

    /// Every role-class part of each commit the rule's cut names (today's whole copies).
    pub fn whole(&self) -> Held {
        let named: BTreeSet<Cid> = self.cut(Rule::Spec).into_iter().map(|(c, _)| c).collect();
        let mut out = Held::new();
        for c in self.commits.iter().filter(|c| named.contains(&c.id) && c.thing != T) {
            out.extend(c.parts.iter().map(|d| (c.id, d.ak())).filter(|(_, ak)| ROLE_CLASS.contains(ak)));
        }
        self.with_own(out)
    }

    fn with_own(&self, mut held: Held) -> Held {
        held.retain(|(c, _)| self.commit(*c).thing != T && !self.known.contains(c));
        for c in self.commits.iter().filter(|c| c.thing == T) {
            held.extend(c.parts.iter().map(|d| (c.id, d.ak())));
        }
        held.extend(self.known.iter().map(|c| (*c, Ak::Keys)));
        held
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum V {
    Valid,
    Invalid,
    Pending,
}

/// What R reads and may do, from the parts it holds.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Seen {
    pub bodies: BTreeMap<Cid, V>,
    /// T's rotations (their verdicts), and those whose epoch R may not encrypt under.
    pub t_rotations: BTreeMap<Cid, V>,
    pub t_blocked: BTreeSet<Cid>,
    /// A's keysets R holds valid (what it seals T to A at).
    pub a_keysets: BTreeSet<u32>,
    /// The epochs of X whose secret R takes from a box to T.
    pub x_taken: BTreeSet<u32>,
    pub x_steps: BTreeMap<Cid, V>,
}

struct Judge<'a> {
    w: &'a World,
    held: &'a Held,
    /// held grant writes in key order: (key, thing, signer, edges applied)
    walk: Vec<((u32, Cid), Id, Vec<(Edge, bool)>)>,
    roles: BTreeMap<Cid, V>,
}

impl<'a> Judge<'a> {
    fn new(w: &'a World, held: &'a Held) -> Judge<'a> {
        let mut j = Judge { w, held, walk: Vec::new(), roles: BTreeMap::new() };
        let mut cs: Vec<&Commit> = w.commits.iter().filter(|c| held.contains(&(c.id, Ak::Roles))).collect();
        cs.sort_by_key(|c| (c.ts, c.id));
        for c in cs {
            let Some(Delta::Roles(es)) = c.part(Ak::Roles) else { continue };
            let &(s, x) = c.hops.last().expect("a grant write states its hop");
            if j.pending(s, x) {
                j.roles.insert(c.id, V::Pending);
                continue;
            }
            let state = j.state_before((c.ts, c.id));
            let by = state.get(&(s, x)).copied();
            let mut applied = Vec::new();
            for e in es {
                let ok = match by {
                    Some((Role::Admin, _)) => true,
                    Some((r, true)) => e.role.is_some_and(|g| g <= r) && !state.contains_key(&(e.holder, x)),
                    _ => false,
                };
                applied.push((*e, ok));
            }
            let v = if applied.iter().all(|(_, ok)| *ok) { V::Valid } else { V::Invalid };
            j.roles.insert(c.id, v);
            j.walk.push(((c.ts, c.id), x, applied));
        }
        j
    }

    /// A hop is unjudgeable while no held grant write sets it and it is no record grant.
    fn pending(&self, h: Id, y: Id) -> bool {
        if self.w.record_edge(h, y) {
            return false;
        }
        !self.w.commits.iter().any(|c| {
            c.thing == y
                && self.held.contains(&(c.id, Ak::Roles))
                && matches!(c.part(Ak::Roles), Some(Delta::Roles(es)) if es.iter().any(|e| e.holder == h))
        })
    }

    fn state_before(&self, key: (u32, Cid)) -> BTreeMap<(Id, Id), (Role, bool)> {
        let mut s: BTreeMap<(Id, Id), (Role, bool)> = self.w.records.iter().map(|(t, m)| ((*m, *t), (Role::Admin, true))).collect();
        for (k, x, applied) in &self.walk {
            if *k >= key {
                break;
            }
            for (e, ok) in applied {
                if !ok {
                    continue;
                }
                match e.role {
                    Some(r) => {
                        s.insert((e.holder, *x), (r, e.may_grant));
                    }
                    None => {
                        s.remove(&(e.holder, *x));
                    }
                }
            }
        }
        s
    }

    /// A delta needing `need` along `c`'s path: every hop giving it just before `c`'s key.
    fn along(&self, c: &Commit, need: Role) -> V {
        if c.hops.iter().any(|&(h, y)| self.pending(h, y)) {
            return V::Pending;
        }
        let s = self.state_before((c.ts, c.id));
        if c.hops.iter().all(|hop| s.get(hop).is_some_and(|(r, _)| *r >= need)) {
            V::Valid
        } else {
            V::Invalid
        }
    }

    /// A role-class part other than `roles.0` (spec/permissions.md §3; §2 May-grant grant: boxes
    /// to its grantees only, judged from the commit alone).
    fn part(&self, c: &Commit, ak: Ak) -> V {
        if c.hops.is_empty() {
            // a thing minted with a key writing itself by its record's key
            return V::Valid;
        }
        let boxes: Vec<BoxAt> = match c.part(ak) {
            Some(Delta::Secrets(bs)) => bs.clone(),
            Some(Delta::Keys { .. }) => Vec::new(),
            Some(Delta::Sync) => return self.along(c, Role::Admin),
            _ => return V::Invalid,
        };
        if self.held.contains(&(c.id, Ak::Roles)) && self.roles.get(&c.id) == Some(&V::Valid) {
            if let Some(Delta::Roles(es)) = c.part(Ak::Roles) {
                if boxes.iter().all(|b| es.iter().any(|e| e.holder == b.holder && e.role.is_some_and(|g| g >= b.role))) {
                    return V::Valid;
                }
            }
        }
        let need = boxes.iter().map(|b| b.role).max().unwrap_or(Role::Write).max(Role::Write);
        self.along(c, need)
    }

    fn seen(&self) -> Seen {
        let w = self.w;
        let mut out = Seen::default();
        let valid = |c: &Commit, ak: Ak| self.held.contains(&(c.id, ak)) && self.part(c, ak) == V::Valid;
        // A's keysets: R reads none of A's boxes, so an epoch of A is blocked by order alone
        for c in w.commits.iter().filter(|c| c.thing == A) {
            if valid(c, Ak::Keys) {
                if let Some(Delta::Keys { keyset }) = c.part(Ak::Keys) {
                    out.a_keysets.insert(*keyset);
                }
            }
        }
        let newest_a = out.a_keysets.iter().max().copied();
        let blocked_a = |e: u32| newest_a.is_some_and(|n| e < n);
        // T: bodies along [node, A, T]; rotations boxing A
        for c in w.commits.iter().filter(|c| c.thing == T) {
            match c.part(Ak::Secrets) {
                Some(Delta::Secrets(bs)) => {
                    let v = self.along(c, Role::Write);
                    out.t_rotations.insert(c.id, v);
                    if v == V::Valid && bs.iter().any(|b| b.holder == A && blocked_a(b.keyset)) {
                        out.t_blocked.insert(c.id);
                    }
                }
                _ => {
                    out.bodies.insert(c.id, self.along(c, Role::Write));
                }
            }
        }
        // X: the boxes to T R takes, X's steps
        for c in w.commits.iter().filter(|c| c.thing == X) {
            if valid(c, Ak::Secrets) {
                if let Some(Delta::Secrets(bs)) = c.part(Ak::Secrets) {
                    out.x_taken.extend(bs.iter().filter(|b| b.holder == T).map(|b| b.epoch));
                }
            }
            if self.held.contains(&(c.id, Ak::Sync)) {
                out.x_steps.insert(c.id, self.part(c, Ak::Sync));
            }
        }
        out
    }
}

/// What R reads holding `held`.
pub fn judge(w: &World, held: &Held) -> Seen {
    Judge::new(w, held).seen()
}

/// Holders of the generator's truth.
#[derive(Default)]
struct Truth {
    a: BTreeMap<Id, (Role, bool)>,
    x: BTreeMap<Id, (Role, bool)>,
    keyset: BTreeMap<Id, u32>,
    a_epoch: u32,
    x_epoch: u32,
    t_epoch: u32,
}

/// A random world of `seed`: an account of two to four nodes, four to fourteen events.
pub fn world(seed: u64) -> World {
    let mut r = Rng::new(seed ^ 0xC0C7);
    let k = 2 + r.below(3) as Id;
    let nodes: Vec<Id> = (1..=k).collect();
    let mut w = World { records: BTreeMap::from([(A, 1), (T, A), (X, XA)]), ..World::default() };
    let mut t = Truth { a: BTreeMap::from([(1, (Role::Admin, true))]), x: BTreeMap::from([(XA, (Role::Admin, true))]), ..Truth::default() };
    for n in &nodes {
        t.keyset.insert(*n, 0);
    }
    let mut id: Cid = 100;
    let mut ts: u32 = 0;
    let mut push = |w: &mut World, signer: Id, thing: Id, hops: Vec<(Id, Id)>, parts: Vec<Delta>| -> Cid {
        id += 1;
        ts += 1;
        w.commits.push(Commit { id, signer, thing, hops, ts, parts });
        id
    };
    let rd = |holder, epoch, keyset| BoxAt { holder, role: Role::Read, epoch, keyset };
    // A's and X's mintings, T's first rotation boxing A
    let b = vec![rd(1, 0, 0)];
    push(&mut w, 1, A, vec![(1, A)], vec![Delta::Keys { keyset: 0 }, Delta::Secrets(b), Delta::Sync]);
    push(&mut w, XA, X, vec![(XA, X)], vec![Delta::Keys { keyset: 0 }, Delta::Secrets(vec![]), Delta::Sync]);
    push(&mut w, 1, T, vec![(1, A), (A, T)], vec![Delta::Secrets(vec![rd(A, 0, 0)])]);
    let events = 4 + r.below(11);
    for _ in 0..events {
        // a box to a node names its current keyset, or (a sealer behind) an older one
        let seen_keyset = |r: &mut Rng, t: &Truth, n: Id| {
            let m = t.keyset[&n];
            if m > 0 && r.chance(30) {
                m - 1
            } else {
                m
            }
        };
        match r.below(12) {
            0..=2 => {
                // a grant on A: by an admin, or by a holder with the may-grant flag
                let granters: Vec<Id> = t.a.iter().filter(|(_, (ro, mg))| *ro == Role::Admin || *mg).map(|(n, _)| *n).collect();
                let s = r.pick(&granters);
                let (sr, _) = t.a[&s];
                let free: Vec<Id> = nodes.iter().copied().filter(|n| !t.a.contains_key(n)).collect();
                let g = if sr == Role::Admin && (free.is_empty() || r.chance(25)) { r.pick(&nodes[1..]) } else if free.is_empty() { continue } else { r.pick(&free) };
                if g == 1 || g == s {
                    continue;
                }
                let roles = [Role::Read, Role::Write, Role::Admin];
                let role = r.pick(&roles[..if sr == Role::Admin { 3 } else { roles.iter().position(|x| *x == sr).unwrap() + 1 }]);
                let mg = r.chance(40);
                let mut boxes = vec![rd(g, t.a_epoch, seen_keyset(&mut r, &t, g))];
                if r.chance(15) {
                    // junk beside the grantee's box: a box to a node the commit grants nothing
                    let o = r.pick(&nodes);
                    if o != g {
                        boxes.push(rd(o, t.a_epoch, t.keyset[&o]));
                    }
                }
                push(&mut w, s, A, vec![(s, A)], vec![Delta::Roles(vec![Edge { holder: g, role: Some(role), may_grant: mg }]), Delta::Secrets(boxes)]);
                if sr == Role::Admin || !t.a.contains_key(&g) {
                    t.a.insert(g, (role, mg));
                }
            }
            3 | 4 => {
                // a rotation of A by an admin, boxing every holder
                let admins: Vec<Id> = t.a.iter().filter(|(_, (ro, _))| *ro == Role::Admin).map(|(n, _)| *n).collect();
                let s = r.pick(&admins);
                t.a_epoch += 1;
                let holders: Vec<Id> = t.a.keys().copied().collect();
                let boxes: Vec<BoxAt> = holders.into_iter().map(|n| rd(n, t.a_epoch, seen_keyset(&mut r, &t, n))).collect();
                push(&mut w, s, A, vec![(s, A)], vec![Delta::Keys { keyset: t.a_epoch }, Delta::Secrets(boxes)]);
            }
            5 => {
                // an admin removes a node
                let admins: Vec<Id> = t.a.iter().filter(|(_, (ro, _))| *ro == Role::Admin).map(|(n, _)| *n).collect();
                let s = r.pick(&admins);
                let others: Vec<Id> = t.a.keys().copied().filter(|n| *n != 1 && *n != s).collect();
                if others.is_empty() {
                    continue;
                }
                let g = r.pick(&others);
                push(&mut w, s, A, vec![(s, A)], vec![Delta::Roles(vec![Edge { holder: g, role: None, may_grant: false }])]);
                t.a.remove(&g);
            }
            6 => {
                // a node rotates its keyset; R holds it, or not
                let n = r.pick(&nodes);
                let m = t.keyset[&n] + 1;
                t.keyset.insert(n, m);
                let c = push(&mut w, n, n, vec![], vec![Delta::Keys { keyset: m }]);
                if r.chance(60) {
                    w.known.push(c);
                }
            }
            7 | 8 => {
                // a body on T, by any node (a reader's is invalid)
                let n = r.pick(&nodes);
                push(&mut w, n, T, vec![(n, A), (A, T)], vec![Delta::Content]);
            }
            9 => {
                // a node rotates T, boxing A at A's epoch as it holds it
                let n = r.pick(&nodes);
                t.t_epoch += 1;
                let e = if t.a_epoch > 0 && r.chance(30) { t.a_epoch - 1 } else { t.a_epoch };
                push(&mut w, n, T, vec![(n, A), (A, T)], vec![Delta::Secrets(vec![rd(A, t.t_epoch, e)])]);
            }
            10 => {
                // a grant on X to T or H, by XA or by a may-grant holder
                let granters: Vec<Id> = t.x.iter().filter(|(_, (ro, mg))| *ro == Role::Admin || *mg).map(|(n, _)| *n).collect();
                let s = r.pick(&granters);
                let g = if s == XA && r.chance(50) { H } else { T };
                if g == s || (s != XA && t.x.contains_key(&g)) {
                    continue;
                }
                let mg = g == H && r.chance(70);
                let mut boxes = vec![rd(g, t.x_epoch, 0)];
                if r.chance(15) {
                    boxes.push(rd(if g == T { H } else { T }, t.x_epoch, 0));
                }
                push(&mut w, s, X, vec![(s, X)], vec![Delta::Roles(vec![Edge { holder: g, role: Some(Role::Read), may_grant: mg }]), Delta::Secrets(boxes)]);
                t.x.insert(g, (Role::Read, mg));
            }
            _ => {
                // X rotates (by XA, boxing its holders) or records a step (by XA, or junk by H)
                if r.chance(60) {
                    t.x_epoch += 1;
                    let boxes: Vec<BoxAt> = t.x.keys().filter(|n| **n != XA).map(|n| rd(*n, t.x_epoch, 0)).collect();
                    push(&mut w, XA, X, vec![(XA, X)], vec![Delta::Keys { keyset: t.x_epoch }, Delta::Secrets(boxes)]);
                } else {
                    let s = if t.x.contains_key(&H) && r.chance(40) { H } else { XA };
                    push(&mut w, s, X, vec![(s, X)], vec![Delta::Sync]);
                }
            }
        }
    }
    w
}

/// Counts over a world: the parts each holding carries.
pub fn parts(held: &Held, ak: Ak) -> usize {
    held.iter().filter(|(_, a)| *a == ak).count()
}
