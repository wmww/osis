//! Boxes cut by holder (spec/wire.md §4 Pieces, spec/permissions.md §4 Copies): a commit's
//! `secrets.0` write on a thing comes in pieces, one per holder its box records are keyed with
//! (and the rest: history boxes, keyed with no holder), each bound by its own hash and judged
//! alone; X's stub in a unit carries the piece of each holder on the unit's chains to X and the
//! rest, and the sync-only cut (readers reaching X only at sync) the piece only, with no header
//! (its box proves itself by the step bearing its secret's sync key; spec/permissions.md §4 Stub).
//! A history box at (role, e) carries every earlier secret of the role and the rotation's names
//! (the holders it saw removed): opened by a holder of e's secret, so it gives a grantee the
//! epochs before its grant, and a holder of sync only opening the sync role's would learn
//! departed holders. Greenfield: the question is which boxes a reader of S, the
//! sync ID of a holder T of X, takes and which of X's holders it learns, and, for a holder of
//! sync only, whether it judges T holding sync on X as X's admins made it: its removal is told by
//! the step past its keys (the newest step bearing no sync key its boxes give), never by a
//! header.
//!
//! The world: X (mint admin XA) grants T (sync only or read, per world), H and others, by XA or
//! by a holder with the may-grant flag, sometimes with a junk box beside the grantee's; its
//! admins and writers rotate X boxing every holder; anyone may write a box to T (a forged one at
//! an epoch no step bears, or a re-seal at the current one while T holds a role); XA records
//! steps, H junk ones; an admin removes holders. Sync and read
//! share one epoch counter. R reads T's unit, which references X: X's stub there, T the holder on
//! the unit's chain to X, as the rule cuts it, closed over evidence (the edge writes on each copied
//! commit's hop (signer, X)), but for a holder of sync only (the sync-only cut: no evidence). Which T holds is the
//! sender's judgement of what it holds (it holds every commit): T reads X where a valid edge write
//! gives it read, so a forged edge write naming T read (by a holder neither admin nor may-grant,
//! or by one holding no role: invalid or pending) changes nothing R receives.
use crate::gen::Rng;
use std::collections::{BTreeMap, BTreeSet};

pub type Id = u32;
pub type Cid = u32;

pub const X: Id = 30;
pub const XA: Id = 31;
pub const T: Id = 20;
pub const H: Id = 32;
pub const O1: Id = 40;
pub const O2: Id = 41;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Role {
    Sync,
    Read,
    Write,
    Admin,
}

#[derive(Clone, Copy, Debug)]
pub struct Edge {
    pub holder: Id,
    pub role: Option<Role>,
    pub may_grant: bool,
}

/// A box of X to `holder`: `role`'s secret at `epoch`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct BoxAt {
    pub holder: Id,
    pub role: Role,
    pub epoch: u32,
}

/// A commit on X along the one hop (signer, X).
#[derive(Clone, Debug)]
pub struct Commit {
    pub id: Cid,
    pub signer: Id,
    pub ts: u32,
    pub roles: Option<Vec<Edge>>,
    /// the `secrets.0` write: its pieces are its boxes grouped by holder
    pub boxes: Vec<BoxAt>,
    /// a `sync.0` step registering the sync key of this epoch; `chain` whether it verifies from
    /// the genesis step (signed by an admin's delete key)
    pub step: Option<(u32, bool)>,
    /// the rest piece: history boxes of these roles at this epoch, each carrying every earlier
    /// epoch's secret of its role and these names
    pub history: Option<History>,
}

#[derive(Clone, Debug)]
pub struct History {
    pub epoch: u32,
    pub roles: Vec<Role>,
    pub names: Vec<Id>,
}

impl Commit {
    fn holders(&self) -> BTreeSet<Id> {
        self.boxes.iter().map(|b| b.holder).collect()
    }
}

/// A part of a commit as a copy holds it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum P {
    Header,
    Roles,
    /// the `secrets.0` piece of this holder
    Piece(Id),
    /// the `secrets.0` piece of the rest (history boxes)
    Rest,
    Sync,
}

pub type Held = BTreeSet<(Cid, P)>;

#[derive(Clone, Debug, Default)]
pub struct World {
    pub commits: Vec<Commit>,
    /// The role X's admins grant T (the generator's): sync only, or read. What R receives
    /// follows `World::reads`, never this.
    pub t_sync_only: bool,
}

/// Which copies R holds, and how it judges a `secrets.0` write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rule {
    /// The spec: T's piece and the rest, each piece judged alone; a holder of sync only its
    /// piece only, no header.
    Spec,
    /// Control, today's copies: the whole `secrets.0` part beside T's box (every holder's piece),
    /// with its header, a holder of sync only's included.
    WholePart,
    /// Control: T's piece alone, but a `secrets.0` write judged as one over the pieces held.
    AspectVerdict,
    /// Control: T's piece alone, a holder of sync only's copies keeping their header.
    SyncHeader,
    /// Control: a holder of sync only takes a box's secret without a step bearing its sync key.
    NoStepCheck,
    /// Control: T's piece without the rest beside it.
    NoRest,
    /// Control: the rest beside a holder of sync only's piece too.
    RestToSync,
    /// Control: a holder of sync only's removal keeps its header (a certificate copy in its
    /// stub).
    RemovalHeader,
    /// Control: a holder of sync only holds sync while any box to it opens, the steps aside.
    HolderKept,
    /// Control: T reads X where any held edge write gives it read, whatever its validity.
    AnyValidity,
}

impl World {
    fn commit(&self, c: Cid) -> &Commit {
        self.commits.iter().find(|x| x.id == c).expect("commit")
    }

    /// Whether T reads X as the logger judges it holding every commit: a valid edge write gives T
    /// read (`Rule::AnyValidity`: any held one does). Else T
    /// holds sync only: its pieces go in a sync-only cut.
    pub fn reads(&self, rule: Rule) -> bool {
        let all: Held = self.commits.iter().flat_map(|c| [(c.id, P::Header), (c.id, P::Roles)]).collect();
        let j = Judge::new(self, &all);
        self.commits.iter().any(|c| {
            c.roles.as_ref().is_some_and(|es| es.iter().any(|e| e.holder == T && e.role >= Some(Role::Read)))
                && (rule == Rule::AnyValidity || j.roles.get(&c.id) == Some(&V::Valid))
        })
    }

    /// The edge writes setting the hop (s, X): evidence of a commit signed by s.
    fn evidence_of(&self, c: &Commit) -> Vec<Cid> {
        if c.signer == XA {
            return Vec::new();
        }
        self.commits.iter().filter(|d| d.roles.as_ref().is_some_and(|es| es.iter().any(|e| e.holder == c.signer))).map(|d| d.id).collect()
    }

    /// The commits X's stub in T's unit names: edge writes naming T, commits boxing T, steps.
    fn named(&self) -> Vec<&Commit> {
        self.commits
            .iter()
            .filter(|c| c.roles.as_ref().is_some_and(|es| es.iter().any(|e| e.holder == T)) || c.holders().contains(&T) || c.step.is_some())
            .collect()
    }

    /// The parts a reader of T's unit holds of X's stub under `rule`.
    pub fn cut(&self, rule: Rule) -> Held {
        let sync_only = !self.reads(rule);
        let mut held = Held::new();
        for c in self.named() {
            let pieces: Vec<Id> = match rule {
                Rule::WholePart => c.holders().into_iter().collect(),
                _ => c.holders().into_iter().filter(|h| *h == T).collect(),
            };
            let rest = c.history.is_some()
                && match rule {
                    Rule::WholePart => true,
                    Rule::NoRest => false,
                    Rule::RestToSync => pieces.contains(&T),
                    _ => pieces.contains(&T) && !sync_only,
                };
            held.extend(pieces.into_iter().map(|h| (c.id, P::Piece(h))));
            if rest {
                held.insert((c.id, P::Rest));
            }
            if c.step.is_some() {
                held.insert((c.id, P::Sync));
            }
            if sync_only {
                // no edge write, no evidence; the header only where the rule keeps it
                let removal = c.roles.as_ref().is_some_and(|es| es.iter().any(|e| e.holder == T && e.role.is_none()));
                if matches!(rule, Rule::WholePart | Rule::SyncHeader) || (rule == Rule::RemovalHeader && removal) {
                    held.insert((c.id, P::Header));
                }
                continue;
            }
            held.insert((c.id, P::Header));
            if c.roles.is_some() {
                held.insert((c.id, P::Roles));
            }
        }
        if !sync_only {
            // closed over evidence
            let mut work: Vec<Cid> = held.iter().map(|(c, _)| *c).collect();
            while let Some(c) = work.pop() {
                for d in self.evidence_of(self.commit(c)) {
                    if held.insert((d, P::Roles)) {
                        held.insert((d, P::Header));
                        work.push(d);
                    }
                }
            }
        }
        held
    }

    /// The reference for a holder of sync only: whether T holds sync on X as X's admins made it,
    /// boxed (granted, rotated or re-sealed while on the roster) at the epoch of X's newest
    /// verified step.
    pub fn t_holds(&self) -> bool {
        let head = self.commits.iter().filter_map(|c| c.step).filter(|(_, chain)| *chain).map(|(e, _)| e).max();
        head.is_some_and(|h| self.commits.iter().any(|c| c.boxes.iter().any(|b| *b == BoxAt { holder: T, role: Role::Sync, epoch: h })))
    }

    /// The reference: whole copies of every commit X's stub names (every part, header
    /// included), closed over evidence, but for a holder of sync only (no evidence).
    pub fn whole(&self) -> Held {
        let sync_only = !self.reads(Rule::Spec);
        let mut held = Held::new();
        for c in self.named() {
            held.insert((c.id, P::Header));
            if c.roles.is_some() {
                held.insert((c.id, P::Roles));
            }
            held.extend(c.holders().into_iter().map(|h| (c.id, P::Piece(h))));
            if c.history.is_some() {
                held.insert((c.id, P::Rest));
            }
            if c.step.is_some() {
                held.insert((c.id, P::Sync));
            }
        }
        if !sync_only {
            let mut work: Vec<Cid> = held.iter().map(|(c, _)| *c).collect();
            while let Some(c) = work.pop() {
                for d in self.evidence_of(self.commit(c)) {
                    if held.insert((d, P::Roles)) {
                        held.insert((d, P::Header));
                        work.push(d);
                    }
                }
            }
        }
        held
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum V {
    Valid,
    Invalid,
    Pending,
}

/// What R takes and learns.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Seen {
    /// X's (role, epoch) secrets R takes from boxes to T
    pub taken: BTreeSet<(Role, u32)>,
    /// X's holders R learns of (box keys, edge writes, headers' signers), T and XA aside
    pub learned: BTreeSet<Id>,
    /// other holders' pieces R carries
    pub others_pieces: usize,
    /// (sync only) whether R judges T holding sync on X: the newest verified step it holds bears
    /// the sync key of a secret a box to T gave
    pub holds: bool,
}

/// R's judgement holding `held` (`Rule::AspectVerdict`: a `secrets.0` write judged as one over
/// the pieces held; `Rule::NoStepCheck`: no step check).
pub fn judge(w: &World, held: &Held, rule: Rule) -> Seen {
    let aspect = rule == Rule::AspectVerdict;
    let mut out = Seen::default();
    for &(c, p) in held {
        let cm = w.commit(c);
        match p {
            P::Header => {
                out.learned.insert(cm.signer);
            }
            P::Roles => out.learned.extend(cm.roles.iter().flatten().map(|e| e.holder)),
            P::Piece(h) => {
                out.learned.insert(h);
                out.others_pieces += (h != T) as usize;
            }
            P::Rest | P::Sync => {}
        }
    }
    out.learned.remove(&T);
    out.learned.remove(&XA);
    if !w.reads(Rule::Spec) {
        // no judging: a box to T proves itself by a held step bearing its sync key
        let borne: BTreeSet<u32> = w.commits.iter().filter(|c| held.contains(&(c.id, P::Sync))).filter_map(|c| c.step).filter(|(_, chain)| *chain).map(|(e, _)| e).collect();
        for c in &w.commits {
            if !held.contains(&(c.id, P::Piece(T))) {
                continue;
            }
            for b in c.boxes.iter().filter(|b| b.holder == T && b.role == Role::Sync) {
                if rule == Rule::NoStepCheck || borne.contains(&b.epoch) {
                    out.taken.insert((b.role, b.epoch));
                }
            }
        }
        // T holds sync while the newest verified step held (epochs only grow) bears a secret
        // its boxes gave: a step past its keys is its removal
        out.holds = match rule {
            Rule::HolderKept => out.taken.iter().any(|(r, _)| *r == Role::Sync),
            _ => borne.last().is_some_and(|e| out.taken.contains(&(Role::Sync, *e))),
        };
        // it judges nothing and takes a secret from its box alone (spec/crypto.md §4
        // Established); a rest piece it holds still opens under the sync secret it took
        let mut opened = out.clone();
        open_history(w, held, &mut opened, |_| true);
        out.learned = opened.learned;
        return out;
    }
    let j = Judge::new(w, held);
    for c in &w.commits {
        let pieces: Vec<Vec<BoxAt>> = {
            let ps: Vec<Vec<BoxAt>> = c.holders().into_iter().filter(|h| held.contains(&(c.id, P::Piece(*h)))).map(|h| c.boxes.iter().copied().filter(|b| b.holder == h).collect()).collect();
            if aspect && !ps.is_empty() {
                vec![ps.concat()]
            } else {
                ps
            }
        };
        for bs in pieces {
            if j.secrets(c, &bs) == V::Valid {
                out.taken.extend(bs.iter().filter(|b| b.holder == T).map(|b| (b.role, b.epoch)));
            }
        }
    }
    open_history(w, held, &mut out, |c| j.rest(c) == V::Valid);
    out
}

/// The history boxes of the rest pieces held that `valid` counts, opened to a fixpoint: one at
/// (r, e) whose secret is taken gives every earlier secret of r and its names (`out.learned`
/// keeps T and XA out).
fn open_history(w: &World, held: &Held, out: &mut Seen, valid: impl Fn(&Commit) -> bool) {
    let rests: Vec<&Commit> = w.commits.iter().filter(|c| held.contains(&(c.id, P::Rest)) && valid(c)).collect();
    loop {
        let before = out.taken.len();
        for c in &rests {
            let Some(h) = &c.history else { continue };
            let opened: Vec<Role> = h.roles.iter().copied().filter(|r| out.taken.contains(&(*r, h.epoch))).collect();
            for r in &opened {
                out.taken.extend((0..h.epoch).map(|e| (*r, e)));
                out.learned.extend(h.names.iter().filter(|n| **n != T && **n != XA));
            }
        }
        if out.taken.len() == before {
            return;
        }
    }
}

struct Judge<'a> {
    w: &'a World,
    held: &'a Held,
    /// edge writes in key order: (ts, edges applied)
    walk: Vec<(u32, Vec<(Edge, bool)>)>,
    roles: BTreeMap<Cid, V>,
}

impl<'a> Judge<'a> {
    fn new(w: &'a World, held: &'a Held) -> Judge<'a> {
        let mut j = Judge { w, held, walk: Vec::new(), roles: BTreeMap::new() };
        let mut cs: Vec<&Commit> = w.commits.iter().filter(|c| held.contains(&(c.id, P::Roles))).collect();
        cs.sort_by_key(|c| c.ts);
        for c in cs {
            let Some(es) = &c.roles else { continue };
            if j.pending(w, c.signer) {
                j.roles.insert(c.id, V::Pending);
                continue;
            }
            let state = j.state_before(c.ts);
            let by = state.get(&c.signer).copied();
            let applied: Vec<(Edge, bool)> = es
                .iter()
                .map(|e| {
                    let ok = match by {
                        Some((Role::Admin, _)) => true,
                        Some((r, true)) => e.role.is_some_and(|g| g <= r) && !state.contains_key(&e.holder),
                        _ => false,
                    };
                    (*e, ok)
                })
                .collect();
            let v = if applied.iter().all(|(_, ok)| *ok) { V::Valid } else { V::Invalid };
            j.roles.insert(c.id, v);
            j.walk.push((c.ts, applied));
        }
        j
    }

    fn pending(&self, w: &World, s: Id) -> bool {
        s != XA && !w.commits.iter().any(|c| self.held.contains(&(c.id, P::Roles)) && c.roles.as_ref().is_some_and(|es| es.iter().any(|e| e.holder == s)))
    }

    fn state_before(&self, ts: u32) -> BTreeMap<Id, (Role, bool)> {
        let mut s = BTreeMap::from([(XA, (Role::Admin, true))]);
        for (k, applied) in &self.walk {
            if *k >= ts {
                break;
            }
            for (e, _) in applied.iter().filter(|(_, ok)| *ok) {
                match e.role {
                    Some(r) => {
                        s.insert(e.holder, (r, e.may_grant));
                    }
                    None => {
                        s.remove(&e.holder);
                    }
                }
            }
        }
        s
    }

    /// A `secrets.0` write (a piece, or the pieces held as one): a may-grant grant's boxes to its
    /// grantees judged from the commit alone (spec/permissions.md §2), else the boxes' greatest
    /// role, at least write, along the hop (spec/permissions.md §3).
    fn secrets(&self, c: &Commit, bs: &[BoxAt]) -> V {
        if !self.held.contains(&(c.id, P::Header)) {
            return V::Pending;
        }
        if let (Some(es), Some(V::Valid)) = (&c.roles, self.roles.get(&c.id)) {
            if self.held.contains(&(c.id, P::Roles)) && bs.iter().all(|b| es.iter().any(|e| e.holder == b.holder && e.role.is_some_and(|g| g >= b.role))) {
                return V::Valid;
            }
        }
        if self.pending(self.w, c.signer) {
            return V::Pending;
        }
        let need = bs.iter().map(|b| b.role).max().unwrap_or(Role::Write).max(Role::Write);
        let s = self.state_before(c.ts);
        if s.get(&c.signer).is_some_and(|(r, _)| *r >= need) {
            V::Valid
        } else {
            V::Invalid
        }
    }

    /// A rest piece: a may-grant grant's history boxes at or below its granted role, judged from
    /// the commit alone; else, as a rotation's or a grant's (beside a keyset or boxes, never a
    /// history add), at least write along the hop.
    fn rest(&self, c: &Commit) -> V {
        let Some(h) = &c.history else { return V::Invalid };
        if !self.held.contains(&(c.id, P::Header)) {
            return V::Pending;
        }
        if let (Some(es), Some(V::Valid)) = (&c.roles, self.roles.get(&c.id)) {
            if self.held.contains(&(c.id, P::Roles)) && h.roles.iter().all(|r| es.iter().any(|e| e.role.is_some_and(|g| g >= *r))) {
                return V::Valid;
            }
        }
        if self.pending(self.w, c.signer) {
            return V::Pending;
        }
        let need = h.roles.iter().copied().max().unwrap_or(Role::Write).max(Role::Write);
        if self.state_before(c.ts).get(&c.signer).is_some_and(|(r, _)| *r >= need) {
            V::Valid
        } else {
            V::Invalid
        }
    }
}

/// The boxes a holder of `role` gets at `epoch`: sync, and read where it reads.
fn boxes_for(h: Id, role: Role, epoch: u32) -> Vec<BoxAt> {
    let mut v = vec![BoxAt { holder: h, role: Role::Sync, epoch }];
    if role >= Role::Read {
        v.push(BoxAt { holder: h, role: Role::Read, epoch });
    }
    v
}

/// A random world of `seed`: four to fourteen events on X.
pub fn world(seed: u64) -> World {
    let mut r = Rng::new(seed ^ 0xB0C5);
    let mut w = World { t_sync_only: seed % 2 == 0, ..World::default() };
    let t_role = if w.t_sync_only { Role::Sync } else { Role::Read };
    let mut x: BTreeMap<Id, (Role, bool)> = BTreeMap::from([(XA, (Role::Admin, true))]);
    let mut epoch: u32 = 0;
    let mut fake: u32 = 1000;
    let mut id: Cid = 0;
    // the holders removed since the last rotation, and each epoch's names
    let mut removed: Vec<Id> = Vec::new();
    let mut names: BTreeMap<u32, Vec<Id>> = BTreeMap::from([(0, Vec::new())]);
    let mut push = |w: &mut World, signer: Id, roles: Option<Vec<Edge>>, boxes: Vec<BoxAt>, step: Option<(u32, bool)>, history: Option<History>| {
        id += 1;
        w.commits.push(Commit { id, signer, ts: id, roles, boxes, step, history });
    };
    push(&mut w, XA, None, Vec::new(), Some((0, true)), None);
    let others = [T, H, O1, O2];
    let events = 4 + r.below(11);
    for _ in 0..events {
        match r.below(11) {
            0..=3 => {
                // a grant, by XA or a may-grant holder
                let granters: Vec<Id> = x.iter().filter(|(_, (ro, mg))| *ro == Role::Admin || *mg).map(|(n, _)| *n).collect();
                let s = r.pick(&granters);
                let (sr, _) = x[&s];
                let g = r.pick(&others);
                if g == s || (sr != Role::Admin && x.contains_key(&g)) {
                    continue;
                }
                let role = if g == T {
                    t_role
                } else {
                    let roles = [Role::Sync, Role::Read, Role::Write, Role::Admin];
                    r.pick(&roles[..if sr == Role::Admin { 4 } else { roles.iter().position(|y| *y == sr).unwrap() + 1 }])
                };
                let mg = g != T && role >= Role::Read && r.chance(50);
                let mut bs = boxes_for(g, role, epoch);
                // the grant writes the history boxes of the roles it boxes again
                let history = Some(History { epoch, roles: bs.iter().map(|b| b.role).collect(), names: names[&epoch].clone() });
                if r.chance(25) {
                    // junk beside the grantee's: a box to a holder the commit grants nothing
                    let o = r.pick(&others);
                    if o != g {
                        bs.push(BoxAt { holder: o, role: Role::Read, epoch });
                    }
                }
                push(&mut w, s, Some(vec![Edge { holder: g, role: Some(role), may_grant: mg }]), bs, None, history);
                if sr == Role::Admin || !x.contains_key(&g) {
                    x.insert(g, (role, mg));
                }
            }
            4 | 5 => {
                // a rotation by a writer or admin, boxing every holder; an admin's step follows
                let rotators: Vec<Id> = x.iter().filter(|(_, (ro, _))| *ro >= Role::Write).map(|(n, _)| *n).collect();
                let s = r.pick(&rotators);
                epoch += 1;
                let bs: Vec<BoxAt> = x.iter().filter(|(n, _)| **n != s).flat_map(|(n, (ro, _))| boxes_for(*n, *ro, epoch)).collect();
                names.insert(epoch, std::mem::take(&mut removed));
                let history = Some(History { epoch, roles: vec![Role::Sync, Role::Read], names: names[&epoch].clone() });
                push(&mut w, s, None, bs, None, history);
                if r.chance(80) {
                    push(&mut w, XA, None, Vec::new(), Some((epoch, true)), None);
                }
            }
            6 => {
                // a box to T by anyone: a re-seal at the epoch, or a forged one at an epoch no step bears
                let s = r.pick(&[XA, H, O1]);
                let e = if r.chance(50) || !x.contains_key(&T) {
                    fake += 1;
                    fake
                } else {
                    epoch
                };
                push(&mut w, s, None, boxes_for(T, t_role, e), None, None);
            }
            7 => {
                // a junk step by H: its chain does not verify
                let e = if r.chance(50) { epoch } else { fake + 1 };
                push(&mut w, H, None, Vec::new(), Some((e, false)), None);
            }
            8 => {
                // a forged edge write naming T read, by one that may not grant it: a holder neither
                // admin nor may-grant (invalid), or one holding no role (pending)
                let forgers: Vec<Id> = [H, O1, O2].into_iter().filter(|n| x.get(n).is_none_or(|(ro, mg)| *ro != Role::Admin && !*mg)).collect();
                if forgers.is_empty() {
                    continue;
                }
                let s = r.pick(&forgers);
                push(&mut w, s, Some(vec![Edge { holder: T, role: Some(Role::Read), may_grant: false }]), Vec::new(), None, None);
            }
            _ => {
                // an admin removes a holder (no rotation: the next rotation boxes those left)
                let admins: Vec<Id> = x.iter().filter(|(_, (ro, _))| *ro == Role::Admin).map(|(n, _)| *n).collect();
                let s = r.pick(&admins);
                let hs: Vec<Id> = x.keys().copied().filter(|n| *n != XA && *n != s).collect();
                if hs.is_empty() {
                    continue;
                }
                let g = r.pick(&hs);
                push(&mut w, s, Some(vec![Edge { holder: g, role: None, may_grant: false }]), Vec::new(), None, None);
                x.remove(&g);
                removed.push(g);
            }
        }
    }
    w
}
