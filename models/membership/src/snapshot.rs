//! Two-level model of roster snapshots (spec/permissions.md §6). Key actor
//! K (node 0) owns person actor P, whose admins are devices; P owns G. Membership writes
//! target P or G; a write on G by a P-admin acts through the owner chain. A **snapshot** of a
//! thing is a write by its owner chain (P: K; G: K or a P-admin at that time) carrying the
//! thing's whole roster. The timeline of a thing starts at its newest *applied* owner-chain
//! snapshot: author had chain authority at its time by the chain's timeline, and no later
//! demotion of the author dropped it. That roster also stands for every earlier time.
//! Without one the node walks everything it holds (a compacted node: from an empty roster).
//! Snapshots by edge-admins are ignored. Everything else is the demoter-frontier rule; a
//! P-demotion audits the device's writes made as P-admin (on P and on G, owner-chain class)
//! and, if the device then holds no G admin edge, its G writes made by edge authority too
//! (it fell through edge admin); a G-demotion only writes made by edge authority, so
//! edge-admins never touch snapshots. A G edge removed while the device still holds the
//! chain audits nothing (its class on G does not fall).
//!
//! Checked (`cargo run --release [samples] snapshot`, `cargo test`): compaction, that is
//! removing every write of a thing before any applied snapshot of it, never changes the
//! result; nothing is dropped when nobody is offline; input order independence; bounded
//! passes. A compaction point that a later backdated removal un-applies diverges from the
//! full history until a fresh snapshot follows the removal (`compaction_at_unapplied`).
//!
//! Projected rosters (`SHist::projected`): a node holding only one actor's certificate
//! closure computes that actor's P and G roles as the full node does, with or without
//! compaction. A **record** here is a plain write on G by its owner chain that touches no
//! roster (`/moved`, say, spec/permissions.md §7); one is valid iff its author was a P-admin
//! at its point and no P demotion dropped it. Checked: a record by a device whose removal's
//! frontier misses it is never valid; record validity is order independent, survives
//! compaction and projection.
//!
//! **Ledger**: a snapshot answers authority before its time by its roster and its ledger of
//! admin intervals (`Entry`): a member held admin inside a closed interval, or after its
//! roster edge's `since`; a write inside a closed interval is dropped iff the frontier of
//! the demotion that closed it misses the write. Without the ledger a key-actor re-snapshot
//! of P that omits a former device disowned that device's earlier records and G writes. Checked: a re-snapshot of P with the
//! roster and ledger the timeline computes (`ledger_of`) changes no record's validity and
//! no G write's application (`resnapshot_neutral`).

use crate::Role;
use std::collections::HashSet;

pub const K: usize = 0;
const LATE: u32 = 1000;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum Thing {
    P,
    G,
}

/// A write's position key in the global order: (t, node, `SWrite::id`), the id standing for
/// the commit ID (0 for a ledger key naming no write).
pub type Key = (u32, usize, usize);

/// The end of a device's P tenure: by a demotion keyed `key` = (t, demoter node, commit).
pub struct Event {
    key: Key,
    member: usize,
}

/// An admin interval in a snapshot's ledger: `member` held admin from the grant keyed
/// `since` (None: from the beginning) until the demotion keyed `until` (None: it still holds
/// admin in the roster). A closed interval's frontier is its demoter's receipts before its
/// time; every earlier write of the member that the frontier misses is dropped (each later
/// demotion re-audits, as in the walk). Every interval here ends by an explicit demotion:
/// the spec's frontier-less ends (`until`, self-removal) and audit-only entries (`since` =
/// `until`, an explicit demotion auditing after such an end or the standing a demoter kept)
/// need `until` and self-removal, which this model lacks (`joint.rs` has self-removal,
/// `edges.rs` both); osis-perm's re-snapshot runs over joint and edges histories
/// (`tests/it/roster.rs`) cover them.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Entry {
    pub member: usize,
    pub since: Option<Key>,
    pub until: Option<Key>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SWrite {
    pub author: usize,
    pub thing: Thing,
    /// Ignored for snapshots.
    pub target: usize,
    pub role: Role,
    pub t: u32,
    /// Full roster of `thing` over all nodes (K's entry ignored).
    pub snap: Option<Vec<Role>>,
    /// Admin intervals before the snapshot (snapshots of P only; G edges authorize nothing
    /// in the chain).
    pub ledger: Vec<Entry>,
    /// Plain owner-chain write on G touching no roster; `target` is an opaque payload.
    pub rec: bool,
    /// Stands for the commit ID: orders writes of one (t, author) (unique, from 1).
    pub id: usize,
}

#[derive(Clone, Debug)]
pub struct SHist {
    pub gp: Vec<Role>,
    pub gg: Vec<Role>,
    pub writes: Vec<SWrite>,
    /// [write][node] receipt time on the receiver's clock; author: its own `t`.
    pub recv: Vec<Vec<u32>>,
}

#[derive(Clone, Debug)]
pub struct ThingOut {
    /// roles_after[k]: roles after processing the first k positions of the global order
    /// (the start roster for every position before the epoch start).
    pub roles_after: Vec<Vec<Role>>,
    pub roles: Vec<Role>,
    pub applied: u64,
    pub dropped: u64,
    /// Applied writes that took their target from effective admin to below: (write, target).
    pub demotions: Vec<(usize, usize)>,
    pub passes: usize,
    pub start: Option<usize>,
}

#[derive(Clone, Debug)]
pub struct Out {
    pub p: ThingOut,
    pub g: ThingOut,
}

fn max_role(a: Role, b: Role) -> Role {
    if a >= b {
        a
    } else {
        b
    }
}

impl SHist {
    pub fn n(&self) -> usize {
        self.gp.len()
    }

    pub fn order(&self) -> Vec<usize> {
        let mut o: Vec<usize> = (0..self.writes.len()).collect();
        o.sort_by_key(|&i| self.key(i));
        o
    }

    /// `audit = false` evaluates without frontiers (nothing is ever dropped), the reference
    /// for the nobody-offline check.
    pub fn eval(&self, audit: bool) -> Out {
        let order = self.order();
        let p = self.walk(Thing::P, &order, &self.gp, &|a, _| if a == K { Role::Admin } else { Role::None }, 0, audit, &[]);
        // A device's writes on G as P-admin are dropped when the frontier of a later P
        // demotion of it misses them: a demotion in the walk, or one that closed a ledger
        // interval ending after the write.
        let mut dropped_g = 0u64;
        if audit {
            let pos_of = pos_of(&order);
            for (j, w) in self.writes.iter().enumerate() {
                let z = w.author;
                if w.thing != Thing::G || z == K || !self.p_admin_at(&p, z, pos_of[j]) {
                    continue;
                }
                let by_ledger = match p.start {
                    Some(s) if pos_of[j] < pos_of[s] => {
                        let k = self.key(j);
                        self.writes[s].ledger.iter().any(|e| e.member == z && e.until.map_or(false, |u| k < u && !(self.recv[j][u.1] < u.0)))
                    }
                    _ => false,
                };
                let by_demotion = p.demotions.iter().any(|&(r, x)| {
                    let rw = &self.writes[r];
                    x == z && pos_of[j] < pos_of[r] && !(self.recv[j][rw.author] < rw.t)
                });
                if by_ledger || by_demotion {
                    dropped_g |= 1 << j;
                }
            }
        }
        let chain = |a: usize, pos: usize| if self.p_admin_at(&p, a, pos) { Role::Admin } else { Role::None };
        // Every end of a P tenure (a demotion in the walk, or a closed ledger interval with its
        // ending key): the device falls from the owner chain on G. If it holds no G admin edge
        // at that point it falls through edge admin too, so the G walk audits its edge-class
        // writes with that demotion's frontier (spec/permissions.md §5.1 step 4).
        let mut events: Vec<Event> = p.demotions.iter().map(|&(r, x)| Event { key: self.key(r), member: x }).collect();
        if let Some(s) = p.start {
            events.extend(self.writes[s].ledger.iter().filter_map(|e| e.until.map(|key| Event { key, member: e.member })));
        }
        events.sort_by_key(|e| e.key);
        let g = self.walk(Thing::G, &order, &self.gg, &chain, dropped_g, audit, if audit { &events } else { &[] });
        Out { p, g }
    }

    fn walk(
        &self,
        thing: Thing,
        order: &[usize],
        genesis: &[Role],
        chain: &dyn Fn(usize, usize) -> Role,
        mut dropped: u64,
        audit: bool,
        events: &[Event],
    ) -> ThingOut {
        let pos_of = pos_of(order);
        // Epoch start: newest applied owner-chain snapshot of this thing. Only a demotion in
        // the chain can drop one, and those drops are known before this walk.
        let start = (0..self.writes.len())
            .filter(|&i| {
                let w = &self.writes[i];
                w.thing == thing && w.snap.is_some() && chain(w.author, pos_of[i]) == Role::Admin && dropped >> i & 1 == 0
            })
            .max_by_key(|&i| pos_of[i]);
        let mut passes = 0;
        'walk: loop {
            passes += 1;
            let (mut roles, start_pos) = match start {
                Some(s) => (self.writes[s].snap.clone().unwrap(), pos_of[s] + 1),
                None => (genesis.to_vec(), 0),
            };
            roles[K] = Role::Admin;
            let mut applied = 0u64;
            if let Some(s) = start {
                applied |= 1 << s;
            }
            let mut demotions = Vec::new();
            let mut roles_after = vec![roles.clone(); start_pos.min(order.len()) + 1];
            let mut next_event = 0;
            for pos in start_pos..=order.len() {
                // Chain demotions up to this point audit edge-class writes of a member that
                // holds no admin edge here.
                let upto = if pos < order.len() { self.key(order[pos]) } else { (u32::MAX, usize::MAX, usize::MAX) };
                let mut grew = false;
                while next_event < events.len() && events[next_event].key <= upto {
                    let ev = &events[next_event];
                    next_event += 1;
                    if roles[ev.member] == Role::Admin {
                        continue;
                    }
                    let (t, d, _) = ev.key;
                    for j in 0..self.writes.len() {
                        if applied >> j & 1 == 0 || self.writes[j].author != ev.member || self.key(j) > ev.key {
                            continue;
                        }
                        if chain(ev.member, pos_of[j]) == Role::Admin {
                            continue; // chain class: dropped up front
                        }
                        if !(self.recv[j][d] < t) {
                            dropped |= 1 << j;
                            grew = true;
                        }
                    }
                }
                if grew {
                    continue 'walk;
                }
                if pos == order.len() {
                    break;
                }
                let i = order[pos];
                let w = &self.writes[i];
                if w.thing != thing || dropped >> i & 1 == 1 || w.target == K || w.snap.is_some() || w.rec {
                    // A snapshot here is inapplicable or dropped (an applied one would be the start).
                    roles_after.push(roles.clone());
                    continue;
                }
                let a = w.author;
                let is_admin = |x: usize, roles: &[Role]| x == K || roles[x] == Role::Admin || chain(x, pos) == Role::Admin;
                if !is_admin(a, &roles) {
                    roles_after.push(roles.clone());
                    continue;
                }
                let old = max_role(roles[w.target], chain(w.target, pos));
                roles[w.target] = w.role;
                applied |= 1 << i;
                let new = max_role(w.role, chain(w.target, pos));
                if old == Role::Admin && new < Role::Admin {
                    demotions.push((i, w.target));
                    if audit {
                        let mut grew = false;
                        for j in 0..self.writes.len() {
                            if applied >> j & 1 == 0 || self.writes[j].author != w.target || j == i {
                                continue;
                            }
                            if chain(w.target, pos_of[j]) == Role::Admin {
                                continue; // made by chain authority, audited by the chain's demotions
                            }
                            let covered = self.recv[j][a] < w.t;
                            if !covered {
                                dropped |= 1 << j;
                                grew = true;
                            }
                        }
                        if grew {
                            continue 'walk;
                        }
                    }
                }
                roles_after.push(roles.clone());
            }
            debug_assert_eq!(roles_after.len(), order.len() + 1);
            return ThingOut { roles_after, roles, applied, dropped, demotions, passes, start };
        }
    }

    fn key(&self, i: usize) -> Key {
        (self.writes[i].t, self.writes[i].author, self.writes[i].id)
    }

    /// The closed ledger interval of `z` in snapshot `sw` containing key `k`.
    fn interval<'a>(&self, sw: &'a SWrite, z: usize, k: Key) -> Option<&'a Entry> {
        sw.ledger.iter().find(|e| e.member == z && e.since.map_or(true, |s| s < k) && e.until.map_or(false, |u| k < u))
    }

    /// Whether `z` held P-admin at position `pos` by P's timeline `p`: before the epoch
    /// start, inside a closed ledger interval, or after every interval and after its roster
    /// edge's `since` (spec/permissions.md §6); after the start, by the walk.
    pub fn p_admin_at(&self, p: &ThingOut, z: usize, pos: usize) -> bool {
        if z == K {
            return true;
        }
        let order = self.order();
        match p.start {
            Some(s) if pos < pos_of(&order)[s] => {
                let sw = &self.writes[s];
                let k = self.key(order[pos]);
                self.interval(sw, z, k).is_some()
                    || sw.snap.as_ref().unwrap()[z] == Role::Admin
                        && sw.ledger.iter().filter(|e| e.member == z).all(|e| e.until.map_or(e.since.map_or(true, |s| s < k), |u| u < k))
            }
            _ => p.roles_after[pos][z] == Role::Admin,
        }
    }

    /// The ledger a snapshot of P taken after every write carries: the epoch start's ledger
    /// carried forward, then every interval the walk opened or closed.
    pub fn ledger_of(&self, p: &ThingOut) -> Vec<Entry> {
        let order = self.order();
        let mut ledger: Vec<Entry> = p.start.map_or(vec![], |s| self.writes[s].ledger.clone());
        for z in 1..self.n() {
            let mut open = ledger.iter().position(|e| e.member == z && e.until.is_none());
            if open.is_none() && p.roles_after[0][z] == Role::Admin {
                // In the start roster without a `since`: from after its last closed interval.
                let since = ledger.iter().filter(|e| e.member == z).filter_map(|e| e.until).max();
                ledger.push(Entry { member: z, since, until: None });
                open = Some(ledger.len() - 1);
            }
            for pos in 0..order.len() {
                let (before, after) = (p.roles_after[pos][z], p.roles_after[pos + 1][z]);
                let k = self.key(order[pos]);
                if before != Role::Admin && after == Role::Admin {
                    ledger.push(Entry { member: z, since: Some(k), until: None });
                    open = Some(ledger.len() - 1);
                } else if before == Role::Admin && after != Role::Admin {
                    ledger[open.unwrap()].until = Some(k);
                    open = None;
                }
            }
        }
        ledger
    }

    /// Snapshots of `thing` whose author had chain authority at their time. `applied` further
    /// requires that no demotion dropped them; those are the compaction points whose result
    /// must equal the full history's. The others were compaction points at some node only
    /// if a backdated removal arrived after it compacted.
    pub fn snapshots(&self, thing: Thing, out: &Out, applied: bool) -> Vec<usize> {
        let order = self.order();
        let pos_of = pos_of(&order);
        let t = if thing == Thing::P { &out.p } else { &out.g };
        (0..self.writes.len())
            .filter(|&i| {
                let w = &self.writes[i];
                let chain_admin = w.author == K || (thing == Thing::G && self.p_admin_at(&out.p, w.author, pos_of[i]));
                w.thing == thing && w.snap.is_some() && chain_admin && (!applied || t.dropped >> i & 1 == 0)
            })
            .collect()
    }

    /// Record `i` is valid iff its author had owner-chain authority at its point by P's
    /// timeline and no P demotion of the author dropped it.
    pub fn record_valid(&self, out: &Out, i: usize) -> bool {
        let pos = pos_of(&self.order())[i];
        self.p_admin_at(&out.p, self.writes[i].author, pos) && out.g.dropped >> i & 1 == 0
    }

    /// Valid records of G.
    pub fn successors(&self, out: &Out) -> Vec<usize> {
        (0..self.writes.len()).filter(|&i| self.writes[i].rec && self.record_valid(out, i)).collect()
    }

    /// What a node verifying actor `z` holds: the entries in the closure and every write that
    /// touches one, every snapshot projected to the closure, and every record.
    /// The closure starts at z's P and G entries and grows by each held write's author (its P
    /// entry; for a non-snapshot write on G also its G entry): the certificate rule.
    pub fn projected(&self, z: usize) -> (SHist, Vec<usize>) {
        let n = self.n();
        let (mut cp, mut cg) = (vec![false; n], vec![false; n]);
        cp[z] = true;
        cg[z] = true;
        let held = |w: &SWrite, cp: &[bool], cg: &[bool]| {
            !w.rec && (w.snap.is_some() || if w.thing == Thing::P { cp[w.target] } else { cg[w.target] })
        };
        loop {
            let mut grew = false;
            for w in &self.writes {
                if !held(w, &cp, &cg) {
                    continue;
                }
                let a = w.author;
                let g_entry = w.thing == Thing::G && w.snap.is_none();
                if !cp[a] || g_entry && !cg[a] {
                    cp[a] = true;
                    cg[a] |= g_entry;
                    grew = true;
                }
            }
            if !grew {
                break;
            }
        }
        let mask = |r: &[Role], c: &[bool]| -> Vec<Role> { (0..n).map(|x| if c[x] { r[x] } else { Role::None }).collect() };
        let keep: Vec<usize> = (0..self.writes.len()).filter(|&i| self.writes[i].rec || held(&self.writes[i], &cp, &cg)).collect();
        let h = SHist {
            gp: mask(&self.gp, &cp),
            gg: mask(&self.gg, &cg),
            writes: keep
                .iter()
                .map(|&i| {
                    let mut w = self.writes[i].clone();
                    w.snap = w.snap.map(|r| mask(&r, if w.thing == Thing::P { &cp } else { &cg }));
                    w
                })
                .collect(),
            recv: keep.iter().map(|&i| self.recv[i].clone()).collect(),
        };
        (h, keep)
    }

    /// The history as held by a node that compacted `thing` at snapshot `s`: every write of
    /// `thing` ordered before `s` is gone, and so is the genesis (nothing before `s` exists).
    pub fn compacted(&self, thing: Thing, s: usize) -> (SHist, Vec<usize>) {
        let order = self.order();
        let pos_of = pos_of(&order);
        let keep: Vec<usize> = (0..self.writes.len())
            .filter(|&i| !(self.writes[i].thing == thing && pos_of[i] < pos_of[s] && !self.writes[i].rec))
            .collect();
        let empty = vec![Role::None; self.n()];
        let h = SHist {
            gp: if thing == Thing::P { empty.clone() } else { self.gp.clone() },
            gg: if thing == Thing::G { empty } else { self.gg.clone() },
            writes: keep.iter().map(|&i| self.writes[i].clone()).collect(),
            recv: keep.iter().map(|&i| self.recv[i].clone()).collect(),
        };
        (h, keep)
    }

    fn permute(&self, perm: &[usize]) -> SHist {
        SHist {
            gp: self.gp.clone(),
            gg: self.gg.clone(),
            writes: perm.iter().map(|&i| self.writes[i].clone()).collect(),
            recv: perm.iter().map(|&i| self.recv[i].clone()).collect(),
        }
    }
}

fn pos_of(order: &[usize]) -> Vec<usize> {
    let mut p = vec![0; order.len()];
    for (pos, &i) in order.iter().enumerate() {
        p[i] = pos;
    }
    p
}

/// Applied set of `h` restricted to the kept writes, in `h`'s indexing.
fn applied_kept(applied: u64, keep: &[usize]) -> u64 {
    let mut m = 0u64;
    for (new, &old) in keep.iter().enumerate() {
        if applied >> old & 1 == 1 {
            m |= 1 << new;
        }
    }
    m
}

// ---------- search ----------

#[derive(Default)]
pub struct Stats {
    histories: u64,
    with_snapshot_start: u64,
    compactions: u64,
    compaction_mismatch: u64,
    unapplied_points: u64,
    unapplied_diverge: u64,
    order_dep: u64,
    honest_mismatch: u64,
    max_passes: usize,
    projections: u64,
    projection_mismatch: u64,
    records: u64,
    records_valid: u64,
    late_record_valid: u64,
    record_mismatch: u64,
    resnapshots: u64,
    disowned: u64,
    disagree: u64,
    ex_disagree: Option<SHist>,
    ex_disowned: Option<SHist>,
    ex_compaction: Option<SHist>,
    ex_projection: Option<SHist>,
    ex_late: Option<SHist>,
    ex_record: Option<SHist>,
    ex_order: Option<SHist>,
    ex_honest: Option<SHist>,
}

impl Stats {
    fn merge(&mut self, o: Stats) {
        self.histories += o.histories;
        self.with_snapshot_start += o.with_snapshot_start;
        self.compactions += o.compactions;
        self.compaction_mismatch += o.compaction_mismatch;
        self.unapplied_points += o.unapplied_points;
        self.unapplied_diverge += o.unapplied_diverge;
        self.order_dep += o.order_dep;
        self.honest_mismatch += o.honest_mismatch;
        self.max_passes = self.max_passes.max(o.max_passes);
        self.projections += o.projections;
        self.projection_mismatch += o.projection_mismatch;
        self.records += o.records;
        self.records_valid += o.records_valid;
        self.late_record_valid += o.late_record_valid;
        self.record_mismatch += o.record_mismatch;
        self.resnapshots += o.resnapshots;
        self.disowned += o.disowned;
        self.disagree += o.disagree;
        fn pick(a: &mut Option<SHist>, b: Option<SHist>) {
            if let Some(b) = b {
                if a.as_ref().map_or(true, |a| b.writes.len() < a.writes.len()) {
                    *a = Some(b);
                }
            }
        }
        pick(&mut self.ex_compaction, o.ex_compaction);
        pick(&mut self.ex_order, o.ex_order);
        pick(&mut self.ex_honest, o.ex_honest);
        pick(&mut self.ex_projection, o.ex_projection);
        pick(&mut self.ex_late, o.ex_late);
        pick(&mut self.ex_record, o.ex_record);
        pick(&mut self.ex_disowned, o.ex_disowned);
        pick(&mut self.ex_disagree, o.ex_disagree);
    }

    pub fn print(&self) {
        println!(
            "snapshot: {} histories | G starts at a snapshot {} | compactions at applied snapshots {} mismatches {} | compactions at since-unapplied snapshots {} diverging {} | order-dependent {} | nodes disagreeing after every delivery {} | drops with nobody offline {} | max passes {}",
            self.histories, self.with_snapshot_start, self.compactions, self.compaction_mismatch, self.unapplied_points, self.unapplied_diverge, self.order_dep, self.disagree, self.honest_mismatch, self.max_passes
        );
        println!(
            "  projections (plain and compacted) {} mismatches {} | owner-chain records {} valid {} | late records valid {} | record validity differing (order, compaction, projection) {} | fresh key-actor snapshots of P with roster and ledger {} changing records or G writes {}",
            self.projections, self.projection_mismatch, self.records, self.records_valid, self.late_record_valid, self.record_mismatch, self.resnapshots, self.disowned
        );
        for (label, ex) in [
            ("compaction mismatch", &self.ex_compaction),
            ("order dependence", &self.ex_order),
            ("drop with nobody offline", &self.ex_honest),
            ("projection mismatch", &self.ex_projection),
            ("late record valid", &self.ex_late),
            ("record validity differing", &self.ex_record),
            ("re-snapshot not neutral", &self.ex_disowned),
            ("disagreement after every delivery", &self.ex_disagree),
        ] {
            if let Some(h) = ex {
                // Shrunk while it still fails the same check.
                let mut h = if flags(h, label) { crate::shrink::shrink(h.clone(), |c| flags(c, label)) } else { h.clone() };
                if label == "drop with nobody offline" {
                    h = honest(&h).unwrap_or(h);
                }
                println!("  smallest {label} example:");
                print_hist(&h);
            }
        }
    }
}

/// A trace: genesis rosters, then each write in walk order with its receipts, then the result.
impl std::fmt::Display for SHist {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        writeln!(f, "    genesis P {:?} G {:?}", self.gp, self.gg)?;
        for i in self.order() {
            let w = &self.writes[i];
            let recv = crate::fmt_recv(&self.recv[i], w.author);
            match &w.snap {
                _ if w.rec => writeln!(f, "    w{i}: {} records #{} on {:?} at t={} id {} | {recv}", w.author, w.target, w.thing, w.t, w.id)?,
                Some(r) => writeln!(f, "    w{i}: {} snapshots {:?} := {:?} ledger {:?} at t={} id {} | {recv}", w.author, w.thing, r, w.ledger, w.t, w.id)?,
                None => writeln!(f, "    w{i}: {} sets {:?}[{}] := {:?} at t={} id {} | {recv}", w.author, w.thing, w.target, w.role, w.t, w.id)?,
            }
        }
        let o = self.eval(true);
        write!(
            f,
            "    -> P roles {:?} start {:?} | G roles {:?} start {:?} applied {:#b} dropped {:#b} ({} passes) | valid records {:?}",
            o.p.roles, o.p.start, o.g.roles, o.g.start, o.g.applied, o.g.dropped, o.g.passes, self.successors(&o)
        )
    }
}

pub fn print_hist(h: &SHist) {
    println!("{h}");
}

/// The result as a function of the write set: roles, epoch starts, applied writes and valid
/// records (by `SWrite::id`).
fn result(h: &SHist, o: &Out) -> (Vec<Role>, Vec<Role>, Vec<Option<usize>>, Vec<usize>, Vec<usize>) {
    let ids = |m: u64| -> Vec<usize> {
        let mut v: Vec<usize> = (0..h.writes.len()).filter(|&j| m >> j & 1 == 1).map(|j| h.writes[j].id).collect();
        v.sort();
        v
    };
    let starts = vec![o.p.start.map(|s| h.writes[s].id), o.g.start.map(|s| h.writes[s].id)];
    let valid = h.successors(o).iter().fold(0u64, |m, &j| m | 1 << j);
    (o.p.roles.clone(), o.g.roles.clone(), starts, ids(o.p.applied | o.g.applied), ids(valid))
}

/// Quiescence: after every delivery, every node agrees (each node's evaluation over the
/// writes in the order it received them gives the canonical result). Returns the first node
/// that disagrees.
pub fn quiescent(h: &SHist) -> Result<(), usize> {
    let res = result(h, &walk(h));
    for n in 0..h.n() {
        let ph = h.permute(&crate::delivery_order(&h.recv, n));
        if result(&ph, &walk(&ph)) != res {
            return Err(n);
        }
    }
    Ok(())
}

/// The timeline of both things (§5.1, §6) with audits on.
pub fn walk(h: &SHist) -> Out {
    h.eval(true)
}

/// Whether `check` counts `h` under the example `label` (for shrinking it).
fn flags(h: &SHist, label: &str) -> bool {
    let mut st = Stats::default();
    check(h, &mut st, &mut crate::Rng(0x5eed));
    match label {
        "compaction mismatch" => st.compaction_mismatch > 0,
        "order dependence" | "disagreement after every delivery" => st.disagree > 0,
        "drop with nobody offline" => honest(h).map_or(false, |h| honest_drops(&h)),
        "projection mismatch" => st.projection_mismatch > 0,
        "late record valid" => st.late_record_valid > 0,
        "record validity differing" => st.record_mismatch > 0,
        "re-snapshot not neutral" => st.disowned > 0,
        _ => false,
    }
}

impl crate::shrink::Shrink for SHist {
    fn smaller(&self) -> Vec<SHist> {
        use crate::shrink::{compact_times, without, LATE};
        let mut out = Vec::new();
        let n = self.n();
        let lower = |r: Role| -> Vec<Role> { [Role::None, Role::Write].into_iter().filter(|&x| x < r).collect() };
        for i in 0..self.writes.len() {
            out.push(SHist { writes: without(&self.writes, i), recv: without(&self.recv, i), ..self.clone() });
        }
        for x in 1..n {
            for r in lower(self.gp[x]) {
                let mut h = self.clone();
                h.gp[x] = r;
                out.push(h);
            }
            for r in lower(self.gg[x]) {
                let mut h = self.clone();
                h.gg[x] = r;
                out.push(h);
            }
        }
        for i in 0..self.writes.len() {
            let w = &self.writes[i];
            for r in lower(w.role) {
                let mut h = self.clone();
                h.writes[i].role = r;
                out.push(h);
            }
            for x in 1..w.snap.as_ref().map_or(0, Vec::len) {
                for r in lower(w.snap.as_ref().unwrap()[x]) {
                    let mut h = self.clone();
                    h.writes[i].snap.as_mut().unwrap()[x] = r;
                    out.push(h);
                }
            }
            for k in 0..w.ledger.len() {
                let mut h = self.clone();
                h.writes[i].ledger.remove(k);
                out.push(h);
            }
            for m in (0..n).filter(|&m| m != w.author && self.recv[i][m] < LATE) {
                let mut h = self.clone();
                h.recv[i][m] = LATE;
                out.push(h);
            }
        }
        let keys = |h: &SHist| -> Vec<u32> { h.writes.iter().flat_map(|w| w.ledger.iter().flat_map(|e| e.since.into_iter().chain(e.until).map(|k| k.0))).collect() };
        let times: Vec<u32> = self.writes.iter().map(|w| w.t).chain(self.recv.iter().flatten().copied()).chain(keys(self)).collect();
        if let Some(map) = compact_times(&times) {
            let mut h = self.clone();
            h.recv.iter_mut().flatten().for_each(|v| *v = map(*v));
            for w in &mut h.writes {
                w.t = map(w.t);
                for e in &mut w.ledger {
                    for k in e.since.iter_mut().chain(e.until.iter_mut()) {
                        k.0 = map(k.0);
                    }
                }
            }
            out.push(h);
        }
        out
    }
}

/// Validity of the records by `author` (any if None) in `c`, holding `keep` of `h`'s
/// writes, equals `h`'s.
fn records_agree(h: &SHist, o: &Out, c: &SHist, keep: &[usize], author: Option<usize>) -> bool {
    let oc = c.eval(true);
    keep.iter().enumerate().all(|(new, &old)| {
        let w = &h.writes[old];
        !w.rec || author.map_or(false, |a| a != w.author) || c.record_valid(&oc, new) == h.record_valid(o, old)
    })
}

/// K re-snapshots P with the roster and ledger the timeline computes (as after removing a
/// device): every record keeps its validity and every G write its application.
pub fn resnapshot_neutral(h: &SHist, o: &Out) -> bool {
    let mut r = h.clone();
    r.writes.push(SWrite { author: K, thing: Thing::P, target: 0, role: Role::None, t: 100, snap: Some(o.p.roles.clone()), ledger: h.ledger_of(&o.p), rec: false, id: h.writes.len() + 1 });
    r.recv.push(vec![100; h.n()]);
    let or = r.eval(true);
    let n = h.writes.len();
    (0..n).all(|j| !h.writes[j].rec || h.record_valid(&o, j) == r.record_valid(&or, j))
        && or.g.roles == o.g.roles
        && or.g.applied & ((1 << n) - 1) == o.g.applied
}

/// A projection for each actor computes that actor's P and G roles as `o` does.
fn projections_agree(h: &SHist, o: &Out, st: &mut Stats) -> bool {
    (1..h.n()).all(|z| {
        st.projections += 1;
        let op = h.projected(z).0.eval(true);
        op.p.roles[z] == o.p.roles[z] && op.g.roles[z] == o.g.roles[z]
    })
}

fn check(h: &SHist, st: &mut Stats, rng: &mut crate::Rng) {
    st.histories += 1;
    let o = h.eval(true);
    let order = h.order();
    let pos = pos_of(&order);
    let mut projection_ok = projections_agree(h, &o, st);
    let mut records_ok = true;
    for j in (0..h.writes.len()).filter(|&j| h.writes[j].rec) {
        st.records += 1;
        let valid = h.record_valid(&o, j);
        st.records_valid += valid as u64;
        // Late: its author was demoted from P by a write whose frontier misses it.
        let late = o.p.demotions.iter().any(|&(r, z)| {
            let rw = &h.writes[r];
            h.writes[j].author == z && pos[j] < pos[r] && !(h.recv[j][rw.author] < rw.t)
        });
        if late && valid {
            st.late_record_valid += 1;
            st.ex_late.get_or_insert_with(|| h.clone());
        }
        let (pj, keep) = h.projected(h.writes[j].author);
        records_ok &= records_agree(h, &o, &pj, &keep, Some(h.writes[j].author));
    }
    st.max_passes = st.max_passes.max(o.p.passes.max(o.g.passes));
    if o.g.start.is_some() {
        st.with_snapshot_start += 1;
    }
    for thing in [Thing::P, Thing::G] {
        let applied = h.snapshots(thing, &o, true);
        for s in h.snapshots(thing, &o, false) {
            let (c, keep) = h.compacted(thing, s);
            let oc = c.eval(true);
            if applied.contains(&s) {
                projection_ok &= projections_agree(&c, &o, st);
                records_ok &= records_agree(h, &o, &c, &keep, None);
            }
            let same = oc.p.roles == o.p.roles
                && oc.g.roles == o.g.roles
                && oc.p.applied == applied_kept(o.p.applied, &keep)
                && oc.g.applied == applied_kept(o.g.applied, &keep);
            if applied.contains(&s) {
                st.compactions += 1;
                if !same {
                    st.compaction_mismatch += 1;
                    st.ex_compaction.get_or_insert_with(|| h.clone());
                }
            } else {
                st.unapplied_points += 1;
                if !same {
                    st.unapplied_diverge += 1;
                }
            }
        }
    }
    if !resnapshot_neutral(h, &o) {
        st.disowned += 1;
        st.ex_disowned.get_or_insert_with(|| h.clone());
    }
    st.resnapshots += 1;
    let perm = rng.perm(h.writes.len());
    let ph = h.permute(&perm);
    let op = ph.eval(true);
    if op.p.roles != o.p.roles || op.g.roles != o.g.roles {
        st.order_dep += 1;
        st.ex_order.get_or_insert_with(|| h.clone());
    }
    records_ok &= records_agree(h, &o, &ph, &perm, None);
    if quiescent(h).is_err() {
        st.disagree += 1;
        st.ex_disagree.get_or_insert_with(|| h.clone());
    }
    if !projection_ok {
        st.projection_mismatch += 1;
        st.ex_projection.get_or_insert_with(|| h.clone());
    }
    if !records_ok {
        st.record_mismatch += 1;
        st.ex_record.get_or_insert_with(|| h.clone());
    }
    if let Some(honest) = honest(h) {
        if honest_drops(&honest) {
            st.honest_mismatch += 1;
            st.ex_honest.get_or_insert(honest);
        }
    }
}

/// `h` with nobody offline (None when two writes share a time).
fn honest(h: &SHist) -> Option<SHist> {
    let distinct = h.writes.iter().map(|w| w.t).collect::<HashSet<_>>().len() == h.writes.len();
    distinct.then(|| {
        let mut honest = h.clone();
        for (i, r) in honest.recv.iter_mut().enumerate() {
            r.fill(h.writes[i].t);
        }
        honest
    })
}

/// With nobody offline nothing is dropped, and the result equals the one without audits.
fn honest_drops(h: &SHist) -> bool {
    let (a, b) = (h.eval(true), h.eval(false));
    a.p.roles != b.p.roles || a.g.roles != b.g.roles || a.p.dropped != 0 || a.g.dropped != 0
}

pub fn random_hist(rng: &mut crate::Rng) -> SHist {
    let devices = 1 + rng.below(2);
    let gnodes = 1 + rng.below(3);
    let n = 1 + devices + gnodes;
    let mut gp = vec![Role::None; n];
    let mut gg = vec![Role::None; n];
    for d in 1..=devices {
        gp[d] = Role::Admin;
    }
    for x in 1 + devices..n {
        gg[x] = [Role::None, Role::Write, Role::Admin, Role::Admin][rng.below(4)];
    }
    let k = 2 + rng.below(7);
    let mut writes = Vec::new();
    let mut recv = Vec::new();
    let rt = |rng: &mut crate::Rng, t: u32| -> u32 {
        if rng.below(3) == 0 {
            LATE
        } else {
            (t as i64 + rng.below(6) as i64 - 2).max(0) as u32
        }
    };
    while writes.len() < k {
        let thing = if rng.below(4) == 0 { Thing::P } else { Thing::G };
        let author = if rng.below(8) == 0 {
            rng.below(n)
        } else if thing == Thing::P || rng.below(2) == 0 {
            rng.below(1 + devices)
        } else {
            1 + devices + rng.below(gnodes)
        };
        // Writes at even times; ledger keys at odd times, so no key ties a write's. Usually
        // one write per (t, author); sometimes two (one key used from two devices), told
        // apart by `id`.
        let t = 2 * (1 + rng.below(10) as u32);
        if rng.below(4) != 0 && writes.iter().any(|w: &SWrite| w.t == t && w.author == author) {
            continue;
        }
        let snap = if rng.below(4) == 0 {
            let roles: Vec<Role> = (0..n)
                .map(|_| match thing {
                    Thing::P => [Role::None, Role::Admin][rng.below(2)],
                    Thing::G => [Role::None, Role::Write, Role::Admin][rng.below(3)],
                })
                .collect();
            Some(roles)
        } else {
            None
        };
        let target = 1 + rng.below(n - 1);
        let role = match thing {
            Thing::P => [Role::None, Role::Admin][rng.below(2)],
            Thing::G => [Role::None, Role::None, Role::Write, Role::Admin][rng.below(4)],
        };
        let mut r: Vec<u32> = (0..n).map(|_| rt(rng, t)).collect();
        r[author] = t;
        let rec = thing == Thing::G && snap.is_none() && rng.below(6) == 0;
        // Random well-formed ledgers (per member: disjoint intervals in order, ending before
        // the snapshot, at most the last one open) exercise the rule; only `ledger_of`
        // produces ones that match a history.
        let mut ledger: Vec<Entry> = vec![];
        if thing == Thing::P && snap.is_some() && rng.below(2) == 0 {
            for member in 1..n {
                let intervals = [0, 0, 1, 1, 2][rng.below(5)];
                let mut times: Vec<u32> = (0..2 * intervals).map(|_| 1 + 2 * rng.below(t as usize / 2) as u32).collect();
                times.sort();
                times.dedup();
                for (i, pair) in times.chunks(2).enumerate() {
                    let key = |t: u32, rng: &mut crate::Rng| (t, rng.below(n), 0);
                    let since = if i == 0 && rng.below(2) == 0 { Option::None } else { Some(key(pair[0], rng)) };
                    let until = if pair.len() == 2 && !(i + 1 == times.len() / 2 && rng.below(3) == 0) { Some(key(pair[1], rng)) } else { Option::None };
                    let open = until.is_none();
                    ledger.push(Entry { member, since, until });
                    if open {
                        break;
                    }
                }
            }
        }
        let id = writes.len() + 1;
        writes.push(SWrite { author, thing, target, role, t, snap, ledger, rec, id });
        recv.push(r);
    }
    // honest receipts: a snapshot sets everyone's edges, a record none
    let ws: Vec<(usize, u32)> = writes.iter().map(|w| (w.author, w.t)).collect();
    let sets = |j: usize, x: usize| writes[j].snap.is_some() || (!writes[j].rec && writes[j].target == x);
    let eligible: Vec<bool> = writes.iter().map(|w| w.snap.is_none() && w.role < Role::Admin).collect();
    let late = crate::late_writes(rng, &eligible);
    crate::hold_chains(&ws, &late, sets, &mut recv);
    SHist { gp, gg, writes, recv }
}

pub fn random(samples: u64, seed: u64) -> Stats {
    let threads = std::thread::available_parallelism().map_or(4, |n| n.get()) as u64;
    let stats: Vec<Stats> = std::thread::scope(|s| {
        let hs: Vec<_> = (0..threads)
            .map(|th| {
                s.spawn(move || {
                    let mut rng = crate::Rng(seed ^ (th + 1).wrapping_mul(0x9E3779B97F4A7C15));
                    let mut st = Stats::default();
                    for _ in 0..samples / threads {
                        let h = random_hist(&mut rng);
                        check(&h, &mut st, &mut rng);
                    }
                    st
                })
            })
            .collect();
        hs.into_iter().map(|h| h.join().unwrap()).collect()
    });
    let mut all = Stats::default();
    for s in stats {
        all.merge(s);
    }
    all
}

// ---------- scenarios ----------

#[cfg(test)]
mod tests {
    use super::*;
    use Role::*;
    use Thing::*;

    // Nodes: K=0, devices D1=1, D2=2, G members A=3 (admin), B=4 (writer), Z=5 (nobody).
    const D1: usize = 1;
    const D2: usize = 2;
    const A: usize = 3;
    const B: usize = 4;
    const Z: usize = 5;
    const GP: [Role; 6] = [None, Admin, Admin, None, None, None];
    const GG: [Role; 6] = [None, None, None, Admin, Write, None];

    #[derive(Clone)]
    struct B6(SHist);
    impl B6 {
        fn new() -> Self {
            B6(SHist { gp: GP.to_vec(), gg: GG.to_vec(), writes: vec![], recv: vec![] })
        }
        fn push(&mut self, mut w: SWrite, recv: &[(usize, u32)]) -> usize {
            w.id = self.0.writes.len() + 1;
            let mut r = vec![LATE; 6];
            r[w.author] = w.t;
            for &(m, tm) in recv {
                r[m] = tm;
            }
            self.0.writes.push(w);
            self.0.recv.push(r);
            self.0.writes.len() - 1
        }
        fn set(&mut self, author: usize, thing: Thing, target: usize, role: Role, t: u32, recv: &[(usize, u32)]) -> usize {
            self.push(SWrite { author, thing, target, role, t, snap: Option::None, ledger: vec![], rec: false, id: 0 }, recv)
        }
        fn snap(&mut self, author: usize, thing: Thing, roster: [Role; 6], t: u32, recv: &[(usize, u32)]) -> usize {
            self.snap_l(author, thing, roster, vec![], t, recv)
        }
        fn snap_l(&mut self, author: usize, thing: Thing, roster: [Role; 6], ledger: Vec<Entry>, t: u32, recv: &[(usize, u32)]) -> usize {
            self.push(SWrite { author, thing, target: 0, role: None, t, snap: Some(roster.to_vec()), ledger, rec: false, id: 0 }, recv)
        }
    }

    fn g(h: &SHist) -> Vec<Role> {
        h.eval(true).g.roles
    }

    fn rec(b: &mut B6, author: usize, to: usize, t: u32, recv: &[(usize, u32)]) -> usize {
        b.push(SWrite { author, thing: G, target: to, role: None, t, snap: Option::None, ledger: vec![], rec: true, id: 0 }, recv)
    }

    /// Every actor's projection agrees with the full node.
    fn assert_projections(h: &SHist) {
        let o = h.eval(true);
        for z in 1..h.n() {
            let op = h.projected(z).0.eval(true);
            assert_eq!((op.p.roles[z], op.g.roles[z]), (o.p.roles[z], o.g.roles[z]), "projection for {z}");
        }
    }

    /// Compacting at every applied snapshot gives the full result.
    fn assert_compaction_invariant(h: &SHist) {
        let o = h.eval(true);
        for thing in [P, G] {
            for s in h.snapshots(thing, &o, true) {
                let (c, _) = h.compacted(thing, s);
                let oc = c.eval(true);
                assert_eq!((oc.p.roles, oc.g.roles), (o.p.roles.clone(), o.g.roles.clone()), "compacted {thing:?} at w{s}");
            }
        }
    }

    /// Owner snapshot then churn: the key actor snapshots G, later writes apply on top, a
    /// post-snapshot demotion audits only post-snapshot writes, and a verifier holding only
    /// the snapshot and later writes agrees.
    #[test]
    fn owner_snapshot_then_churn() {
        let mut b = B6::new();
        b.set(A, G, Z, Admin, 2, &[]); // pre-snapshot grant, nobody else saw it
        b.snap(K, G, [None, None, None, Admin, Write, Admin], 5, &[]);
        b.set(Z, G, B, Admin, 6, &[]); // Z admin by the snapshot
        b.set(A, G, Z, None, 8, &[]); // A demotes Z without having received w2: dropped
        let h = b.0;
        assert_eq!(g(&h), vec![Admin, None, None, Admin, Write, None]);
        let o = h.eval(true);
        assert_eq!(o.g.dropped, 0b100);
        assert_compaction_invariant(&h);
        let (c, _) = h.compacted(G, 1);
        assert_eq!(c.writes.len(), 3);
        assert_projections(&h);
        assert_projections(&c);
    }

    /// A grant with a pre-snapshot timestamp arriving after the snapshot is ignored
    /// everywhere, whether or not the pre-snapshot history is still held.
    #[test]
    fn late_pre_snapshot_grant() {
        let mut b = B6::new();
        b.snap(D1, G, [None, None, None, Admin, Write, None], 5, &[(K, 5), (D2, 5), (A, 5), (B, 5)]);
        b.set(A, G, Z, Admin, 4, &[]); // in flight while D1 snapshotted
        let h = b.0;
        assert_eq!(g(&h), vec![Admin, None, None, Admin, Write, None]);
        assert_compaction_invariant(&h);
    }

    /// Stolen device D1 snapshots G at t=5 granting Z admin. D2 removes D1 from P backdated
    /// to t=3: the snapshot no longer applies. A node holding the full history falls back to
    /// it (Z gone, A and B as before); a node that compacted at the snapshot holds nothing
    /// before it and sees an empty roster: they diverge until D2's fresh snapshot, which
    /// both start from. Removal at t=7 by a node that received the snapshot at t=6 leaves
    /// it standing; at t=7 without having received it, the snapshot is dropped, same
    /// divergence, same remedy.
    #[test]
    fn stolen_device_snapshot_undone_by_backdated_removal() {
        let mut b = B6::new();
        b.snap(D1, G, [None, None, None, Admin, Write, Admin], 5, &[(D2, 6), (A, 5), (Z, 5)]);
        b.set(D2, P, D1, None, 3, &[]);
        let h = b.0.clone();
        let o = h.eval(true);
        assert_eq!(o.p.roles, vec![Admin, None, Admin, None, None, None]);
        assert_eq!(o.g.start, Option::None);
        assert_eq!(o.g.roles, vec![Admin, None, None, Admin, Write, None]);
        assert!(h.snapshots(G, &o, true).is_empty());
        let (c, _) = h.compacted(G, 0);
        assert_eq!(g(&c), vec![Admin, None, None, None, None, None]);
        // Recourse: D2 re-snapshots after the removal; full and compacted agree again.
        b.snap(D2, G, [None, None, None, Admin, Write, None], 7, &[]);
        let h2 = b.0;
        assert_eq!(g(&h2), vec![Admin, None, None, Admin, Write, None]);
        let (c2, _) = h2.compacted(G, 0);
        assert_eq!(g(&c2), g(&h2));
        assert_compaction_invariant(&h2);
        // Removal at t=7 with the snapshot received at t=6: covered, it stands.
        let mut b = B6::new();
        b.snap(D1, G, [None, None, None, Admin, Write, Admin], 5, &[(D2, 6), (A, 5), (Z, 5)]);
        b.set(D2, P, D1, None, 7, &[]);
        assert_eq!(g(&b.0), vec![Admin, None, None, Admin, Write, Admin]);
        assert_compaction_invariant(&b.0);
        // Removal at t=7 by a remover that never received it: dropped.
        let mut b = B6::new();
        let s = b.snap(D1, G, [None, None, None, Admin, Write, Admin], 5, &[(A, 5), (Z, 5)]);
        b.set(D2, P, D1, None, 7, &[]);
        let o = b.0.eval(true);
        assert_eq!(o.g.dropped >> s & 1, 1);
        assert_eq!(o.g.roles, vec![Admin, None, None, Admin, Write, None]);
        assert_projections(&b.0);
    }

    /// A device removed from P cannot mint an epoch start: a snapshot claimed after its
    /// removal is inapplicable, one backdated into its tenure is dropped by the removal's
    /// frontier. Neither is ever the start, so nobody compacts at it and nothing diverges.
    #[test]
    fn forged_snapshot_by_removed_device() {
        let mut b = B6::new();
        b.set(D2, P, D1, None, 4, &[(K, 4), (A, 4)]);
        b.snap(D1, G, [None, None, None, None, None, Admin], 8, &[]); // after removal
        b.snap(D1, G, [None, None, None, None, None, Admin], 3, &[]); // backdated into tenure
        let h = b.0.clone();
        let o = h.eval(true);
        assert_eq!(o.g.start, Option::None);
        assert_eq!(o.g.dropped, 0b100);
        assert_eq!(o.g.roles, vec![Admin, None, None, Admin, Write, None]);
        assert!(h.snapshots(G, &o, true).is_empty());
        b.snap(D2, G, [None, None, None, Admin, Write, None], 6, &[]);
        let o = b.0.eval(true);
        assert_eq!(o.g.start, Some(3));
        assert_eq!(o.g.roles, vec![Admin, None, None, Admin, Write, None]);
        assert_compaction_invariant(&b.0);
    }

    /// An edge-admin of G demoting an ex-device's edge role audits only the writes it made
    /// by edge authority, never its snapshot.
    #[test]
    fn edge_demotion_never_audits_chain_writes() {
        let mut b = B6::new();
        b.set(A, G, D1, Admin, 1, &[(D1, 1)]); // D1 also edge-admin of G
        let s = b.snap(D1, G, [None, Admin, None, Admin, Write, Admin], 5, &[(D2, 5), (A, 5)]);
        b.set(D2, P, D1, None, 7, &[]); // covered: D2 received the snapshot
        b.set(A, G, D1, None, 9, &[]); // A never received the snapshot; irrelevant
        let o = b.0.eval(true);
        assert_eq!(o.g.dropped >> s & 1, 0);
        assert_eq!(o.g.start, Some(s));
        assert_eq!(o.g.roles, vec![Admin, None, None, Admin, Write, Admin]);
        assert_compaction_invariant(&b.0);
    }

    /// A snapshot by an edge-admin of G is not an epoch start and is ignored.
    #[test]
    fn edge_admin_snapshot_ignored() {
        let mut b = B6::new();
        b.snap(A, G, [None, None, None, Admin, Admin, Admin], 5, &[]);
        let h = b.0;
        let o = h.eval(true);
        assert_eq!(o.g.start, Option::None);
        assert_eq!(o.g.roles, vec![Admin, None, None, Admin, Write, None]);
    }

    /// A demotion in P audits the device's ordinary writes on G too.
    #[test]
    fn p_demotion_audits_g_writes() {
        let mut b = B6::new();
        b.set(D1, G, Z, Admin, 2, &[]);
        b.set(D2, P, D1, None, 5, &[]);
        assert_eq!(g(&b.0)[Z], None);
        let mut b = B6::new();
        b.set(D1, G, Z, Admin, 2, &[(D2, 3)]);
        b.set(D2, P, D1, None, 5, &[]);
        assert_eq!(g(&b.0)[Z], Admin);
    }

    /// The key actor's snapshot of P: its roster and ledger stand for all earlier time, so
    /// a device neither lists never had authority on G, and compaction of P changes nothing.
    #[test]
    fn owner_snapshot_of_p_governs_earlier_time() {
        let mut b = B6::new();
        b.set(D1, G, Z, Admin, 2, &[(D2, 2), (A, 2)]);
        b.snap(K, P, [None, None, Admin, None, None, None], 6, &[]);
        let h = b.0;
        let o = h.eval(true);
        assert_eq!(o.p.roles, vec![Admin, None, Admin, None, None, None]);
        assert_eq!(o.g.roles[Z], None);
        assert_eq!(o.g.applied, 0);
        assert_compaction_invariant(&h);
    }

    /// Two owner-chain snapshots: the newer applicable one wins, and compacting at the
    /// older one still agrees.
    #[test]
    fn newest_applicable_snapshot_wins() {
        let mut b = B6::new();
        b.snap(D1, G, [None, None, None, Admin, Write, Admin], 3, &[]);
        b.set(A, G, B, Admin, 4, &[]);
        b.snap(D2, G, [None, None, None, Admin, None, None], 6, &[]);
        b.set(A, G, Z, Write, 7, &[]);
        let h = b.0;
        assert_eq!(g(&h), vec![Admin, None, None, Admin, None, Write]);
        assert_eq!(h.eval(true).g.start, Some(2));
        assert_compaction_invariant(&h);
    }

    /// Projection closure: B's role on G hinges on Z, who granted it; Z's own grant came
    /// from device D1, whose removal from P (frontier missing the grant) drops it, which
    /// takes B's grant with it. The projection for B holds exactly that chain.
    #[test]
    fn projection_follows_the_chain() {
        let mut b = B6::new();
        b.set(D1, G, Z, Admin, 2, &[(Z, 2)]);
        b.set(Z, G, B, Admin, 3, &[]);
        b.set(A, G, D2, Write, 4, &[]); // unrelated to B
        b.set(D2, P, D1, None, 5, &[]);
        let h = b.0;
        assert_eq!(g(&h)[B], Write);
        let (p, _) = h.projected(B);
        assert_eq!(p.writes.len(), 3);
        assert_projections(&h);
    }

    /// Record disowned: D1 writes a record #9 on G at t=5; D2, which never received it,
    /// removes D1 from P, backdated to t=4 or at t=7. Either way the record is invalid at
    /// every node, compacted or not.
    #[test]
    fn record_disowned_by_device_removal() {
        for removal_t in [4, 7] {
            let mut b = B6::new();
            let h_rec = rec(&mut b, D1, 9, 5, &[(A, 5)]);
            b.set(D2, P, D1, None, removal_t, &[]);
            let s = b.snap(D2, G, [None, None, None, Admin, Write, None], 8, &[]);
            let h = b.0;
            let o = h.eval(true);
            assert!(!h.record_valid(&o, h_rec), "removal at {removal_t}");
            assert!(h.successors(&o).is_empty());
            let (c, keep) = h.compacted(G, s);
            let ci = keep.iter().position(|&i| i == h_rec).unwrap();
            assert!(!c.record_valid(&c.eval(true), ci));
        }
        // Received by D2 before its removal of D1: the record stands.
        let mut b = B6::new();
        let h_rec = rec(&mut b, D1, 9, 5, &[(D2, 6)]);
        b.set(D2, P, D1, None, 7, &[]);
        let o = b.0.eval(true);
        assert_eq!(b.0.successors(&o), vec![h_rec]);
    }

    /// A removed device's late record never becomes a valid successor: after its removal it
    /// has no authority, backdated into its tenure it is dropped by the removal's frontier.
    /// A competing honest record by D2 is then the only valid successor (no fork).
    #[test]
    fn removed_device_late_record_never_valid() {
        let mut b = B6::new();
        b.set(D2, P, D1, None, 4, &[(K, 4), (D1, 4), (A, 4)]);
        let after = rec(&mut b, D1, 9, 6, &[(K, 6), (A, 6)]);
        let backdated = rec(&mut b, D1, 9, 3, &[(K, 6), (A, 6)]);
        let honest = rec(&mut b, D2, 8, 8, &[]);
        let h = b.0;
        let o = h.eval(true);
        assert!(!h.record_valid(&o, after));
        assert!(!h.record_valid(&o, backdated));
        assert_eq!(h.successors(&o), vec![honest]);
        for z in [D1, D2] {
            let (p, keep) = h.projected(z);
            let op = p.eval(true);
            let valid: Vec<usize> = p.successors(&op).iter().map(|&i| keep[i]).collect();
            assert_eq!(valid, vec![honest], "projection for {z}");
        }
    }

    /// The key actor re-snapshots P after D2 removed D1 (as §6 recommends). The ledger
    /// carries D1's admin interval and the removal's frontier, so the record D1 signed
    /// as a legitimate admin, which D2 had received, stays valid, compacted or not, while
    /// one D2 had not received stays invalid. A snapshot without the ledger disowned both.
    #[test]
    fn p_resnapshot_keeps_former_device_records() {
        let mut b = B6::new();
        let seen = rec(&mut b, D1, 9, 3, &[(D2, 3)]);
        let unseen = rec(&mut b, D1, 8, 4, &[]);
        let rm = b.set(D2, P, D1, None, 5, &[]);
        let o = b.0.eval(true);
        assert_eq!(b.0.successors(&o), vec![seen]);
        let ledger = b.0.ledger_of(&o.p);
        assert_eq!(
            ledger,
            vec![Entry { member: D1, since: Option::None, until: Some((5, D2, rm + 1)) }, Entry { member: D2, since: Option::None, until: Option::None }]
        );
        assert!(resnapshot_neutral(&b.0, &o));
        let roster = [None, None, Admin, None, None, None];
        let mut with = b.clone();
        let s = with.snap_l(K, P, roster, ledger, 7, &[]);
        let ow = with.0.eval(true);
        assert_eq!(ow.p.start, Some(s));
        assert_eq!(with.0.successors(&ow), vec![seen]);
        assert!(!with.0.record_valid(&ow, unseen));
        let (c, keep) = with.0.compacted(P, s);
        let oc = c.eval(true);
        assert_eq!(c.successors(&oc).iter().map(|&i| keep[i]).collect::<Vec<_>>(), vec![seen]);
        b.snap(K, P, roster, 7, &[]);
        assert!(b.0.successors(&b.0.eval(true)).is_empty());
    }

    /// A ledger interval keeps the gap closed: D1 removed at 2 (seen by D2), re-granted at
    /// 4, current admin. A record D1 signed in the gap is invalid by the full history and
    /// stays so after K re-snapshots P with D1 in the roster, since its roster edge's
    /// `since` is the re-grant; a snapshot without `since` would adopt it.
    #[test]
    fn p_resnapshot_keeps_gap_closed() {
        let mut b = B6::new();
        b.set(D2, P, D1, None, 2, &[]);
        let gap = rec(&mut b, D1, 9, 3, &[(D2, 3)]);
        let regrant = b.set(D2, P, D1, Admin, 4, &[]);
        let o = b.0.eval(true);
        assert!(!b.0.record_valid(&o, gap));
        assert!(resnapshot_neutral(&b.0, &o));
        let ledger = b.0.ledger_of(&o.p);
        assert_eq!(ledger.iter().find(|e| e.member == D1 && e.until.is_none()).unwrap().since, Some((4, D2, regrant + 1)));
        b.snap_l(K, P, [None, Admin, Admin, None, None, None], ledger, 7, &[]);
        assert!(!b.0.record_valid(&b.0.eval(true), gap));
        let mut no_since = B6::new();
        let gap = rec(&mut no_since, D1, 9, 3, &[(D2, 3)]);
        no_since.snap(K, P, [None, Admin, Admin, None, None, None], 7, &[]);
        assert!(no_since.0.record_valid(&no_since.0.eval(true), gap));
    }

    /// A G snapshot by D1 at t=4 and a G grant by D1 at t=5 survive P's re-snapshot at t=7
    /// after D1's removal at t=6, through the ledger; the §6 re-snapshot of G is no longer
    /// needed for correctness.
    #[test]
    fn p_resnapshot_keeps_former_device_g_writes() {
        let mut b = B6::new();
        let s = b.snap(D1, G, [None, None, None, Admin, Write, None], 4, &[(D2, 4)]);
        b.set(D1, G, Z, Write, 5, &[(D2, 5)]);
        b.set(D2, P, D1, None, 6, &[]);
        let o = b.0.eval(true);
        assert_eq!(o.g.start, Some(s));
        assert_eq!(g(&b.0)[Z], Write);
        assert!(resnapshot_neutral(&b.0, &o));
        let ledger = b.0.ledger_of(&o.p);
        let mut bare = b.clone();
        bare.snap(K, P, [None, None, Admin, None, None, None], 7, &[]);
        let ob = bare.0.eval(true);
        assert_eq!(ob.g.start, Option::None);
        assert_eq!(ob.g.roles[Z], None);
        b.snap_l(K, P, [None, None, Admin, None, None, None], ledger, 7, &[]);
        let o = b.0.eval(true);
        assert_eq!(o.g.start, Some(s));
        assert_eq!(o.g.roles[Z], Write);
    }

    /// Two admin paths to G: A is G's edge admin and, from t=2, a P admin (owner chain).
    /// A's grant of Z at t=1 is edge class. Whichever path is removed first, the removal that
    /// leaves A without admin on G audits it: edge first (D1 at 3, no fall: A still holds the
    /// chain), then D2's removal from P at 4 falls through edge admin too; chain first, D1's
    /// edge removal at 4 audits it. Dropped unless that remover had received it.
    #[test]
    fn two_admin_paths_class_attribution() {
        for edge_first in [true, false] {
            for seen in [false, true] {
                let mut b = B6::new();
                let (te, tp) = if edge_first { (3, 4) } else { (4, 3) };
                let last = if edge_first { D2 } else { D1 };
                let recv: &[(usize, u32)] = if seen { &[(last, 1)] } else { &[] };
                b.set(A, G, Z, Admin, 1, recv);
                b.set(D1, P, A, Admin, 2, &[]);
                b.set(D1, G, A, None, te, &[]);
                b.set(D2, P, A, None, tp, &[]);
                let h = b.0;
                assert_eq!(g(&h)[Z], if seen { Admin } else { None }, "edge first {edge_first}, seen {seen}");
                assert_compaction_invariant(&h);
                assert_projections(&h);
            }
        }
    }

    /// The same through the ledger: K re-snapshots P after D2 removed A, so the tenure end is
    /// a ledger entry; the result is unchanged.
    #[test]
    fn two_admin_paths_through_ledger() {
        let mut b = B6::new();
        b.set(A, G, Z, Admin, 1, &[]);
        b.set(D1, P, A, Admin, 2, &[]);
        b.set(D1, G, A, None, 3, &[]);
        b.set(D2, P, A, None, 4, &[]);
        let o = b.0.eval(true);
        assert_eq!(o.g.roles[Z], None);
        assert!(resnapshot_neutral(&b.0, &o));
        let ledger = b.0.ledger_of(&o.p);
        let s = b.snap_l(K, P, [None, Admin, Admin, None, None, None], ledger, 7, &[]);
        let (c, _) = b.0.compacted(P, s);
        assert_eq!(g(&c)[Z], None);
    }
}
