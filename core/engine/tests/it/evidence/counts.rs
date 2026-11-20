//! Count tests (spec/permissions.md §4; notes/evidence-derivation.md, Incremental): the work each change does, at n and
//! 10n, on the derivation alone. K writes D along a path of k holder things H1..Hk outside D's
//! unit (X mints them and D; X grants K on H1, each Hj on the next, Hk on D).
use osis_engine::evidence::{Config, Counts, Evidence, Hop, Kind, Part, Write};

type E = Evidence<u32, u16, u32>;
const X: u16 = 1;
const K: u16 = 2;
const Z: u16 = 3;
const D: u16 = 100;
const D2: u16 = 101;

fn rec(a: u16, b: u16) -> Hop<u16> {
    Hop { edge: (a, b), record: true }
}
fn hop(a: u16, b: u16) -> Hop<u16> {
    Hop { edge: (a, b), record: false }
}
fn write(holder: u16) -> Kind<u32, u16> {
    Kind::Write(Write { holder, grant: true, removal: false, gives_write: true, gives_read: true, relies: None, creation: None })
}

fn minus(a: Counts, b: Counts) -> Counts {
    Counts { atoms: a.atoms - b.atoms, edges: a.edges - b.edges, visits: a.visits - b.visits, rechecks: a.rechecks - b.rechecks, reach: a.reach - b.reach, reach_seeds: a.reach_seeds - b.reach_seeds, opened: a.opened - b.opened, closes: a.closes - b.closes, bodies: a.bodies - b.bodies, seeds: a.seeds - b.seeds }
}

struct World {
    ev: E,
    next: u32,
    hs: Vec<u16>,
}

impl World {
    /// The path of `k` holder things and `n` writes of K on `on` along it.
    fn new(k: usize, n: usize) -> World {
        let mut ev = E::new(Config { vouches: true, reach: false, keys_open: false });
        for s in [D, D2] {
            ev.add_sid(s, s);
            ev.join(&s, s);
        }
        let hs: Vec<u16> = (0..k as u16).map(|j| 10 + j).collect();
        let mut w = World { ev, next: 1, hs };
        if let Some(&h0) = w.hs.first() {
            w.grant(K, h0, vec![rec(X, h0)], true);
        }
        for j in 0..k {
            let h = w.hs[j];
            let next = w.hs.get(j + 1).copied().unwrap_or(D);
            w.grant(h, next, vec![rec(X, next)], true);
            if next == D {
                w.grant(h, D2, vec![rec(X, D2)], true);
            }
        }
        for _ in 0..n {
            w.content(D);
        }
        w
    }
    fn grant(&mut self, holder: u16, on: u16, hops: Vec<Hop<u16>>, chained: bool) -> (u32, u16) {
        let c = (self.next, on);
        self.next += 1;
        self.ev.add(c, vec![Part { kind: write(holder), hops: Some(hops), pos: c.0, chained }]);
        c
    }
    fn content(&mut self, on: u16) {
        let mut hops = vec![];
        let mut prev = K;
        for &h in &self.hs {
            hops.push(hop(prev, h));
            prev = h;
        }
        hops.push(hop(prev, on));
        let c = (self.next, on);
        self.next += 1;
        self.ev.add(c, vec![Part { kind: Kind::Content, hops: Some(hops), pos: c.0, chained: false }]);
    }
    /// The work `f` does.
    fn work(&mut self, f: impl FnOnce(&mut World)) -> Counts {
        let before = self.ev.counts();
        f(self);
        minus(self.ev.counts(), before)
    }
}

/// A body appended on a path of k edges: k + 1 atoms in D, no closure work, the same at n and 10n
/// (O(k), independent of history).
#[test]
fn a_body_appended_costs_its_path_whatever_the_history() {
    for k in [1, 3] {
        let at = |n: usize| {
            let mut w = World::new(k, n);
            let c = w.work(|w| w.content(D));
            assert_eq!(w.ev.required(&D).unwrap().len(), k);
            c
        };
        let (a, b) = (at(10), at(100));
        assert_eq!(a, b, "k {k}");
        assert_eq!((a.atoms, a.edges, a.visits, a.closes, a.bodies), (k + 1, 0, 0, 0, 1), "k {k}: {a:?}");
    }
}

/// A role commit on an edge m bodies use (X grants K on H1 again): one copy taken into each sync
/// ID using the edge, found by the edge's index; no body read, no closure again, the same at m and
/// 10m.
#[test]
fn a_role_commit_on_a_used_edge_reaches_its_sync_ids_by_the_edge_index() {
    let at = |m: usize| {
        let mut w = World::new(2, m);
        let h0 = w.hs[0];
        let before = w.ev.required(&D).unwrap().len();
        let c = w.work(|w| {
            w.grant(K, h0, vec![rec(X, h0)], true);
        });
        assert_eq!(w.ev.required(&D).unwrap().len(), before + 1);
        c
    };
    let (a, b) = (at(10), at(100));
    assert_eq!(a, b);
    assert_eq!((a.bodies, a.closes, a.atoms), (0, 0, 0), "{a:?}");
    assert!(a.visits <= 2, "{a:?}");
}

/// Junk (P10): unchained grants by a non-admin on a used edge cost their own arrival only (one
/// recheck each) and are no copy; a sync ID taking the edge in later reads none of them.
#[test]
fn junk_costs_its_own_arrival_and_is_no_copy() {
    let at = |n: usize| {
        let mut w = World::new(2, 5);
        let h0 = w.hs[0];
        let before = w.ev.required(&D).cloned();
        let c = w.work(|w| {
            for _ in 0..n {
                w.grant(K, h0, vec![hop(Z, h0)], false);
            }
        });
        assert_eq!(w.ev.required(&D).cloned(), before);
        // D2 takes the path's edges in with its first body: what it reads is the same however much
        // junk lies on them
        let later = w.work(|w| w.content(D2));
        (c, later)
    };
    let ((a, la), (b, lb)) = (at(3), at(30));
    assert_eq!((a.visits, a.edges, a.atoms, a.bodies, a.closes), (0, 0, 0, 0, 0), "{a:?}");
    assert_eq!((a.rechecks, b.rechecks), (3, 30));
    assert_eq!(la, lb);
}

/// A thing entering a unit with b bodies: each read once, its path's edges counted (O(b · path)).
#[test]
fn a_thing_entering_a_unit_reads_its_bodies_once() {
    let at = |b: usize| {
        let mut w = World::new(2, b);
        w.ev.add_sid(200, 200);
        w.work(|w| w.ev.join(&200, D))
    };
    // the b writes and Hk's grant on D, each write's 3 path edges and the grant's record edge
    let (a, c) = (at(10), at(100));
    assert_eq!((a.bodies, c.bodies), (11, 101));
    assert_eq!((a.atoms, c.atoms), (31, 301));
    assert_eq!(a.visits, c.visits);
}

/// From scratch is linear in the bodies; the memory a sync ID keeps (its edges, atoms and
/// copies) is the edges its paths use, the same at n and 10n.
#[test]
fn from_scratch_is_linear_and_a_sync_id_keeps_its_edges_not_its_bodies() {
    let at = |n: usize| {
        let w = World::new(3, n);
        let (copies, c) = w.ev.from_scratch_counted(&D).unwrap();
        assert_eq!(copies.len(), 3);
        let kept = (w.ev.edges(&D).unwrap().len(), w.ev.atoms(&D).unwrap().len(), w.ev.required(&D).unwrap().len());
        (c, kept)
    };
    let ((a, ka), (b, kb)) = (at(10), at(100));
    assert_eq!((a.bodies, b.bodies), (11, 101));
    assert_eq!(a.visits, b.visits);
    assert_eq!(ka, kb);
}

/// Role changes travel: a write naming a sync ID's actor is a seed by itself, found by the holder
/// index; it reads none of the actor's earlier writes (the same at n and 10n of them).
#[test]
fn a_write_naming_the_actor_reads_none_of_its_earlier_ones() {
    let at = |n: usize| {
        let mut w = World::new(1, 1);
        w.ev.add_sid(Z, Z);
        for j in 0..n {
            w.grant(Z, 500 + j as u16, vec![rec(X, 500 + j as u16)], true);
        }
        let c = w.work(|w| {
            w.grant(Z, 499, vec![rec(X, 499)], true);
        });
        assert_eq!(w.ev.required(&Z).unwrap().len(), n + 1);
        w.ev.check().unwrap();
        c
    };
    let (a, b) = (at(10), at(100));
    assert_eq!(a, b);
    assert_eq!((a.seeds, a.closes, a.bodies), (0, 0, 0), "{a:?}");
}

/// A body forgotten (a compaction covering it, a purge): under an organisation A with m members,
/// each granted write on A and writing D through [A] twice, D's evidence holds m grants. A body
/// whose edge another body still uses costs its path's atoms and no closure; the last body on an
/// edge closes D again from its atoms and seeds: closure-sized work (m visits), never body-sized.
#[test]
fn a_forgotten_body_closes_again_only_when_it_was_the_last_on_an_edge() {
    const A: u16 = 50;
    let at = |m: u16| {
        let mut ev = E::new(Config { vouches: true, reach: false, keys_open: false });
        ev.add_sid(D, D);
        ev.join(&D, D);
        let mut next = 1u32;
        let mut add = |ev: &mut E, on: u16, kind: Kind<u32, u16>, hops: Vec<Hop<u16>>, chained: bool| {
            let c = (next, on);
            ev.add(c, vec![Part { kind, hops: Some(hops), pos: next, chained }]);
            next += 1;
            c
        };
        add(&mut ev, D, write(A), vec![rec(X, D)], true);
        let mut bodies = vec![];
        for j in 0..m {
            let k = 1000 + j;
            add(&mut ev, A, write(k), vec![rec(X, A)], true);
            for _ in 0..2 {
                bodies.push(add(&mut ev, D, Kind::Content, vec![hop(k, A), hop(A, D)], false));
            }
        }
        assert_eq!(ev.required(&D).unwrap().len(), m as usize);
        let before = ev.counts();
        ev.forget(&bodies[0]);
        let shared = minus(ev.counts(), before);
        let before = ev.counts();
        ev.forget(&bodies[1]);
        let last = minus(ev.counts(), before);
        ev.check().unwrap();
        assert_eq!(ev.required(&D).unwrap().len(), m as usize - 1);
        (shared, last)
    };
    let ((s10, l10), (s1000, l1000)) = (at(10), at(1000));
    assert_eq!(s10, s1000);
    assert_eq!((s10.closes, s10.visits, s10.atoms), (0, 0, 2), "{s10:?}");
    assert_eq!((l10.closes, l1000.closes), (1, 1));
    // the close takes every edge and copy in again: m visits, m + 2 edges, however few it lost
    assert_eq!((l10.visits, l1000.visits, l10.edges, l1000.edges), (10, 1000, 12, 1002), "{l10:?} {l1000:?}");
}

/// A compaction dropping the last bodies of many writers at once (`forget_all`): one close of D,
/// not one per body.
#[test]
fn a_compaction_forgetting_many_bodies_closes_once() {
    const A: u16 = 50;
    let mut ev = E::new(Config { vouches: true, reach: false, keys_open: false });
    ev.add_sid(D, D);
    ev.join(&D, D);
    ev.add((1, D), vec![Part { kind: write(A), hops: Some(vec![rec(X, D)]), pos: 1, chained: true }]);
    let mut bodies = vec![];
    for j in 0..20u16 {
        let (g, b) = (2 + 2 * j as u32, 3 + 2 * j as u32);
        ev.add((g, A), vec![Part { kind: write(1000 + j), hops: Some(vec![rec(X, A)]), pos: g, chained: true }]);
        ev.add((b, D), vec![Part { kind: Kind::Content, hops: Some(vec![hop(1000 + j, A), hop(A, D)]), pos: b, chained: false }]);
        bodies.push((b, D));
    }
    let before = ev.counts();
    ev.forget_all(bodies[..10].iter().copied());
    let c = minus(ev.counts(), before);
    ev.check().unwrap();
    assert_eq!(ev.required(&D).unwrap().len(), 10);
    assert_eq!((c.closes, c.bodies), (1, 10), "{c:?}");
}

// ---- reach and keys-open travel (notes/evidence-derivation.md, Reach and keys-open travel) ----

/// A world for reach counts: things minted by X, every write chained, reach and keys-open travel on.
struct Reach {
    ev: E,
    next: u32,
}

impl Reach {
    fn new() -> Reach {
        Reach { ev: E::new(Config { vouches: true, reach: true, keys_open: true }), next: 1 }
    }
    fn sid(&mut self, s: u16) {
        self.ev.add_sid(s, s);
        self.ev.join(&s, s);
    }
    fn edge(&mut self, holder: u16, on: u16, grant: bool, chained: bool) -> (u32, u16) {
        let c = (self.next, on);
        self.next += 1;
        let kind = Kind::Write(Write { holder, grant, removal: !grant, gives_write: grant, gives_read: grant, relies: None, creation: None });
        self.ev.add(c, vec![Part { kind, hops: Some(vec![rec(X, on)]), pos: c.0, chained }]);
        c
    }
    /// A chained write grant of `holder` on `on`.
    fn grant(&mut self, holder: u16, on: u16) -> (u32, u16) {
        self.edge(holder, on, true, true)
    }
    /// A chained removal of `holder` from `on`.
    fn remove(&mut self, holder: u16, on: u16) -> (u32, u16) {
        self.edge(holder, on, false, true)
    }
    fn work(&mut self, f: impl FnOnce(&mut Reach)) -> Counts {
        let before = self.ev.counts();
        f(self);
        let c = minus(self.ev.counts(), before);
        self.ev.check().unwrap();
        c
    }
}

const A: u16 = 50;
const H: u16 = 51;
const H2: u16 = 52;
const Q: u16 = 4;

/// A removal arriving: of s sync IDs, r lie below its target (A writes H, H writes D1..Dr; another
/// hub writes the other s - r). It walks what A leads to once and, per sync ID reached, the way
/// into it: work 7r + 3, the same at s = 10, 100 and 1,000; each reached sync ID takes the removal
/// and A's grant on H.
#[test]
fn a_removal_arriving_reaches_only_the_sync_ids_below_it() {
    let at = |s: u16, r: u16| {
        let mut w = Reach::new();
        w.grant(K, A);
        w.grant(A, H);
        for i in 0..s {
            let d = 1000 + i;
            w.sid(d);
            w.grant(if i < r { H } else { H2 }, d);
        }
        let mut rm = (0, 0);
        let c = w.work(|w| rm = w.remove(K, A));
        for i in 0..s {
            assert_eq!(w.ev.required(&(1000 + i)).unwrap().contains_key(&rm), i < r);
        }
        c
    };
    let (a, b, c) = (at(10, 5), at(100, 5), at(1000, 5));
    assert_eq!((a, a), (b, c));
    assert_eq!((a.reach, a.reach_seeds, a.closes), (7 * 5 + 3, 4 * 5, 0), "{a:?}");
    assert_eq!(at(100, 50).reach, 7 * 50 + 3);
}

/// What does no reach work: a content body, junk (an unchained removal or write grant), a finalize,
/// a vouch: no walk, no seed, however many removals and sync IDs there are.
#[test]
fn content_junk_and_other_role_changes_do_no_reach_work() {
    let mut w = Reach::new();
    w.grant(K, A);
    w.grant(A, H);
    for i in 0..10 {
        w.sid(1000 + i);
        w.grant(H, 1000 + i);
    }
    let rm = w.remove(K, A);
    let d = 1000;
    let content = w.work(|w| {
        let c = (w.next, d);
        w.next += 1;
        w.ev.add(c, vec![Part { kind: Kind::Content, hops: Some(vec![hop(K, A), hop(A, H), hop(H, d)]), pos: c.0, chained: false }]);
    });
    let junk = w.work(|w| {
        w.edge(Z, H, true, false);
        w.edge(Z, H, false, false);
    });
    let finalize = w.work(|w| {
        let c = (w.next, A);
        w.next += 1;
        let kind = Kind::Write(Write { holder: Q, grant: false, removal: false, gives_write: false, gives_read: false, relies: None, creation: None });
        w.ev.add(c, vec![Part { kind, hops: Some(vec![rec(X, A)]), pos: c.0, chained: true }]);
    });
    let vouch = w.work(|w| {
        let c = (w.next, A);
        w.next += 1;
        w.ev.add(c, vec![Part { kind: Kind::Vouch { keyed: rm }, hops: Some(vec![rec(X, A)]), pos: c.0, chained: true }]);
    });
    for c in [content, junk, finalize, vouch] {
        assert_eq!((c.reach, c.reach_seeds), (0, 0), "{c:?}");
    }
}

/// A write grant joining two parts of the grant graph (H writes H2) with a removals above (each
/// Aj writes H, K removed from each) and b sync IDs below (H2 writes D1..Db): each sync ID below
/// takes each removal above, with the ways: b (2a + 1) seeds, once. The same grant again goes
/// where the edge does (b seeds, no walk); a write grant elsewhere with no removal above walks only
/// what leads to it.
#[test]
fn a_write_grant_joining_removals_above_to_sync_ids_below_costs_their_product_once() {
    let at = |a: u16, b: u16| {
        let mut w = Reach::new();
        for j in 0..a {
            let aj = 200 + j;
            w.grant(K, aj);
            w.grant(aj, H);
            w.remove(K, aj);
        }
        for i in 0..b {
            w.sid(1000 + i);
            w.grant(H2, 1000 + i);
        }
        let join = w.work(|w| {
            w.grant(H, H2);
        });
        for i in 0..b {
            let (seeds, _) = w.ev.reach_size(&(1000 + i)).unwrap();
            assert_eq!(seeds, 2 * a as usize + 1);
        }
        let again = w.work(|w| {
            w.grant(H, H2);
        });
        let elsewhere = w.work(|w| {
            w.grant(Z, 999);
        });
        (join, again, elsewhere)
    };
    let ((j1, g1, e1), (j2, g2, e2)) = (at(2, 3), at(4, 6));
    // seeds given: per sync ID below, the a removals, the a + 2 ways ((Aj, H), (H, H2), (H2, Di))
    // and the a + 1 grants on them off the unit: b (3a + 3), a product
    assert_eq!((j1.reach_seeds, j2.reach_seeds), (3 * (3 * 2 + 3), 6 * (3 * 4 + 3)), "{j1:?} {j2:?}");
    // the walks, linear: above (H, Aj, K and their edges, 3a + 2) and below (H2, Di and their
    // edges, 2b + 1) once, each sync ID's way in (3b), the ways from the targets once (2a + 1)
    assert_eq!((j1.reach, j2.reach), (5 * 2 + 5 * 3 + 4, 5 * 4 + 5 * 6 + 4), "{j1:?} {j2:?}");
    assert_eq!((g1.reach, g1.reach_seeds, g2.reach, g2.reach_seeds), (0, 3, 0, 6));
    assert_eq!((e1.reach, e2.reach), (1, 1));
}

/// A forget of a grant reach used (A1's grant on H): each sync ID whose reach held it computes its
/// reach again from nothing (the things leading into its unit), and closes again: b closes, each
/// walk O(a); a sync ID it never reached does nothing.
#[test]
fn a_forgotten_reach_grant_recomputes_the_sync_ids_that_used_it() {
    let at = |a: u16, b: u16| {
        let mut w = Reach::new();
        let mut first = None;
        for j in 0..a {
            let aj = 200 + j;
            w.grant(K, aj);
            let g = w.grant(aj, H);
            first.get_or_insert(g);
            w.remove(K, aj);
        }
        w.grant(H, H2);
        for i in 0..b {
            w.sid(1000 + i);
            w.grant(H2, 1000 + i);
        }
        // a sync ID the grant never reached
        w.sid(999);
        w.grant(Q, 999);
        let g = first.unwrap();
        w.work(|w| w.ev.forget(&g))
    };
    let (c1, c2) = (at(2, 3), at(4, 6));
    assert_eq!((c1.closes, c2.closes), (3, 6));
    // per sync ID: the things leading into its unit and their edges, then the ways from the
    // remaining targets: 5a + 6
    assert_eq!((c1.reach, c2.reach), (3 * (5 * 2 + 6), 6 * (5 * 4 + 6)), "{c1:?} {c2:?}");
}

/// Keys-open travel: a grant giving read joins the things a sync ID's actor opens; it takes the
/// writes naming each newly opened holder, found by the holder index: the walk is what the new edge
/// opens, the same however many other sync IDs and writes there are.
#[test]
fn a_read_grant_opens_only_what_it_leads_to() {
    let at = |n: u16| {
        let mut w = Reach::new();
        w.sid(A);
        for i in 0..n {
            w.sid(2000 + i);
            w.grant(2000 + i, 3000 + i);
        }
        w.grant(H, H2);
        let c = w.work(|w| {
            w.grant(A, H);
        });
        assert_eq!(w.ev.required(&A).unwrap().len(), 2);
        c
    };
    let (a, b) = (at(10), at(100));
    assert_eq!(a.opened, b.opened);
    assert_eq!(a.opened, 3);
}

/// Memory and copies in an organisation: O has m members (write grants by X) and n documents
/// (each its own sync ID, O writes it); M1 writes each document through [O]; X removes r members.
/// With reach each document requires the r removals and the r grants their resets name, besides
/// M1's grant: 2r + 1 copies, flat in n; without reach, M1's grant alone. The reach index holds r
/// seeds and one way per document.
#[test]
fn an_organisations_documents_each_carry_every_removal_above_them() {
    const O: u16 = 60;
    let at = |n: u16, r: u16, reach: bool| {
        let mut ev = E::new(Config { vouches: true, reach, keys_open: true });
        let mut next = 1u32;
        let mut add = |ev: &mut E, on: u16, kind: Kind<u32, u16>, hops: Vec<Hop<u16>>| {
            let c = (next, on);
            let chained = !matches!(kind, Kind::Content);
            ev.add(c, vec![Part { kind, hops: Some(hops), pos: next, chained }]);
            next += 1;
            c
        };
        let mut grants = vec![];
        for j in 0..=r {
            grants.push(add(&mut ev, O, write(2000 + j), vec![rec(X, O)]));
        }
        for i in 0..n {
            let d = 1000 + i;
            ev.add_sid(d, d);
            ev.join(&d, d);
            add(&mut ev, d, write(O), vec![rec(X, d)]);
            add(&mut ev, d, Kind::Content, vec![hop(2000, O), hop(O, d)]);
        }
        for j in 1..=r {
            let creation = Some(grants[j as usize]);
            let kind = Kind::Write(Write { holder: 2000 + j, grant: false, removal: true, gives_write: false, gives_read: false, relies: None, creation });
            add(&mut ev, O, kind, vec![rec(X, O)]);
        }
        ev.check().unwrap();
        let per: Vec<(usize, usize, usize)> = (0..n).map(|i| {
            let d = 1000 + i;
            let (seeds, ways) = ev.reach_size(&d).unwrap();
            (ev.required(&d).unwrap().len(), seeds, ways)
        }).collect();
        assert!(per.iter().all(|p| *p == per[0]), "{per:?}");
        per[0]
    };
    assert_eq!(at(10, 10, true), (21, 10, 1));
    assert_eq!(at(100, 10, true), (21, 10, 1));
    assert_eq!(at(10, 10, false), (1, 0, 0));
    assert_eq!(at(10, 100, true), (201, 100, 1));
}
