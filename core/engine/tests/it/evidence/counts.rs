//! Count tests (spec/permissions.md §4; notes/evidence-derivation.md, Incremental): the work each change does, at n and
//! 10n, on the derivation alone. K writes D along a path of k holder things H1..Hk outside D's
//! unit (X mints them and D; X grants K on H1, each Hj on the next, Hk on D).
use osis_engine::evidence::{Config, Counts, Edge, Evidence, Kind, Part, Write};

type E = Evidence<u32, u16, u32>;
const X: u16 = 1;
const K: u16 = 2;
const Z: u16 = 3;
const D: u16 = 100;
const D2: u16 = 101;

/// A record edge (the mint admin's) as a hop.
fn rec(a: u16, b: u16) -> Edge<u16> {
    (a, b)
}
fn hop(a: u16, b: u16) -> Edge<u16> {
    (a, b)
}
fn write(holder: u16) -> Kind<u16> {
    Kind::Write(Write { holder, gives_read: true })
}

fn minus(a: Counts, b: Counts) -> Counts {
    a - b
}

struct World {
    ev: E,
    next: u32,
    hs: Vec<u16>,
}

impl World {
    /// The path of `k` holder things and `n` writes of K on `on` along it.
    fn new(k: usize, n: usize) -> World {
        let mut ev = E::new(Config { keys_open: false });
        for s in [D, D2] {
            ev.add_sid(s, s);
            ev.join(&s, s);
        }
        let hs: Vec<u16> = (0..k as u16).map(|j| 10 + j).collect();
        let mut w = World { ev, next: 1, hs };
        if let Some(&h0) = w.hs.first() {
            w.grant(K, h0, vec![rec(X, h0)]);
        }
        for j in 0..k {
            let h = w.hs[j];
            let next = w.hs.get(j + 1).copied().unwrap_or(D);
            w.grant(h, next, vec![rec(X, next)]);
            if next == D {
                w.grant(h, D2, vec![rec(X, D2)]);
            }
        }
        for _ in 0..n {
            w.content(D);
        }
        w
    }
    fn grant(&mut self, holder: u16, on: u16, hops: Vec<Edge<u16>>) -> (u32, u16) {
        let c = (self.next, on);
        self.next += 1;
        self.ev.add(c, vec![Part::new(write(holder), Some(hops))]);
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
        self.ev.add(c, vec![Part::new(Kind::Content, Some(hops))]);
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
            w.grant(K, h0, vec![rec(X, h0)]);
        });
        assert_eq!(w.ev.required(&D).unwrap().len(), before + 1);
        c
    };
    let (a, b) = (at(10), at(100));
    assert_eq!(a, b);
    assert_eq!((a.bodies, a.closes, a.atoms), (0, 0, 0), "{a:?}");
    assert!(a.visits <= 2, "{a:?}");
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
            w.grant(Z, 500 + j as u16, vec![rec(X, 500 + j as u16)]);
        }
        let c = w.work(|w| {
            w.grant(Z, 499, vec![rec(X, 499)]);
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
        let mut ev = E::new(Config { keys_open: false });
        ev.add_sid(D, D);
        ev.join(&D, D);
        let mut next = 1u32;
        let mut add = |ev: &mut E, on: u16, kind: Kind<u16>, hops: Vec<Edge<u16>>| {
            let c = (next, on);
            ev.add(c, vec![Part::new(kind, Some(hops))]);
            next += 1;
            c
        };
        add(&mut ev, D, write(A), vec![rec(X, D)]);
        let mut bodies = vec![];
        for j in 0..m {
            let k = 1000 + j;
            add(&mut ev, A, write(k), vec![rec(X, A)]);
            for _ in 0..2 {
                bodies.push(add(&mut ev, D, Kind::Content, vec![hop(k, A), hop(A, D)]));
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
    let mut ev = E::new(Config { keys_open: false });
    ev.add_sid(D, D);
    ev.join(&D, D);
    ev.add((1, D), vec![Part::new(write(A), Some(vec![rec(X, D)]))]);
    let mut bodies = vec![];
    for j in 0..20u16 {
        let (g, b) = (2 + 2 * j as u32, 3 + 2 * j as u32);
        ev.add((g, A), vec![Part::new(write(1000 + j), Some(vec![rec(X, A)]))]);
        ev.add((b, D), vec![Part::new(Kind::Content, Some(vec![hop(1000 + j, A), hop(A, D)]))]);
        bodies.push((b, D));
    }
    let before = ev.counts();
    ev.forget_all(bodies[..10].iter().copied());
    let c = minus(ev.counts(), before);
    ev.check().unwrap();
    assert_eq!(ev.required(&D).unwrap().len(), 10);
    assert_eq!((c.closes, c.bodies), (1, 10), "{c:?}");
}

// ---- keys-open travel (notes/evidence-derivation.md, Keys-open travel) ----

/// A world for keys-open counts: things minted by X, keys-open travel on.
struct Travel {
    ev: E,
    next: u32,
}

impl Travel {
    fn new() -> Travel {
        Travel { ev: E::new(Config { keys_open: true }), next: 1 }
    }
    fn sid(&mut self, s: u16) {
        self.ev.add_sid(s, s);
        self.ev.join(&s, s);
    }
    /// A write grant of `holder` on `on`.
    fn grant(&mut self, holder: u16, on: u16) -> (u32, u16) {
        let c = (self.next, on);
        self.next += 1;
        self.ev.add(c, vec![Part::new(write(holder), Some(vec![rec(X, on)]))]);
        c
    }
    fn work(&mut self, f: impl FnOnce(&mut Travel)) -> Counts {
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

/// Keys-open travel: a grant giving read joins the things a sync ID's actor opens; it takes the
/// writes naming each newly opened holder, found by the holder index: the walk is what the new edge
/// opens, the same however many other sync IDs and writes there are.
#[test]
fn a_read_grant_opens_only_what_it_leads_to() {
    let at = |n: u16| {
        let mut w = Travel::new();
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

/// A sync ID taken back leaves nothing of it (the derivation's own check: every reverse index
/// holds what the remaining sync IDs do), the other sync IDs as they were; registered again, it
/// is as from nothing.
#[test]
fn a_sync_id_taken_back_leaves_nothing_and_comes_again_as_new() {
    let mut w = World::new(3, 10);
    let (d, d2) = (w.ev.required(&D).unwrap().clone(), w.ev.required(&D2).unwrap().clone());
    assert!(!d.is_empty(), "D requires its path's grants");
    w.ev.remove_sid(&D);
    w.ev.check().unwrap();
    assert!(w.ev.required(&D).is_none() && w.ev.required(&D2) == Some(&d2), "D is gone, D2 as it was");
    w.ev.add_sid(D, D);
    w.ev.join(&D, D);
    w.ev.check().unwrap();
    assert_eq!(w.ev.required(&D), Some(&d), "D again");
}

/// A record edge taken back (its thing's record forgotten) closes the keys it opened: the
/// writes naming what only it led to travel under the sync ID no more, and an edge a held grant
/// also sets stands. Taken back at 10 and 100 other sync IDs it walks the same.
#[test]
fn a_record_taken_back_closes_what_only_it_opened() {
    let at = |n: u16| {
        let mut w = Travel::new();
        w.sid(A);
        for i in 0..n {
            w.sid(2000 + i);
            w.grant(2000 + i, 3000 + i);
        }
        // A mints H; X grants H on H2: the write naming H travels under A by the record alone
        w.ev.add_record((A, H));
        let g = w.grant(H, H2);
        assert!(w.ev.required(&A).unwrap().contains_key(&g), "the grant to H travels under A");
        let c = w.work(|w| w.ev.remove_record(&(A, H)));
        w.ev.check().unwrap();
        assert!(w.ev.required(&A).unwrap().is_empty(), "nothing travels under A");
        // beside a grant setting the same edge, the record's going moves nothing
        w.ev.add_record((A, H));
        w.grant(A, H);
        let n = w.ev.required(&A).unwrap().len();
        w.ev.remove_record(&(A, H));
        w.ev.check().unwrap();
        assert_eq!(w.ev.required(&A).unwrap().len(), n, "the grant keeps the edge");
        c
    };
    let (a, b) = (at(10), at(100));
    assert_eq!((a.opened, a.closes), (b.opened, b.closes));
    assert_eq!(a.closes, 1);
}
