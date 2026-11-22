//! Count tests (spec/permissions.md §4; notes/evidence-derivation.md, Incremental): the work each change does, at n and
//! 10n, on the derivation alone. K writes D along a path of k holder things H1..Hk outside D's
//! unit (X mints them and D; X grants K on H1, each Hj on the next, Hk on D).
use osis_engine::evidence::{Config, Counts, Evidence, Gives, Hop, Kind, Need, Part, Write};

type E = Evidence<u32, u16, u32>;
const X: u16 = 1;
const K: u16 = 2;
const Z: u16 = 3;
const D: u16 = 100;
const D2: u16 = 101;

fn rec(a: u16, b: u16) -> Hop<u16> {
    Hop { edge: (a, b), record: true, need: Need::Role(osis_base::Role::Write) }
}
fn hop(a: u16, b: u16) -> Hop<u16> {
    Hop { edge: (a, b), record: false, need: Need::Role(osis_base::Role::Write) }
}
fn write(holder: u16) -> Kind<u32, u16> {
    Kind::Write(Write { holder, grant: Some(Gives::role(osis_base::Role::Write)), removal: false, gives_write: true, gives_read: true, creation: None, leaves: vec![] })
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
        let mut ev = E::new(Config { keys_open: false, leaves: false });
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
        let mut ev = E::new(Config { keys_open: false, leaves: false });
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
    let mut ev = E::new(Config { keys_open: false, leaves: false });
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

// ---- keys-open travel (notes/evidence-derivation.md, Keys-open travel) ----

/// A world for keys-open counts: things minted by X, every write chained, keys-open travel on.
struct Travel {
    ev: E,
    next: u32,
}

impl Travel {
    fn new() -> Travel {
        Travel { ev: E::new(Config { keys_open: true, leaves: false }), next: 1 }
    }
    fn sid(&mut self, s: u16) {
        self.ev.add_sid(s, s);
        self.ev.join(&s, s);
    }
    /// A chained write grant of `holder` on `on`.
    fn grant(&mut self, holder: u16, on: u16) -> (u32, u16) {
        let c = (self.next, on);
        self.next += 1;
        self.ev.add(c, vec![Part { kind: write(holder), hops: Some(vec![rec(X, on)]), pos: c.0, chained: true }]);
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
const Q: u16 = 4;

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

// ---- A3: leaves (notes/evidence-derivation.md, Leaves) ----

/// A3's derivation alone: K's write grant on A (X's, by A's record) is every removal's witness; X
/// removes K from A any number of times, each listing what it names in its leaves.
struct Lists {
    ev: E,
    next: u32,
}

const A3: Config = Config { keys_open: true, leaves: true };

impl Lists {
    fn new() -> Lists {
        let mut ev = E::new(A3);
        ev.add_record((X, A));
        let mut l = Lists { ev, next: 1 };
        l.add(A, write(K), vec![rec(X, A)]);
        l
    }
    fn add(&mut self, on: u16, kind: Kind<u32, u16>, hops: Vec<Hop<u16>>) -> (u32, u16) {
        let c = (self.next, on);
        self.next += 1;
        let chained = !matches!(kind, Kind::Content);
        self.ev.add(c, vec![Part { kind, hops: Some(hops), pos: c.0, chained }]);
        c
    }
    /// A removal of `holder` from `on` with leaves for `leaves`.
    fn removal(&mut self, holder: u16, on: u16, leaves: Vec<u16>) -> (u32, u16) {
        self.add(on, Kind::Write(Write { holder, grant: None, removal: true, gives_write: false, gives_read: false, creation: None, leaves }), vec![rec(X, on)])
    }
    /// A sync ID of `d`, A granted write on it (by its record), the grant a body there.
    fn doc(&mut self, d: u16) {
        self.ev.add_sid(d, d);
        self.ev.join(&d, d);
        self.ev.add_record((X, d));
        self.add(d, write(A), vec![rec(X, d)]);
    }
    /// `who`'s write on `d` through [A].
    fn body(&mut self, who: u16, d: u16) -> (u32, u16) {
        self.add(d, Kind::Content, vec![hop(who, A), hop(A, d)])
    }
    fn work<R>(&mut self, f: impl FnOnce(&mut Lists) -> R) -> (Counts, R) {
        let before = self.ev.counts();
        let r = f(self);
        (minus(self.ev.counts(), before), r)
    }
}

/// A body arriving on D where r removals of K from A have a leaf for D: the first such body sends
/// each of them to decide its leaf again (2 checks each: found, decided), a later one none; which
/// leaves judge a body looks up those r alone. The u removals of K with a leaf for another thing
/// enter D's set with the first body (evidence of it, on its edge): one check each for its one
/// leaf, none for a later body. The u removals on another edge cost nothing: at u = 10, 100, 1,000.
#[test]
fn a_body_arriving_looks_up_only_the_leaves_of_its_edges() {
    let at = |u: u16| {
        let mut l = Lists::new();
        l.add(A, write(Q), vec![rec(X, A)]);
        l.doc(D);
        for _ in 0..3 {
            l.removal(K, A, vec![D]);
        }
        for j in 0..u {
            l.removal(K, A, vec![2000 + j]);
            l.removal(Q, A, vec![D]);
        }
        let (first, _) = l.work(|l| l.body(K, D));
        let (later, b) = l.work(|l| l.body(K, D));
        let (look, judging) = l.work(|l| l.ev.reading(&b));
        l.ev.check().unwrap();
        assert_eq!(judging.len(), 3);
        assert_eq!(l.ev.leaves(&D).unwrap().len(), 3);
        (first.leaf_checks, later.leaf_checks, look.leaf_checks)
    };
    for u in [10, 100, 1000] {
        assert_eq!(at(u), (6 + usize::from(u), 0, 3), "u {u}");
    }
}

/// A leaf arriving judges the held parts it reads: n bodies on D resting on (K, A), none of the m
/// resting on (Q, A), at n, m = 10, 100.
#[test]
fn a_leaf_judges_only_the_parts_resting_on_its_edge() {
    let at = |n: u16, m: u16| {
        let mut l = Lists::new();
        l.add(A, write(Q), vec![rec(X, A)]);
        l.doc(D);
        for _ in 0..n {
            l.body(K, D);
        }
        for _ in 0..m {
            l.body(Q, D);
        }
        let r = l.removal(K, A, vec![D]);
        let (c, judged) = l.work(|l| l.ev.judged_by(&r, D));
        assert_eq!(judged.len(), usize::from(n));
        c.judged
    };
    assert_eq!(at(10, 10), 10);
    assert_eq!(at(10, 100), 10);
    assert_eq!(at(100, 10), 100);
}

/// Memory per sync ID: a removal on A with a leaf for each of k documents, each with a body resting
/// on (K, A): A keeps the k far leaves (its own sync ID, where the removal is a body), each
/// document its own leaf alone, at k = 10, 100.
#[test]
fn a_document_keeps_its_own_leaf_and_the_removals_home_every_far_leaf() {
    let at = |k: u16| {
        let mut l = Lists::new();
        l.ev.add_sid(A, A);
        l.ev.join(&A, A);
        let docs: Vec<u16> = (0..k).map(|j| 1000 + j).collect();
        for &d in &docs {
            l.doc(d);
            l.body(K, d);
        }
        l.removal(K, A, docs.clone());
        l.ev.check().unwrap();
        let per: Vec<usize> = docs.iter().map(|d| l.ev.leaves(d).unwrap().len()).collect();
        assert!(per.iter().all(|n| *n == 1), "{per:?}");
        l.ev.leaves(&A).unwrap().len()
    };
    assert_eq!((at(10), at(100)), (10, 100));
}

/// A closure rebuilt (the last body on an edge of A forgotten) decides its members' leaves again,
/// never its bodies': r removals that are bodies of A, each with far leaves for k documents, cost
/// nothing there, at (r, k) = (10, 10), (10, 100), (100, 10).
#[test]
fn a_rebuilt_closure_decides_only_its_members_leaves() {
    let at = |r: u16, k: u16| {
        let mut l = Lists::new();
        l.ev.add_sid(A, A);
        l.ev.join(&A, A);
        let docs: Vec<u16> = (0..k).map(|j| 1000 + j).collect();
        for _ in 0..r {
            l.removal(K, A, docs.clone());
        }
        l.add(A, write(Q), vec![rec(X, A)]);
        let b = l.add(A, Kind::Content, vec![hop(Q, A)]);
        let (c, _) = l.work(|l| l.ev.forget(&b));
        l.ev.check().unwrap();
        assert_eq!(l.ev.leaves(&A).unwrap().len(), usize::from(r) * usize::from(k));
        (c.closes, c.leaf_checks)
    };
    assert_eq!(at(10, 10), (1, 0));
    assert_eq!(at(10, 100), (1, 0));
    assert_eq!(at(100, 10), (1, 0));
}
