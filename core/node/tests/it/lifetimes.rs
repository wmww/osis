#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Thing lifetimes by reference (issues/thing-lifetimes.md): the engine's judgment against
//! held-model `lifetimes` (the walk, the work list, `pending`), and over several nodes.
//! spec: none yet (issues/thing-lifetimes.md step 4 writes it).

use crate::net;
use held_model::lifetimes as hm;
use net::*;
use osis_base::{Ak, CommitId, Tid, Value};
use osis_commit::PurgeItem;
use osis_crdt::{Op, PathOp};
use osis_node::Engine;
use osis_node::Mutation;
use osis_node::retention::lifetimes::Status;
use osis_schema::RawKey;
use osis_schema::core_types as ct;
use std::collections::BTreeSet;

/// The aspect the tests reference things from.
fn refs_ak() -> Ak {
    Ak::new("t:refs.0").unwrap()
}

fn tids(xs: &BTreeSet<usize>, things: &[Tid]) -> Value {
    Value::Set(xs.iter().map(|x| Value::Tid(things[*x])).collect())
}

/// Writes `x`'s list (`None`: removes it) into `m`.
fn list(m: &mut Mutation, x: Tid, l: Option<BTreeSet<Tid>>) {
    match l {
        Some(l) => m.set(x, &ct::RETAINERS, &l).unwrap(),
        None => m.op(x, &ct::RETAINERS, PathOp { path: Vec::new(), op: Op::RemoveAspect }).unwrap(),
    };
}

fn refs(m: &mut Mutation, x: Tid, to: Value) {
    m.set(x, &refs_ak(), &to).unwrap();
}

/// A purge of `t`'s creation by node `by` (an erasure: `end`).
fn end(net: &mut Net, by: usize, t: Tid) -> CommitId {
    let mut m = Mutation::new();
    m.set(t, &ct::PURGE, &osis_base::WallMs(net.now())).unwrap();
    m.purge(PurgeItem::Aspect { tid: t, ak: Ak::new(ct::CREATED.ak()).unwrap() });
    net.engine(by).commit(m).unwrap().unwrap()
}

/// What engine `e` holds of `things`, as the model's view.
fn view(e: &mut Engine, things: &[Tid]) -> hm::View {
    things
        .iter()
        .map(|t| match e.lifetime_status(t) {
            Status::Ended => hm::Held::Ended,
            Status::Unknown => hm::Held::Unknown,
            Status::Known => {
                let list = e.get_typed(t, &ct::RETAINERS).unwrap().map(|l| l.iter().filter_map(|r| things.iter().position(|x| x == r)).collect());
                let rows = e.references_from(t).unwrap();
                let refs = rows.iter().filter(|r| !r.lists() && !r.ephemeral()).filter_map(|r| things.iter().position(|x| *x == r.target)).collect();
                hm::Held::Known { list, refs }
            }
        })
        .collect()
}

fn idx(xs: &[Tid], things: &[Tid]) -> BTreeSet<usize> {
    xs.iter().map(|x| things.iter().position(|t| t == x).unwrap()).collect()
}

struct Rng(u64);
impl Rng {
    fn next(&mut self, n: usize) -> usize {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        (self.0 % n as u64) as usize
    }
    fn set(&mut self, n: usize) -> BTreeSet<usize> {
        let m = self.next(1 << n);
        (0..n).filter(|i| m & (1 << i) != 0).collect()
    }
}

/// `n` standalone things on node `a`, first admin its account.
fn things(net: &mut Net, a: usize, n: usize) -> Vec<Tid> {
    let me = net.tid(a);
    let e = net.engine(a);
    let mut m = Mutation::new();
    let out: Vec<Tid> = (0..n).map(|_| e.new_thing(&mut m, me)).collect();
    e.commit(m).unwrap();
    out
}

// issues/thing-lifetimes.md (The judgment; Steps 3): over random worlds of lists, references and
// ends, every batch of changes judged together: the engine releases exactly what the model's
// from-scratch judgment of the engine's held view says is unreachable (this node holds every
// right), in batches of one to three changes in one commit or several.
#[test]
fn the_judgment_releases_what_the_model_judges_unreachable() {
    const N: usize = 5;
    let (mut net, [a]) = local_nodes::<1>();
    let mut released = 0;
    for seed in 1..=40u64 {
        let mut r = Rng(seed.wrapping_mul(0x9E3779B97F4A7C15) | 1);
        let t = things(&mut net, a, N);
        let mut log = Vec::new();
        for _ in 0..8 {
            for _ in 0..1 + r.next(3) {
                let x = t[r.next(N)];
                let mut m = Mutation::new();
                match r.next(5) {
                    0 | 1 => {
                        let l = (r.next(3) != 0).then(|| r.set(N).into_iter().map(|i| t[i]).collect());
                        log.push(format!("list {x:?} {l:?}"));
                        list(&mut m, x, l);
                    }
                    2 | 3 => {
                        let s = r.set(N);
                        log.push(format!("refs {x:?} {s:?}"));
                        refs(&mut m, x, tids(&s, &t));
                    }
                    _ => {
                        if net.engine(a).lifetime_status(&x) == Status::Known {
                            log.push(format!("end {x:?}"));
                            end(&mut net, a, x);
                        }
                        continue;
                    }
                }
                if net.engine(a).lifetime_status(&x) == Status::Known {
                    net.engine(a).commit(m).unwrap();
                }
            }
            let v = view(net.engine(a), &t);
            let want = hm::unreachable(&v);
            let got = net.engine(a).judge_lifetimes(&|_| true).unwrap();
            assert_eq!(idx(&got.release, &t), want, "seed {seed}: {v:?} {log:?}");
            assert!(net.engine(a).lifetimes_pending().unwrap().is_empty());
            released += got.release.len();
            // released, as a purge here until release requests are written
            for x in got.release {
                end(&mut net, a, x);
            }
            assert!(net.engine(a).judge_lifetimes(&|_| true).unwrap().release.is_empty(), "seed {seed}: judged twice");
        }
    }
    assert!(released > 40, "{released}");
}

// issues/thing-lifetimes.md (Cost): a root referencing n children, each listing it and
// referencing a child of its own: unreferencing one child judges it and its child, at n and 10n.
#[test]
fn a_change_judges_what_it_touches_at_n_and_10n() {
    let count = |n: usize| {
        let (mut net, [a]) = local_nodes::<1>();
        let t = things(&mut net, a, 1 + 2 * n);
        let (root, kids, grand) = (t[0], &t[1..=n], &t[n + 1..]);
        let mut m = Mutation::new();
        refs(&mut m, root, Value::Set(kids.iter().map(|k| Value::Tid(*k)).collect()));
        for (k, g) in kids.iter().zip(grand) {
            list(&mut m, *k, Some([root].into()));
            refs(&mut m, *k, Value::Set([Value::Tid(*g)].into()));
            list(&mut m, *g, Some([*k].into()));
        }
        net.engine(a).commit(m).unwrap();
        assert!(net.engine(a).judge_lifetimes(&|_| true).unwrap().release.is_empty());
        let mut m = Mutation::new();
        refs(&mut m, root, Value::Set(kids[1..].iter().map(|k| Value::Tid(*k)).collect()));
        net.engine(a).commit(m).unwrap();
        let got = net.engine(a).judge_lifetimes(&|_| true).unwrap();
        assert_eq!(got.release, vec![kids[0], grand[0]]);
        got.judged
    };
    assert_eq!(count(10), 2);
    assert_eq!(count(100), 2);
}

// issues/thing-lifetimes.md (The judgment: an unknown retainer keeps): a node holding a thing but
// not its retainer releases nothing and keeps nothing pending, though it may end the thing; the
// node holding both keeps it while the retainer references it.
#[test]
fn a_node_missing_a_retainer_releases_nothing() {
    let (mut net, _host, [a, b], g, []) = crate::net::hosted::<2, 0>(&[(1, osis_base::Role::Admin)], [], true);
    let me = net.tid(a);
    let e = net.engine(a);
    let mut m = Mutation::new();
    let r = e.new_thing(&mut m, me);
    let x = e.new_thing(&mut m, g);
    list(&mut m, x, Some([r].into()));
    refs(&mut m, r, Value::Set([Value::Tid(x)].into()));
    let mut items = e.get_typed(&g, &ct::GROUP).unwrap().unwrap_or_default();
    items.items.insert(x);
    m.set(g, &ct::GROUP, &items).unwrap();
    e.commit(m).unwrap();
    net.run();
    assert_eq!(net.engine(b).lifetime_status(&x), Status::Known);
    assert_eq!(net.engine(b).lifetime_status(&r), Status::Unknown);
    for n in [a, b] {
        assert!(net.engine(n).judge_lifetimes(&|_| true).unwrap().release.is_empty(), "node {n}");
        assert!(net.engine(n).lifetimes_pending().unwrap().is_empty(), "node {n}");
    }
    // the retainer stops referencing it: the node holding both judges it unreachable, the other
    // still cannot judge
    let mut m = Mutation::new();
    refs(&mut m, r, Value::Set(Default::default()));
    net.engine(a).commit(m).unwrap();
    net.run();
    assert_eq!(net.engine(a).judge_lifetimes(&|_| true).unwrap().release, vec![x]);
    assert!(net.engine(b).judge_lifetimes(&|_| true).unwrap().release.is_empty());
}
