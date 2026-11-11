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
            assert_eq!(got.request.is_some(), !got.release.is_empty(), "seed {seed}: one request for what it releases");
            for x in &got.release {
                assert_eq!(net.engine(a).lifetime_status(x), Status::Ended, "seed {seed}: released");
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

// issues/thing-lifetimes.md (The judgment; Cascade): a thing created with its list in one commit
// is judged; a walk not heard out waits and leaves nothing pending; judged, an unreachable thing
// takes what only it kept, and the work list is empty after.
#[test]
fn a_new_listed_thing_is_judged_once_heard_out() {
    let (mut net, [a]) = local_nodes::<1>();
    let me = net.tid(a);
    let e = net.engine(a);
    let mut m = Mutation::new();
    let r = e.new_thing(&mut m, me);
    let x = e.new_thing(&mut m, me);
    let y = e.new_thing(&mut m, me);
    list(&mut m, x, Some([r].into()));
    refs(&mut m, x, Value::Set([Value::Tid(y)].into()));
    list(&mut m, y, Some([x].into()));
    e.commit(m).unwrap();
    let got = e.judge_lifetimes(&|t| *t != r).unwrap();
    assert!(got.release.is_empty());
    assert!(got.waiting > 0);
    assert!(e.lifetimes_pending().unwrap().is_empty());
    assert!(e.lifetimes_due().unwrap());
    assert_eq!(e.judge_lifetimes(&|_| true).unwrap().release.into_iter().collect::<BTreeSet<_>>(), [x, y].into());
    assert!(!e.lifetimes_due().unwrap());
}

// issues/thing-lifetimes.md (The release; Cascade), spec/commits.md §5 (Ending): r, an actor first
// admin of x and y, lives by root's reference; x lives by r's. Unreferenced, r is released with x
// in one request (x's right comes through r, judged with it), at both nodes; y, which r is first
// admin of but does not keep, lives on as r's dependent and is written through r's frozen edges
#[test]
fn a_cascade_releases_an_actor_and_what_it_kept_in_one_commit() {
    let (mut net, _host, [a, b], g, []) = crate::net::hosted::<2, 0>(&[(1, osis_base::Role::Admin)], [], true);
    let e = net.engine(a);
    let mut m = Mutation::new();
    let root = e.new_thing(&mut m, g);
    let r = e.new_thing(&mut m, g);
    let x = e.new_thing(&mut m, r);
    let y = e.new_thing(&mut m, r);
    refs(&mut m, root, Value::Set([Value::Tid(r)].into()));
    list(&mut m, r, Some([root].into()));
    refs(&mut m, r, Value::Set([Value::Tid(x)].into()));
    list(&mut m, x, Some([r].into()));
    refs(&mut m, y, Value::Set(Default::default()));
    let mut items = e.get_typed(&g, &ct::GROUP).unwrap().unwrap_or_default();
    items.items.extend([root, r, x, y]);
    m.set(g, &ct::GROUP, &items).unwrap();
    e.commit(m).unwrap();
    net.run();
    assert!(net.engine(a).judge_lifetimes(&|_| true).unwrap().release.is_empty());
    let mut m = Mutation::new();
    refs(&mut m, root, Value::Set(Default::default()));
    net.engine(a).commit(m).unwrap();
    let got = net.engine(a).judge_lifetimes(&|_| true).unwrap();
    assert_eq!(got.release.iter().copied().collect::<BTreeSet<_>>(), [r, x].into());
    let h = net.engine(a).header(&got.request.unwrap()).unwrap();
    assert_eq!(h.aspects.iter().map(|p| (p.tid, p.ak.as_str())).collect::<BTreeSet<_>>(), [(r, ct::RELEASED.ak()), (x, ct::RELEASED.ak())].into(), "one released.0 part per thing");
    net.run();
    for n in [a, b] {
        let e = net.engine(n);
        for t in [r, x] {
            assert_eq!(e.lifetime_status(&t), Status::Ended, "node {n}: {t:?} released");
            assert!(!e.knows(&t), "node {n}: {t:?} reads absent");
        }
        assert!(e.knows(&y), "node {n}: y lives on");
        assert!(e.core.created(&r).is_some(), "node {n}: r's record kept for y");
    }
    let mut m = Mutation::new();
    refs(&mut m, y, Value::Set([Value::Tid(root)].into()));
    net.engine(b).commit(m).unwrap().unwrap();
    net.run();
    assert_eq!(net.engine(a).get(&y, &refs_ak()).unwrap(), Some(Value::Set([Value::Tid(root)].into())), "y written through r's frozen edges");
}

// issues/thing-lifetimes.md (The release): the judgment and the release request are two
// transactions; a released thing stays pending until the request, applied, ends it, so a request
// that fails to be written (here the store refuses it once) is judged again at the next open
// and released then. Without the pending row nothing would queue it again.
#[test]
fn a_release_that_fails_to_be_written_is_judged_again_at_the_next_open() {
    let f = osis_store::Faults::new();
    let mut net = Net::new();
    let a = net.forensic_node(1, &[], &f);
    let me = net.tid(a);
    let e = net.engine(a);
    let mut m = Mutation::new();
    let r = e.new_thing(&mut m, me);
    let x = e.new_thing(&mut m, me);
    list(&mut m, x, Some([r].into()));
    refs(&mut m, r, Value::Set([Value::Tid(x)].into()));
    e.commit(m).unwrap();
    assert!(e.judge_lifetimes(&|_| true).unwrap().release.is_empty());
    let mut m = Mutation::new();
    refs(&mut m, r, Value::Set(Default::default()));
    e.commit(m).unwrap();
    // the judgment's transaction is write 0, the request's first write fails
    f.at(1, osis_store::Fault::Fail);
    assert!(e.judge_lifetimes(&|_| true).is_err(), "the request is not written");
    // a failed write breaks the store until the node opens again
    net.restart(a, 2);
    let e = net.engine(a);
    assert_eq!(e.lifetime_status(&x), Status::Known);
    assert_eq!(e.lifetimes_pending().unwrap(), vec![x], "judged, pending until ended");
    assert!(e.lifetimes_due().unwrap(), "the open judges what is pending");
    let got = e.judge_lifetimes(&|_| true).unwrap();
    assert_eq!(got.release, vec![x]);
    assert!(got.request.is_some());
    assert_eq!(e.lifetime_status(&x), Status::Ended);
    assert!(e.lifetimes_pending().unwrap().is_empty());
    assert!(!e.lifetimes_due().unwrap());
}

// issues/thing-lifetimes.md (The release: Forgotten, Comes back after), spec/commits.md §5
// (Forgetting, Never received): x, kept by r's reference, is released once r lets go; at its
// request's expiry, with nothing listing or referencing it, the node forgets it whole: x reads
// unknown and no header of a commit on it stays, the request's included. A stale copy then comes
// back as a live thing, is judged again and released by a new request
#[test]
fn a_released_thing_is_forgotten_at_its_requests_expiry_and_a_stale_copy_is_judged_again() {
    let (mut net, [a]) = local_nodes::<1>();
    let me = net.tid(a);
    let e = net.engine(a);
    let mut m = Mutation::new();
    let r = e.new_thing(&mut m, me);
    e.commit(m).unwrap();
    let mut m = Mutation::new();
    let x = e.new_thing(&mut m, me);
    list(&mut m, x, Some([r].into()));
    let made = e.commit(m).unwrap().unwrap();
    let mut m = Mutation::new();
    refs(&mut m, r, Value::Set([Value::Tid(x)].into()));
    e.commit(m).unwrap();
    let mut m = Mutation::new();
    m.set(x, &Ak::new("t:v.0").unwrap(), &Value::Int(1)).unwrap();
    let wrote = e.commit(m).unwrap().unwrap();
    assert!(e.judge_lifetimes(&|_| true).unwrap().release.is_empty());
    let stale = e.package(&made).unwrap().unwrap();
    let mut m = Mutation::new();
    refs(&mut m, r, Value::Set(Default::default()));
    e.commit(m).unwrap();
    let first = e.judge_lifetimes(&|_| true).unwrap();
    assert_eq!(first.release, vec![x]);
    let req = first.request.unwrap();
    assert_eq!(e.lifetime_status(&x), Status::Ended);
    net.advance(osis_base::format::ROLE_KEEP_MS / 2);
    assert_eq!(net.engine(a).lifetime_status(&x), Status::Ended, "held until the request expires");
    net.advance(osis_base::format::ROLE_KEEP_MS / 2 + 1_000);
    let e = net.engine(a);
    assert_eq!(e.lifetime_status(&x), Status::Unknown, "forgotten at its request's expiry");
    for c in [req, made, wrote] {
        assert!(e.header(&c).is_none(), "{c:?} forgotten");
    }
    assert!(e.core.on_thing(&x).next().is_none(), "no commit on x stays");
    assert!(e.core.created(&x).is_none(), "nor its record");
    net.restart(a, 2);
    let e = net.engine(a);
    assert_eq!(e.lifetime_status(&x), Status::Unknown, "forgotten over a restart");
    let _ = e.ingest(&stale.bytes, stale.blobs);
    assert_eq!(e.lifetime_status(&x), Status::Known, "a stale copy comes back");
    let again = e.judge_lifetimes(&|_| true).unwrap();
    assert_eq!(again.release, vec![x], "judged again: unreachable");
    assert_ne!(again.request, Some(req), "by a new request");
    assert_eq!(e.lifetime_status(&x), Status::Ended);
}

// issues/thing-lifetimes.md (The release: Forgotten), spec/commits.md §5 (Never received): x made
// in one commit with r's reference to it; once its release is forgotten that commit keeps its
// header for r's part, and its parts on x count as never received: x is unknown, and a copy of the
// commit arriving again brings x back to be judged
#[test]
fn a_commit_on_a_forgotten_thing_and_a_live_one_keeps_its_header() {
    let (mut net, [a]) = local_nodes::<1>();
    let me = net.tid(a);
    let e = net.engine(a);
    let mut m = Mutation::new();
    let r = e.new_thing(&mut m, me);
    e.commit(m).unwrap();
    let mut m = Mutation::new();
    let x = e.new_thing(&mut m, me);
    list(&mut m, x, Some([r].into()));
    refs(&mut m, r, Value::Set([Value::Tid(x)].into()));
    let made = e.commit(m).unwrap().unwrap();
    let stale = e.package(&made).unwrap().unwrap();
    let mut m = Mutation::new();
    refs(&mut m, r, Value::Set(Default::default()));
    e.commit(m).unwrap();
    assert_eq!(e.judge_lifetimes(&|_| true).unwrap().release, vec![x]);
    net.advance(osis_base::format::ROLE_KEEP_MS + 1_000);
    let e = net.engine(a);
    assert_eq!(e.lifetime_status(&x), Status::Unknown);
    assert!(e.header(&made).is_some(), "kept for r's part");
    let _ = e.ingest(&stale.bytes, stale.blobs);
    assert_eq!(e.lifetime_status(&x), Status::Known, "x's parts join again");
    assert_eq!(e.judge_lifetimes(&|_| true).unwrap().release, vec![x]);
}

// spec/commits.md §5 (Forgetting: role commits included): a released thing with an edge write of
// its own (a role commit on it alone) is forgotten whole at its request's expiry, the grant's header
// too, and stays so over a restart
#[test]
fn a_forgotten_released_thing_takes_its_role_commits() {
    let (mut net, [a, b]) = local_nodes::<2>();
    let me = net.tid(a);
    let tb = net.tid(b);
    let e = net.engine(a);
    let mut m = Mutation::new();
    let r = e.new_thing(&mut m, me);
    e.commit(m).unwrap();
    let mut m = Mutation::new();
    let x = e.new_thing(&mut m, me);
    list(&mut m, x, Some([r].into()));
    e.commit(m).unwrap();
    let mut m = Mutation::new();
    refs(&mut m, r, Value::Set([Value::Tid(x)].into()));
    e.commit(m).unwrap();
    let e = net.engine(a);
    let mut m = Mutation::new();
    let edge = ct::Edge { role: osis_base::Role::Write, until: None, invite: None, tied: None };
    m.op(x, &ct::ROLES, PathOp { path: vec![osis_crdt::PathSeg::Key(Value::Tid(tb))], op: Op::Set(osis_schema::Codec::to_value(&edge)) }).unwrap();
    let grant = e.commit(m).unwrap().unwrap();
    assert!(!e.roster(&x).is_empty());
    let mut m = Mutation::new();
    refs(&mut m, r, Value::Set(Default::default()));
    e.commit(m).unwrap();
    assert_eq!(e.judge_lifetimes(&|_| true).unwrap().release, vec![x]);
    assert!(e.header(&grant).is_some());
    net.advance(osis_base::format::ROLE_KEEP_MS + 1_000);
    let e = net.engine(a);
    assert_eq!(e.lifetime_status(&x), Status::Unknown);
    assert!(e.header(&grant).is_none(), "the edge write forgotten with x");
    assert!(e.roster(&x).is_empty());
    net.restart(a, 3);
    assert_eq!(net.engine(a).lifetime_status(&x), Status::Unknown);
}

// issues/thing-lifetimes.md (What is kept; Cost): what a label's certificates read of ended things
// is bounded by what live things need, not by what ended: with n and 10n purged things nothing
// references, finding the one released thing r references reads as many candidates (after the
// first look leaves out the unneeded)
#[test]
fn finding_needed_endings_reads_what_live_things_need_at_n_and_10n() {
    let count = |n: usize| {
        let (mut net, [a]) = local_nodes::<1>();
        let t = things(&mut net, a, n + 2);
        let (r, x, gone) = (t[0], t[1], &t[2..]);
        let mut m = Mutation::new();
        refs(&mut m, r, Value::Set([Value::Tid(x)].into()));
        net.engine(a).commit(m).unwrap();
        for g in gone {
            end(&mut net, a, *g);
        }
        net.engine(a).release(&[x]).unwrap().unwrap();
        let e = net.engine(a);
        assert_eq!(e.ended_needed(&r).unwrap(), [x].into());
        osis_node::costs::take();
        assert_eq!(e.ended_needed(&r).unwrap(), [x].into());
        osis_node::costs::take().into_iter().find(|(k, _, _)| *k == "ended needed: candidates").map_or(0, |x| x.2)
    };
    let (small, big) = (count(10), count(100));
    assert!(small >= 1 && big == small, "{small} at n, {big} at 10n");
}

// spec/commits.md §5 (Forgetting: no per-aspect row): x and y released by one request; x is
// forgotten at its expiry while z's reference keeps y, so the request keeps its header for y;
// once z lets go, y is forgotten and the request goes whole. No row names x or y then but the
// headers a live thing's commits keep (z's and w's), over a restart too
#[test]
fn a_request_going_whole_after_one_of_its_things_leaves_no_row_of_it() {
    let (mut net, [a]) = local_nodes::<1>();
    let me = net.tid(a);
    let e = net.engine(a);
    let mut m = Mutation::new();
    let [z, x, y, w] = std::array::from_fn(|_| e.new_thing(&mut m, me));
    let made = e.commit(m).unwrap().unwrap();
    let mut m = Mutation::new();
    refs(&mut m, z, Value::Set([Value::Tid(y)].into()));
    m.set(x, &Ak::new("t:v.0").unwrap(), &Value::Int(1)).unwrap();
    m.set(w, &Ak::new("t:v.0").unwrap(), &Value::Int(1)).unwrap();
    let wrote = e.commit(m).unwrap().unwrap();
    let req = e.release(&[x, y]).unwrap().unwrap();
    net.advance(osis_base::format::ROLE_KEEP_MS + 1_000);
    let e = net.engine(a);
    assert_eq!(e.lifetime_status(&x), Status::Unknown);
    assert_eq!(e.lifetime_status(&y), Status::Ended, "z references y");
    assert!(e.header(&req).is_some(), "kept for y");
    let mut m = Mutation::new();
    refs(&mut m, z, Value::Set(Default::default()));
    e.commit(m).unwrap();
    assert_eq!(e.lifetime_status(&y), Status::Unknown, "forgotten once z lets go");
    assert!(e.header(&req).is_none(), "the request gone whole");
    let headers = |e: &mut Engine, t: Tid| {
        let keep = [made, wrote].map(|c| e.local_rows_naming(&c.0).unwrap());
        e.local_rows_naming(t.as_bytes()).unwrap().into_iter().all(|r| keep.iter().any(|k| k.contains(&r)))
    };
    for t in [x, y] {
        assert!(headers(net.engine(a), t), "only z's and w's commits name {t:?}");
    }
    net.restart(a, 2);
    for t in [x, y] {
        assert!(headers(net.engine(a), t), "over a restart");
    }
}
