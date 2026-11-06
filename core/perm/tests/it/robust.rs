//! Untrusted records never panic perm (notes/architecture.md §3): seeded junk held sets with
//! self edges, owner edges, ownerless things, invites above roles, inverted ranges, unknown
//! things, then every query.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use crate::common;

use common::*;
use roles_model::Rng;
use osis_base::{Role, Tid, WallMs};
use osis_perm::{At, Edge, EdgeOp, Frontier, RoleCommit, MemoryHeldSet, Point, Timeline};
use std::sync::Arc;

fn pick<T: Copy>(rng: &mut Rng, v: &[T]) -> T {
    v[rng.below(v.len())]
}

fn junk(rng: &mut Rng) -> (MemoryHeldSet, Vec<Tid>) {
    let mut h = MemoryHeldSet::new();
    let mut tids: Vec<Tid> = key_actors(3, rng.next() as u8).into_iter().map(|(t, r)| {
        h.created.insert(t, r);
        t
    }).collect();
    for i in 0..4 {
        let admin = pick(rng, &tids);
        let (t, r) = thing_record(admin, rng.next() ^ i);
        if rng.below(4) != 0 {
            h.created.insert(t, r);
        }
        tids.push(t);
    }
    tids.push(Tid::from_bytes([9; 15]));
    let roles = [Role::Read, Role::Write, Role::Admin];
    let any_edge = |rng: &mut Rng| -> Option<Edge> {
        (rng.below(4) != 0).then(|| Edge {
            role: pick(rng, &roles),
            until: (rng.below(3) == 0).then(|| WallMs(rng.below(12) as u64)),
            invite: (rng.below(2) == 0).then(|| pick(rng, &roles)),
            tied: None,
        })
    };
    let frontier = |rng: &mut Rng| -> Option<Arc<Frontier>> {
        (rng.below(2) == 0).then(|| {
            let mut f = Frontier::default();
            f.commits.insert(cid(rng.below(40) as u32));
            Arc::new(f)
        })
    };
    for i in 0..(2 + rng.below(12)) {
        let target = pick(rng, &tids);
        let mut ops = vec![EdgeOp { target, holder: pick(rng, &tids), edge: any_edge(rng) }];
        if rng.below(4) == 0 {
            ops.push(EdgeOp { target: pick(rng, &tids), holder: pick(rng, &tids), edge: any_edge(rng) });
        }
        let author = pick(rng, &tids);
        h.add_commit(RoleCommit { id: cid(i as u32), ts: ts(rng.below(12) as u64), author, actor: author, frontier: frontier(rng), ops });
    }
    (h, tids)
}

/// spec: none (notes/architecture.md §3): no panics on data.
#[test]
fn junk_never_panics() {
    let mut rng = Rng(0x0b5e55ed);
    for _ in 0..300 {
        let (h, tids) = junk(&mut rng);
        let tl = Timeline::evaluate(&h);
        for x in &tids {
            for t in &tids {
                for at in [At::END, At::now(ts(6)), At::before(Point { ts: ts(5), node: *x, commit: cid(7) })] {
                    let _ = (tl.role(x, t, at), tl.invite(x, t, at), tl.class(x, t, at), tl.roster(t, at));
                }
                let p = Point { ts: ts(rng.below(12) as u64), node: *x, commit: cid(3) };
                let _ = tl.delta_valid(p, t, Role::Write);
            }
        }
    }
}
