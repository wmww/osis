//! Making a thing (spec/sync-set.md §2 Making a thing, Cost): the work of making the next
//! thing is what it changed, never what the node holds already. Counted at n and 10n held.
//! spec: spec/sync-set.md

use crate::common::*;
use osis::internals::costs;
use osis::{Dispatcher, MemStore, Osis};
use std::collections::BTreeMap;
use std::sync::Arc;

fn pumped() -> Osis {
    let mut c = cfg(0, MemStore::new(), &clock());
    c.app.dispatch = Dispatcher::Pump(Arc::new(|| {}));
    osis::internals::create(c).unwrap()
}

/// Makes one thing, held where it lives: plain in the account root's sync unit, else under the
/// account (own keys, a sync ID of its own, the account's ticket for it in the account root).
fn make(db: &Osis, plain: bool) {
    let mut w = db.write();
    match plain {
        true => drop(w.create_held_with_admin(db.account_root()).unwrap()),
        false => drop(w.create_held().unwrap()),
    }
    w.commit().unwrap();
    db.settle();
}

/// Per counted kind, the work of making one more thing after `n` held ones: the least of three
/// such makes, since an aspect the makes write (the account root's `holds.0` and `tickets.0`)
/// compacts once its bodies outweigh a snapshot (spec/sync-compaction.md §1), a cost its trigger
/// spreads over the writes it covers.
fn next(n: usize, plain: bool) -> BTreeMap<&'static str, u64> {
    let db = pumped();
    for _ in 0..n {
        make(&db, plain);
    }
    let mut runs = Vec::new();
    for _ in 0..3 {
        costs::take();
        make(&db, plain);
        runs.push(costs::take().into_iter().map(|(k, _, c)| (k, c)).collect::<BTreeMap<_, _>>());
    }
    let kinds: std::collections::BTreeSet<&'static str> = runs.iter().flat_map(|r| r.keys().copied()).collect();
    kinds.into_iter().map(|k| (k, runs.iter().map(|r| r.get(k).copied().unwrap_or(0)).min().unwrap_or(0))).filter(|x| x.1 > 0).collect()
}

/// The kinds whose count at 10n grew past half again that at n: work in proportion to what is
/// held grows tenfold, while a driver's rounds to quiet differ by one or two between makes.
/// Bytes streamed included: a snapshot of the account root's aspects below a page is decoded
/// once per write of it, not streamed whole at each cover judgment of a body against it.
fn grown(small: &BTreeMap<&'static str, u64>, big: &BTreeMap<&'static str, u64>) -> Vec<(&'static str, u64, u64)> {
    big.iter().filter_map(|(k, b)| {
        let s = small.get(k).copied().unwrap_or(0);
        (*b > s + s / 2 + 2).then_some((*k, s, *b))
    }).collect()
}

// spec/sync-set.md §2 (Cost: a change costs work in proportion to what it adds; Making a thing): one more plain
// thing in the account root's sync unit moves its own unit membership alone (no memo over the
// whole unit: bodies, facts, own commits and judgements re-read only what it names) and no other
// thing's certificates: every counted kind flat from 80 to 400 such things (the root's `holds.0`
// paged at both: a set pages from about 3 KB). Among them: a role is read back from its thing
// (`perm: roles walked`), the new leaf moves its component's whole-timeline reads once
// (`timelines: components moved`), and what reaches its first admin gains it without a walk
// (`perm: chain reach walked`).
#[test]
fn making_a_plain_thing_costs_what_it_changed_spec_sync_set_2() {
    let (small, big) = (next(80, true), next(400, true));
    assert_eq!(grown(&small, &big), [], "work of the next plain thing grew with the things held");
}

// spec/sync-set.md §2 (Cost; Making a thing), spec/permissions.md §3 (a thing whose first admin is
// an account gets secrets of its own): one more thing with own keys moves no other sync ID's dial peers, tickets, lost access,
// role duty, wrap or judgements: every counted kind flat from 4 to 40 such things.
#[test]
fn making_a_thing_with_own_keys_costs_what_it_changed_spec_sync_set_2() {
    let (small, big) = (next(4, false), next(40, false));
    assert_eq!(grown(&small, &big), [], "work of the next thing with own keys grew with the things held");
}
