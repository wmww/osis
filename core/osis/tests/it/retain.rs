//! Retain (spec/permissions.md §3): what a removed holder's node keeps. Commits travel by
//! `deliver` (no sync; as plaintext packages, so what a copy refuses is the node's rule, not a
//! key it lacks), and the lost-access trigger, sync's to run, is run by hand after each delivery
//! (`drop_lost_due`).

use crate::common::*;
use osis::internals::Internals as _;
use osis::{DynamicAspectKey, Error, Osis, Role, SetRoleOpts, Tid, Value};

fn x() -> DynamicAspectKey {
    DynamicAspectKey::untyped(ak("t:x.0"))
}

fn s(v: &str) -> Value {
    Value::Str(v.into())
}

/// Delivers what `from` holds to `to`, then runs `to`'s lost-access trigger.
fn carry(from: &Osis, to: &Osis) {
    deliver(from, to);
    to.engine(|e| e.drop_lost_due().unwrap());
}

/// Alice's group `g` holding `t` (`t:x.0` "before"), `g`'s retain default `default`, Bob granted
/// read and holding it: (alice, bob, g, t).
fn bob_reads(default: Option<bool>) -> (Osis, Osis, Tid, Tid) {
    let (alice, bob) = (db(1), db(2));
    deliver(&bob, &alice);
    let mut w = alice.write();
    let g = w.create().unwrap();
    let t = w.create_in(g, &[g]).unwrap();
    w.at(t, x()).set(&s("before")).unwrap();
    w.commit().unwrap();
    if let Some(k) = default {
        alice.set_retain_copies_default(g, k).unwrap();
    }
    alice.grant(g, bob.me(), Role::Read, Default::default()).unwrap();
    carry(&alice, &bob);
    assert_eq!(bob.at(t, x()).get().unwrap(), Some(s("before")));
    (alice, bob, g, t)
}

fn write_refused(db: &Osis, t: Tid) -> bool {
    matches!(db.commit_set(t, x(), &s("mine")), Err(Error::Permission { .. }))
}

// spec/permissions.md §3 (Retain): a removal saying retain, or saying nothing under a default
// that does, leaves the removed node a read-only copy it reads and may erase; one saying erase,
// or nothing with no default, leaves nothing.
#[test]
fn a_removal_keeps_a_copy_as_it_says_spec_permissions_3() {
    for (default, say, kept) in [(Some(true), None, true), (Some(true), Some(false), false), (None, Some(true), true), (None, None, false)] {
        let (alice, bob, g, t) = bob_reads(default);
        alice.set_role(g, bob.me(), None, SetRoleOpts { retain_copy: say }).unwrap();
        carry(&alice, &bob);
        let case = format!("default {default:?}, removal says {say:?}");
        assert_eq!(bob.retained_copies().unwrap(), if kept { vec![g] } else { vec![] }, "{case}");
        assert_eq!(bob.at(t, x()).get().unwrap(), kept.then(|| s("before")), "{case}");
        if kept {
            assert!(write_refused(&bob, t), "read-only");
            bob.drop_retained_copy(g).unwrap();
            assert!(bob.retained_copies().unwrap().is_empty());
            assert_eq!(bob.at(t, x()).get().unwrap(), None, "erased");
        }
    }
}

// spec/permissions.md §3 (Retain: The copy: a later part is not joined; a role with a secret
// again ends the copy): a copy stays as it was while the thing moves on; granted again, the node
// is a holder again and keeps no copy. (Fetching the parts it refused meanwhile is sync's.)
#[test]
fn a_regrant_ends_a_copy_spec_permissions_3() {
    let (alice, bob, g, t) = bob_reads(Some(true));
    alice.set_role(g, bob.me(), None, SetRoleOpts::default()).unwrap();
    carry(&alice, &bob);
    assert_eq!(bob.retained_copies().unwrap(), vec![g]);
    alice.commit_set(t, x(), &s("during")).unwrap();
    carry(&alice, &bob);
    assert_eq!(bob.at(t, x()).get().unwrap(), Some(s("before")), "frozen");
    alice.grant(g, bob.me(), Role::Read, Default::default()).unwrap();
    alice.commit_set(t, x(), &s("after")).unwrap();
    carry(&alice, &bob);
    assert!(bob.retained_copies().unwrap().is_empty());
    assert_eq!(bob.role_on(g).unwrap(), Some(Role::Read));
    assert_eq!(bob.at(t, x()).get().unwrap(), Some(s("after")));
}

// spec/permissions.md §3 (Retain: an ended grant says what the thing's default says; The copy:
// a later part is not joined; it cannot write it): a grant ending at its `until` under a default
// that retains leaves a copy; what is written after never reaches it, and the node writes
// nothing there, durable or ephemeral. (Ephemeral commits travel only by sync: whether one
// reaches a copy waits for it.)
#[test]
fn an_until_ending_keeps_a_copy_that_takes_nothing_new_spec_permissions_3() {
    let c = clock();
    let (alice, bob) = (osis::internals::create(cfg(1, osis::MemStore::new(), &c)).unwrap(), osis::internals::create(cfg(2, osis::MemStore::new(), &c)).unwrap());
    deliver(&bob, &alice);
    let e = DynamicAspectKey::untyped(ak("t:e+.0"));
    let mut w = alice.write();
    let g = w.create().unwrap();
    let t = w.create_in(g, &[g]).unwrap();
    w.at(t, x()).set(&s("before")).unwrap();
    w.commit().unwrap();
    alice.set_retain_copies_default(g, true).unwrap();
    let until = osis::Time(T0 + 60_000);
    alice.grant(g, bob.me(), Role::Write, osis::GrantOpts { until: Some(until), may_grant: None }).unwrap();
    carry(&alice, &bob);
    c.advance(120_000);
    // lost by the time alone: sync drops it once it has heard the sync IDs out (§2)
    let leaving = bob.engine(|e| e.lost_leaving().unwrap());
    assert!(leaving.timed.contains_key(&g), "{leaving:?}");
    bob.engine(|e| e.forget_lost(osis::internals::engine::rotation::LostScope::Only(&[g])).unwrap());
    assert_eq!(bob.retained_copies().unwrap(), vec![g]);
    alice.commit_set(t, x(), &s("after")).unwrap();
    carry(&alice, &bob);
    assert_eq!(bob.at(t, x()).get().unwrap(), Some(s("before")), "frozen");
    assert!(write_refused(&bob, t));
    assert!(matches!(bob.commit_set(t, e, &s("mine")), Err(Error::Permission { .. })));
}


// spec/permissions.md §3 (The copy: expiry runs as on any held body): a write that expires
// leaves a copy at its time too.
#[test]
fn a_copy_still_expires_spec_permissions_3() {
    let c = clock();
    let (alice, bob) = (osis::internals::create(cfg(1, osis::MemStore::new(), &c)).unwrap(), osis::internals::create(cfg(2, osis::MemStore::new(), &c)).unwrap());
    deliver(&bob, &alice);
    let mut w = alice.write();
    let g = w.create().unwrap();
    let t = w.create_in(g, &[g]).unwrap();
    w.at(t, x()).set(&s("kept")).unwrap();
    w.commit().unwrap();
    let mut w = alice.write();
    w.expires(osis::Expiry::In(std::time::Duration::from_secs(60)));
    w.at(t, DynamicAspectKey::untyped(ak("t:gone.0"))).set(&s("for a minute")).unwrap();
    w.commit().unwrap();
    alice.grant(g, bob.me(), Role::Read, Default::default()).unwrap();
    carry(&alice, &bob);
    alice.set_role(g, bob.me(), None, SetRoleOpts { retain_copy: Some(true) }).unwrap();
    carry(&alice, &bob);
    assert_eq!(bob.retained_copies().unwrap(), vec![g]);
    assert_eq!(bob.at(t, DynamicAspectKey::untyped(ak("t:gone.0"))).get().unwrap(), Some(s("for a minute")));
    c.advance(61_000);
    assert_eq!(bob.at(t, DynamicAspectKey::untyped(ak("t:gone.0"))).get().unwrap(), None, "expired");
    assert_eq!(bob.at(t, x()).get().unwrap(), Some(s("kept")));
}
