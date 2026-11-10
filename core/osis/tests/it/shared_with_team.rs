//! A thing shared with a team its admin is not in (spec/crypto.md §4 Holder actors): the team's
//! members read it, and keep reading it across key changes, whether or not the thing's admin was
//! ever a member of the team, and whatever reaches the admin first.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use crate::common::*;
use crate::common::CreateIn;
use osis::{Osis, Role, SetRoleOpts, Tid, Value};
use osis_sim::world::World;

fn s(x: &str) -> Value {
    Value::Str(x.into())
}

fn item(db: &Osis, g: Tid, v: &str) -> Tid {
    let mut w = db.write();
    let t = w.create_in(g, &[g]).unwrap();
    w.at(t, osis::DynamicAspectKey::untyped(ak("t:x.0"))).set(&s(v)).unwrap();
    w.commit().unwrap();
    t
}

fn read(db: &Osis, t: Tid) -> Option<Value> {
    db.at(t, osis::DynamicAspectKey::untyped(ak("t:x.0"))).get().unwrap()
}

fn group(db: &Osis, peers: &[osis::Address]) -> Tid {
    let mut w = db.write();
    let g = w.create_in(db.me(), &[db.home()]).unwrap();
    w.commit().unwrap();
    db.sync(g, peers).unwrap();
    g
}

fn settle(w: &mut World) {
    for _ in 0..2 {
        w.advance(70_000);
        w.run();
    }
}

/// What reaches Carol first after T's change: everything at once (`Together`), or the change to T
/// alone (`Away`: Carol offline through it, hearing of it by her inbox; T's members cut off from
/// X's host until after Carol wrote to X, so T's new keys reach her only then).
#[derive(Clone, Copy, Debug)]
enum Order {
    Together,
    Away,
}

struct Cast {
    w: World,
    x_host: usize,
    alice: Osis,
    bob: Osis,
    carol: Osis,
    dave: Osis,
    erin: Osis,
    t: Tid,
    x: Tid,
}

/// Alice's team T (Bob and Dave read it, Carol too when `member`) on the one host everyone uses;
/// Carol's doc X, she its only admin, read by T and by Erin, synced on a host of its own. When
/// Carol is no member she learns T's keys from Alice's doc S, which both T and Carol read.
fn cast(member: bool) -> Cast {
    let mut w = World::new();
    let host = w.add_host();
    let x_host = w.add_host();
    let alice = w.account(1, &[host]);
    let bob = w.account(2, &[host]);
    let carol = w.account(3, &[host]);
    let dave = w.account(4, &[host]);
    let erin = w.account(5, &[host]);
    w.run();
    let card = |w: &mut World, of: &Osis, to: &Osis| {
        let c = of.contact_card().unwrap();
        w.run();
        w.until(to.import_contact(&c), 1000, 10).unwrap()
    };
    let (b, c, d) = (card(&mut w, &bob, &alice), card(&mut w, &carol, &alice), card(&mut w, &dave, &alice));
    let e = card(&mut w, &erin, &carol);
    let t = group(&alice, &[]);
    for h in [b, d].into_iter().chain(member.then_some(c)) {
        alice.grant(t, h, Role::Read, Default::default()).unwrap();
    }
    w.run();
    if !member {
        let s = group(&alice, &[]);
        alice.grant(s, t, Role::Read, Default::default()).unwrap();
        alice.grant(s, c, Role::Read, Default::default()).unwrap();
        w.run();
    }
    let x = group(&carol, &[w.addr(x_host).unwrap()]);
    carol.grant(x, t, Role::Read, Default::default()).unwrap();
    carol.grant(x, e, Role::Read, Default::default()).unwrap();
    w.run();
    let before = item(&carol, x, "before");
    settle(&mut w);
    for db in [&bob, &dave, &erin] {
        assert_eq!(read(db, before), Some(s("before")), "member {member}");
    }
    Cast { w, x_host, alice, bob, carol, dave, erin, t, x }
}

/// Alice changes T (`change`), arriving at Carol in `order`; Carol writes to X, then changes X's
/// keys (removing Erin) and writes again. T's remaining members read both writes; `gone` (left T)
/// and Erin read neither the write after X's new keys nor, `gone`, anything once T's new keys
/// reached Carol.
fn run(mut c: Cast, order: Order, gone: Option<&Osis>, change: impl FnOnce(&Cast)) {
    let what = format!("{order:?}");
    let team = [c.alice.clone(), c.bob.clone(), c.dave.clone()];
    let carol = c.carol.clone();
    if let Order::Away = order {
        for db in &team {
            c.w.set_reachable(db, c.x_host, false);
        }
        c.w.set_online(&carol, false);
    }
    change(&c);
    c.w.run();
    if let Order::Away = order {
        settle(&mut c.w);
        c.w.set_online(&carol, true);
        c.w.run();
    }
    let after = item(&c.carol, c.x, "after");
    c.w.run();
    settle(&mut c.w);
    for db in &team {
        c.w.set_reachable(db, c.x_host, true);
    }
    settle(&mut c.w);
    c.carol.set_role(c.x, c.erin.me(), None, SetRoleOpts::default()).unwrap();
    settle(&mut c.w);
    let rotated = item(&c.carol, c.x, "rotated");
    settle(&mut c.w);
    for db in [&c.bob, &c.dave].into_iter().filter(|db| gone.is_none_or(|g| g.me() != db.me())) {
        assert_eq!(read(db, after), Some(s("after")), "{what}");
        assert_eq!(read(db, rotated), Some(s("rotated")), "{what}: reads X after Carol changed its keys");
    }
    assert_eq!(read(&c.erin, rotated), None, "{what}");
    if let Some(g) = gone {
        assert_eq!(read(g, rotated), None, "{what}: the departed member");
    }
}

// spec/crypto.md §4 Holder actors, Encrypting under (a node's own departure holds back none of
// its encrypting): Carol, X's only admin, was a member of T and is removed from it, keeping a copy;
// T's members still read X, including after Carol changes X's keys.
#[test]
fn admin_removed_from_the_team_keeps_it_reading_spec_crypto_4() {
    for order in [Order::Together, Order::Away] {
        let c = cast(true);
        let (t, carol) = (c.t, c.carol.me());
        run(c, order, None, |c| c.alice.set_role(t, carol, None, SetRoleOpts { retain_copy: Some(true) }).unwrap());
    }
}

// spec/crypto.md §4 Holder actors: Carol never was a member of T; Dave is removed from T. T's
// other members read X with Carol's new keys, Dave does not.
#[test]
fn member_removed_from_a_foreign_team_reads_nothing_new_spec_crypto_4() {
    for order in [Order::Together, Order::Away] {
        let c = cast(false);
        let (t, dave) = (c.t, c.dave.me());
        let gone = c.dave.clone();
        run(c, order, Some(&gone), |c| c.alice.set_role(t, dave, None, SetRoleOpts::default()).unwrap());
    }
}
