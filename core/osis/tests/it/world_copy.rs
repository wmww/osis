//! World copies of `osis` nodes (notes/test-harnesses.md, Copied worlds): a copied sim `World` goes on
//! exactly as the original, its nodes' watches work, and the two share nothing.

use crate::common::*;
use osis::internals::Internals as _;
use osis::{Osis, Role, Tid, Value};
use osis_sim::world::World;
use std::sync::{Arc, Mutex};

fn x(db: &Osis, t: Tid) -> Option<Value> {
    db.at(t, osis::DynamicAspectKey::untyped(ak("t:x.0"))).get().unwrap()
}

fn set(db: &Osis, t: Tid, v: &str) {
    let mut w = db.write();
    w.at(t, osis::DynamicAspectKey::untyped(ak("t:x.0"))).set(&Value::Str(v.into())).unwrap();
    w.commit().unwrap();
}

/// A host, Alice and Bob, Bob in Alice's contacts and a writer of her synced group `g` holding `t`;
/// a pairing offer of Alice's not yet used.
fn setup() -> (World, [Osis; 2], (Tid, Tid, osis::PairOffer)) {
    let mut w = World::new();
    let host = w.add_host();
    let alice = w.account(1, &[host]);
    let bob = w.account(2, &[host]);
    w.run();
    let card = bob.contact_card().unwrap();
    w.run();
    let b = w.until(alice.import_contact(&card), 1000, 10).unwrap();
    let mut wr = alice.write();
    let g = wr.create().unwrap();
    wr.commit().unwrap();
    alice.sync(g, &[]).unwrap();
    alice.grant(g, b, Role::Write, Default::default()).unwrap();
    let t = {
        let mut wr = alice.write();
        let t = wr.create_in(g, &[g]).unwrap();
        wr.commit().unwrap();
        t
    };
    set(&alice, t, "a0");
    w.run();
    let offer = alice.pair_offer().unwrap();
    // left unsettled: a write in flight, part of it still in Bob's queue, part in the world's
    set(&bob, t, "b0");
    w.step(None);
    set(&bob, t, "b1");
    (w, [alice, bob], (g, t, offer))
}

/// Further steps: watches on both nodes, writes, a third account granted in, Alice's offer used,
/// time.
fn further(w: &mut World, dbs: &[Osis; 2], g: Tid, t: Tid, offer: &osis::PairOffer) -> Vec<String> {
    let [alice, bob] = dbs;
    let watched = watched(bob, t, osis::DynamicAspectKey::untyped(ak("t:x.0"))).unwrap();
    let told = Arc::new(Mutex::new(Vec::new()));
    let sub = {
        let told = told.clone();
        alice.on_status_change(move |_, s| told.lock().unwrap().push(format!("{s:?}"))).unwrap()
    };
    w.run();
    set(alice, t, "a1");
    w.run();
    let carol = w.account(3, &[0]);
    w.run();
    let card = carol.contact_card().unwrap();
    w.run();
    let c = w.until(alice.import_contact(&card), 1000, 10).unwrap();
    alice.grant(g, c, Role::Read, Default::default()).unwrap();
    let join = osis::internals::pair(w.cfg(4, &[0]), offer).unwrap();
    let (_, reply) = alice.pair_accept(join.request()).unwrap();
    let alice2 = join.finish(&reply).unwrap();
    w.advance(61_000);
    w.run();
    bob.settle();
    alice.settle();
    drop(sub);
    let told = std::mem::take(&mut *told.lock().unwrap());
    vec![format!("{:?} {:?} {:?} {:?} {told:?}", watched.current(), x(&carol, t), x(&alice2, t), w.diagnostics(alice))]
}

/// What a test could compare: reads, status, engine indexes, roles and stores, traffic and the world's counters.
fn observe(w: &mut World, dbs: &[Osis], t: Tid) -> Vec<String> {
    let mut out = vec![format!("{} {}", w.hops(), w.now())];
    for db in dbs {
        out.push(format!("{:?} {:?} {:?} {}", x(db, t), db.status(), w.traffic(db), db.watches()));
        out.push(db.engine(|e| format!("{:?} {} {:?}", e.index_digest(), e.perm_digest(false), e.store_dump().unwrap())));
    }
    out
}

// spec: none (internal: notes/test-harnesses.md, Copied worlds). A copied world goes on exactly as
// the original and as a world built afresh: the same further steps (with watches on the copies)
// leave the same reads, indexes, stores and counters, and steps on either leave the other as it
// was.
#[test]
fn a_copied_world_goes_on_as_the_original() {
    let (mut w, dbs, (g, t, offer)) = setup();
    let (mut fresh, fdbs, (_, _, foffer)) = setup();
    let (mut copy, c) = w.copy();
    let cdbs = [c[0].clone().unwrap(), c[1].clone().unwrap()];
    drop(c);
    let (mut untouched, u) = w.copy();
    let udbs = [u[0].clone().unwrap(), u[1].clone().unwrap()];
    drop(u);
    assert_eq!(observe(&mut fresh, &fdbs, t), observe(&mut copy, &cdbs, t), "as built");
    assert_eq!(observe(&mut w, &dbs, t), observe(&mut copy, &cdbs, t), "as copied");
    let before = observe(&mut untouched, &udbs, t);
    assert_eq!(w.diagnostics(&dbs[0]), copy.diagnostics(&cdbs[0]), "diagnostics so far");
    let a = further(&mut w, &dbs, g, t, &offer);
    let b = further(&mut copy, &cdbs, g, t, &offer);
    assert_eq!(a, b, "watched and read");
    assert_eq!(further(&mut fresh, &fdbs, g, t, &foffer), b, "watched and read, as built");
    assert!(a[0].starts_with(r#"Ok(Some(Str("a1"))) Some(Str("a1")) Some(Str("a1"))"#), "the watch, the new reader and the paired node saw the write: {a:?}");
    let after = observe(&mut copy, &cdbs, t);
    assert_eq!(observe(&mut w, &dbs, t), after, "after the same steps");
    assert_eq!(observe(&mut fresh, &fdbs, t), after, "after the same steps, as built");
    assert_eq!(observe(&mut untouched, &udbs, t), before, "the others' steps stay in them");
}
