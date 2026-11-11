//! Backlinks (notes/api.md Backlinks; issues/thing-lifetimes.md, Index and backlinks): the things
//! whose current values reference a thing, paged, as the acting actor may read them, and live.
//! spec: none (a local read over a rebuildable index; notes/engine-refs.md).

use crate::common::*;
use osis::internals::Internals as _;
use osis::internals::node::costs;
use osis::{Backlink, BacklinkPage, BacklinkQuery, DynamicAspectKey, MemStore, Osis, Role, SetRoleOpts, Tid, Value, p};
use osis_sim::world::World;
use std::sync::{Arc, Mutex};

fn key(k: &str) -> DynamicAspectKey {
    DynamicAspectKey::untyped(ak(k))
}

fn things(db: &Osis, n: usize) -> Vec<Tid> {
    db.commit_with(|w| (0..n).map(|_| w.create()).collect()).unwrap()
}

fn bl(t: Tid, k: &str) -> Backlink {
    Backlink { tid: t, ak: ak(k) }
}

/// Every backlink of `t` on `db`, one default page.
fn all(db: &osis::ReadOnly, t: Tid) -> Vec<Backlink> {
    let p = db.backlinks(t, &BacklinkQuery::default()).unwrap();
    assert!(!p.more);
    p.backlinks
}

fn sorted(mut v: Vec<Backlink>) -> Vec<Backlink> {
    v.sort();
    v
}

/// What a backlinks listener heard, in order.
struct Heard(Arc<Mutex<Vec<osis::Result<BacklinkPage>>>>, #[allow(dead_code)] osis::Subscription);

impl Heard {
    fn on(db: &Osis, t: Tid, q: &BacklinkQuery) -> Heard {
        let got = Arc::new(Mutex::new(Vec::new()));
        let g = got.clone();
        let sub = db.on_backlinks_change(t, q, move |_, p| g.lock().unwrap().push(p)).unwrap();
        db.settle();
        Heard(got, sub)
    }

    /// The pages heard since the last call, as their backlinks.
    fn take(&self, db: &Osis) -> Vec<Vec<Backlink>> {
        db.settle();
        std::mem::take(&mut *self.0.lock().unwrap()).into_iter().map(|p| p.unwrap().backlinks).collect()
    }
}

// issues/thing-lifetimes.md (Backlinks): a note linking a note shows, at any depth and on any
// aspect, ephemeral ones included, and a group listing it (`group.0`) like any other; a string
// spelling the tid does not; it stops showing when the reference goes, and the target need not
// be known.
#[test]
fn a_reference_shows_and_stops_showing() {
    let db = db(1);
    let [a, b, g, x] = things(&db, 4)[..] else { panic!() };
    db.commit_with(|w| {
        w.at(a, key("t:link.0")).set(&Value::Tid(x))?;
        w.at(b, key("t:m.0")).set(&Value::Map([(Value::Int(1), Value::List(vec![Value::Tid(x)]))].into_iter().collect()))?;
        w.at(b, key("t:txt.0")).set(&Value::Str(x.to_uri()))?;
        w.group(g).add(osis::Member::Item(x))
    })
    .unwrap();
    db.commit_with(|w| w.at(a, key("t:cursor+.0")).set(&Value::Tid(x))).unwrap();
    assert_eq!(all(&db, x), sorted(vec![bl(a, "t:cursor+.0"), bl(a, "t:link.0"), bl(b, "t:m.0"), bl(g, "group.0")]));
    db.commit_with(|w| {
        w.at(b, key("t:m.0")).path(p!(Value::Int(1))).set(&Value::List(vec![]))?;
        w.group(g).remove(osis::Member::Item(x))
    })
    .unwrap();
    assert_eq!(all(&db, x), vec![bl(a, "t:cursor+.0"), bl(a, "t:link.0")]);
    db.commit_with(|w| w.at(a, key("t:link.0")).remove()).unwrap();
    assert_eq!(all(&db, x), vec![bl(a, "t:cursor+.0")]);
    db.commit_with(|w| w.at(a, key("t:cursor+.0")).remove()).unwrap();
    assert_eq!(all(&db, x), vec![]);
    // an unknown target
    let ghost = Tid::from_bytes([7; 15]);
    db.commit_with(|w| w.at(b, key("t:link.0")).set(&Value::Tid(ghost))).unwrap();
    assert_eq!(all(&db, ghost), vec![bl(b, "t:link.0")]);
}

// issues/thing-lifetimes.md (Backlinks): another node shows the writer's backlinks, in any arrival
// order of the commits that wrote them.
#[test]
fn backlinks_follow_writes_in_any_arrival_order() {
    let orders = [[0, 1, 2], [0, 2, 1], [1, 0, 2], [1, 2, 0], [2, 0, 1], [2, 1, 0]];
    for order in orders {
        let (a, b, _) = paired();
        let [r, s, x] = things(&a, 3)[..] else { panic!() };
        let before: std::collections::BTreeSet<_> = a.engine(|e| e.commit_ids()).into_iter().collect();
        a.commit_with(|w| w.at(r, key("t:a.0")).set(&Value::Tid(x))).unwrap();
        a.commit_with(|w| w.at(s, key("t:a.0")).set(&Value::Set([Value::Tid(x)].into_iter().collect()))).unwrap();
        a.commit_with(|w| w.at(r, key("t:a.0")).set(&Value::Int(0))).unwrap();
        let ids = a.engine(|e| e.commit_ids());
        let (old, new): (Vec<_>, Vec<_>) = ids.into_iter().partition(|c| before.contains(c));
        let pk = |c| a.engine(|e| e.package(c).unwrap().unwrap());
        for c in &old {
            let p = pk(c);
            b.engine(|e| e.ingest(&p.bytes, p.blobs.clone()).unwrap());
        }
        let heard = Heard::on(&b, x, &BacklinkQuery::default());
        let mut new: Vec<_> = new.into_iter().map(|c| (a.engine(|e| e.header(&c).unwrap().ts), c)).collect();
        new.sort();
        for i in order {
            let p = pk(&new[i].1);
            b.engine(|e| e.ingest(&p.bytes, p.blobs.clone()).unwrap());
        }
        b.engine(|e| e.reexamine().unwrap());
        assert_eq!(all(&a, x), vec![bl(s, "t:a.0")]);
        assert_eq!(all(&b, x), all(&a, x), "order {order:?}");
        assert_eq!(heard.take(&b).last(), Some(&vec![bl(s, "t:a.0")]), "the listener ends where the read does, order {order:?}");
    }
}

// notes/api.md Backlinks: a page holds what the acting actor may read; a source it may not read
// is skipped (paging past it), and shows once it may read it, live.
#[test]
fn only_what_the_actor_may_read() {
    let db = db(1);
    let (actor, _) = db.add_client(None).unwrap();
    let [g, h] = things(&db, 2)[..] else { panic!() };
    let mut w = db.write();
    let x = w.create().unwrap();
    // three readable, three not
    let srcs: Vec<(Tid, bool)> = (0..6).map(|i| (w.create_in([g, h][i % 2], &[[g, h][i % 2]]).unwrap(), i % 2 == 0)).collect();
    for (s, _) in &srcs {
        w.at(*s, key("t:a.0")).set(&Value::Tid(x)).unwrap();
    }
    w.commit().unwrap();
    db.grant(g, actor, Role::Read, Default::default()).unwrap();
    let c = db.acting_as(actor);
    let want: Vec<Backlink> = sorted(srcs.iter().filter(|s| s.1).map(|s| bl(s.0, "t:a.0")).collect());
    assert_eq!(want.len(), 3);
    assert_eq!(all(&c, x), want);
    assert_eq!(all(&db, x).len(), 6, "the node reads all");
    // paged one at a time, the hidden skipped
    let mut q = BacklinkQuery { after: None, limit: Some(1) };
    let mut got = Vec::new();
    loop {
        let p = c.backlinks(x, &q).unwrap();
        got.extend(p.backlinks.iter().cloned());
        if !p.more {
            break;
        }
        q.after = p.backlinks.last().cloned();
    }
    assert_eq!(got, want);
    // read gained: the listener hears the rest
    let heard = Heard::on(&c, x, &BacklinkQuery::default());
    assert_eq!(heard.take(&c), vec![want.clone()], "initial");
    db.grant(h, actor, Role::Read, Default::default()).unwrap();
    assert_eq!(heard.take(&c).last().map(|v| v.len()), Some(6));
}

// notes/api.md Backlinks: pages chain in `Backlink` order through every backlink, `more` on all
// but the last; a page reads O(page) index rows at n and 10n backlinks.
#[test]
fn paged_at_n_and_10n() {
    fn count(n: usize) -> u64 {
        let db = db(1);
        let x = things(&db, 1)[0];
        let srcs = things(&db, n);
        db.commit_with(|w| srcs.iter().try_for_each(|s| w.at(*s, key("t:a.0")).set(&Value::Tid(x)))).unwrap();
        let mut q = BacklinkQuery { after: None, limit: Some(10) };
        let mut got = Vec::new();
        loop {
            let p = db.backlinks(x, &q).unwrap();
            assert!(p.backlinks.len() == 10 || !p.more);
            got.extend(p.backlinks.iter().cloned());
            if !p.more {
                break;
            }
            q.after = p.backlinks.last().cloned();
        }
        let mut want: Vec<_> = srcs.iter().map(|s| bl(*s, "t:a.0")).collect();
        want.sort();
        assert_eq!(got, want);
        // the default page: capped
        let p = db.backlinks(x, &BacklinkQuery { after: None, limit: Some(usize::MAX) }).unwrap();
        assert_eq!((p.backlinks.len(), p.more), (n.min(osis::internals::BACKLINK_PAGE), n > osis::internals::BACKLINK_PAGE));
        // one page from the middle
        costs::take();
        let p = db.backlinks(x, &BacklinkQuery { after: Some(want[n / 2].clone()), limit: Some(10) }).unwrap();
        let cs = costs::take();
        assert_eq!(p.backlinks, want[n / 2 + 1..n / 2 + 11].to_vec());
        cs.iter().find(|x| x.0 == "refs: row read").map_or(0, |x| x.2)
    }
    let small = count(40);
    assert_eq!(small, 11, "the page and one past it");
    assert_eq!(count(400), small);
}

// notes/api.md Backlinks: the listener hears the page at once, then each change, local ones
// included: an add, a removal, an expiry, a purge; a change past a full page's last is no change.
#[test]
fn live_through_add_remove_expiry_purge() {
    let c = clock();
    let db = osis::internals::create(cfg(1, MemStore::new(), &c)).unwrap();
    let [a, b, x] = things(&db, 3)[..] else { panic!() };
    let heard = Heard::on(&db, x, &BacklinkQuery::default());
    assert_eq!(heard.take(&db), vec![vec![]], "initial, empty");
    db.commit_with(|w| w.at(a, key("t:a.0")).set(&Value::Tid(x))).unwrap();
    assert_eq!(heard.take(&db), vec![vec![bl(a, "t:a.0")]], "added");
    db.commit_with(|w| w.at(a, key("t:a.0")).set(&Value::List(vec![Value::Tid(x)]))).unwrap();
    assert_eq!(heard.take(&db), Vec::<Vec<Backlink>>::new(), "the same page: nothing told");
    db.commit_with(|w| w.at(a, key("t:a.0")).remove()).unwrap();
    assert_eq!(heard.take(&db), vec![vec![]], "removed");
    let mut w = db.write();
    w.expires(osis::Expiry::In(std::time::Duration::from_secs(60)));
    w.at(a, key("t:a.0")).set(&Value::Tid(x)).unwrap();
    w.commit().unwrap();
    let ret = osis::Retention { by: osis::internals::schema::PurgeBy::Writer };
    db.commit_with(|w| w.at(b, key("t:b.0")).retention(ret).set(&Value::Tid(x))).unwrap();
    assert_eq!(heard.take(&db).last(), Some(&sorted(vec![bl(a, "t:a.0"), bl(b, "t:b.0")])));
    c.advance(61_000);
    db.engine(|e| e.tick()).unwrap();
    assert_eq!(heard.take(&db), vec![vec![bl(b, "t:b.0")]], "expired");
    db.commit_with(|w| w.at(b, key("t:b.0")).purge(osis::Purge::All)).unwrap();
    assert_eq!(heard.take(&db), vec![vec![]], "purged");
}

// notes/api.md Backlinks: a reference whose write turns invalid (its writer removed with a
// frontier that omits it) leaves the page, and the listener hears it.
#[test]
fn a_validity_flip_is_heard() {
    let mut w = World::new();
    let host = w.add_host();
    let alice = w.account(1, &[host]);
    let bob = w.account(2, &[host]);
    w.run();
    let card = bob.contact_card().unwrap();
    w.run();
    let b = w.until(alice.import_contact(&card), 1000, 10).unwrap();
    let g = alice
        .commit_with(|x| {
            let g = x.create()?;
            x.group(alice.home()).add(osis::Member::Item(g))?;
            Ok(g)
        })
        .unwrap();
    alice.sync(g, &[]).unwrap();
    alice.grant(g, b, Role::Write, Default::default()).unwrap();
    w.run();
    for r in bob.invite_requests().unwrap_or_default() {
        let _ = bob.accept_invite(r);
    }
    w.run();
    w.set_online(&bob, false);
    w.advance(1000);
    alice.set_role(g, b, None, SetRoleOpts { retain_copy: Some(true) }).unwrap();
    w.run();
    let target = alice.home();
    let heard = Heard::on(&bob, target, &BacklinkQuery::default());
    bob.commit_with(|x| x.at(g, key("t:a.0")).set(&Value::Tid(target))).unwrap();
    assert!(heard.take(&bob).last().is_some_and(|p| p.contains(&bl(g, "t:a.0"))), "valid where written");
    w.set_online(&bob, true);
    w.advance(60_000);
    w.run();
    assert!(!all(&bob, target).contains(&bl(g, "t:a.0")), "invalid once the removal arrives");
    assert!(heard.take(&bob).last().is_some_and(|p| !p.contains(&bl(g, "t:a.0"))), "heard");
}
