//! A messenger's basics over the sim's real nodes: an invite and a write reach the peer, and a
//! contact stays readable, whatever raced them.
use crate::common::TestWrites as _;
use crate::common::ak;
use osis::internals::Internals as _;
use osis::{SetRoleOpts, SyncFirst, Member, Address, MemStore, Osis, Role, Store, SyncScope, SyncState, Tid, Value};
use osis_sim::world::World;
use std::sync::{Arc, Mutex};

fn s(x: &str) -> Value {
    Value::Str(x.into())
}

fn text() -> osis::Ak {
    ak("msg:text.0")
}

fn says(db: &Osis, t: Tid) -> Option<Value> {
    db.at(t, osis::DynamicAspectKey::untyped(text())).get().unwrap()
}

/// A shared group of `a`'s under its own label at `hosts` (none: `a`'s peers).
fn chat(a: &Osis, hosts: &[Address]) -> Tid {
    let mut w = a.write();
    let g = w.create().unwrap();
    w.group(a.me()).add(osis::Member::Item(g)).unwrap();
    w.commit().unwrap();
    a.sync(g, hosts).unwrap();
    g
}

/// A message in `g`.
fn message(db: &Osis, g: Tid, v: &str) -> Tid {
    db.commit_with(|w| {
        let m = w.create_owned_by(g)?;
        w.group(g).add(osis::Member::Item(m))?;
        w.at(m, osis::DynamicAspectKey::untyped(text())).set(&s(v))?;
        Ok(m)
    })
    .unwrap()
}

/// Alice and Bob at `hosts`, Bob a contact of Alice's: (alice, bob, Bob's account).
fn pair(w: &mut World, hosts: &[usize]) -> (Osis, Osis, Tid) {
    let (a, _) = w.person(1, hosts);
    let (b, _) = w.person(2, hosts);
    w.run();
    let card = b.contact_card().unwrap();
    w.run();
    let bob = w.until(a.import_contact(&card), 1000, 10).unwrap();
    (a, b, bob)
}

fn skip() -> SetRoleOpts {
    SetRoleOpts { sync: SyncFirst::Skip, retain_copy: None }
}

// spec/sync.md §3 (a recipient looks for what an inbox blob names), §5: the invite to a chat its maker has not registered at the chat's peer yet: the invitee is told "not here" and looks again after a back-off, well before the periodic resync, not stranded meanwhile
#[test]
fn invite_to_a_group_not_yet_at_its_peer_looks_again_spec_sync_3() {
    let mut w = World::new();
    let h0 = w.add_host();
    let h1 = w.add_host();
    let (a, b, bob) = pair(&mut w, &[h0]);
    w.set_reachable(&a, h1, false);
    let g = chat(&a, &[w.addr(h1).unwrap()]);
    let m = message(&a, g, "hello");
    a.grant(g, bob, Role::Write, Default::default()).unwrap();
    w.run();
    w.advance(1000);
    w.run();
    assert_eq!(says(&b, m), None, "the chat is at no host yet");
    assert_ne!(b.status().unwrap().groups.get(&g).map(|x| x.state), Some(SyncState::Stranded));
    w.set_reachable(&a, h1, true);
    // retry_ms 5 s for each side's dial and look, well under resync_ms (60 s)
    for _ in 0..20 {
        w.advance(1000);
        w.run();
        if says(&b, m).is_some() {
            break;
        }
    }
    assert_eq!(says(&b, m), Some(s("hello")), "{:?}", w.diagnostics(&b));
}

// spec/sync.md §3 (a grantee node places a certificate copy): a grant to a group its granter owns: the group's inbox is the granter's, so its own deposit comes back naming a commit it holds, and that alone must start the group's label's pass: the group's member reads the chat with no clock passing
#[test]
fn grant_to_ones_own_group_reaches_its_members_at_once_spec_sync_3() {
    let mut w = World::new();
    let h0 = w.add_host();
    let (a, b, bob) = pair(&mut w, &[h0]);
    let realm = chat(&a, &[]);
    a.grant(realm, bob, Role::Write, Default::default()).unwrap();
    w.run();
    let g = chat(&a, &[]);
    let m = message(&a, g, "hello");
    w.run();
    a.grant(g, realm, Role::Read, Default::default()).unwrap();
    w.run();
    assert_eq!(says(&b, m), Some(s("hello")));
}

// spec/sync.md §6 (a content write passes only the labels holding it): with no clock passing, so no resync: one commit across two chats, a message in two labels, one in a group nested in a chat, a member's write and a profile rename each reach every reader
#[test]
fn content_writes_reach_every_label_holding_them_at_once_spec_sync_6() {
    let mut w = World::new();
    let h0 = w.add_host();
    let (a, b, bob) = pair(&mut w, &[h0]);
    let (c, _) = w.person(3, &[h0]);
    w.run();
    let card = c.contact_card().unwrap();
    w.run();
    let carol = w.until(a.import_contact(&card), 1000, 10).unwrap();
    let (g1, g2) = (chat(&a, &[]), chat(&a, &[]));
    a.grant(g1, bob, Role::Write, Default::default()).unwrap();
    a.grant(g2, carol, Role::Write, Default::default()).unwrap();
    w.run();
    // one commit across both, each thing new and placed in it
    let (m1, m2) = a
        .commit_with(|x| {
            let (m1, m2) = (x.create_owned_by(g1)?, x.create_owned_by(g2)?);
            x.group(g1).add(osis::Member::Item(m1))?;
            x.group(g2).add(osis::Member::Item(m2))?;
            x.at(m1, osis::DynamicAspectKey::untyped(text())).set(&s("one"))?;
            x.at(m2, osis::DynamicAspectKey::untyped(text())).set(&s("two"))?;
            Ok((m1, m2))
        })
        .unwrap();
    w.run();
    assert_eq!((says(&b, m1), says(&c, m2)), (Some(s("one")), Some(s("two"))));
    // no placement in the next ones, so only the labels holding them pass
    let mut x = a.write();
    x.at(m1, osis::DynamicAspectKey::untyped(text())).set(&s("one more")).unwrap();
    x.at(m2, osis::DynamicAspectKey::untyped(text())).set(&s("two more")).unwrap();
    x.commit().unwrap();
    w.run();
    assert_eq!((says(&b, m1), says(&c, m2)), (Some(s("one more")), Some(s("two more"))));
    // a group under the first with a label of its own: a message in it is in both labels
    let mut x = a.write();
    let t = x.create_owned_by(g1).unwrap();
    x.group(g1).add(osis::Member::Subgroup(t)).unwrap();
    let sub = t;
    x.commit().unwrap();
    a.sync(sub, &[]).unwrap();
    a.grant(sub, carol, Role::Read, Default::default()).unwrap();
    w.run();
    let both = message(&a, sub, "both");
    w.run();
    assert_eq!((says(&b, both), says(&c, both)), (Some(s("both")), Some(s("both"))));
    a.commit_set(both, osis::DynamicAspectKey::untyped(text()), &s("both again")).unwrap();
    w.run();
    assert_eq!((says(&b, both), says(&c, both)), (Some(s("both again")), Some(s("both again"))));
    // a nested group without one, then a message in it
    let mut x = a.write();
    let t = x.create_owned_by(g2).unwrap();
    x.group(g2).add(osis::Member::Subgroup(t)).unwrap();
    let nested = t;
    x.commit().unwrap();
    w.run();
    let inner = message(&a, nested, "inner");
    w.run();
    assert_eq!(says(&c, inner), Some(s("inner")));
    a.commit_set(inner, osis::DynamicAspectKey::untyped(text()), &s("inner again")).unwrap();
    w.run();
    assert_eq!(says(&c, inner), Some(s("inner again")));
    // a member's write
    b.commit_set(m1, osis::DynamicAspectKey::untyped(text()), &s("by bob")).unwrap();
    w.run();
    assert_eq!(says(&a, m1), Some(s("by bob")));
    // a profile rename reaches who holds the card
    let p = b.profile().unwrap();
    b.commit_set(p, osis::core::NAME, &"Robert".to_string()).unwrap();
    w.run();
    assert_eq!(a.at(p, osis::core::NAME).get().unwrap().as_deref(), Some("Robert"));
}

// spec: none (API surface, notes/api.md Sync configuration and status): a live node polled by `sync_now` stays Synced, so an app's polling cannot hold `wait_synced` back; a write made meanwhile still goes. It sends nothing but a ping, once a connection is quiet for `retry_ms`
#[test]
fn polling_sync_now_costs_nothing_and_holds_nothing_back() {
    let mut w = World::new();
    let h0 = w.add_host();
    let (a, b, bob) = pair(&mut w, &[h0]);
    let g = chat(&a, &[]);
    let m = message(&a, g, "hello");
    a.grant(g, bob, Role::Write, Default::default()).unwrap();
    w.run();
    assert_eq!(says(&b, m), Some(s("hello")));
    let before = w.traffic(&b);
    for _ in 0..5 {
        b.nudge_sync().unwrap();
        let st = b.status().unwrap();
        assert!(st.groups.values().all(|x| x.state == SyncState::Synced), "{st:?}");
        w.run();
    }
    let after = w.traffic(&b);
    assert_eq!((after.up, after.down), (before.up, before.down), "polling a live node sends nothing");
    // the connection may have died unnoticed (a network change): one ping asks, not one per poll
    w.advance(6000);
    w.run();
    let before = w.traffic(&b);
    b.nudge_sync().unwrap();
    w.run();
    let pinged = w.traffic(&b);
    assert!(pinged.up > before.up, "a quiet connection is pinged");
    assert_eq!((pinged.up - before.up) / 100, 0, "a ping, no Sync");
    b.nudge_sync().unwrap();
    w.run();
    assert_eq!(w.traffic(&b).up, pinged.up, "not again at once");
    let t = message(&b, g, "written while polled");
    b.nudge_sync().unwrap();
    w.run();
    assert_eq!(says(&a, t), Some(s("written while polled")));
    w.until(b.wait_synced(SyncScope::AllWithPeers), 100, 5).unwrap();
}

/// Time to `db` hearing Bob's write on `t` once Bob is back: the redial's pause (`retry_ms`, 5 s) and
/// no more.
fn back_online(w: &mut World, db: &Osis, t: Tid) {
    for _ in 0..6 {
        if says(db, t) == Some(s("by bob")) {
            return;
        }
        w.advance(1000);
        w.run();
    }
}

/// Bob, offline, writes one commit across a thing of `live` and one of `g`.
fn write_across(b: &Osis, u: Tid, m: Tid) {
    let mut x = b.write();
    x.at(u, osis::DynamicAspectKey::untyped(text())).set(&s("by bob")).unwrap();
    x.at(m, osis::DynamicAspectKey::untyped(text())).set(&s("by bob, unsent")).unwrap();
    x.commit().unwrap();
}

// spec/sync.md §6, notes/arbitrary-values-table.md `retry_ms`: a write made offline reaches a peer at the first redial once back, on a thing the group owns and placed only in it
#[test]
fn offline_write_reaches_the_peer_at_the_redial_spec_sync_6() {
    let mut w = World::new();
    let h0 = w.add_host();
    let (a, b, bob) = pair(&mut w, &[h0]);
    let g = chat(&a, &[]);
    a.grant(g, bob, Role::Write, Default::default()).unwrap();
    w.run();
    assert_eq!(b.role_on(g).unwrap(), Some(Role::Write));
    w.set_online(&b, false);
    let t = message(&b, g, "by bob");
    w.advance(30_000);
    w.run();
    assert_eq!(says(&a, t), None);
    w.set_online(&b, true);
    back_online(&mut w, &a, t);
    assert_eq!(says(&a, t), Some(s("by bob")));
}

// spec/commits.md §4 (a node never waits for a part): an unsent commit across a live thing and one of a group its author was removed from: the author cannot place the second delta any more, and the reader shows the first
#[test]
fn write_beside_a_removed_thing_reaches_the_peer_spec_commits_4() {
    let mut w = World::new();
    let h0 = w.add_host();
    let (a, b, bob) = pair(&mut w, &[h0]);
    let g = chat(&a, &[]);
    let m = message(&a, g, "hello");
    a.grant(g, bob, Role::Write, Default::default()).unwrap();
    let live = chat(&a, &[]);
    let u = message(&a, live, "live");
    a.grant(live, bob, Role::Write, Default::default()).unwrap();
    w.run();
    assert_eq!(says(&b, u), Some(s("live")));
    w.set_online(&b, false);
    write_across(&b, u, m);
    w.until(a.set_role(g, bob, None, skip()), 1000, 10).unwrap();
    w.run();
    w.set_online(&b, true);
    w.run();
    back_online(&mut w, &a, u);
    assert_eq!(says(&a, u), Some(s("by bob")), "pending {:?}", a.engine(|e| e.pending()));
    assert_eq!(says(&a, m), Some(s("hello")), "the removed writer's delta does not count");
    assert!(a.engine(|e| e.pending()).is_empty());
}

// spec/commits.md §4: arrival order: a reader holding the live part shows it at once, the rest away, before and after the removal arrives
#[test]
fn live_part_shows_whatever_the_removal_spec_commits_4() {
    let mut w = World::new();
    let h0 = w.add_host();
    let h1 = w.add_host();
    let (a, b, bob) = pair(&mut w, &[h0, h1]);
    let (c, _) = w.person(3, &[h0, h1]);
    w.run();
    let card = c.contact_card().unwrap();
    w.run();
    let carol = w.until(a.import_contact(&card), 1000, 10).unwrap();
    let g = chat(&a, &[w.addr(h1).unwrap()]);
    let m = message(&a, g, "hello");
    let live = chat(&a, &[w.addr(h0).unwrap()]);
    let u = message(&a, live, "live");
    for (t, who) in [(g, bob), (live, bob), (g, carol), (live, carol)] {
        a.grant(t, who, Role::Write, Default::default()).unwrap();
    }
    w.run();
    w.advance(10_000);
    w.run();
    assert_eq!((says(&c, u), says(&c, m)), (Some(s("live")), Some(s("hello"))));
    w.set_reachable(&c, h1, false);
    w.advance(1000);
    w.run();
    w.set_online(&b, false);
    write_across(&b, u, m);
    w.until(a.set_role(g, bob, None, skip()), 1000, 10).unwrap();
    w.run();
    w.set_online(&b, true);
    w.run();
    back_online(&mut w, &a, u);
    assert_eq!(says(&a, u), Some(s("by bob")));
    assert_eq!(says(&c, u), Some(s("by bob")), "the rest away");
    w.set_reachable(&c, h1, true);
    for _ in 0..10 {
        w.advance(1000);
        w.run();
    }
    assert_eq!(says(&c, u), Some(s("by bob")), "pending {:?}", c.engine(|e| e.pending()));
}

// notes/std.md (profile: everyone holding the card keeps receiving changes), spec/permissions.md §3, §8 (Bearer use): an account adding a client or node changes their roles: a contact keeps reading their profile and hears no loss; the link ended, it goes
#[test]
fn contact_outlives_the_persons_role_changes_spec_permissions_8() {
    let mut w = World::new();
    let h0 = w.add_host();
    let store = MemStore::new();
    let at = |w: &World, seed| {
        let mut c = w.cfg(seed, &[h0]);
        c.store = Store::Memory(store.clone());
        c
    };
    let a = osis::internals::create(at(&w, 1)).unwrap().0;
    let (b, _) = w.person(2, &[h0]);
    w.run();
    let card = b.contact_card().unwrap();
    let p = b.profile().unwrap();
    let name = ak("name.0");
    b.commit_set(p, osis::DynamicAspectKey::untyped(name.clone()), &s("Bob")).unwrap();
    w.run();
    let bob = w.until(a.import_contact(&card), 1000, 10).unwrap();
    w.run();
    assert_eq!(a.at(p, osis::DynamicAspectKey::untyped(name.clone())).get().unwrap(), Some(s("Bob")));
    assert_eq!(a.engine(|e| e.core.ix.bearers.len()), 1);
    // what it reads as survives a restart
    assert_eq!(a.close().unwrap(), osis::Close::Closed);
    let a = osis::internals::open(at(&w, 3)).unwrap();
    w.run();
    let (client, _) = b.add_client(None).unwrap();
    b.grant(bob, client, Role::Write, Default::default()).unwrap();
    w.run();
    assert_eq!(a.at(p, osis::DynamicAspectKey::untyped(name.clone())).get().unwrap(), Some(s("Bob")), "{:?}", w.diagnostics(&a));
    assert!(!w.diagnostics(&a).iter().any(|d| d.starts_with("lost access")));
    b.commit_set(p, osis::DynamicAspectKey::untyped(name.clone()), &s("Robert")).unwrap();
    w.run();
    assert_eq!(a.at(p, osis::DynamicAspectKey::untyped(name.clone())).get().unwrap(), Some(s("Robert")));
    let link = b.links_of(p).unwrap().remove(0).id;
    w.until(b.revoke_link(link, SyncFirst::Skip), 1000, 10).unwrap();
    w.run();
    assert_eq!(a.at(p, osis::DynamicAspectKey::untyped(name.clone())).get().unwrap(), None, "the link ended: what it read goes (spec/permissions.md §3)");
    assert!(w.diagnostics(&a).iter().any(|d| d.starts_with("lost access")));
    assert_eq!(a.engine(|e| e.core.ix.bearers.len()), 0, "and its record");
}

// spec/sync.md §3 (entitlement), notes/api.md (`place`): a thing placed in a shared group whose holders may not read it does not reach them: the writer is told, a wait on it fails; `share_into` is not told, an edge follows
#[test]
fn placing_where_holders_may_not_read_is_reported_spec_sync_3() {
    let mut w = World::new();
    let h0 = w.add_host();
    let (a, b, bob) = pair(&mut w, &[h0]);
    let g = chat(&a, &[]);
    a.grant(g, bob, Role::Write, Default::default()).unwrap();
    w.run();
    let told = Arc::new(Mutex::new(Vec::new()));
    let t2 = told.clone();
    let _sub = b.on_diagnostic(move |_, d| t2.lock().unwrap().push(d)).unwrap();
    let mut x = b.write();
    let t = x.create().unwrap();
    x.group(g).add(osis::Member::Item(t)).unwrap();
    x.at(t, osis::DynamicAspectKey::untyped(text())).set(&s("mine")).unwrap();
    let mine = t;
    x.commit().unwrap();
    w.run();
    b.settle();
    assert_eq!(says(&a, mine), None);
    assert!(told.lock().unwrap().iter().any(|d| matches!(d, osis::Diagnostic::NotSynced { thing, .. } if *thing == mine)), "{:?}", told.lock().unwrap());
    let mut x = b.write();
    let t = x.create().unwrap();
    x.at(t, osis::DynamicAspectKey::untyped(text())).set(&s("given")).unwrap();
    let shared = t;
    x.commit().unwrap();
    b.add_with_grant(Member::Item(shared), g, Role::Read).unwrap();
    w.run();
    b.settle();
    assert_eq!(says(&a, shared), Some(s("given")));
    assert!(!told.lock().unwrap().iter().any(|d| matches!(d, osis::Diagnostic::NotSynced { thing, .. } if *thing == shared)), "{:?}", told.lock().unwrap());
}
