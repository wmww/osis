use crate::{clock, drive, opening, paired, person};
use osis::internals::ManualNet;
use osis::{Error, GrantOpts, Osis, Role, SetRoleOpts, SyncScope, Tid, Weak};
use osis_account::schema::{OF, REALM};
use osis_account::{Account, AccountNode, Realm};

/// The nodes with a dial entry on `t` at `db` (spec/sync-set.md §1).
fn dials(db: &Osis, t: Tid) -> Vec<Weak> {
    db.at(t, osis::core::DIAL).get().unwrap().unwrap_or_default().into_keys().collect()
}

/// A thing minted with the account as admin and held from its `holds.0`, named `name`.
fn make(db: &Osis, a: &Account, name: &str) -> Tid {
    let mut w = db.write();
    let t = w.create(a.thing(), None).unwrap();
    w.hold(a.thing(), t).unwrap();
    w.at(t, osis::core::NAME).set(&name.to_string()).unwrap();
    w.commit().unwrap();
    t
}

// spec/permissions.md §8 Making: the account is a thing of its own, the node its admin, keeping
// its settings and dial entry on it; its profile names it, carries the entry too and is public; a
// node makes one account at most, and a node that made none acts for none.
#[test]
fn making_an_account_spec_permissions_8() {
    let c = clock();
    let net = ManualNet::new(c.clone());
    let (db, a, _) = person(&net, 1, &c);
    assert_eq!(Account::of(&db).unwrap(), Some(a));
    assert_ne!(a.thing(), db.node(), "the account is not the node");
    assert_eq!(db.settings_thing().unwrap(), Some(a.thing()));
    assert_eq!(a.nodes(&db).unwrap(), [AccountNode { node: db.node(), role: Role::Admin }]);
    let p = a.realm().profile(&db).unwrap().expect("a profile");
    assert_eq!(db.at(p, OF).get().unwrap(), Some(Weak(a.thing())));
    assert_eq!(db.grants(p).unwrap().get(&Tid::PUBLIC).map(|g| g.role), Some(Role::Read), "the profile is public");
    let key = dials(&db, a.thing());
    assert_eq!(key.len(), 1, "its entry on the account");
    assert_eq!(dials(&db, p), key, "and on the profile");
    assert!(matches!(Account::make(&db), Err(Error::Invalid(_))), "one account per node");
    // its other holders of write are no nodes of it: a realm, a client's thing
    let r = Realm::make(&db, a.realm(), "a realm").unwrap();
    let (client, _) = db.add_client(a.thing(), None).unwrap();
    for h in [r.thing(), client] {
        db.grant(a.thing(), h, Role::Write, GrantOpts::default()).unwrap();
    }
    assert_eq!(a.nodes(&db).unwrap(), [AccountNode { node: db.node(), role: Role::Admin }], "the node alone");
    let bare = osis::internals::create(opening(&net, 2, &c, Vec::new())).unwrap();
    assert_eq!(Account::of(&bare).unwrap(), None);
}

// spec/permissions.md §8 Pairing and Removing: a paired node, configured to dial nothing, reaches
// the pairer by the offer's dial hints; it acts for the account, both are its admin nodes, what one
// makes for the account reaches the other both ways; a removed node is its node no more, its dial
// entries gone. A request to another offer pairs nothing.
#[test]
fn pairing_and_removing_a_node_spec_permissions_8() {
    let (net, c, first, b) = paired();
    let (db, a, _) = &first;
    assert_eq!(Account::of(&b).unwrap(), Some(*a));
    let mut nodes = a.nodes(db).unwrap();
    nodes.sort_by_key(|n| n.node);
    let mut want = vec![AccountNode { node: db.node(), role: Role::Admin }, AccountNode { node: b.node(), role: Role::Admin }];
    want.sort_by_key(|n| n.node);
    assert_eq!(nodes, want);
    let mut there = a.nodes(&b).unwrap();
    there.sort_by_key(|n| n.node);
    assert_eq!(there, want, "alike at the paired node");
    let t = make(db, a, "from the first");
    drive(&net, db.wait_synced(SyncScope::All)).unwrap();
    drive(&net, b.wait_synced(SyncScope::All)).unwrap();
    assert_eq!(b.at(t, osis::core::NAME).get().unwrap().as_deref(), Some("from the first"));
    let u = make(&b, a, "from the second");
    drive(&net, b.wait_synced(SyncScope::All)).unwrap();
    drive(&net, db.wait_synced(SyncScope::All)).unwrap();
    assert_eq!(db.at(u, osis::core::NAME).get().unwrap().as_deref(), Some("from the second"));
    assert_eq!(dials(db, a.thing()).len(), 2, "each node's entry");
    // an offer pairs only the node that took it
    let o = opening(&net, 3, &c, Vec::new());
    let first = a.offer_pairing(db).unwrap();
    let join = osis_account::pair(o.store, first.offer(), o.cfg).unwrap();
    let other = a.offer_pairing(db).unwrap();
    assert!(matches!(other.accept(db, join.request()), Err(Error::Invalid(_))), "another offer's request");
    // removing
    assert_eq!(a.remove_node(db, b.node(), SetRoleOpts::default()).unwrap(), []);
    assert_eq!(a.nodes(db).unwrap(), [AccountNode { node: db.node(), role: Role::Admin }]);
    assert_eq!(dials(db, a.thing()).len(), 1, "the removed node's entry gone");
    assert_eq!(a.remove_node(db, b.node(), SetRoleOpts::default()).unwrap(), [], "no node of the account: nothing to do");
}

// spec/sync-inbox.md §5 (contact card), spec/sync-set.md §4: a contact card is a public link to the
// profile; a stranger importing it reads the profile, gets its account, whose keys are then here
// (a grant to it goes through), and records the profile.
#[test]
fn a_stranger_importing_a_card_grants_its_account_spec_sync_inbox_5() {
    let c = clock();
    let net = ManualNet::new(c.clone());
    let (alice, aa, _) = person(&net, 1, &c);
    let (bob, ba, _) = person(&net, 2, &c);
    let p = aa.realm().profile(&alice).unwrap().unwrap();
    let mut w = alice.write();
    w.at(p, osis::core::NAME).set(&"Alice".to_string()).unwrap();
    w.commit().unwrap();
    let card = aa.realm().contact_card(&alice).unwrap();
    let who = drive(&net, ba.realm().import_contact(&bob, &card)).unwrap();
    assert_eq!(who, aa.thing());
    assert_eq!(ba.realm().profile_of(&bob, who).unwrap(), Some(p));
    assert_eq!(bob.at(p, osis::core::NAME).get().unwrap().as_deref(), Some("Alice"), "the profile read");
    let t = make(&bob, &ba, "for alice");
    bob.grant(t, who, Role::Read, GrantOpts::default()).unwrap();
    assert!(bob.grants(t).unwrap().contains_key(&who));
}

// spec/permissions.md §7, §8 Making: a link made with the account as admin is the account's:
// another node of it lists and ends it, and a node leaving its own grant on the target leaves
// the link to the account, which stays its admin.
#[test]
fn links_are_the_accounts_spec_permissions_7() {
    let (net, _, first, b) = paired();
    let (db, a, _) = &first;
    let t = make(db, a, "linked");
    db.grant(t, db.node(), Role::Admin, GrantOpts::default()).unwrap();
    db.make_link(t, Role::Read, a.thing(), osis::LinkOpts::default()).unwrap();
    let id = db.links().unwrap()[0].id;
    db.leave(db.node(), t, SetRoleOpts::default()).unwrap();
    assert_eq!(db.links().unwrap().len(), 1, "the account's link stays");
    // the link's thing waits for its key's holder: the account alone is waited on
    let account = SyncScope::Thing(a.thing());
    drive(&net, db.wait_synced(account)).unwrap();
    drive(&net, b.wait_synced(account)).unwrap();
    assert_eq!(b.links().unwrap().iter().map(|l| l.id).collect::<Vec<_>>(), [id], "listed on the other node");
    b.revoke_link(id).unwrap();
    assert!(b.links().unwrap().is_empty());
}

// notes/realms.md: an account is a realm, and a realm made in it is marked and named, held from
// the account, administered through it, and keeps a removed member's copy by default.
#[test]
fn a_realm_made_in_the_account() {
    let c = clock();
    let net = ManualNet::new(c.clone());
    let (db, a, _) = person(&net, 1, &c);
    assert!(db.at(a.thing(), REALM).get().unwrap().is_some(), "the account is a realm");
    let r = Realm::make(&db, a.realm(), "Climbing").unwrap().thing();
    assert!(db.at(r, REALM).get().unwrap().is_some());
    assert_eq!(db.at(r, osis::core::NAME).get().unwrap().as_deref(), Some("Climbing"));
    assert!(db.holds(a.thing(), r).unwrap());
    assert_eq!(db.role_on(r).unwrap(), Some(Role::Admin), "through the account");
    assert!(db.at(r, osis::core::RETENTION).get().unwrap().unwrap().retain_copies);
}

// spec/permissions.md §8 Removing: a node removing itself drops its own dial entries while it may
// still write the account, then its role (retaining a copy, read here).
#[test]
fn a_node_removing_itself_drops_its_entries_spec_permissions_8() {
    let (net, _, first, b) = paired();
    let (db, a, _) = &first;
    drive(&net, b.wait_synced(SyncScope::All)).unwrap();
    assert_eq!(dials(&b, a.thing()).len(), 2, "each node's entry");
    a.remove_node(&b, b.node(), SetRoleOpts { retain_copy: Some(true), ..SetRoleOpts::default() }).unwrap();
    assert!(!b.grants(a.thing()).unwrap().contains_key(&b.node()), "its role gone");
    assert_eq!(dials(&b, a.thing()), [Weak(db.node())], "its entry gone");
}

// spec/permissions.md §8 Removing, notes/client-port.md §3: a client's thing is the account's
// (`add_client` with the account as admin), so a removed node no longer acts for the account
// through its client: what it writes as the client after the removal holds at no other node.
// Minting the thing writes its keys and steps, so naming the account takes administering it: a
// node lowered to writing the account is told so up front (`Permission` on the account).
#[test]
fn a_removed_node_no_longer_acts_through_its_client_spec_permissions_8() {
    let (net, _, first, b) = paired();
    let (db, a, _) = &first;
    let t = make(&b, a, "before");
    let (client, _) = b.add_client(a.thing(), None).unwrap();
    b.grant(t, client, Role::Write, GrantOpts::default()).unwrap();
    let mut w = b.write();
    w.act_as(client).at(t, osis::core::NAME).set(&"by the client".to_string()).unwrap();
    w.commit().unwrap();
    drive(&net, b.wait_synced(SyncScope::All)).unwrap();
    drive(&net, db.wait_synced(SyncScope::All)).unwrap();
    assert_eq!(db.at(t, osis::core::NAME).get().unwrap().as_deref(), Some("by the client"));
    db.set_role(a.thing(), b.node(), Some(Role::Write), SetRoleOpts::default()).unwrap();
    drive(&net, db.wait_synced(SyncScope::All)).unwrap();
    drive(&net, b.wait_synced(SyncScope::All)).unwrap();
    let r = b.add_client(a.thing(), None);
    assert!(matches!(r, Err(Error::Permission { tid, needs: Role::Admin }) if tid == a.thing()), "{r:?}");
    assert_eq!(b.clients().unwrap().len(), 1, "no new entry");
    a.remove_node(db, b.node(), SetRoleOpts { retain_copy: Some(true), ..SetRoleOpts::default() }).unwrap();
    let mut w = b.write();
    w.act_as(client).at(t, osis::core::NAME).set(&"after removal".to_string()).unwrap();
    let _ = w.commit();
    // one run takes the write to db where the node administers the thing
    for _ in 0..2 {
        net.run();
    }
    assert_eq!(db.at(t, osis::core::NAME).get().unwrap().as_deref(), Some("by the client"), "the removed node's write as the client holds nowhere else");
}

// spec/permissions.md §8 Removing: a node acts for the account its node thing holds a grant on;
// removed (erasing), it acts for none, at a client of it alike, live and after a restart, and it
// makes an account of its own.
#[test]
fn a_removed_node_acts_for_no_account_spec_permissions_8() {
    let c = clock();
    let net = ManualNet::new(c.clone());
    let first = person(&net, 1, &c);
    let (db, a, _) = &first;
    let o = opening(&net, 2, &c, Vec::new());
    let store = o.store.clone();
    let offering = a.offer_pairing(db).unwrap();
    let join = osis_account::pair(o.store, offering.offer(), o.cfg.clone()).unwrap();
    let (_, reply) = offering.accept(db, join.request()).unwrap();
    let (b, _) = join.finish(&reply).unwrap();
    drive(&net, b.wait_synced(SyncScope::All)).unwrap();
    // a client of b's (its thing b's node thing's, so it outlives the removal) reads as b
    let (_, secret) = b.add_client(b.node(), None).unwrap();
    let client = |net: &ManualNet, b: &Osis| {
        let addr = b.listen(&["peer://127.0.0.1:1".parse().unwrap()]).unwrap().remove(0);
        let mut app = osis::AppConfig::default();
        app.internals.net = Some(net.clone());
        app.internals.clock = Some(c.clone());
        drive(net, Osis::connect(&[osis::NodeLogin { addr, secret: secret.clone() }], app)).unwrap()
    };
    let cl = client(&net, &b);
    assert_eq!(Account::of(&b).unwrap(), Some(*a));
    assert_eq!(Account::of(&cl).unwrap(), Some(*a), "at its client");
    a.remove_node(db, b.node(), SetRoleOpts::default()).unwrap();
    // b learns its removal from db (neither waits on A synced: it is b's no more)
    net.run();
    assert_eq!(Account::of(&b).unwrap(), None, "removed");
    assert_eq!(Account::of(&cl).unwrap(), None, "at its client");
    assert!(matches!(cl.close().unwrap(), osis::Close::Closed));
    assert!(matches!(b.close().unwrap(), osis::Close::Closed), "closed for the restart");
    // reopened on a net of its own: the closed node's place on `net` keeps its key
    let net = ManualNet::new(c.clone());
    let mut o = opening(&net, 2, &c, Vec::new());
    o.store = store;
    let b = osis::internals::open(o).unwrap();
    assert_eq!(Account::of(&b).unwrap(), None, "after a restart");
    assert_eq!(Account::of(&client(&net, &b)).unwrap(), None, "at its client after a restart");
    let mine = Account::make(&b).unwrap();
    assert_ne!(mine, *a);
    assert_eq!(Account::of(&b).unwrap(), Some(mine));
    assert_eq!(mine.nodes(&b).unwrap(), [AccountNode { node: b.node(), role: Role::Admin }]);
}

// spec/permissions.md §8: a node acts for the account while its node thing's grant on it gives
// write or admin, as `nodes` counts it: from pairing on (before it syncs), until a timed grant's
// `until` passes, or until it is lowered to read.
#[test]
fn a_node_acts_for_the_account_while_it_may_write_spec_permissions_8() {
    let c = clock();
    let net = ManualNet::new(c.clone());
    let first = person(&net, 1, &c);
    let (db, a, _) = &first;
    let o = opening(&net, 2, &c, Vec::new());
    let offering = a.offer_pairing(db).unwrap();
    let join = osis_account::pair(o.store, offering.offer(), o.cfg).unwrap();
    let (_, reply) = offering.accept(db, join.request()).unwrap();
    let (b, _) = join.finish(&reply).unwrap();
    assert_eq!(Account::of(&b).unwrap(), Some(*a), "paired, before it syncs");
    drive(&net, b.wait_synced(SyncScope::All)).unwrap();
    // far beyond what the syncs below run the clock on
    let until = osis::Time(db.now().unwrap().0 + 30 * 86_400_000);
    db.grant(a.thing(), b.node(), Role::Admin, GrantOpts { until: Some(until), retain_copy: Some(true), ..Default::default() }).unwrap();
    net.run();
    drive(&net, b.wait_synced(SyncScope::All)).unwrap();
    assert_eq!(b.grants(a.thing()).unwrap().get(&b.node()).and_then(|g| g.until), Some(until), "b holds the timed grant");
    assert_eq!(Account::of(&b).unwrap(), Some(*a), "before its end");
    net.advance(until.0 - b.now().unwrap().0);
    assert_eq!(Account::of(&b).unwrap(), None, "its end passed, nothing written");
    assert_eq!(a.nodes(db).unwrap(), [AccountNode { node: db.node(), role: Role::Admin }]);

    let c = clock();
    let net = ManualNet::new(c.clone());
    let first = person(&net, 1, &c);
    let (db, a, _) = &first;
    let b = crate::pair(&net, &first, 2, &c);
    db.set_role(a.thing(), b.node(), Some(Role::Read), SetRoleOpts::default()).unwrap();
    net.run();
    drive(&net, b.wait_synced(SyncScope::All)).unwrap();
    assert_eq!(b.grants(a.thing()).unwrap().get(&b.node()).map(|g| g.role), Some(Role::Read), "b reads A still");
    assert_eq!(Account::of(&b).unwrap(), None, "lowered to read");
    assert_eq!(a.nodes(db).unwrap(), [AccountNode { node: db.node(), role: Role::Admin }], "not one of A's nodes");
    let mine = Account::make(&b).unwrap();
    assert_eq!(Account::of(&b).unwrap(), Some(mine));
}
