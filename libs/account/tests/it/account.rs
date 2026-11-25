use crate::{clock, drive, opening, pair, person};
use osis::internals::ManualNet;
use osis::{Error, GrantOpts, Osis, Role, SetRoleOpts, SyncScope, Tid, Weak};
use osis_account::schema::OF;
use osis_account::{Account, AccountNode};

/// `t`'s dial list keys at `db` (spec/sync-set.md §1).
fn dials(db: &Osis, t: Tid) -> Vec<Vec<u8>> {
    use osis::internals::Internals as _;
    db.engine(|e| e.get_typed(&t, &osis::internals::core_types::DIAL).unwrap()).unwrap_or_default().into_keys().collect()
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
// its settings and dial entry on it; its profile names it and carries the entry too; a node
// makes one account at most, and a node that made none acts for none.
#[test]
fn making_an_account_spec_permissions_8() {
    let c = clock();
    let net = ManualNet::new(c.clone());
    let (db, a, _) = person(&net, 1, &c);
    assert_eq!(Account::of(&db).unwrap(), Some(a));
    assert_ne!(a.thing(), db.node(), "the account is not the node");
    assert_eq!(db.settings_thing().unwrap(), Some(a.thing()));
    assert_eq!(a.nodes(&db).unwrap(), [AccountNode { node: db.node(), role: Role::Admin }]);
    let p = a.profile(&db).unwrap().expect("a profile");
    assert_eq!(db.at(p, OF).get().unwrap(), Some(Weak(a.thing())));
    let key = dials(&db, a.thing());
    assert_eq!(key.len(), 1, "its entry on the account");
    assert_eq!(dials(&db, p), key, "and on the profile");
    assert!(matches!(Account::make(&db), Err(Error::Invalid(_))), "one account per node");
    let bare = osis::internals::create(opening(&net, 2, &c, Vec::new())).unwrap();
    assert_eq!(Account::of(&bare).unwrap(), None);
}

// spec/permissions.md §8 Pairing and Removing: a paired node acts for the account, both are its
// admin nodes, what one makes for the account reaches the other both ways; a removed node is its
// node no more, its dial entries gone. An offer past its 10 minutes, or a request to another
// offer, pairs nothing.
#[test]
fn pairing_and_removing_a_node_spec_permissions_8() {
    let c = clock();
    let net = ManualNet::new(c.clone());
    let first = person(&net, 1, &c);
    let (db, a, _) = &first;
    let b = pair(&net, &first, 2, &c);
    assert_eq!(Account::of(&b).unwrap(), Some(*a));
    let mut nodes = a.nodes(db).unwrap();
    nodes.sort_by_key(|n| n.node);
    let mut want = vec![AccountNode { node: db.node(), role: Role::Admin }, AccountNode { node: b.node(), role: Role::Admin }];
    want.sort_by_key(|n| n.node);
    assert_eq!(nodes, want);
    let t = make(db, a, "from the first");
    drive(&net, db.wait_synced(SyncScope::All)).unwrap();
    drive(&net, b.wait_synced(SyncScope::All)).unwrap();
    assert_eq!(b.at(t, osis::core::NAME).get().unwrap().as_deref(), Some("from the first"));
    let u = make(&b, a, "from the second");
    drive(&net, b.wait_synced(SyncScope::All)).unwrap();
    drive(&net, db.wait_synced(SyncScope::All)).unwrap();
    assert_eq!(db.at(u, osis::core::NAME).get().unwrap().as_deref(), Some("from the second"));
    assert_eq!(dials(db, a.thing()).len(), 2, "each node's entry");
    // an offer pairs once, within its time, only the node that took it
    let o = opening(&net, 3, &c, Vec::new());
    let stale = a.offer_pairing(db).unwrap();
    let join = osis_account::pair(o.store, stale.offer(), o.cfg).unwrap();
    c.advance(10 * 60_000);
    assert!(matches!(stale.accept(db, join.request()), Err(Error::Invalid(_))), "past its time");
    let other = a.offer_pairing(db).unwrap();
    assert!(matches!(other.accept(db, join.request()), Err(Error::Invalid(_))), "another offer's request");
    // removing
    assert_eq!(a.remove_node(db, b.node(), SetRoleOpts::default()).unwrap(), []);
    assert_eq!(a.nodes(db).unwrap(), [AccountNode { node: db.node(), role: Role::Admin }]);
    assert_eq!(dials(db, a.thing()).len(), 1, "the removed node's entry gone");
    assert_eq!(a.remove_node(db, b.node(), SetRoleOpts::default()).unwrap(), [], "no node of the account: nothing to do");
}

// spec/sync-inbox.md §5 (contact card), spec/sync-set.md §4: a card is made once per account;
// importing it gives its account, whose keys are then here (a grant to it goes through), and
// records its profile.
#[test]
fn importing_a_card_gives_the_account_spec_sync_inbox_5() {
    let c = clock();
    let net = ManualNet::new(c.clone());
    let (alice, aa, _) = person(&net, 1, &c);
    let (bob, ba, _) = person(&net, 2, &c);
    let card = aa.contact_card(&alice).unwrap();
    assert_eq!(aa.contact_card(&alice).unwrap(), card, "made once");
    let who = drive(&net, ba.import_contact(&bob, &card)).unwrap();
    assert_eq!(who, aa.thing());
    assert_eq!(ba.profile_of(&bob, who).unwrap(), aa.profile(&alice).unwrap());
    let t = make(&bob, &ba, "for alice");
    bob.grant(t, who, Role::Read, GrantOpts::default()).unwrap();
    assert!(bob.grants(t).unwrap().contains_key(&who));
}
