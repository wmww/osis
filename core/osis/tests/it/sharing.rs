#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Sharing across nodes in process, commits carried by hand (notes/api.md Sharing and roles).

use osis::internals::Internals as _;
use crate::common;
use common::*;
use osis::{SetRoleOpts, Error, Role};

/// How many commits `db` holds: a call that writes nothing leaves it.
fn commits(db: &osis::Osis) -> usize {
    db.engine(|e| e.commit_ids().len())
}

/// Alice, and Bob whose card she holds (`deliver`): Alice can grant him.
fn alice_knows_bob() -> (osis::Osis, osis::Osis) {
    let (alice, bob) = (db(1), db(2));
    deliver(&bob, &alice);
    (alice, bob)
}

// spec/permissions.md §2, §3 Retain: a timed grant carries what its `until` passing says, the
// thing's default when written unless told; a later default leaves it as written; `set_role`
// moving its role keeps it. `retain_copy` without an `until` is refused.
// spec: spec/permissions.md §3
#[test]
fn a_timed_grant_keeps_the_retain_it_was_written_with_spec_permissions_3() {
    let (alice, bob) = alice_knows_bob();
    let b = bob.author();
    let g = alice.commit_with(|w| w.create_held()).unwrap();
    let until = Some(osis::Time(T0 + 3_600_000));
    let retains = |db: &osis::Osis| db.grants(g).unwrap()[&b].retain_copy;
    alice.set_retain_copies_default(g, true).unwrap();
    alice.grant(g, b, Role::Read, osis::GrantOpts { until, ..Default::default() }).unwrap();
    assert!(retains(&alice), "the default when written");
    alice.set_retain_copies_default(g, false).unwrap();
    assert!(retains(&alice), "a later default changes nothing");
    alice.grant(g, b, Role::Write, osis::GrantOpts { until, ..Default::default() }).unwrap();
    assert!(!retains(&alice), "a new grant takes the default now");
    alice.grant(g, b, Role::Admin, osis::GrantOpts { until, retain_copy: Some(true), ..Default::default() }).unwrap();
    assert!(retains(&alice), "as told");
    alice.set_retain_copies_default(g, false).unwrap();
    alice.set_role(g, b, Some(Role::Read), SetRoleOpts::default()).unwrap();
    assert!(retains(&alice), "lowering keeps it");
    alice.set_role(g, b, Some(Role::Write), SetRoleOpts::default()).unwrap();
    assert!(retains(&alice), "raising keeps it");
    let no_until = osis::GrantOpts { retain_copy: Some(true), ..Default::default() };
    assert!(matches!(alice.grant(g, b, Role::Admin, no_until), Err(Error::Invalid(_))));
}

// notes/api.md Sharing and roles: `grant` adds and raises, never lowers (`Invalid`, nothing
// written); `set_role` to the present role writes nothing, lowers, and with `None` removes,
// after which another removal writes nothing. Observed at the granting node.
// spec: none (API surface, notes/api.md)
#[test]
fn grant_never_lowers_and_set_role_writes_only_changes() {
    let (alice, bob) = alice_knows_bob();
    let b = bob.author();
    let g = alice.commit_with(|w| w.create_held()).unwrap();
    let role = |db: &osis::Osis| db.grants(g).unwrap().get(&b).map(|x| x.role);
    alice.grant(g, b, Role::Write, Default::default()).unwrap();
    let n = commits(&alice);
    assert!(matches!(alice.grant(g, b, Role::Read, Default::default()), Err(Error::Invalid(_))));
    assert_eq!((role(&alice), commits(&alice)), (Some(Role::Write), n), "nothing written");
    alice.set_role(g, b, Some(Role::Write), SetRoleOpts::default()).unwrap();
    assert_eq!(commits(&alice), n, "the same role writes nothing");
    alice.grant(g, b, Role::Admin, Default::default()).unwrap();
    assert_eq!(role(&alice), Some(Role::Admin));
    alice.set_role(g, b, Some(Role::Read), SetRoleOpts::default()).unwrap();
    assert_eq!(role(&alice), Some(Role::Read));
    assert!(matches!(alice.set_role(g, b, Some(Role::Write), SetRoleOpts { retain_copy: Some(true), ..Default::default() }), Err(Error::Invalid(_))), "retain with a role");
    alice.set_role(g, b, None, SetRoleOpts::default()).unwrap();
    assert_eq!(role(&alice), None);
    assert!(!alice.holders(g).unwrap().iter().any(|h| h.thing == b));
    let n = commits(&alice);
    alice.set_role(g, b, None, SetRoleOpts::default()).unwrap();
    assert_eq!(commits(&alice), n, "no role, nothing to remove");
}

// notes/api.md Sharing and roles (`holders`): a holder through an organization is listed with the organization
// between, at the least role along the way, after the organization itself (nearest first); an actor
// with two ways in is listed once per way.
// spec: none (API surface, notes/api.md)
#[test]
fn holders_list_every_way_in_nearest_first() {
    let (alice, bob) = alice_knows_bob();
    let b = bob.author();
    let (g, org) = alice.commit_with(|w| Ok((w.create_held()?, w.create_held()?))).unwrap();
    alice.grant(org, b, Role::Admin, Default::default()).unwrap();
    alice.grant(g, org, Role::Read, Default::default()).unwrap();
    let hs = alice.holders(g).unwrap();
    let pos = |thing, through: &[osis::Tid]| hs.iter().position(|h| h.thing == thing && h.through == through).unwrap_or_else(|| panic!("{hs:?}"));
    assert!(pos(org, &[]) < pos(b, &[org]), "nearest first: {hs:?}");
    assert_eq!(hs[pos(b, &[org])].role, Role::Read, "the least along the way");
    assert_eq!(hs[pos(org, &[])].kind, osis::HolderKind::Thing);
    alice.grant(g, b, Role::Write, Default::default()).unwrap();
    let hs = alice.holders(g).unwrap();
    let ways: Vec<_> = hs.iter().filter(|h| h.thing == b).map(|h| (h.role, h.through.clone())).collect();
    assert_eq!(ways.len(), 2, "{hs:?}");
    assert!(ways.contains(&(Role::Write, vec![])) && ways.contains(&(Role::Read, vec![org])));
}

// notes/api.md Sharing and roles (`leave`): leaving with no way in writes nothing; this node,
// an admin of the target, leaving for another holder is `Invalid` (that is `set_role`'s) and
// writes nothing, a link's join of the same holder included; a holder's own leave ends its role
// at once, and a link it made goes on.
// spec: none (API surface, notes/api.md)
#[test]
fn leave_ends_only_own_ways_and_refuses_before_writing() {
    let (alice, bob) = alice_knows_bob();
    let (g, org) = alice.commit_with(|w| Ok((w.create_held()?, w.create_held()?))).unwrap();
    let n = commits(&alice);
    alice.leave(org, g, SetRoleOpts::default()).unwrap();
    assert_eq!(commits(&alice), n, "no way in: nothing written");
    alice.grant(g, org, Role::Write, Default::default()).unwrap();
    alice.make_link(g, Role::Write, alice.node(), Default::default()).unwrap();
    let k = alice.links_of(g).unwrap()[0].id.thing();
    alice.grant(k, org, Role::Read, Default::default()).unwrap();
    let n = commits(&alice);
    assert!(matches!(alice.leave(org, g, SetRoleOpts::default()), Err(Error::Invalid(_))));
    assert_eq!(commits(&alice), n, "refused before anything is written");
    assert!(alice.grants(k).unwrap().contains_key(&org), "the join of the link stays");
    // bob's own thing, alice a writer of it who makes a link: her leave ends her role only
    deliver(&alice, &bob);
    let t = bob.commit_with(|w| w.create_held()).unwrap();
    bob.grant(t, alice.author(), Role::Admin, Default::default()).unwrap();
    { let mut w = alice.write(); w.hold(alice.node_root().unwrap(), t).unwrap(); w.commit().unwrap(); }
    deliver(&bob, &alice);
    alice.make_link(t, Role::Read, alice.node(), Default::default()).unwrap();
    assert_eq!(alice.role_on(t).unwrap(), Some(Role::Admin));
    // the link's thing has her as its only admin: her leave of it is meant, or refused first
    let k = alice.links_of(t).unwrap()[0].id.thing();
    let n = commits(&alice);
    assert!(matches!(alice.leave(alice.author(), t, SetRoleOpts::default()), Err(Error::LeavesNoAdmin { tid }) if tid == k));
    assert_eq!(commits(&alice), n, "refused before anything is written");
    alice.leave(alice.author(), t, SetRoleOpts { leave_adminless: true, ..Default::default() }).unwrap();
    assert_eq!(alice.role_on(t).unwrap(), None, "no way in is left");
    assert_eq!(alice.links_of(t).unwrap().len(), 1, "a leave ends no link");
}

// spec/permissions.md §6 (a node does not sign a purge request): a purge request that would drop
// none of the held deltas it names is refused `Permission { needs: Admin }` (admins may always
// purge; a writer it refuses holds write), nothing written; under the default
// (admins only) a writer purges none, not even its own; one written `author_or_admin` it purges.
// A superseded write forgotten is an unknown commit (`Invalid`), as one never received.
#[test]
fn purge_without_the_right_is_refused_spec_permissions_6() {
    let (alice, bob) = alice_knows_bob();
    let g = alice.commit_with(|w| w.create_held()).unwrap();
    alice.grant(g, bob.author(), Role::Write, Default::default()).unwrap();
    { let mut w = bob.write(); w.hold(bob.node_root().unwrap(), g).unwrap(); w.commit().unwrap(); }
    let k = || untyped("t:m.0");
    let hers = commit_with(&alice, |w| w.at(g, k()).set(&s("hers"))).stamp.id;
    deliver(&alice, &bob);
    let refused = |what: osis::Purge| {
        let n = commits(&bob);
        let mut x = bob.write();
        x.at(g, k()).purge(what).unwrap();
        matches!(x.commit(), Err(Error::Permission { tid, needs: Role::Admin }) if tid == g) && commits(&bob) == n
    };
    assert!(refused(osis::Purge::Commit(hers)), "another's write by commit");
    assert!(refused(osis::Purge::Author(alice.author())), "another's writes by author");
    let his = commit_with(&bob, |w| w.at(g, k()).set(&s("his, by default"))).stamp.id;
    assert!(refused(osis::Purge::Commit(his)), "his own, under the default");
    let mine = commit_with(&bob, |w| w.at(g, k()).purge_by(osis::PurgeBy::AuthorOrAdmin).set(&s("his"))).stamp.id;
    commit_with(&bob, |w| w.at(g, k()).purge(osis::Purge::Commit(mine)));
    // an admin purges another's write still held
    let again = commit_with(&bob, |w| w.at(g, k()).set(&s("again"))).stamp.id;
    deliver(&bob, &alice);
    commit_with(&alice, |w| w.at(g, k()).purge(osis::Purge::Commit(again)));
    // a write superseded with no history kept is forgotten: its commit is unknown, as one never
    // received (no rights judged)
    let mut x = alice.write();
    x.at(g, k()).purge(osis::Purge::Commit(his)).unwrap();
    let r = x.commit();
    assert!(matches!(&r, Err(Error::Invalid(m)) if m.starts_with("unknown commit")), "{r:?}");
}

// spec/permissions.md §5.1 (Trust set: a node's side is its own), notes/api.md Disputes: two admins
// remove each other, neither having seen the other's removal; a third node takes the side of the
// removal it held first, is told, lists the dispute and can switch; each party stands with
// itself. Either removal may name the dispute (the walk's key order picks which one is open), so
// the sides are read from the one told. A dispute's id reads back from its text; a side of
// another kind is `Invalid`.
#[test]
fn disputes_listed_told_and_chosen_spec_permissions_5_1() {
    let (a, b, c) = (db(1), db(2), db(3));
    deliver(&b, &a);
    deliver(&c, &a);
    let g = a.commit_with(|w| w.create_held()).unwrap();
    a.grant(g, b.author(), Role::Admin, Default::default()).unwrap();
    a.grant(g, c.author(), Role::Read, Default::default()).unwrap();
    deliver(&a, &b);
    deliver(&a, &c);
    // each writes only what it holds
    { let mut w = b.write(); w.hold(b.node_root().unwrap(), g).unwrap(); w.commit().unwrap(); }
    { let mut w = c.write(); w.hold(c.node_root().unwrap(), g).unwrap(); w.commit().unwrap(); }
    b.set_role(g, a.author(), None, SetRoleOpts::default()).unwrap();
    a.set_role(g, b.author(), None, SetRoleOpts::default()).unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    let _sub = c.on_dispute(move |_, d| drop(tx.send(d))).unwrap();
    deliver(&b, &c);
    deliver(&a, &c);
    deliver(&a, &b);
    deliver(&b, &a);
    c.settle();
    let holds = |db: &osis::Osis, x: osis::Tid| db.grants(g).unwrap().contains_key(&x);
    assert!(!holds(&c, a.author()) && holds(&c, b.author()), "b's removal was here first");
    let told = rx.try_iter().last().expect("told");
    let osis::Dispute::Removal { author, holder, side, chosen, .. } = told.clone();
    assert!((author, holder) == (a.author(), b.author()) || (author, holder) == (b.author(), a.author()), "one of the two removals: {told:?}");
    // the side a stands on: the author's of a's removal, the holder's of b's
    let (a_side, b_side) = if author == a.author() { (osis::Side::Author, osis::Side::Holder) } else { (osis::Side::Holder, osis::Side::Author) };
    assert_eq!((side, chosen), (b_side, false), "b's side, by the removal held first");
    assert_eq!(c.disputes().unwrap(), (vec![told.clone()], 0));
    let id: osis::DisputeId = told.id().to_string().parse().unwrap();
    assert_eq!(id, told.id());
    c.choose_side(id, a_side).unwrap();
    assert!(holds(&c, a.author()) && !holds(&c, b.author()), "a's side: b's removal of a does not count, a's of b does");
    let (ds, _) = c.disputes().unwrap();
    assert_eq!((ds[0].side(), ds[0].chosen()), (a_side, true));
    c.choose_side(id, b_side).unwrap();
    assert!(!holds(&c, a.author()) && holds(&c, b.author()));
    assert!(holds(&a, a.author()) && !holds(&a, b.author()), "each party stands with itself");
    assert!(holds(&b, b.author()) && !holds(&b, a.author()));
}

// A write is never refused or split for its paths (notes/path-form.md; spec/wire.md §4 `Split`): one `Write` changing things its
// signer reaches through different actors is one commit, never refused or split: Bob writes G,
// which he reaches through organization H, and his own thing O, and makes a thing under G. Carol, who reads
// both G and O, and Alice, who reads G alone, each read what that commit wrote on what they read.
#[test]
fn the_owners_rule_one_write_through_different_actors_is_one_commit_spec_wire_4() {
    let (alice, bob, carol) = (db(1), db(2), db(3));
    let all = [&alice, &bob, &carol];
    mesh(&all);
    let (g, h) = alice.commit_with(|w| Ok((w.create_held()?, w.create_held()?))).unwrap();
    alice.grant(h, bob.author(), Role::Write, Default::default()).unwrap();
    alice.grant(g, h, Role::Write, Default::default()).unwrap();
    alice.grant(g, carol.author(), Role::Read, Default::default()).unwrap();
    let o = bob.commit_with(|w| w.create_held()).unwrap();
    bob.grant(o, carol.author(), Role::Read, Default::default()).unwrap();
    mesh(&all);
    // Bob holds what he writes (spec/sync-set.md §2 Writing): H, which he acts through, and G
    { let mut w = bob.write(); w.hold(bob.node_root().unwrap(), h).unwrap(); w.commit().unwrap(); }
    { let mut w = bob.write(); w.hold(bob.node_root().unwrap(), g).unwrap(); w.commit().unwrap(); }
    { let mut w = carol.write(); w.hold(carol.node_root().unwrap(), g).unwrap(); w.commit().unwrap(); }
    { let mut w = carol.write(); w.hold(carol.node_root().unwrap(), o).unwrap(); w.commit().unwrap(); }
    mesh(&all);
    let k = || untyped("t:x.0");
    let before: std::collections::BTreeSet<_> = bob.engine(|e| e.commit_ids()).into_iter().collect();
    let mut w = bob.write();
    w.at(g, k()).set(&s("on g")).unwrap();
    w.at(o, k()).set(&s("on o")).unwrap();
    let x = w.create_held_with_admin(g).unwrap();
    w.at(x, k()).set(&s("of g")).unwrap();
    w.commit().unwrap().unwrap();
    // the write's commits: a role commit after it is a duty it made due (G, minting X, now holds
    // admin for keys, so a KEM key is due on G: spec/crypto.md §3), no part of the write
    let new: Vec<_> = bob.engine(|e| e.commit_ids()).into_iter().filter(|id| !before.contains(id) && !bob.engine(|e| e.header(id)).is_some_and(|h| h.kind.is_role())).collect();
    assert_eq!(new.len(), 1, "one commit");
    assert!(bob.engine(|e| e.header(&new[0]).unwrap().is_split()), "each thing its own path");
    mesh(&all);
    for (who, db) in [("carol", &carol), ("alice", &alice)] {
        assert_eq!(db.at(g, k()).get().unwrap(), Some(s("on g")), "{who} reads G");
        assert_eq!(db.at(x, k()).get().unwrap(), Some(s("of g")), "{who} reads the thing minted with admin G");
    }
    assert_eq!(carol.at(o, k()).get().unwrap(), Some(s("on o")), "carol reads O");
    assert_eq!(alice.at(o, k()).get().unwrap(), None, "alice reads no O");
}

/// Carries every node's commits to every other, then settles each.
fn mesh(dbs: &[&osis::Osis]) {
    for (i, from) in dbs.iter().enumerate() {
        for (j, to) in dbs.iter().enumerate() {
            if i != j {
                deliver(from, to);
            }
        }
    }
    for d in dbs {
        d.settle();
    }
}

// spec/requirements.md Permissions (a role M holds on G never depends on who is in M),
// spec/crypto.md §4 (Carried demotions): Carol reads G, which organization M (Bob's, Alice a reader of it
// too) writes; Bob removes Erin, a writer of M. Carol's node holds the removal with M's new keyset
// (it is how G's writers count Erin out), but it shows her no roster of M, before or after: only
// G's, and M's to Bob. Once Carol reads M her watch on M's grants hears its roster, and hears it
// hidden once she reads it no more.
#[test]
fn a_parents_reader_sees_no_roster_of_its_member_org_spec_crypto_4() {
    let (alice, bob, carol, erin) = (db(1), db(2), db(3), db(4));
    let all = [&alice, &bob, &carol, &erin];
    mesh(&all);
    let m = bob.commit_with(|w| w.create_held()).unwrap();
    // M a writer of something, so a holder whose keysets up to write carry KEM keys (spec/crypto.md
    // §3): alice, no writer of M, may grant it
    let o = bob.commit_with(|w| w.create_held()).unwrap();
    bob.grant(o, m, Role::Write, Default::default()).unwrap();
    bob.grant(m, erin.author(), Role::Write, Default::default()).unwrap();
    bob.grant(m, alice.author(), Role::Read, Default::default()).unwrap();
    mesh(&all);
    // alice holds the organization she reads
    { let mut w = alice.write(); w.hold(alice.node_root().unwrap(), m).unwrap(); w.commit().unwrap(); }
    mesh(&all);
    let g = alice.commit_with(|w| w.create_held()).unwrap();
    alice.grant(g, m, Role::Write, Default::default()).unwrap();
    alice.grant(g, carol.author(), Role::Read, Default::default()).unwrap();
    mesh(&all);
    { let mut w = carol.write(); w.hold(carol.node_root().unwrap(), g).unwrap(); w.commit().unwrap(); }
    mesh(&all);
    assert!(carol.grants(g).unwrap().contains_key(&m), "G's roster shows to its reader");
    assert!(carol.grants(m).unwrap().is_empty(), "no roster of M");
    bob.set_role(m, erin.author(), None, SetRoleOpts::default()).unwrap();
    mesh(&all);
    assert!(!bob.grants(m).unwrap().contains_key(&erin.author()), "Erin left M");
    assert!(carol.grants(m).unwrap().is_empty(), "no roster of M once Erin left");
    assert!(carol.holders(g).unwrap().iter().all(|h| h.thing != erin.author()), "nor through G's holders");
    // once Carol reads M (a roster change on M's way in, not on M's), her watch on M's grants
    // hears its roster
    let t = bob.commit_with(|w| w.create_held()).unwrap();
    bob.grant(m, t, Role::Read, Default::default()).unwrap();
    mesh(&all);
    let heard = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let h = heard.clone();
    let _sub = carol.on_grants_change(m, move |_, r| h.lock().unwrap().push(r.unwrap())).unwrap();
    bob.grant(t, carol.author(), Role::Read, Default::default()).unwrap();
    mesh(&all);
    assert_eq!(carol.role_on(m).unwrap(), Some(Role::Read), "Carol reads M through T");
    assert!(carol.grants(m).unwrap().contains_key(&t), "M's roster shows to its reader");
    assert!(heard.lock().unwrap().last().is_some_and(|g| g.contains_key(&t)), "her watch heard it: {:?}", heard.lock().unwrap());
    // and once she no longer reads M (T's roster changed, M's not), it hears the roster hidden
    bob.set_role(t, carol.author(), None, SetRoleOpts::default()).unwrap();
    mesh(&all);
    assert_eq!(carol.role_on(m).unwrap(), None, "Carol left T");
    assert!(carol.grants(m).unwrap().is_empty(), "no roster of M");
    assert!(heard.lock().unwrap().last().is_some_and(|g| g.is_empty()), "her watch heard it hidden: {:?}", heard.lock().unwrap());
}

// spec/permissions.md §1 (The last admin), notes/api.md Sharing and roles: the last admin's
// removal, lowering, leave or `until` is `LeavesNoAdmin`, naming the thing, and changes nothing;
// the same call with `leave_adminless` goes through, and the thing then has no admin.
#[test]
fn the_last_admin_is_refused_unless_meant_spec_perm_1() {
    let alice = db(1);
    let mut w = alice.write();
    let t = w.create_held().unwrap();
    w.commit().unwrap();
    // the thing's one admin: the account it was minted with
    let me = crate::common::home(&alice);
    let no_admin = |r: osis::Result<()>| matches!(r, Err(Error::LeavesNoAdmin { tid }) if tid == t);
    assert!(no_admin(alice.set_role(t, me, None, SetRoleOpts::default())), "a removal");
    assert!(no_admin(alice.set_role(t, me, Some(Role::Write), SetRoleOpts::default())), "a lowering");
    assert!(no_admin(alice.leave(me, t, SetRoleOpts::default())), "a leave");
    let until = osis::GrantOpts { until: Some(osis::Time(T0 + 60_000)), ..Default::default() };
    assert!(no_admin(alice.grant(t, me, Role::Admin, until)), "an until");
    assert_eq!(alice.role_on(t).unwrap(), Some(Role::Admin), "nothing changed");
    alice.leave(me, t, SetRoleOpts { leave_adminless: true, ..Default::default() }).unwrap();
    assert_eq!(alice.role_on(t).unwrap(), None);
    assert!(alice.grants(t).unwrap().values().all(|g| g.role != Role::Admin), "no admin");
}
