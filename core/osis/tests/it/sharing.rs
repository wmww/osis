#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Sharing across nodes in process, commits carried by hand (notes/api.md Sharing and roles).

use osis::internals::Internals as _;
use crate::common;
use common::*;
use osis::{SetRoleOpts, Error, Role, Value};

fn s(x: &str) -> Value {
    Value::Str(x.into())
}

// spec/crypto.md §7 (Header list): a writer lists the thing's delete keys, notes/api.md Rights: a role whose
// delete keys are not here yet (no inbox hint, the thing's `keys.0` in a later batch: another node
// of the grantee's account, a group's grant learned from its certificate copy) reads as `Read`
// and a content write on it is `Permission`, until the keys come; then both say the role. An
// admin's calls are `Permission { needs: Admin }` meanwhile alike, by the same rule.
#[test]
fn role_before_delete_keys_reads_as_read_spec_crypto_7() {
    for role in [Role::Write, Role::Admin] {
        let (alice, bob, carol, dave) = (db(1), db(2), db(3), db(4));
        deliver(&bob, &alice);
        deliver(&carol, &alice);
        deliver(&dave, &bob);
        let mut w = alice.write();
        let t = w.create().unwrap();
        w.at(t, osis::DynamicAspectKey::untyped(ak("t:x.0"))).set(&s("one")).unwrap();
        w.commit().unwrap();
        // the first holder gives `t` secrets of its own: its `keys.0` goes in that commit
        alice.grant(t, carol.me(), Role::Read, Default::default()).unwrap();
        alice.grant(t, bob.me(), role, Default::default()).unwrap();
        // (a grant's `keys.0` part records its boxes: the keyset is the rotation's)
        let (later, now): (Vec<_>, Vec<_>) = alice.engine(|e| {
            e.commit_ids().into_iter().map(|id| (e.writes_keyset(&t, &id), e.package(&id).unwrap().unwrap())).partition(|(k, _)| *k)
        });
        assert_eq!(later.len(), 1, "one commit carries t's keysets");
        for (_, pk) in &now {
            bob.engine(|e| e.ingest(&pk.bytes, pk.blobs.clone()).unwrap());
        }
        let write = |v: &str| {
            let mut w = bob.write();
            w.at(t, osis::DynamicAspectKey::untyped(ak("t:x.0"))).set(&s(v))?;
            w.commit().map(drop)
        };
        assert_eq!(bob.engine(|e| e.role_on(&t)), Some(role), "the grant is here");
        assert_eq!(bob.role_on(t).unwrap(), Some(Role::Read));
        assert!(matches!(write("two"), Err(Error::Permission { tid, needs: Role::Write }) if tid == t));
        let grant = || bob.grant(t, dave.me(), Role::Read, Default::default());
        if role == Role::Admin {
            let r = grant();
            assert!(matches!(r, Err(Error::Permission { tid, needs: Role::Admin }) if tid == t), "grant: {r:?}");
            let r = bob.set_role(t, carol.me(), None, SetRoleOpts::default());
            assert!(matches!(r, Err(Error::Permission { tid, needs: Role::Admin }) if tid == t), "set_role: {r:?}");
            assert_eq!(bob.grants(t).unwrap().get(&carol.me()).map(|g| g.role), Some(Role::Read), "nothing written");
        }
        for (_, pk) in &later {
            bob.engine(|e| e.ingest(&pk.bytes, pk.blobs.clone()).unwrap());
        }
        assert_eq!(bob.role_on(t).unwrap(), Some(role));
        write("two").unwrap();
        if role == Role::Admin {
            grant().unwrap();
        }
    }
}


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

// notes/api.md Sharing and roles: `grant` adds and raises, never lowers (`Invalid`, nothing
// written); `set_role` to the present role writes nothing, lowers, and with `None` removes,
// after which another removal writes nothing. Observed at the granting node.
// spec: none (API surface, notes/api.md)
#[test]
fn grant_never_lowers_and_set_role_writes_only_changes() {
    let (alice, bob) = alice_knows_bob();
    let b = bob.me();
    let g = alice.commit_with(|w| w.create()).unwrap();
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
    assert!(matches!(alice.set_role(g, b, Some(Role::Write), SetRoleOpts { retain_copy: Some(true) }), Err(Error::Invalid(_))), "retain with a role");
    alice.set_role(g, b, None, SetRoleOpts::default()).unwrap();
    assert_eq!(role(&alice), None);
    assert!(!alice.holders(g).unwrap().iter().any(|h| h.actor == b));
    let n = commits(&alice);
    alice.set_role(g, b, None, SetRoleOpts::default()).unwrap();
    assert_eq!(commits(&alice), n, "no role, nothing to remove");
}

// notes/api.md Sharing and roles (`holders`): a holder through a team is listed with the team
// between, at the least role along the way, after the team itself (nearest first); an actor
// with two ways in is listed once per way.
// spec: none (API surface, notes/api.md)
#[test]
fn holders_list_every_way_in_nearest_first() {
    let (alice, bob) = alice_knows_bob();
    let b = bob.me();
    let (g, team) = alice.commit_with(|w| Ok((w.create()?, w.create()?))).unwrap();
    alice.grant(team, b, Role::Admin, Default::default()).unwrap();
    alice.grant(g, team, Role::Read, Default::default()).unwrap();
    let hs = alice.holders(g).unwrap();
    let pos = |actor, through: &[osis::Tid]| hs.iter().position(|h| h.actor == actor && h.through == through).unwrap_or_else(|| panic!("{hs:?}"));
    assert!(pos(team, &[]) < pos(b, &[team]), "nearest first: {hs:?}");
    assert_eq!(hs[pos(b, &[team])].role, Role::Read, "the least along the way");
    assert_eq!(hs[pos(team, &[])].kind, osis::HolderKind::Actor);
    alice.grant(g, b, Role::Write, Default::default()).unwrap();
    let hs = alice.holders(g).unwrap();
    let ways: Vec<_> = hs.iter().filter(|h| h.actor == b).map(|h| (h.role, h.through.clone())).collect();
    assert_eq!(ways.len(), 2, "{hs:?}");
    assert!(ways.contains(&(Role::Write, vec![])) && ways.contains(&(Role::Read, vec![team])));
}

// notes/api.md Sharing and roles (`leave`): leaving with no way in writes nothing; this node,
// an admin of the target, leaving for another actor is `Invalid` (that is `set_role`'s) and
// writes nothing, a link's join of the same actor included; a holder's own leave ends its role
// at once, and a link it made goes on.
// spec: none (API surface, notes/api.md)
#[test]
fn leave_ends_only_own_ways_and_refuses_before_writing() {
    let (alice, bob) = alice_knows_bob();
    let (g, team) = alice.commit_with(|w| Ok((w.create()?, w.create()?))).unwrap();
    let n = commits(&alice);
    alice.leave(team, g).unwrap();
    assert_eq!(commits(&alice), n, "no way in: nothing written");
    alice.grant(g, team, Role::Write, Default::default()).unwrap();
    alice.make_link(g, Role::Write, Default::default()).unwrap();
    let k = alice.links_of(g).unwrap()[0].id.actor();
    alice.grant(k, team, Role::Read, Default::default()).unwrap();
    let n = commits(&alice);
    assert!(matches!(alice.leave(team, g), Err(Error::Invalid(_))));
    assert_eq!(commits(&alice), n, "refused before anything is written");
    assert!(alice.grants(k).unwrap().contains_key(&team), "the join of the link stays");
    // bob's own thing, alice a writer of it who makes a link: her leave ends her role only
    deliver(&alice, &bob);
    let t = bob.commit_with(|w| w.create()).unwrap();
    bob.grant(t, alice.me(), Role::Admin, Default::default()).unwrap();
    deliver(&bob, &alice);
    alice.make_link(t, Role::Read, Default::default()).unwrap();
    assert_eq!(alice.role_on(t).unwrap(), Some(Role::Admin));
    alice.leave(alice.me(), t).unwrap();
    assert_eq!(alice.role_on(t).unwrap(), None, "no way in is left");
    assert_eq!(alice.links_of(t).unwrap().len(), 1, "a leave ends no link");
}

// spec/permissions.md §6 (a node does not sign a purge request): a purge request that would drop
// none of the held deltas it names is refused `Permission`, nothing written; under the default
// (admins only) a writer purges none, not even its own; one written `author_or_admin` it purges.
#[test]
fn purge_without_the_right_is_refused_spec_permissions_6() {
    let (alice, bob) = alice_knows_bob();
    let g = alice.commit_with(|w| w.create()).unwrap();
    alice.grant(g, bob.me(), Role::Write, Default::default()).unwrap();
    let k = || osis::DynamicAspectKey::untyped(ak("t:m.0"));
    let hers = commit_with(&alice, |w| w.at(g, k()).set(&s("hers"))).stamp.id;
    deliver(&alice, &bob);
    let refused = |what: osis::Purge| {
        let n = commits(&bob);
        let mut x = bob.write();
        x.at(g, k()).purge(what).unwrap();
        matches!(x.commit(), Err(Error::Permission { tid, .. }) if tid == g) && commits(&bob) == n
    };
    assert!(refused(osis::Purge::Commit(hers)), "another's write by commit");
    assert!(refused(osis::Purge::Author(alice.me())), "another's writes by author");
    let his = commit_with(&bob, |w| w.at(g, k()).set(&s("his, by default"))).stamp.id;
    assert!(refused(osis::Purge::Commit(his)), "his own, under the default");
    let mine = commit_with(&bob, |w| w.at(g, k()).retention(osis::Retention { by: osis::PurgeBy::AuthorOrAdmin }).set(&s("his"))).stamp.id;
    commit_with(&bob, |w| w.at(g, k()).purge(osis::Purge::Commit(mine)));
    deliver(&bob, &alice);
    commit_with(&alice, |w| w.at(g, k()).purge(osis::Purge::Commit(his)));
}

// spec/permissions.md §5.1 (Trust set: a node's side is its own), notes/api.md Disputes: two admins
// remove each other, neither having seen the other's removal; a third node takes the side of the
// removal it held first, is told, lists the dispute and can switch; each party stands with
// itself. A dispute's id reads back from its text; a side of another kind is `Invalid`.
#[test]
fn disputes_listed_told_and_chosen_spec_permissions_5_1() {
    let (a, b, c) = (db(1), db(2), db(3));
    deliver(&b, &a);
    deliver(&c, &a);
    let g = a.commit_with(|w| w.create()).unwrap();
    a.grant(g, b.me(), Role::Admin, Default::default()).unwrap();
    a.grant(g, c.me(), Role::Read, Default::default()).unwrap();
    deliver(&a, &b);
    deliver(&a, &c);
    b.set_role(g, a.me(), None, SetRoleOpts::default()).unwrap();
    a.set_role(g, b.me(), None, SetRoleOpts::default()).unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    let _sub = c.on_dispute(move |_, d| drop(tx.send(d))).unwrap();
    deliver(&b, &c);
    deliver(&a, &c);
    deliver(&a, &b);
    deliver(&b, &a);
    c.settle();
    let holds = |db: &osis::Osis, x: osis::Tid| db.grants(g).unwrap().contains_key(&x);
    assert!(!holds(&c, a.me()) && holds(&c, b.me()), "b's removal was here first");
    let told = rx.try_iter().last().expect("told");
    let osis::Dispute::Removal { author, holder, side, chosen, commit, .. } = told.clone() else { panic!("a removal: {told:?}") };
    assert_eq!((author, holder, side, chosen), (b.me(), a.me(), osis::Side::Author, false), "b's removal, which counts here");
    assert_eq!(c.disputes().unwrap(), (vec![told.clone()], 0));
    let id: osis::DisputeId = told.id().to_string().parse().unwrap();
    assert_eq!(id, told.id());
    assert!(matches!(c.choose_side(id, osis::Side::Version(commit)), Err(Error::Invalid(_))), "a version is no side of a removal");
    c.choose_side(id, osis::Side::Holder).unwrap();
    assert!(holds(&c, a.me()) && !holds(&c, b.me()), "a's side: b's removal of a does not count, a's of b does");
    let (ds, _) = c.disputes().unwrap();
    assert_eq!((ds[0].side(), ds[0].chosen()), (osis::Side::Holder, true));
    c.choose_side(id, osis::Side::Author).unwrap();
    assert!(!holds(&c, a.me()) && holds(&c, b.me()));
    assert!(holds(&a, a.me()) && !holds(&a, b.me()), "each party stands with itself");
    assert!(holds(&b, b.me()) && !holds(&b, a.me()));
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
// spec/crypto.md §4 (Carried demotions): Carol reads G, which team M (Bob's, Alice a reader of it
// too) writes; Bob removes Erin, a writer of M. Carol's node holds the removal with M's new keyset
// (it is how G's writers count Erin out), but it shows her no roster of M, before or after: only
// G's, and M's to Bob. Once Carol reads M her watch on M's grants hears its roster, and hears it
// hidden once she reads it no more.
#[test]
fn a_parents_reader_sees_no_roster_of_its_member_team_spec_crypto_4() {
    let (alice, bob, carol, erin) = (db(1), db(2), db(3), db(4));
    let all = [&alice, &bob, &carol, &erin];
    mesh(&all);
    let m = bob.commit_with(|w| w.create()).unwrap();
    bob.grant(m, erin.me(), Role::Write, Default::default()).unwrap();
    bob.grant(m, alice.me(), Role::Read, Default::default()).unwrap();
    mesh(&all);
    let g = alice.commit_with(|w| w.create()).unwrap();
    alice.grant(g, m, Role::Write, Default::default()).unwrap();
    alice.grant(g, carol.me(), Role::Read, Default::default()).unwrap();
    mesh(&all);
    assert!(carol.grants(g).unwrap().contains_key(&m), "G's roster shows to its reader");
    assert!(carol.grants(m).unwrap().is_empty(), "no roster of M");
    bob.set_role(m, erin.me(), None, SetRoleOpts::default()).unwrap();
    mesh(&all);
    assert!(!bob.grants(m).unwrap().contains_key(&erin.me()), "Erin left M");
    assert!(carol.grants(m).unwrap().is_empty(), "no roster of M once Erin left");
    assert!(carol.holders(g).unwrap().iter().all(|h| h.actor != erin.me()), "nor through G's holders");
    // once Carol reads M (a roster change on M's way in, not on M's), her watch on M's grants
    // hears its roster
    let t = bob.commit_with(|w| w.create()).unwrap();
    bob.grant(m, t, Role::Read, Default::default()).unwrap();
    mesh(&all);
    let heard = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let h = heard.clone();
    let _sub = carol.on_grants_change(m, move |_, r| h.lock().unwrap().push(r.unwrap())).unwrap();
    bob.grant(t, carol.me(), Role::Read, Default::default()).unwrap();
    mesh(&all);
    assert_eq!(carol.role_on(m).unwrap(), Some(Role::Read), "Carol reads M through T");
    assert!(carol.grants(m).unwrap().contains_key(&t), "M's roster shows to its reader");
    assert!(heard.lock().unwrap().last().is_some_and(|g| g.contains_key(&t)), "her watch heard it: {:?}", heard.lock().unwrap());
    // and once she no longer reads M (T's roster changed, M's not), it hears the roster hidden
    bob.set_role(t, carol.me(), None, SetRoleOpts::default()).unwrap();
    mesh(&all);
    assert_eq!(carol.role_on(m).unwrap(), None, "Carol left T");
    assert!(carol.grants(m).unwrap().is_empty(), "no roster of M");
    assert!(heard.lock().unwrap().last().is_some_and(|g| g.is_empty()), "her watch heard it hidden: {:?}", heard.lock().unwrap());
}
