//! Two nodes of one account (siblings, paired by the product's pairing: `World::pair`) and a
//! node of another: what a sibling changes and what it does not.

use crate::harness::history::file;
use crate::harness::{World, fixture, fixture_with, siblings, stranger_siblings, two_nodes};
use osis_base::{Ak, Role, Tid, Value};
use osis_engine::Mutation;
use osis_engine::flows::Demotion;
use osis_schema::core_types as ct;

fn edge(role: Role) -> ct::Edge {
    ct::Edge { role, until: None, invite: None, tied: None, floor: None }
}

/// Node `i`'s synced group (`synced^.0` on its account's D).
fn synced_group(w: &mut World, i: usize) -> Tid {
    let me = w.engine(i).tid();
    let d = w.engine(i).account().unwrap().unwrap().1;
    *w.engine(i).get_typed(&d, &ct::SYNCED).unwrap().unwrap().get(&me).expect("node i's synced group")
}

/// Node `i` lists `t` as a subgroup of its own synced group (`add`) or takes it out.
fn list_own(w: &mut World, i: usize, t: Tid, add: bool) {
    let g = synced_group(w, i);
    w.write(i, |e| {
        let mut x = e.get_typed(&g, &ct::GROUP).unwrap().unwrap_or_default();
        if add {
            x.subgroups.insert(t);
        } else {
            x.subgroups.retain(|y| *y != t);
        }
        let mut m = Mutation::new();
        m.set(g, &ct::GROUP, &x).unwrap();
        e.write(m).unwrap();
    });
}

/// Node 0 makes a thing with a value, files it in its D and grants account 1 `role` on it.
fn granted(w: &mut World, role: Role) -> (Tid, Ak) {
    let (a0, a1) = (w.node(0).account.unwrap(), w.node(1).account.unwrap());
    let ak = Ak::new("u:v.0").unwrap();
    let t = w.write(0, |e| {
        let mut m = Mutation::new();
        let t = e.new_thing(&mut m, a0);
        m.set(t, &ak, &Value::Str("x".into())).unwrap();
        e.commit(m).unwrap();
        t
    });
    file(w, 0, vec![t], Vec::new());
    w.write(0, |e| e.grant(&t, &a1, &edge(role))).unwrap();
    w.run();
    (t, ak)
}

/// `siblings` with `granted(Write)` listed in each sibling's own synced group: both read it.
/// Built once (`fixture_with`).
fn listed() -> (World, Tid, Ak) {
    let (w, (t, ak)) = fixture_with("siblings listed", || {
        let mut w = siblings();
        let (t, ak) = granted(&mut w, Role::Write);
        list_own(&mut w, 1, t, true);
        list_own(&mut w, 2, t, true);
        w.run();
        for i in [1, 2] {
            assert_eq!(w.engine(i).get(&t, &ak).unwrap(), Some(Value::Str("x".into())), "node {i} reads it");
        }
        (w, (t, ak))
    });
    (w, t, ak)
}

// spec/permissions.md §3 (Lost access: a self-remover keeps the secrets until its self-removal is
// held elsewhere, or no peer but its account's nodes shares where it goes): node 0 unsyncs a thing
// both siblings list in their own synced groups and write; node 1 leaves it while node 2, away, still shares it (node 1's record of
// it holds S), and drops its secrets at once. (A sibling holding the removal never counts as held
// elsewhere: status::self_removal_not_held_at_own_nodes.)
#[test]
fn a_self_removal_shared_only_with_a_sibling_drops_at_once_spec_perm_3() {
    let (mut w, t, _) = listed();
    let a1 = w.node(1).account.unwrap();
    let s = w.engine(1).sync_ids(&t).unwrap()[0].id;
    w.write(0, |e| {
        let d = e.account().unwrap().unwrap().1;
        let mut g = e.get_typed(&d, &ct::GROUP).unwrap().unwrap_or_default();
        g.items.retain(|x| *x != t);
        let mut m = Mutation::new();
        m.set(d, &ct::GROUP, &g).unwrap();
        e.commit(m).unwrap();
    });
    w.flush();
    assert!(w.store(0).synced(&s).is_none(), "node 0 stopped syncing it");
    assert!(w.store(2).synced(&s).is_some(), "node 2 shares it");
    // node 1 told its connection to node 2 closed before it writes (else the removal reaches node
    // 2 and is held elsewhere: the test proves nothing)
    w.partition(1, 2);
    w.flush();
    let c = w.write(1, |e| e.demote(&t, &Demotion { holder: a1, new: None, retain: None })).unwrap().commits[0];
    w.flush();
    assert!(!w.engine(1).waiting_removals().unwrap().contains(&c), "only a sibling shares it: done");
    assert!(w.engine(1).epochs(&t).is_none_or(|e| e.read.held().next().is_none()), "dropped");
}

/// `stranger_siblings` with a sync grant from node 0's account to account 1 accepted on node 1
/// (`Engine::accept_invite` into its synced group), run to quiet: (world, thing, its sync ID).
fn accepted_on_one() -> (World, Tid, osis_base::SyncId) {
    let mut w = stranger_siblings();
    let (t, _) = granted(&mut w, Role::Sync);
    let s = w.engine(0).home_sync_id(&t).unwrap().unwrap();
    for i in [1, 2] {
        let inv = w.engine(i).invitations().unwrap();
        assert!(inv.iter().any(|x| x.thing == t && !x.taken && x.role == Role::Sync), "node {i}: an invitation: {inv:?}");
        assert!(w.engine(i).sync_record(&t).unwrap().is_none(), "node {i}: nothing kept before the accept");
    }
    let g1 = synced_group(&mut w, 1);
    w.write(1, |e| e.accept_invite(&t, &g1)).unwrap();
    w.run();
    (w, t, s)
}

// spec/sync.md §3 (Sync record: a kept sync ID only by an accept, the record read by every node
// of the account), spec/sync-set.md §4 (Invitations; Accepting), spec/sync-inbox.md §2 (a boxes
// payload is never taken: no author is connected for it): a grant of sync from a contact of
// account 1 (node 0 holds its card) waits for an accept at both siblings like any other; accepted
// on node 1, both keep it under the granter's sync ID, node 1 opens it and records its secret.
#[test]
fn a_sync_grant_accepted_on_one_sibling_is_kept_at_both_spec_sync_3() {
    let (mut w, t, s) = accepted_on_one();
    for i in [1, 2] {
        let r = w.engine(i).sync_record(&t).unwrap().unwrap_or_else(|| panic!("node {i} keeps it"));
        assert_eq!(r.sync_ids, vec![s], "node {i}");
        assert!(!r.recorded.is_empty(), "node {i}: the secret its path bears, recorded");
        assert!(!w.engine(i).invitations().unwrap().iter().any(|x| x.thing == t && !x.taken), "node {i}: no invitation");
    }
    assert!(!w.store(1).entries(&s).unwrap().is_empty(), "node 1 holds the writes");
}

// spec/sync.md §3 (Sync record: read by a node paired later, whatever inbox blobs have expired),
// spec/sync-inbox.md §5 (Grant copy: none for a holder of sync alone): a node paired past
// INBOX_LIFETIME, the grant's blob gone, keeps the thing from the record alone and holds its
// writes. NetTrust `UN_local` (a record per node) fails this.
#[test]
fn a_sibling_paired_after_inbox_lifetime_keeps_an_accepted_grant_spec_sync_3() {
    let (mut w, t, s) = accepted_on_one();
    w.advance(osis_base::format::INBOX_LIFETIME_MS + 3 * osis_base::format::MAX_DRIFT_MS);
    w.run();
    let n = w.pair(1);
    w.run();
    let r = w.engine(n).sync_record(&t).unwrap().expect("kept from the record");
    assert_eq!(r.sync_ids, vec![s]);
    assert!(!r.recorded.is_empty() && r.secrets.keys().all(|e| r.recorded.contains(e)), "only recorded secrets: every offer expired");
    assert_eq!(w.engine(n).thing_sync(&t).unwrap(), osis_engine::sync::ThingSync::Unread(vec![s]));
    assert!(!w.store(n).entries(&s).unwrap().is_empty(), "the late node holds the writes");
}

// spec/sync.md §3 (A recorded secret: from any box that opens, no accept), spec/wire.md §9
// (GrantSig: a rotation's boxes payload is unsigned): node 0 grants a third account
// read and removes it, rotating read and sync; both siblings follow to the new step without an
// accept, the new sync secret recorded.
#[test]
fn a_rotation_reaches_kept_siblings_without_an_accept_spec_sync_3() {
    let (mut w, t, s) = accepted_on_one();
    let before = w.engine(1).sync_record(&t).unwrap().unwrap().recorded.len();
    let x = w.add_node();
    let ax = w.node(x).account.unwrap();
    w.run();
    crate::harness::history::hand(&mut w, x, 0);
    w.write(0, |e| e.grant(&t, &ax, &edge(Role::Read))).unwrap();
    w.run();
    w.write(0, |e| e.demote(&t, &Demotion { holder: ax, new: None, retain: None })).unwrap();
    w.run();
    let head = w.engine(0).sync_ids(&t).unwrap().iter().find(|o| o.id == s).unwrap().path.steps.last().map(|(st, _)| st.id());
    assert_eq!(w.store(1).head(&s).unwrap().map(|h| h.id()), head, "node 1 at the new step");
    for i in [1, 2] {
        assert!(w.engine(i).sync_record(&t).unwrap().unwrap().recorded.len() > before, "node {i}: the rotation's secret recorded");
        assert!(!w.engine(i).invitations().unwrap().iter().any(|x| x.thing == t && !x.taken), "node {i}: no accept asked");
    }
}

// spec/sync-set.md §3 (Unsyncing: whoever holds it elsewhere): each sibling lists a thing in its
// own synced group; node 1 takes it out of its own, stops syncing it and forgets its copy, while
// node 2 keeps it and reads a later write.
#[test]
fn unsyncing_on_one_sibling_leaves_the_other_its_copy_spec_sync_set_3() {
    let (mut w, t, ak) = listed();
    let s = w.engine(1).sync_ids(&t).unwrap()[0].id;
    list_own(&mut w, 1, t, false);
    w.flush();
    assert_eq!(w.engine(1).get(&t, &ak).unwrap(), None, "node 1 forgot it");
    assert!(w.store(1).synced(&s).is_none() && !w.store(1).held_ids().unwrap().contains(&s), "node 1 stopped and shredded");
    w.write(0, |e| {
        let mut m = Mutation::new();
        m.set(t, &ak, &Value::Str("y".into())).unwrap();
        e.commit(m).unwrap();
    });
    w.flush();
    assert_eq!(w.engine(2).get(&t, &ak).unwrap(), Some(Value::Str("y".into())), "node 2 keeps it");
    assert_eq!(w.engine(1).get(&t, &ak).unwrap(), None, "node 1 still not");
}

// spec/permissions.md §3 (Lost access: whichever node of the account made it), spec/sync-status.md
// §2: node 1 leaves a thing both siblings read while node 0, which shares it, is away; node 2
// applies the removal from node 1 and waits as node 1 does (node 0's record holds S: a peer away),
// through a restart, then drops its secrets and stops syncing S once node 0 holds the removal,
// so node 0's later write never reaches it.
#[test]
fn a_siblings_self_removal_waits_and_drops_at_both_siblings_spec_perm_3() {
    let (mut w, t, ak) = listed();
    let a1 = w.node(1).account.unwrap();
    let s = w.engine(2).sync_ids(&t).unwrap()[0].id;
    w.partition(0, 1);
    w.partition(0, 2);
    w.flush();
    let c = w.write(1, |e| e.demote(&t, &Demotion { holder: a1, new: None, retain: None })).unwrap().commits[0];
    w.flush();
    assert!(w.engine(2).commit_ids().contains(&c), "node 2 holds the removal");
    w.power_off(2);
    w.power_on(2);
    w.run();
    for i in [1, 2] {
        assert!(w.engine(i).waiting_removals().unwrap().contains(&c), "node {i} waits: node 0 shares S, away");
        assert!(w.engine(i).epochs(&t).is_some_and(|x| x.read.holds_any()), "node {i} keeps its secrets while it waits");
    }
    w.heal();
    w.run();
    for i in [1, 2] {
        assert!(!w.engine(i).waiting_removals().unwrap().contains(&c), "node {i}: node 0 holds it");
        assert!(w.engine(i).epochs(&t).is_none_or(|x| x.read.held().next().is_none()), "node {i} dropped");
        assert!(w.store(i).synced(&s).is_none(), "node {i} stopped syncing S");
    }
    w.write(0, |e| {
        let mut m = Mutation::new();
        m.set(t, &ak, &Value::Str("after".into())).unwrap();
        e.commit(m).unwrap();
    });
    w.run();
    assert_ne!(w.engine(2).get(&t, &ak).unwrap(), Some(Value::Str("after".into())), "node 2 reads nothing after");
}

/// Node 1 writes t, grants node 0's account read, node 0 reads it; node 1 removes its sibling
/// node 2 from its account's D; node 0 keeps every commit it held, reads the write from before
/// and one after, and holds no thing list of D (spec/permissions.md §5.5: outsiders get the
/// rotation alone); node 2 reads nothing written after.
fn outsider_across_a_node_removal(mut w: World) {
    let (a0, a1) = (w.node(0).account.unwrap(), w.node(1).account.unwrap());
    let ak = Ak::new("u:v.0").unwrap();
    let set = |w: &mut World, t: Option<Tid>, v: &str| {
        w.write(1, |e| {
            let mut m = Mutation::new();
            let t = t.unwrap_or_else(|| e.new_thing(&mut m, a1));
            m.set(t, &ak, &Value::Str(v.into())).unwrap();
            e.commit(m).unwrap();
            t
        })
    };
    let t = set(&mut w, None, "before");
    file(&mut w, 1, vec![t], Vec::new());
    w.write(1, |e| e.grant(&t, &a0, &edge(Role::Read))).unwrap();
    w.run();
    file(&mut w, 0, Vec::new(), vec![t]);
    w.run();
    assert_eq!(w.engine(0).get(&t, &ak).unwrap(), Some(Value::Str("before".into())));
    // a content commit on another thing may be forgotten as covered meanwhile (a dial list
    // replaced whole: spec/commits.md §5 Forgetting); t's and every role commit stay
    let before: Vec<_> = w.engine(0).commit_ids();
    let held: Vec<_> = before.iter().copied().filter(|c| w.engine(0).header(c).is_some_and(|h| h.kind.is_role() || h.aspects.iter().any(|a| a.tid == t))).collect();
    let (n2, d) = (w.engine(2).tid(), w.engine(1).account().unwrap().unwrap().1);
    w.write(1, |e| e.demote(&d, &Demotion { holder: n2, new: None, retain: None })).unwrap();
    w.run();
    let lost: Vec<_> = held.iter().filter(|c| !w.engine(0).commit_ids().contains(c)).collect();
    assert!(lost.is_empty(), "node 0 dropped {} commits it held", lost.len());
    assert!(w.engine(0).roster(&t).contains_key(&a0), "node 0's account keeps its read edge");
    assert_eq!(w.engine(0).get(&t, &ak).unwrap(), Some(Value::Str("before".into())), "the write before the removal");
    // what an outsider learns of the account's lists: only lists of what it reads (t; the
    // account's profile and what the two share where they are contacts) and of the account
    // (whose rotations are its certificates), naming only commits it holds or held (one forgotten
    // as covered since): nothing of D or its nodes
    let mine = w.engine(0).commit_ids();
    let rots = w.engine(1).account_rotations(&a1);
    assert!(rots.iter().any(|r| w.engine(1).rotation_lists(r).unwrap().iter().any(|(x, _)| *x == d)), "node 1 holds D's list");
    for r in rots {
        for (x, ids) in w.engine(0).rotation_lists(&r).unwrap() {
            let reads = matches!(w.engine(0).thing_sync(&x).unwrap(), osis_engine::sync::ThingSync::Read(_));
            assert!(x == t || x == a1 || reads, "node 0 holds a thing list of {x:?} (d {d:?})");
            assert!(ids.iter().all(|c| mine.contains(c) || before.contains(c)), "a list of {x:?} names a commit node 0 never held");
        }
    }
    // nor D's record or the removed node's (spec/requirements.md: outsiders never learn an
    // account's devices)
    assert!(w.engine(0).core.created(&d).is_none() && w.engine(0).core.created(&n2).is_none(), "node 0 holds D's or node 2's record");
    set(&mut w, Some(t), "after");
    w.run();
    assert_eq!(w.engine(0).get(&t, &ak).unwrap(), Some(Value::Str("after".into())), "the write after the removal");
    assert_ne!(w.engine(2).get(&t, &ak).unwrap(), Some(Value::Str("after".into())), "node 2 reads nothing after its removal");
}

/// Node 1 redeemed node 0's card and filed its profile; node 2 is node 1's sibling.
fn one_way_contact_siblings() -> World {
    let mut w = two_nodes();
    let card = w.make_link(0, w.node(0).profile.expect("a profile"), Role::Read);
    w.redeem(1, &card);
    w.run();
    assert_eq!(w.redeem(1, &card), osis_sync::types::Waiting::Done, "node 1 redeems node 0's card");
    file(&mut w, 1, Vec::new(), vec![card.target]);
    w.pair(1);
    w.run();
    w
}

// spec/permissions.md §5.5 (Honest nodes of P: removing a node X from D; Rotation's list: a thing
// list is a chain certificate of T), spec/sync-judgement.md §1 (List blobs): node 0's account
// holds nothing of node 1's account but t, so the rotation reaches it under t's sync ID alone,
// with t's thing list, and t's commits at the closed epoch count there.
#[test]
fn an_outsider_reads_the_accounts_writes_across_a_node_removal_spec_permissions_5_5() {
    let w = fixture("one-way contact siblings", one_way_contact_siblings);
    outsider_across_a_node_removal(w);
}

// spec/sync-set.md §3 (One rule ends syncing it: N keeps syncing S until a complete pass of S begun
// after S left ends, and what that pass brings may give S back), spec/permissions.md §5.5: the same where node 0 holds node 1's
// contact card. A's rotation reaches it first under the card's sync ID, before t's thing list, so
// t reads plain for now and S_t leaves; node 0 keeps syncing S_t (opening and proving by t's read
// secrets) through a pass, which brings the list, and S_t comes back. The API flow is osis
// `sync::an_outsider_reads_the_accounts_writes_across_a_node_removal_*`.
#[test]
fn an_outsider_with_the_card_reads_the_accounts_writes_across_a_node_removal_spec_sync_set_3() {
    outsider_across_a_node_removal(siblings());
}

// spec/crypto.md §4 (Roles secrets: a history-less holder holds every earlier epoch's roles
// secret), spec/crypto.md §5 (A rotation's thing lists: they wrap as it does, under the roles
// secret), spec/permissions.md
// §5.5: after account A removes node 2 (rotation r), node 1 grants t from now to a new account's
// node 3. Node 3 opens t's thing list of r under the closed epoch's roles secret, so it judges A's
// grant to node 0's account as node 0 does: both hold the same roster of t.
#[test]
fn a_from_now_grantee_after_a_removal_holds_the_old_readers_roster_spec_crypto_5() {
    use osis_engine::flows::edges::History;
    let mut w = fixture("one-way contact siblings", one_way_contact_siblings);
    let (a0, a1) = (w.node(0).account.unwrap(), w.node(1).account.unwrap());
    let ak = Ak::new("u:v.0").unwrap();
    let t = w.write(1, |e| {
        let mut m = Mutation::new();
        let t = e.new_thing(&mut m, a1);
        m.set(t, &ak, &Value::Str("before".into())).unwrap();
        e.commit(m).unwrap();
        t
    });
    file(&mut w, 1, vec![t], Vec::new());
    w.write(1, |e| e.grant(&t, &a0, &edge(Role::Read))).unwrap();
    w.run();
    file(&mut w, 0, Vec::new(), vec![t]);
    w.run();
    let (n2, d) = (w.engine(2).tid(), w.engine(1).account().unwrap().unwrap().1);
    w.write(1, |e| e.demote(&d, &Demotion { holder: n2, new: None, retain: None })).unwrap();
    w.run();
    let n3 = w.add_node();
    let a3 = w.node(n3).account.unwrap();
    let card = w.make_link(n3, w.node(n3).profile.expect("a profile"), Role::Read);
    w.redeem(1, &card);
    w.run();
    w.write(1, |e| e.grant_with(&t, &a3, &edge(Role::Read), History::None)).unwrap();
    w.run();
    file(&mut w, n3, Vec::new(), vec![t]);
    w.run();
    let old = w.engine(0).roster(&t);
    assert!(old.contains_key(&a0), "node 0 keeps its read edge");
    assert!(w.engine(n3).roster(&t).contains_key(&a3), "node 3 holds its grant");
    assert_eq!(w.engine(n3).roster(&t), w.engine(1).roster(&t), "node 3 holds the writer's roster of t");
    assert_eq!(w.engine(0).roster(&t), w.engine(1).roster(&t), "so does node 0");
    // spec/crypto.md §4 State at a cut: what node 3 holds of a commit sealed before its cut (the
    // removal's rotation: its role parts, by the roles secret) lacks nothing it could get
    for c in w.engine(n3).commit_ids() {
        for s in w.engine(n3).sync_bodies(&c).unwrap().keys() {
            assert!(!w.engine(n3).read_facts(s, &c).unwrap().missing, "node 3 counts a part of {c:?} under {s:?} missing that is sealed below its floor");
        }
    }
}

// spec/sync-opens.md §3 (who it may be: the node it names while a node of this account),
// spec/sync-set.md §3 (it waits only while some peer is to be waited for on S): node 1 writes a
// thing of its own both siblings sync (its own sync ID: a link no one redeems) while node 2 is
// away, removes node 2 from its account's D, then unfiles the thing. Node 2's record still holds
// S, but the node it names is no longer the account's: no one to wait for, so node 1 leaves S at
// once.
#[test]
fn a_removed_siblings_record_is_no_peer_spec_sync_opens_3() {
    let mut w = siblings();
    let a1 = w.node(1).account.unwrap();
    let ak = Ak::new("u:v.0").unwrap();
    let set = |w: &mut World, t: Option<Tid>, v: &str| {
        w.write(1, |e| {
            let mut m = Mutation::new();
            let t = t.unwrap_or_else(|| e.new_thing(&mut m, a1));
            m.set(t, &ak, &Value::Str(v.into())).unwrap();
            e.commit(m).unwrap();
            t
        })
    };
    let t = set(&mut w, None, "before");
    file(&mut w, 1, vec![t], Vec::new());
    // a link no one redeems gives t secrets, so a sync ID, of its own
    w.make_link(1, t, Role::Read);
    w.run();
    assert_eq!(w.engine(2).get(&t, &ak).unwrap(), Some(Value::Str("before".into())), "node 2 reads it");
    let s = w.engine(1).sync_ids(&t).unwrap()[0].id;
    w.partition(1, 2);
    w.flush();
    set(&mut w, Some(t), "away");
    let (n2, d) = (w.engine(2).tid(), w.engine(1).account().unwrap().unwrap().1);
    w.write(1, |e| e.demote(&d, &Demotion { holder: n2, new: None, retain: None })).unwrap();
    w.run();
    w.write(1, |e| {
        let mut g = e.get_typed(&d, &ct::GROUP).unwrap().unwrap_or_default();
        g.items.retain(|x| *x != t);
        let mut m = Mutation::new();
        m.set(d, &ct::GROUP, &g).unwrap();
        e.commit(m).unwrap();
    });
    w.run();
    assert!(w.store(1).synced(&s).is_none(), "node 1 left S: a removed node is no peer");
}

// spec/sync-set.md §3 (to be waited for on S: a peer that may hold S by the rosters, or whose
// kept record holds S; A peer away keeps it waiting until that peer connects),
// spec/sync-opens.md §3 (a node of another account whose epoch closed is still that account): node
// 0 writes a thing account 1 holds a role on while both siblings are away; node 1 removes node 2
// from its account's D (a rotation of account 1's key, handed to node 0), then node 0 unfiles the
// thing. Node 1, away but honest, is still account 1: node 0 keeps its only copy of the write
// past the pass's wait, and node 1 takes it once back.
#[test]
fn a_peer_away_across_its_accounts_rotation_is_waited_for_spec_sync_set_3() {
    let mut w = stranger_siblings();
    let (t, ak) = granted(&mut w, Role::Write);
    list_own(&mut w, 1, t, true);
    list_own(&mut w, 2, t, true);
    w.run();
    assert_eq!(w.engine(1).get(&t, &ak).unwrap(), Some(Value::Str("x".into())), "node 1 reads it");
    let s = w.engine(0).sync_ids(&t).unwrap()[0].id;
    w.partition(0, 1);
    w.partition(0, 2);
    w.flush();
    w.write(0, |e| {
        let mut m = Mutation::new();
        m.set(t, &ak, &Value::Str("away".into())).unwrap();
        e.commit(m).unwrap();
    });
    let (n2, d) = (w.engine(2).tid(), w.engine(1).account().unwrap().unwrap().1);
    w.write(1, |e| e.demote(&d, &Demotion { holder: n2, new: None, retain: None })).unwrap();
    w.flush();
    assert!(crate::harness::history::hand(&mut w, 1, 0), "node 0 is handed account 1's rotation");
    w.write(0, |e| {
        let d0 = e.account().unwrap().unwrap().1;
        let mut g = e.get_typed(&d0, &ct::GROUP).unwrap().unwrap_or_default();
        g.items.retain(|x| *x != t);
        let mut m = Mutation::new();
        m.set(d0, &ct::GROUP, &g).unwrap();
        e.commit(m).unwrap();
    });
    w.advance(osis_proto::limits::PASS_WAIT_MS + 1);
    assert!(w.store(0).synced(&s).is_some(), "node 0 waits for node 1, away across its account's rotation");
    w.heal();
    w.run();
    assert_eq!(w.engine(1).get(&t, &ak).unwrap(), Some(Value::Str("away".into())), "node 1 took node 0's write");
    assert!(w.store(0).synced(&s).is_none(), "then node 0 left S");
}

/// spec/sync-judgement.md §1: a part sealed below a node's floor counts missing only once the
/// node holds a read secret under it; meanwhile its body under S is every reader's (judged with
/// that part: covered, carriers, purges). Granted history after a from-now grant, the node
/// fetches and holds what it now opens.
#[test]
fn a_from_now_grantee_granted_history_holds_what_was_below_its_floor_spec_sync_judgement_1() {
    use osis_engine::flows::edges::History;
    let mut w = fixture("one-way contact siblings", one_way_contact_siblings);
    let a1 = w.node(1).account.unwrap();
    let ak = Ak::new("u:v.0").unwrap();
    let t = w.write(1, |e| {
        let mut m = Mutation::new();
        let t = e.new_thing(&mut m, a1);
        m.set(t, &ak, &Value::Str("before".into())).unwrap();
        e.commit(m).unwrap();
        t
    });
    file(&mut w, 1, vec![t], Vec::new());
    let (n2, d) = (w.engine(2).tid(), w.engine(1).account().unwrap().unwrap().1);
    w.write(1, |e| e.demote(&d, &Demotion { holder: n2, new: None, retain: None })).unwrap();
    w.run();
    let n3 = w.add_node();
    let a3 = w.node(n3).account.unwrap();
    let card = w.make_link(n3, w.node(n3).profile.expect("a profile"), Role::Read);
    w.redeem(1, &card);
    w.run();
    w.write(1, |e| e.grant_with(&t, &a3, &edge(Role::Read), History::None)).unwrap();
    w.run();
    file(&mut w, n3, Vec::new(), vec![t]);
    w.run();
    // below its floor: node 3 lacks a part of a body under some S, and counts nothing missing
    let lacks = w.engine(n3).commit_parts_missing().into_iter().any(|(c, ps)| w.engine(n3).sync_bodies(&c).unwrap().values().any(|m| m.parts.iter().any(|p| ps.contains(p))));
    assert!(lacks, "node 3 lacks a part sealed below its floor");
    for c in w.engine(n3).commit_ids() {
        let full = w.engine(1).sync_bodies(&c).unwrap();
        for (s, m) in w.engine(n3).sync_bodies(&c).unwrap().iter() {
            assert!(!w.engine(n3).read_facts(s, &c).unwrap().missing, "node 3 counts a part of {c:?} under {s:?} missing that is sealed below its floor");
            if let Some(f) = full.get(s) {
                assert_eq!(m.parts, f.parts, "node 3 judges {c:?} under {s:?} by node 1's body");
            }
        }
    }
    w.write(1, |e| e.grant(&t, &a3, &edge(Role::Admin))).unwrap();
    w.run();
    assert_eq!(w.engine(n3).get(&t, &ak).unwrap(), Some(Value::Str("before".into())), "node 3 reads what was written before its cut");
    let missing = w.engine(n3).commit_parts_missing();
    for c in w.engine(n3).commit_ids() {
        for (s, m) in w.engine(n3).sync_bodies(&c).unwrap().iter() {
            assert!(!w.engine(n3).read_facts(s, &c).unwrap().missing, "node 3 counts a part of {c:?} under {s:?} missing");
            assert!(m.parts.iter().all(|p| missing.get(&c).is_none_or(|x| !x.contains(p))), "node 3 holds every part of {c:?} under {s:?}");
        }
    }
}
