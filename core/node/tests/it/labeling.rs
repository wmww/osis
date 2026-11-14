#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Labeling on hand-built groups (spec/sync-ids.md §1; spec/crypto.md §5, §7): entitlement,
//! one blob per commit with its prefix groups, wraps, head keys, delete keys.

use crate::net::{hosted, local_nodes};
use crate::net;
use net::*;
use osis_base::{Role, WallMs};
use osis_label::Prefix;
use osis_node::Mutation;
use osis_crypto::SeededRng;
use osis_schema::core_types as ct;

// spec/sync-judgement.md §1 (entitlement): a shared folder's label holds what its actor may read: items
// below it and the folder's own writes; an item under another first admin dropped into `group.0` without
// an edge is silently not shared (only the folder's `group.0` delta goes).
#[test]
fn shared_folder_entitlement_spec_sync_3() {
    let (mut net, [a, b]) = local_nodes::<2>();
    let g = net.group(a, &[(b, Role::Write)], &[]);
    let inside = net.item(a, g, g, "in");
    let at = net.tid(a);
    let outside = net.item(a, g, at, "out");
    let e = net.engine(a);
    assert!(e.closure(&g).contains(&inside) && e.closure(&g).contains(&outside));
    assert!(e.may_read(&g, &inside));
    assert!(!e.may_read(&g, &outside));
    let bodies = e.label_bodies(&g).unwrap();
    let touched = |t: osis_base::Tid, e: &mut osis_node::Engine| {
        bodies.iter().any(|b| {
            let h = e.header(&b.commit).unwrap();
            b.parts.iter().any(|ai| h.aspects[*ai].tid == t)
        })
    };
    assert!(touched(inside, e));
    assert!(!touched(outside, e), "a thing the group's actor cannot read is not under its label");
    assert!(touched(g, e));
}

// spec/sync-judgement.md §1 (closure through `group.0`), spec/data-model.md §8: an unlabeled group nested
// below g as a subgroup only (no item of g) carries its items to g's readers: they read them, list
// them in g, and a reader arriving later finds them at the host (no reader deletes them there).
#[test]
fn nested_subgroup_items_reach_readers_spec_sync_3() {
    let (mut net, _host, [a, b, c], g, []) = crate::net::hosted::<3, 0>(&[(1, Role::Write), (2, Role::Read)], [], true);
    net.set_online(c, false);
    let e = net.engine(a);
    let mut m = Mutation::new();
    let (sub, inner) = (e.new_thing(&mut m, g), e.new_thing(&mut m, g));
    m.set(sub, &ct::GROUP, &ct::Group { items: Default::default(), subgroups: [inner].into() }).unwrap();
    e.commit(m).unwrap();
    let w = net.item(a, inner, g, "w");
    net.run();
    let mut def = net.engine(a).get_typed(&g, &ct::GROUP).unwrap().unwrap_or_default();
    def.subgroups.insert(sub);
    let mut m = Mutation::new();
    m.set(g, &ct::GROUP, &def).unwrap();
    net.engine(a).commit(m).unwrap();
    net.run();
    for _ in 0..3 {
        net.advance(15_000);
    }
    assert_eq!(net.read(b, w), Some(s("w")), "a reader of g reads it");
    assert!(net.engine(b).groups_of(&w).contains(&g), "and lists it in g");
    net.set_online(a, false);
    net.set_online(b, false);
    net.set_online(c, true);
    for _ in 0..3 {
        net.advance(15_000);
    }
    assert_eq!(net.read(c, w), Some(s("w")), "a later reader finds it at the host");
}

// spec/sync-ids.md §1, spec/sync-judgement.md §1, spec/wire.md §5: one blob per commit whatever its retention classes; its
// prefix carries the commit's expiry and one commitment group per distinct delete-key set, and
// opens against its header.
#[test]
fn one_blob_prefix_groups_per_key_set_spec_wire_5() {
    let (mut net, [a, b]) = local_nodes::<2>();
    let g = net.group(a, &[(b, Role::Write)], &[]);
    let t = net.item(a, g, g, "x");
    net.keep(a, t, &[("t:gone.0", PURGE)]);
    let mut m = Mutation::new();
    let at = WallMs(net.engine(a).now().0 + 3_600_000);
    for (k, v) in [(&REG, "plain"), (&crate::common::KEPT, "kept"), (&GONE, "gone")] {
        m.set(t, k, &s(v)).unwrap();
        m.expires(t, k, at).unwrap();
    }
    let c = net.engine(a).commit(m).unwrap().unwrap();
    let body = net.engine(a).body(&c).unwrap().unwrap();
    assert_eq!(body.parts.len(), 3, "three retention classes in one body");
    assert_eq!(body.expires, Some(at.0), "the commit's expiry");
    let h = net.engine(a).header(&c).unwrap();
    let mut sets: Vec<&Vec<usize>> = h.aspects.iter().map(|x| &x.keys).collect();
    sets.dedup();
    let mut rng = SeededRng::from_u64(0);
    let sealed = net.engine(a).seal(&body, osis_label::Class::Durable, &[], &mut rng).unwrap().unwrap();
    let p = Prefix::parse(&sealed.blob).unwrap();
    assert_eq!(p.expiry(), body.expires.map(WallMs));
    assert_eq!(p.groups().len(), sets.len(), "one group per distinct key set");
    assert!(p.groups().len() >= 2);
    let o = net.engine(a).open_commit(&sealed.blob, &sealed.key).unwrap();
    assert_eq!(o.parts(), body.parts);
    assert!(o.sealed.is_empty());
    assert_eq!(o.ais, vec![0, 1, 2]);
    // two encryptions of one body are unlinkable blobs
    assert_ne!(net.engine(a).seal(&body, osis_label::Class::Durable, &[], &mut rng).unwrap().unwrap().id, sealed.id);
}

// spec/crypto.md §5: content is wrapped under the newest current read epoch; a rotation commit
// under the epoch it supersedes, so the holders it seals to can open it.
#[test]
fn rotation_wrap_exception_spec_crypto_5() {
    let (mut net, [a, b]) = local_nodes::<2>();
    let g = net.group(a, &[(b, Role::Write)], &[]);
    let bt = net.tid(b);
    let at = net.tid(a);
    let e = net.engine(a);
    let before = e.epochs(&g).unwrap().read.newest_held().map(|(_, s)| s.clone()).unwrap();
    let rs = recipients_of(e, &[(at, Role::Admin), (bt, Role::Write)]);
    let c = rotation(e, g, &rs, 9, false);
    let after = e.epochs(&g).unwrap().read.newest_held().map(|(_, s)| s.clone()).unwrap();
    assert_ne!(before.expose(), after.expose());
    let parts: Vec<usize> = (0..e.header(&c).unwrap().aspects.len()).collect();
    assert_eq!(e.wrap_secret(&g, Some((&c, &parts))).unwrap().unwrap().expose(), before.expose());
    assert_eq!(e.wrap_secret(&g, None).unwrap().unwrap().expose(), after.expose());
}

// spec/sync-ids.md §6, spec/crypto.md §4: a writer stamps with the head's write key, a reader only
// opens (sync key) and deposits, an admin also holds the delete key; a holder of the thing's
// write secret signs for the level-3 commitment of a `writer` body; a reader holds no delete key.
#[test]
fn head_keys_and_delete_keys_spec_sync_5() {
    let (mut net, [a, b, r]) = local_nodes::<3>();
    let g = net.group(a, &[(b, Role::Write), (r, Role::Read)], &[]);
    let (_, l) = net.group_labels(a).into_iter().next().unwrap();
    let head = l.steps.values().next().unwrap().0.clone();
    let ka = net.engine(a).head_keys(&g, &head).unwrap();
    assert!(ka.sync.is_some() && ka.write.is_some() && ka.delete.is_some() && ka.deposit.is_some());
    let kb = net.engine(b).head_keys(&g, &head).unwrap();
    assert!(kb.sync.is_some() && kb.write.is_some() && kb.delete.is_none());
    let kr = net.engine(r).head_keys(&g, &head).unwrap();
    assert!(kr.sync.is_some() && kr.write.is_none() && kr.delete.is_none() && kr.deposit.is_some());
    let t = net.item(a, g, g, "x");
    net.keep(a, t, &[("t:gone.0", PURGE)]);
    let mut m = Mutation::new();
    m.set(t, &GONE, &s("gone")).unwrap();
    let c = net.engine(a).commit(m).unwrap().unwrap();
    net.pair(a, b);
    let body = net.engine(a).body(&c).unwrap().unwrap();
    let sealed = net.engine(a).seal(&body, osis_label::Class::Durable, &[], &mut SeededRng::from_u64(0)).unwrap().unwrap();
    let p = Prefix::parse(&sealed.blob).unwrap();
    let ds = net.engine(b).delete_secrets_of(&c, &sealed.ais).remove(0);
    let d = [7u8; 32];
    let k3 = p.key_at(0, 3).unwrap();
    assert!(ds.iter().any(|(lvl, dk)| *lvl == 3 && osis_crypto::verify_delete(&k3, &d, &dk.sign(p.salt(), &body.blind, &d)).is_ok()), "a writer holds the level-3 key: {:?}", ds.iter().map(|x| x.0).collect::<Vec<_>>());
    net.pair(a, r);
    assert!(net.engine(r).delete_secrets_of(&c, &sealed.ais).iter().all(Vec::is_empty));
}

// spec/sync-ids.md §2 (growth, notes/growth.md): an admin's `label.0` write drops the claim sets
// (entry boxes with them) of the steps superseded for `ROLE_KEEP`; the newer ones stay.
#[test]
fn old_claim_sets_dropped_spec_sync_2() {
    use osis_schema::core_types as ct;
    let (mut net, _, [a], g, []) = hosted::<1, 0>(&[], [], true);
    let l = net.label(a);
    let label = |net: &mut Net| net.engine(a).get_typed(&g, &ct::LABEL).unwrap().unwrap().remove(&l).unwrap();
    let head = |net: &mut Net| osis_label::tips(&label(net)).unwrap()[0];
    let s0 = head(&mut net);
    let s1 = net.engine(a).issue_step(&g, &l, &s0, true).unwrap().0.unwrap().0.id();
    net.run();
    net.advance(osis_base::format::ROLE_KEEP_MS);
    let s2 = net.engine(a).issue_step(&g, &l, &s1, true).unwrap().0.unwrap().0.id();
    net.run();
    let rec = label(&mut net);
    let claims = |id: &osis_label::StepId| rec.steps.get(&id.0).unwrap().claims.is_some();
    assert_eq!((claims(&s0), claims(&s1), claims(&s2)), (false, true, true), "only the set superseded for ROLE_KEEP went");
    assert_eq!(rec.steps.len(), 3, "the steps themselves stay");
}

// spec/requirements.md, Scale; spec/data-model.md §6: a real registration for 2100 readers: its
// claim set, above `CHUNK_THRESHOLD`, stays inline in `label.0` and its role commit applies.
#[test]
#[ignore = "by hand: 2100 holders"]
fn registration_of_thousands_of_readers() {
    use osis_base::Value;
    use osis_crdt::{Op, PathOp, PathSeg};
    use osis_crypto::{Epoch, KeyActorKeys, Secret32};
    use osis_keys::{HolderKeys, Recipient, rotate};
    use osis_schema::core_types as ct;
    use osis_schema::Codec;
    use std::collections::{BTreeMap, BTreeSet};
    let mut lp = crate::common::net(1, 0);
    let e = &mut lp.peers[0].engine;
    let me = e.me();
    let mut m = Mutation::new();
    let a = e.new_thing(&mut m, me);
    e.commit(m).unwrap().unwrap();
    let all = BTreeSet::from(Role::ALL);
    let own = [Recipient { holder: me, role: Role::Admin, keys: HolderKeys::KeyActor { kem: e.identity().keys().kem.public().clone(), seed: None } }];
    let view = e.epochs(&a).unwrap();
    let r0 = rotate(&a, &all, &view, &Default::default(), &own, &osis_keys::Names::default(), &mut SeededRng::from_u64(2)).unwrap();
    let write = |m: &mut Mutation, r: &osis_keys::Rotation| {
        for (k, b) in &r.secrets.boxes {
            m.op(a, &ct::SECRETS, PathOp { path: vec![PathSeg::Field(0), PathSeg::Key(k.to_value())], op: Op::Set(b.to_value()) }).unwrap();
        }
        for (k, h) in &r.secrets.history {
            m.op(a, &ct::SECRETS, PathOp { path: vec![PathSeg::Field(1), PathSeg::Key(k.to_value())], op: Op::Set(Value::Bytes(h.clone())) }).unwrap();
        }
        for (role, ks) in &r.keys.keysets {
            let f = osis_keys::aspects::keyset_field(*role);
            m.op(a, &ct::KEYS, PathOp { path: vec![PathSeg::Field(f)], op: Op::Replace(Some(ks.clone()).to_value()) }).unwrap();
        }
    };
    let mut m = Mutation::new();
    write(&mut m, &r0);
    m.op(a, &ct::KEYS, PathOp { path: vec![PathSeg::Field(5)], op: Op::Replace(Some([7u8; 32]).to_value()) }).unwrap();
    e.commit(m).unwrap().unwrap();
    // holders with a read keyset each, in commits of a hundred
    let ep = Epoch::new(1, [3; 32]).unwrap();
    let template = r0.keys.keysets.get(&Role::Read).unwrap().clone();
    let mut holders = own.to_vec();
    for batch in 0..21u8 {
        let mut m = Mutation::new();
        for i in 0..100u8 {
            let kem = KeyActorKeys::from_seed(&Secret32::from_bytes([batch, i, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9])).kem.public().clone();
            let h = e.new_thing(&mut m, me);
            let ks = ct::Keyset { kem_key: ct::KemKey::X25519MlKem768(kem.as_bytes().to_vec()), ..template.clone() };
            m.op(h, &ct::KEYS, PathOp { path: vec![PathSeg::Field(0)], op: Op::Replace(Some(ks).to_value()) }).unwrap();
            m.op(a, &ct::ROLES, PathOp { path: vec![PathSeg::Key(Value::Tid(h))], op: Op::Set(ct::Edge { role: Role::Read, until: None, invite: None, tied: None }.to_value()) }).unwrap();
            holders.push(Recipient { holder: h, role: Role::Read, keys: HolderKeys::Actor { keysets: [(Role::Read, vec![(ep, kem)])].into_iter().collect(), own: BTreeMap::new() } });
        }
        e.commit_hostile(m).unwrap().unwrap();
    }
    // the rotation boxing every holder, with the sync ID (spec/sync-ids.md §2)
    e.give_own_secrets(&a).unwrap();
    let label = e.label_of(&a).unwrap().unwrap().0;
    let labels = e.get_typed(&a, &ct::LABEL).unwrap().unwrap();
    let claims = labels.values().flat_map(|l| l.steps.values()).filter_map(|s| s.claims.as_ref()).map(Vec::len).max().unwrap();
    println!("label {label:?} for 2100 readers: {claims} B of claims");
    assert!(claims > osis_base::format::CHUNK_THRESHOLD, "{claims}");
}

/// Writer `c` holds write on g only through team `team` (an actor with secrets of its own that g's
/// actor may not read; `listed`: also an item of g, so in g's closure), and writes an item of g:
/// whether reader `b`, which never reads the team, reads it.
fn write_through_a_team(listed: bool) -> Option<osis_base::Value> {
    let (mut net, host, [a, b, c]) = crate::net::hosted_nodes::<3>();
    let g = net.group(a, &[(b, Role::Read)], &[host]);
    let team = net.group(a, &[], &[host]);
    net.grant(a, g, team, Role::Write);
    if listed {
        let mut def = net.engine(a).get_typed(&g, &ct::GROUP).unwrap().unwrap_or_default();
        def.items.insert(team);
        let mut m = Mutation::new();
        m.set(g, &ct::GROUP, &def).unwrap();
        net.engine(a).commit(m).unwrap();
    }
    net.run();
    for _ in 0..3 {
        net.advance(15_000);
    }
    // c joins the team once g's closure holds it everywhere
    net.pair(c, a);
    let writer = net.tid(c);
    net.grant(a, team, writer, Role::Write);
    net.pair(a, c);
    net.run();
    for _ in 0..3 {
        net.advance(15_000);
    }
    assert!(!net.engine(a).may_read(&g, &team), "g's actor does not read the team");
    let w = net.item(c, g, g, "w");
    net.run();
    for _ in 0..3 {
        net.advance(15_000);
    }
    assert_eq!(net.read(a, w), Some(s("w")), "the team's admin reads it");
    net.read(b, w)
}

// spec/sync-judgement.md §1 (entitlement), spec/permissions.md §4 (Logging certificates): a part g's actor may not read
// reaches g's readers as a certificate copy whether or not its thing is in g's closure. Writer c
// holds write on g through a team g does not read; listed as an item of g or not, a reader of g
// gets the team's edge to c with c's write, and reads it.
#[test]
fn a_chain_through_an_unread_closure_thing_reaches_readers_spec_sync_3() {
    assert_eq!(write_through_a_team(false), Some(s("w")), "the team outside g's closure");
    assert_eq!(write_through_a_team(true), Some(s("w")), "the team an item of g");
}

// spec/permissions.md §3 (a removal and the new `keys.0` go under the labels the removed party
// could read), spec/sync-judgement.md §1 (entitlement): team `team` is listed in g, which does not read it
// and on which it holds no role. Removing c from the team leaves g's label without the removal:
// reader b of g, who never reads the team, gets no entry of it.
#[test]
fn a_removal_from_an_unread_closure_thing_stays_off_its_group_spec_permissions_3() {
    let (mut net, host, [a, b, c]) = crate::net::hosted_nodes::<3>();
    let g = net.group(a, &[(b, Role::Read)], &[host]);
    let team = net.group(a, &[(c, Role::Write)], &[host]);
    let mut def = net.engine(a).get_typed(&g, &ct::GROUP).unwrap().unwrap_or_default();
    def.items.insert(team);
    let mut m = Mutation::new();
    m.set(g, &ct::GROUP, &def).unwrap();
    net.engine(a).commit(m).unwrap();
    net.run();
    for _ in 0..3 {
        net.advance(15_000);
    }
    assert!(net.engine(a).closure(&g).contains(&team) && !net.engine(a).may_read(&g, &team), "the team in g's closure, unread");
    let x = net.tid(c);
    let d = osis_node::flows::Demotion { holder: x, new: None, retain: None };
    let done = net.engine(a).demote(&team, &d).unwrap();
    let removal = *done.commits.last().unwrap();
    let acts = net.sync(a).carry_out(done).unwrap();
    net.actions(a, acts);
    net.run();
    for _ in 0..3 {
        net.advance(15_000);
    }
    let l = net.group_labels(b).into_iter().find(|(y, _)| *y == g).unwrap().1.id;
    let named = |k: &osis_node::sync::EntryKind| matches!(k, osis_node::sync::EntryKind::Commit { commit, .. } | osis_node::sync::EntryKind::Awaits { commit, .. } if *commit == removal);
    assert!(!net.sync(b).entries(&l).iter().any(|(_, k)| named(k)), "the removal is under g's label");
}

/// Team `team` is listed in g (which does not read it) and in h (whose actor holds read on it),
/// and holds write on `doc`; a removes the team from doc. Whether reader b of g, and of h, gets an
/// entry of that removal under g's and h's labels.
fn team_removal_reaches() -> (bool, bool) {
    let (mut net, host, [a, b]) = crate::net::hosted_nodes::<2>();
    let g = net.group(a, &[(b, Role::Read)], &[host]);
    let h = net.group(a, &[(b, Role::Read)], &[host]);
    let team = net.group(a, &[], &[host]);
    let doc = net.group(a, &[], &[host]);
    net.grant(a, doc, team, Role::Write);
    net.grant(a, team, h, Role::Read);
    for x in [g, h] {
        let mut def = net.engine(a).get_typed(&x, &ct::GROUP).unwrap().unwrap_or_default();
        def.items.insert(team);
        let mut m = Mutation::new();
        m.set(x, &ct::GROUP, &def).unwrap();
        net.engine(a).commit(m).unwrap();
    }
    net.run();
    for _ in 0..3 {
        net.advance(15_000);
    }
    let e = net.engine(a);
    assert!(e.closure(&g).contains(&team) && !e.may_read(&g, &team), "the team in g's closure, unread");
    assert!(e.closure(&h).contains(&team) && e.may_read(&h, &team), "the team in h's closure, read");
    let d = osis_node::flows::Demotion { holder: team, new: None, retain: None };
    let done = net.engine(a).demote(&doc, &d).unwrap();
    let removal = *done.commits.last().unwrap();
    let acts = net.sync(a).carry_out(done).unwrap();
    net.actions(a, acts);
    net.run();
    for _ in 0..3 {
        net.advance(15_000);
    }
    let named = |k: &osis_node::sync::EntryKind| matches!(k, osis_node::sync::EntryKind::Commit { commit, .. } | osis_node::sync::EntryKind::Awaits { commit, .. } if *commit == removal);
    let labels = net.group_labels(b);
    let mut under = |x: osis_base::Tid| {
        let l = labels.iter().find(|(y, _)| *y == x).unwrap().1.id;
        net.sync(b).entries(&l).iter().any(|(_, k)| named(k))
    };
    (under(g), under(h))
}

// spec/permissions.md §3 (a removal of another actor's grant goes under the labels holding it),
// spec/sync-judgement.md §1 (entitlement): a label holds the team only where its actor reads it. The team's
// removal from doc stays off the label of g, which lists the team unread, and reaches the label
// of h, which reads it.
#[test]
fn a_removal_of_an_unread_closure_things_grant_stays_off_its_group_spec_permissions_3() {
    assert_eq!(team_removal_reaches(), (false, true), "(under g, under h)");
}
