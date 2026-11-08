#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Labeling on hand-built groups (spec/sync.md §1-§3, §5; spec/crypto.md §5, §7): entitlement,
//! one blob per commit with its prefix groups, wraps, head keys, delete keys.

use crate::net;
use net::*;
use osis_base::{Role, WallMs};
use osis_label::Prefix;
use osis_node::Mutation;
use osis_crypto::SeededRng;

// spec/sync.md §3 (entitlement): a shared folder's label holds what its actor may read: items
// below it and the folder's own writes; an item under another first admin dropped into `group.0` without
// an edge is silently not shared (only the folder's `group.0` delta goes).
#[test]
fn shared_folder_entitlement_spec_sync_3() {
    let mut net = Net::new();
    let a = net.node(1, &[]);
    let b = net.node(2, &[]);
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

// spec/sync.md §1, §3, spec/wire.md §5: one blob per commit whatever its retention classes; its
// prefix carries the commit's expiry and one commitment group per distinct delete-key set, and
// opens against its header.
#[test]
fn one_blob_prefix_groups_per_key_set_spec_wire_5() {
    let mut net = Net::new();
    let a = net.node(1, &[]);
    let b = net.node(2, &[]);
    let g = net.group(a, &[(b, Role::Write)], &[]);
    let t = net.item(a, g, g, "x");
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
    let mut rng = SeededRng::from_u64(5);
    let sealed = net.engine(a).seal(&body, osis_label::Class::Durable, &[], &mut rng).unwrap().unwrap();
    let p = Prefix::parse(&sealed.blob).unwrap();
    assert_eq!(p.expiry(), body.expires.map(WallMs));
    assert_eq!(p.groups().len(), sets.len(), "one group per distinct key set");
    assert!(p.groups().len() >= 2);
    let o = net.engine(a).open_commit(&sealed.blob, &sealed.key, None).unwrap();
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
    let mut net = Net::new();
    let a = net.node(1, &[]);
    let b = net.node(2, &[]);
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

// spec/sync.md §5, spec/crypto.md §4: a writer stamps with the head's write key, a reader only
// opens (sync key) and deposits, an admin also holds the delete key; a holder of the thing's
// write secret signs for the level-3 commitment of a `writer` body; a reader holds no delete key.
#[test]
fn head_keys_and_delete_keys_spec_sync_5() {
    let mut net = Net::new();
    let a = net.node(1, &[]);
    let b = net.node(2, &[]);
    let r = net.node(3, &[]);
    let g = net.group(a, &[(b, Role::Write), (r, Role::Read)], &[]);
    let (_, l) = net.sync(a).labels().into_iter().next().unwrap();
    let head = l.steps.values().next().unwrap().0.clone();
    let ka = net.engine(a).head_keys(&g, l.index, &head).unwrap();
    assert!(ka.sync.is_some() && ka.write.is_some() && ka.delete.is_some() && ka.deposit.is_some());
    let kb = net.engine(b).head_keys(&g, l.index, &head).unwrap();
    assert!(kb.sync.is_some() && kb.write.is_some() && kb.delete.is_none());
    let kr = net.engine(r).head_keys(&g, l.index, &head).unwrap();
    assert!(kr.sync.is_some() && kr.write.is_none() && kr.delete.is_none() && kr.deposit.is_some());
    let t = net.item(a, g, g, "x");
    let mut m = Mutation::new();
    m.set(t, &GONE, &s("gone")).unwrap();
    let c = net.engine(a).commit(m).unwrap().unwrap();
    net.pair(a, b);
    let body = net.engine(a).body(&c).unwrap().unwrap();
    let sealed = net.engine(a).seal(&body, osis_label::Class::Durable, &[], &mut SeededRng::from_u64(3)).unwrap().unwrap();
    let p = Prefix::parse(&sealed.blob).unwrap();
    let ds = net.engine(b).delete_secrets_of(&c, &sealed.ais).remove(0);
    let d = [7u8; 32];
    let k3 = p.key_at(0, 3).unwrap();
    assert!(ds.iter().any(|(lvl, dk)| *lvl == 3 && osis_crypto::verify_delete(&k3, &d, &dk.sign(p.salt(), &body.blind, &d)).is_ok()), "a writer holds the level-3 key: {:?}", ds.iter().map(|x| x.0).collect::<Vec<_>>());
    net.pair(a, r);
    assert!(net.engine(r).delete_secrets_of(&c, &sealed.ais).iter().all(Vec::is_empty));
}

// spec/sync.md §2 (growth, notes/growth.md): an admin's `label.0` write drops the claim sets
// (entry boxes with them) of the steps superseded for `ROLE_KEEP`; the newer ones stay.
#[test]
fn old_claim_sets_dropped_spec_sync_2() {
    use osis_schema::core_types as ct;
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let g = net.group(a, &[], &[host]);
    net.run();
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
#[ignore = "tier 2: 2100 holders"]
fn registration_of_thousands_of_readers() {
    use osis_base::Value;
    use osis_crdt::{Op, PathOp, PathSeg};
    use osis_crypto::{Epoch, KeyActorKeys, Secret32};
    use osis_keys::{HolderKeys, Recipient, rotate};
    use osis_schema::core_types as ct;
    use osis_schema::{Codec, RawKey};
    use std::collections::{BTreeMap, BTreeSet};
    let mut lp = crate::common::net(1, 7);
    let e = &mut lp.peers[0].engine;
    let me = e.tid();
    let mut m = Mutation::new();
    let a = e.new_thing(&mut m, me);
    e.commit(m).unwrap().unwrap();
    let all = BTreeSet::from([Role::Read, Role::Write, Role::Admin]);
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
            let f = match role {
                Role::Read => 0,
                Role::Write => 1,
                Role::Admin => 2,
            };
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
            holders.push(Recipient { holder: h, role: Role::Read, keys: HolderKeys::Actor { keysets: [(Role::Read, (ep, kem))].into_iter().collect(), own: BTreeMap::new() } });
        }
        e.commit_hostile(m).unwrap().unwrap();
    }
    let view = e.epochs(&a).unwrap();
    let state = e.get(&a, &crate::common::ak("secrets.0")).unwrap().map(|v| ct::SECRETS.decode(&v).unwrap()).unwrap_or_default();
    let r = rotate(&a, &BTreeSet::from([Role::Read]), &view, &state, &holders, &osis_keys::Names::default(), &mut SeededRng::from_u64(1)).unwrap();
    let mut m = Mutation::new();
    write(&mut m, &r);
    e.commit_hostile(m).unwrap().unwrap();
    let (label, _) = e.create_label(&a, &[]).unwrap();
    let labels = e.get_typed(&a, &ct::LABEL).unwrap().unwrap();
    let claims = labels.values().flat_map(|l| l.steps.values()).filter_map(|s| s.claims.as_ref()).map(Vec::len).max().unwrap();
    println!("label {label:?} for 2100 readers: {claims} B of claims");
    assert!(claims > osis_base::format::CHUNK_THRESHOLD, "{claims}");
}
