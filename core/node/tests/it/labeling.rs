#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Labeling on hand-built groups (spec/sync.md §1-§3, §5; spec/crypto.md §5, §7): entitlement,
//! projection by retention class, wraps, head keys, delete keys.

use crate::net;
use net::*;
use osis_base::{Role, WallMs};
use osis_label::Prefix;
use osis_node::Mutation;
use osis_node::labeling::{open_commit, seal_body};
use osis_crypto::SeededRng;

// spec/sync.md §3 (entitlement): a shared folder's label holds what its actor may read: items
// it owns and the folder's own writes; an item of another owner dropped into `group.0` without
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
            b.parts.iter().any(|(ai, _)| h.aspects[*ai].tid == t)
        })
    };
    assert!(touched(inside, e));
    assert!(!touched(outside, e), "a thing the group's actor cannot read is not under its label");
    assert!(touched(g, e));
}

// spec/sync.md §1, §3: one blob per (reader actor, retention class); each blob's prefix carries
// the commit's expiry and the delete-key commitments of its class, and opens against its header.
#[test]
fn projection_by_retention_class_spec_sync_3() {
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
    let bodies = net.engine(a).bodies(&c).unwrap();
    assert_eq!(bodies.len(), 3, "three retention classes, one reader");
    assert!(bodies.iter().all(|b| b.expires == Some(at.0)), "the commit's expiry");
    let mut rng = SeededRng::from_u64(5);
    for body in &bodies {
        let sealed = seal_body(body, &mut rng).unwrap();
        let p = Prefix::parse(&sealed.blob).unwrap();
        assert_eq!(p.expiry(), body.expires.map(WallMs));
        assert_eq!(p.commitments().len(), body.keys.len());
        let (_, cb) = open_commit(&sealed.blob, &sealed.key).unwrap();
        assert_eq!(cb.parts.iter().map(|x| (x.ai, x.di)).collect::<Vec<_>>(), body.parts);
        // two encryptions of one body are unlinkable blobs
        assert_ne!(seal_body(body, &mut rng).unwrap().id, sealed.id);
    }
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
    let parts: Vec<(usize, usize)> = (0..e.header(&c).unwrap().aspects.len()).map(|i| (i, 0)).collect();
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
    let body = net.engine(a).bodies(&c).unwrap().remove(0);
    let sealed = seal_body(&body, &mut SeededRng::from_u64(3)).unwrap();
    let p = Prefix::parse(&sealed.blob).unwrap();
    let ds = net.engine(b).delete_secrets_of(&c, &body.parts);
    let d = [7u8; 32];
    let k3 = p.key_at(3).unwrap();
    assert!(ds.iter().any(|(lvl, dk)| *lvl == 3 && osis_crypto::verify_delete(&k3, &d, &dk.sign(p.salt(), &body.blind, &d)).is_ok()), "a writer holds the level-3 key: {:?}", ds.iter().map(|x| x.0).collect::<Vec<_>>());
    net.pair(a, r);
    assert!(net.engine(r).delete_secrets_of(&c, &body.parts).is_empty());
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
