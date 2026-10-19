#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Labeling on hand-built groups (spec/sync.md §1-§3, §5; spec/crypto.md §5, §7): entitlement,
//! projection by retention class, wraps, head keys, delete tokens.

mod net;
use net::*;
use osis_core::{Role, WallMs};
use osis_label::Prefix;
use osis_node::Mutation;
use osis_node::labeling::{open_commit, seal_body};
use osis_crypto::SeededRng;

// spec/sync.md §3 (entitlement): a shared folder's label holds what its actor may read: items
// it owns and the folder's own writes; an item of another owner dropped into `/group` without
// an edge is silently not shared (only the folder's `/group` delta goes).
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
    let touched = |t: osis_core::Tid, e: &mut osis_node::Engine| {
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
// the expiry and the token commitments of its class, and opens against its header.
#[test]
fn projection_by_retention_class_spec_sync_3() {
    let mut net = Net::new();
    let a = net.node(1, &[]);
    let b = net.node(2, &[]);
    let g = net.group(a, &[(b, Role::Write)], &[]);
    let t = net.item(a, g, g, "x");
    let mut m = Mutation::new();
    m.set(t, &REG, &s("kept")).unwrap();
    m.set(t, &BRIEF, &s("brief")).unwrap();
    m.set(t, &GONE, &s("gone")).unwrap();
    let c = net.engine(a).commit(m).unwrap().unwrap();
    let bodies = net.engine(a).bodies(&c).unwrap();
    assert_eq!(bodies.len(), 3, "three retention classes, one reader");
    let expiring: Vec<_> = bodies.iter().filter(|b| b.expires.is_some()).collect();
    assert_eq!(expiring.len(), 1);
    let mut rng = SeededRng::from_u64(5);
    for body in &bodies {
        let sealed = seal_body(body, &mut rng).unwrap();
        let p = Prefix::parse(&sealed.blob).unwrap();
        assert_eq!(p.expiry(), body.expires.map(WallMs));
        assert_eq!(p.commitments().len(), body.tokens.len());
        let (_, cb) = open_commit(&sealed.blob, &sealed.key).unwrap();
        assert_eq!(cb.parts.iter().map(|x| (x.ai, x.di)).collect::<Vec<_>>(), body.parts);
        // two encryptions of one body are unlinkable blobs
        assert_ne!(seal_body(body, &mut rng).unwrap().id, sealed.id);
    }
}

// spec/crypto.md §5: content is wrapped under the newest current read epoch; a rotation commit
// under the epoch it supersedes, so the members it seals to can open it.
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
// opens (sync key) and deposits, an admin also holds the delete key; tokens of a `writer` body
// match its blob's commitments for a holder of the thing's write secret.
#[test]
fn head_keys_and_tokens_spec_sync_5() {
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
    let toks = net.engine(b).tokens_of(&c, &body.parts);
    assert!(toks.iter().any(|(lvl, t)| *lvl == 3 && p.match_token(t.expose()) == Some(3)), "a writer derives the level-3 token: {:?}", toks.iter().map(|x| x.0).collect::<Vec<_>>());
    net.pair(a, r);
    assert!(net.engine(r).tokens_of(&c, &body.parts).iter().all(|(lvl, _)| *lvl != 3));
}
