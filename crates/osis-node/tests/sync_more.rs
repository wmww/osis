#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Certificates and heartbeats, pages and lazy chunks, reconciliation, inbox blobs through a
//! blind node (spec/sync.md §3, §6; spec/permissions.md §4).

mod net;
use net::*;
use osis_core::{Ak, Role, Value};
use osis_node::Mutation;
use osis_node::sync::{EntryKind, SyncConfig};
use osis_schema::AspectKey;
use osis_schema::core_types as ct;
use osis_server::Policy;
use std::collections::BTreeSet;

fn diags(net: &mut Net, nodes: &[usize]) {
    for n in nodes {
        let d = net.sync(*n).take_diagnostics();
        if !d.is_empty() {
            eprintln!("node {n}: {d:?}");
        }
    }
}

/// Commits under label `l` that `n` knows, with the aspects their headers touch.
fn commits_under(net: &mut Net, n: usize, l: &osis_core::LabelId) -> Vec<(osis_core::CommitId, osis_core::Tid, BTreeSet<String>)> {
    let entries = net.sync(n).entries(l);
    let mut out = Vec::new();
    for (_, k) in entries {
        if let EntryKind::Commit { commit, .. } = k
            && let Some(h) = net.engine(n).header(&commit)
        {
            out.push((commit, h.author, h.aspects.iter().map(|a| a.ak.as_str().to_string()).collect()));
        }
    }
    out
}

// spec/permissions.md §4, spec/sync.md §3, §5: every node placing under a label puts its node
// card and heartbeat there, a reader by deposit; co-members apply them.
#[test]
fn certificates_and_heartbeats_spec_permissions_4() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let r = net.node(2, &[sv]);
    let _g = net.group(a, &[(r, Role::Read)], &[sv]);
    net.run();
    // a deposit is promoted after a writer's relay wait (spec/sync.md §5)
    net.advance(30_000);
    diags(&mut net, &[a, r]);
    let l = net.label(a);
    let rt = net.tid(r);
    let under = commits_under(&mut net, a, &l);
    let by_r: Vec<&BTreeSet<String>> = under.iter().filter(|(_, au, _)| *au == rt).map(|(_, _, a)| a).collect();
    assert!(by_r.iter().any(|a| a.contains("/node")), "the reader's node card: {under:?}");
    assert!(by_r.iter().any(|a| a.contains("/seen")), "the reader's heartbeat");
    let seen = net.engine(a).get_typed(&rt, &ct::SEEN).unwrap().unwrap();
    assert!(!seen.stranded);
    // the writer promoted the reader's deposited card (re-uploaded stamped); never a heartbeat
    let entries = net.sync(a).entries(&l);
    let store = net.servers[sv].hub.store();
    let mut card = 0;
    for (id, k) in entries {
        let EntryKind::Commit { commit, .. } = k else { continue };
        let Some((_, au, aks)) = under.iter().find(|(c, _, _)| *c == commit) else { continue };
        if *au != rt {
            continue;
        }
        let stamped = osis_proto::LabelStore::entry(store, &l, &id).unwrap().unwrap().stamp.is_some();
        if aks.contains("/seen") {
            assert!(!stamped, "heartbeats are never promoted");
        } else if aks.contains("/node") {
            assert!(stamped, "the card was promoted");
            card += 1;
        }
    }
    assert!(card > 0);
    // a heartbeat at most once per interval
    let n = net.server_ids(sv, &l).len();
    net.advance(60_000);
    assert_eq!(net.server_ids(sv, &l).len(), n);
}

// spec/permissions.md §4 (chain certificates per label: what any entry already holds is not
// copied again; closure deltas are never copied): the admin places first, then a writer, then a
// reader; the later ones copy only their own cards, so no delta of any commit sits in two
// entries under the label.
#[test]
fn certificates_once_per_label_spec_permissions_4() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let w = net.node(2, &[sv]);
    let r = net.node(3, &[sv]);
    let _g = net.group(a, &[(w, Role::Write), (r, Role::Read)], &[sv]);
    net.set_online(w, false);
    net.set_online(r, false);
    net.run();
    net.set_online(w, true);
    net.run();
    net.set_online(r, true);
    net.run();
    let l = net.label(a);
    let ids: BTreeSet<osis_core::BlobId> = net.server_ids(sv, &l).into_iter().collect();
    let mut held: std::collections::BTreeMap<osis_core::CommitId, Vec<(usize, usize)>> = Default::default();
    for (id, k) in net.sync(a).entries(&l) {
        if let EntryKind::Commit { commit, parts, .. } = k
            && ids.contains(&id)
        {
            let seen = held.entry(commit).or_default();
            assert!(parts.iter().all(|p| !seen.contains(p)), "a delta of {commit:?} twice under the label");
            seen.extend(parts);
        }
    }
    for n in [w, r] {
        let t = net.tid(n);
        assert!(held.keys().any(|c| net.engine(a).header(c).is_some_and(|h| h.author == t && h.aspects.iter().any(|x| x.ak.as_str() == "/node"))), "node {n}'s card is there");
    }
}

// spec/sync.md §6, spec/commits.md §4: pages of a paged delta are fetched before its commit
// applies; chunks of a large value are fetched lazily, on demand.
#[test]
fn pages_and_lazy_chunks_spec_sync_6() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.add_node(2, SyncConfig { servers: vec![net.address(sv)], inline_limit: 0, ..SyncConfig::default() });
    let g = net.group(a, &[(b, Role::Read)], &[sv]);
    let t = net.item(a, g, g, "x");
    let big: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    let map: std::collections::BTreeMap<Value, Value> = (0..2000).map(|i| (Value::Str(format!("key {i:05}")), Value::Str("v".repeat(60)))).collect();
    let mut m = Mutation::new();
    m.set(t, &BLOB, &Value::Bytes(big.clone())).unwrap();
    net.engine(a).commit(m).unwrap();
    let mut m = Mutation::new();
    m.set(t, &BIG, &Value::Map(map.clone())).unwrap();
    net.engine(a).commit(m).unwrap();
    net.run();
    diags(&mut net, &[a, b]);
    let big_ak = Ak::new(BIG.ak()).unwrap();
    let got = net.engine(b).get(&t, &big_ak).unwrap();
    assert!(got == Some(Value::Map(map)), "the paged delta applied; pending {:?}", net.engine(b).pending());
    let blob_ak = Ak::new(BLOB.ak()).unwrap();
    assert!(net.engine(b).get_full(&t, &blob_ak).is_err(), "chunks not fetched yet");
    let acts = net.sync(b).fetch_missing();
    net.actions(b, acts);
    net.settle(100_000);
    assert_eq!(net.engine(b).get_full(&t, &blob_ak).unwrap(), Some(Value::Bytes(big)));
}

// spec/sync.md §6: a cursor the server no longer serves (log trimmed) falls back to range
// reconciliation, then a fresh cursor.
#[test]
fn reconciliation_fallback_spec_sync_6() {
    let mut net = Net::new();
    let sv = net.add_server_with(Policy { log_keep: 16, ..Policy::default() });
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let g = net.group(a, &[(b, Role::Read)], &[sv]);
    let t = net.item(a, g, g, "v0");
    net.run();
    net.set_online(b, false);
    for i in 1..40 {
        net.write(a, t, &format!("v{i}"));
        net.run();
    }
    net.set_online(b, true);
    net.advance(10_000);
    diags(&mut net, &[b]);
    assert_eq!(net.read(b, t), Some(s("v39")));
}

// spec/sync.md §2-§3, spec/crypto.md §5: an inbox blob sealed to an actor's read key and
// deposited under its inbox (its home label) is opened by a member device and applied.
#[test]
fn inbox_delivery_spec_sync_3() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let s_ = net.node(3, &[sv]);
    // P: an actor of A (admin) and B, its home label its inbox
    let p = net.group(a, &[(b, Role::Write)], &[sv]);
    let (_, home) = net.sync(a).labels().into_iter().next().unwrap();
    let mut m = Mutation::new();
    let inbox = ct::Inbox { label: home.id, servers: home.servers.clone() };
    m.op(p, &ct::KEYS, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Field(4)], op: osis_crdt::Op::Replace(Some(inbox).to_value()) }).unwrap();
    net.engine(a).commit(m).unwrap();
    net.run();
    // the sender knows P's /keys (paired with A) and B knows the sender's chain
    net.pair(a, s_);
    net.pair(s_, b);
    let me = net.tid(s_);
    let e = net.engine(s_);
    let mut m = Mutation::new();
    let x = e.new_thing(&mut m, me);
    m.set(x, &REG, &s("for P")).unwrap();
    let c = e.commit(m).unwrap().unwrap();
    let all: BTreeSet<usize> = (0..net.engine(s_).header(&c).unwrap().aspects.len()).collect();
    let acts = net.sync(s_).deliver_inbox(&p, &c, &all).unwrap();
    net.actions(s_, acts);
    net.run();
    diags(&mut net, &[s_, b]);
    assert!(net.sync(b).entries(&home.id).iter().any(|(_, k)| matches!(k, EntryKind::Inbox(_))));
    assert_eq!(net.read(b, x), Some(s("for P")));
}

use osis_schema::Codec;

// spec/sync.md §2: a group's `/label` (with its `/created`) is also published under the home
// label of the nearest owner-chain actor that has one, so that actor's other devices find it.
#[test]
fn label_published_under_home_label_spec_sync_2() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let p = net.group(a, &[(b, Role::Write)], &[sv]);
    net.run();
    // a group owned by P, labeled, never delivered to B
    let e = net.engine(a);
    let mut m = Mutation::new();
    let g2 = e.new_thing(&mut m, p);
    m.set(g2, &ct::GROUP, &ct::Group::default()).unwrap();
    e.commit(m).unwrap();
    let at = net.tid(a);
    let e = net.engine(a);
    let rs = recipients_of(e, &[(at, Role::Admin), (p, Role::Admin)]);
    rotation(e, g2, &rs, 71, true);
    let addr = net.address(sv);
    let acts = net.sync(a).create_label(&g2, vec![addr]).unwrap().1;
    net.actions(a, acts);
    let t = net.item(a, g2, g2, "inside");
    net.run();
    net.run();
    diags(&mut net, &[a, b]);
    let labels = net.engine(b).get_typed(&g2, &ct::LABEL).unwrap();
    assert!(labels.is_some_and(|l| l.len() == 1), "B found the group's label through P's home label");
    // B is listed by P's claim key (P owns the group): it claims, downloads the rotation under
    // the epoch it superseded (derived from P's), opens its boxes and reads
    assert_eq!(net.read(b, t), Some(s("inside")));
}

// spec/sync.md §2 (replacement): the admin secret the old label registers is rotated first; a
// new label at the next index takes the live blobs; the old one is marked replaced and no
// longer synced by members; the admin places the replacement's `/label` commit under it,
// deletes its content entries there, and then stops syncing it.
#[test]
fn label_replacement_spec_sync_2() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let g = net.group(a, &[(b, Role::Write)], &[sv]);
    let t = net.item(a, g, g, "kept");
    net.run();
    let old = net.label(a);
    let before: BTreeSet<_> = commits_under(&mut net, a, &old).into_iter().map(|x| x.0).collect();
    let admin0 = net.engine(a).epochs(&g).unwrap().admin.newest_held().unwrap().0;
    let (new, _) = net.sync(a).replace_label(&g, &old).unwrap();
    assert_ne!(net.engine(a).epochs(&g).unwrap().admin.newest_held().unwrap().0, admin0, "the admin secret rotated");
    // the admin restarts before syncing: it reopens the replaced label as well
    net.restart(a, 9);
    net.run();
    net.run();
    diags(&mut net, &[a, b]);
    assert_ne!(new, old);
    let labels: Vec<_> = net.sync(b).labels().into_iter().map(|(_, l)| (l.id, l.index)).collect();
    assert_eq!(labels, vec![(new, 1)], "only the new label is synced");
    assert!(!net.server_ids(sv, &new).is_empty());
    let live: BTreeSet<_> = net.server_ids(sv, &old).into_iter().collect();
    let under: Vec<_> = net.sync(a).entries(&old).into_iter().filter(|(id, _)| live.contains(id)).collect();
    let mut labels_after = 0;
    for (_, k) in under {
        let EntryKind::Commit { commit, .. } = k else { continue };
        let h = net.engine(a).header(&commit).unwrap();
        assert!(h.aspects.iter().all(|x| x.tid != t), "content of the item left under the old label");
        labels_after += usize::from(!before.contains(&commit) && h.aspects.iter().any(|x| x.ak.as_str() == "/label"));
    }
    // the new label's record with the old one marked replaced
    assert_eq!(labels_after, 1, "the replacement's /label commit under the old label");
    let labels: Vec<_> = net.sync(a).labels().into_iter().map(|(_, l)| l.id).collect();
    assert_eq!(labels, vec![new], "the admin is done with the old label");
    net.write(b, t, "on the new label");
    net.run();
    assert_eq!(net.read(a, t), Some(s("on the new label")));
    assert_eq!(net.server_ids(sv, &old).into_iter().collect::<BTreeSet<_>>(), live, "nothing more under the old label");
}

// spec/permissions.md §4, §6; spec/sync.md §3: a node's chain to a group runs node → P → T → G
// by ownership; T's roster snapshot names none of the chain (its member is another node), so
// the certificate copy under G's label carries T's reset-only deltas alone: the verifier, a
// reader of G only, holds the snapshot as an epoch start with an empty roster, as perm's
// certificate closure projects it, and never sees T's member.
#[test]
fn nested_chain_empty_projection_spec_perm_6() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let x = net.node(2, &[sv]);
    let c = net.node(3, &[sv]);
    net.pair(x, a);
    net.pair(c, a);
    let me = net.tid(a);
    let (xt, ct_) = (net.tid(x), net.tid(c));
    let mk = |net: &mut Net, owner| {
        let e = net.engine(a);
        let mut m = Mutation::new();
        let t = e.new_thing(&mut m, owner);
        m.set(t, &REG, &s("t")).unwrap();
        e.commit(m).unwrap();
        t
    };
    let p = mk(&mut net, me);
    let r = recipients_of(net.engine(a), &[(me, Role::Admin)]);
    rotation(net.engine(a), p, &r, 3, true);
    let t = mk(&mut net, p);
    set_edge(net.engine(a), t, xt, Role::Read);
    let g = {
        let e = net.engine(a);
        let mut m = Mutation::new();
        let g = e.new_thing(&mut m, t);
        m.set(g, &ct::GROUP, &ct::Group::default()).unwrap();
        e.commit(m).unwrap();
        g
    };
    set_edge(net.engine(a), g, ct_, Role::Read);
    let r = recipients_of(net.engine(a), &[(me, Role::Admin), (ct_, Role::Read)]);
    rotation(net.engine(a), g, &r, 4, true);
    let addr = net.address(sv);
    net.engine(a).create_label(&g, &[addr]).unwrap();
    net.pair(a, c);
    // the snapshot reaches c only as a certificate copy under G's label (T is outside its closure)
    let done = net.engine(a).roster_snapshot(&t, None).unwrap();
    let snap = *done.commits.last().unwrap();
    let item = net.item(a, g, g, "by a");
    net.run();
    net.run();
    assert_eq!(net.read(c, item), Some(s("by a")));
    let certs = net.engine(a).certificates(&g);
    let parts = certs.get(&snap).expect("T's snapshot is a chain certificate").clone();
    let h = net.engine(a).header(&snap).unwrap();
    assert_eq!(parts.len(), 2, "the two reset-only deltas: {parts:?}");
    assert!(parts.iter().all(|(ai, _)| h.aspects[*ai].tid == t));
    let held = osis_commit::CommitBlob::decode(&net.engine(c).commit_bytes(&snap).unwrap().expect("c holds the snapshot")).unwrap();
    let held: BTreeSet<(usize, usize)> = held.parts.iter().map(|p| (p.ai, p.di)).collect();
    assert_eq!(held, parts, "c holds the reset-only deltas alone");
    assert!(net.engine(c).roster(&t).is_empty(), "T's member is not shown to c");
    let _ = x;
}

/// Whether label `l` at server `s` holds a commit carrying a `/label` write the admin `n` made
/// after `before`.
fn label_commit_at(net: &mut Net, n: usize, s: usize, l: &osis_core::LabelId, before: &BTreeSet<osis_core::CommitId>) -> bool {
    let live: BTreeSet<_> = net.server_ids(s, l).into_iter().collect();
    let entries: Vec<_> = net.sync(n).entries(l).into_iter().filter(|(id, _)| live.contains(id)).collect();
    entries.into_iter().any(|(_, k)| matches!(k, EntryKind::Commit { commit, .. } if !before.contains(&commit) && net.engine(n).header(&commit).is_some_and(|h| h.aspects.iter().any(|x| x.ak.as_str() == "/label"))))
}

// spec/sync.md §2 (replacement): at a server that lost the old label the admin registers its
// recorded path again so the replacement's `/label` commit is found there, then is done.
#[test]
fn replaced_label_reregistered_where_lost_spec_sync_2() {
    let mut net = Net::new();
    let (s0, s1) = (net.add_server(), net.add_server());
    let a = net.node(1, &[s0, s1]);
    let b = net.node(2, &[s0, s1]);
    let g = net.group(a, &[(b, Role::Write)], &[s0, s1]);
    net.item(a, g, g, "kept");
    net.run();
    let old = net.label(a);
    let before: BTreeSet<_> = commits_under(&mut net, a, &old).into_iter().map(|x| x.0).collect();
    net.set_online(a, false);
    net.wipe_server(s1);
    assert!(net.server_path(s1, &old).is_empty());
    net.set_online(a, true);
    let (new, _) = net.sync(a).replace_label(&g, &old).unwrap();
    net.run();
    // past the redial backoff
    net.advance(120_000);
    net.run();
    net.run();
    assert!(!net.server_path(s1, &old).is_empty(), "the old label registered again where it was lost");
    assert!(label_commit_at(&mut net, a, s1, &old, &before), "the replacement /label commit is found there");
    let labels: Vec<_> = net.sync(a).labels().into_iter().map(|(_, l)| l.id).collect();
    assert_eq!(labels, vec![new], "done at both servers");
}

// spec/sync.md §2 (replacement): a server of the old label the admin cannot reach never settles a
// pass; the admin stops syncing the old label after `MEMBERSHIP_KEEP` all the same.
#[test]
fn replaced_label_retired_with_server_unreachable_spec_sync_2() {
    let mut net = Net::new();
    let (s0, s1) = (net.add_server(), net.add_server());
    let a = net.node(1, &[s0, s1]);
    let b = net.node(2, &[s0, s1]);
    let g = net.group(a, &[(b, Role::Write)], &[s0, s1]);
    net.item(a, g, g, "kept");
    net.run();
    let old = net.label(a);
    net.set_online(a, false);
    net.blocked.insert((a, s1));
    net.set_online(a, true);
    let (new, _) = net.sync(a).replace_label(&g, &old).unwrap();
    net.run();
    net.run();
    let labels: BTreeSet<_> = net.sync(a).labels().into_iter().map(|(_, l)| l.id).collect();
    assert_eq!(labels, BTreeSet::from([new, old]), "not done at the unreachable server");
    net.advance(osis_core::format::MEMBERSHIP_KEEP_MS + 1);
    net.run();
    let labels: Vec<_> = net.sync(a).labels().into_iter().map(|(_, l)| l.id).collect();
    assert_eq!(labels, vec![new], "retired after MEMBERSHIP_KEEP");
}

// spec/sync.md §3 (inbox), spec/crypto.md §4 (secrets of a pending commit kept for reading;
// decided): a grant reaches another person's device only as an inbox
// blob; it opens the pending grant's boxes, reaches the group's label from the blob's hints,
// downloads the group's chain and content, and the grant applies.
#[test]
fn grant_by_inbox_end_to_end_spec_sync_3() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let addr = net.address(sv);
    let (alice, done) = net.engine(a).create_person(std::slice::from_ref(&addr)).unwrap();
    let acts = net.sync(a).carry_out(done).unwrap();
    net.actions(a, acts);
    let (bob, done) = net.engine(b).create_person(std::slice::from_ref(&addr)).unwrap();
    let acts = net.sync(b).carry_out(done).unwrap();
    net.actions(b, acts);
    net.run();
    // Alice's device knows Bob's card (his `/keys`), nothing more travels directly
    net.pair(b, a);
    let e = net.engine(a);
    let mut m = Mutation::new();
    let g = e.new_thing(&mut m, alice.person);
    m.set(g, &ct::GROUP, &ct::Group::default()).unwrap();
    e.commit(m).unwrap();
    // label, grant, content, then the first sync
    let (_, done) = net.engine(a).create_label(&g, &[addr]).unwrap();
    let acts = net.sync(a).carry_out(done).unwrap();
    net.actions(a, acts);
    let edge = ct::Edge { role: Role::Read, until: None, invite: None, since: None };
    let done = net.engine(a).grant(&g, &bob.person, &edge).unwrap();
    assert!(done.deliveries.iter().any(|d| matches!(d, osis_node::flows::Delivery::Inbox { .. })));
    let acts = net.sync(a).carry_out(done).unwrap();
    net.actions(a, acts);
    let t = net.item(a, g, g, "for bob");
    for _ in 0..3 {
        net.advance(70_000);
    }
    diags(&mut net, &[a, b]);
    assert!(net.engine(b).pending().is_empty(), "the grant applied: {:?}", net.engine(b).pending());
    assert_eq!(net.read(b, t), Some(s("for bob")));
}

// spec/sync.md §2, §5 (static entries): a recovery key held on a fresh device opens its
// person's home label by static entry, takes the read secret from the head's entry box and
// downloads what the label holds.
#[test]
fn static_entry_opens_home_label_spec_sync_5() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let c = net.node(3, &[sv]);
    let addr = net.address(sv);
    let (alice, done) = net.engine(a).create_person(std::slice::from_ref(&addr)).unwrap();
    let acts = net.sync(a).carry_out(done).unwrap();
    net.actions(a, acts);
    let t = net.item(a, alice.person, alice.person, "on the card's label");
    net.run();
    let card = alice.card.clone();
    let rk = net.engine(c).hold_key_actor(card.seed.clone()).unwrap();
    let acts = net.sync(c).follow(rk, card.person, card.home_label, card.servers.clone());
    net.actions(c, acts);
    net.run();
    net.run();
    diags(&mut net, &[c]);
    assert_eq!(net.read(c, t), Some(s("on the card's label")));
}

// spec/crypto.md §4, spec/permissions.md §3, spec/sync.md §3: a grant by inbox carries the
// history boxes of the epochs it boxes: the grantee reads content placed before the grant and
// the grant does not stay pending.
#[test]
fn grant_by_inbox_reads_earlier_content_spec_crypto_4() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let addr = net.address(sv);
    let (alice, done) = net.engine(a).create_person(std::slice::from_ref(&addr)).unwrap();
    let acts = net.sync(a).carry_out(done).unwrap();
    net.actions(a, acts);
    let (bob, done) = net.engine(b).create_person(std::slice::from_ref(&addr)).unwrap();
    let acts = net.sync(b).carry_out(done).unwrap();
    net.actions(b, acts);
    net.run();
    net.pair(b, a);
    let e = net.engine(a);
    let mut m = Mutation::new();
    let g = e.new_thing(&mut m, alice.person);
    m.set(g, &ct::GROUP, &ct::Group::default()).unwrap();
    e.commit(m).unwrap();
    let (_, done) = net.engine(a).create_label(&g, &[addr]).unwrap();
    let acts = net.sync(a).carry_out(done).unwrap();
    net.actions(a, acts);
    // content first, synced up, then the grant
    let t = net.item(a, g, g, "before bob");
    for _ in 0..3 {
        net.advance(70_000);
    }
    let edge = ct::Edge { role: Role::Read, until: None, invite: None, since: None };
    let done = net.engine(a).grant(&g, &bob.person, &edge).unwrap();
    let acts = net.sync(a).carry_out(done).unwrap();
    net.actions(a, acts);
    for _ in 0..3 {
        net.advance(70_000);
    }
    diags(&mut net, &[a, b]);
    assert!(net.engine(b).pending().is_empty(), "the grant applied: {:?}", net.engine(b).pending());
    assert_eq!(net.read(b, t), Some(s("before bob")));
}

// spec/crdt.md §9, §4.7; spec/permissions.md §4: a heartbeat writes `/seen` whole, so the
// expiry of an earlier heartbeat takes no field of a later one.
#[test]
fn heartbeat_outlives_earlier_spec_permissions_4() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let r = net.node(2, &[sv]);
    let _g = net.group(a, &[(r, Role::Read)], &[sv]);
    net.run();
    let at = net.tid(a);
    // a second heartbeat shortly before the first one's expiry (two days), which then passes
    // within the interval (no third heartbeat yet)
    net.advance(44 * 3_600_000);
    net.advance(5 * 3_600_000);
    let seen = net.engine(a).get_typed(&at, &ct::SEEN).unwrap().unwrap();
    assert!(!seen.stranded);
    assert!(net.sync(a).take_diagnostics().iter().all(|d| !d.contains("missing field")));
}

/// Seeded pseudo-random bytes.
fn noise(n: usize, seed: u64) -> Vec<u8> {
    let mut v = vec![0u8; n];
    osis_crypto::RngCore::fill_bytes(&mut osis_crypto::SeededRng::from_u64(seed), &mut v);
    v
}

// spec/sync.md §1 (a reused chunk keeps its blob), §7 (chunk blobs still linked from a retained
// version are kept); spec/commits.md §5 (a purge drops every body carrying the values): purging
// a version whose chunks the next version reuses deletes only the chunks only it reached, at
// the server and locally; the shared ones still read through the live version, also at a
// reader that fetches them afterwards.
#[test]
fn purge_shreds_only_unique_chunks_spec_sync_7() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let g = net.group(a, &[(b, Role::Read)], &[sv]);
    let t = net.item(a, g, g, "x");
    let blob_ak = Ak::new(BLOB.ak()).unwrap();
    let v1 = noise(1 << 20, 7);
    let mut m = Mutation::new();
    m.set(t, &BLOB, &Value::Bytes(v1.clone())).unwrap();
    let c1 = net.engine(a).commit(m).unwrap().unwrap();
    net.run();
    let mut v2 = v1.clone();
    v2.splice(600_000..600_000, noise(100, 8));
    let mut m = Mutation::new();
    m.set(t, &BLOB, &Value::Bytes(v2.clone())).unwrap();
    let c2 = net.engine(a).commit(m).unwrap().unwrap();
    net.run();
    let ids = |net: &mut Net, c| -> BTreeSet<osis_core::BlobId> { net.engine(a).package(&c).unwrap().unwrap().blobs.into_iter().map(|(id, _)| id).collect() };
    let (first, second) = (ids(&mut net, c1), ids(&mut net, c2));
    let live = net.engine(a).live_trees(&t).unwrap();
    assert!(live.missing.is_empty());
    let live = live.blobs;
    let shared: BTreeSet<_> = first.intersection(&live).copied().collect();
    let unique: BTreeSet<_> = first.difference(&live).copied().collect();
    assert!(shared.len() > unique.len() && !unique.is_empty(), "shared {} unique {}", shared.len(), unique.len());
    assert!(second.is_disjoint(&first), "reused chunks are not listed again");
    let l = net.label(a);
    let at_server = |net: &Net| -> BTreeSet<osis_core::BlobId> { net.server_ids(sv, &l).into_iter().collect() };
    assert!(first.is_subset(&at_server(&net)));
    let mut m = Mutation::new();
    m.set(t, &REG, &s("purged v1")).unwrap();
    m.purge(osis_commit::PurgeItem::Commit { commit: c1, tid: t, ak: blob_ak.clone() });
    net.engine(a).commit(m).unwrap().unwrap();
    net.run();
    diags(&mut net, &[a, b]);
    let server = at_server(&net);
    assert!(unique.is_disjoint(&server), "a chunk only the purged version reached is gone at the server");
    assert!(shared.is_subset(&server), "shared chunks stay");
    for id in &unique {
        assert!(net.engine(a).blob(id).unwrap().is_none(), "unique chunk kept locally");
    }
    assert_eq!(net.engine(a).get_full(&t, &blob_ak).unwrap(), Some(Value::Bytes(v2.clone())));
    let acts = net.sync(b).fetch_missing();
    net.actions(b, acts);
    net.settle(100_000);
    assert_eq!(net.engine(b).get_full(&t, &blob_ak).unwrap(), Some(Value::Bytes(v2)));
}

/// Commits in the order server `s` logged their blobs under `l` (blob IDs mapped through node
/// `n`'s entries; first appearance).
fn logged_commits(net: &mut Net, s: usize, n: usize, l: &osis_core::LabelId) -> Vec<osis_core::CommitId> {
    use osis_proto::LabelStore;
    let of: std::collections::BTreeMap<osis_core::BlobId, osis_core::CommitId> =
        net.sync(n).entries(l).into_iter().filter_map(|(id, k)| if let EntryKind::Commit { commit, .. } = k { Some((id, commit)) } else { None }).collect();
    let log = net.servers[s].hub.store().log_after(l, 0, 100_000).unwrap().unwrap();
    let mut out = Vec::new();
    for (_, r) in log {
        if let osis_proto::LogRecord::Added(id) = r
            && let Some(c) = of.get(&id)
            && !out.contains(c)
        {
            out.push(*c);
        }
    }
    out
}

// spec/permissions.md §3 (removal placement): a content write, then a removal, both before the
// next sync; that sync places the removal (which carries the group's new `/keys`) under both of
// the group's labels before the earlier content write.
#[test]
fn removal_placed_first_under_every_label_spec_perm_3() {
    use osis_node::flows::{Delivery, Demotion, PreSync};
    let mut net = Net::new();
    let (s0, s1) = (net.add_server(), net.add_server());
    let a = net.node(1, &[s0, s1]);
    let b = net.node(2, &[s0, s1]);
    let c = net.node(3, &[s0, s1]);
    let g = net.group(a, &[(b, Role::Write), (c, Role::Read)], &[s0]);
    let addr = net.address(s1);
    let (l1, done) = net.engine(a).create_label(&g, &[addr]).unwrap();
    let acts = net.sync(a).carry_out(done).unwrap();
    net.actions(a, acts);
    let t = net.item(a, g, g, "before");
    net.run();
    let labels: Vec<osis_core::LabelId> = net.sync(a).labels().into_iter().filter(|(x, _)| *x == g).map(|(_, l)| l.id).collect();
    assert_eq!(labels.len(), 2);
    assert!(labels.contains(&l1));
    assert_eq!(net.read(c, t), Some(s("before")));
    let ct_ = net.tid(c);
    // a content write not yet uploaded, then the removal
    let after = net.write(a, t, "after");
    let done = net.engine(a).demote(&g, &Demotion { member: ct_, new: None, presync: PreSync::Synced }).unwrap();
    assert!(done.deliveries.iter().any(|d| matches!(d, Delivery::First { .. })));
    let removal = done.commits[0];
    let h = net.engine(a).header(&removal).unwrap();
    assert!(h.aspects.iter().any(|x| x.ak.as_str() == "/keys"), "the removal carries the new /keys");
    let acts = net.sync(a).carry_out(done).unwrap();
    net.actions(a, acts);
    net.run();
    for (s, l) in [(s0, labels.iter().find(|l| **l != l1).copied().unwrap()), (s1, l1)] {
        let order = logged_commits(&mut net, s, a, &l);
        let (r, w) = (order.iter().position(|x| *x == removal), order.iter().position(|x| *x == after));
        assert!(r.is_some() && w.is_some() && r < w, "server {s}: removal at {r:?}, later content at {w:?}");
    }
    assert_eq!(net.read(b, t), Some(s("after")));
}

/// A thing in a new group `g` (admin `a`, reader or writer `b`) holding a 1 MiB blob written
/// twice by `a`, the second version reusing most chunks of the first: the thing, the blob AK,
/// the two commits, the second value, and the first commit's chunks the live tree shares and
/// does not.
#[allow(clippy::type_complexity)]
fn reused_blob(net: &mut Net, a: usize, b: usize, role: Role, sv: usize) -> (osis_core::Tid, Ak, [osis_core::CommitId; 2], Vec<u8>, BTreeSet<osis_core::BlobId>, BTreeSet<osis_core::BlobId>) {
    let g = net.group(a, &[(b, role)], &[sv]);
    let t = net.item(a, g, g, "x");
    let v1 = noise(1 << 20, 7);
    let mut m = Mutation::new();
    m.set(t, &BLOB, &Value::Bytes(v1.clone())).unwrap();
    let c1 = net.engine(a).commit(m).unwrap().unwrap();
    net.run();
    let mut v2 = v1;
    v2.splice(600_000..600_000, noise(100, 8));
    let mut m = Mutation::new();
    m.set(t, &BLOB, &Value::Bytes(v2.clone())).unwrap();
    let c2 = net.engine(a).commit(m).unwrap().unwrap();
    net.run();
    let first: BTreeSet<_> = net.engine(a).package(&c1).unwrap().unwrap().blobs.into_iter().map(|(id, _)| id).collect();
    let live = net.engine(a).live_trees(&t).unwrap().blobs;
    let shared: BTreeSet<_> = first.intersection(&live).copied().collect();
    let unique: BTreeSet<_> = first.difference(&live).copied().collect();
    assert!(!shared.is_empty() && !unique.is_empty());
    (t, Ak::new(BLOB.ak()).unwrap(), [c1, c2], v2, shared, unique)
}

// spec/sync.md §3 (closure: the chunk and tree-node blobs the commits reference), §2
// (replacement): chunks the live value reuses are listed only by the version that introduced
// them; once that version is purged and the label replaced, the writer still uploads them under
// the new label with the live body, so a reader there reads the value.
#[test]
fn reused_chunks_follow_a_new_label_spec_sync_3() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let (t, blob_ak, [c1, _], v2, shared, _) = reused_blob(&mut net, a, b, Role::Read, sv);
    let mut m = Mutation::new();
    m.set(t, &REG, &s("purged v1")).unwrap();
    m.purge(osis_commit::PurgeItem::Commit { commit: c1, tid: t, ak: blob_ak.clone() });
    net.engine(a).commit(m).unwrap().unwrap();
    net.run();
    let g = net.engine(a).groups_of(&t).into_iter().next().unwrap();
    let old = net.label(a);
    let (new, acts) = net.sync(a).replace_label(&g, &old).unwrap();
    net.actions(a, acts);
    net.run();
    net.run();
    diags(&mut net, &[a, b]);
    let under: BTreeSet<_> = net.server_ids(sv, &new).into_iter().collect();
    assert!(shared.is_subset(&under), "reused chunks under the new label: {} of {}", shared.intersection(&under).count(), shared.len());
    let acts = net.sync(b).fetch_missing();
    net.actions(b, acts);
    net.settle(100_000);
    assert_eq!(net.engine(b).get_full(&t, &blob_ak).unwrap(), Some(Value::Bytes(v2)));
}

// spec/sync.md §3 (closure): a commit touching a thing of the group and another thing of the
// same reader actor outside the group's closure uploads under the label only what its own
// deltas link: never the outside thing's large value.
#[test]
fn body_links_stay_in_the_closure_spec_sync_3() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let g = net.group(a, &[(b, Role::Read)], &[sv]);
    let t1 = net.item(a, g, g, "in");
    // t2: owned by g, not in its /group
    let mut m = Mutation::new();
    let t2 = net.engine(a).new_thing(&mut m, g);
    m.set(t2, &BLOB, &Value::Bytes(noise(1 << 20, 9))).unwrap();
    net.engine(a).commit(m).unwrap().unwrap();
    let mut m = Mutation::new();
    m.set(t1, &REG, &s("both")).unwrap();
    m.set(t2, &REG, &s("both")).unwrap();
    let both = net.engine(a).commit(m).unwrap().unwrap();
    net.run();
    net.run();
    diags(&mut net, &[a, b]);
    let outside = net.engine(a).live_trees(&t2).unwrap().blobs;
    assert!(outside.len() > 4);
    let l = net.label(a);
    // the body under the label carries t2's part too (same reader actor)
    let h = net.engine(a).header(&both).unwrap();
    let t2_part = net.sync(a).entries(&l).into_iter().any(|(_, k)| matches!(k, EntryKind::Commit { commit, parts, .. } if commit == both && parts.iter().any(|(ai, _)| h.aspects[*ai].tid == t2)));
    assert!(t2_part, "the commit's body under the label touches t2");
    let under: BTreeSet<_> = net.server_ids(sv, &l).into_iter().collect();
    assert!(outside.is_disjoint(&under), "{} blobs of an outside thing under the label", outside.intersection(&under).count());
}

// spec/sync.md §7 (chunk blobs still linked from a retained version are kept), spec/commits.md
// §5: a right holder that never fetched the value's tree (lazy chunks) fetches its node blobs
// before judging the dropped chunks, so it shreds those only the purged version reached, like
// a node that holds the tree, and keeps the shared ones.
#[test]
fn lazy_node_shreds_dropped_chunks_spec_sync_7() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    // b fetches chunk and tree-node blobs only on demand
    let b = net.add_node(2, SyncConfig { servers: vec![net.address(sv)], inline_limit: 0, ..SyncConfig::default() });
    let (t, blob_ak, [c1, c2], v2, shared, unique) = reused_blob(&mut net, a, b, Role::Admin, sv);
    let root = match net.engine(a).get(&t, &blob_ak).unwrap() {
        Some(Value::Link(l)) => l.blob,
        v => panic!("{v:?}"),
    };
    assert!(net.engine(b).blob(&root).unwrap().is_none(), "b fetched no tree");
    assert!(net.engine(b).header(&c2).is_some());
    // the node holding the tree is away: b alone judges
    net.set_online(a, false);
    let mut m = Mutation::new();
    m.set(t, &REG, &s("purged v1")).unwrap();
    m.purge(osis_commit::PurgeItem::Commit { commit: c1, tid: t, ak: blob_ak.clone() });
    net.engine(b).commit(m).unwrap().unwrap();
    net.run();
    net.run();
    diags(&mut net, &[b]);
    let l = net.label(b);
    let server: BTreeSet<_> = net.server_ids(sv, &l).into_iter().collect();
    assert!(unique.is_disjoint(&server), "a chunk only the purged version reached is gone at the server");
    assert!(shared.is_subset(&server), "shared chunks stay");
    let acts = net.sync(b).fetch_missing();
    net.actions(b, acts);
    net.settle(100_000);
    assert_eq!(net.engine(b).get_full(&t, &blob_ak).unwrap(), Some(Value::Bytes(v2)));
}

/// Node `n`'s certificate commit by `author` touching `ak` among `n`'s chain certificates for
/// `g`, with the aspect indexes to carry.
fn chain_commit(net: &mut Net, n: usize, g: osis_core::Tid, author: osis_core::Tid, ak: &str) -> (osis_core::CommitId, BTreeSet<(usize, usize)>) {
    let certs = net.engine(n).certificates(&g);
    certs
        .into_iter()
        .find(|(c, _)| net.engine(n).header(c).is_some_and(|h| h.author == author && h.aspects.iter().any(|a| a.tid == author && a.ak.as_str() == ak)))
        .expect("a chain commit")
}

/// The entries under `l` that node `n` knows holding commit `c` and present at server `sv`.
fn entries_of(net: &mut Net, n: usize, sv: usize, l: &osis_core::LabelId, c: &osis_core::CommitId) -> Vec<(osis_core::BlobId, EntryKind)> {
    let live: BTreeSet<osis_core::BlobId> = net.server_ids(sv, l).into_iter().collect();
    net.sync(n).entries(l).into_iter().filter(|(id, k)| live.contains(id) && matches!(k, EntryKind::Commit { commit, .. } if commit == c)).collect()
}

// spec/commits.md §4 (a delta must hash to its header entry), spec/permissions.md §4 (a copy
// counts once opened as the same commit): a blob under the label with the header of the
// writer's card commit but forged deltas holds nothing: the writer marks it bad and places its
// own copy.
#[test]
fn forged_certificate_copy_ignored_spec_commits_4() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let w = net.node(2, &[sv]);
    let g = net.group(a, &[(w, Role::Write)], &[sv]);
    net.set_online(w, false);
    net.run();
    let l = net.label(a);
    let wt = net.tid(w);
    let (cc, ais) = chain_commit(&mut net, w, g, wt, "/node");
    let secret = net.engine(a).wrap_secret(&g, None).unwrap().unwrap();
    let mut forged = Vec::new();
    for b in net.engine(w).part_bodies(&cc, &ais).unwrap() {
        let mut blob = osis_commit::CommitBlob::decode(&b.plaintext).unwrap();
        for p in &mut blob.parts {
            p.delta.push(0);
        }
        let fake = osis_node::labeling::Body { plaintext: blob.encode(), ..b };
        let s = osis_node::labeling::seal_body(&fake, &mut osis_crypto::SeededRng::from_u64(7)).unwrap();
        let wrap = osis_crypto::wrap(&secret, &s.id, &s.key).unwrap();
        let put = osis_proto::Put { blob_id: s.id, blob: &s.blob, wrap, stamp: None, expiry: None };
        osis_proto::LabelStore::put(net.servers[sv].hub.store_mut(), &l, put).unwrap();
        forged.push(s.id);
    }
    net.set_online(w, true);
    net.run();
    let entries = net.sync(w).entries(&l);
    assert!(forged.iter().all(|f| entries.iter().any(|(id, k)| id == f && *k == EntryKind::Bad)), "the forged copies are bad input");
    assert!(entries_of(&mut net, w, sv, &l, &cc).iter().any(|(id, _)| !forged.contains(id)), "the writer placed its own card");
}

// spec/permissions.md §4 (another node's copy counts while it is there): the reader relies on
// the admin's copy of the admin's card; once that copy is deleted at the server, the reader
// places its own.
#[test]
fn deleted_copy_placed_again_spec_permissions_4() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let r = net.node(2, &[sv]);
    let g = net.group(a, &[(r, Role::Read)], &[sv]);
    net.set_online(r, false);
    net.run();
    net.set_online(r, true);
    net.run();
    let l = net.label(a);
    let at = net.tid(a);
    let (cc, _) = chain_commit(&mut net, r, g, at, "/node");
    let before = entries_of(&mut net, r, sv, &l, &cc);
    assert_eq!(before.len(), 2, "the admin's copy only (two retention classes): {before:?}");
    net.set_online(r, false);
    for (id, _) in &before {
        let now = net.now();
        osis_proto::LabelStore::delete(net.servers[sv].hub.store_mut(), &l, id, now).unwrap();
    }
    net.set_online(r, true);
    net.run();
    // the next pass (the periodic one at the latest) sees the copy gone
    net.advance(61_000);
    net.run();
    let after = entries_of(&mut net, r, sv, &l, &cc);
    assert!(!after.is_empty() && after.iter().all(|x| !before.contains(x)), "the reader placed its own: {after:?}");
}

// spec/permissions.md §3, §4 (another node's new `/keys` is its author's to place; a node may
// wait at most `SETTLE_MS` after receipt): the reader receives the admin's new card keys while
// the admin is offline, holds back its copy, and places it once the wait is over.
#[test]
fn others_fresh_keys_left_to_author_spec_permissions_4() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let r = net.node(2, &[sv]);
    let g = net.group(a, &[(r, Role::Read)], &[sv]);
    net.run();
    let l = net.label(a);
    let at = net.tid(a);
    net.set_online(a, false);
    // a change of the admin node's `/keys` (a deposit seed field it lacked)
    let mut m = Mutation::new();
    let op = osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Field(5)], op: osis_crdt::Op::Replace(osis_schema::Codec::to_value(&Some([0x5e; 32]))) };
    m.op(at, &ct::KEYS, op).unwrap();
    let c = net.engine(a).commit(m).unwrap().unwrap();
    net.pair(a, r);
    net.run();
    assert_eq!(chain_commit(&mut net, r, g, at, "/keys").0, c, "the new keys are on the reader's chain");
    assert!(entries_of(&mut net, r, sv, &l, &c).is_empty(), "left to its author for now");
    net.advance(31_000);
    net.run();
    assert!(!entries_of(&mut net, r, sv, &l, &c).is_empty(), "placed once the wait is over");
}

// spec/crypto.md §4 (a grant or rotation boxing an epoch carries its history box), spec/
// permissions.md §4 (copies placed by any node count): a newcomer first boxed after a rotation
// opens certificate copies wrapped under the older epoch and so verifies a writer whose card
// went up before the rotation (why copies under older epochs count for newcomers).
#[test]
fn newcomer_after_rotation_reads_older_copies_spec_crypto_4() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let w = net.node(2, &[sv]);
    let r = net.node(3, &[sv]);
    let g = net.group(a, &[(w, Role::Write)], &[sv]);
    net.set_online(r, false);
    net.run();
    let l = net.label(a);
    let (at, wt, rt) = (net.tid(a), net.tid(w), net.tid(r));
    let old = net.engine(a).wrap_secret(&g, None).unwrap().unwrap();
    // r joins with the rotation: its first box is at the new epoch
    net.pair(r, a);
    let e = net.engine(a);
    set_edge(e, g, rt, Role::Read);
    let rs = recipients_of(e, &[(at, Role::Admin), (wt, Role::Write), (rt, Role::Read)]);
    rotation(e, g, &rs, 78, false);
    net.pair(a, r);
    net.run();
    let t = net.item(w, g, g, "after");
    net.run();
    // the writer's card went up only under the old epoch
    let (cc, _) = chain_commit(&mut net, w, g, wt, "/node");
    let cards: Vec<osis_core::BlobId> = net.sync(w).entries(&l).into_iter().filter(|(_, k)| matches!(k, EntryKind::Commit { commit, .. } if *commit == cc)).map(|(id, _)| id).collect();
    let store = net.servers[sv].hub.store();
    assert!(!cards.is_empty() && cards.iter().all(|id| osis_proto::LabelStore::entry(store, &l, id).unwrap().is_some_and(|m| osis_crypto::unwrap(&old, id, &m.wrap).is_ok())));
    net.set_online(r, true);
    net.run();
    assert_eq!(net.read(r, t), Some(s("after")), "the newcomer verified the writer");
}

// spec/sync.md §1 (a chunk reused by a later delta keeps its blob; one a server deleted is
// re-encrypted), §7: a purger that has not seen a co-writer's concurrent reuse deletes the
// shared chunks at the server; the reuser, seeing them deleted, writes its value again with
// them re-encrypted, so every reader still reads it whole.
#[test]
fn purged_chunk_reused_concurrently_is_reencrypted_spec_sync_1() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let c = net.node(3, &[sv]);
    // an admin co-writer: it holds the admin secret, so its framing keeps a's chunks
    let g = net.group(a, &[(b, Role::Admin), (c, Role::Read)], &[sv]);
    let t = net.item(a, g, g, "x");
    let blob_ak = Ak::new(BLOB.ak()).unwrap();
    let v1 = noise(1 << 20, 9);
    let mut m = Mutation::new();
    m.set(t, &BLOB, &Value::Bytes(v1.clone())).unwrap();
    let c1 = net.engine(a).commit(m).unwrap().unwrap();
    net.run();
    assert_eq!(net.engine(b).get_full(&t, &blob_ak).unwrap(), Some(Value::Bytes(v1.clone())));
    // b edits offline, reusing v1's chunks; a purges v1 without seeing that
    net.set_online(b, false);
    let mut v2 = v1.clone();
    v2.splice(300_000..300_000, noise(100, 10));
    let mut m = Mutation::new();
    m.set(t, &BLOB, &Value::Bytes(v2.clone())).unwrap();
    net.engine(b).commit(m).unwrap().unwrap();
    let first: BTreeSet<osis_core::BlobId> = net.engine(a).package(&c1).unwrap().unwrap().blobs.into_iter().map(|(id, _)| id).collect();
    let reused: BTreeSet<_> = first.intersection(&net.engine(b).live_trees(&t).unwrap().blobs).copied().collect();
    assert!(!reused.is_empty());
    let mut m = Mutation::new();
    m.set(t, &REG, &s("purged v1")).unwrap();
    m.purge(osis_commit::PurgeItem::Commit { commit: c1, tid: t, ak: blob_ak.clone() });
    net.engine(a).commit(m).unwrap().unwrap();
    net.run();
    let l = net.label(a);
    let server: BTreeSet<osis_core::BlobId> = net.server_ids(sv, &l).into_iter().collect();
    assert!(reused.is_disjoint(&server), "the purger deleted the chunks it judged dead");
    net.set_online(b, true);
    // past the redial pause
    net.advance(6_000);
    net.run();
    for n in [a, b, c] {
        let acts = net.sync(n).fetch_missing();
        net.actions(n, acts);
    }
    net.settle(100_000);
    let live = net.engine(b).live_trees(&t).unwrap().blobs;
    assert!(live.is_disjoint(&reused), "the reuser re-encrypted them");
    for n in [a, b, c] {
        assert_eq!(net.engine(n).get_full(&t, &blob_ak).unwrap(), Some(Value::Bytes(v2.clone())), "node {n}");
    }
}

/// Commits `n` authored on `(t, ak)`, with their expiry there.
fn own_writes(net: &mut Net, n: usize, t: osis_core::Tid, ak: &Ak) -> Vec<Option<u64>> {
    let me = net.tid(n);
    let ids = net.engine(n).commit_ids();
    ids.iter().filter_map(|c| net.engine(n).header(c)).filter(|h| h.author == me).filter_map(|h| h.aspects.iter().find(|a| a.tid == t && a.ak == *ak).map(|a| a.expires)).collect()
}

/// A writer `b` edits an untyped `{big, note}` value offline, reusing v1's chunks, while the
/// admin `a` purges v1 (deleting every chunk at the server) and writes `note` offline.
fn reuse_race(expires: Option<u64>) -> (Net, [usize; 3], osis_core::Tid, Ak, Vec<u8>) {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let c = net.node(3, &[sv]);
    let g = net.group(a, &[(b, Role::Admin), (c, Role::Read)], &[sv]);
    let t = net.item(a, g, g, "x");
    let doc = Ak::new("/u/doc").unwrap();
    let k = |s: &str| Value::Str(s.into());
    let v1 = noise(1 << 20, 11);
    let mut m = Mutation::new();
    m.set(t, &doc, &Value::Map([(k("big"), Value::Bytes(v1.clone())), (k("note"), k("x"))].into_iter().collect())).unwrap();
    let c1 = net.engine(a).commit(m).unwrap().unwrap();
    net.run();
    net.set_online(b, false);
    let mut v2 = v1.clone();
    v2.splice(500_000..500_000, noise(50, 12));
    let mut m = Mutation::new();
    m.op(t, &doc, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Key(k("big"))], op: osis_crdt::Op::Set(Value::Bytes(v2.clone())) }).unwrap();
    if let Some(e) = expires {
        m.expires(t, &doc, osis_core::WallMs(e)).unwrap();
    }
    net.engine(b).commit(m).unwrap().unwrap();
    let mut m = Mutation::new();
    m.set(t, &REG, &s("purged v1")).unwrap();
    m.purge(osis_commit::PurgeItem::Commit { commit: c1, tid: t, ak: doc.clone() });
    net.engine(a).commit(m).unwrap().unwrap();
    net.run();
    // a's concurrent edit of another position, older than b's repair, unseen by b
    net.set_online(a, false);
    let mut m = Mutation::new();
    m.op(t, &doc, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Key(k("note"))], op: osis_crdt::Op::Set(k("y")) }).unwrap();
    net.engine(a).commit(m).unwrap().unwrap();
    net.advance(1_000);
    net.set_online(b, true);
    net.advance(6_000);
    net.run();
    net.set_online(a, true);
    net.advance(6_000);
    net.run();
    for n in [a, b, c] {
        let acts = net.sync(n).fetch_missing();
        net.actions(n, acts);
    }
    net.settle(100_000);
    (net, [a, b, c], t, doc, v2)
}

// spec/sync.md §1: the reuser repairs only the large positions whose chunks are gone, so a
// concurrent older edit of another position survives everywhere; the value reads whole.
#[test]
fn reencrypted_chunk_keeps_concurrent_edit_spec_sync_1() {
    let (mut net, nodes, t, doc, v2) = reuse_race(None);
    let want: Value = Value::Map([(Value::Str("big".into()), Value::Bytes(v2)), (Value::Str("note".into()), Value::Str("y".into()))].into_iter().collect());
    for n in nodes {
        assert_eq!(net.engine(n).get_full(&t, &doc).unwrap(), Some(want.clone()), "node {n}");
    }
}

// spec/sync.md §1: the repair carries the reusing delta's expiry.
#[test]
fn reencrypted_chunk_keeps_expiry_spec_sync_1() {
    let at = 1_700_000_000_000 + 30 * 86_400_000;
    let (mut net, [_, b, _], t, doc, _) = reuse_race(Some(at));
    let w = own_writes(&mut net, b, t, &doc);
    assert!(w.len() >= 2, "the edit and its repair: {w:?}");
    assert!(w.iter().all(|e| *e == Some(at)), "{w:?}");
}

// spec/sync.md §1: a single hostile server (it alone decides what is gone) deleting each fresh
// chunk again drives at most one repair per back-off interval per aspect, the interval doubling;
// what the back-off holds back is retried when it passes.
#[test]
fn reencrypt_loop_bounded_spec_sync_1() {
    let (mut net, [a, b, _], t, doc, _) = reuse_race(None);
    let repairs = |net: &mut Net| own_writes(net, b, t, &doc).len();
    let first = repairs(&mut net);
    let l = net.label(a);
    // the server drops every chunk the live value links, then b syncs again
    let spam = |net: &mut Net| {
        let live = net.engine(b).live_trees(&t).unwrap().blobs;
        let now = net.now();
        let ids = net.server_ids(0, &l);
        for id in ids {
            if live.contains(&id) {
                osis_proto::LabelStore::delete(net.servers[0].hub.store_mut(), &l, &id, now).unwrap();
            }
        }
        net.set_online(b, false);
        net.set_online(b, true);
        net.advance(6_000);
        net.run();
    };
    for _ in 0..4 {
        spam(&mut net);
    }
    assert_eq!(repairs(&mut net), first, "within the back-off: no repair");
    // the held-back chunks are retried once the back-off passes
    net.advance(2 * 3_600_000);
    net.run();
    assert_eq!(repairs(&mut net), first + 1, "after it: one");
    // the interval doubled: held back at 1.5 h, done past 2 h
    spam(&mut net);
    net.advance(90 * 60_000);
    net.run();
    assert_eq!(repairs(&mut net), first + 1, "the back-off doubled");
    net.advance(45 * 60_000);
    net.run();
    assert_eq!(repairs(&mut net), first + 2);
}

// spec/crypto.md §7, spec/wire.md §9: an inbox grant names the target's current admin and write
// delete keys, so a grantee that holds the grant but not yet the target's `/keys` writes at once,
// and a self-removal by it succeeds too; the keys it lists are the target's.
#[test]
fn grant_by_inbox_writes_before_keys_spec_crypto_7() {
    use osis_node::flows::{Delivery, Demotion, PreSync};
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let addr = net.address(sv);
    let (alice, done) = net.engine(a).create_person(std::slice::from_ref(&addr)).unwrap();
    let acts = net.sync(a).carry_out(done).unwrap();
    net.actions(a, acts);
    let (bob, done) = net.engine(b).create_person(std::slice::from_ref(&addr)).unwrap();
    let acts = net.sync(b).carry_out(done).unwrap();
    net.actions(b, acts);
    net.run();
    net.pair(b, a);
    let e = net.engine(a);
    let mut m = Mutation::new();
    let g = e.new_thing(&mut m, alice.person);
    m.set(g, &ct::GROUP, &ct::Group::default()).unwrap();
    e.commit(m).unwrap();
    let edge = ct::Edge { role: Role::Write, until: None, invite: None, since: None };
    let done = net.engine(a).grant(&g, &bob.person, &edge).unwrap();
    let blob = done.deliveries.iter().find_map(|d| if let Delivery::Inbox { blob, .. } = d { Some(blob.clone()) } else { None }).expect("an inbox blob");
    // everything but the commits writing g's `/keys` reaches b directly; the grant by inbox
    let keys_ak = Ak::new("/keys").unwrap();
    for id in net.engine(a).commit_ids() {
        let h = net.engine(a).header(&id).unwrap();
        if h.aspects.iter().any(|x| x.tid == g && x.ak == keys_ak) {
            continue;
        }
        let pk = net.engine(a).package(&id).unwrap().unwrap();
        let _ = net.engine(b).ingest(&pk.bytes, pk.blobs);
    }
    net.engine(b).accept_inbox(&blob).unwrap();
    assert!(net.engine(b).get_typed(&g, &ct::KEYS).unwrap().is_none(), "b holds no /keys of g");
    let mut m = Mutation::new();
    m.set(g, &REG, &s("by bob")).unwrap();
    let c = net.engine(b).commit(m).unwrap().unwrap();
    let h = net.engine(b).header(&c).unwrap();
    let admin = net.engine(a).epochs(&g).unwrap().admin.newest_held().map(|(_, s)| osis_crypto::DeleteSecret::derive(s).verifying_key().to_bytes()).unwrap();
    assert!(h.keys.iter().any(|k| k.level == 1 && k.key == admin), "b lists g's admin delete key");
    let done = net.engine(b).demote(&g, &Demotion { member: bob.person, new: None, presync: PreSync::Synced }).unwrap();
    let _ = done;
}
