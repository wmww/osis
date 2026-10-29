#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! A malicious blind node against a node's sync engine (spec/requirements.md: "Nothing trusts a
//! server's word"; "Peer input never causes unbounded allocation, work, storage or
//! diagnostics"): frames injected on a node's server connection, or a scripted server; plus
//! what deletion must reach at a blind node.

use crate::net;
use net::*;
use osis_base::format::MAX_DRIFT_MS;
use osis_base::{Ak, LabelId, Role, Value};
use osis_crypto::{Epoch, LabelRole, Secret32, SeededRng, label_role_key};
use osis_label::{Parent, StepKeys, genesis_label, register};
use osis_node::sync::{Action, ConnId, Event, SyncEngine};
use osis_proto::{Cursor, FrameDecoder, Hello, Message, encode_frame};

fn frame(m: Message) -> Vec<u8> {
    encode_frame(&m.encode())
}

/// Messages a node sent in `acts` on `conn`.
fn sent(acts: &[Action], conn: ConnId) -> Vec<Message> {
    let mut out = Vec::new();
    for a in acts {
        if let Action::Send { conn: c, bytes } = a
            && *c == conn
        {
            let mut d = FrameDecoder::new();
            d.push(bytes);
            while let Ok(Some(body)) = d.next_frame() {
                if let Ok(m) = Message::decode(&body) {
                    out.push(m);
                }
            }
        }
    }
    out
}

/// A valid genesis step of some other label.
fn foreign_step(b: u8) -> osis_label::Step {
    let (read, write, admin, dep) = (Secret32::from_bytes([b; 32]), Secret32::from_bytes([b + 1; 32]), Secret32::from_bytes([b + 2; 32]), Secret32::from_bytes([b + 3; 32]));
    let keys = StepKeys::derive(&read, &write, &admin, 0, &dep, &genesis_label(&admin, 0));
    let delete = label_role_key(LabelRole::Delete, &admin, 0);
    register(Parent::Genesis(&delete), keys, &[], (Epoch::new(0, [0; 16]).unwrap(), &read), &mut SeededRng::from_u64(b as u64)).unwrap().0
}

// spec/wire.md §11.2 (Push: "the peer then sends Push" for subscribed labels only), spec/
// requirements.md (peer input never causes unbounded storage): a Push for a label the node never
// opened on that connection stores no entry and no blob.
#[test]
fn unsolicited_push_stores_nothing_spec_wire_11_2() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let g = net.group(a, &[], &[sv]);
    net.item(a, g, g, "x");
    net.run();
    let conn = net.conn_to(a, sv).expect("connected");
    let junk = LabelId([0x77; 16]);
    let blobs: Vec<Vec<u8>> = (0..50u8).map(|i| vec![i; 64]).collect();
    let events = blobs.iter().map(|b| osis_proto::Event::Added { blob_id: osis_label::blob_id(b), blob: Some(b.clone()), wrap: [1; 49], stamp: None }).collect();
    net.feed(a, Event::Bytes { conn, bytes: frame(Message::Push { label: junk, events, cursor: Cursor { log_id: [0; 16], seq: 1 } }) });
    net.settle(10_000);
    assert!(net.sync(a).entries(&junk).is_empty(), "no entry under a label not opened");
    for b in &blobs {
        assert!(!net.sync(a).holds_blob(&osis_label::blob_id(b)), "no blob stored");
    }
}

// spec/sync.md §5 (walk: "verifying each step under its parent's delete key, the genesis step
// against the label ID"), spec/requirements.md (no unbounded allocation): a server path that
// does not verify is refused at its first page, not buffered until the server ends it.
#[test]
fn bad_path_refused_at_first_page_spec_sync_5() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let _g = net.group(a, &[], &[sv]);
    let mut se: SyncEngine = net.take(a);
    let acts = se.handle(Event::Local);
    let conn = acts.iter().find_map(|x| if let Action::Dial { conn, .. } = x { Some(*conn) } else { None }).expect("dial");
    se.handle(Event::Up { conn });
    let acts = se.handle(Event::Bytes { conn, bytes: encode_frame(&Hello::new(net.now(), [9; 32]).encode()) });
    let (id, label) = sent(&acts, conn).into_iter().find_map(|m| if let Message::Open { id, label, .. } = m { Some((id, label)) } else { None }).expect("open");
    // an unrecorded head: the node asks for the path to verify it
    let acts = se.handle(Event::Bytes { conn, bytes: frame(Message::Opened { id, head: foreign_step(40), entry_box: None }) });
    let pid = sent(&acts, conn).into_iter().find_map(|m| if let Message::Path { id, label: l, .. } = m { (l == label).then_some(id) } else { None }).expect("path");
    se.take_diagnostics();
    se.handle(Event::Bytes { conn, bytes: frame(Message::PathReply { id: pid, steps: vec![foreign_step(50); 4], more: true }) });
    let d = se.take_diagnostics();
    assert!(d.iter().any(|x| x.contains("server path does not verify")), "refused at the first page: {d:?}");
}

// notes/ephemeral.md Signals (a relay-only commit older than `MAX_DRIFT` is dropped, its only
// replay window; one delivered is remembered): a server pushing a captured signal again fires
// nothing, at once or later.
#[test]
fn replayed_signal_dropped_spec_sync_5() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let g = net.group(a, &[(b, Role::Read)], &[sv]);
    let t = net.item(a, g, g, "x");
    net.run();
    let rx = net.listen(b);
    let mut m = osis_node::Mutation::new();
    m.set(t, &ukey("/t/typing", osis_schema::Lifetime::Signal), &Value::Bool(true)).unwrap();
    net.engine(a).write(m).unwrap();
    let acts = net.sync(a).handle(Event::Local);
    let conn_a = net.conn_to(a, sv).unwrap();
    let (label, entry) = sent(&acts, conn_a)
        .into_iter()
        .find_map(|m| match m {
            Message::Upload { label, entries, .. } => entries.into_iter().next().map(|e| (label, e)),
            _ => None,
        })
        .expect("relay-only entry sent");
    net.actions(a, acts);
    net.settle(10_000);
    assert_eq!(fired(&rx).len(), 1, "delivered once");
    let push = |e: &osis_proto::Entry| Message::Push { label, events: vec![osis_proto::Event::Added { blob_id: osis_label::blob_id(&e.blob), blob: Some(e.blob.clone()), wrap: e.wrap, stamp: Some(e.stamp) }], cursor: osis_proto::Cursor { log_id: [0; 16], seq: 0 } };
    let conn_b = net.conn_to(b, sv).unwrap();
    net.feed(b, Event::Bytes { conn: conn_b, bytes: frame(push(&entry)) });
    assert!(fired(&rx).is_empty(), "a duplicate fires nothing");
    net.clock.advance(MAX_DRIFT_MS + 60_000);
    let conn_b = net.conn_to(b, sv).unwrap();
    net.feed(b, Event::Bytes { conn: conn_b, bytes: frame(push(&entry)) });
    assert!(fired(&rx).is_empty(), "a stale replay fires nothing");
}

// spec/requirements.md (blind nodes must not learn device identities; groups unlinkable beyond
// their overlap), spec/sync.md §2 (a key actor reads a label as a listed reader): a node holding a
// key actor (a link or recovery key) never presents its signing key at a label whose group does
// not list it, however its other opens fare.
#[test]
fn key_actor_not_presented_elsewhere_spec_sync_5() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let _g = net.group(a, &[], &[sv]);
    let ka = net.engine(a).hold_key_actor(Secret32::from_bytes([0x3c; 32])).unwrap();
    assert!(net.engine(a).held_key_actors() > 0, "{ka}");
    let signing = osis_crypto::KeyActorKeys::from_seed(&Secret32::from_bytes([0x3c; 32])).signing.verifying_key();
    let mut se: SyncEngine = net.take(a);
    let acts = se.handle(Event::Local);
    let conn = acts.iter().find_map(|x| if let Action::Dial { conn, .. } = x { Some(*conn) } else { None }).expect("dial");
    se.handle(Event::Up { conn });
    let mut acts = se.handle(Event::Bytes { conn, bytes: encode_frame(&Hello::new(net.now(), [9; 32]).encode()) });
    // every open refused: the node goes through all its tries
    for _ in 0..64 {
        let opens: Vec<Message> = sent(&acts, conn).into_iter().filter(|m| matches!(m, Message::Open { .. })).collect();
        if opens.is_empty() {
            break;
        }
        let mut next = Vec::new();
        for m in opens {
            let Message::Open { id, proof, .. } = m else { continue };
            if let osis_label::Proof::Static { signing: pk, .. } = proof {
                assert_ne!(pk, signing, "the key actor's signing key went to a label it does not read");
            }
            next.extend(se.handle(Event::Bytes { conn, bytes: frame(Message::Error { id, code: osis_proto::Code::REFUSED }) }));
        }
        acts = next;
    }
}

// spec/requirements.md (peer input never causes unbounded storage), spec/sync.md §3 (only writers
// add stamped entries; deposits are readable by co-readers): a server's made-up unstamped
// entries under an opened label that open under nothing held leave no blob, and only a capped
// number of entries.
#[test]
fn junk_under_opened_label_kept_nowhere_spec_sync_3() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let g = net.group(a, &[], &[sv]);
    net.item(a, g, g, "x");
    net.run();
    let l = net.label(a);
    let before = net.sync(a).entries(&l).len();
    let conn = net.conn_to(a, sv).expect("connected");
    let blobs: Vec<Vec<u8>> = (0..50u8).map(|i| vec![i; 4096]).collect();
    let events = blobs.iter().map(|b| osis_proto::Event::Added { blob_id: osis_label::blob_id(b), blob: Some(b.clone()), wrap: [1; 49], stamp: None }).collect();
    net.feed(a, Event::Bytes { conn, bytes: frame(Message::Push { label: l, events, cursor: Cursor { log_id: [0; 16], seq: 1 << 40 } }) });
    net.settle(10_000);
    for b in &blobs {
        assert!(!net.sync(a).holds_blob(&osis_label::blob_id(b)), "no junk blob kept");
    }
    // past the cap not even the entry: a server's endless junk leaves bounded metadata
    let n = net.sync(a).entries(&l).len();
    assert!(n <= before + 50, "{n}");
}

// spec/sync.md §2, §5 (a key actor claims the current step by its static entry; the step's entry
// box carries the read secret; walks verify each step under its parent, the genesis against the
// label ID), spec/crypto.md §4 (sealed boxes are unauthenticated): a server's forged head and
// entry box teach the key actor no secret.
#[test]
fn forged_entry_box_teaches_nothing_spec_sync_5() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let seed = Secret32::from_bytes([0x3c; 32]);
    let ka = net.engine(a).hold_key_actor(seed.clone()).unwrap();
    let held = |se: &SyncEngine| se.engine().epochs(&ka).map(|e| e.read.held_newest_first().len()).unwrap_or(0);
    let keys = osis_crypto::KeyActorKeys::from_seed(&seed);
    // the server's own label, its genesis boxing a secret of its choice to the key actor
    let b = 0x60u8;
    let (read, write, admin, dep) = (Secret32::from_bytes([b; 32]), Secret32::from_bytes([b + 1; 32]), Secret32::from_bytes([b + 2; 32]), Secret32::from_bytes([b + 3; 32]));
    let skeys = StepKeys::derive(&read, &write, &admin, 0, &dep, &genesis_label(&admin, 0));
    let delete = label_role_key(LabelRole::Delete, &admin, 0);
    let reader = osis_label::Reader::Static { signing: keys.signing.verifying_key(), entry: osis_label::EntryTo::Sealed(keys.kem.public()) };
    let (fake, set) = register(Parent::Genesis(&delete), skeys, &[reader], (Epoch::new(0, [0; 16]).unwrap(), &read), &mut SeededRng::from_u64(9)).unwrap();
    let entry_box = set.entry_box(&fake.label, &keys.signing.verifying_key()).cloned().expect("entry box");
    let target = LabelId([0x42; 16]);
    let addr = net.address(sv);
    let mut se: SyncEngine = net.take(a);
    let before = held(&se);
    let acts = se.follow(ka, ka, target, vec![addr]);
    let conn = acts.iter().find_map(|x| if let Action::Dial { conn, .. } = x { Some(*conn) } else { None }).expect("dial");
    se.handle(Event::Up { conn });
    let mut acts = se.handle(Event::Bytes { conn, bytes: encode_frame(&Hello::new(net.now(), [9; 32]).encode()) });
    let mut path = None;
    for _ in 0..64 {
        let opens: Vec<Message> = sent(&acts, conn).into_iter().filter(|m| matches!(m, Message::Open { label, .. } if *label == target)).collect();
        if opens.is_empty() {
            break;
        }
        let mut next = Vec::new();
        for m in opens {
            let Message::Open { id, proof, .. } = m else { continue };
            let reply = match proof {
                osis_label::Proof::Static { .. } => Message::Opened { id, head: fake.clone(), entry_box: Some(entry_box.clone()) },
                _ => Message::Error { id, code: osis_proto::Code::REFUSED },
            };
            let r = se.handle(Event::Bytes { conn, bytes: frame(reply) });
            path = path.or_else(|| sent(&r, conn).into_iter().find_map(|m| if let Message::Path { id, label, .. } = m { (label == target).then_some(id) } else { None }));
            next.extend(r);
        }
        acts = next;
    }
    assert_eq!(held(&se), before, "nothing learned before the path verified");
    let pid = path.expect("the head's path is asked for");
    se.take_diagnostics();
    se.handle(Event::Bytes { conn, bytes: frame(Message::PathReply { id: pid, steps: vec![fake.clone()], more: false }) });
    assert!(se.take_diagnostics().iter().any(|x| x.contains("server path does not verify")));
    assert_eq!(held(&se), before, "a forged head's box teaches nothing");
}

// spec/sync.md §2 (a step's entry box carries the read secret of its epoch, whose sync key the
// step registers), spec/crypto.md §4 (sealed boxes are unauthenticated): a genuine head with a
// substituted entry box (sealed by the server to the key actor's public KEM key) teaches no
// secret: one that does not derive the head's sync key is refused.
#[test]
fn substituted_entry_box_teaches_nothing_spec_sync_2() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let seed = Secret32::from_bytes([0x3d; 32]);
    let ka = net.engine(a).hold_key_actor(seed.clone()).unwrap();
    let held = |se: &SyncEngine| se.engine().epochs(&ka).is_some_and(|e| e.read.held_newest_first().iter().any(|(_, s)| s.expose() == &[0x99; 32]));
    let keys = osis_crypto::KeyActorKeys::from_seed(&seed);
    let b = 0x70u8;
    let (read, write, admin, dep) = (Secret32::from_bytes([b; 32]), Secret32::from_bytes([b + 1; 32]), Secret32::from_bytes([b + 2; 32]), Secret32::from_bytes([b + 3; 32]));
    let skeys = StepKeys::derive(&read, &write, &admin, 0, &dep, &genesis_label(&admin, 0));
    let delete = label_role_key(LabelRole::Delete, &admin, 0);
    let reader = || osis_label::Reader::Static { signing: keys.signing.verifying_key(), entry: osis_label::EntryTo::Sealed(keys.kem.public()) };
    let e1 = Epoch::new(1, [1; 16]).unwrap();
    // the genuine genesis (its path verifies), and a box for its slot carrying another secret
    let (head, _) = register(Parent::Genesis(&delete), skeys, &[reader()], (e1, &read), &mut SeededRng::from_u64(10)).unwrap();
    let slot = osis_crypto::BoxSlot::Entry { label: head.label, step_key: head.step_key };
    let item = osis_crypto::BoxItem { role: Role::Read, epoch: e1, secret: Secret32::from_bytes([0x99; 32]) };
    let sealed = osis_crypto::seal_box(keys.kem.public(), &slot, None, &[item], &mut SeededRng::from_u64(11)).unwrap();
    use osis_schema::core_types as ct;
    let forged = ct::SecretBox::Sealed(ct::SealedBox { keyset: None, suite: u64::from(osis_crypto::SUITE_1), sealed: ct::Sealed::X25519MlKem768(sealed) });
    let target = head.label;
    let addr = net.address(sv);
    let mut se: SyncEngine = net.take(a);
    let before = held(&se);
    let acts = se.follow(ka, ka, target, vec![addr]);
    let conn = acts.iter().find_map(|x| if let Action::Dial { conn, .. } = x { Some(*conn) } else { None }).expect("dial");
    se.handle(Event::Up { conn });
    let mut acts = se.handle(Event::Bytes { conn, bytes: encode_frame(&Hello::new(net.now(), [9; 32]).encode()) });
    let mut path = None;
    for _ in 0..64 {
        let opens: Vec<Message> = sent(&acts, conn).into_iter().filter(|m| matches!(m, Message::Open { label, .. } if *label == target)).collect();
        if opens.is_empty() {
            break;
        }
        let mut next = Vec::new();
        for m in opens {
            let Message::Open { id, proof, .. } = m else { continue };
            let reply = match proof {
                osis_label::Proof::Static { .. } => Message::Opened { id, head: head.clone(), entry_box: Some(forged.clone()) },
                _ => Message::Error { id, code: osis_proto::Code::REFUSED },
            };
            let r = se.handle(Event::Bytes { conn, bytes: frame(reply) });
            path = path.or_else(|| sent(&r, conn).into_iter().find_map(|m| if let Message::Path { id, label, .. } = m { (label == target).then_some(id) } else { None }));
            next.extend(r);
        }
        acts = next;
    }
    let pid = path.expect("the head's path is asked for");
    se.take_diagnostics();
    se.handle(Event::Bytes { conn, bytes: frame(Message::PathReply { id: pid, steps: vec![head.clone()], more: false }) });
    let diags = se.take_diagnostics();
    assert_eq!(held(&se), before, "a substituted box teaches nothing");
    assert!(diags.iter().any(|x| x.contains("does not derive the head's sync key")), "{diags:?}");
}

// spec/requirements.md, Deletion ("an admin's [purge of a large value] removes all of [its
// chunks]" at untrusted nodes), spec/sync.md §5 (delete-key holders delete must-not-hold bodies): a
// purged large value's chunk blobs leave the server.
#[test]
fn purged_chunks_leave_the_server_spec_sync_5() {
    use osis_schema::AspectKey;
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let g = net.group(a, &[(b, Role::Write)], &[sv]);
    let t = net.item(a, g, g, "x");
    let big: String = (0..300_000u32).map(|i| char::from(b'a' + (i.wrapping_mul(2654435761) >> 27) as u8 % 26)).collect();
    let mut m = osis_node::Mutation::new();
    m.set(t, &GONE, &s(&big)).unwrap();
    let c = net.engine(a).commit(m).unwrap().unwrap();
    net.run();
    let l = net.label(a);
    let chunks: Vec<osis_base::BlobId> = net.engine(a).header(&c).unwrap().chunks.iter().map(|ch| ch.blob).collect();
    assert!(!chunks.is_empty(), "a chunked value");
    assert!(chunks.iter().all(|id| net.server_ids(sv, &l).contains(id)), "chunks uploaded");
    let mut m = osis_node::Mutation::new();
    m.purge(osis_commit::PurgeItem::Commit { commit: c, tid: t, ak: Ak::new(GONE.ak()).unwrap() });
    m.remove_aspect(t, &GONE).unwrap();
    net.engine(a).commit(m).unwrap();
    net.run();
    net.run();
    let left: Vec<_> = chunks.iter().filter(|id| net.server_ids(sv, &l).contains(id)).collect();
    assert!(left.is_empty(), "{} of {} chunks of the purged value stay at the server", left.len(), chunks.len());
}

// spec/crypto.md §7 (a chunk commits to the delete keys of the delta that created it),
// spec/sync.md §5: a writer that is no admin of the label purges a `writer` value another node
// wrote; it fetches the chunks it never read for their salts and deletes them by its delete key.
#[test]
fn writer_purge_deletes_chunks_by_delete_key_spec_crypto_7() {
    use osis_schema::AspectKey;
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let g = net.group(a, &[(b, Role::Write)], &[sv]);
    let t = net.item(a, g, g, "x");
    let big: String = (0..300_000u32).map(|i| char::from(b'a' + (i.wrapping_mul(2654435761) >> 27) as u8 % 26)).collect();
    let mut m = osis_node::Mutation::new();
    m.set(t, &GONE, &s(&big)).unwrap();
    let c = net.engine(a).commit(m).unwrap().unwrap();
    net.run();
    let l = net.label(a);
    let chunks: Vec<osis_base::BlobId> = net.engine(a).header(&c).unwrap().chunks.iter().map(|ch| ch.blob).collect();
    assert!(!chunks.is_empty(), "a chunked value");
    assert!(chunks.iter().all(|id| net.server_ids(sv, &l).contains(id)), "chunks uploaded");
    // the admin (holder of the delete key) is gone: only the writer's delete key can delete
    net.set_online(a, false);
    let mut m = osis_node::Mutation::new();
    m.purge(osis_commit::PurgeItem::Commit { commit: c, tid: t, ak: Ak::new(GONE.ak()).unwrap() });
    m.remove_aspect(t, &GONE).unwrap();
    net.engine(b).commit(m).unwrap();
    net.feed(b, Event::Local);
    net.run();
    net.run();
    let left: Vec<_> = chunks.iter().filter(|id| net.server_ids(sv, &l).contains(id)).collect();
    assert!(left.is_empty(), "{} of {} chunks of the purged value stay at the server", left.len(), chunks.len());
}

// spec/wire.md §5, spec/crypto.md §7, spec/sync.md §5: the chunks and tree nodes of a linked
// header list carry exactly the commit's level-2 (author-chain) commitments; a server deletes
// them by the author-chain delete key, and refuses the thing-admin delete key of the same commit.
#[test]
fn header_list_chunks_level_2_only_spec_wire_5() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let g = net.group(a, &[], &[sv]);
    let t = net.item(a, g, g, "x");
    let mut m = osis_node::Mutation::new();
    for i in 0..800 {
        m.set(t, &Ak::new(format!("/u/{}{i:05}", "a".repeat(100))).unwrap(), &s("v")).unwrap();
    }
    let c = net.engine(a).commit(m).unwrap().unwrap();
    net.run();
    let l = net.label(a);
    let h = net.engine(a).header(&c).unwrap();
    assert!(h.links.aspects.is_some(), "the aspect list goes by link");
    let level2 = h.keys.iter().filter(|x| x.level == 2).count();
    assert_eq!(level2, 1);
    assert!(h.keys.iter().any(|x| x.level == 1), "the commit has a thing-admin key");
    let lists: Vec<osis_base::BlobId> = net.engine(a).package(&c).unwrap().unwrap().blobs.iter().map(|(id, _)| *id).collect();
    assert!(lists.len() > 1, "chunks and a tree node");
    assert!(lists.iter().all(|id| net.server_ids(sv, &l).contains(id)), "header-list blobs uploaded");
    // the commit's own delete secrets per level, found by the header's delete keys
    let mut ds = net.engine(a).delete_secrets_of(&c, &[(0, 0)]);
    assert_eq!(ds.iter().map(|x| x.0).collect::<Vec<_>>(), vec![1, 2]);
    let (chain, admin) = (ds.pop().unwrap().1, ds.pop().unwrap().1);
    let gl = net.sync(a).labels().into_iter().find(|(x, _)| *x == g).unwrap().1;
    let head = net.server_path(sv, &l).last().unwrap().clone();
    let sync = net.engine(a).head_keys(&g, gl.index, &head).unwrap().sync.unwrap();
    let by = |dk: &osis_crypto::DeleteSecret, level: u8, id: u32, net: &mut Net| {
        let mut items = Vec::new();
        for b in &lists {
            let bytes = net.engine(a).blob(b).unwrap().unwrap();
            let p = osis_label::Prefix::parse(&bytes).unwrap();
            assert_eq!(p.commitments().len(), level2, "level-2 commitments only");
            assert!(p.commitments().iter().all(|x| x[0] == 2));
            items.push(osis_label::DeleteItem::sign_by(&sync, dk, level, p.salt(), &h.blind, &l, *b, None).unwrap());
        }
        let conn = net.conn_to(a, sv).expect("connected");
        net.actions(a, vec![Action::Send { conn, bytes: frame(Message::Delete { id, label: l, items }) }]);
        net.settle(10_000);
        lists.iter().filter(|id| net.server_ids(sv, &l).contains(id)).count()
    };
    assert_eq!(by(&admin, 1, 900_001, &mut net), lists.len(), "the thing-admin key deletes nothing");
    assert_eq!(by(&admin, 2, 900_002, &mut net), lists.len(), "the thing-admin key at level 2 deletes nothing");
    assert_eq!(by(&chain, 2, 900_003, &mut net), 0, "the author-chain key deletes every header-list blob");
}

// spec/commits.md §4 (a commit blob whose prefix disagrees with its header is bad input), for a
// commit whose header lists go by link (spec/commits.md §1): checked once the lists are
// resolved; the forged blob counts as no body, so a writer places its own.
#[test]
fn linked_header_prefix_checked_spec_commits_4() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let g = net.group(a, &[(b, Role::Write)], &[sv]);
    let t = net.item(a, g, g, "x");
    net.run();
    let l = net.label(a);
    net.set_online(a, false);
    let mut m = osis_node::Mutation::new();
    for i in 0..800 {
        m.set(t, &Ak::new(format!("/u/{}{i:05}", "a".repeat(100))).unwrap(), &s("v")).unwrap();
    }
    let c = net.engine(a).commit(m).unwrap().unwrap();
    let h = net.engine(a).header(&c).unwrap();
    assert!(h.links.aspects.is_some(), "the aspect list goes by link");
    let body = net.engine(a).bodies(&c).unwrap().into_iter().next().unwrap();
    let parts = body.parts.clone();
    // the same body under a prefix with another expiry and no commitments
    let prefix = osis_label::Prefix::new([5; 16], Some(osis_base::WallMs(T0 + 1_000_000_000)), vec![]).unwrap();
    let (key, blob) = osis_label::frame(&prefix, &body.plaintext, &mut SeededRng::from_u64(3)).unwrap();
    let id = osis_label::blob_id(&blob);
    let secret = net.engine(a).wrap_secret(&g, Some((&c, &parts))).unwrap().unwrap();
    let wrap = osis_crypto::wrap(&secret, &id, &key).unwrap();
    let pk = net.engine(a).package(&c).unwrap().unwrap();
    let mut events: Vec<osis_proto::Event> = pk.blobs.iter().map(|(bid, bytes)| osis_proto::Event::Added { blob_id: *bid, blob: Some(bytes.clone()), wrap: [1; 49], stamp: None }).collect();
    events.push(osis_proto::Event::Added { blob_id: id, blob: Some(blob), wrap, stamp: None });
    let conn = net.conn_to(b, sv).expect("connected");
    net.feed(b, Event::Bytes { conn, bytes: frame(Message::Push { label: l, events, cursor: Cursor { log_id: [0; 16], seq: 1 << 40 } }) });
    net.settle(10_000);
    // another node's commit: left to its author for a while (spec/sync.md §6)
    net.advance(30_000);
    assert!(net.engine(b).header(&c).is_some(), "applied from the forged blob");
    let entries = net.sync(b).entries(&l);
    assert!(entries.iter().any(|(x, k)| *x == id && *k == osis_node::sync::EntryKind::Bad), "the forged blob is bad input");
    assert!(entries.iter().any(|(x, k)| *x != id && matches!(k, osis_node::sync::EntryKind::Commit { commit, .. } if *commit == c)), "a writer placed its own encryption");
}

/// Junk entries under `l`, unstamped or stamped with `stamp_key`, each `tag`-distinct.
fn junk(l: &LabelId, tag: u8, n: u8, stamp_key: Option<&osis_crypto::SigningSecret>) -> (Vec<osis_base::BlobId>, Message) {
    let blobs: Vec<Vec<u8>> = (0..n).map(|i| vec![tag, i, 7, 7]).collect();
    let ids = blobs.iter().map(|b| osis_label::blob_id(b)).collect();
    let events = blobs
        .iter()
        .map(|b| {
            let id = osis_label::blob_id(b);
            let wrap = [tag; 49];
            osis_proto::Event::Added { blob_id: id, blob: Some(b.clone()), wrap, stamp: stamp_key.map(|k| osis_label::sign_stamp(k, l, &id, &wrap)) }
        })
        .collect();
    (ids, Message::Push { label: *l, events, cursor: Cursor { log_id: [tag; 16], seq: 1 << 40 } })
}

// spec/sync.md §3 (unvouched entries); spec/requirements.md ("nothing trusts a server's word"; peer input never causes unbounded
// storage): the cap on unvouched entries counts per server, so one server's junk does not evict
// what another server announces
#[test]
fn unvouched_cap_per_server_spec_sync_3() {
    let mut net = Net::new();
    let (s1, s2) = (net.add_server(), net.add_server());
    let cfg = osis_node::sync::SyncConfig { servers: vec![net.address(s1), net.address(s2)], unvouched_cap: 8, ..Default::default() };
    let a = net.add_node(1, cfg);
    let g = net.group(a, &[], &[s1, s2]);
    net.item(a, g, g, "x");
    net.run();
    let l = net.label(a);
    let (c1, c2) = (net.conn_to(a, s1).expect("s1"), net.conn_to(a, s2).expect("s2"));
    let (_, flood) = junk(&l, 1, 40, None);
    net.feed(a, Event::Bytes { conn: c1, bytes: frame(flood) });
    net.settle(10_000);
    let (ids, other) = junk(&l, 2, 1, None);
    net.feed(a, Event::Bytes { conn: c2, bytes: frame(other) });
    net.settle(10_000);
    assert!(net.sync(a).entries(&l).iter().any(|(b, _)| *b == ids[0]), "s2's entry crowded out by s1's junk");
}

// spec/sync.md §5 (honest servers take stamps under the head's write key only), spec/
// requirements.md (peer input never causes unbounded storage): stamps under a superseded step's
// write key (a removed writer's) vouch for nothing once the head is newer: such entries are
// capped and their bytes not kept
#[test]
fn old_step_stamp_vouches_nothing_spec_sync_5() {
    let mut net = Net::new();
    let sv = net.add_server();
    let cfg = osis_node::sync::SyncConfig { servers: vec![net.address(sv)], unvouched_cap: 8, ..Default::default() };
    let a = net.add_node(1, cfg);
    let b = net.node(2, &[sv]);
    let g = net.group(a, &[(b, Role::Write)], &[sv]);
    net.item(a, g, g, "x");
    net.run();
    let l = net.label(a);
    let old = net.engine(a).epochs(&g).unwrap().write.newest_held().unwrap().1.clone();
    let old_write = label_role_key(LabelRole::Write, &old, 0);
    let (at, bt) = (net.tid(a), net.tid(b));
    let e = net.engine(a);
    let rs = recipients_of(e, &[(at, Role::Admin)]);
    remove_member(e, g, bt, &rs, 43);
    net.run();
    assert_eq!(net.server_path(sv, &l).len(), 2, "a newer step");
    let before = net.sync(a).entries(&l).len();
    let conn = net.conn_to(a, sv).expect("connected");
    let (ids, push) = junk(&l, 3, 40, Some(&old_write));
    net.feed(a, Event::Bytes { conn, bytes: frame(push) });
    net.settle(10_000);
    for id in &ids {
        assert!(!net.sync(a).holds_blob(id), "junk bytes kept on an old-step stamp");
    }
    let n = net.sync(a).entries(&l).len();
    assert!(n <= before + 9, "{n}");
}

/// A Push of `events` under `l` (a server's word).
fn push(l: LabelId, events: Vec<osis_proto::Event>) -> Vec<u8> {
    frame(Message::Push { label: l, events, cursor: Cursor { log_id: [0; 16], seq: 1 << 40 } })
}

/// The entries node `n` knows under `l` holding a commit that touches `t`.
fn entries_of(net: &mut Net, n: usize, l: &LabelId, t: osis_base::Tid) -> Vec<osis_base::BlobId> {
    let all = net.sync(n).entries(l);
    all.into_iter()
        .filter_map(|(id, k)| match k {
            osis_node::sync::EntryKind::Commit { commit, .. } => net.engine(n).header(&commit).filter(|h| h.aspects.iter().any(|a| a.tid == t)).map(|_| id),
            _ => None,
        })
        .collect()
}

// spec/sync.md §5 (a wrap may be replaced by another holder's), spec/requirements.md ("nothing
// trusts a server's word"): a server re-announcing a held entry with a wrap that opens under no
// held read secret, or opens to another blob key, changes nothing; a wrap of the same key under
// another held read secret is taken.
#[test]
fn wrap_not_opening_to_known_key_ignored_spec_sync_5() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let r = net.node(2, &[sv]);
    let x = net.node(3, &[sv]);
    let g = net.group(a, &[(r, Role::Read), (x, Role::Read)], &[sv]);
    let t = net.item(a, g, g, "x");
    net.run();
    let l = net.label(r);
    // a rotation (x removed): r holds two read secrets
    let (at, rt, xt) = (net.tid(a), net.tid(r), net.tid(x));
    let e = net.engine(a);
    let rs = recipients_of(e, &[(at, Role::Admin), (rt, Role::Read)]);
    remove_member(e, g, xt, &rs, 44);
    net.run();
    assert_eq!(net.read(r, t), Some(s("x")));
    let secrets: Vec<Secret32> = net.engine(r).epochs(&g).unwrap().read.held_newest_first().into_iter().map(|(_, s)| s.clone()).collect();
    assert!(secrets.len() >= 2, "{}", secrets.len());
    let id = entries_of(&mut net, r, &l, t)[0];
    let (wrap0, _) = net.sync(r).entry_meta(&l, &id).unwrap();
    let (i, key) = osis_label::unwrap_any(secrets.iter(), &id, &wrap0).unwrap();
    assert!(i > 0, "the item's entry is wrapped under the older epoch");
    let conn = net.conn_to(r, sv).expect("connected");
    let added = |wrap| vec![osis_proto::Event::Added { blob_id: id, blob: None, wrap, stamp: None }];
    let other_key = osis_crypto::wrap(&secrets[0], &id, &Secret32::from_bytes([0x42; 32])).unwrap();
    for w in [[0x13; 49], other_key] {
        net.feed(r, Event::Bytes { conn, bytes: push(l, added(w)) });
        net.settle(10_000);
        assert_eq!(net.sync(r).entry_meta(&l, &id).unwrap().0, wrap0);
    }
    let rewrap = osis_crypto::wrap(&secrets[0], &id, &key).unwrap();
    net.feed(r, Event::Bytes { conn, bytes: push(l, added(rewrap)) });
    net.settle(10_000);
    assert_eq!(net.sync(r).entry_meta(&l, &id).unwrap().0, rewrap, "a re-wrap of the known key is taken");
}

// spec/sync.md §5 (honest servers take stamps under the head's write key only; anyone may relay
// a stamped entry), spec/requirements.md ("nothing trusts a server's word"): a reader keeps an
// announced entry's stamp only when it verifies under the head's write key, so it never relays
// a forged one as stamped.
#[test]
fn relayed_stamp_checked_against_head_spec_sync_5() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let r = net.node(2, &[sv]);
    let g = net.group(a, &[(r, Role::Read)], &[sv]);
    net.item(a, g, g, "x");
    net.run();
    let l = net.label(r);
    let w = net.engine(a).epochs(&g).unwrap().write.newest_held().unwrap().1.clone();
    let head_write = label_role_key(LabelRole::Write, &w, 0);
    let forger = label_role_key(LabelRole::Write, &Secret32::from_bytes([0x66; 32]), 0);
    let conn = net.conn_to(r, sv).expect("connected");
    let (forged, p) = junk(&l, 5, 1, Some(&forger));
    net.feed(r, Event::Bytes { conn, bytes: frame(p) });
    let (honest, p) = junk(&l, 6, 1, Some(&head_write));
    net.feed(r, Event::Bytes { conn, bytes: frame(p) });
    net.settle(10_000);
    let kept = net.sync(r).entry_meta(&l, &forged[0]).expect("the forged entry is kept, unstamped");
    assert_eq!(kept.1, None, "a stamp not under the head's key kept");
    assert!(net.sync(r).entry_meta(&l, &honest[0]).and_then(|m| m.1).is_some(), "a head-key stamp dropped");
}

// spec/sync.md §2 (a replaced label's content entries are deleted by an admin), §6
// (must-not-hold: outside the label's bodies; deletions wait while an entry that opens is not
// applied, spec/sync.md §3: a receiver keeps what it cannot explain yet): after a label
// replacement the item's content entries under the old label go only once the view is settled.
#[test]
fn outside_delete_waits_for_settled_view_spec_sync_6() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let g = net.group(a, &[], &[sv]);
    let t = net.item(a, g, g, "x");
    net.run();
    let old = net.label(a);
    let ids = entries_of(&mut net, a, &old, t);
    assert!(!ids.is_empty() && ids.iter().all(|i| net.server_ids(sv, &old).contains(i)));
    // a server announces an entry that opens under the group's read secret, without its bytes
    let read = net.engine(a).epochs(&g).unwrap().read.newest_held().unwrap().1.clone();
    let blocker = osis_base::BlobId([0x99; 32]);
    let wrap = osis_crypto::wrap(&read, &blocker, &Secret32::from_bytes([1; 32])).unwrap();
    let conn = net.conn_to(a, sv).expect("connected");
    net.feed(a, Event::Bytes { conn, bytes: push(old, vec![osis_proto::Event::Added { blob_id: blocker, blob: None, wrap, stamp: None }]) });
    net.settle(10_000);
    let (new, acts) = net.sync(a).replace_label(&g, &old).unwrap();
    net.actions(a, acts);
    net.run();
    assert!(!net.server_ids(sv, &new).is_empty());
    let key = net.address(sv).key;
    let v = net.sync(a).verdicts(&key, &old).unwrap().unwrap();
    assert!(v.unsettled.contains(&None), "{:?}", v.unsettled);
    assert!(ids.iter().all(|i| net.server_ids(sv, &old).contains(i)), "deleted as outside on an unsettled view");
    // the server drops the unexplained entry: the view settles and the content goes
    net.feed(a, Event::Bytes { conn, bytes: push(old, vec![osis_proto::Event::Deleted(blocker)]) });
    net.settle(10_000);
    net.advance(61_000);
    assert!(ids.iter().all(|i| !net.server_ids(sv, &old).contains(i)), "content kept under the replaced label on a settled view");
}

// spec/requirements.md (blind nodes: a server cannot link labels), spec/sync.md §2, §5: a hinted
// open (a link's or recovery card's label) presents only the static entry of the key actor it
// follows for, never another held key actor's signing key.
#[test]
fn hinted_open_presents_only_its_key_actor_spec_sync_5() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let (s1, s2) = (Secret32::from_bytes([0x3d; 32]), Secret32::from_bytes([0x3e; 32]));
    let k1 = net.engine(a).hold_key_actor(s1.clone()).unwrap();
    net.engine(a).hold_key_actor(s2.clone()).unwrap();
    let (v1, v2) = (osis_crypto::KeyActorKeys::from_seed(&s1).signing.verifying_key(), osis_crypto::KeyActorKeys::from_seed(&s2).signing.verifying_key());
    let target = LabelId([0x43; 16]);
    let addr = net.address(sv);
    let mut se: SyncEngine = net.take(a);
    let acts = se.follow(k1, k1, target, vec![addr]);
    let conn = acts.iter().find_map(|x| if let Action::Dial { conn, .. } = x { Some(*conn) } else { None }).expect("dial");
    se.handle(Event::Up { conn });
    let mut acts = se.handle(Event::Bytes { conn, bytes: encode_frame(&Hello::new(net.now(), [9; 32]).encode()) });
    let mut statics = Vec::new();
    for _ in 0..64 {
        let opens: Vec<Message> = sent(&acts, conn).into_iter().filter(|m| matches!(m, Message::Open { label, .. } if *label == target)).collect();
        if opens.is_empty() {
            break;
        }
        let mut next = Vec::new();
        for m in opens {
            let Message::Open { id, proof, .. } = m else { continue };
            if let osis_label::Proof::Static { signing, .. } = proof {
                statics.push(signing);
            }
            next.extend(se.handle(Event::Bytes { conn, bytes: frame(Message::Error { id, code: osis_proto::Code::REFUSED }) }));
        }
        acts = next;
    }
    assert!(statics.contains(&v1), "the followed key actor tries its static entry");
    assert!(!statics.contains(&v2), "another held key actor is never named to the server");
}

// spec/sync.md §5 (a superseded step's child is verified under its parent; a hinted label has
// none recorded), spec/requirements.md (blind nodes: a server cannot link labels or recognise
// devices): a server answering a hinted label's open with a step of its choosing gets claims
// only by the actors the hint is for (the thing's members this node is), never by another
// actor this node holds secrets of.
#[test]
fn hinted_walk_claims_only_for_its_actors_spec_sync_5() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    // a is a member of g (b's group) and admin of its own g2
    let g = net.group(b, &[(a, Role::Read)], &[sv]);
    let g2 = net.group_seeded(a, &[], vec![net.address(sv)], 7);
    let k = net.engine(a).hold_key_actor(Secret32::from_bytes([0x3f; 32])).unwrap();
    let held = |net: &mut Net, t| net.engine(a).epochs(&t).unwrap().read.held_newest_first().into_iter().map(|(_, s)| osis_crypto::role_kem(s).x25519().clone()).collect::<Vec<_>>();
    let others: Vec<osis_crypto::X25519Secret> = held(&mut net, g2).into_iter().chain(held(&mut net, g)).collect();
    assert!(!others.is_empty());
    let own = net.engine(a).identity().keys().kem.x25519().clone();
    let target = LabelId([0x44; 16]);
    let addr = net.address(sv);
    let mut se: SyncEngine = net.take(a);
    let acts = se.follow(k, g, target, vec![addr]);
    let conn = acts.iter().find_map(|x| if let Action::Dial { conn, .. } = x { Some(*conn) } else { None }).expect("dial");
    se.handle(Event::Up { conn });
    let mut acts = se.handle(Event::Bytes { conn, bytes: encode_frame(&Hello::new(net.now(), [9; 32]).encode()) });
    let forged = foreign_step(60);
    let (mut walked, mut claims) = (false, Vec::new());
    for _ in 0..64 {
        let opens: Vec<Message> = sent(&acts, conn).into_iter().filter(|m| matches!(m, Message::Open { label, .. } if *label == target)).collect();
        if opens.is_empty() {
            break;
        }
        let mut next = Vec::new();
        for m in opens {
            let Message::Open { id, proof, .. } = m else { continue };
            let reply = match proof {
                // the first guessed sync key is answered with the server's own "next step"
                osis_label::Proof::Sync { .. } if !walked => {
                    walked = true;
                    Message::Step { id, step: forged.clone() }
                }
                osis_label::Proof::Claim { pk, .. } => {
                    claims.push(pk);
                    Message::Error { id, code: osis_proto::Code::REFUSED }
                }
                _ => Message::Error { id, code: osis_proto::Code::REFUSED },
            };
            next.extend(se.handle(Event::Bytes { conn, bytes: frame(reply) }));
        }
        acts = next;
    }
    assert!(walked, "the hinted open was answered with a step");
    assert_eq!(claims, vec![forged.claim_key(&own).unwrap().verifying_key()], "claims by this node's own key only (a's edge on g)");
    for x in &others {
        assert!(!claims.contains(&forged.claim_key(x).unwrap().verifying_key()), "another actor's pseudonym went to the server");
    }
}

// spec/sync.md §5 (claims by the keys a step's claim set lists: members' read-role KEM keys),
// spec/crypto.md §4 (boxes): a node that reads the hinted thing through an actor a rotation
// boxed, with no `/members` edge of it held, still claims by that actor's key, and by no other.
#[test]
fn hinted_walk_claims_for_boxed_actor_spec_sync_5() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    // P and g2: a's groups; g: b's, its rotation boxing P with no edge of P on g
    let p = net.group_seeded(a, &[], vec![net.address(sv)], 5);
    let g2 = net.group_seeded(a, &[], vec![net.address(sv)], 7);
    net.pair(a, b);
    let g = net.group_seeded(b, &[], vec![net.address(sv)], 3);
    let bt = net.tid(b);
    let e = net.engine(b);
    let rcpt = recipients_of(e, &[(bt, Role::Admin), (p, Role::Read)]);
    rotation(e, g, &rcpt, 11, false);
    net.pair(b, a);
    assert!(net.engine(a).epochs(&g).is_some_and(|x| !x.read.held_newest_first().is_empty()), "a reads g through P's box");
    assert!(!net.engine(a).get_typed(&g, &osis_schema::core_types::MEMBERS).unwrap().unwrap_or_default().contains_key(&p), "no edge of P on g");
    let k = net.engine(a).hold_key_actor(Secret32::from_bytes([0x40; 32])).unwrap();
    let kem = |net: &mut Net, t| net.engine(a).epochs(&t).unwrap().read.held_newest_first().into_iter().map(|(_, s)| osis_crypto::role_kem(s).x25519().clone()).collect::<Vec<_>>();
    let ps = kem(&mut net, p);
    let others: Vec<osis_crypto::X25519Secret> = kem(&mut net, g2).into_iter().chain(kem(&mut net, g)).collect();
    let own = net.engine(a).identity().keys().kem.x25519().clone();
    let target = LabelId([0x45; 16]);
    let addr = net.address(sv);
    let mut se: SyncEngine = net.take(a);
    let acts = se.follow(k, g, target, vec![addr]);
    let conn = acts.iter().find_map(|x| if let Action::Dial { conn, .. } = x { Some(*conn) } else { None }).expect("dial");
    se.handle(Event::Up { conn });
    let mut acts = se.handle(Event::Bytes { conn, bytes: encode_frame(&Hello::new(net.now(), [9; 32]).encode()) });
    let forged = foreign_step(70);
    let (mut walked, mut claims) = (false, Vec::new());
    for _ in 0..64 {
        let opens: Vec<Message> = sent(&acts, conn).into_iter().filter(|m| matches!(m, Message::Open { label, .. } if *label == target)).collect();
        if opens.is_empty() {
            break;
        }
        let mut next = Vec::new();
        for m in opens {
            let Message::Open { id, proof, .. } = m else { continue };
            let reply = match proof {
                osis_label::Proof::Sync { .. } if !walked => {
                    walked = true;
                    Message::Step { id, step: forged.clone() }
                }
                osis_label::Proof::Claim { pk, .. } => {
                    claims.push(pk);
                    Message::Error { id, code: osis_proto::Code::REFUSED }
                }
                _ => Message::Error { id, code: osis_proto::Code::REFUSED },
            };
            next.extend(se.handle(Event::Bytes { conn, bytes: frame(reply) }));
        }
        acts = next;
    }
    assert!(walked);
    let want: Vec<_> = ps.iter().map(|x| forged.claim_key(x).unwrap().verifying_key()).collect();
    assert!(!want.is_empty() && want.iter().all(|k| claims.contains(k)), "claims by P's keys");
    assert!(!claims.contains(&forged.claim_key(&own).unwrap().verifying_key()), "not by the node's own key (no edge of it on g)");
    for x in &others {
        assert!(!claims.contains(&forged.claim_key(x).unwrap().verifying_key()), "another actor's pseudonym went to the server");
    }
}

// spec/crypto.md §7, spec/sync.md §5, spec/permissions.md §8: a thing's admin who is no admin of
// its group deletes a write-only member's blobs at a server by the level-1 delete key the writer
// listed from the thing's published `/keys` (the gap hashed tokens left), after a
// rotation of the thing too (it holds the old epoch); the writer's own keys delete none of the
// admin's `admin`-retention blobs (levels stay apart).
#[test]
fn thing_admin_deletes_writer_blobs_by_delete_key_spec_crypto_7() {
    use osis_node::sync::EntryKind;
    use osis_schema::AspectKey;
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let c = net.node(2, &[sv]);
    let w = net.node(3, &[sv]);
    let g = net.group(a, &[(c, Role::Write), (w, Role::Write)], &[sv]);
    let (ct_, wt) = (net.tid(c), net.tid(w));
    // c owns thing t in g and makes w its writer and g its reader (so t's content goes under
    // g's label): t gets secrets of its own and a `/keys`
    let t = net.item(c, g, ct_, "x");
    net.pair(w, c);
    let e = net.engine(c);
    set_edge(e, t, wt, Role::Write);
    set_edge(e, t, g, Role::Read);
    let rs = recipients_of(e, &[(ct_, Role::Admin), (wt, Role::Write), (g, Role::Read)]);
    let rot = rotation(e, t, &rs, 21, false);
    net.run();
    net.pair(c, w);
    assert!(net.engine(w).epochs(&t).unwrap().admin.newest_held().is_none(), "w holds no admin secret of t");
    let cw = net.write(w, t, "by w");
    let h = net.engine(w).header(&cw).unwrap();
    let a0 = &h.aspects[0];
    let l1 = a0.keys.iter().map(|i| h.keys[*i]).find(|k| k.level == 1).expect("the writer lists level 1");
    let admin_now = net.engine(c).epochs(&t).unwrap().admin.newest_held().map(|(_, s)| osis_crypto::DeleteSecret::derive(s).verifying_key()).unwrap();
    assert_eq!(l1.key, admin_now.to_bytes(), "the thing's published admin delete key");
    net.feed(w, Event::Local);
    net.run();
    let l = net.label(a);
    let blobs: Vec<_> = net.sync(w).entries(&l).into_iter().filter(|(_, k)| matches!(k, EntryKind::Commit { commit, .. } if *commit == cw)).map(|(id, _)| id).collect();
    assert!(!blobs.is_empty() && blobs.iter().all(|id| net.server_ids(sv, &l).contains(id)), "w's body uploaded");

    // levels stay apart: w signs for c's rotation commit (admin retention: level 1 only) with
    // its write key at level 3 and at level 1; the server refuses both
    assert!(net.engine(w).delete_secrets_of(&rot, &[(0, 0)]).is_empty(), "w holds no key of an admin body");
    let rblobs: Vec<_> = net.sync(c).entries(&l).into_iter().filter(|(_, k)| matches!(k, EntryKind::Commit { commit, .. } if *commit == rot)).map(|(id, _)| id).collect();
    assert!(!rblobs.is_empty());
    let wk = osis_crypto::DeleteSecret::derive(net.engine(w).epochs(&t).unwrap().write.newest_held().unwrap().1);
    let gl = net.sync(w).labels().into_iter().find(|(x, _)| *x == g).unwrap().1;
    let head = net.server_path(sv, &l).last().unwrap().clone();
    let keys = net.engine(w).head_keys(&g, gl.index, &head).unwrap();
    let (sync, write) = (keys.sync.unwrap(), keys.write.unwrap());
    let rhb = net.engine(c).header(&rot).unwrap().blind;
    let mut items = Vec::new();
    for b in &rblobs {
        let bytes = net.engine(c).blob(b).unwrap().unwrap();
        let p = osis_label::Prefix::parse(&bytes).unwrap();
        items.push(osis_label::DeleteItem::sign_by(&write, &wk, 3, p.salt(), &rhb, &l, *b, None).unwrap());
        items.push(osis_label::DeleteItem::sign_by(&sync, &wk, 1, p.salt(), &rhb, &l, *b, None).unwrap());
    }
    let conn = net.conn_to(w, sv).expect("connected");
    net.actions(w, vec![Action::Send { conn, bytes: frame(Message::Delete { id: 900_010, label: l, items }) }]);
    net.settle(10_000);
    assert!(rblobs.iter().all(|id| net.server_ids(sv, &l).contains(id)), "the writer deleted an admin body");

    // c rotates t again, then purges w's write with the group admin and w away: c has no label
    // delete key, so its level-1 key of the old epoch deletes the body at the server
    let e = net.engine(c);
    let rs = recipients_of(e, &[(ct_, Role::Admin), (wt, Role::Write), (g, Role::Read)]);
    rotation(e, t, &rs, 22, false);
    net.run();
    net.pair(c, w);
    assert_ne!(net.engine(c).epochs(&t).unwrap().admin.newest_held().map(|(_, s)| osis_crypto::DeleteSecret::derive(s).verifying_key()).unwrap(), admin_now);
    let gl = net.sync(c).labels().into_iter().find(|(x, _)| *x == g).unwrap().1;
    assert!(net.engine(c).head_keys(&g, gl.index, &head).unwrap().delete.is_none(), "c is no group admin");
    net.set_online(a, false);
    net.set_online(w, false);
    let mut m = osis_node::Mutation::new();
    m.purge(osis_commit::PurgeItem::Commit { commit: cw, tid: t, ak: Ak::new(REG.ak()).unwrap() });
    m.remove_aspect(t, &REG).unwrap();
    net.engine(c).commit(m).unwrap();
    net.feed(c, Event::Local);
    net.run();
    net.run();
    let left: Vec<_> = blobs.iter().filter(|id| net.server_ids(sv, &l).contains(id)).collect();
    assert!(left.is_empty(), "{} of {} blobs of the purged write stay at the server", left.len(), blobs.len());
}

// spec/sync.md §5, spec/crypto.md §7, spec/requirements.md (deletion needs current membership):
// a removed writer still holds a valid delete key for its own blob (its author chain), but its
// label sync key is stale once the admin re-registers: the server refuses the delete.
#[test]
fn removed_writer_stale_label_key_refused_spec_sync_5() {
    use osis_node::sync::EntryKind;
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let w = net.node(2, &[sv]);
    let g = net.group(a, &[(w, Role::Write)], &[sv]);
    let t = net.item(a, g, g, "x");
    net.run();
    let cw = net.write(w, t, "by w");
    net.feed(w, Event::Local);
    net.run();
    let l = net.label(a);
    let blobs: Vec<_> = net.sync(w).entries(&l).into_iter().filter(|(_, k)| matches!(k, EntryKind::Commit { commit, .. } if *commit == cw)).collect();
    assert!(!blobs.is_empty());
    // w's keys before its removal: its author-chain delete key and the head's sync key
    let mut ds = net.engine(w).delete_secrets_of(&cw, &[(0, 0)]);
    let (level, dk) = ds.iter().position(|x| x.0 == 2).map(|i| ds.remove(i)).expect("w holds its level-2 key");
    let gl = net.sync(w).labels().into_iter().find(|(x, _)| *x == g).unwrap().1;
    let old_head = net.server_path(sv, &l).last().unwrap().clone();
    let sync = net.engine(w).head_keys(&g, gl.index, &old_head).unwrap().sync.unwrap();
    let hb = net.engine(w).header(&cw).unwrap().blind;
    // positive control: the same delete verifies against the head before the removal
    for (b, k) in &blobs {
        let EntryKind::Commit { salt, .. } = k else { unreachable!() };
        let item = osis_label::DeleteItem::sign_by(&sync, &dk, level, salt, &hb, &l, *b, None).unwrap();
        let prefix = osis_label::Prefix::parse(&net.engine(w).blob(b).unwrap().unwrap()).unwrap();
        item.verify(&old_head, Some(&prefix)).unwrap();
    }
    // the admin removes w with a rotation and steps the label
    let (at, wt) = (net.tid(a), net.tid(w));
    let e = net.engine(a);
    let rs = recipients_of(e, &[(at, Role::Admin)]);
    remove_member(e, g, wt, &rs, 31);
    net.feed(a, Event::Local);
    net.run();
    net.run();
    assert_ne!(net.server_path(sv, &l).last().unwrap().id(), old_head.id(), "the label stepped");
    let mut items = Vec::new();
    for (b, k) in &blobs {
        let EntryKind::Commit { salt, .. } = k else { unreachable!() };
        items.push(osis_label::DeleteItem::sign_by(&sync, &dk, level, salt, &hb, &l, *b, None).unwrap());
    }
    let conn = net.conn_to(w, sv).expect("connected");
    net.actions(w, vec![Action::Send { conn, bytes: frame(Message::Delete { id: 900_020, label: l, items }) }]);
    net.settle(10_000);
    assert!(blobs.iter().all(|(id, _)| net.server_ids(sv, &l).contains(id)), "a removed member's delete went through");
}
