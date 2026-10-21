#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! A malicious blind node against a node's sync engine (spec/requirements.md: "Nothing trusts a
//! server's word"; "Peer input never causes unbounded allocation, work, storage or
//! diagnostics"): frames injected on a node's server connection, or a scripted server; plus
//! what deletion must reach at a blind node.

mod net;
use net::*;
use osis_core::format::MAX_DRIFT_MS;
use osis_core::{Ak, LabelId, Role, Value};
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

// spec/sync.md §9 (receivers drop a signal whose `ts` is more than `MAX_DRIFT` from their
// corrected clock): a server replaying a captured signal later fires nothing.
#[test]
fn replayed_signal_dropped_spec_sync_9() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let g = net.group(a, &[(b, Role::Read)], &[sv]);
    let t = net.item(a, g, g, "x");
    net.run();
    let acts = net.sync(a).signal(&t, Ak::new("/t/typing").unwrap(), Value::Bool(true), None).unwrap();
    let conn_a = net.conn_to(a, sv).unwrap();
    let captured = sent(&acts, conn_a).into_iter().find(|m| matches!(m, Message::Signal { .. })).expect("signal sent");
    net.actions(a, acts);
    net.settle(10_000);
    assert_eq!(net.sync(b).take_signals().len(), 1, "delivered once");
    net.clock.advance(MAX_DRIFT_MS + 60_000);
    let conn_b = net.conn_to(b, sv).unwrap();
    net.feed(b, Event::Bytes { conn: conn_b, bytes: frame(captured) });
    assert!(net.sync(b).take_signals().is_empty(), "a stale replay fires nothing");
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
// chunks]" at untrusted nodes), spec/sync.md §5 (token holders delete must-not-hold bodies): a
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
    let chunks: Vec<osis_core::BlobId> = net.engine(a).header(&c).unwrap().chunks.iter().map(|ch| ch.blob).collect();
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

// spec/crypto.md §7 (chunk token: one per token secret of the delta that created the chunk),
// spec/sync.md §5: a writer that is no admin of the label purges a `writer` value another node
// wrote; it fetches the chunks it never read for their salts and deletes them by chunk token.
#[test]
fn writer_purge_deletes_chunks_by_token_spec_crypto_7() {
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
    let chunks: Vec<osis_core::BlobId> = net.engine(a).header(&c).unwrap().chunks.iter().map(|ch| ch.blob).collect();
    assert!(!chunks.is_empty(), "a chunked value");
    assert!(chunks.iter().all(|id| net.server_ids(sv, &l).contains(id)), "chunks uploaded");
    // the admin (holder of the delete key) is gone: only the writer's token can delete
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
    let prefix = osis_label::Prefix::new([5; 16], Some(osis_core::WallMs(T0 + 1_000_000_000)), vec![]).unwrap();
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
fn junk(l: &LabelId, tag: u8, n: u8, stamp_key: Option<&osis_crypto::SigningSecret>) -> (Vec<osis_core::BlobId>, Message) {
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
