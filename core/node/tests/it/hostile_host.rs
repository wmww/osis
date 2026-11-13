#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! A malicious host against a node's sync engine (spec/requirements.md: "Nothing trusts a
//! host's word"; "Peer input never causes unbounded allocation, work, storage or
//! diagnostics"): frames injected on a node's connection to a peer that cannot read the label, or a scripted one; plus
//! what deletion must reach at a host.

use crate::net::hosted;
use crate::net;
use net::*;
use osis_base::format::MAX_DRIFT_MS;
use osis_base::{Ak, LabelId, Role, Value};
use osis_crypto::{Epoch, LabelRole, Secret32, SeededRng, label_role_key};
use osis_label::{Parent, StepKeys, genesis_label, register};
use osis_node::sync::{Action, Event};
use osis_proto::{Message, encode_frame};

fn frame(m: Message) -> Vec<u8> {
    encode_frame(&m.encode())
}


/// A valid genesis step of some other label.
pub(crate) fn foreign_step(b: u8) -> osis_label::Step {
    let (read, write, admin, dep) = (Secret32::from_bytes([b; 32]), Secret32::from_bytes([b + 1; 32]), Secret32::from_bytes([b + 2; 32]), Secret32::from_bytes([b + 3; 32]));
    let keys = StepKeys::derive(&read, &write, &admin, &dep, &genesis_label(&admin));
    let delete = label_role_key(LabelRole::Delete, &admin);
    register(Parent::Genesis(&delete), keys, &[], (&osis_base::Tid::from_bytes([b; 15]), Epoch::new(0, [0; 32]).unwrap(), &read), (Epoch::new(0, [0; 32]).unwrap(), &read), &mut SeededRng::from_u64(b as u64)).unwrap().0
}

// spec/wire.md §11.2 (Pull: a stream carries the members of the connection's shared set), spec/
// requirements.md (peer input never causes unbounded storage): a Stream for a label the node never
// opened on that connection stores no entry and no blob.
#[test]
fn unsolicited_push_stores_nothing_spec_wire_11_2() {
    let (mut net, host, [a], g, []) = hosted::<1, 0>(&[], [], false);
    net.item(a, g, g, "x");
    net.run();
    let conn = net.conn_to(a, host).expect("connected");
    let junk = LabelId([0x77; 16]);
    let blobs: Vec<Vec<u8>> = (0..50u8).map(|i| vec![i; 64]).collect();
    let events = blobs.iter().map(|b| osis_proto::Event::Added { blob_id: osis_label::blob_id(b), blob: Some(b.clone()), wrap: [1; osis_crypto::WRAP_LEN], stamp: None }).collect();
    net.receive(a, conn, frame(crate::net::stream_msg(junk, events, 1)));
    net.settle(10_000);
    assert!(net.sync(a).entries(&junk).is_empty(), "no entry under a label not opened");
    for b in &blobs {
        assert!(!net.sync(a).holds_blob(&osis_label::blob_id(b)), "no blob stored");
    }
}

/// The first relay-only entry sent on `conn` (a cursorless Stream carrying its bytes): its label
/// and event.
fn relay_sent(acts: &[Action], hc: osis_node::sync::ConnId) -> Option<(osis_base::LabelId, osis_proto::Event)> {
    Net::sent_on(acts, hc).into_iter().find_map(|m| match m {
        Message::Stream(x) if x.cursor.is_none() => x.events.into_iter().find(|(_, e)| matches!(e, osis_proto::Event::Added { blob: Some(b), stamp: Some(_), .. } if osis_label::Prefix::parse(b).is_ok_and(|p| p.class() == osis_label::Class::Relay))),
        _ => None,
    })
}

// spec/sync.md §9 (a relay-only commit older than `MAX_DRIFT` is dropped, its only replay window;
// one delivered is remembered): a host pushing a captured ephemeral signal again fires nothing, at once
// or later.
#[test]
fn replayed_ephemeral_signal_dropped_spec_sync_9() {
    let (mut net, host, [a, b], _g, [t]) = hosted::<2, 1>(&[(1, Role::Read)], ["x"], true);
    let rx = net.listen(b);
    let mut m = osis_node::Mutation::new();
    m.set(t, &crate::common::ak("t:typing+~0"), &Value::Bool(true)).unwrap();
    net.engine(a).write(m).unwrap();
    let acts = net.sync(a).handle(Event::Local);
    let conn_a = net.link_conn(a, net.conn_to(a, host).unwrap());
    let (label, entry) = relay_sent(&acts, conn_a).expect("relay-only entry sent");
    net.actions(a, acts);
    net.settle(10_000);
    assert_eq!(fired(&rx).len(), 1, "delivered once");
    let push = |e: &osis_proto::Event| crate::net::stream_msg(label, vec![e.clone()], 0);
    let conn_b = net.conn_to(b, host).unwrap();
    net.receive(b, conn_b, frame(push(&entry)));
    assert!(fired(&rx).is_empty(), "a duplicate fires nothing");
    net.clock.advance(MAX_DRIFT_MS + 60_000);
    let conn_b = net.conn_to(b, host).unwrap();
    net.receive(b, conn_b, frame(push(&entry)));
    assert!(fired(&rx).is_empty(), "a stale replay fires nothing");
}

// spec/sync.md §9, spec/requirements.md ("Nothing trusts a host's word"): a host pushing more
// junk relay-only blobs (no keys needed: a relay prefix far ahead and random bytes) than a node
// remembers cannot raise the label's floor, so a later real signal through any host still fires
#[test]
fn junk_relays_raise_no_floor_spec_sync_9() {
    let (mut net, host, [a, b], _g, [t]) = hosted::<2, 1>(&[(1, Role::Read)], ["x"], true);
    let rx = net.listen(b);
    let signal = |net: &mut Net, v: bool| {
        let mut m = osis_node::Mutation::new();
        m.set(t, &crate::common::ak("t:typing+~0"), &Value::Bool(v)).unwrap();
        net.engine(a).write(m).unwrap();
        let acts = net.sync(a).handle(Event::Local);
        let conn_a = net.link_conn(a, net.conn_to(a, host).unwrap());
        let (label, _) = relay_sent(&acts, conn_a).expect("relay-only entry sent");
        net.actions(a, acts);
        net.settle(10_000);
        label
    };
    let label = signal(&mut net, true);
    assert_eq!(fired(&rx).len(), 1);
    let far = osis_base::WallMs(net.now() + 2 * MAX_DRIFT_MS - 1_000);
    let junk: Vec<osis_proto::Event> = (0..(1u32 << 16) + 8)
        .map(|n| {
            let mut salt = [0u8; 16];
            salt[..4].copy_from_slice(&n.to_le_bytes());
            let mut blob = osis_label::Prefix::new(salt, Some(far), vec![]).unwrap().with_class(osis_label::Class::Relay).to_bytes();
            blob.extend_from_slice(&[7; 40]);
            osis_proto::Event::Added { blob_id: osis_label::blob_id(&blob), blob: Some(blob), wrap: [0; osis_crypto::WRAP_LEN], stamp: None }
        })
        .collect();
    for chunk in junk.chunks(4096) {
        let conn_b = net.conn_to(b, host).unwrap();
        net.receive(b, conn_b, frame(crate::net::stream_msg(label, chunk.to_vec(), 0)));
    }
    net.clock.advance(1_000);
    signal(&mut net, false);
    assert_eq!(fired(&rx).len(), 1, "the real signal fires");
}

// spec/requirements.md (peer input never causes unbounded storage), spec/sync.md §3 (only writers
// add stamped entries; deposits are readable by co-readers): a host's made-up unstamped
// entries under an opened label that open under nothing held leave no blob, and only a capped
// number of entries.
#[test]
fn junk_under_opened_label_kept_nowhere_spec_sync_3() {
    let (mut net, host, [a], g, []) = hosted::<1, 0>(&[], [], false);
    net.name_inbox_elsewhere(a, g);
    net.item(a, g, g, "x");
    net.run();
    let l = net.label(a);
    let before = net.sync(a).entries(&l).len();
    let conn = net.conn_to(a, host).expect("connected");
    let blobs: Vec<Vec<u8>> = (0..50u8).map(|i| vec![i; 4096]).collect();
    let events = blobs.iter().map(|b| osis_proto::Event::Added { blob_id: osis_label::blob_id(b), blob: Some(b.clone()), wrap: [1; osis_crypto::WRAP_LEN], stamp: None }).collect();
    net.receive(a, conn, frame(crate::net::stream_msg(l, events, 1 << 40)));
    net.settle(10_000);
    for b in &blobs {
        assert!(!net.sync(a).holds_blob(&osis_label::blob_id(b)), "no junk blob kept");
    }
    // past the cap not even the entry: a host's endless junk leaves bounded metadata
    let n = net.sync(a).entries(&l).len();
    assert!(n <= before + 50, "{n}");
}

// spec/requirements.md, Deletion ("an admin's [purge of a large value] removes all of [its
// chunks]" at nodes that cannot read them), spec/sync.md §5 (delete-key holders delete must-not-hold bodies): a
// purged large value's chunk blobs leave the host.
#[test]
fn purged_chunks_leave_the_host_spec_sync_5() {
    use osis_schema::RawKey;
    let (mut net, host, [a, _], _, [t]) = hosted::<2, 1>(&[(1, Role::Write)], ["x"], false);
    net.keep(a, t, &[("t:gone.0", PURGE)]);
    let big: String = (0..300_000u32).map(|i| char::from(b'a' + (i.wrapping_mul(2654435761) >> 27) as u8 % 26)).collect();
    let mut m = osis_node::Mutation::new();
    m.set(t, &GONE, &s(&big)).unwrap();
    let c = net.engine(a).commit(m).unwrap().unwrap();
    net.run();
    let l = net.label(a);
    let chunks: Vec<osis_base::BlobId> = crate::common::linked_blobs(net.engine(a), &c);
    assert!(!chunks.is_empty(), "a chunked value");
    assert!(chunks.iter().all(|id| net.host_ids(host, &l).contains(id)), "chunks held at the host");
    let mut m = osis_node::Mutation::new();
    m.purge_commit(c, t, Ak::new(GONE.ak()).unwrap());
    m.remove_aspect(t, &GONE).unwrap();
    net.engine(a).commit(m).unwrap();
    net.run();
    net.run();
    let left: Vec<_> = chunks.iter().filter(|id| net.host_ids(host, &l).contains(id)).collect();
    assert!(left.is_empty(), "{} of {} chunks of the purged value stay at the host", left.len(), chunks.len());
}

// spec/crypto.md §7 (a chunk commits to the delete keys of the delta that created it),
// spec/sync.md §5: a writer that is no admin of the label purges a `writer` value another node
// wrote; it fetches the chunks it never read for their salts and deletes them by its delete key.
#[test]
fn writer_purge_deletes_chunks_by_delete_key_spec_crypto_7() {
    use osis_schema::RawKey;
    let (mut net, host, [a, b], _, [t]) = hosted::<2, 1>(&[(1, Role::Write)], ["x"], false);
    net.keep(a, t, &[("t:gone.0", PURGE)]);
    let big: String = (0..300_000u32).map(|i| char::from(b'a' + (i.wrapping_mul(2654435761) >> 27) as u8 % 26)).collect();
    let mut m = osis_node::Mutation::new();
    m.set(t, &GONE, &s(&big)).unwrap();
    let c = net.engine(a).commit(m).unwrap().unwrap();
    net.run();
    let l = net.label(a);
    let chunks: Vec<osis_base::BlobId> = crate::common::linked_blobs(net.engine(a), &c);
    assert!(!chunks.is_empty(), "a chunked value");
    assert!(chunks.iter().all(|id| net.host_ids(host, &l).contains(id)), "chunks held at the host");
    // the admin (holder of the delete key) is gone: only the writer's delete key can delete
    net.set_online(a, false);
    let mut m = osis_node::Mutation::new();
    m.purge_commit(c, t, Ak::new(GONE.ak()).unwrap());
    m.remove_aspect(t, &GONE).unwrap();
    net.engine(b).commit(m).unwrap();
    net.feed(b, Event::Local);
    net.run();
    net.run();
    let left: Vec<_> = chunks.iter().filter(|id| net.host_ids(host, &l).contains(id)).collect();
    assert!(left.is_empty(), "{} of {} chunks of the purged value stay at the host", left.len(), chunks.len());
}

// spec/wire.md §5, spec/crypto.md §7, spec/sync.md §5: the chunks and tree nodes of a linked
// header list carry exactly the commit's level-2 (author-chain) commitments; a host deletes
// them by the author-chain delete key, and refuses the thing-admin delete key of the same commit.
#[test]
fn header_list_chunks_level_2_only_spec_wire_5() {
    let (mut net, host, [a], g, [t]) = hosted::<1, 1>(&[], ["x"], false);
    let mut m = osis_node::Mutation::new();
    crate::common::link_aspects(&mut m, t);
    // one aspect its author may purge: the commit lists a level-2 key
    m.set(t, &crate::common::REG, &crate::common::s("own")).unwrap();
    m.retention(t, &crate::common::REG, crate::common::purgeable_by(osis_base::PurgeBy::AuthorOrAdmin)).unwrap();
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
    assert!(lists.iter().all(|id| net.host_ids(host, &l).contains(id)), "header-list blobs held at the host");
    // the commit's own delete secrets per level, found by the header's delete keys
    let mut ds = net.engine(a).delete_secrets_of(&c, &[0]).remove(0);
    assert_eq!(ds.iter().map(|x| x.0).collect::<Vec<_>>(), vec![1, 2]);
    let (chain, admin) = (ds.pop().unwrap().1, ds.pop().unwrap().1);
    let head = net.host_path(host, &l).last().unwrap().clone();
    let sync = net.engine(a).head_keys(&g, &head).unwrap().sync.unwrap();
    // each blob's commitments are blinded by its link blind bound to the header's actor
    // (spec/crypto.md §7): the header's link to the list's tree, and the tree's nodes, give
    // every blob's key
    let mut keys = std::collections::BTreeMap::new();
    let mut stack = vec![h.links.aspects.unwrap()];
    while let Some(link) = stack.pop() {
        keys.insert(link.blob, link.key);
        let bytes = net.engine(a).blob(&link.blob).unwrap().unwrap();
        let (_, pt) = osis_label::open(&bytes, &osis_crypto::Secret32::from_bytes(link.key)).unwrap();
        if let Ok((_, kids)) = osis_label::tree::parse_node(&pt) {
            stack.extend(kids.into_iter().map(|(l, _)| l));
        }
    }
    assert_eq!(keys.len(), lists.len());
    let by = |dk: &osis_crypto::DeleteSecret, level: u8, id: u32, net: &mut Net| {
        let mut items = Vec::new();
        for b in &lists {
            let bytes = net.engine(a).blob(b).unwrap().unwrap();
            let p = osis_label::Prefix::parse(&bytes).unwrap();
            assert_eq!(p.commitments().count(), level2, "level-2 commitments only");
            assert!(p.commitments().all(|x| x[0] == 2));
            items.push(osis_label::DeleteItem::sign_by(&sync, &[(level, dk)], p.salt(), &osis_crypto::thing_blind(&osis_crypto::link_blind(&keys[b]), h.actor.as_bytes()), &l, *b).unwrap());
        }
        let conn = net.conn_to(a, host).expect("connected");
        net.actions(a, vec![Action::Hub { conn: net.link_conn(a, conn), down: osis_host::Down::Message(Box::new(Message::Delete { id, label: l, items })) }]);
        net.settle(10_000);
        lists.iter().filter(|id| net.host_ids(host, &l).contains(id)).count()
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
    let (mut net, host, [a, b], g, [t]) = hosted::<2, 1>(&[(1, Role::Write)], ["x"], true);
    let l = net.label(a);
    net.set_online(a, false);
    let mut m = osis_node::Mutation::new();
    crate::common::link_aspects(&mut m, t);
    let c = net.engine(a).commit(m).unwrap().unwrap();
    let h = net.engine(a).header(&c).unwrap();
    assert!(h.links.aspects.is_some(), "the aspect list goes by link");
    let body = net.engine(a).body(&c).unwrap().unwrap();
    let parts = body.parts.clone();
    // the same body under a prefix with another expiry and no commitments
    let read = net.engine(a).wrap_secret(&g, None).unwrap().unwrap();
    let cb = osis_commit::CommitBlob::decode(&body.plaintext).unwrap();
    let env = osis_commit::seal_commit(&cb, |_| (), |_, _| Some((read.clone(), vec![])), &[], &mut SeededRng::from_u64(0)).unwrap();
    let prefix = osis_label::Prefix::new([5; 16], Some(osis_base::WallMs(T0 + 1_000_000_000)), vec![]).unwrap();
    let (key, blob) = osis_label::frame(&prefix, &env.encode(), &mut SeededRng::from_u64(1)).unwrap();
    let id = osis_label::blob_id(&blob);
    let secret = net.engine(a).wrap_secret(&g, Some((&c, &parts))).unwrap().unwrap();
    let wrap = osis_crypto::wrap(&secret, &id, &key, 1).unwrap();
    let pk = net.engine(a).package(&c).unwrap().unwrap();
    let mut events: Vec<osis_proto::Event> = pk.blobs.iter().map(|(bid, bytes)| osis_proto::Event::Added { blob_id: *bid, blob: Some(bytes.clone()), wrap: [1; osis_crypto::WRAP_LEN], stamp: None }).collect();
    events.push(osis_proto::Event::Added { blob_id: id, blob: Some(blob), wrap, stamp: None });
    let conn = net.conn_to(b, host).expect("connected");
    net.receive(b, conn, frame(crate::net::stream_msg(l, events, 1 << 40)));
    net.settle(10_000);
    // the lists came with it, so the prefix is checked at opening: nothing of the forged blob
    // applies and the entry is bad input
    net.advance(30_000);
    assert!(net.engine(b).header(&c).is_none(), "nothing applied from the forged blob");
    let entries = net.sync(b).entries(&l);
    assert!(entries.iter().any(|(x, k)| *x == id && *k == osis_node::sync::EntryKind::Bad), "the forged blob is bad input");
    // the author back, its own encryption reaches the writer
    net.set_online(a, true);
    net.run();
    assert!(net.engine(b).header(&c).is_some(), "the commit from its author");
    let entries = net.sync(b).entries(&l);
    assert!(entries.iter().any(|(x, k)| *x != id && matches!(k, osis_node::sync::EntryKind::Commit { commit, .. } if *commit == c)), "the author's encryption");
}

/// Junk entries under `l`, unstamped or stamped with `stamp_key`, each `tag`-distinct.
fn junk(l: &LabelId, tag: u8, n: u8, stamp_key: Option<&osis_crypto::SigningSecret>) -> (Vec<osis_base::BlobId>, Message) {
    let blobs: Vec<Vec<u8>> = (0..n).map(|i| vec![tag, i, 7, 7]).collect();
    let ids = blobs.iter().map(|b| osis_label::blob_id(b)).collect();
    let events = blobs
        .iter()
        .map(|b| {
            let id = osis_label::blob_id(b);
            let wrap = [tag; osis_crypto::WRAP_LEN];
            osis_proto::Event::Added { blob_id: id, blob: Some(b.clone()), wrap, stamp: stamp_key.map(|k| osis_label::sign_stamp(k, l, &id, &wrap, false)) }
        })
        .collect();
    (ids, crate::net::stream_msg(*l, events, 1 << 40))
}

// spec/sync.md §3 (unvouched entries); spec/requirements.md ("nothing trusts a host's word"; peer input never causes unbounded
// storage): the cap on unvouched entries counts per host, so one host's junk does not evict
// what another host announces
#[test]
fn unvouched_cap_per_host_spec_sync_3() {
    let mut net = Net::new();
    let (s1, s2) = (net.add_host(), net.add_host());
    let cfg = osis_node::sync::SyncConfig { hosts: vec![net.address(s1), net.address(s2)], unvouched_cap: 8, ..Default::default() };
    let a = net.add_node(1, cfg);
    let g = net.group(a, &[], &[s1, s2]);
    net.name_inbox_elsewhere(a, g);
    net.item(a, g, g, "x");
    net.run();
    let l = net.label(a);
    let (c1, c2) = (net.conn_to(a, s1).expect("s1"), net.conn_to(a, s2).expect("s2"));
    let (_, flood) = junk(&l, 1, 40, None);
    net.receive(a, c1, frame(flood));
    net.settle(10_000);
    let (ids, other) = junk(&l, 2, 1, None);
    net.receive(a, c2, frame(other));
    net.settle(10_000);
    assert!(net.sync(a).entries(&l).iter().any(|(b, _)| *b == ids[0]), "s2's entry crowded out by s1's junk");
}

/// Host `h` lists to writer `b` (`unvouched_cap` 8), unstamped, `n` genuine commits of reader
/// `r` on an item, each invalid at `b`, ephemeral with `memory` (a hostile host's word: an honest
/// one carries at most its deposit budget of them). How many of them `b` knows (a header each,
/// its body dropped) once settled.
fn host_lists_invalid(n: usize, memory: bool) -> usize {
    let mut net = Net::new();
    let h = net.add_host();
    let a = net.node(1, &[h]);
    let b = net.add_node(2, osis_node::sync::SyncConfig { hosts: vec![net.address(h)], unvouched_cap: 8, ..Default::default() });
    let r = net.node(3, &[h]);
    let g = net.group(a, &[(b, Role::Write), (r, Role::Read)], &[h]);
    net.name_inbox_elsewhere(a, g);
    let t = net.item(a, g, g, "x");
    net.run();
    let l = net.label(b);
    let conn = net.conn_to(b, h).expect("connected");
    let mut flood = Vec::new();
    let mut events = Vec::new();
    for i in 0..n {
        let mut m = osis_node::Mutation::new();
        let id = if memory {
            m.set(t, &crate::common::ak("win:notes+.0"), &s(&format!("r{i}"))).unwrap();
            net.engine(r).commit_in_memory_hostile(m).unwrap().unwrap()
        } else {
            m.set(t, &REG, &s(&format!("r{i}"))).unwrap();
            net.engine(r).commit_hostile(m).unwrap().unwrap()
        };
        let cb = osis_commit::CommitBlob::decode(&net.engine(r).take_forged().unwrap()).unwrap();
        let (_, ev) = crate::ephemeral::sealed(&mut net, b, g, &cb, None, 1000 + i as u64);
        flood.push(id);
        events.push(ev);
    }
    net.receive(b, conn, push(l, events));
    net.settle(10_000);
    net.advance(1_000);
    flood.iter().filter(|c| net.engine(b).header(c).is_some()).count()
}

// spec/sync.md §3 (unvouched entries), spec/permissions.md §6 (invalid deltas), spec/requirements.md
// (peer input never causes unbounded storage), security: a host listing unstamped commits invalid
// at the node (their bodies dropped, each header kept while its entry is) counts them against
// `unvouched_cap` as entries it cannot judge, so the node knows as few of them at 10n as at n,
// durable and ephemeral alike
#[test]
fn unvouched_invalid_entries_capped_spec_sync_3() {
    for memory in [false, true] {
        let (k, k10) = (host_lists_invalid(20, memory), host_lists_invalid(200, memory));
        assert!(k <= 9 && k10 <= 9, "memory {memory}: headers known past the cap: {k} at n, {k10} at 10n");
    }
}

// spec/sync.md §5 (honest hosts take stamps under the head's write key only), spec/
// requirements.md (peer input never causes unbounded storage): stamps under a superseded step's
// write key (a removed writer's) vouch for nothing once the head is newer: such entries are
// capped and their bytes not kept
#[test]
fn old_step_stamp_vouches_nothing_spec_sync_5() {
    let mut net = Net::new();
    let host = net.add_host();
    let cfg = osis_node::sync::SyncConfig { hosts: vec![net.address(host)], unvouched_cap: 8, ..Default::default() };
    let a = net.add_node(1, cfg);
    let b = net.node(2, &[host]);
    let g = net.group(a, &[(b, Role::Write)], &[host]);
    net.item(a, g, g, "x");
    net.run();
    let l = net.label(a);
    let old = net.engine(a).epochs(&g).unwrap().write.newest_held().unwrap().1.clone();
    let old_write = label_role_key(LabelRole::Write, &old);
    let (at, bt) = (net.tid(a), net.tid(b));
    let e = net.engine(a);
    let rs = recipients_of(e, &[(at, Role::Admin)]);
    remove_holder(e, g, bt, &rs, 43);
    net.run();
    assert_eq!(net.host_path(host, &l).len(), 2, "a newer step");
    let before = net.sync(a).entries(&l).len();
    let conn = net.conn_to(a, host).expect("connected");
    let (ids, push) = junk(&l, 3, 40, Some(&old_write));
    net.receive(a, conn, frame(push));
    net.settle(10_000);
    for id in &ids {
        assert!(!net.sync(a).holds_blob(id), "junk bytes kept on an old-step stamp");
    }
    let n = net.sync(a).entries(&l).len();
    assert!(n <= before + 9, "{n}");
}

/// A Push of `events` under `l` (a host's word).
fn push(l: LabelId, events: Vec<osis_proto::Event>) -> Vec<u8> {
    frame(crate::net::stream_msg(l, events, 1 << 40))
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
// trusts a host's word"): a host re-announcing a held entry with a wrap that opens under no
// held read secret, or opens to another blob key, changes nothing; a wrap of the same key under
// another held read secret is taken.
#[test]
fn wrap_not_opening_to_known_key_ignored_spec_sync_5() {
    let (mut net, host, [a, r, x], g, [t]) = hosted::<3, 1>(&[(1, Role::Read), (2, Role::Read)], ["x"], true);
    let l = net.label(r);
    // a rotation (x removed): r holds two read secrets
    let (at, rt, xt) = (net.tid(a), net.tid(r), net.tid(x));
    let e = net.engine(a);
    let rs = recipients_of(e, &[(at, Role::Admin), (rt, Role::Read)]);
    remove_holder(e, g, xt, &rs, 44);
    net.run();
    assert_eq!(net.read(r, t), Some(s("x")));
    let secrets: Vec<Secret32> = net.engine(r).epochs(&g).unwrap().read.held_newest_first().into_iter().map(|(_, s)| s.clone()).collect();
    assert!(secrets.len() >= 2, "{}", secrets.len());
    let id = entries_of(&mut net, r, &l, t)[0];
    let (wrap0, _) = net.sync(r).entry_meta(&l, &id).unwrap();
    let (i, key) = osis_label::unwrap_any(secrets.iter(), &id, &wrap0).unwrap();
    assert!(i > 0, "the item's entry is wrapped under the older epoch");
    let conn = net.conn_to(r, host).expect("connected");
    let added = |wrap| vec![osis_proto::Event::Added { blob_id: id, blob: None, wrap, stamp: None }];
    let other_key = osis_crypto::wrap(&secrets[0], &id, &Secret32::from_bytes([0x42; 32]), 1).unwrap();
    for w in [[0x13; osis_crypto::WRAP_LEN], other_key] {
        net.receive(r, conn, push(l, added(w)));
        net.settle(10_000);
        assert_eq!(net.sync(r).entry_meta(&l, &id).unwrap().0, wrap0);
    }
    let rewrap = osis_crypto::wrap(&secrets[0], &id, &key, 1).unwrap();
    net.receive(r, conn, push(l, added(rewrap)));
    net.settle(10_000);
    assert_eq!(net.sync(r).entry_meta(&l, &id).unwrap().0, rewrap, "a re-wrap of the known key is taken");
}

// spec/sync.md §5 (honest hosts take stamps under the head's write key only; anyone may relay
// a stamped entry), spec/requirements.md ("nothing trusts a host's word"): a reader keeps an
// announced entry's stamp only when it verifies under the head's write key, so it never relays
// a forged one as stamped.
#[test]
fn relayed_stamp_checked_against_head_spec_sync_5() {
    let (mut net, host, [a, r], g, []) = hosted::<2, 0>(&[(1, Role::Read)], [], false);
    net.item(a, g, g, "x");
    net.run();
    let l = net.label(r);
    let w = net.engine(a).epochs(&g).unwrap().write.newest_held().unwrap().1.clone();
    let head_write = label_role_key(LabelRole::Write, &w);
    let forger = label_role_key(LabelRole::Write, &Secret32::from_bytes([0x66; 32]));
    let conn = net.conn_to(r, host).expect("connected");
    let (forged, p) = junk(&l, 5, 1, Some(&forger));
    net.receive(r, conn, frame(p));
    let (honest, p) = junk(&l, 6, 1, Some(&head_write));
    net.receive(r, conn, frame(p));
    net.settle(10_000);
    let kept = net.sync(r).entry_meta(&l, &forged[0]).expect("the forged entry is kept, unstamped");
    assert_eq!(kept.1, None, "a stamp not under the head's key kept");
    assert!(net.sync(r).entry_meta(&l, &honest[0]).and_then(|m| m.1).is_some(), "a head-key stamp dropped");
}

// spec/sync.md §6 (must-not-hold: outside the label's bodies; deletions wait while an entry that
// opens is not applied, spec/sync.md §3: a receiver keeps what it cannot explain yet): once an item
// leaves the group, its content entries under the label go only once the view is settled.
#[test]
fn outside_delete_waits_for_settled_view_spec_sync_6() {
    let (mut net, host, [a], g, [t]) = hosted::<1, 1>(&[], ["x"], true);
    let l = net.label(a);
    // a write on the item alone (its first commit also writes the group's membership)
    let before = entries_of(&mut net, a, &l, t);
    net.write(a, t, "y");
    net.run();
    let ids: Vec<_> = entries_of(&mut net, a, &l, t).into_iter().filter(|i| !before.contains(i)).collect();
    assert!(!ids.is_empty() && ids.iter().all(|i| net.host_ids(host, &l).contains(i)));
    // a host announces an entry that opens under the group's read secret, without its bytes
    let read = net.engine(a).epochs(&g).unwrap().read.newest_held().unwrap().1.clone();
    let blocker = osis_base::BlobId([0x99; 32]);
    let wrap = osis_crypto::wrap(&read, &blocker, &Secret32::from_bytes([1; 32]), 1).unwrap();
    let conn = net.conn_to(a, host).expect("connected");
    net.receive(a, conn, push(l, vec![osis_proto::Event::Added { blob_id: blocker, blob: None, wrap, stamp: None }]));
    net.settle(10_000);
    // the item leaves the group: its entries are outside the label's bodies
    let mut items = net.engine(a).get_typed(&g, &osis_schema::core_types::GROUP).unwrap().unwrap_or_default();
    items.items.remove(&t);
    let mut m = osis_node::Mutation::new();
    m.set(g, &osis_schema::core_types::GROUP, &items).unwrap();
    net.engine(a).commit(m).unwrap();
    net.run();
    let key = net.address(host).key;
    let v = net.sync(a).verdicts(&key, &l).unwrap().unwrap();
    assert!(v.unsettled.contains(&None), "{:?}", v.unsettled);
    assert!(ids.iter().all(|i| net.host_ids(host, &l).contains(i)), "deleted as outside on an unsettled view");
    // the host drops the unexplained entry: the view settles and the content goes
    net.receive(a, conn, push(l, vec![osis_proto::Event::Deleted(blocker)]));
    net.settle(10_000);
    net.advance(61_000);
    assert!(ids.iter().all(|i| !net.host_ids(host, &l).contains(i)), "content outside the group kept on a settled view");
}

// spec/crypto.md §7, spec/sync.md §5, spec/permissions.md §6: a thing's admin who is no admin of
// its group deletes a write-only holder's blobs at a host by the level-1 delete key the writer
// listed from the thing's published `keys.0` (the gap hashed tokens left), after a
// rotation of the thing too (it holds the old epoch); the writer's own keys delete none of the
// admin's `admin`-retention blobs (levels stay apart).
#[test]
fn thing_admin_deletes_writer_blobs_by_delete_key_spec_crypto_7() {
    use osis_node::sync::EntryKind;
    use osis_schema::RawKey;
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let c = net.node(2, &[host]);
    let w = net.node(3, &[host]);
    let g = net.group(a, &[(c, Role::Write), (w, Role::Write)], &[host]);
    let (ct_, wt) = (net.tid(c), net.tid(w));
    // c is first admin of thing t in g and makes w its writer and g its reader (so t's content goes under
    // g's label): t gets secrets of its own and a `keys.0`
    let t = net.item(c, g, ct_, "x");
    net.pair(w, c);
    let e = net.engine(c);
    // bare edges: the rotation below boxes every holder before any pass (a grant by hand)
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
    assert!(!blobs.is_empty() && blobs.iter().all(|id| net.host_ids(host, &l).contains(id)), "w's body held at the host");

    // levels stay apart: w signs for c's rotation commit (admin retention: level 1 only) with
    // its write key at level 3 and at level 1; the host refuses both
    assert!(net.engine(w).delete_secrets_of(&rot, &[0]).iter().all(Vec::is_empty), "w holds no key of an admin body");
    let rblobs: Vec<_> = net.sync(c).entries(&l).into_iter().filter(|(_, k)| matches!(k, EntryKind::Commit { commit, .. } if *commit == rot)).map(|(id, _)| id).collect();
    assert!(!rblobs.is_empty());
    let wk = osis_crypto::DeleteSecret::derive(net.engine(w).epochs(&t).unwrap().write.newest_held().unwrap().1);
    let head = net.host_path(host, &l).last().unwrap().clone();
    let keys = net.engine(w).head_keys(&g, &head).unwrap();
    let (sync, write) = (keys.sync.unwrap(), keys.write.unwrap());
    let rhb = net.engine(c).header(&rot).unwrap().blind;
    let mut items = Vec::new();
    for b in &rblobs {
        let bytes = net.engine(c).blob(b).unwrap().unwrap();
        let p = osis_label::Prefix::parse(&bytes).unwrap();
        items.push(osis_label::DeleteItem::sign_by(&write, &[(3, &wk)], p.salt(), &rhb, &l, *b).unwrap());
        items.push(osis_label::DeleteItem::sign_by(&sync, &[(1, &wk)], p.salt(), &rhb, &l, *b).unwrap());
    }
    let conn = net.conn_to(w, host).expect("connected");
    net.actions(w, vec![Action::Hub { conn: net.link_conn(w, conn), down: osis_host::Down::Message(Box::new(Message::Delete { id: 900_010, label: l, items })) }]);
    net.settle(10_000);
    assert!(rblobs.iter().all(|id| net.host_ids(host, &l).contains(id)), "the writer deleted an admin body");

    // c rotates t again, then purges w's write with the group admin and w away: c has no label
    // delete key, so its level-1 key of the old epoch deletes the body at the host
    let e = net.engine(c);
    let rs = recipients_of(e, &[(ct_, Role::Admin), (wt, Role::Write), (g, Role::Read)]);
    rotation(e, t, &rs, 22, false);
    net.run();
    net.pair(c, w);
    assert_ne!(net.engine(c).epochs(&t).unwrap().admin.newest_held().map(|(_, s)| osis_crypto::DeleteSecret::derive(s).verifying_key()).unwrap(), admin_now);
    assert!(net.engine(c).head_keys(&g, &head).unwrap().delete.is_none(), "c is no group admin");
    net.set_online(a, false);
    net.set_online(w, false);
    let mut m = osis_node::Mutation::new();
    m.purge_commit(cw, t, Ak::new(REG.ak()).unwrap());
    m.remove_aspect(t, &REG).unwrap();
    net.engine(c).commit(m).unwrap();
    net.feed(c, Event::Local);
    net.run();
    net.run();
    let left: Vec<_> = blobs.iter().filter(|id| net.host_ids(host, &l).contains(id)).collect();
    assert!(left.is_empty(), "{} of {} blobs of the purged write stay at the host", left.len(), blobs.len());
}

// spec/sync.md §5, spec/crypto.md §7, spec/requirements.md (deletion needs current roles):
// a removed writer still holds a valid delete key for its own blob (its author chain), but its
// label sync key is stale once the admin re-registers: the host refuses the delete.
#[test]
fn removed_writer_stale_label_key_refused_spec_sync_5() {
    use osis_node::sync::EntryKind;
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let w = net.node(2, &[host]);
    let g = net.group(a, &[(w, Role::Write)], &[host]);
    let t = net.item(a, g, g, "x");
    net.run();
    let cw = net.write_own(w, t, "by w");
    net.feed(w, Event::Local);
    net.run();
    let l = net.label(a);
    let blobs: Vec<_> = net.sync(w).entries(&l).into_iter().filter(|(_, k)| matches!(k, EntryKind::Commit { commit, .. } if *commit == cw)).collect();
    assert!(!blobs.is_empty());
    // w's keys before its removal: its author-chain delete key and the head's sync key
    let mut ds = net.engine(w).delete_secrets_of(&cw, &[0]).remove(0);
    let (level, dk) = ds.iter().position(|x| x.0 == 2).map(|i| ds.remove(i)).expect("w holds its level-2 key");
    let old_head = net.host_path(host, &l).last().unwrap().clone();
    let sync = net.engine(w).head_keys(&g, &old_head).unwrap().sync.unwrap();
    let hb = net.engine(w).header(&cw).unwrap().blind;
    // positive control: the same delete verifies against the head before the removal
    let salts: Vec<[u8; 16]> = blobs.iter().map(|(b, _)| *osis_label::Prefix::parse(&net.engine(w).blob(b).unwrap().unwrap()).unwrap().salt()).collect();
    for ((b, _), salt) in blobs.iter().zip(&salts) {
        let item = osis_label::DeleteItem::sign_by(&sync, &[(level, &dk)], salt, &hb, &l, *b).unwrap();
        let prefix = osis_label::Prefix::parse(&net.engine(w).blob(b).unwrap().unwrap()).unwrap();
        item.verify(&old_head, Some(&prefix)).unwrap();
    }
    // the admin removes w with a rotation and steps the label
    let (at, wt) = (net.tid(a), net.tid(w));
    let e = net.engine(a);
    let rs = recipients_of(e, &[(at, Role::Admin)]);
    remove_holder(e, g, wt, &rs, 31);
    net.feed(a, Event::Local);
    net.run();
    net.run();
    assert_ne!(net.host_path(host, &l).last().unwrap().id(), old_head.id(), "the label stepped");
    let mut items = Vec::new();
    for ((b, _), salt) in blobs.iter().zip(&salts) {
        items.push(osis_label::DeleteItem::sign_by(&sync, &[(level, &dk)], salt, &hb, &l, *b).unwrap());
    }
    let conn = net.conn_to(w, host).expect("connected");
    net.actions(w, vec![Action::Hub { conn: net.link_conn(w, conn), down: osis_host::Down::Message(Box::new(Message::Delete { id: 900_020, label: l, items })) }]);
    net.settle(10_000);
    assert!(blobs.iter().all(|(id, _)| net.host_ids(host, &l).contains(id)), "a removed holder's delete went through");
}


// spec/sync.md §5 Promotion, §6 Tombstones: a host showing again an entry its writer removed
// (one that kept it past the delete) is judged there as any entry, never taken for a deposit:
// the writer promotes no blob within its tombstone, so nothing new goes to the host. Here the
// removed blob holds a live part a snapshot covers, its bytes kept, its other part re-placed.
#[test]
fn a_removed_entry_shown_again_is_not_promoted_spec_sync_5() {
    use osis_node::sync::EntryKind;
    use osis_schema::RawKey;
    let mut net = Net::new();
    let host = net.add_host();
    let (a, b) = (net.node(1, &[host]), net.node(2, &[host]));
    let g = net.group(a, &[(b, Role::Write)], &[host]);
    let t = net.item(a, g, g, "x");
    net.run();
    let l = net.label(a);
    let mut m = osis_node::Mutation::new();
    m.set(t, &REG, &s("one")).unwrap();
    m.set(t, &GONE, &s("kept")).unwrap();
    let c = net.engine(b).commit(m).unwrap().unwrap();
    net.run();
    let ids = net.sync(b).entries(&l).into_iter().filter(|(_, k)| matches!(k, EntryKind::Commit { commit, .. } if *commit == c)).map(|(id, _)| id).collect::<Vec<_>>();
    let [id] = ids[..] else { panic!("{ids:?}") };
    let blob = net.engine(b).blob(&id).unwrap().unwrap();
    let (wrap, _) = net.sync(b).entry_meta(&l, &id).unwrap();
    net.advance(osis_base::format::ROLE_KEEP_MS + 3_600_000);
    net.run();
    let acts = net.sync(a).compact_now(&t, &Ak::new(REG.ak()).unwrap()).unwrap();
    net.actions(a, acts);
    net.run();
    net.advance(MAX_DRIFT_MS);
    net.run();
    let before = net.host_ids(host, &l);
    assert!(!before.contains(&id) && net.engine(b).blob(&id).unwrap().is_some(), "removed at the host, its bytes kept");
    let conn = net.conn_to(b, host).unwrap();
    let e = osis_proto::Event::Added { blob_id: id, blob: Some(blob), wrap, stamp: None };
    net.receive(b, conn, frame(crate::net::stream_msg(l, vec![e], (1 << 40) + 5)));
    net.run();
    net.advance(MAX_DRIFT_MS);
    net.run();
    assert_eq!(net.host_ids(host, &l), before, "the writer placed something for the removed entry");
}

/// A forged chain on `real`, the head of a label (spec/sync.md §5 Opens): `real` with the delete
/// key swapped for the forger's own (it verifies under nothing), then a child signed by that key,
/// carrying `real`'s sync key (an open by it lasts) and the forger's other keys.
fn forged_chain(real: &osis_label::Step) -> Vec<osis_label::Step> {
    let k = |b: u8| Secret32::from_bytes([b; 32]);
    let own = label_role_key(LabelRole::Delete, &k(0xf0));
    let mut head = real.clone();
    head.keys.delete = own.verifying_key();
    let mut keys = StepKeys::derive(&k(0xf1), &k(0xf2), &k(0xf3), &k(0xf4), &real.label);
    keys.sync = real.keys.sync;
    let at = Epoch::new(0, [0; 32]).unwrap();
    let child = register(Parent::Child { step: &head, delete: &own }, keys, &[], (&osis_base::Tid::from_bytes([0xf5; 15]), at, &k(0xf6)), (at, &k(0xf7)), &mut SeededRng::from_u64(0xf8)).unwrap().0;
    child.verify_child(&head).unwrap();
    vec![head, child]
}

/// An admin `c` of a group with admin `a` at peer `s` opens its label `l` with no head (spec/
/// sync.md §5 Walk: L rotated while c was away, and c learned the newest secrets alone, as an
/// inbox grant would bring them, so it holds a sync key no recorded step bears), while `s` names
/// the steps `forge(real head)` gives wherever it would name its head, and `a` is away. c writes
/// an item meanwhile. Checked: c records none of the named steps in `label.0`, nor any step
/// under them, and registers nothing under them. Returns the net, `[s, a, c]`, `l`, the
/// item and the host's entries of `l` before it, the tamper still on.
fn opened_on_forged_heads(forge: impl Fn(&osis_label::Step) -> Vec<osis_label::Step>) -> (Net, [usize; 3], LabelId, osis_base::Tid, Vec<osis_base::BlobId>) {
    use osis_proto::Event as Ev;
    use std::cell::RefCell;
    use std::rc::Rc;
    let (mut net, s, [a, c]) = hosted_nodes::<2>();
    let g = net.group(a, &[(c, Role::Admin)], &[s]);
    net.item(a, g, g, "item");
    net.run();
    net.advance(61_000);
    let l = net.label(a);
    net.set_online(c, false);
    let (at, ct_) = (net.tid(a), net.tid(c));
    let rs = recipients_of(net.engine(a), &[(at, Role::Admin), (ct_, Role::Admin)]);
    rotation(net.engine(a), g, &rs, 61, false);
    net.run();
    net.advance(61_000);
    let real = net.host_path(s, &l).last().unwrap().clone();
    assert!(!net.group_labels(c).iter().any(|(_, gl)| gl.steps.contains_key(&real.id())), "c never recorded the head");
    for r in [Role::Sync, Role::Read, Role::Write, Role::Admin] {
        let ep = net.engine(a).epochs(&g).unwrap();
        let (e, secret) = ep.role(r).held_newest_first().into_iter().next().map(|(e, x)| (e, x.clone())).unwrap();
        net.engine(c).learn_secret(&g, r, e, secret).unwrap();
    }
    net.set_online(a, false);
    let named = forge(&real);
    let forged: Vec<_> = named.iter().map(|x| x.id()).collect();
    let heads: Vec<Ev> = named.into_iter().map(Ev::Head).collect();
    let swap = move |evs: &[(LabelId, Ev)]| -> Vec<(LabelId, Ev)> {
        evs.iter()
            .flat_map(|(x, e)| match e {
                Ev::Head(_) if *x == l => heads.iter().map(|h| (l, h.clone())).collect(),
                _ => vec![(*x, e.clone())],
            })
            .collect()
    };
    net.host_tamper = Some(Box::new(move |m| match m {
        Message::Stream(st) if st.events.iter().any(|(_, e)| matches!(e, Ev::Head(_))) => Some(Message::Stream(Box::new(osis_proto::msg::Stream { events: swap(&st.events), ..(**st).clone() }))),
        Message::PullReply(r) if r.events.iter().any(|(_, e)| matches!(e, Ev::Head(_))) => Some(Message::PullReply(Box::new(osis_proto::msg::PullReply { events: swap(&r.events), ..(**r).clone() }))),
        _ => None,
    }));
    // what c registers at the peer meanwhile
    let registered = Rc::new(RefCell::new(Vec::new()));
    let r2 = registered.clone();
    net.tamper_link = Some((c, s));
    net.tamper = Some(Box::new(move |m| {
        if let Message::Register { step, .. } = m {
            r2.borrow_mut().push(step.clone());
        }
        None
    }));
    net.set_online(c, true);
    for _ in 0..3 {
        net.run();
        net.advance(61_000);
    }
    let conn = net.conn_to(c, s).expect("connected");
    assert!(net.sync(c).shared_members(conn).contains(&l), "L open at the peer: {:?}", net.sync(c).describe());
    let before = net.host_ids(s, &l);
    let t = net.item(c, g, g, "meanwhile");
    for _ in 0..3 {
        net.run();
        net.advance(61_000);
    }
    let under = |x: &osis_label::Step| forged.contains(&x.id()) || x.prev.is_some_and(|p| forged.contains(&p));
    for (_, gl) in net.group_labels(c) {
        assert!(!gl.steps.values().any(|(x, _)| under(x)), "a named step, or one under it, in label.0");
    }
    assert!(!registered.borrow().iter().any(under), "a step registered under the named ones");
    (net, [s, a, c], l, t, before)
}

// spec/sync.md §5 (Opens, Walk: a sync key no recorded step bears opens at the head the stream
// names), §2 (label.0 records the path): a peer that cannot read L names a forged head carrying
// L's sync key under its own delete key, then a child signed by it, to an admin that opened L
// with no head. The admin records neither step in `label.0` and registers nothing under them;
// once the peer is honest again, its write made meanwhile reaches the others.
#[test]
fn a_forged_head_and_its_child_are_never_recorded_spec_sync_5() {
    let (mut net, [_, a, c], _, t, _) = opened_on_forged_heads(forged_chain);
    net.host_tamper = None;
    net.tamper = None;
    net.tamper_link = None;
    net.set_online(c, false);
    net.set_online(c, true);
    net.set_online(a, true);
    for _ in 0..4 {
        net.run();
        net.advance(61_000);
    }
    assert_eq!(net.read(a, t), Some(net::s("meanwhile")));
}

// spec/sync.md §5 (Re-registration: an admin issues a child of a head recorded in `label.0`): a
// peer names a head carrying L's real keys but another deposit key to an admin that opened L
// with no head. Such a head would be due a child (its deposit key is not the actor's), but the
// admin issues none under a head the peer alone named: none of its passes fails, and its write
// reaches the peer meanwhile.
#[test]
fn no_step_under_an_unrecorded_head_spec_sync_5() {
    let forge = |real: &osis_label::Step| {
        let mut head = real.clone();
        head.keys.deposit = label_role_key(LabelRole::Delete, &Secret32::from_bytes([0xf0; 32])).verifying_key();
        vec![head]
    };
    let (mut net, [s, _, c], l, _, before) = opened_on_forged_heads(forge);
    let d = net.diagnostics(c);
    assert!(!d.iter().any(|x| x.contains("pass of")), "every pass ran: {d:?}");
    assert!(net.host_ids(s, &l).len() > before.len(), "c's write reached the peer");
}


// spec/sync.md §6 (a delete stands once it took a body placed again past one), notes/peers.md
// (a host lying in its log): host `h` never lists admin b's covering snapshots to writer a. b
// deletes a's write as covered; a, seeing no cover, places it again once, b deletes that too, and
// the delete stands: no fresh blob and tombstone per round trip at either writer (else a storm
// growing both stores). Quiet from then on: the host logs nothing more, both stores hold steady
// (rows and bytes), across a restart of a.
#[test]
fn a_host_hiding_a_cover_from_one_writer_costs_one_placement_again_spec_sync_6() {
    use osis_node::sync::EntryKind;
    use std::collections::BTreeSet;
    let mut net = Net::new();
    let h = net.add_host();
    let a = net.node(1, &[h]);
    let b = net.node(2, &[h]);
    let g = net.group(b, &[(a, Role::Write)], &[h]);
    let t = net.item(b, g, g, "first");
    net.run();
    let reg = Ak::new("t:reg.0").unwrap();
    let mut m = osis_node::Mutation::new();
    m.set(t, &reg, &s("a's")).unwrap();
    let c = net.engine(a).commit(m).unwrap().unwrap();
    net.run();
    let l = net.label(a);
    let known: BTreeSet<_> = net.sync(a).entries(&l).into_iter().map(|(id, _)| id).collect();
    let of_c = |k: &EntryKind| matches!(k, EntryKind::Commit { commit, .. } if *commit == c);
    // what b logs from now on, a's write placed again aside, the host never lists to a
    let hide = |net: &mut Net| {
        let hidden = net.sync(b).entries(&l).into_iter().filter(|(id, k)| !known.contains(id) && !of_c(k)).map(|(id, _)| id).collect();
        net.hide_blobs.insert(a, hidden);
    };
    let mut placed: BTreeSet<osis_base::BlobId> = BTreeSet::new();
    for i in 0..12 {
        let mut m = osis_node::Mutation::new();
        m.set(t, &reg, &s(&format!("b{i}"))).unwrap();
        net.engine(b).commit(m).unwrap().unwrap();
        net.feed(b, Event::Local);
        for ms in [0, 1_000] {
            net.tick(ms);
            for _ in 0..200 {
                if net.queue_len() == 0 {
                    break;
                }
                hide(&mut net);
                net.round();
                for n in [a, b] {
                    placed.extend(net.sync(n).entries(&l).into_iter().filter(|(_, k)| of_c(k)).map(|(id, _)| id));
                }
            }
        }
    }
    hide(&mut net);
    // `run` asserts quiescence: no loop
    net.run();
    assert_eq!(placed.len(), 2, "a's write placed and placed again once: {placed:?}");
    assert!(net.engine(b).header(&c).is_some() && net.engine(b).held_bodies(&t, &reg) < 4, "b compacted a's write");
    assert_eq!(net.read(a, t), Some(s("a's")), "a sees none of b's writes");
    let census = |net: &mut Net| (net.engine(a).local_census().unwrap(), net.engine(b).local_census().unwrap(), net.logged_at(h, &l));
    // b's item commit a holds uncovered too goes again once, at a's next pass
    net.advance(31_000);
    let before = census(&mut net);
    for i in 0..10 {
        // a restart forgets nothing of it (`BlobRec::again` is stored)
        if i == 5 {
            net.restart(a, 1);
        }
        net.advance(31_000);
    }
    let after = census(&mut net);
    assert!(before == after, "nothing more placed, deleted or kept:\n{before:?}\n{after:?}");
}
