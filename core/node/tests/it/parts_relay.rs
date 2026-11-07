#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! A relay's copies against a real node (spec/commits.md §4, Copies): a pending commit keeps the first
//! copy of each slot and of its signature, and node-sync ingests the commit's other entries again when
//! one proves junk (`SyncEngine::redeliver`). Entries are pushed on the node's connection, one message at
//! a time, as a reader of the label could make them come.

use crate::net;
use net::*;
use osis_base::{CommitId, LabelId, Role, Tid, Value};
use osis_commit::CommitBlob;
use osis_crypto::SeededRng;
use osis_node::sync::{EntryKind, Event};
use osis_proto::{Cursor, Message, encode_frame};

fn frame(m: Message) -> Vec<u8> {
    encode_frame(&m.encode())
}

/// One sealed entry under `l`, readable by `g`'s read secret held at `from`.
fn entry(net: &mut Net, _from: usize, keys: usize, g: Tid, plaintext: Vec<u8>, _c: &CommitId, seed: u64) -> (osis_base::BlobId, osis_proto::Event) {
    // one section under the label's secret (a per-label copy's shape: the forged things may
    // have no secret here)
    let secret = net.engine(keys).wrap_secret(&g, None).unwrap().unwrap();
    let sealed = osis_node::labeling::seal_plain(&plaintext, &secret, osis_label::Class::Durable, &mut SeededRng::from_u64(seed)).unwrap();
    let wrap = osis_crypto::wrap(&secret, &sealed.id, &sealed.key, 1).unwrap();
    (sealed.id, osis_proto::Event::Added { blob_id: sealed.id, blob: Some(sealed.blob), wrap, stamp: None })
}

fn push(net: &mut Net, n: usize, host: usize, l: LabelId, e: osis_proto::Event, at: u64) {
    let conn = net.conn_to(n, host).expect("connected");
    net.feed(n, Event::Bytes { conn, bytes: frame(Message::Push { label: l, events: vec![e], cursor: Cursor { log_id: [0; 16], seq: (1 << 40) + at } }) });
    net.settle(10_000);
}

/// The body of commit `c` as `from` holds it, an entry under `l`.
#[allow(clippy::too_many_arguments)]
fn every_body(net: &mut Net, from: usize, keys: usize, g: Tid, n: usize, host: usize, l: LabelId, c: &CommitId, seed: u64) {
    let secret = net.engine(keys).wrap_secret(&g, None).unwrap().unwrap();
    let Some(body) = net.engine(from).body(c).unwrap() else { return };
    let sealed = osis_node::labeling::seal_plain(&body.plaintext, &secret, osis_label::Class::Durable, &mut SeededRng::from_u64(seed)).unwrap();
    let wrap = osis_crypto::wrap(&secret, &sealed.id, &sealed.key, 1).unwrap();
    push(net, n, host, l, osis_proto::Event::Added { blob_id: sealed.id, blob: Some(sealed.blob), wrap, stamp: None }, seed);
}

fn plain(net: &mut Net, from: usize, c: &CommitId) -> Vec<u8> {
    net.engine(from).body(c).unwrap().unwrap().plaintext
}

fn junk_parts(bytes: &[u8], fill: u8) -> Vec<u8> {
    let mut b = CommitBlob::decode(bytes).unwrap();
    for p in &mut b.parts {
        p.delta = osis_base::encode(&Value::List(vec![Value::Bytes(vec![fill; 40])]));
    }
    b.encode()
}

/// `b` connected, `a` offline with a new thing `h` under `g` (its record in commit `r`) and a later
/// write on it (`c`); nothing of them at the host.
struct Case {
    net: Net,
    host: usize,
    a: usize,
    b: usize,
    g: Tid,
    h: Tid,
    l: LabelId,
    r: CommitId,
    c: CommitId,
}

fn case() -> Case {
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let g = net.group(a, &[(b, Role::Write)], &[host]);
    net.item(a, g, g, "x");
    net.run();
    let l = net.label(a);
    net.set_online(a, false);
    let before = net.engine(a).commit_ids();
    let h = net.item(a, g, g, "first");
    let r = net.engine(a).commit_ids().into_iter().find(|c| !before.contains(c)).unwrap();
    net.advance(10);
    let c = net.write(a, h, "second");
    Case { net, host, a, b, g, h, l, r, c }
}

impl Case {
    fn give(&mut self, plaintext: Vec<u8>, c: CommitId, seed: u64) -> osis_base::BlobId {
        let (id, e) = entry(&mut self.net, self.a, self.a, self.g, plaintext, &c, seed);
        push(&mut self.net, self.b, self.host, self.l, e, seed);
        id
    }
    fn give_record(&mut self, seed: u64) {
        let r = self.r;
        every_body(&mut self.net, self.a, self.a, self.g, self.b, self.host, self.l, &r, seed);
    }
    fn read(&mut self) -> Option<Value> {
        self.net.engine(self.b).get(&self.h, &osis_base::Ak::new("t:reg.0").unwrap()).unwrap()
    }
    fn holds(&mut self, c: CommitId) -> bool {
        self.net.engine(self.b).commit_ids().contains(&c)
    }
    fn is_bad(&mut self, id: osis_base::BlobId) -> bool {
        let l = self.l;
        self.net.sync(self.b).entries(&l).iter().any(|(x, k)| *x == id && *k == EntryKind::Bad)
    }
}

// spec/commits.md §4 (copies): junk under the true commit ID, however many, before or after the true
// copy, its thing's record last: the true one is taken, no name left.
#[test]
fn junk_entry_keeps_out_no_entry_spec_commits_4() {
    for true_at in [0u64, 1, 2] {
        let mut x = case();
        let c = x.c;
        let good = plain(&mut x.net, x.a, &c);
        for i in 0..3u64 {
            if i == true_at {
                x.give(good.clone(), c, 100 + i);
            }
            x.give(junk_parts(&good, i as u8), c, 200 + i);
        }
        assert!(!x.holds(c));
        x.give_record(300);
        assert!(x.holds(c), "true copy at {true_at}");
        assert_eq!(x.read(), Some(Value::Str("second".into())), "true copy at {true_at}");
        assert!(x.net.engine(x.b).pending().is_empty());
        assert!(x.net.engine(x.b).take_redeliver().is_empty());
    }
}

// spec/commits.md §4 (copies): only junk came: nothing of it stays, and a true copy is taken later.
#[test]
fn all_junk_then_true_entry_spec_commits_4() {
    let mut x = case();
    let c = x.c;
    let good = plain(&mut x.net, x.a, &c);
    x.give(junk_parts(&good, 1), c, 100);
    x.give(junk_parts(&good, 2), c, 101);
    x.give_record(300);
    assert!(!x.holds(c));
    assert!(x.net.engine(x.b).pending().is_empty());
    x.give(good, c, 400);
    assert_eq!(x.read(), Some(Value::Str("second".into())));
}

// spec/commits.md §4 (copies): a restart with a commit waiting, its first copy junk and the true one an
// entry: the record arriving after it finds the true copy; and a name a crash lost is looked at on start.
#[test]
fn restart_with_a_commit_waiting_spec_commits_4() {
    for lost_name in [false, true] {
        let mut x = case();
        let (c, r) = (x.c, x.r);
        let good = plain(&mut x.net, x.a, &c);
        x.give(junk_parts(&good, 1), c, 100);
        x.give(good, c, 101);
        if lost_name {
            // the record applied and the junk dropped in one transaction, the crash before node-sync looked
            let pk = x.net.engine(x.a).package(&r).unwrap().unwrap();
            x.net.engine(x.b).ingest(&pk.bytes, pk.blobs).unwrap();
            x.net.engine(x.b).reexamine().unwrap();
            assert!(!x.net.engine(x.b).take_redeliver().is_empty(), "named");
            assert!(!x.holds(c));
        }
        x.net.restart(x.b, 77);
        if !lost_name {
            assert!(!x.holds(c));
            x.net.feed(x.b, Event::Local);
            x.net.settle(10_000);
            x.give_record(300);
        } else {
            x.net.feed(x.b, Event::Local);
            x.net.settle(10_000);
        }
        assert!(x.holds(c), "lost name {lost_name}");
        assert_eq!(x.read(), Some(Value::Str("second".into())), "lost name {lost_name}");
    }
}

// spec/commits.md §4 (copies): a junk signature with its author's record away: the commit goes when the
// author comes, the true copy among the entries is ingested again; only junk signatures, nothing stays.
#[test]
fn junk_signature_with_the_author_away_spec_commits_4() {
    for junk_first in [true, false] {
        let mut x = case();
        // `d`: a writer `b` has not heard of, its commit on `h`'s sibling
        let d = x.net.node(3, &[x.host]);
        x.net.set_online(d, false);
        let dt = x.net.engine(d).tid();
        let (a, g, b) = (x.a, x.g, x.b);
        let t = x.h;
        let mut m = osis_node::Mutation::new();
        m.op(t, &osis_schema::core_types::ROLES, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Key(Value::Tid(dt))], op: osis_crdt::Op::Set(osis_schema::Codec::to_value(&osis_schema::core_types::Edge { role: Role::Write, until: None, invite: None, tied: None })) }).unwrap();
        x.net.engine(a).commit(m).unwrap();
        for id in x.net.engine(a).commit_ids() {
            let pk = x.net.engine(a).package(&id).unwrap().unwrap();
            let _ = x.net.engine(d).ingest(&pk.bytes, pk.blobs);
        }
        for id in x.net.engine(d).commit_ids() {
            let pk = x.net.engine(d).package(&id).unwrap().unwrap();
            let _ = x.net.engine(a).ingest(&pk.bytes, pk.blobs);
        }
        x.net.engine(d).reexamine().unwrap();
        let before = x.net.engine(d).commit_ids();
        let c = x.net.write(d, t, "by d");
        assert!(!before.contains(&c));
        let good = plain(&mut x.net, d, &c);
        let mut forged = CommitBlob::decode(&good).unwrap();
        forged.signature = osis_crypto::Signature::from_slice(&[9; 64]).unwrap();
        let forged = forged.encode();
        let order = if junk_first { [forged.clone(), good.clone()] } else { [good.clone(), forged.clone()] };
        let mut forged_entry = None;
        for (i, p) in order.into_iter().enumerate() {
            let is_forged = p == forged;
            let (id, e) = entry(&mut x.net, d, a, g, p, &c, 100 + i as u64);
            push(&mut x.net, b, x.host, x.l, e, 100 + i as u64);
            if is_forged {
                forged_entry = Some(id);
            }
        }
        assert!(!x.holds(c));
        // everything else `d`'s write needs
        let held = x.net.engine(b).commit_ids();
        let mut rest: Vec<CommitId> = x.net.engine(d).commit_ids().into_iter().filter(|i| *i != c && !held.contains(i)).collect();
        rest.sort_by_key(|i| x.net.engine(d).header(i).unwrap().ts);
        for (i, id) in rest.into_iter().enumerate() {
            every_body(&mut x.net, d, a, g, b, x.host, x.l, &id, 2000 + 10 * i as u64);
        }
        assert!(x.holds(c), "junk first {junk_first}");
        assert_eq!(x.read(), Some(Value::Str("by d".into())), "junk first {junk_first}");
        assert!(x.net.engine(b).pending().is_empty());
        if junk_first {
            assert!(x.is_bad(forged_entry.unwrap()), "a junk signature is judged bad, once");
        }
    }
}

// spec/requirements.md (no unbounded work from peer input): after a flood settles nothing is looked at
// again: steps of the node leave the junk entries alone and name nothing.
#[test]
fn no_repeated_redelivery_spec_commits_4() {
    let mut x = case();
    let c = x.c;
    let good = plain(&mut x.net, x.a, &c);
    for i in 0..40u64 {
        x.give(junk_parts(&good, i as u8), c, 100 + i);
    }
    x.give(good, c, 200);
    x.give_record(300);
    assert!(x.holds(c));
    let (b, g) = (x.b, x.g);
    let rx = x.net.engine(b).subscribe();
    for _ in 0..5 {
        x.net.feed(b, Event::Local);
        x.net.settle(1000);
    }
    let again = rx.try_iter().filter(|e| matches!(e, osis_node::Event::Diagnostic(_) | osis_node::Event::Applied { .. } | osis_node::Event::Joined { .. })).count();
    assert_eq!(again, 0, "no ingest happened again");
    assert!(x.net.sync(b).redelivered <= 1, "the true copy, not the flood: {}", x.net.sync(b).redelivered);
    assert!(x.net.engine(b).pending().is_empty());
    let _ = g;
}

fn edge_op(holder: Tid) -> osis_crdt::PathOp {
    osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Key(Value::Tid(holder))], op: osis_crdt::Op::Set(osis_schema::Codec::to_value(&osis_schema::core_types::Edge { role: Role::Write, until: None, invite: None, tied: None })) }
}

// spec/commits.md §4 (copies), crash: a role commit applied, its part on a thing whose record is away
// waiting with a junk copy in its slot. The record comes, the junk goes, and the crash takes the name:
// the commit neither pends nor misses anything by the index of what pends. The start finds the true copy.
#[test]
fn restart_with_a_waiting_part_of_an_applied_commit_spec_commits_4() {
    let mut x = case();
    let (a, b, g, h, r) = (x.a, x.b, x.g, x.h, x.r);
    let holder = x.net.tid(a);
    let mut m = osis_node::Mutation::new();
    m.op(g, &osis_schema::core_types::ROLES, edge_op(holder)).unwrap();
    m.op(h, &osis_schema::core_types::ROLES, edge_op(holder)).unwrap();
    let c = x.net.engine(a).commit_hostile(m).unwrap().unwrap();
    let good = x.net.engine(a).package(&c).unwrap().unwrap().bytes;
    let mut junk = CommitBlob::decode(&good).unwrap();
    assert!(junk.header.aspects.iter().any(|e| e.tid == g));
    for p in &mut junk.parts {
        if junk.header.aspects[p.ai].tid == h {
            p.delta = osis_base::encode(&Value::List(vec![Value::Bytes(vec![3; 40])]));
        }
    }
    x.give(junk.encode(), c, 100);
    assert!(x.holds(c), "its part on g applied");
    assert!(x.net.engine(b).pending().iter().any(|p| p.0 == c), "its part on h waits");
    x.give(good, c, 101);
    let pk = x.net.engine(a).package(&r).unwrap().unwrap();
    x.net.engine(b).ingest(&pk.bytes, pk.blobs).unwrap();
    x.net.engine(b).reexamine().unwrap();
    assert!(!x.net.engine(b).take_redeliver().is_empty(), "named");
    x.net.restart(b, 77);
    x.net.feed(b, Event::Local);
    x.net.settle(10_000);
    assert!(x.net.engine(b).pending().iter().all(|p| p.0 != c));
    assert!(x.net.engine(b).get_typed(&h, &osis_schema::core_types::ROLES).unwrap().unwrap_or_default().contains_key(&holder), "the true part of h came");
}

// spec/commits.md §4 (copies): a name raised while node-sync works on another commit: `d`'s slot on `h2`
// proves junk only when `e`'s true copy, ingested again in the same round, brings `h2`'s record.
#[test]
fn a_name_raised_during_redelivery_is_kept_spec_commits_4() {
    let mut x = case();
    let (a, b, h1) = (x.a, x.b, x.h);
    x.net.engine(b).set_syncing(h1, true).unwrap();
    let mut m = osis_node::Mutation::new();
    let h2 = x.net.engine(a).new_thing(&mut m, x.g);
    m.set(h2, &REG, &Value::Str("two".into())).unwrap();
    m.set(h1, &REG, &Value::Str("e".into())).unwrap();
    let e = x.net.engine(a).commit(m).unwrap().unwrap();
    // `d` before `e` in the order of a round
    let (d, want) = (0..1000).find_map(|i| {
        let mut m = osis_node::Mutation::new();
        m.set(h1, &REG, &Value::Str(format!("d{i}"))).unwrap();
        m.set(h2, &REG, &Value::Str(format!("d{i}"))).unwrap();
        let d = x.net.engine(a).commit(m).unwrap().unwrap();
        (d < e).then(|| (d, format!("d{i}")))
    }).unwrap();
    let good_d = plain(&mut x.net, a, &d);
    x.give(junk_parts(&good_d, 1), d, 100);
    x.give(good_d, d, 101);
    // `e`'s copy with its `t:reg.0` writes, its slot on `h1` junk
    let body = x.net.engine(a).body(&e).unwrap().unwrap();
    let mut junk_e = CommitBlob::decode(&body.plaintext).unwrap();
    let hdr = junk_e.header.clone();
    junk_e.parts.retain(|p| hdr.aspects[p.ai].tid == h1 && hdr.aspects[p.ai].ak.as_str() == "t:reg.0");
    for p in &mut junk_e.parts {
        p.delta = osis_base::encode(&Value::List(vec![Value::Bytes(vec![2; 40])]));
    }
    let secret = x.net.engine(a).wrap_secret(&x.g, None).unwrap().unwrap();
    let sealed = osis_node::labeling::seal_plain(&junk_e.encode(), &secret, osis_label::Class::Durable, &mut SeededRng::from_u64(102)).unwrap();
    let wrap = osis_crypto::wrap(&secret, &sealed.id, &sealed.key, 1).unwrap();
    let (host, l) = (x.host, x.l);
    push(&mut x.net, b, host, l, osis_proto::Event::Added { blob_id: sealed.id, blob: Some(sealed.blob), wrap, stamp: None }, 102);
    let g = x.g;
    every_body(&mut x.net, a, a, g, b, host, l, &e, 110);
    x.give_record(300);
    assert!(x.holds(e), "e: {:?} {:?}", x.net.engine(b).pending(), x.net.diagnostics(b));
    assert!(x.holds(d), "d: {:?}", x.net.engine(b).pending());
    assert_eq!(x.net.engine(b).get(&h2, &osis_base::Ak::new("t:reg.0").unwrap()).unwrap(), Some(Value::Str(want)), "{:?}", x.net.engine(b).pending());
}

// spec/requirements.md (no unbounded work from peer input): a junk copy that kept nothing out names
// nothing: a flood of them on a waiting commit whose record is known costs no look at its entries.
#[test]
fn junk_with_a_known_record_names_nothing_spec_commits_4() {
    let mut x = case();
    let (a, b, g, h) = (x.a, x.b, x.g, x.h);
    let r = x.r;
    every_body(&mut x.net, a, a, g, b, x.host, x.l, &r, 90);
    // a second thing, its record away: the commit on both waits with `h`'s slot checkable
    let mut m = osis_node::Mutation::new();
    let h2 = x.net.engine(a).new_thing(&mut m, g);
    m.set(h2, &REG, &Value::Str("two".into())).unwrap();
    x.net.engine(a).commit(m).unwrap().unwrap();
    let mut m = osis_node::Mutation::new();
    m.set(h, &REG, &Value::Str("c".into())).unwrap();
    m.set(h2, &REG, &Value::Str("c".into())).unwrap();
    let c = x.net.engine(a).commit(m).unwrap().unwrap();
    let good = plain(&mut x.net, a, &c);
    let mut stored = CommitBlob::decode(&good).unwrap();
    let hdr = stored.header.clone();
    stored.parts.retain(|p| hdr.aspects[p.ai].tid == h2);
    x.net.engine(b).ingest(&stored.encode(), Vec::new()).unwrap();
    assert!(x.net.engine(b).pending().iter().any(|p| p.0 == c));
    let mut junk = CommitBlob::decode(&good).unwrap();
    junk.parts.retain(|p| hdr.aspects[p.ai].tid == h);
    for p in &mut junk.parts {
        p.delta = osis_base::encode(&Value::List(vec![Value::Bytes(vec![4; 40])]));
    }
    let _ = x.net.engine(b).ingest(&junk.encode(), Vec::new());
    assert!(x.net.engine(b).take_redeliver().is_empty(), "it kept nothing out");
}

// spec/commits.md §5: a part pending at its expiry counts as never received: a start's look at what pends
// does not bring it back from the blob of its entry, and its record coming leaves it gone, the flag up.
#[test]
fn redelivery_leaves_a_part_past_its_expiry_spec_commits_5() {
    let mut x = case();
    let (a, b, h) = (x.a, x.b, x.h);
    let mut m = osis_node::Mutation::new();
    m.set(h, &REG, &Value::Str("gone at T".into())).unwrap();
    let t = x.net.engine(a).now().0 + 60_000;
    m.expires(h, &REG, osis_base::WallMs(t)).unwrap();
    let c = x.net.engine(a).commit(m).unwrap().unwrap();
    let good = plain(&mut x.net, a, &c);
    let id = x.give(good, c, 100);
    assert!(x.net.sync(b).holds_blob(&id));
    x.net.advance(120_000);
    x.net.feed(b, Event::Tick);
    x.net.settle(10_000);
    assert_eq!(x.net.engine(b).suspects().unwrap().len(), 1, "flagged at T");
    assert!(!x.net.sync(b).holds_blob(&id), "its blob and key go at T");
    x.net.restart(b, 77);
    x.net.feed(b, Event::Local);
    x.net.settle(10_000);
    assert_eq!(x.net.sync(b).redelivered, 0, "its copy stays out");
    x.give_record(300);
    assert!(x.holds(c));
    assert_eq!(x.read(), Some(Value::Str("first".into())));
    assert_eq!(x.net.engine(b).suspects().unwrap().len(), 1, "still counts as never received");
}

// spec/commits.md §4, §5: a commit given one part applies it; a purge request naming that part drops
// it and the blob holding it goes. Its other delta joins when it comes.
#[test]
fn purged_part_leaves_its_blob_spec_commits_5() {
    let mut x = case();
    let (a, b, g, h) = (x.a, x.b, x.g, x.h);
    x.give_record(90);
    let mut m = osis_node::Mutation::new();
    m.set(h, &REG, &Value::Str("purged".into())).unwrap();
    m.set(h, &crate::common::KEPT, &Value::Str("kept".into())).unwrap();
    let c = x.net.engine(a).commit(m).unwrap().unwrap();
    // sealed before the purge drops it at its author: the `t:reg.0` part alone
    let body = x.net.engine(a).body(&c).unwrap().unwrap();
    let hdr = x.net.engine(a).header(&c).unwrap();
    let reg = osis_commit::rewrite(&CommitBlob::decode(&body.plaintext).unwrap(), |ai| hdr.aspects[ai].ak.as_str() != "t:reg.0");
    assert_eq!(reg.parts.len(), 1);
    let (id, e) = entry(&mut x.net, a, a, g, reg.encode(), &c, 100);
    x.net.advance(10);
    let mut m = osis_node::Mutation::new();
    m.set(h, &REG, &Value::Str("public".into())).unwrap();
    m.purge(osis_commit::PurgeItem::Commit { commit: c, tid: h, ak: osis_base::Ak::new("t:reg.0").unwrap() });
    let p = x.net.engine(a).commit(m).unwrap().unwrap();
    let (host, l) = (x.host, x.l);
    push(&mut x.net, b, host, l, e, 100);
    assert!(x.holds(c), "it waits for nothing");
    assert_eq!(x.read(), Some(Value::Str("purged".into())));
    assert!(x.net.sync(b).holds_blob(&id));
    let pp = plain(&mut x.net, a, &p);
    x.give(pp, p, 110);
    assert!(x.holds(p));
    assert!(!x.net.sync(b).holds_blob(&id), "the purged part's blob and key go");
    every_body(&mut x.net, a, a, g, b, host, l, &c, 120);
    assert!(x.holds(c), "{:?}", x.net.engine(b).pending());
    assert_eq!(x.read(), Some(Value::Str("public".into())));
}

// spec/commits.md §5: a body dropped (as covered) leaves its commit's settled slots as they were: a
// name on its commit brings no copy of it back.
#[test]
fn redelivery_leaves_a_dropped_body_spec_commits_5() {
    let mut x = case();
    let (a, b, h, c) = (x.a, x.b, x.h, x.c);
    x.give_record(300);
    let good = plain(&mut x.net, a, &c);
    x.give(good, c, 100);
    assert!(x.holds(c));
    let reg = osis_base::Ak::new("t:reg.0").unwrap();
    x.net.engine(b).snapshot(&h, &reg).unwrap().unwrap();
    let slots = x.net.engine(b).settled_slots(&c).unwrap();
    x.net.engine(b).drop_body(&c, &h, &reg).unwrap();
    assert_eq!(x.net.engine(b).settled_slots(&c).unwrap(), slots);
}

// spec/commits.md §4 (copies): a commit on one thing in two bodies, junk first in a slot and its true
// copy second, the thing's record last. The redelivery takes the true copy, which applies alone; the
// other body joins when it comes, and no name is left.
#[test]
fn junk_first_in_one_body_keeps_out_no_entry_spec_commits_4() {
    for other_first in [true, false] {
        let mut x = case();
        let (a, b, h) = (x.a, x.b, x.h);
        let mut m = osis_node::Mutation::new();
        m.retention(h, &GONE, crate::timed_dead::purge_on_replace().unwrap()).unwrap();
        m.set(h, &GONE, &Value::Str("v".into())).unwrap();
        m.set(h, &REG, &Value::Str("third".into())).unwrap();
        let c = x.net.engine(a).commit(m).unwrap().unwrap();
        let body = x.net.engine(a).body(&c).unwrap().unwrap();
        let whole = CommitBlob::decode(&body.plaintext).unwrap();
        assert_eq!(whole.parts.len(), 2, "two retention classes in one blob");
        let reg_ai = x.net.engine(a).header(&c).unwrap().aspects.iter().position(|y| y.ak.as_str() == "t:reg.0").unwrap();
        // the blob split by hand into one per class (a rewrite's shape, spec/sync.md §5)
        let on_reg = osis_commit::rewrite(&whole, |ai| ai != reg_ai).encode();
        let other = osis_commit::rewrite(&whole, |ai| ai == reg_ai).encode();
        let give = |x: &mut Case, plaintext: Vec<u8>, seed: u64| {
            let (g, l, host) = (x.g, x.l, x.host);
            let secret = x.net.engine(a).wrap_secret(&g, None).unwrap().unwrap();
            let sealed = osis_node::labeling::seal_plain(&plaintext, &secret, osis_label::Class::Durable, &mut SeededRng::from_u64(seed)).unwrap();
            let wrap = osis_crypto::wrap(&secret, &sealed.id, &sealed.key, 1).unwrap();
            push(&mut x.net, b, host, l, osis_proto::Event::Added { blob_id: sealed.id, blob: Some(sealed.blob), wrap, stamp: None }, seed);
        };
        if other_first {
            give(&mut x, other.clone(), 90);
        }
        give(&mut x, junk_parts(&on_reg, 7), 100);
        give(&mut x, on_reg, 101);
        x.give_record(300);
        let reg_slots: Vec<usize> = x.net.engine(a).body(&c).unwrap().unwrap().parts.into_iter().filter(|ai| *ai == reg_ai).collect();
        assert!(reg_slots.iter().all(|p| x.net.engine(b).settled_slots(&c).unwrap().contains(p)), "other first {other_first}: the true copy came");
        assert!(x.net.engine(b).take_redeliver().is_empty());
        assert!(x.holds(c), "other first {other_first}");
        if !other_first {
            give(&mut x, other, 400);
        }
        assert_eq!(x.read(), Some(Value::Str("third".into())), "other first {other_first}");
        assert!(x.net.engine(b).pending().is_empty());
    }
}

struct Rng(u64);
impl Rng {
    fn below(&mut self, n: u64) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0 % n.max(1)
    }
}

/// One seed: `a` and an offline writer `d` make commits a node has none of (things and records, a commit
/// on two things, role commits on two things, a junk signature's commit by an author it has not heard
/// of). Their true entries and a relay's junk come in random order, the node restarting, some of its
/// names lost to a crash. The node ends holding every slot of every commit, as `a` reads, nothing
/// waiting, and it ingested again no more than the entries it was given.
fn relay_seed(seed: u64) {
    let mut rng = Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1);
    let mut x = case();
    let (a, b, g, h1, host, l) = (x.a, x.b, x.g, x.h, x.host, x.l);
    let d = x.net.node(3, &[host]);
    x.net.set_online(d, false);
    let dt = x.net.tid(d);
    let mut sources: Vec<(usize, CommitId)> = vec![(a, x.r), (a, x.c)];
    let mut m = osis_node::Mutation::new();
    let h2 = x.net.engine(a).new_thing(&mut m, g);
    m.set(h2, &REG, &Value::Str("two".into())).unwrap();
    m.set(h1, &REG, &Value::Str("with two".into())).unwrap();
    sources.push((a, x.net.engine(a).commit(m).unwrap().unwrap()));
    x.net.advance(10);
    let mut m = osis_node::Mutation::new();
    m.set(h1, &REG, &Value::Str("both".into())).unwrap();
    m.set(h2, &REG, &Value::Str("both".into())).unwrap();
    sources.push((a, x.net.engine(a).commit(m).unwrap().unwrap()));
    x.net.advance(10);
    // (a junk role commit on two things: not on the author's own record edges, which it would
    // lower by self-removal)
    let mut m = osis_node::Mutation::new();
    m.op(g, &osis_schema::core_types::ROLES, edge_op(dt)).unwrap();
    m.op(h2, &osis_schema::core_types::ROLES, edge_op(dt)).unwrap();
    sources.push((a, x.net.engine(a).commit_hostile(m).unwrap().unwrap()));
    x.net.advance(10);
    let mut m = osis_node::Mutation::new();
    m.op(h1, &osis_schema::core_types::ROLES, edge_op(dt)).unwrap();
    sources.push((a, x.net.engine(a).commit(m).unwrap().unwrap()));
    x.net.advance(10);
    // one thing in two bodies: a junk copy of one holds its true copy out, the other waits for it
    let mut m = osis_node::Mutation::new();
    m.retention(h2, &GONE, crate::timed_dead::purge_on_replace().unwrap()).unwrap();
    m.set(h2, &GONE, &Value::Str("gone".into())).unwrap();
    m.set(h2, &REG, &Value::Str("two bodies".into())).unwrap();
    sources.push((a, x.net.engine(a).commit(m).unwrap().unwrap()));
    x.net.advance(10);
    for id in x.net.engine(a).commit_ids() {
        let pk = x.net.engine(a).package(&id).unwrap().unwrap();
        let _ = x.net.engine(d).ingest(&pk.bytes, pk.blobs);
    }
    x.net.engine(d).reexamine().unwrap();
    let held_a = x.net.engine(a).commit_ids();
    for id in x.net.engine(d).commit_ids().into_iter().filter(|i| !held_a.contains(i)) {
        sources.push((d, id));
    }
    x.net.advance(10);
    let c_d = x.net.write(d, h1, "by d");
    sources.push((d, c_d));
    let want = (x.net.engine(d).get(&h1, &osis_base::Ak::new("t:reg.0").unwrap()).unwrap(), x.net.engine(a).get(&h2, &osis_base::Ak::new("t:reg.0").unwrap()).unwrap());

    let secret = x.net.engine(a).wrap_secret(&g, None).unwrap().unwrap();
    let mut entries: Vec<(osis_base::BlobId, osis_proto::Event)> = Vec::new();
    let mut seal = |_x: &mut Case, _from: usize, plaintext: &[u8], at: u64| {
        let sealed = osis_node::labeling::seal_plain(plaintext, &secret, osis_label::Class::Durable, &mut SeededRng::from_u64(at)).unwrap();
        let wrap = osis_crypto::wrap(&secret, &sealed.id, &sealed.key, 1).unwrap();
        entries.push((sealed.id, osis_proto::Event::Added { blob_id: sealed.id, blob: Some(sealed.blob), wrap, stamp: None }));
    };
    let mut slots = Vec::new();
    let mut at = seed.wrapping_mul(1000);
    for (from, c) in &sources {
        if let Some(body) = x.net.engine(*from).body(c).unwrap() {
            slots.extend(body.parts.iter().map(|p| (*c, *p)));
            at += 1;
            seal(&mut x, *from, &body.plaintext, at);
            for _ in 0..rng.below(4) {
                let mut j = CommitBlob::decode(&body.plaintext).unwrap();
                match rng.below(3) {
                    // every part
                    0 => j.parts.iter_mut().for_each(|p| p.delta = osis_base::encode(&Value::List(vec![Value::Bytes(vec![rng.below(250) as u8; 40])]))),
                    // one part
                    1 => {
                        let i = rng.below(j.parts.len() as u64) as usize;
                        j.parts[i].delta = osis_base::encode(&Value::List(vec![Value::Bytes(vec![rng.below(250) as u8; 40])]));
                    }
                    _ => j.signature = osis_crypto::Signature::from_slice(&[rng.below(250) as u8 + 1; 64]).unwrap(),
                }
                at += 1;
                seal(&mut x, *from, &j.encode(), at);
            }
        }
    }
    if rng.below(2) == 0 {
        x.net.engine(b).set_syncing(h1, true).unwrap();
        x.net.engine(b).set_syncing(h2, true).unwrap();
    }
    let n = entries.len() as u64;
    for i in (1..entries.len()).rev() {
        entries.swap(i, rng.below(i as u64 + 1) as usize);
    }
    for (i, (_, e)) in entries.into_iter().enumerate() {
        push(&mut x.net, b, host, l, e, 500_000 * seed + i as u64);
        match rng.below(16) {
            // a record comes and the crash takes what that named
            0 => {
                let (from, c) = sources[[0, 2][rng.below(2) as usize]];
                let pk = x.net.engine(from).package(&c).unwrap().unwrap();
                let _ = x.net.engine(b).ingest(&pk.bytes, pk.blobs);
                x.net.engine(b).reexamine().unwrap();
                x.net.engine(b).take_redeliver();
                x.net.restart(b, seed + i as u64);
                x.net.feed(b, Event::Local);
                x.net.settle(10_000);
            }
            1 => {
                x.net.restart(b, seed + i as u64);
                x.net.feed(b, Event::Local);
                x.net.settle(10_000);
            }
            _ => {}
        }
    }
    x.net.feed(b, Event::Local);
    x.net.settle(10_000);
    let pending = x.net.engine(b).pending();
    assert!(pending.is_empty(), "seed {seed}: {pending:?}");
    for (c, p) in &slots {
        assert!(x.net.engine(b).settled_slots(c).unwrap().contains(p), "seed {seed}: {c:?} {p:?}");
    }
    let got = (x.net.engine(b).get(&h1, &osis_base::Ak::new("t:reg.0").unwrap()).unwrap(), x.net.engine(b).get(&h2, &osis_base::Ak::new("t:reg.0").unwrap()).unwrap());
    assert_eq!(got, want, "seed {seed}");
    assert_eq!(x.net.engine(b).get_typed(&h2, &osis_schema::core_types::ROLES).unwrap().unwrap_or_default().get(&dt).map(|e| e.role), Some(Role::Write), "seed {seed}");
    assert!(x.net.sync(b).redelivered <= 4 * n, "seed {seed}: {} of {n}", x.net.sync(b).redelivered);
}

// spec/commits.md §4 (copies), at the real node: every order of true entries and junk, with restarts and
// lost names, ends where the true entries alone would.
#[test]
fn relay_differential_spec_commits_4() {
    for seed in 1..9 {
        relay_seed(seed);
    }
}

#[test]
#[ignore]
fn relay_differential_large_spec_commits_4() {
    osis_base::testenv::Seeds::from_env("OSIS_RELAY_START", "OSIS_RELAY_SEEDS", osis_base::testenv::large(1..151)).run("parts_relay::relay_differential_large_spec_commits_4", relay_replay, relay_seed);
}

fn relay_replay(s: u64) -> String {
    format!("OSIS_RELAY_START={s} OSIS_RELAY_SEEDS=1 cargo test -p osis-node --test it -- --ignored --exact parts_relay::relay_differential_large_spec_commits_4")
}

// spec/commits.md §4 (copies), §5: a commit applies without a part on a thing whose record is away, that
// part's slot held by a junk copy; a purge drops the applied part. The blob holding both stays while it
// may hold the waiting part's only true copy, and goes once the commit holds that part.
#[test]
fn copy_kept_for_a_junk_held_slot_of_an_applied_commit_spec_commits_5() {
    let mut x = case();
    let (a, b, h) = (x.a, x.b, x.h);
    // the item `a` made before going offline, known at `b`
    let known = x.net.engine(b).commit_ids();
    let ids = x.net.engine(a).commit_ids();
    let x0 = ids.iter().filter(|i| known.contains(i)).flat_map(|i| x.net.engine(a).header(i).unwrap().aspects.clone()).find(|asp| asp.ak.as_str() == "t:reg.0").unwrap().tid;
    let mut m = osis_node::Mutation::new();
    m.set(x0, &REG, &Value::Str("secret".into())).unwrap();
    m.set(h, &REG, &Value::Str("other".into())).unwrap();
    let c = x.net.engine(a).commit(m).unwrap().unwrap();
    let good = plain(&mut x.net, a, &c);
    let hdr = x.net.engine(a).header(&c).unwrap();
    assert_eq!(CommitBlob::decode(&good).unwrap().parts.len(), 2, "one blob holds both");
    let mut j = CommitBlob::decode(&good).unwrap();
    j.parts.retain(|p| hdr.aspects[p.ai].tid == h);
    for p in &mut j.parts {
        p.delta = osis_base::encode(&Value::List(vec![Value::Bytes(vec![4; 40])]));
    }
    x.give(j.encode(), c, 100);
    let id = x.give(good, c, 101);
    x.net.advance(10);
    let mut m = osis_node::Mutation::new();
    m.set(x0, &REG, &Value::Str("public".into())).unwrap();
    m.purge(osis_commit::PurgeItem::Commit { commit: c, tid: x0, ak: osis_base::Ak::new("t:reg.0").unwrap() });
    let p = x.net.engine(a).commit(m).unwrap().unwrap();
    let pp = plain(&mut x.net, a, &p);
    x.give(pp, p, 110);
    assert!(x.holds(p) && x.holds(c), "applied without h's part");
    assert!(x.net.sync(b).holds_blob(&id), "kept: it may hold h's only true copy");
    x.give_record(300);
    assert_eq!(x.read(), Some(Value::Str("other".into())), "h's part came from the kept copy");
    assert!(!x.net.sync(b).holds_blob(&id), "then it goes");
}
