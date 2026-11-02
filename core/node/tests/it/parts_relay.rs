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
fn entry(net: &mut Net, from: usize, keys: usize, g: Tid, plaintext: Vec<u8>, c: &CommitId, seed: u64) -> (osis_base::BlobId, osis_proto::Event) {
    let body = net.engine(from).bodies(c).unwrap().into_iter().find(|b| !b.parts.is_empty()).unwrap();
    let body = osis_node::labeling::Body { plaintext, ..body };
    let sealed = osis_node::labeling::seal_body(&body, &mut SeededRng::from_u64(seed)).unwrap();
    let secret = net.engine(keys).wrap_secret(&g, None).unwrap().unwrap();
    let wrap = osis_crypto::wrap(&secret, &sealed.id, &sealed.key).unwrap();
    (sealed.id, osis_proto::Event::Added { blob_id: sealed.id, blob: Some(sealed.blob), wrap, stamp: None })
}

fn push(net: &mut Net, n: usize, host: usize, l: LabelId, e: osis_proto::Event, at: u64) {
    let conn = net.conn_to(n, host).expect("connected");
    net.feed(n, Event::Bytes { conn, bytes: frame(Message::Push { label: l, events: vec![e], cursor: Cursor { log_id: [0; 16], seq: (1 << 40) + at } }) });
    net.settle(10_000);
}

/// Every body of commit `c`, each an entry under `l`.
#[allow(clippy::too_many_arguments)]
fn every_body(net: &mut Net, from: usize, keys: usize, g: Tid, n: usize, host: usize, l: LabelId, c: &CommitId, seed: u64) {
    let secret = net.engine(keys).wrap_secret(&g, None).unwrap().unwrap();
    for (i, body) in net.engine(from).bodies(c).unwrap().into_iter().enumerate() {
        let sealed = osis_node::labeling::seal_body(&body, &mut SeededRng::from_u64(seed + i as u64)).unwrap();
        let wrap = osis_crypto::wrap(&secret, &sealed.id, &sealed.key).unwrap();
        push(net, n, host, l, osis_proto::Event::Added { blob_id: sealed.id, blob: Some(sealed.blob), wrap, stamp: None }, seed + i as u64);
    }
}

fn plain(net: &mut Net, from: usize, c: &CommitId) -> Vec<u8> {
    net.engine(from).bodies(c).unwrap().into_iter().find(|b| !b.parts.is_empty()).unwrap().plaintext
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
// copy, its thing's record last: the true one is taken, each junk entry judged bad once, no name left.
#[test]
fn junk_entry_keeps_out_no_entry_spec_commits_4() {
    for true_at in [0u64, 1, 2] {
        let mut x = case();
        let c = x.c;
        let good = plain(&mut x.net, x.a, &c);
        let mut junk = Vec::new();
        for i in 0..3u64 {
            if i == true_at {
                x.give(good.clone(), c, 100 + i);
            }
            junk.push(x.give(junk_parts(&good, i as u8), c, 200 + i));
        }
        assert!(!x.holds(c));
        x.give_record(300);
        assert!(x.holds(c), "true copy at {true_at}");
        assert_eq!(x.read(), Some(Value::Str("second".into())), "true copy at {true_at}");
        assert!(x.net.engine(x.b).pending().is_empty());
        // a true first copy leaves nothing to look at
        if true_at > 0 {
            for j in junk {
                assert!(x.is_bad(j), "true copy at {true_at}");
            }
        }
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
        m.op(t, &osis_schema::core_types::ROLES, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Key(Value::Tid(dt))], op: osis_crdt::Op::Set(osis_schema::Codec::to_value(&osis_schema::core_types::Edge { role: Role::Write, until: None, invite: None, since: None, tied: None })) }).unwrap();
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
