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
use osis_node::sync::Event;
use osis_proto::{Cursor, Message, encode_frame};

fn frame(m: Message) -> Vec<u8> {
    encode_frame(&m.encode())
}

/// One sealed entry under `l`, readable by `g`'s read secret held at `from`.
pub(crate) fn entry(net: &mut Net, _from: usize, keys: usize, g: Tid, plaintext: Vec<u8>, _c: &CommitId, seed: u64) -> (osis_base::BlobId, osis_proto::Event) {
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

pub(crate) fn plain(net: &mut Net, from: usize, c: &CommitId) -> Vec<u8> {
    net.engine(from).body(c).unwrap().unwrap().plaintext
}

pub(crate) fn junk_parts(bytes: &[u8], fill: u8) -> Vec<u8> {
    let mut b = CommitBlob::decode(bytes).unwrap();
    for p in &mut b.parts {
        p.delta = osis_base::encode(&Value::List(vec![Value::Bytes(vec![fill; 40])]));
    }
    b.encode()
}

/// `b` connected, `a` offline with a new thing `h` under `g` (its record in commit `r`) and a later
/// write on it (`c`); nothing of them at the host.
pub(crate) struct Case {
    pub(crate) net: Net,
    host: usize,
    pub(crate) a: usize,
    pub(crate) b: usize,
    g: Tid,
    h: Tid,
    pub(crate) l: LabelId,
    r: CommitId,
    pub(crate) c: CommitId,
}

pub(crate) fn case() -> Case {
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
    pub(crate) fn give(&mut self, plaintext: Vec<u8>, c: CommitId, seed: u64) -> osis_base::BlobId {
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

fn edge_op(holder: Tid) -> osis_crdt::PathOp {
    osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Key(Value::Tid(holder))], op: osis_crdt::Op::Set(osis_schema::Codec::to_value(&osis_schema::core_types::Edge { role: Role::Write, until: None, invite: None, tied: None })) }
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
                    _ => j.sigs.signature = osis_crypto::Signature::from_slice(&[rng.below(250) as u8 + 1; 64]).unwrap(),
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

#[test]
#[ignore]
fn relay_differential_large_spec_commits_4() {
    osis_base::testenv::Seeds::from_env("OSIS_RELAY_START", "OSIS_RELAY_SEEDS", osis_base::testenv::large(1..151)).run("parts_relay::relay_differential_large_spec_commits_4", relay_replay, relay_seed);
}

fn relay_replay(s: u64) -> String {
    format!("OSIS_RELAY_START={s} OSIS_RELAY_SEEDS=1 cargo test -p osis-node --test it -- --ignored --exact parts_relay::relay_differential_large_spec_commits_4")
}

