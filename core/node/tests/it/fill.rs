//! A label's first sync at a host (spec/sync.md §6, spec/crypto.md §5 `order`): listed, then
//! fetched in the wraps' order, the pass ending with the fill. Order independence of what is read
//! at each step: `order` (`fill_order`).

use crate::net::{self, Net};
use osis_base::{Ak, BlobId, LabelId, Role, Tid, Value};
use osis_node::Mutation;
use osis_node::sync::EntryKind;
use osis_schema::{Aspect, StaticSchema};
use std::collections::BTreeSet;

static KEPT: StaticSchema = StaticSchema::new("fill.osis", "version 1; aspect f:msgs.0: string [by: author, keep_at_least: abs 9223372036854775807];\n");
const MSG: Aspect<Value> = Aspect::new("f:msgs.0", &KEPT);

/// What the node asks at a time (`sync::fill`): the point part way is past a batch or so.
const FILL_BATCH: usize = 128;

/// More than a few batches, and few enough for tier 1.
const N: usize = 500;

fn msg(i: usize) -> Value {
    Value::Str(format!("{i:05}"))
}

fn say(net: &mut Net, n: usize, t: Tid, i: usize) {
    let mut m = Mutation::new();
    m.set(t, &MSG, &msg(i)).unwrap();
    net.engine(n).commit(m).unwrap().unwrap();
}

struct Chat {
    net: Net,
    host: usize,
    a: usize,
    c: usize,
    g: Tid,
    t: Tid,
    l: LabelId,
}

/// `a` writes `N` kept messages; `c`, a new node holding its grant, has never met the host.
fn chat(role: Role) -> Chat {
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let c = net.node(3, &[host]);
    let g = net.group(a, &[(c, role)], &[host]);
    let t = net.item(a, g, g, "chat");
    net.set_online(c, false);
    net.run();
    for i in 0..N {
        say(&mut net, a, t, i);
    }
    net.run();
    let l = net.label(a);
    Chat { net, host, a, c, g, t, l }
}

impl Chat {
    /// Opens `c` and goes on until `done`, one hop at a time.
    fn until(&mut self, mut done: impl FnMut(&mut Self) -> bool) {
        for _ in 0..100_000 {
            if done(self) {
                return;
            }
            if self.net.queue_len() == 0 {
                self.net.tick(1_000);
            }
            self.net.round();
        }
        panic!("not reached");
    }

    fn held(&mut self) -> Vec<Option<Value>> {
        let k = Ak::new("f:msgs.0").unwrap();
        self.net.engine(self.c).body_page(&self.t, &k, true, 0, N + 10).unwrap().into_iter().map(|b| b.value).collect()
    }

    fn filling(&mut self) -> bool {
        let g = self.g;
        self.net.sync(self.c).label_status().iter().any(|s| s.group == g && (s.idle < s.open || s.open < s.connected))
    }

    /// Goes on to a point part way through the fill: some messages here, more to come.
    fn part_way(&mut self) {
        self.net.set_online(self.c, true);
        self.until(|s| s.held().len() >= 3 * FILL_BATCH / 2);
        assert!(self.held().len() < N, "still filling");
    }

    /// What `c` holds at each hop is the newest of the messages.
    fn assert_newest(&mut self) {
        let held = self.held();
        for (i, v) in held.iter().enumerate() {
            assert_eq!(v.as_ref(), Some(&msg(N - 1 - i)), "newest first, position {i} of {}", held.len());
        }
    }

    fn finish(&mut self) {
        self.net.run();
        self.net.advance(61_000);
        assert_eq!(self.held().len(), N);
        self.assert_newest();
    }
}

// spec/sync.md §6: what is held at each step is the newest messages, and from the first of them
// on every role commit, wherever in the log it was written.
#[test]
fn newest_first_after_what_judging_needs_spec_sync_6() {
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let c = net.node(3, &[host]);
    let d = net.node(4, &[]);
    let g = net.group(a, &[(c, Role::Read), (d, Role::Read)], &[host]);
    let t = net.item(a, g, g, "chat");
    net.set_online(c, false);
    net.run();
    let mut role = None;
    for i in 0..N {
        say(&mut net, a, t, i);
        if i == N / 2 {
            let holder = net.tid(d);
            role = Some(net::set_edge(net.engine(a), t, holder, Role::Write));
        }
    }
    net.run();
    let role = role.unwrap();
    let l = net.label(a);
    let mut f = Chat { net, host, a, c, g, t, l };
    f.net.set_online(c, true);
    let mut part = 0;
    f.until(|s| {
        let n = s.held().len();
        if n > 0 {
            assert!(s.net.engine(s.c).header(&role).is_some(), "the role commit first");
            s.assert_newest();
            part += usize::from(n < N);
        }
        n == N
    });
    assert!(part > 0, "seen part way");
    f.finish();
}

// spec/sync.md §6, §8: part way the label is not synced, no pass has ended, and a read says so
// (status `Syncing`, `HistoryPage.complete` false); at the end it is.
#[test]
fn pass_ends_with_the_fill_spec_sync_6() {
    let mut f = chat(Role::Read);
    f.part_way();
    assert!(f.filling(), "status: filling");
    let g = f.g;
    assert!(!f.net.sync(f.c).complete_pass(&g), "no pass ended");
    assert!(!f.net.sync(f.c).is_idle(), "work left");
    f.finish();
    assert!(!f.filling());
    assert!(f.net.sync(f.c).complete_pass(&g));
    let passes = f.net.sync(f.c).pass_stats().passes;
    assert!(passes < 2 * N as u64 / FILL_BATCH as u64, "no pass per batch: {passes}");
}

// spec/sync.md §6: a filling node sends its own writes.
#[test]
fn own_writes_go_out_during_a_fill_spec_sync_6() {
    let mut f = chat(Role::Write);
    f.part_way();
    let (c, host, l, t) = (f.c, f.host, f.l, f.t);
    let w = f.net.write(c, t, "mine");
    f.net.feed(c, osis_node::sync::Event::Local);
    f.until(|s| {
        assert!(s.held().len() < N, "before the fill ended");
        let at_host: BTreeSet<BlobId> = s.net.host_ids(host, &l).into_iter().collect();
        s.net.sync(c).entries(&l).into_iter().any(|(b, k)| at_host.contains(&b) && matches!(k, EntryKind::Commit { commit, .. } if commit == w))
    });
    // its pass asks for nothing out of order
    f.until(|s| {
        s.assert_newest();
        !s.filling()
    });
    f.finish();
    assert_eq!(f.net.read(f.a, t), Some(net::s("mine")));
}

// spec/sync.md §6: a fill goes on across a restart from what is listed, not a second listing, and
// brings what does not open too (here a chunk: a filler wrap), as a replay did.
#[test]
fn restart_goes_on_without_listing_again_spec_sync_6() {
    let mut f = chat(Role::Read);
    let (a, c, host, l, t) = (f.a, f.c, f.host, f.l, f.t);
    let mut m = Mutation::new();
    m.set(t, &crate::net::REG, &net::s(&"x".repeat(1 << 20))).unwrap();
    f.net.engine(a).commit(m).unwrap().unwrap();
    f.net.run();
    f.part_way();
    let held = f.held().len();
    f.net.told.insert(c, Default::default());
    f.net.restart(c, 3);
    f.finish();
    let told = f.net.told.get(&c).map_or(0, |x| x.len());
    assert!(told < N - held + 16, "listed again: {told} entries told, {held} held");
    let ids: Vec<BlobId> = f.net.host_ids(host, &l);
    for b in ids {
        assert!(f.net.engine(c).has_blob(&b), "every entry fetched");
    }
}

// spec/crypto.md §5: what did not open at the listing takes its place in the order once secrets
// arrive: messages under a rotation's new epoch, its rotation fetched first.
#[test]
fn secrets_arriving_order_the_rest_spec_sync_6() {
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let c = net.node(3, &[host]);
    let d = net.node(4, &[]);
    let g = net.group(a, &[(c, Role::Read), (d, Role::Read)], &[host]);
    let t = net.item(a, g, g, "chat");
    net.set_online(c, false);
    net.run();
    for i in 0..N / 2 {
        say(&mut net, a, t, i);
    }
    net.run();
    // d leaves: a new read epoch, boxed to a and c
    let (ta, tc, td) = (net.tid(a), net.tid(c), net.tid(d));
    let recipients = net::recipients_of(net.engine(a), &[(ta, Role::Admin), (tc, Role::Read)]);
    net::remove_holder(net.engine(a), g, td, &recipients, 9);
    net.run();
    net.advance(61_000);
    for i in N / 2..N {
        say(&mut net, a, t, i);
    }
    net.run();
    let l = net.label(a);
    let mut f = Chat { net, host, a, c, g, t, l };
    f.net.set_online(c, true);
    f.until(|s| {
        s.assert_newest();
        s.held().len() == N
    });
    // no stranded heartbeat: it holds the head's read secret from what it fetched first, and no
    // pass judged before that
    assert!(!f.net.sync(c).stranded_at(&l), "no stranded heartbeat");
    f.finish();
}

// spec/sync.md §7, §6: a body this node holds from elsewhere, deleted at the host under a snapshot:
// while the fill has not fetched that snapshot the body is not established uncovered, so it does
// not go up again.
#[test]
fn a_covered_body_stays_gone_during_a_fill_spec_sync_6() {
    let mut f = chat(Role::Write);
    let (a, c, host, l, t) = (f.a, f.c, f.host, f.l, f.t);
    let w = f.net.write(a, t, "old");
    let pk = f.net.engine(a).package(&w).unwrap().unwrap();
    f.net.engine(c).ingest(&pk.bytes, pk.blobs).unwrap();
    f.net.write(a, t, "new");
    f.net.run();
    let reg = Ak::new("t:reg.0").unwrap();
    let acts = f.net.sync(a).compact(&t, &reg).unwrap();
    f.net.actions(a, acts);
    f.net.run();
    f.net.advance(osis_base::format::MAX_DRIFT_MS + 61_000);
    // what the snapshot left newest, so it comes some batches in
    for i in 0..8 * FILL_BATCH {
        say(&mut f.net, a, t, N + i);
    }
    f.net.run();
    let copies_at = |net: &mut Net, n: usize| -> BTreeSet<BlobId> { net.sync(n).entries(&l).into_iter().filter(|(_, k)| matches!(k, EntryKind::Commit { commit, .. } if *commit == w)).map(|x| x.0).collect() };
    let at_a = copies_at(&mut f.net, a);
    let before: BTreeSet<BlobId> = f.net.host_ids(host, &l).into_iter().collect();
    assert!(at_a.is_disjoint(&before), "deleted at the host");
    f.net.set_online(c, true);
    f.until(|s| s.held().len() >= FILL_BATCH);
    // past a co-writer's wait to relay it (`relay_at`, at most 30 s), with passes (each 60 s)
    let passes = f.net.sync(c).pass_stats().passes;
    for _ in 0..2 {
        f.net.tick(61_000);
        for _ in 0..3 {
            f.net.round();
            // no entry of it here: none listed, and none placed (a deletes one placed within hops)
            assert!(copies_at(&mut f.net, c).is_empty(), "the body went up during the fill");
        }
    }
    assert!(f.net.sync(c).pass_stats().passes >= passes + 2, "passes ran");
    assert!(f.filling());
}

// spec/sync.md §7 Repair: a node part way through a fill does not answer another's suspect report:
// its snapshot would be of a state not whole yet.
#[test]
fn no_repair_from_a_state_part_way_spec_sync_6() {
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let r = net.node(2, &[host]);
    let c = net.node(3, &[host]);
    let g = net.group(a, &[(r, Role::Read), (c, Role::Write)], &[host]);
    net.set_online(c, false);
    net.run();
    // the suspect reader, as in `suspect_aspect_repaired_by_writer_snapshot_spec_permissions_4`
    net.set_online(r, false);
    let t = net.item(a, g, g, "chat");
    let mut m = Mutation::new();
    m.set(t, &crate::net::REG, &net::s("v2")).unwrap();
    m.expires(t, &crate::net::REG, osis_base::WallMs(net.now() + 60_000)).unwrap();
    let w = net.engine(a).commit(m).unwrap().unwrap();
    net.run();
    let pk = net.engine(a).package(&w).unwrap().unwrap();
    net.engine(r).ingest(&pk.bytes, pk.blobs.clone()).unwrap();
    net.advance(120_000);
    net.engine(r).tick().unwrap();
    assert!(!net.engine(r).suspects().unwrap().is_empty());
    for i in 0..N {
        say(&mut net, a, t, i);
    }
    net.set_online(r, true);
    net.run();
    net.advance(osis_base::format::HEARTBEAT_MIN_INTERVAL_MS + 60_000);
    let l = net.label(a);
    let mut f = Chat { net, host, a, c, g, t, l };
    f.part_way();
    // a pass, the fill going on
    f.net.tick(61_000);
    f.net.round();
    assert!(f.held().len() < N);
    let d = f.net.diagnostics(c);
    assert!(!d.iter().any(|x| x.contains("Repair")), "{d:?}");
    f.finish();
}

// spec/sync.md §5: what no writer vouched for and does not open is listed before its bytes come in
// a fill, and goes as they do, as it would have arriving inline.
#[test]
fn junk_listed_goes_when_it_comes_spec_sync_6() {
    let mut f = chat(Role::Read);
    let (c, host, l, g) = (f.c, f.host, f.l, f.g);
    let a = f.a;
    let (_, gl) = f.net.sync(a).labels().into_iter().find(|(_, x)| x.id == l).unwrap();
    let head = f.net.host_path(host, &l).last().unwrap().clone();
    let keys = f.net.engine(a).head_keys(&g, gl.index, &head).unwrap();
    let mut rng = osis_crypto::SeededRng::from_u64(7);
    let prefix = osis_label::Prefix::new(osis_label::Prefix::random_salt(&mut rng), None, Vec::new()).unwrap();
    let (_, blob) = osis_label::frame(&prefix, b"junk", &mut rng).unwrap();
    let id = osis_label::blob_id(&blob);
    let wrap = [0x13; osis_crypto::WRAP_LEN];
    let sig = osis_label::sign_deposit(keys.deposit.as_ref().unwrap(), &l, &id, &wrap);
    crate::wrap_poison::send(&mut f.net, a, host, osis_proto::Message::Deposit { id: 0x4000_0001, label: l, blob, wrap, sig });
    f.net.run();
    assert!(f.net.host_ids(host, &l).contains(&id), "at the host");
    f.net.set_online(c, true);
    f.finish();
    assert!(!f.net.engine(c).has_blob(&id), "bytes of an unvouched entry that opens under nothing");
}

/// `c`, a new node, past the listing, the rotation that brings the head's read secret held back:
/// no pass runs, so no stranded heartbeat, whatever wants one: `write` an own write, and with two
/// hosts the second host's fill, which finds order 0 in flight on the first and goes on.
fn no_pass_before_order_0(hosts: usize, write: bool) {
    let mut net = Net::new();
    let hs: Vec<usize> = (0..hosts).map(|_| net.add_host()).collect();
    let a = net.node(1, &hs);
    let c = net.node(3, &hs);
    let d = net.node(4, &[]);
    let g = net.group(a, &[(c, Role::Write), (d, Role::Read)], &hs);
    let t = net.item(a, g, g, "chat");
    net.set_online(c, false);
    net.run();
    for i in 0..N / 2 {
        say(&mut net, a, t, i);
    }
    net.run();
    let (ta, tc, td) = (net.tid(a), net.tid(c), net.tid(d));
    let recipients = net::recipients_of(net.engine(a), &[(ta, Role::Admin), (tc, Role::Write)]);
    let rotation = net::remove_holder(net.engine(a), g, td, &recipients, 9);
    net.run();
    net.advance(61_000);
    let l = net.label(a);
    let held: Vec<BlobId> = net.sync(a).entries(&l).into_iter().filter(|(_, k)| matches!(k, EntryKind::Commit { commit, .. } if *commit == rotation)).map(|x| x.0).collect();
    assert!(!held.is_empty());
    let mut f = Chat { net, host: hs[0], a, c, g, t, l };
    f.net.set_online(c, true);
    f.until(|s| s.net.sync(c).entries(&l).len() > N / 2);
    // listed: the fetch's reply waits
    f.net.hold_blobs.extend(held);
    assert!(f.net.sync(c).fill_before_passes());
    if write {
        let mut m = Mutation::new();
        m.set(tc, &crate::net::REG, &net::s("mine")).unwrap();
        f.net.engine(c).commit(m).unwrap().unwrap();
        f.net.feed(c, osis_node::sync::Event::Local);
    }
    for _ in 0..200 {
        f.net.round();
        if f.net.queue_len() == 0 {
            f.net.tick(1_000);
        }
        assert!(!f.net.sync(c).stranded_at(&l), "a pass before order 0");
    }
    // the second host's fill went on with the newest
    let ids = f.net.host_ids(hs[0], &l);
    let fetched = ids.iter().filter(|b| f.net.engine(c).has_blob(b)).count();
    assert_eq!(fetched > FILL_BATCH / 2, hosts == 2, "{fetched} fetched at {hosts} host(s)");
    f.net.release();
    f.net.run();
    f.net.advance(61_000);
    assert!(!f.net.sync(c).stranded_at(&l), "no stranded heartbeat");
    assert_eq!(f.held().len(), N / 2);
}

// spec/sync.md §6: order 0 before a pass.
#[test]
fn no_pass_before_order_0_spec_sync_6() {
    no_pass_before_order_0(1, true);
}

// spec/sync.md §6: order 0 before a pass, whichever host fetches it.
#[test]
fn no_pass_before_order_0_at_two_hosts_spec_sync_6() {
    no_pass_before_order_0(2, false);
}

// spec/sync.md §6: a rotation part way can end the open at the host with a batch asked under it:
// the host refuses it, the reopen goes on from what is listed, in order, and the pass still ends
// only when everything is here.
#[test]
fn a_rotation_part_way_loses_nothing_spec_sync_6() {
    let mut refused = 0;
    for wait in 0..4 {
        let mut net = Net::new();
        let host = net.add_host();
        let a = net.node(1, &[host]);
        let c = net.node(3, &[host]);
        let d = net.node(4, &[]);
        let g = net.group(a, &[(c, Role::Read), (d, Role::Read)], &[host]);
        let t = net.item(a, g, g, "chat");
        net.set_online(c, false);
        net.run();
        for i in 0..N {
            say(&mut net, a, t, i);
        }
        net.run();
        let l = net.label(a);
        let mut f = Chat { net, host, a, c, g, t, l };
        f.part_way();
        for _ in 0..wait {
            f.net.round();
        }
        let (ta, tc, td) = (f.net.tid(a), f.net.tid(c), f.net.tid(d));
        let recipients = net::recipients_of(f.net.engine(a), &[(ta, Role::Admin), (tc, Role::Read)]);
        net::remove_holder(f.net.engine(a), g, td, &recipients, 9);
        f.net.feed(a, osis_node::sync::Event::Local);
        f.until(|s| {
            let n = s.held().len();
            let g = s.g;
            s.assert_newest();
            if n < N {
                assert!(!s.net.sync(s.c).complete_pass(&g), "a pass ended with {n} of {N} held");
                assert!(s.filling(), "status: filling, {n} of {N} held");
            }
            n == N
        });
        refused += f.net.diagnostics(c).iter().filter(|x| x.contains("Fetch refused")).count();
        f.finish();
    }
    assert!(refused > 0, "no batch was refused: nothing tested");
}

// spec/sync.md §6: a message written during a fill comes next, not after the backlog.
#[test]
fn a_push_during_a_fill_comes_next_spec_sync_6() {
    let mut f = chat(Role::Read);
    f.part_way();
    let (a, t) = (f.a, f.t);
    let held = f.held().len();
    let mut m = Mutation::new();
    m.set(t, &MSG, &Value::Str("zz new".into())).unwrap();
    f.net.engine(a).commit(m).unwrap().unwrap();
    f.net.feed(a, osis_node::sync::Event::Local);
    f.until(|s| s.held().first().is_some_and(|v| v.as_ref() == Some(&Value::Str("zz new".into()))));
    assert!(f.held().len() < held + 2 * FILL_BATCH, "next: {} held", f.held().len());
    f.net.run();
    f.net.advance(61_000);
    assert_eq!(f.held().len(), N + 1);
}

// spec/sync.md §6, spec/crdt.md §5.7: text fetched newest first reads as what it holds, an own
// insert anchored in it goes out, and every node ends with one text.
#[test]
fn an_own_edit_of_text_part_way_joins_spec_sync_6() {
    use osis_crdt::{Op, PathOp};
    let mut f = chat(Role::Write);
    let (a, c, t) = (f.a, f.c, f.t);
    let mut m = Mutation::new();
    m.set(t, &net::SEQ, &net::s("base")).unwrap();
    f.net.engine(a).commit(m).unwrap().unwrap();
    for i in 0..N {
        let mut m = Mutation::new();
        m.op(t, &net::SEQ, PathOp { path: Vec::new(), op: Op::Insert { at: 4 + i, items: vec![net::s("x")] } }).unwrap();
        f.net.engine(a).commit(m).unwrap().unwrap();
    }
    f.net.run();
    let seq = Ak::new("t:seq.0").unwrap();
    f.net.set_online(c, true);
    f.until(|s| s.net.engine(s.c).get(&s.t, &seq).unwrap().is_some() && s.held().len() >= FILL_BATCH);
    let mut m = Mutation::new();
    m.op(t, &net::SEQ, PathOp { path: Vec::new(), op: Op::Insert { at: 0, items: vec![net::s("Z")] } }).unwrap();
    f.net.engine(c).commit(m).unwrap().unwrap();
    f.net.feed(c, osis_node::sync::Event::Local);
    f.net.run();
    f.net.advance(61_000);
    let (at_a, at_c) = (f.net.engine(a).get(&t, &seq).unwrap(), f.net.engine(c).get(&t, &seq).unwrap());
    assert_eq!(at_a, at_c);
    let Some(Value::Str(text)) = at_a else { panic!("text") };
    assert_eq!(text.matches('x').count(), N);
    assert!(text.contains('Z') && text.contains("base"), "{text}");
}

// spec/sync.md §6: a compaction part way (an app's own) covers only what it holds: nothing the
// node has not got is lost, for it or anyone.
#[test]
fn a_compaction_part_way_loses_nothing_spec_sync_6() {
    let mut f = chat(Role::Write);
    let (a, c, t) = (f.a, f.c, f.t);
    let big = Ak::new("t:big.0").unwrap();
    for i in 0..N {
        let mut m = Mutation::new();
        m.op(t, &net::BIG, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Key(net::s(&format!("{i:05}")))], op: osis_crdt::Op::Put(net::s("v")) }).unwrap();
        f.net.engine(a).commit(m).unwrap().unwrap();
    }
    f.net.run();
    f.net.advance(osis_base::format::MAX_DRIFT_MS + 61_000);
    f.net.set_online(c, true);
    f.until(|s| s.net.engine(s.c).get(&s.t, &big).unwrap().is_some() && s.held().len() >= FILL_BATCH);
    let acts = f.net.sync(c).compact(&t, &big).unwrap();
    f.net.actions(c, acts);
    f.net.run();
    f.net.advance(61_000);
    let (at_a, at_c) = (f.net.engine(a).get(&t, &big).unwrap(), f.net.engine(c).get(&t, &big).unwrap());
    assert_eq!(at_a, at_c);
    let Some(Value::Map(m)) = at_c else { panic!("map") };
    assert_eq!(m.len(), N);
    assert_eq!(f.held().len(), N);
}

// spec/crypto.md §5: a purge request is order 0: here before any message, wherever in the log.
#[test]
fn a_purge_comes_with_order_0_spec_crypto_5() {
    let mut f = chat(Role::Read);
    let (a, c, t) = (f.a, f.c, f.t);
    let target = {
        let mut m = Mutation::new();
        m.set(t, &MSG, &Value::Str("target".into())).unwrap();
        f.net.engine(a).commit(m).unwrap().unwrap()
    };
    let mut m = Mutation::new();
    m.purge(osis_commit::PurgeItem::Commit { commit: target, tid: t, ak: Ak::new("f:msgs.0").unwrap() });
    m.set(t, &crate::net::REG, &net::s("p")).unwrap();
    let purge = f.net.engine(a).commit(m).unwrap().unwrap();
    for i in N..N + 2 * FILL_BATCH {
        say(&mut f.net, a, t, i);
    }
    f.net.run();
    f.net.set_online(c, true);
    f.until(|s| {
        let n = s.held().len();
        if n > 0 {
            assert!(s.net.engine(s.c).header(&purge).is_some(), "the purge first");
        }
        n > 0
    });
}
