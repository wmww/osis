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

/// `a` writes `N` kept messages; `c`, a new device holding its grant, has never met the host.
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
        self.net.sync(self.c).label_status().iter().any(|s| s.group == g && s.idle < s.open)
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

// spec/sync.md §6: a filling device sends its own writes.
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
    // past a co-writer's wait to relay it (`relay_due`), two passes
    for _ in 0..2 {
        f.net.tick(3_600_000);
        for _ in 0..3 {
            f.net.round();
        }
    }
    assert!(f.filling());
    let copies = copies_at(&mut f.net, c);
    let up: Vec<BlobId> = f.net.host_ids(host, &l).into_iter().filter(|b| !before.contains(b) && copies.contains(b)).collect();
    assert!(up.is_empty(), "the body went up during the fill: {up:?}");
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
