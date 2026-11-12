#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Co-reader-peer serving limits and LAN routes (spec/sync.md §5, §10): tombstones, budgets,
//! session caps, refused strangers and removed holders, LAN candidates, co-reader caps.

use crate::net::{hosted_nodes, local_nodes};
use crate::net;
use net::*;
use osis_base::{LabelId, Role};
use osis_crypto::SigningSecret;
use osis_label::Address;
use osis_node::sync::{Action, ConnId, EntryKind, Event, SyncConfig};
use osis_proto::{ClientConfig, ClientEvent, ClientInput, ClientOutput, ClientSession, Command};

const LOCAL: [u8; 32] = [0x42; 32];

/// A hand-driven peer session into node `n`: its served session there and its hub connection.
struct Dialer {
    conn: ConnId,
    hc: ConnId,
    cs: ClientSession,
}

fn exchange(net: &mut Net, n: usize, p: &mut Dialer, acts: Vec<Action>, outs: Vec<ClientOutput>) -> Vec<ClientEvent> {
    net.hand_exchange(n, p.hc, &mut p.cs, acts, outs, true)
}

fn dial_in(net: &mut Net, n: usize) -> (Dialer, Vec<ClientEvent>) {
    let (hc, sent) = net.hand_accept(n, LOCAL, osis_transport::Peer::Key([0x43; 32]));
    let mut p = Dialer { conn: 0, hc, cs: ClientSession::new(ClientConfig { peer_static_key: LOCAL, challenge: [7; 32] }) };
    let now = net.now();
    let mut outs = p.cs.handle(now, ClientInput::Start);
    for f in sent {
        outs.extend(p.cs.handle(now, ClientInput::Bytes(f)));
    }
    let evs = exchange(net, n, &mut p, Vec::new(), outs);
    p.conn = net.served(n, hc);
    (p, evs)
}

fn command(net: &mut Net, n: usize, p: &mut Dialer, cmd: Command) -> Vec<ClientEvent> {
    let now = net.now();
    let outs = p.cs.handle(now, ClientInput::Command(cmd));
    exchange(net, n, p, Vec::new(), outs)
}

/// A hand dialer of node `n` that proved `proven_as`'s node key and is a member of `l` here.
fn member_session(net: &mut Net, n: usize, proven_as: usize, l: LabelId) -> Dialer {
    member_pulled(net, n, proven_as, l).0
}

/// `member_session`, with what `n` sent it once `l` joined (its Pull).
fn member_pulled(net: &mut Net, n: usize, proven_as: usize, l: LabelId) -> (Dialer, Vec<ClientEvent>) {
    let (mut p, _) = dial_in(net, n);
    let own = net.engine(proven_as).account_tid().is_some_and(|x| net.engine(n).account_tid() == Some(x));
    let provers = net.sync(proven_as).provers(own).unwrap();
    command(net, n, &mut p, Command::Prove(provers));
    let mut out = Vec::new();
    net.sync(n).shared_admit(p.conn, l, &mut out).unwrap();
    let evs = exchange(net, n, &mut p, out, Vec::new());
    (p, evs)
}

fn reach(net: &mut Net, n: usize, key: u8) {
    let acts = net.sync(n).publish_reach([key; 32], vec![]).unwrap();
    net.actions(n, acts);
}

/// Whether node `b`, with `peer_bytes`, keeps an unstamped entry no key here opens, 1000 bytes,
/// that a reader sharing L brings in reply to `b`'s Pull.
fn kept_from_reader(peer_bytes: u64) -> bool {
    let (mut net, [a]) = local_nodes::<1>();
    let cfg = SyncConfig { peers: false, peer_bytes, ..SyncConfig::default() };
    let b = net.add_node(2, cfg);
    reach(&mut net, a, 0xa1);
    reach(&mut net, b, 0xb1);
    net.blocked_peers.insert((a, b));
    net.group_at(a, &[(b, Role::Write)], vec![]);
    net.run();
    let l = net.label(b);
    let (mut p, evs) = member_pulled(&mut net, b, a, l);
    let id = evs.iter().find_map(|e| if let ClientEvent::Peer(m) = e { if let osis_proto::Message::Pull(x) = &**m { Some(x.id) } else { None } } else { None }).expect("b pulls its member");
    let blob = vec![0x5a; 1000];
    let blob_id = osis_label::blob_id(&blob);
    let ev = osis_proto::Event::Added { blob_id, blob: Some(blob), wrap: [0x11; osis_crypto::WRAP_LEN], stamp: None };
    let reply = osis_proto::msg::PullReply { id, events: vec![(l, ev)], cursor: Some(vec![1; 8]), whole: false, trimmed: false, more: false, report: false, joins: Vec::new() };
    command(&mut net, b, &mut p, Command::Peer(Box::new(osis_proto::Message::PullReply(Box::new(reply)))));
    net.sync(b).entries(&l).iter().any(|(x, _)| *x == blob_id)
}

// spec/sync.md §5 (hosts cap storage per label; co-reader peer applies the same rule), spec/requirements.md
// (peer input never grows storage unbounded): unopened, unstamped entries a reader's stream brings
// count against the peer budget, and past it are not kept.
#[test]
fn peer_budget_refuses_spec_sync_5() {
    assert!(kept_from_reader(SyncConfig::default().peer_bytes), "within the budget, kept");
    assert!(!kept_from_reader(64), "past it, not kept");
}

/// Whether node `b`, with `peer_bytes`, keeps a commit that opens and pends here (drift: its
/// author's clock two hours ahead) that a reader sharing L brings, unstamped, in reply to `b`'s
/// Pull; and whether `b` then holds it pending.
fn pending_kept_from_reader(peer_bytes: u64) -> (bool, bool) {
    let mut net = Net::new();
    let a = net.node(1, &[]);
    let cfg = SyncConfig { peers: false, peer_bytes, ..SyncConfig::default() };
    let b = net.add_node(2, cfg);
    reach(&mut net, a, 0xa1);
    reach(&mut net, b, 0xb1);
    net.blocked_peers.insert((a, b));
    let g = net.group_at(a, &[(b, Role::Write)], vec![]);
    net.run();
    net.set_skew(a, 2 * 3_600_000);
    let c = net.write(a, g, "ahead");
    let acts = net.sync(a).handle(Event::Local);
    net.actions(a, acts);
    net.run();
    net.set_skew(a, 0);
    let l = net.label(b);
    let la = net.label(a);
    let blob_id = net.sync(a).entries(&la).into_iter().find(|(_, k)| matches!(k, EntryKind::Commit { commit, .. } if *commit == c)).expect("a placed it").0;
    let (wrap, _) = net.sync(a).entry_meta(&la, &blob_id).unwrap();
    let blob = net.engine(a).blob(&blob_id).unwrap().unwrap();
    let (mut p, evs) = member_pulled(&mut net, b, a, l);
    let id = evs.iter().find_map(|e| if let ClientEvent::Peer(m) = e { if let osis_proto::Message::Pull(x) = &**m { Some(x.id) } else { None } } else { None }).expect("b pulls its member");
    let ev = osis_proto::Event::Added { blob_id, blob: Some(blob), wrap, stamp: None };
    let reply = osis_proto::msg::PullReply { id, events: vec![(l, ev)], cursor: Some(vec![1; 8]), whole: false, trimmed: false, more: false, report: false, joins: Vec::new() };
    command(&mut net, b, &mut p, Command::Peer(Box::new(osis_proto::Message::PullReply(Box::new(reply)))));
    let kept = net.sync(b).entries(&l).iter().any(|(x, _)| *x == blob_id);
    let pending = net.engine(b).pending().iter().any(|(x, _)| *x == c);
    (kept, pending)
}

// notes/node-sync.md (Input giving nothing), spec/requirements.md (peer input never grows storage
// unbounded): an entry from a reader that opens to a commit pending here counts against the peer
// budget as an unopened one does; past it neither the entry nor the pending commit is kept.
#[test]
fn pending_from_reader_counts_against_peer_budget_spec_sync_5() {
    assert_eq!(pending_kept_from_reader(SyncConfig::default().peer_bytes), (true, true), "within the budget, kept pending");
    assert_eq!(pending_kept_from_reader(64), (false, false), "past it, neither kept");
}

/// A reader sharing L brings writer `b` two batches of `k` unstamped entries giving nothing
/// there, each batch on its own session: unopened 1000-byte entries, or with `pending` commits
/// that open and pend (drift). `peer_bytes` is the first batch's size; with `restart` `b`
/// restarts between the batches. How many of each batch `b` holds after the second.
fn budget_across_restart(pending: bool, restart: bool) -> (usize, usize) {
    let k = 3;
    let mut net = Net::new();
    let a = net.node(1, &[]);
    let b = net.add_node(2, SyncConfig { peers: false, ..SyncConfig::default() });
    reach(&mut net, a, 0xa1);
    reach(&mut net, b, 0xb1);
    net.blocked_peers.insert((a, b));
    let g = net.group_at(a, &[(b, Role::Write)], vec![]);
    // each write keeps its own commit and entry (else the trigger compacts them)
    net.keep(a, g, &[(osis_schema::RawKey::ak(&crate::net::REG), osis_schema::History::FOREVER)]);
    net.run();
    let l = net.label(b);
    let mut events = Vec::new();
    if pending {
        net.set_skew(a, 2 * 3_600_000);
        let la = net.label(a);
        for i in 0..2 * k {
            let c = net.write(a, g, &format!("ahead {i}"));
            let acts = net.sync(a).handle(Event::Local);
            net.actions(a, acts);
            net.run();
            let blob_id = net.sync(a).entries(&la).into_iter().find(|(_, x)| matches!(x, EntryKind::Commit { commit, .. } if *commit == c)).expect("a placed it").0;
            let (wrap, _) = net.sync(a).entry_meta(&la, &blob_id).unwrap();
            let blob = net.engine(a).blob(&blob_id).unwrap().unwrap();
            events.push((blob_id, blob, wrap));
        }
        net.set_skew(a, 0);
    } else {
        for i in 0..2 * k {
            let blob = vec![0x50 + i as u8; 1000];
            events.push((osis_label::blob_id(&blob), blob, [0x11; osis_crypto::WRAP_LEN]));
        }
    }
    let budget: u64 = events.iter().take(k).map(|(_, x, _)| x.len() as u64).sum();
    net.sync(b).config_mut().peer_bytes = budget;
    for (i, batch) in events.chunks(k).enumerate() {
        if i == 1 && restart {
            net.restart(b, 9);
            net.sync(b).config_mut().peer_bytes = budget;
        }
        let (mut p, evs) = member_pulled(&mut net, b, a, l);
        let id = evs.iter().find_map(|e| if let ClientEvent::Peer(m) = e { if let osis_proto::Message::Pull(x) = &**m { Some(x.id) } else { None } } else { None }).expect("b pulls its member");
        let evs = batch.iter().map(|(blob_id, blob, wrap)| (l, osis_proto::Event::Added { blob_id: *blob_id, blob: Some(blob.clone()), wrap: *wrap, stamp: None })).collect();
        let reply = osis_proto::msg::PullReply { id, events: evs, cursor: Some(vec![1 + i as u8; 8]), whole: false, more: false, report: false, trimmed: false, joins: Vec::new() };
        command(&mut net, b, &mut p, Command::Peer(Box::new(osis_proto::Message::PullReply(Box::new(reply)))));
    }
    let held = net.sync(b).entries(&l);
    let count = |batch: &[(osis_base::BlobId, Vec<u8>, [u8; osis_crypto::WRAP_LEN])]| batch.iter().filter(|(x, _, _)| held.iter().any(|(y, _)| y == x)).count();
    (count(&events[..k]), count(&events[k..]))
}

// spec/requirements.md (peer input never grows storage unbounded), notes/peers.md Budget: the
// peer budget holds across a restart. A reader fills it with entries giving nothing (unopened,
// or commits pending here), the node restarts, and the reader's next batch is refused as it is
// without the restart: what the node holds stays within one budget.
#[test]
fn peer_budget_holds_across_restart_spec_sync_5() {
    for pending in [false, true] {
        assert_eq!(budget_across_restart(pending, false), (3, 0), "pending {pending}: the first batch fills the budget");
        assert_eq!(budget_across_restart(pending, true), (3, 0), "pending {pending}: a restart gives no fresh budget");
    }
}

/// Whether node `b` (`peer_bytes` 1500) keeps the second of two unopened 1000-byte entries that
/// reader `a` brings over two sessions, each proving `a`'s account and, with `fresh`, also an
/// account known by nothing at `b`, below `a`'s in tid order (anyone can make one per session).
fn second_kept(fresh: bool) -> bool {
    let (mut net, [a]) = local_nodes::<1>();
    let cfg = SyncConfig { peers: false, peer_bytes: 1500, ..SyncConfig::default() };
    let b = net.add_node(2, cfg);
    reach(&mut net, a, 0xa1);
    reach(&mut net, b, 0xb1);
    net.blocked_peers.insert((a, b));
    net.group_at(a, &[(b, Role::Write)], vec![]);
    net.run();
    let l = net.label(b);
    let pa = net.tid(a);
    let mut strangers = Vec::new();
    for seed in 10.. {
        let s = net.node(seed, &[]);
        if net.tid(s) < pa {
            strangers.push(s);
        }
        if strangers.len() == 2 {
            break;
        }
    }
    let mut kept = false;
    for (i, s) in strangers.into_iter().enumerate() {
        let (mut p, _) = dial_in(&mut net, b);
        let mut provers = net.sync(a).provers(false).unwrap();
        if fresh {
            provers.extend(net.sync(s).provers(false).unwrap());
        }
        command(&mut net, b, &mut p, Command::Prove(provers));
        let mut out = Vec::new();
        net.sync(b).shared_admit(p.conn, l, &mut out).unwrap();
        let evs = exchange(&mut net, b, &mut p, out, Vec::new());
        let id = evs.iter().find_map(|e| if let ClientEvent::Peer(m) = e { if let osis_proto::Message::Pull(x) = &**m { Some(x.id) } else { None } } else { None }).expect("b pulls its member");
        let blob = vec![0x5a + i as u8; 1000];
        let blob_id = osis_label::blob_id(&blob);
        let ev = osis_proto::Event::Added { blob_id, blob: Some(blob), wrap: [0x11; osis_crypto::WRAP_LEN], stamp: None };
        let reply = osis_proto::msg::PullReply { id, events: vec![(l, ev)], cursor: Some(vec![1; 8]), whole: false, trimmed: false, more: false, report: false, joins: Vec::new() };
        command(&mut net, b, &mut p, Command::Peer(Box::new(osis_proto::Message::PullReply(Box::new(reply)))));
        kept = net.sync(b).entries(&l).iter().any(|(x, _)| *x == blob_id);
    }
    kept
}

// spec/sync.md §5 (co-reader peer budgets), notes/peers.md Source: a peer's bytes count against
// the account it proved, not one known by nothing here: proving a fresh account beside its own
// gives a session no budget of its own.
#[test]
fn a_fresh_account_splits_no_budget_spec_sync_5() {
    assert!(!second_kept(false), "one account, one budget");
    assert!(!second_kept(true), "a fresh account beside it adds none");
}

/// The bytes of node `n`'s stored entry rows under `l` (`y/e`), by blob.
fn entry_rows(net: &mut Net, n: usize, l: LabelId) -> std::collections::BTreeMap<osis_base::BlobId, usize> {
    net.sync(n).sync_row_sizes(b'e').into_iter().filter(|(k, _)| k.windows(16).any(|w| w == l.0)).filter_map(|(k, v)| {
        let id: [u8; 32] = k.get(k.len().checked_sub(32)?..)?.try_into().ok()?;
        Some((osis_base::BlobId(id), v))
    }).collect()
}

// notes/peers.md Budget (`Entry::source`): an entry charged to a peer's source keeps it in its row
// (15 bytes) while it counts, the same per entry at n and 10n, and drops it once the entry gives
// something held (here pending commits that apply once the clock passes their drift).
#[test]
fn a_charged_source_costs_its_row_until_judged_spec_sync_5() {
    let mut per_entry = Vec::new();
    for n in [2, 20] {
        let mut net = Net::new();
        let a = net.node(1, &[]);
        let b = net.add_node(2, SyncConfig { peers: false, ..SyncConfig::default() });
        reach(&mut net, a, 0xa1);
        reach(&mut net, b, 0xb1);
        net.blocked_peers.insert((a, b));
        let g = net.group_at(a, &[(b, Role::Write)], vec![]);
        // each write keeps its own commit and entry (else the trigger compacts them)
        net.keep(a, g, &[(osis_schema::RawKey::ak(&crate::net::REG), osis_schema::History::FOREVER)]);
        net.run();
        let (l, la) = (net.label(b), net.label(a));
        net.set_skew(a, 2 * 3_600_000);
        let mut events = Vec::new();
        for i in 0..n {
            let c = net.write(a, g, &format!("ahead {i:03}"));
            let acts = net.sync(a).handle(Event::Local);
            net.actions(a, acts);
            net.run();
            let blob_id = net.sync(a).entries(&la).into_iter().find(|(_, x)| matches!(x, EntryKind::Commit { commit, .. } if *commit == c)).expect("a placed it").0;
            let (wrap, _) = net.sync(a).entry_meta(&la, &blob_id).unwrap();
            let blob = net.engine(a).blob(&blob_id).unwrap().unwrap();
            events.push((l, osis_proto::Event::Added { blob_id, blob: Some(blob), wrap, stamp: None }));
        }
        net.set_skew(a, 0);
        let ids: Vec<osis_base::BlobId> = events.iter().filter_map(|(_, e)| if let osis_proto::Event::Added { blob_id, .. } = e { Some(*blob_id) } else { None }).collect();
        let (mut p, evs) = member_pulled(&mut net, b, a, l);
        let id = evs.iter().find_map(|e| if let ClientEvent::Peer(m) = e { if let osis_proto::Message::Pull(x) = &**m { Some(x.id) } else { None } } else { None }).expect("b pulls its member");
        let reply = osis_proto::msg::PullReply { id, events, cursor: Some(vec![1; 8]), whole: false, more: false, report: false, trimmed: false, joins: Vec::new() };
        command(&mut net, b, &mut p, Command::Peer(Box::new(osis_proto::Message::PullReply(Box::new(reply)))));
        let charged = entry_rows(&mut net, b, l);
        assert!(ids.iter().all(|x| charged.contains_key(x)), "n {n}: every entry kept pending");
        net.advance(2 * 3_600_000 + 60_000);
        assert!(net.engine(b).pending().is_empty(), "n {n}: the commits applied");
        let judged = entry_rows(&mut net, b, l);
        let charged: usize = ids.iter().map(|x| charged[x]).sum();
        let judged: usize = ids.iter().map(|x| judged.get(x).copied().expect("kept applied")).sum();
        assert_eq!(charged, judged + 15 * n, "n {n}: 15 bytes per charged row, gone once judged");
        per_entry.push(charged / n);
    }
    assert_eq!(per_entry[0], per_entry[1], "the same row per entry at n and 10n");
}

/// Writer `b` (`peer_bytes`) syncing a label with no host; reader `r` serves it as a co-reader
/// peer and streams `n` genuine commits of its own on item `t`, each invalid at `b` (a reader
/// writes nothing), ephemeral with `memory`. Returns how many of them `b` still knows (a header
/// with no body each), the bytes of `b`'s store, and whether writer `a`'s commit, streamed next
/// by a session proving `a`, applies at `b`.
fn reader_flood(n: usize, memory: bool) -> (usize, usize, bool) {
    let mut net = Net::new();
    let a = net.node(1, &[]);
    let b = net.add_node(2, SyncConfig { peers: false, ..SyncConfig::default() });
    let r = net.node(3, &[]);
    for (n, k) in [(a, 0xa1), (b, 0xb1), (r, 0xc1)] {
        reach(&mut net, n, k);
    }
    for x in [(a, b), (b, a), (r, b), (b, r)] {
        net.blocked_peers.insert(x);
    }
    let g = net.group_at(a, &[(b, Role::Write), (r, Role::Read)], vec![]);
    let t = net.item(a, g, g, "doc");
    net.run();
    let l = net.label(b);
    // the item reaches b (a host-less label: a's stream)
    let la = net.label(a);
    let pull = |evs: &[ClientEvent]| evs.iter().find_map(|e| if let ClientEvent::Peer(m) = e { if let osis_proto::Message::Pull(x) = &**m { Some(x.id) } else { None } } else { None });
    let a_events = |net: &mut Net| -> Vec<(LabelId, osis_proto::Event)> {
        net.sync(a).entries(&la).into_iter().filter_map(|(blob_id, _)| {
            let (wrap, _) = net.sync(a).entry_meta(&la, &blob_id)?;
            let blob = net.engine(a).blob(&blob_id).ok()??;
            Some((l, osis_proto::Event::Added { blob_id, blob: Some(blob), wrap, stamp: None }))
        }).collect()
    };
    let (mut pa, evs) = member_pulled(&mut net, b, a, l);
    let id = pull(&evs).expect("b pulls a");
    let events = a_events(&mut net);
    let reply = osis_proto::msg::PullReply { id, events, cursor: Some(vec![1; 8]), whole: false, more: false, report: false, trimmed: false, joins: Vec::new() };
    command(&mut net, b, &mut pa, Command::Peer(Box::new(osis_proto::Message::PullReply(Box::new(reply)))));
    assert_eq!(net.read(b, t), Some(s("doc")), "the item reached b");
    let mut flood = Vec::new();
    let mut events = Vec::new();
    for i in 0..n {
        let mut m = osis_node::Mutation::new();
        let e = net.engine(r);
        let id = if memory {
            m.set(t, &crate::common::ak("win:notes+.0"), &s(&format!("r{i}"))).unwrap();
            e.commit_in_memory_hostile(m).unwrap().unwrap()
        } else {
            m.set(t, &REG, &s(&format!("r{i}"))).unwrap();
            e.commit_hostile(m).unwrap().unwrap()
        };
        let cb = osis_commit::CommitBlob::decode(&net.engine(r).take_forged().unwrap()).unwrap();
        let (_, ev) = crate::ephemeral::sealed(&mut net, b, g, &cb, None, 1000 + i as u64);
        flood.push(id);
        events.push((l, ev));
    }
    let (mut pr, evs) = member_pulled(&mut net, b, r, l);
    let id = pull(&evs).expect("b pulls r");
    let reply = osis_proto::msg::PullReply { id, events, cursor: Some(vec![1; 8]), whole: false, more: false, report: false, trimmed: false, joins: Vec::new() };
    command(&mut net, b, &mut pr, Command::Peer(Box::new(osis_proto::Message::PullReply(Box::new(reply)))));
    // a tick forgets what no entry carries
    net.advance(1_000);
    let known = flood.iter().filter(|c| net.engine(b).header(c).is_some()).count();
    let stored: usize = osis_store::Backend::scan(&net.nodes[b].backend, &[], None, usize::MAX).unwrap().iter().map(|(k, v)| k.len() + v.len()).sum();
    // a's next write, on a's own session
    net.write(a, t, "after");
    let acts = net.sync(a).handle(Event::Local);
    net.actions(a, acts);
    let events: Vec<_> = a_events(&mut net).into_iter().filter(|(_, e)| matches!(e, osis_proto::Event::Added { blob_id, .. } if net.engine(b).blob(blob_id).ok().flatten().is_none())).collect();
    let st = osis_proto::msg::Stream { events, cursor: Some(vec![2; 8]), report: false };
    command(&mut net, b, &mut pa, Command::Peer(Box::new(osis_proto::Message::Stream(Box::new(st)))));
    let applied = net.read(b, t) == Some(s("after"));
    (known, stored, applied)
}

// spec/requirements.md (peer input never causes unbounded storage), spec/sync.md §5 (co-reader
// peer budgets), spec/permissions.md §6 (invalid deltas), security: a reader serving the label as
// a co-reader peer, no host between, streams genuine commits each invalid at the receiver
// (durable and ephemeral alike); what the receiver keeps of them (a header each, no body) counts
// against that peer's budget, so at n and at 10n it keeps the same bounded number, and another
// writer's commit still applies
#[test]
fn reader_flood_of_invalid_commits_bounded_spec_sync_5() {
    for memory in [false, true] {
        let (known, stored, ok) = reader_flood(40, memory);
        assert!(ok, "memory {memory}: a's write applies past the flood of 40");
        let (known10, stored10, ok) = reader_flood(400, memory);
        assert!(ok, "memory {memory}: a's write applies past the flood of 400");
        assert_eq!((known, known10), (0, 0), "memory {memory}: no header of the flood outlives its entries");
        // 360 more headers would add about 200 KB; the store's pages vary by a few KB
        assert!(stored10 <= stored + stored / 10, "memory {memory}: the store at 10n ({stored10} bytes) is the store at n ({stored})");
    }
}

// spec/sync.md §5, spec/permissions.md §3: a removed holder's node is not dialed (its old
// `reach.0` is held, it may not read now) and, once the label has a new step, opens nothing
// served.
// spec/sync.md §5 (co-reader peer)
#[test]
fn removed_holder_not_dialed_nor_served_spec_sync_5() {
    let (mut net, host, [a]) = hosted_nodes::<1>();
    let r = net.node(2, &[]);
    reach(&mut net, a, 0xa1);
    reach(&mut net, r, 0xb1);
    let g = net.group(a, &[(r, Role::Read)], &[host]);
    let t = net.item(a, g, g, "before");
    net.run();
    assert_eq!(net.read(r, t), Some(s("before")));
    assert!(net.sync(a).peers().contains_key(&[0xb1; 32]));
    let (ta, tr) = (net.tid(a), net.tid(r));
    let e = net.engine(a);
    let rec = recipients_of(e, &[(ta, Role::Admin)]);
    remove_holder(e, g, tr, &rec, 77);
    net.set_online(r, false);
    net.run();
    let la = net.label(a);
    assert!(net.host_path(host, &la).len() >= 2, "a registered a new step");
    assert!(!net.sync(a).peers().contains_key(&[0xb1; 32]), "not dialed");
    net.write(a, t, "after");
    net.set_online(r, true);
    net.advance(61_000);
    let served = net.sync(a).served_opened();
    assert!(!served.is_empty(), "r dialed a");
    assert!(served.values().all(|o| o.is_empty()), "served nothing");
    assert_eq!(net.read(r, t), Some(s("before")));
}

fn net_label(net: &mut Net, n: usize, g: osis_base::Tid) -> LabelId {
    net.engine(n).group_labels(&g).unwrap()[0].id
}

fn reach_ed(net: &mut Net, n: usize) -> [u8; 32] {
    let secret = net.sync(n).dialable_secret();
    let k = SigningSecret::from_seed(&secret).verifying_key().to_bytes();
    let acts = net.sync(n).publish_reach(k, vec![]).unwrap();
    net.actions(n, acts);
    k
}

fn dials(acts: &[Action]) -> Vec<Address> {
    acts.iter().filter_map(|x| if let Action::Dial { address, .. } = x { Some(address.clone()) } else { None }).collect()
}

const IP: &str = "192.168.7.7";

/// A LAN source at `ip`.
fn src(ip: &str) -> std::net::SocketAddr {
    (ip.parse::<std::net::IpAddr>().unwrap(), 47380).into()
}

// spec/sync.md §10: a LAN address is only a candidate; one whose connection fails before coming
// up is backed off without pausing the peer, which is reached by its `peer://` route at once,
// and a repeat of its announcement is not dialed while backed off.
#[test]
fn lan_candidate_failure_keeps_route_spec_sync_10() {
    let (mut net, [a, b]) = local_nodes::<2>();
    reach_ed(&mut net, a);
    let kb = reach_ed(&mut net, b);
    net.blocked_peers.insert((a, b));
    let g = net.group_at(a, &[(b, Role::Write)], vec![]);
    net.run();
    net.blocked_peers.clear();
    net.clock.advance(60_001);
    // b announces a key nobody listens with
    let ann = net.sync(b).lan_announcement([0x77; 32], 9).unwrap();
    let (hit, acts) = net.sync(a).lan_seen(&ann, src(IP));
    assert_eq!(hit, Some(kb));
    let bogus = Address { url: format!("peer://{IP}:9"), key: [0x77; 32] };
    assert_eq!(dials(&acts), vec![bogus.clone()]);
    net.actions(a, acts);
    net.settle(100_000);
    let t = net.item(a, g, g, "via peer route");
    net.run();
    assert_eq!(net.read(b, t), Some(s("via peer route")));
    let (_, acts) = net.sync(a).lan_seen(&ann, src(IP));
    assert!(dials(&acts).is_empty());
}

// spec/sync.md §10: a candidate that fails falls back to the most heard verified source (a
// rejoin's announcement from a second address that is not reachable, then the first again).
#[test]
fn lan_candidate_falls_back_to_most_heard_spec_sync_10() {
    let (mut net, [a, b]) = local_nodes::<2>();
    reach_ed(&mut net, a);
    reach_ed(&mut net, b);
    net.blocked_peers.insert((a, b));
    net.group_at(a, &[(b, Role::Write)], vec![]);
    net.run();
    let lk = SigningSecret::from_seed(&net.sync(b).lan_secret()).verifying_key().to_bytes();
    net.lan_keys.insert(lk, b);
    let ann = net.sync(b).lan_announcement(lk, 5000).unwrap();
    // the peer:// route failed (paused): the first real announcement cuts the pause and is
    // dialed; repeats and the second address meanwhile dial nothing
    net.clock.advance(60_001);
    net.feed(a, Event::Tick);
    net.settle(100_000);
    let real = IP;
    let spoof = "192.168.7.66";
    let lk2 = [0x55; 32];
    let ann2 = net.sync(b).lan_announcement(lk2, 5000).unwrap();
    let (_, first) = net.sync(a).lan_seen(&ann, src(real));
    let real_addr = Address { url: format!("peer://{real}:5000"), key: lk };
    assert_eq!(dials(&first), vec![real_addr.clone()]);
    for _ in 0..2 {
        assert!(dials(&net.sync(a).lan_seen(&ann, src(real)).1).is_empty());
    }
    net.clock.advance(osis_node::sync::peers::LAN_CHANGE_MS);
    assert!(dials(&net.sync(a).lan_seen(&ann2, src(spoof)).1).is_empty());
    // that first dial got nowhere; the second candidate is dialed after the pause and fails:
    // the first one takes over
    let conn = first.iter().find_map(|x| if let Action::Dial { conn, .. } = x { Some(*conn) } else { None }).unwrap();
    net.sync(a).handle(Event::Down { conn });
    let spoofed = Address { url: format!("peer://{spoof}:5000"), key: lk2 };
    net.blocked_peers.clear();
    net.clock.advance(61_000);
    let acts = net.sync(a).handle(Event::Tick);
    assert_eq!(dials(&acts), vec![spoofed.clone()]);
    let conn = acts.iter().find_map(|x| if let Action::Dial { conn, .. } = x { Some(*conn) } else { None }).unwrap();
    let acts = net.sync(a).handle(Event::Down { conn });
    assert_eq!(dials(&acts), vec![real_addr]);
}

// spec/sync.md §10: a connection through a LAN address that comes up proves the route (the
// signature bound the key to the node): it is dialed first from then on; a newer candidate
// does not displace a running connection.
#[test]
fn lan_route_proven_by_up_spec_sync_10() {
    let (mut net, [a, b]) = local_nodes::<2>();
    reach_ed(&mut net, a);
    reach_ed(&mut net, b);
    net.blocked_peers.insert((a, b));
    let g = net.group_at(a, &[(b, Role::Write)], vec![]);
    net.run();
    net.blocked_peers.clear();
    net.clock.advance(60_001);
    // b listens on the LAN with a fresh key
    let lk = SigningSecret::from_seed(&net.sync(b).lan_secret()).verifying_key().to_bytes();
    net.lan_keys.insert(lk, b);
    let ann = net.sync(b).lan_announcement(lk, 5000).unwrap();
    let (_, acts) = net.sync(a).lan_seen(&ann, src(IP));
    let route = Address { url: format!("peer://{IP}:5000"), key: lk };
    assert_eq!(dials(&acts), vec![route.clone()]);
    net.actions(a, acts);
    net.settle(100_000);
    let t = net.item(a, g, g, "over the LAN");
    net.run();
    assert_eq!(net.read(b, t), Some(s("over the LAN")));
    // another address while connected: no dial
    let (_, acts) = net.sync(a).lan_seen(&ann, src("192.168.7.8"));
    assert!(dials(&acts).is_empty(), "{acts:?}");
    // the connection drops: after the pause the proven route is dialed, not the candidate
    net.set_online(b, false);
    net.set_online(b, true);
    net.advance(61_000);
    let acts = net.sync(a).handle(Event::Tick);
    assert!(dials(&acts).iter().all(|d| *d != Address { url: "peer://192.168.7.8:5000".into(), key: lk }), "{acts:?}");
}

// spec/sync.md §10 (Shared set): what a session serves is its shared set's, and once the proved
// node is removed from the group its member closes (issues/net-shared-set.md, Opens)
#[test]
fn a_member_closes_with_the_right_spec_sync_10() {
    let (mut net, [a, b]) = local_nodes::<2>();
    reach_ed(&mut net, a);
    reach_ed(&mut net, b);
    let g = net.group_at(a, &[(b, Role::Read)], vec![]);
    net.run();
    let l: LabelId = net.label(a);
    let p = member_session(&mut net, a, b, l);
    assert!(net.sync(a).served_opened()[&p.conn].contains(&l));
    // b removed from g
    let (ta, tb) = (net.tid(a), net.tid(b));
    let e = net.engine(a);
    let rec = recipients_of(e, &[(ta, Role::Admin)]);
    remove_holder(e, g, tb, &rec, 79);
    let acts = net.sync(a).handle(Event::Local);
    net.actions(a, acts);
    assert_eq!(net.sync(a).shared_members(p.conn), std::collections::BTreeSet::new(), "the member closed");
    assert!(net.sync(a).served_opened()[&p.conn].is_empty(), "serves nothing");
}

// spec: none (notes/api.md Sync configuration and status): sources count per proven source
// (`pass_source`); a served session with none is its own source, never caught up, so it cannot
// make the count read caught up.
#[test]
fn a_session_of_a_node_not_dialed_is_a_source_not_caught_up() {
    let (mut net, [a, b, c]) = local_nodes::<3>();
    for n in [a, b, c] {
        reach_ed(&mut net, n);
    }
    let g = net.group_at(a, &[(b, Role::Read), (c, Role::Read)], vec![]);
    net.run();
    net.set_online(c, false);
    net.run();
    let status = |net: &mut Net| net.sync(a).label_status().into_iter().find(|s| s.group == g).unwrap();
    let before = status(&mut net);
    assert_eq!(before.idle, before.sources, "caught up with the connection it dialed: {before:?}");
    let l: LabelId = net.label(a);
    let _p = member_session(&mut net, a, c, l);
    let after = status(&mut net);
    assert_eq!(after.sources, before.sources + 1, "its own source: {after:?}");
    assert_eq!(after.idle, before.idle, "not caught up: {after:?}");
}

// spec/permissions.md §3: a complete pass also waits for every co-reader the node received the
// label from and can reach: with that peer's replies held back, the host's pass alone is not
// enough; a node that is no co-reader is never waited for. `a` never stops waiting for peers, so
// only b's own passes complete it.
#[test]
fn complete_pass_counts_peers_spec_permissions_3() {
    let mut net = Net::new();
    let host = net.add_host();
    let cfg = SyncConfig { hosts: vec![net.address(host)], peer_pass_wait_ms: u64::MAX, ..SyncConfig::default() };
    let a = net.add_node(1, cfg);
    let b = net.node(2, &[host]);
    let c = net.node(3, &[host]);
    let x = net.node(4, &[host]);
    reach_ed(&mut net, a);
    reach_ed(&mut net, b);
    reach_ed(&mut net, x);
    let g = net.group(a, &[(b, Role::Admin), (c, Role::Read)], &[host]);
    net.item(b, g, g, "from b");
    net.run();
    assert!(net.sync(a).complete_pass(&g));
    // x shares nothing with a: its replies held back change nothing
    net.held.insert((x, a));
    net.held.insert((b, a));
    let (tb, tc) = (net.tid(b), net.tid(c));
    let e = net.engine(b);
    let rec = recipients_of(e, &[(tb, Role::Admin)]);
    remove_holder(e, g, tc, &rec, 78);
    net.run();
    assert!(!net.sync(a).complete_pass(&g), "b's pass is held back");
    net.release();
    // b's rotation boxed only b: its re-seal of a comes by a's inbox over b's link once released,
    // a role change after a's last pass at the host, which a then asks the host for
    net.run();
    assert!(net.sync(a).complete_pass(&g));
}

// spec/permissions.md §3: a co-reader removed from G while still sharing another label with the
// node no longer holds G's complete pass, even with its replies held back; nor does one that
// stays silent past `peer_pass_wait_ms`.
#[test]
fn complete_pass_drops_removed_coreader_spec_permissions_3() {
    let (mut net, host, [a, x, b]) = hosted_nodes::<3>();
    reach_ed(&mut net, a);
    reach_ed(&mut net, x);
    let g = net.group(a, &[(x, Role::Write), (b, Role::Read)], &[host]);
    let g2 = net.group_seeded(a, &[(x, Role::Read)], vec![net.address(host)], 2);
    net.item(x, g, g, "from x");
    net.run();
    assert!(net.sync(a).complete_pass(&g) && net.sync(a).complete_pass(&g2));
    net.held.insert((x, a));
    let (ta, tx) = (net.tid(a), net.tid(x));
    let e = net.engine(a);
    let rec = recipients_of(e, &[(ta, Role::Admin)]);
    remove_holder(e, g, tx, &rec, 81);
    // a role change of g from elsewhere: b's grant
    let tb = net.tid(b);
    net.grant(a, g, tb, Role::Write);
    net.run();
    assert!(net.sync(a).peers().get(&net.sync(x).own_reach().unwrap().dialable).is_some_and(|p| !p.labels.contains(&net_label(&mut net, a, g))), "x still shares g2 only");
    assert!(net.sync(a).complete_pass(&g), "x no longer counts for g");
}

// spec/permissions.md §4: `reach.0` goes under every label: two nodes of other accounts sharing
// a group at a host learn each other's dialable key there and dial each other.
#[test]
fn reach_under_every_label_spec_permissions_4() {
    let (mut net, host, [a, b]) = hosted_nodes::<2>();
    net.group(a, &[(b, Role::Read)], &[host]);
    let ka = reach_ed(&mut net, a);
    let kb = reach_ed(&mut net, b);
    net.run();
    assert!(net.sync(b).peers().contains_key(&ka));
    assert!(net.sync(a).peers().contains_key(&kb));
}

// spec/sync.md §5: co-readers dialed per label are capped.
#[test]
fn co_readers_capped_spec_sync_5() {
    let mut net = Net::new();
    let cfg = SyncConfig { max_peers_per_label: 1, ..SyncConfig::default() };
    let a = net.add_node(1, cfg);
    let b = net.node(2, &[]);
    let c = net.node(3, &[]);
    reach(&mut net, a, 0xa1);
    reach(&mut net, b, 0xb1);
    reach(&mut net, c, 0xc1);
    net.group_at(a, &[(b, Role::Read), (c, Role::Read)], vec![]);
    assert_eq!(net.sync(a).peers().len(), 1);
}
