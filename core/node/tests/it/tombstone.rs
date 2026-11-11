#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Lasting tombstones (spec/commits.md §5, spec/sync.md §6): a purged permanent delta keeps its
//! header for good, at the label and at a new node; every other retention leaves none.

use crate::common::LIST;
use crate::net;
use net::*;
use osis_base::format::ROLE_KEEP_MS;
use osis_base::{Ak, CommitId, LabelId, Role, Tid};
use osis_commit::{FOREVER, PurgeItem};
use osis_node::Mutation;
use osis_node::sync::EntryKind;
use osis_schema::{RawKey, History, PurgeBy, Retention};

/// A message's retention: by its author or admins (`kept_item` keeps it for good: permanent).
fn permanent() -> Retention {
    Retention { by: PurgeBy::AuthorOrAdmin }
}

/// `net.item`, its register kept for good (its writes permanent), `GONE` (where purge requests
/// write their own value) purged on replace.
fn kept_item(net: &mut Net, n: usize, g: Tid, admin: Tid, v: &str) -> Tid {
    let t = net.item(n, g, admin, v);
    net.keep(n, t, &[(REG.ak(), History::FOREVER), (GONE.ak(), History::PurgeOnReplace)]);
    t
}

/// The messages' aspect.
fn k() -> Ak {
    Ak::new(REG.ak()).unwrap()
}

/// Where a purge request writes its own value (`purge`): purged on replace.
fn own() -> Ak {
    Ak::new(GONE.ak()).unwrap()
}

/// Node `n` writes `v` on `own()`: it replaces a purge request's own delta there.
fn write_own(net: &mut Net, n: usize, t: Tid, v: &str) {
    let mut m = Mutation::new();
    m.set(t, &GONE, &s(v)).unwrap();
    net.engine(n).commit(m).unwrap();
}

fn msg(net: &mut Net, n: usize, t: Tid, v: &str, r: Retention) -> CommitId {
    let mut m = Mutation::new();
    m.retention(t, &REG, r).unwrap();
    m.set(t, &REG, &s(v)).unwrap();
    net.engine(n).commit(m).unwrap().unwrap()
}

/// A purge of `c`'s message, its own delta on `own()` under `r`.
fn purge(net: &mut Net, n: usize, t: Tid, c: CommitId, r: Retention) -> CommitId {
    purge_on(net, n, t, c, k(), r)
}

/// A purge of `c`'s part on `ak`, its own delta on `own()` under `r`.
fn purge_on(net: &mut Net, n: usize, t: Tid, c: CommitId, ak: Ak, r: Retention) -> CommitId {
    let mut m = Mutation::new();
    m.purge(PurgeItem::Commit { commit: c, tid: t, ak });
    m.retention(t, &GONE, r).unwrap();
    // a value of its own: writing the same value again is no write
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    m.set(t, &GONE, &s(&format!("after {}", N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)))).unwrap();
    // past the writer's own refusal of a request without the right: the receivers judge it
    net.engine(n).commit_hostile(m).unwrap().unwrap()
}

/// The delta sets of commit `c`'s entries node `n` knows present at `host`.
fn at_host(net: &mut Net, n: usize, host: usize, l: &LabelId, c: CommitId) -> Vec<Vec<usize>> {
    let ids = net.host_ids(host, l);
    net.sync(n)
        .entries(l)
        .into_iter()
        .filter(|(id, _)| ids.contains(id))
        .filter_map(|(_, e)| match e {
            EntryKind::Commit { commit, parts, .. } if commit == c => Some(parts),
            _ => None,
        })
        .collect()
}

/// Admin `a`, writer `b`, reader `n` kept offline from the start: a new node once it comes up.
struct Chat {
    net: Net,
    host: usize,
    a: usize,
    b: usize,
    n: usize,
    t: Tid,
    l: LabelId,
}

fn chat() -> Chat {
    let mut net = Net::new();
    let host = net.add_host();
    let (a, b, n) = (net.node(1, &[host]), net.node(2, &[host]), net.node(3, &[host]));
    let g = net.group(a, &[(b, Role::Write), (n, Role::Read)], &[host]);
    net.set_online(n, false);
    let t = kept_item(&mut net, a, g, g, "x");
    net.run();
    let l = net.label(a);
    Chat { net, host, a, b, n, t, l }
}

/// New node `n` sees `c` as a tombstone: applied, no body, the purge named, author and time
/// from the header, valid, none of the value left; alike after a restart.
fn sees_tombstone(net: &mut Net, n: usize, t: Tid, c: CommitId, p: CommitId, author: Tid) {
    for round in 0..2 {
        let e = net.engine(n);
        assert!(e.commit_ids().contains(&c), "round {round}: the tombstone is not applied");
        assert!(!e.body_not_dropped(&c, &t, &k()), "round {round}: its body is held");
        assert_eq!(e.purged_on(&t, &k()).unwrap().get(&c), Some(&p), "round {round}: its purge");
        let h = e.header(&c).unwrap();
        assert_eq!((h.author, h.actor), (author, author));
        assert!(e.held_commits(Some(&[(t, k())])).iter().any(|x| x.id == c && x.aspects.iter().any(|a| a.1 == k() && !a.2)), "round {round}: reads as held without its body");
        assert_ne!(e.get(&t, &k()).unwrap(), Some(s("SECRET")), "round {round}");
        net.restart(n, 900 + round);
        net.run();
    }
}

// spec/commits.md §5, spec/sync.md §6: a purged permanent delta stays under the label as its header
// alone, whatever the purge commit's own retention, and a new node applies it, seeing who wrote
// it and when; the body is gone from the host.
#[test]
fn new_node_sees_a_purged_permanent_delta_spec_commits_5() {
    for r in [Retention::default(), Retention { by: PurgeBy::Writer }] {
        let Chat { mut net, host, a, b, n, t, l } = chat();
        let c = msg(&mut net, b, t, "SECRET", permanent());
        net.run();
        let body = at_host(&mut net, a, host, &l, c);
        assert!(body.iter().all(|x| !x.is_empty()) && !body.is_empty());
        let p = purge(&mut net, b, t, c, r);
        net.run();
        assert_eq!(at_host(&mut net, a, host, &l, c), vec![Vec::<usize>::new()], "its header alone at the host");
        net.set_online(n, true);
        net.run();
        let author = net.tid(b);
        sees_tombstone(&mut net, n, t, c, p, author);
        // and the holders still agree
        for x in [a, b] {
            assert_eq!(net.engine(x).purged_on(&t, &k()).unwrap().get(&c), Some(&p));
        }
    }
}

// spec/commits.md §5, spec/wire.md §4: the same for a request by author carrying no write on the
// aspect, only `purge.0`: a new node applies each purged delta, reads the entry as a tombstone in
// the history, and the writer's other message stays.
#[test]
fn new_node_sees_a_purge_by_author_spec_commits_5() {
    use osis_node::engine::listing::{CommitFrom, PartBody};
    let Chat { mut net, a, b, n, t, .. } = chat();
    let c = msg(&mut net, b, t, "SECRET", permanent());
    let other = msg(&mut net, a, t, "kept", permanent());
    net.run();
    let author = net.tid(b);
    let mut m = Mutation::new();
    let now = net.engine(a).now();
    m.set(t, &osis_schema::core_types::PURGE, &now).unwrap();
    m.purge(PurgeItem::Author { tid: t, ak: k(), actor: author });
    let p = net.engine(a).commit(m).unwrap().unwrap();
    net.run();
    net.set_online(n, true);
    net.run();
    sees_tombstone(&mut net, n, t, c, p, author);
    let (rows, _) = net.engine(n).held_parts(&t, &k(), CommitFrom::Oldest, 9, usize::MAX).unwrap();
    let of = |x: CommitId| rows.iter().find(|r| r.id == x).unwrap();
    assert_eq!((of(c).actor, of(c).body.clone()), (author, PartBody::Purged(p)));
    assert_eq!(of(other).body, PartBody::Held(Some(s("kept"))));
}

// spec/commits.md §5: lost at the host, a holder uploads the header-only blob again, as any
// must-hold body; a new node fetches it from there.
#[test]
fn a_lost_tombstone_is_uploaded_again_spec_sync_6() {
    let Chat { mut net, host, a, b, n, t, l } = chat();
    let c = msg(&mut net, b, t, "SECRET", permanent());
    net.run();
    let p = purge(&mut net, b, t, c, permanent());
    net.run();
    net.set_online(a, false);
    net.wipe_host(host);
    net.set_online(a, true);
    net.run();
    net.advance(120_000);
    net.run();
    assert_eq!(at_host(&mut net, a, host, &l, c), vec![Vec::<usize>::new()]);
    net.set_online(n, true);
    net.run();
    let author = net.tid(b);
    sees_tombstone(&mut net, n, t, c, p, author);
}

// spec/commits.md §5: under every other setting a purge leaves no lasting tombstone: nothing of
// the commit stays at the host, and a new node never learns of it.
#[test]
fn other_retention_leaves_none_spec_commits_5() {
    let keep = |until, after| Some(History::Keep { until, after });
    let cases = [("no history", None), ("kept a while after replaced", keep(None, Some(1000))), ("kept until a finite time", keep(Some(FOREVER - 1), None)), ("purged on replace", Some(History::PurgeOnReplace))];
    for (what, h) in cases {
        let Chat { mut net, host, a, b, n, t, l } = chat();
        net.keep(a, t, &h.map(|h| vec![(REG.ak(), h)]).unwrap_or_default());
        net.run();
        let c = msg(&mut net, b, t, "SECRET", Retention::default());
        net.run();
        purge(&mut net, b, t, c, Retention::default());
        net.run();
        assert!(at_host(&mut net, a, host, &l, c).is_empty(), "{what}: left at the host");
        net.set_online(n, true);
        net.run();
        assert!(!net.engine(n).commit_ids().contains(&c), "{what}: reached a new node");
    }
}

// spec/commits.md §5, §6: an expired write is not permanent, whatever its keep at least: expiry
// leaves no header at the host and none at a new node, as before.
#[test]
fn expired_write_leaves_none_spec_commits_6() {
    let Chat { mut net, host, a, b, n, t, l } = chat();
    let mut m = Mutation::new();
    m.retention(t, &REG, permanent()).unwrap();
    let at = osis_base::WallMs(net.engine(b).now().0 + 60_000);
    m.set(t, &REG, &s("SECRET")).unwrap();
    m.expires(t, &REG, at).unwrap();
    let c = net.engine(b).commit(m).unwrap().unwrap();
    let h = net.engine(b).header(&c).unwrap();
    assert!(!h.aspects.iter().any(|x| net.engine(b).permanent(&h, x)));
    net.run();
    assert!(!at_host(&mut net, a, host, &l, c).is_empty());
    net.advance(120_000);
    net.run();
    assert!(at_host(&mut net, a, host, &l, c).is_empty());
    net.set_online(n, true);
    net.run();
    assert!(!net.engine(n).commit_ids().contains(&c));
}

// spec/commits.md §5: the purge commit stays too, as its header once its own body goes (past its
// `ROLE_KEEP` floor, covered): a new node counts the purged delta as held only by the request.
#[test]
fn the_purge_request_stays_as_its_header_spec_commits_5() {
    let Chat { mut net, host, a, b, n, t, l } = chat();
    let c = msg(&mut net, b, t, "SECRET", permanent());
    net.run();
    let p = purge(&mut net, a, t, c, Retention::default());
    net.run();
    assert!(at_host(&mut net, a, host, &l, p).iter().all(|x| !x.is_empty()));
    // past its floor, a later write covering the purge commit's own delta
    cover(&mut net, a, t);
    net.write(a, t, "later");
    net.run();
    assert!(!net.engine(a).body_not_dropped(&p, &t, &own()), "the purge commit's body is covered and gone");
    assert_eq!(at_host(&mut net, a, host, &l, p), vec![Vec::<usize>::new()], "its header stays");
    assert_eq!(at_host(&mut net, a, host, &l, c), vec![Vec::<usize>::new()]);
    net.set_online(n, true);
    net.run();
    let author = net.tid(b);
    sees_tombstone(&mut net, n, t, c, p, author);
    assert_eq!(net.read(n, t), Some(s("later")));
}

// spec/commits.md §5: a purge commit naming no permanent delta is not kept: past its floor and
// covered, nothing of it stays at the host.
#[test]
fn a_purge_of_other_retention_goes_spec_commits_5() {
    let Chat { mut net, host, a, b, t, l, .. } = chat();
    // messages kept no more
    net.keep(a, t, &[(GONE.ak(), History::PurgeOnReplace)]);
    net.run();
    let c = msg(&mut net, b, t, "SECRET", Retention::default());
    net.run();
    let p = purge(&mut net, a, t, c, Retention::default());
    net.run();
    cover(&mut net, a, t);
    assert!(at_host(&mut net, a, host, &l, p).is_empty());
}

// spec/commits.md §5: purge of a commit with other live parts: the blob of those parts carries the
// header, so no header-only blob goes up beside it; once they go too, the header alone stays.
#[test]
fn other_live_parts_carry_the_header_spec_commits_5() {
    let Chat { mut net, host, a, b, n, t, l } = chat();
    let mut m = Mutation::new();
    m.retention(t, &REG, permanent()).unwrap();
    m.set(t, &REG, &s("SECRET")).unwrap();
    m.set(t, &LIST, &osis_base::Value::List(vec![s("other")])).unwrap();
    let c = net.engine(b).commit(m).unwrap().unwrap();
    net.run();
    let p = purge(&mut net, a, t, c, permanent());
    net.run();
    let h = net.engine(a).header(&c).unwrap();
    let held = at_host(&mut net, a, host, &l, c);
    assert_eq!(held.len(), 1, "{held:?}");
    assert_eq!(h.aspects[held[0][0]].ak, Ak::new(LIST.ak()).unwrap());
    net.set_online(n, true);
    net.run();
    assert_eq!(net.engine(n).get(&t, &Ak::new(LIST.ak()).unwrap()).unwrap(), Some(osis_base::Value::List(vec![s("other")])));
    assert_eq!(net.engine(n).purged_on(&t, &k()).unwrap().get(&c), Some(&p));
    // its other part purged too (`Aspect` purge of that aspect): the header alone
    let mut m = Mutation::new();
    m.purge(PurgeItem::Aspect { tid: t, ak: Ak::new(LIST.ak()).unwrap() });
    m.set(t, &LIST, &osis_base::Value::List(Vec::new())).unwrap();
    net.engine(a).commit(m).unwrap().unwrap();
    net.run();
    assert_eq!(at_host(&mut net, a, host, &l, c), vec![Vec::<usize>::new()]);
    net.advance(1_000);
    net.run();
    assert!(net.engine(n).commit_ids().contains(&c));
}

// spec/commits.md §4: a header-only blob of a commit whose other part is on a thing the node does
// not sync does not wait for that part: the permanent delta on a thing it syncs stands for it.
#[test]
fn the_other_part_on_another_label_is_not_waited_for_spec_commits_4() {
    let Chat { mut net, host, a, b, n, t, l } = chat();
    let addrs = vec![net.hosts[host].address.clone()];
    let g2 = net.group_seeded(a, &[(b, Role::Write)], addrs, 2);
    let u = kept_item(&mut net, a, g2, g2, "y");
    net.run();
    let mut m = Mutation::new();
    m.retention(t, &REG, permanent()).unwrap();
    m.set(t, &REG, &s("SECRET")).unwrap();
    m.set(u, &LIST, &osis_base::Value::List(vec![s("elsewhere")])).unwrap();
    let c = net.engine(b).commit(m).unwrap().unwrap();
    net.run();
    let p = purge(&mut net, a, t, c, permanent());
    net.run();
    assert_eq!(at_host(&mut net, a, host, &l, c), vec![Vec::<usize>::new()], "under the purged delta's label");
    net.set_online(n, true);
    net.run();
    let author = net.tid(b);
    sees_tombstone(&mut net, n, t, c, p, author);
    assert!(net.engine(n).get(&u, &Ak::new(LIST.ak()).unwrap()).is_err() || net.engine(n).get(&u, &Ak::new(LIST.ak()).unwrap()).unwrap().is_none());
}

// spec/commits.md §5, notes/growth.md: a hostile author naming its own message again and again costs
// a header per commit it wrote: at most one lasting blob per commit.
#[test]
fn a_flood_costs_a_header_per_write_spec_commits_5() {
    let Chat { mut net, host, a, b, t, l, .. } = chat();
    let c = msg(&mut net, b, t, "SECRET", permanent());
    net.run();
    let ps: Vec<CommitId> = (0..8).map(|_| purge(&mut net, b, t, c, Retention::default())).collect();
    net.run();
    net.advance(1_000);
    net.run();
    assert_eq!(at_host(&mut net, a, host, &l, c), vec![Vec::<usize>::new()]);
    for p in ps {
        assert_eq!(at_host(&mut net, a, host, &l, p).len(), 1);
    }
}

// spec/commits.md §5: a commit naming a permanent delta it may not purge earns nothing: its request
// is no witness, and the delta stays.
#[test]
fn a_purge_without_the_right_is_no_witness_spec_commits_5() {
    let Chat { mut net, host, a, b, t, l, .. } = chat();
    let c = msg(&mut net, a, t, "SECRET", Retention { by: PurgeBy::Admin });
    net.run();
    let p = purge(&mut net, b, t, c, Retention::default());
    net.run();
    assert!(net.engine(a).body_not_dropped(&c, &t, &k()));
    cover(&mut net, a, t);
    assert!(at_host(&mut net, a, host, &l, p).is_empty(), "no lasting blob of the purge without the right");
    assert_eq!(at_host(&mut net, a, host, &l, c).len(), 1);
    assert!(!at_host(&mut net, a, host, &l, c)[0].is_empty());
}

/// The compaction snapshots of `(t, k())` node `x` holds.
fn snapshots(net: &mut Net, x: usize, t: Tid) -> Vec<CommitId> {
    let e = net.engine(x);
    e.commit_ids().into_iter().filter(|c| e.header(c).is_some_and(|h| h.kind.is_compaction() && h.aspects.iter().any(|a| a.tid == t && a.ak == k())) && e.body_not_dropped(c, &t, &k())).collect()
}

// spec/commits.md §5 Purge: a refused request drops nothing, so no writer re-snapshots for it.
#[test]
fn a_refused_purge_writes_no_snapshot_spec_commits_5() {
    let Chat { mut net, a, b, t, .. } = chat();
    let c = msg(&mut net, a, t, "SECRET", Retention { by: PurgeBy::Admin });
    net.run();
    let before = [snapshots(&mut net, a, t), snapshots(&mut net, b, t)];
    purge(&mut net, b, t, c, Retention::default());
    net.run();
    assert_eq!([snapshots(&mut net, a, t), snapshots(&mut net, b, t)], before, "a snapshot for a refused purge");
    assert!(net.engine(a).body_not_dropped(&c, &t, &k()) && net.engine(b).body_not_dropped(&c, &t, &k()));
}

// spec/commits.md §5 Covered: a live body is the state, so a snapshot covering it drops nothing
// at any node, and it lists as held with its value.
#[test]
fn a_live_body_survives_a_covering_snapshot_spec_commits_5() {
    use osis_node::engine::listing::{CommitFrom, PartBody};
    let Chat { mut net, a, b, t, .. } = chat();
    let c = msg(&mut net, b, t, "live", permanent());
    net.run();
    net.advance(ROLE_KEEP_MS + 3_600_000);
    let acts = net.sync(a).compact(&t, &k()).unwrap();
    net.actions(a, acts);
    net.run();
    net.advance(3_600_000);
    net.run();
    for x in [a, b] {
        let snaps = snapshots(&mut net, x, t);
        assert!(snaps.iter().any(|s| net.engine(x).covered(s, &c, &t, &k()).unwrap() == Some(true)), "node {x}: a snapshot covers it");
        assert!(net.engine(x).body_not_dropped(&c, &t, &k()), "node {x}: a live body dropped");
        let (rows, _) = net.engine(x).held_parts(&t, &k(), CommitFrom::Oldest, 9, usize::MAX).unwrap();
        assert_eq!(rows.iter().find(|r| r.id == c).unwrap().body, PartBody::Held(Some(s("live"))));
    }
}

// spec/commits.md §5: a purged large value's chunks leave the host as any purge's; its header stays.
#[test]
fn a_purged_value_leaves_its_chunks_spec_commits_5() {
    let Chat { mut net, host, a, b, n, t, l } = chat();
    let big: String = (0..300_000u32).map(|i| char::from(b'a' + (i.wrapping_mul(2654435761) >> 27) as u8 % 26)).collect();
    let c = msg(&mut net, b, t, &big, permanent());
    net.run();
    let chunks: Vec<osis_base::BlobId> = net.engine(a).header(&c).unwrap().chunks.iter().map(|ch| ch.blob).collect();
    assert!(!chunks.is_empty() && chunks.iter().all(|id| net.host_ids(host, &l).contains(id)));
    let p = purge(&mut net, a, t, c, permanent());
    net.run();
    net.run();
    assert!(chunks.iter().all(|id| !net.host_ids(host, &l).contains(id)), "a purged chunk stayed");
    assert_eq!(at_host(&mut net, a, host, &l, c), vec![Vec::<usize>::new()]);
    net.set_online(n, true);
    net.run();
    let author = net.tid(b);
    sees_tombstone(&mut net, n, t, c, p, author);
    assert!(chunks.iter().all(|id| !net.engine(n).has_blob(id)));
}

// spec/commits.md §5: the purge shown is the earliest whose author may purge: a request without the
// right, earlier, names nothing.
#[test]
fn the_purge_shown_is_one_with_the_right_spec_commits_5() {
    let Chat { mut net, a, b, t, .. } = chat();
    let c = msg(&mut net, a, t, "SECRET", Retention { by: PurgeBy::Admin });
    net.run();
    purge(&mut net, b, t, c, Retention::default());
    net.run();
    net.advance(1_000);
    let p = purge(&mut net, a, t, c, Retention::default());
    net.run();
    net.advance(1_000);
    purge(&mut net, a, t, c, Retention::default());
    net.run();
    for x in [a, b] {
        assert_eq!(net.engine(x).purged_on(&t, &k()).unwrap().get(&c), Some(&p), "at {x}");
    }
}

// spec/permissions.md §5.1: a kick lists a purged delta (it was not dropped as covered), so the
// tombstone of a removed writer's message stays valid at a new node holding the removal.
#[test]
fn a_kicked_writers_tombstone_stays_spec_perm_5_1() {
    let Chat { mut net, host, a, b, n, t, l } = chat();
    let c = msg(&mut net, b, t, "SECRET", permanent());
    net.run();
    let p = purge(&mut net, a, t, c, permanent());
    net.run();
    assert_eq!(net.engine(b).named_permanent_count().unwrap(), 1);
    let g = net.group_labels(a).into_iter().find(|x| x.1.id == l).unwrap().0;
    let holder = net.tid(b);
    let d = osis_node::flows::Demotion { holder, new: None, retain: None };
    let done = net.engine(a).demote(&g, &d).unwrap();
    let acts = net.sync(a).carry_out(done).unwrap();
    net.actions(a, acts);
    net.run();
    assert_eq!(at_host(&mut net, a, host, &l, c), vec![Vec::<usize>::new()]);
    // what `b` forgets, the note of what the purge dropped goes with
    net.engine(b).drop_lost_due().unwrap();
    assert_eq!(net.engine(b).named_permanent_count().unwrap(), 0);
    net.set_online(n, true);
    net.run();
    sees_tombstone(&mut net, n, t, c, p, holder);
}

// spec/sync.md §1: a header-only blob's prefix carries no expiry and no commitment: any other is bad
// input, so a writer cannot set a tombstone to expire at the host.
#[test]
fn header_only_prefix_is_checked_spec_sync_1() {
    let Chat { mut net, b, t, .. } = chat();
    let c = msg(&mut net, b, t, "y", permanent());
    let pk = net.engine(b).package(&c).unwrap().unwrap();
    let blob = osis_commit::CommitBlob::decode(&pk.bytes).unwrap();
    let bare = osis_commit::rewrite(&blob, |_| true);
    let mut rng = osis_crypto::SeededRng::from_u64(5);
    let read = net.engine(b).wrap_secret(&t, None).unwrap().unwrap();
    let env = osis_commit::seal_commit(&bare, |_| (), |_, _| Some((read.clone(), vec![])), &[], &mut rng).unwrap();
    let frame = |expires: Option<u64>, rng: &mut osis_crypto::SeededRng| {
        let prefix = osis_label::Prefix::new(osis_label::Prefix::random_salt(rng), expires.map(osis_base::WallMs), vec![]).unwrap();
        osis_label::frame(&prefix, &env.encode(), rng).unwrap()
    };
    let (key, good) = frame(None, &mut rng);
    assert!(net.engine(b).open_commit(&good, &key, None).is_ok());
    let (key, bad) = frame(Some(FOREVER), &mut rng);
    assert!(net.engine(b).open_commit(&bad, &key, None).is_err());
}

fn pending(net: &mut Net, n: usize) -> usize {
    net.engine(n).pending().len()
}

fn bare_header(net: &mut Net, from: usize, c: &CommitId) -> Vec<u8> {
    let pk = net.engine(from).package(c).unwrap().unwrap();
    osis_commit::rewrite(&osis_commit::CommitBlob::decode(&pk.bytes).unwrap(), |_| true).encode()
}

// spec/commits.md §4, §5: a writer forging a header-only blob of another's message, alone or with a
// request it has no right to make, hides nothing: the commit applies as its header, no purge shows,
// and the body joins once it comes.
#[test]
fn a_forged_header_only_blob_is_no_tombstone_spec_commits_5() {
    let mut net = Net::new();
    let host = net.add_host();
    let (a, b, n) = (net.node(1, &[host]), net.node(2, &[host]), net.node(3, &[host]));
    let g = net.group(a, &[(b, Role::Write), (n, Role::Read)], &[host]);
    let t = kept_item(&mut net, a, g, g, "x");
    net.run();
    net.set_online(n, false);
    let c = msg(&mut net, a, t, "SECRET", permanent());
    net.run();
    let bare = bare_header(&mut net, b, &c);
    net.engine(n).ingest(&bare, Vec::new()).unwrap();
    assert!(net.engine(n).commit_ids().contains(&c), "its header alone");
    let p = purge(&mut net, b, t, c, Retention::default());
    let pp = net.engine(b).package(&p).unwrap().unwrap();
    net.engine(n).ingest(&pp.bytes, pp.blobs.clone()).unwrap();
    assert!(net.engine(n).purged_on(&t, &k()).unwrap().is_empty(), "a request without the right");
    net.set_online(n, true);
    net.run();
    net.advance(120_000);
    net.run();
    assert!(net.engine(n).body_not_dropped(&c, &t, &k()));
    assert!(net.engine(n).purged_on(&t, &k()).unwrap().is_empty());
}

// spec/permissions.md §6, spec/commits.md §5: an admin's purge falls when its demotion stamped earlier
// arrives. Nodes that had dropped the body take it again from the holder that kept it, no purge is
// shown, and a new node reads the message; nobody deletes it again, no upload and delete for good.
#[test]
fn a_fallen_purge_shows_no_tombstone_spec_perm_6() {
    let mut net = Net::new();
    let host = net.add_host();
    let (a, b, c2, n) = (net.node(1, &[host]), net.node(2, &[host]), net.node(4, &[host]), net.node(3, &[host]));
    let g = net.group(a, &[(b, Role::Write), (c2, Role::Admin), (n, Role::Read)], &[host]);
    net.set_online(n, false);
    let t = kept_item(&mut net, a, g, g, "x");
    net.run();
    let m = msg(&mut net, b, t, "SECRET", permanent());
    net.run();
    net.set_online(a, false);
    let d = osis_node::flows::Demotion { holder: net.tid(c2), new: None, retain: None };
    let done = net.engine(a).demote(&g, &d).unwrap();
    net.advance(5_000);
    purge(&mut net, c2, t, m, Retention::default());
    net.run();
    assert!(net.engine(b).purged_on(&t, &k()).unwrap().contains_key(&m), "its right holds as far as b knows");
    net.set_online(a, true);
    let acts = net.sync(a).carry_out(done).unwrap();
    net.actions(a, acts);
    net.run();
    for x in [a, b, c2] {
        assert!(net.engine(x).purged_on(&t, &k()).unwrap().is_empty(), "at {x}");
    }
    // the request's lasting note stays where it dropped one; history shows no purge
    for x in [a, b] {
        let row = net.engine(x).held_part(&t, &k(), &m, usize::MAX).unwrap().unwrap();
        assert!(!matches!(row.body, osis_node::engine::listing::PartBody::Purged(_)), "at {x}: {:?}", row.body);
    }
    assert!(net.engine(b).named_permanent_count().unwrap() > 0, "a fallen request stays lasting there");
    assert!(net.engine(a).body_not_dropped(&m, &t, &k()));
    net.set_online(n, true);
    net.run();
    net.advance(120_000);
    net.run();
    assert!(net.engine(n).body_not_dropped(&m, &t, &k()));
    assert!(net.engine(n).purged_on(&t, &k()).unwrap().is_empty());
    let holds = |net: &mut Net, x: usize| net.engine(x).core.ix.commits.get(&m).is_some_and(|c| c.missing.is_empty() && c.dropped.is_empty());
    // not the demoted admin: it reads the label no more
    for x in [a, b, n] {
        assert!(holds(&mut net, x), "at {x}: the body is back");
    }
    let before = known_entries(&mut net, a, host);
    for _ in 0..6 {
        net.advance(120_000);
        net.run();
    }
    assert_eq!(known_entries(&mut net, a, host), before, "an upload and delete loop");
    for x in [a, b, n] {
        assert!(holds(&mut net, x), "at {x}: still");
    }
}

/// Admin `a`, writer `b`, reader `n` offline, and thing `u` of a second group: its label and hosts
/// are `a`'s and `b`'s, and `n` when `n_too`.
fn second_label(c: &mut Chat, n_too: bool) -> Tid {
    let addrs = vec![c.net.hosts[c.host].address.clone()];
    let holders: Vec<(usize, Role)> = if n_too { vec![(c.b, Role::Write), (c.n, Role::Read)] } else { vec![(c.b, Role::Write)] };
    let g2 = c.net.group_seeded(c.a, &holders, addrs, 2);
    let u = c.net.item(c.a, g2, g2, "y");
    c.net.run();
    u
}

// spec/commits.md §4, §5: a purge commit with a write on another label's thing too, its body under
// the purged message's label gone: a node on that label alone applies its header, or it would
// never count the message's delta as purged.
#[test]
fn a_purge_commit_does_not_wait_for_another_label_spec_commits_4() {
    let mut chat = chat();
    let u = second_label(&mut chat, false);
    let Chat { mut net, host, a, b, n, t, l } = chat;
    let c = msg(&mut net, b, t, "SECRET", permanent());
    net.run();
    let mut m = Mutation::new();
    m.purge(PurgeItem::Commit { commit: c, tid: t, ak: k() });
    m.set(t, &GONE, &s("after")).unwrap();
    m.set(u, &LIST, &osis_base::Value::List(vec![s("elsewhere")])).unwrap();
    let p = net.engine(a).commit(m).unwrap().unwrap();
    net.run();
    cover(&mut net, a, t);
    assert_eq!(at_host(&mut net, a, host, &l, p), vec![Vec::<usize>::new()]);
    net.set_online(n, true);
    net.run();
    assert_eq!(pending(&mut net, n), 0);
    let author = net.tid(b);
    sees_tombstone(&mut net, n, t, c, p, author);
}

// spec/commits.md §4: a lasting header applies alone: a message beside a part on a second thing the
// node syncs too, the message purged and the other part withheld, applies as its header and the
// other part joins when it comes.
#[test]
fn a_lasting_header_applies_and_the_rest_joins_spec_commits_4() {
    let mut chat = chat();
    let u = second_label(&mut chat, true);
    let Chat { mut net, a, b, n, t, .. } = chat;
    net.set_online(n, true);
    net.run();
    net.set_online(n, false);
    let mut m = Mutation::new();
    m.retention(t, &REG, permanent()).unwrap();
    m.set(t, &REG, &s("SECRET")).unwrap();
    m.set(u, &LIST, &osis_base::Value::List(vec![s("card")])).unwrap();
    let c = net.engine(b).commit(m).unwrap().unwrap();
    net.run();
    let p = purge(&mut net, a, t, c, Retention::default());
    net.run();
    let bare = bare_header(&mut net, a, &c);
    let pp = net.engine(a).package(&p).unwrap().unwrap();
    assert!(net.engine(n).core.syncs(&t) && net.engine(n).core.syncs(&u));
    net.engine(n).ingest(&pp.bytes, pp.blobs.clone()).unwrap();
    net.engine(n).ingest(&bare, Vec::new()).unwrap();
    assert!(net.engine(n).commit_ids().contains(&p));
    assert!(net.engine(n).commit_ids().contains(&c), "its header alone");
    assert_eq!(net.engine(n).get(&u, &Ak::new(LIST.ak()).unwrap()).unwrap(), None);
    net.set_online(n, true);
    net.run();
    net.advance(120_000);
    net.run();
    assert!(net.engine(n).commit_ids().contains(&c));
    assert_eq!(net.engine(n).get(&u, &Ak::new(LIST.ak()).unwrap()).unwrap(), Some(osis_base::Value::List(vec![s("card")])));
}

// spec/commits.md §4, §5: a purge commit's own delta purged in turn, gone by a purge on replace, with
// a snapshot or none: the request applies as its lasting header at a new node, so the
// tombstone shows there and nothing is shown wrongly.
#[test]
fn a_purge_purged_in_turn_spec_commits_5() {
    for snap in [true, false] {
        let Chat { mut net, host, a, b, n, t, l } = chat();
        let c = msg(&mut net, b, t, "SECRET", permanent());
        net.run();
        let p1 = purge(&mut net, a, t, c, Retention::default());
        net.run();
        let p2 = purge_on(&mut net, a, t, p1, own(), Retention::default());
        net.run();
        net.advance(ROLE_KEEP_MS + 3_600_000);
        net.run();
        write_own(&mut net, a, t, "later");
        net.run();
        if snap {
            let acts = net.sync(a).compact(&t, &own()).unwrap();
            net.actions(a, acts);
            net.run();
        }
        net.advance(3_600_000);
        net.run();
        assert_eq!(at_host(&mut net, a, host, &l, p1), vec![Vec::<usize>::new()]);
        assert!(at_host(&mut net, a, host, &l, p2).is_empty());
        net.set_online(n, true);
        net.run();
        assert!(net.engine(n).commit_ids().contains(&c), "snap {snap}");
        assert_eq!(net.engine(n).purged_on(&t, &k()).unwrap().get(&c), Some(&p1), "snap {snap}");
        assert_ne!(net.engine(n).get(&t, &k()).unwrap(), Some(s("SECRET")));
    }
}

// spec/commits.md §5: a permanent message a snapshot carries, then purged: the snapshot goes with it
// and a new node sees the tombstone, nothing pending.
#[test]
fn a_purge_of_a_snapshotted_message_spec_commits_5() {
    let Chat { mut net, a, b, n, t, .. } = chat();
    let c = msg(&mut net, b, t, "SECRET", permanent());
    net.run();
    let acts = net.sync(a).compact(&t, &k()).unwrap();
    net.actions(a, acts);
    net.run();
    let p = purge(&mut net, a, t, c, Retention::default());
    net.run();
    net.advance(3_600_000);
    net.run();
    net.set_online(n, true);
    net.run();
    assert_eq!(pending(&mut net, n), 0);
    let author = net.tid(b);
    sees_tombstone(&mut net, n, t, c, p, author);
}

/// Past its floor and replaced on `own()` (purged on replace), then a snapshot: a purge commit's own
/// delta is gone.
fn cover(net: &mut Net, a: usize, t: Tid) {
    net.advance(ROLE_KEEP_MS + 3_600_000);
    net.run();
    write_own(net, a, t, "later");
    net.run();
    let acts = net.sync(a).compact(&t, &own()).unwrap();
    net.actions(a, acts);
    net.run();
    net.advance(3_600_000);
    net.run();
}

// spec/commits.md §5: an aspect-wide request is lasting only if it dropped a permanent delta: one by an
// admin stays as its header, one by a writer with no right over what the aspect holds goes.
#[test]
fn an_aspect_wide_request_lasts_by_what_it_dropped_spec_commits_5() {
    for admin in [true, false] {
        let Chat { mut net, host, a, b, n, t, l } = chat();
        let c = msg(&mut net, a, t, "SECRET", Retention { by: PurgeBy::Admin });
        net.run();
        net.advance(1_000);
        let by = if admin { a } else { b };
        let mut m = Mutation::new();
        m.purge(PurgeItem::Aspect { tid: t, ak: k() });
        m.set(t, &GONE, &s("after")).unwrap();
        let p = net.engine(by).commit_hostile(m).unwrap().unwrap();
        net.run();
        cover(&mut net, a, t);
        assert!(!net.engine(a).body_not_dropped(&p, &t, &own()));
        assert_eq!(at_host(&mut net, a, host, &l, p), if admin { vec![Vec::<usize>::new()] } else { Vec::new() });
        net.set_online(n, true);
        net.run();
        // after a restart too: what it dropped is noted, not walked
        net.restart(a, 77);
        net.run();
        net.advance(3_600_000);
        net.run();
        assert_eq!(at_host(&mut net, a, host, &l, p), if admin { vec![Vec::<usize>::new()] } else { Vec::new() });
        assert_eq!(net.engine(n).purged_on(&t, &k()).unwrap().get(&c), admin.then_some(&p));
        assert_eq!(net.engine(n).body_not_dropped(&c, &t, &k()), !admin);
    }
}

/// All entries `n` knows under any label at `host`.
fn known_entries(net: &mut Net, n: usize, host: usize) -> usize {
    net.labels_at(host).into_iter().map(|l| net.sync(n).entries(&l).len()).sum()
}

// spec/sync.md §6, spec/permissions.md §6: a holder that held the demotion first comes back to find
// the purge's delete at the host: the message has no live write (a later write killed it), so a
// delete would keep it out; but the request falls there, so the holder places it again and the
// writer that dropped it takes it.
#[test]
fn a_holder_that_saw_a_fallen_purges_delete_uploads_again_spec_sync_6() {
    let mut net = Net::new();
    let host = net.add_host();
    let (a, b, x, h) = (net.node(1, &[host]), net.node(2, &[host]), net.node(4, &[host]), net.node(5, &[host]));
    let g = net.group(a, &[(b, Role::Write), (x, Role::Admin), (h, Role::Write)], &[host]);
    let t = kept_item(&mut net, a, g, g, "x");
    net.run();
    let m = msg(&mut net, b, t, "SECRET", permanent());
    net.run();
    msg(&mut net, b, t, "later", permanent());
    net.run();
    assert!(net.engine(h).body_not_dropped(&m, &t, &k()));
    net.set_online(a, false);
    net.set_online(h, false);
    let d = osis_node::flows::Demotion { holder: net.tid(x), new: None, retain: None };
    net.engine(a).demote(&g, &d).unwrap();
    let packs: Vec<_> = net.engine(a).commit_ids().into_iter().filter_map(|id| net.engine(a).package(&id).unwrap()).collect();
    for pk in &packs {
        let _ = net.engine(h).ingest(&pk.bytes, pk.blobs.clone());
    }
    net.advance(5_000);
    purge(&mut net, x, t, m, permanent());
    net.run();
    assert!(!net.engine(b).body_not_dropped(&m, &t, &k()), "the writer dropped it");
    assert!(net.engine(h).body_not_dropped(&m, &t, &k()), "the holder knows better");
    net.set_online(h, true);
    net.run();
    net.advance(120_000);
    net.run();
    let holds = |net: &mut Net, x: usize| net.engine(x).core.ix.commits.get(&m).is_some_and(|c| c.missing.is_empty() && c.dropped.is_empty());
    for n in [b, h] {
        assert!(holds(&mut net, n), "at {n}");
        assert!(net.engine(n).purged_on(&t, &k()).unwrap().is_empty(), "at {n}");
    }
}

// spec/sync.md §6, spec/permissions.md §6: a purge that fell after every holder dropped the body: it
// is gone for good (no holder), the part missing at each, no purge shown. The header-only blobs up
// by then stay, judged lasting by nobody: no upload and delete for good.
#[test]
fn a_header_only_some_judge_lasting_is_left_alone_spec_sync_6() {
    let mut net = Net::new();
    let host = net.add_host();
    let (a, b, x, d2) = (net.node(1, &[host]), net.node(2, &[host]), net.node(4, &[host]), net.node(5, &[host]));
    let g = net.group(a, &[(b, Role::Write), (x, Role::Admin), (d2, Role::Admin)], &[host]);
    let t = kept_item(&mut net, a, g, g, "x");
    net.run();
    net.set_online(d2, false);
    let m = msg(&mut net, b, t, "SECRET", permanent());
    net.run();
    let d = osis_node::flows::Demotion { holder: net.tid(x), new: None, retain: None };
    let done = net.engine(d2).demote(&g, &d).unwrap();
    net.advance(5_000);
    let p = purge(&mut net, x, t, m, Retention::default());
    net.run();
    cover(&mut net, a, t);
    net.set_online(d2, true);
    let acts = net.sync(d2).carry_out(done).unwrap();
    net.actions(d2, acts);
    net.run();
    assert!(net.engine(a).purged_on(&t, &k()).unwrap().is_empty());
    assert!(net.engine(d2).commit_ids().contains(&m) && net.engine(a).core.ix.commits.get(&m).unwrap().missing.len() == 1);
    net.advance(120_000);
    let before = known_entries(&mut net, a, host);
    for _ in 0..6 {
        net.advance(120_000);
    }
    assert_eq!(known_entries(&mut net, a, host), before, "an upload and delete loop");
    let l = net.labels_at(host).into_iter().find(|l| !at_host(&mut net, a, host, l, p).is_empty()).expect("the holders' copy stays");
    assert_eq!(at_host(&mut net, a, host, &l, m), vec![Vec::<usize>::new()]);
}

// spec/commits.md §5: a node with a slow clock purges a message a fast node stamped ahead of
// it, after a restart too: applying it moved the clock past it (spec/crdt.md §2.2).
#[test]
fn a_slow_clock_purges_a_message_stamped_ahead_spec_commits_5() {
    let Chat { mut net, a, b, t, .. } = chat();
    net.set_skew(b, 20 * 60_000);
    net.set_skew(a, -20 * 60_000);
    let m = msg(&mut net, b, t, "SECRET", permanent());
    net.run();
    assert!(net.engine(a).commit_ids().contains(&m));
    net.restart(a, 55);
    net.run();
    let p = purge(&mut net, a, t, m, Retention::default());
    assert!(net.engine(b).header(&m).unwrap().ts < net.engine(a).header(&p).unwrap().ts);
    net.run();
    for x in [a, b] {
        assert!(!net.engine(x).body_not_dropped(&m, &t, &k()), "at {x}");
    }
}

// spec/permissions.md §5.1, §6: a fresh node demotes an admin whose old purge it never held. Non
// permanent: the request went with compaction, so the frontier cannot list it. The purge falls where
// it is held, but no node holds the body and the host has none: nothing comes back. Permanent: the
// request lasts as a header, the fresh node lists it, and the tombstone stays.
#[test]
fn a_fresh_node_demotes_and_nothing_comes_back_spec_perm_6() {
    for lasting in [false, true] {
        let mut net = Net::new();
        let host = net.add_host();
        let (a, x, b, f) = (net.node(1, &[host]), net.node(2, &[host]), net.node(4, &[host]), net.node(3, &[host]));
        let g = net.group(a, &[(x, Role::Admin), (b, Role::Write), (f, Role::Admin)], &[host]);
        net.set_online(f, false);
        let t = if lasting { kept_item(&mut net, a, g, g, "x") } else { net.item(a, g, g, "x") };
        net.run();
        let l = net.label(a);
        let m = msg(&mut net, b, t, "SECRET", permanent());
        net.run();
        let p = purge(&mut net, x, t, m, Retention::default());
        net.run();
        // the request's own write replaced and compacted: its body goes from the host
        net.advance(10_000);
        write_own(&mut net, a, t, "later");
        net.run();
        net.advance(100 * 86_400_000);
        net.run();
        net.engine(a).snapshot(&t, &own()).unwrap().unwrap();
        net.run();
        net.advance(120_000);
        net.run();
        net.set_online(f, true);
        net.run();
        net.advance(120_000);
        net.run();
        assert_eq!(net.engine(f).commit_ids().contains(&p), lasting, "what the fresh node holds of the request");
        let holder = net.tid(x);
        let d = osis_node::flows::Demotion { holder, new: Some(crate::common::edge(Role::Write)), retain: None };
        let done = net.engine(f).demote(&g, &d).unwrap();
        let acts = net.sync(f).carry_out(done).unwrap();
        net.actions(f, acts);
        net.run();
        for _ in 0..4 {
            net.advance(120_000);
            net.run();
        }
        for n in [a, b, f] {
            assert_ne!(net.engine(n).get(&t, &k()).unwrap(), Some(s("SECRET")), "node {n}");
            assert!(!net.engine(n).body_not_dropped(&m, &t, &k()) || net.engine(n).core.ix.commits.get(&m).is_none_or(|c| !c.missing.is_empty()), "node {n}: the body is back");
            assert_eq!(net.engine(n).purged_on(&t, &k()).unwrap().contains_key(&m), lasting, "node {n}: the tombstone");
        }
        let at = at_host(&mut net, a, host, &l, m);
        assert!(at.iter().all(Vec::is_empty), "a body at the host: {at:?}");
        assert_eq!(!at.is_empty(), lasting, "its header alone, while it lasts");
    }
}

// spec/commits.md §4 (a node never waits for a part), §5 (a lasting commit's header stays under its
// labels): a request whose one delta is dead stays as a header-only blob; its killer expires, so a
// new node gets the header from the host with nothing later on the aspect. Both headers apply at
// once, the request standing.
#[test]
fn a_lasting_request_applies_when_its_killer_left_spec_commits_4() {
    let Chat { mut net, host, a, b, n, t, l } = chat();
    let c = msg(&mut net, b, t, "SECRET", permanent());
    net.run();
    net.advance(120_000);
    net.run();
    net.advance(1_000);
    let mut m = Mutation::new();
    m.purge(PurgeItem::Commit { commit: c, tid: t, ak: k() });
    m.set(t, &GONE, &s("g1")).unwrap();
    let p = net.engine(a).commit(m).unwrap().unwrap();
    net.run();
    net.advance(120_000);
    net.run();
    net.advance(1_000);
    let mut m = Mutation::new();
    m.set(t, &GONE, &s("g2")).unwrap();
    m.expires(t, &GONE, osis_base::WallMs(net.now() + ROLE_KEEP_MS + 7_200_000)).unwrap();
    let killer = net.engine(a).commit(m).unwrap().unwrap();
    net.run();
    net.advance(ROLE_KEEP_MS + 3_600_000);
    net.run();
    net.advance(7_200_000);
    net.run();
    for _ in 0..4 {
        net.advance(120_000);
        net.run();
    }
    assert_eq!(at_host(&mut net, a, host, &l, p), vec![Vec::<usize>::new()], "its header alone at the host");
    assert!(at_host(&mut net, a, host, &l, killer).is_empty(), "the killer expired");
    net.set_online(n, true);
    net.run();
    net.advance(120_000);
    net.run();
    assert_eq!(pending(&mut net, n), 0);
    assert!(net.engine(n).header(&p).is_some() && net.engine(n).header(&c).is_some());
    assert_eq!(net.engine(n).purged_on(&t, &k()).unwrap().get(&c), Some(&p));
}
