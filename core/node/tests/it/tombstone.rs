#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Lasting tombstones (spec/commits.md §5, spec/sync.md §6): a purged permanent delta keeps its
//! header for good, at the label and at a new device; every other retention leaves none.

use crate::common::LIST;
use crate::net;
use net::*;
use osis_base::format::ROLE_KEEP_MS;
use osis_base::{Ak, CommitId, LabelId, Role, Tid};
use osis_commit::{FOREVER, PurgeItem};
use osis_node::Mutation;
use osis_node::sync::EntryKind;
use osis_schema::{AspectKey, Bound, PurgeBy, Retention};

fn permanent() -> Retention {
    Retention { by: PurgeBy::AuthorOrAdmin, at_least: Bound { abs: Some(FOREVER), rel: None }, at_most: Bound::default() }
}

fn k() -> Ak {
    Ak::new(REG.ak()).unwrap()
}

fn msg(net: &mut Net, n: usize, t: Tid, v: &str, r: Retention) -> CommitId {
    let mut m = Mutation::new();
    m.retention(t, &REG, r).unwrap();
    m.set(t, &REG, &s(v)).unwrap();
    net.engine(n).commit(m).unwrap().unwrap()
}

/// A purge of `c`, its own delta under `r`.
fn purge(net: &mut Net, n: usize, t: Tid, c: CommitId, r: Retention) -> CommitId {
    let mut m = Mutation::new();
    m.purge(PurgeItem::Commit { commit: c, tid: t, ak: k() });
    m.retention(t, &REG, r).unwrap();
    // a value of its own: writing the same value again is no write
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    m.set(t, &REG, &s(&format!("after {}", N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)))).unwrap();
    net.engine(n).commit(m).unwrap().unwrap()
}

/// The delta sets of commit `c`'s entries node `n` knows present at `host`.
fn at_host(net: &mut Net, n: usize, host: usize, l: &LabelId, c: CommitId) -> Vec<Vec<(usize, usize)>> {
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

/// Admin `a`, writer `b`, reader `n` kept offline from the start: a new device once it comes up.
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
    let t = net.item(a, g, g, "x");
    net.run();
    let l = net.label(a);
    Chat { net, host, a, b, n, t, l }
}

/// New device `n` sees `c` as a tombstone: applied, no body, the purge named, author and time
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
// alone, whatever the purge commit's own retention, and a new device applies it, seeing who wrote
// it and when; the body is gone from the host.
#[test]
fn new_device_sees_a_purged_permanent_delta_spec_commits_5() {
    for r in [Retention::default(), permanent()] {
        let Chat { mut net, host, a, b, n, t, l } = chat();
        let c = msg(&mut net, b, t, "SECRET", permanent());
        net.run();
        let body = at_host(&mut net, a, host, &l, c);
        assert!(body.iter().all(|x| !x.is_empty()) && !body.is_empty());
        let p = purge(&mut net, b, t, c, r);
        net.run();
        assert_eq!(at_host(&mut net, a, host, &l, c), vec![Vec::new()], "its header alone at the host");
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

// spec/commits.md §5: lost at the host, a holder uploads the header-only blob again, as any
// must-hold body; a new device fetches it from there.
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
    assert_eq!(at_host(&mut net, a, host, &l, c), vec![Vec::new()]);
    net.set_online(n, true);
    net.run();
    let author = net.tid(b);
    sees_tombstone(&mut net, n, t, c, p, author);
}

// spec/commits.md §5: every other retention leaves no lasting tombstone: nothing of the commit stays
// at the host, and a new device never learns of it. `nobody`-free sets alike.
#[test]
fn other_retention_leaves_none_spec_commits_5() {
    let forever = Bound { abs: Some(FOREVER), rel: None };
    let finite = Bound { abs: Some(FOREVER - 1), rel: None };
    let cases = [
        ("default", Retention::default()),
        ("relative keep at least", Retention { at_least: Bound { abs: None, rel: Some(1000) }, ..Default::default() }),
        ("a finite absolute keep at least", Retention { at_least: finite, ..Default::default() }),
        ("forever with a keep at most", Retention { by: PurgeBy::Writer, at_least: forever, at_most: Bound { abs: None, rel: Some(FOREVER) } }),
    ];
    for (what, r) in cases {
        let Chat { mut net, host, a, b, n, t, l } = chat();
        let c = msg(&mut net, b, t, "SECRET", r);
        net.run();
        purge(&mut net, b, t, c, Retention::default());
        net.run();
        assert!(at_host(&mut net, a, host, &l, c).is_empty(), "{what}: left at the host");
        net.set_online(n, true);
        net.run();
        assert!(!net.engine(n).commit_ids().contains(&c), "{what}: reached a new device");
    }
}

// spec/commits.md §5, §6: an expired write is not permanent, whatever its keep at least: expiry
// leaves no header at the host and none at a new device, as before.
#[test]
fn expired_write_leaves_none_spec_commits_6() {
    let Chat { mut net, host, a, b, n, t, l } = chat();
    let mut m = Mutation::new();
    m.retention(t, &REG, permanent()).unwrap();
    let at = osis_base::WallMs(net.engine(b).now().0 + 60_000);
    m.set(t, &REG, &s("SECRET")).unwrap();
    m.expires(t, &REG, at).unwrap();
    let c = net.engine(b).commit(m).unwrap().unwrap();
    assert!(!net.engine(b).header(&c).unwrap().aspects.iter().any(|x| x.permanent()));
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
// `ROLE_KEEP` floor, covered): a new device counts the purged delta as held only by the request.
#[test]
fn the_purge_request_stays_as_its_header_spec_commits_5() {
    let Chat { mut net, host, a, b, n, t, l } = chat();
    let c = msg(&mut net, b, t, "SECRET", permanent());
    net.run();
    let p = purge(&mut net, a, t, c, Retention::default());
    net.run();
    assert!(at_host(&mut net, a, host, &l, p).iter().all(|x| !x.is_empty()));
    // a later write, then a snapshot covering the purge commit's own delta, past its floor
    net.advance(ROLE_KEEP_MS + 3_600_000);
    net.run();
    net.write(a, t, "later");
    net.run();
    let acts = net.sync(a).compact(&t, &k()).unwrap();
    net.actions(a, acts);
    net.run();
    net.advance(3_600_000);
    net.run();
    assert!(!net.engine(a).body_not_dropped(&p, &t, &k()), "the purge commit's body is covered and gone");
    assert_eq!(at_host(&mut net, a, host, &l, p), vec![Vec::new()], "its header stays");
    assert_eq!(at_host(&mut net, a, host, &l, c), vec![Vec::new()]);
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
    let c = msg(&mut net, b, t, "SECRET", Retention::default());
    net.run();
    let p = purge(&mut net, a, t, c, Retention::default());
    net.run();
    net.advance(ROLE_KEEP_MS + 3_600_000);
    net.run();
    net.write(a, t, "later");
    net.run();
    let acts = net.sync(a).compact(&t, &k()).unwrap();
    net.actions(a, acts);
    net.run();
    net.advance(3_600_000);
    net.run();
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
    assert_eq!(h.aspects[held[0][0].0].ak, Ak::new(LIST.ak()).unwrap());
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
    assert_eq!(at_host(&mut net, a, host, &l, c), vec![Vec::new()]);
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
    let u = net.item(a, g2, g2, "y");
    net.run();
    let mut m = Mutation::new();
    m.retention(t, &REG, permanent()).unwrap();
    m.set(t, &REG, &s("SECRET")).unwrap();
    m.set(u, &LIST, &osis_base::Value::List(vec![s("elsewhere")])).unwrap();
    let c = net.engine(b).commit(m).unwrap().unwrap();
    net.run();
    let p = purge(&mut net, a, t, c, permanent());
    net.run();
    assert_eq!(at_host(&mut net, a, host, &l, c), vec![Vec::new()], "under the purged delta's label");
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
    assert_eq!(at_host(&mut net, a, host, &l, c), vec![Vec::new()]);
    for p in ps {
        assert_eq!(at_host(&mut net, a, host, &l, p).len(), 1);
    }
}

// spec/commits.md §5: a commit naming a permanent delta it may not purge earns nothing: its request
// is no witness, and the delta stays.
#[test]
fn a_purge_without_the_right_is_no_witness_spec_commits_5() {
    let Chat { mut net, host, a, b, t, l, .. } = chat();
    let c = msg(&mut net, a, t, "SECRET", Retention { by: PurgeBy::Admin, ..permanent() });
    net.run();
    let p = purge(&mut net, b, t, c, Retention::default());
    net.run();
    assert!(net.engine(a).body_not_dropped(&c, &t, &k()));
    net.advance(ROLE_KEEP_MS + 3_600_000);
    net.run();
    net.write(a, t, "later");
    net.run();
    let acts = net.sync(a).compact(&t, &k()).unwrap();
    net.actions(a, acts);
    net.run();
    net.advance(3_600_000);
    net.run();
    assert!(at_host(&mut net, a, host, &l, p).is_empty(), "no lasting blob of the purge without the right");
    assert_eq!(at_host(&mut net, a, host, &l, c).len(), 1);
    assert!(!at_host(&mut net, a, host, &l, c)[0].is_empty());
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
    assert_eq!(at_host(&mut net, a, host, &l, c), vec![Vec::new()]);
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
    let c = msg(&mut net, a, t, "SECRET", Retention { by: PurgeBy::Admin, ..permanent() });
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
// tombstone of a removed writer's message stays valid at a new device holding the removal.
#[test]
fn a_kicked_writers_tombstone_stays_spec_perm_5_1() {
    let Chat { mut net, host, a, b, n, t, l } = chat();
    let c = msg(&mut net, b, t, "SECRET", permanent());
    net.run();
    let p = purge(&mut net, a, t, c, permanent());
    net.run();
    let g = net.sync(a).labels().into_iter().find(|x| x.1.id == l).unwrap().0;
    let holder = net.tid(b);
    let d = osis_node::flows::Demotion { holder, new: None, presync: osis_node::flows::PreSync::Synced };
    let done = net.engine(a).demote(&g, &d).unwrap();
    let acts = net.sync(a).carry_out(done).unwrap();
    net.actions(a, acts);
    net.run();
    assert_eq!(at_host(&mut net, a, host, &l, c), vec![Vec::new()]);
    net.set_online(n, true);
    net.run();
    sees_tombstone(&mut net, n, t, c, p, holder);
}

// spec/sync.md §1: a header-only blob's prefix carries no expiry and no commitment: any other is bad
// input, so a writer cannot set a tombstone to expire at the host.
#[test]
fn header_only_prefix_is_checked_spec_sync_1() {
    use osis_node::labeling::{Body, open_commit, seal_body};
    let Chat { mut net, b, t, .. } = chat();
    let c = msg(&mut net, b, t, "y", permanent());
    let pk = net.engine(b).package(&c).unwrap().unwrap();
    let blob = osis_commit::CommitBlob::decode(&pk.bytes).unwrap();
    let pt = osis_commit::rewrite(&blob, |_, _| true).encode();
    let body = |expires| Body { commit: c, reader: t, parts: Vec::new(), expires, keys: Vec::new(), blind: blob.header.blind, plaintext: pt.clone(), role_commit: false };
    let mut rng = osis_crypto::SeededRng::from_u64(5);
    let good = seal_body(&body(None), &mut rng).unwrap();
    assert!(open_commit(&good.blob, &good.key).is_ok());
    let bad = seal_body(&body(Some(FOREVER)), &mut rng).unwrap();
    assert!(open_commit(&bad.blob, &bad.key).is_err());
}
