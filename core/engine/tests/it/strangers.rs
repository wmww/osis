//! What a stranger's open fires leave on the node they reach (spec/commits.md §5 The setting,
//! spec/sync-inbox.md §2, §4): only a setting entry naming an open signal keeps its fires, and a
//! sealed fire's records and chain go with the last of its fires.

use crate::common::{ak, s, set_setting};
use crate::flows::send;
use osis_base::Tid;
use osis_engine::local_peer::LocalPeer;
use osis_schema::core_types as ct;

const NOTE: &str = "x:note@~0";
const JUNK: &str = "x:junk@~0";
const HOUR_MS: u64 = 3_600_000;

/// Peer 0's account and `n` strangers, each its own account holding peer 0's public records
/// (all peer 0 made, one way): peer 0 knows none of them. Peer 0's inbox keeps `NOTE` an hour
/// beside its three signals, and every other aspect for good by default. Its inbox.
fn strangers(n: usize) -> (LocalPeer, Tid) {
    let mut lp = crate::common::net_bare(n + 1, 0);
    let p0 = lp.peers[0].engine.create_account().unwrap().0.account;
    for i in 1..=n {
        lp.peers[i].engine.create_account().unwrap();
    }
    let inbox = lp.peers[0].engine.inbox_thing(&p0).unwrap();
    let mut x = lp.peers[0].engine.get_typed(&inbox, &ct::RETENTION).unwrap().unwrap();
    x.rules.insert(ak(NOTE), ct::RetentionEntry { history: Some(osis_schema::History::Keep { until: None, after: Some(HOUR_MS) }), ..Default::default() });
    x.default = Some(ct::RetentionEntry { history: Some(osis_schema::History::FOREVER), ..Default::default() });
    set_setting(&mut lp, 0, inbox, &x);
    let ids = lp.peers[0].engine.commit_ids();
    for i in 1..=n {
        send(&mut lp, 0, i, &ids);
        send(&mut lp, 0, i, &ids);
    }
    (lp, inbox)
}

/// Stranger `i` fires `ak` on `inbox` with `v`, sealed; peer 0 opens it under the inbox's sync
/// ID. The fire's commit.
fn fire(lp: &mut LocalPeer, i: usize, inbox: Tid, ak: &str, v: &str) -> osis_base::CommitId {
    let e = &mut lp.peers[i].engine;
    e.fire_open(&inbox, ak, s(v)).unwrap();
    let id = *e.fires_owed().last().expect("owed sealed");
    let out = e.sealed_fire(&id).unwrap().expect("sealed");
    e.fire_taken(&id).unwrap();
    let b = osis_blob::blob_id(&out.blob);
    match lp.peers[0].engine.open_entry(&out.sync_id, &b, &[0; 57], &out.blob, u64::MAX).unwrap() {
        osis_engine::sync::Opened::Commit(c, _) => c,
        o => panic!("not opened: {o:?}"),
    }
}

/// What node-sync does once no entry of a fire's blob is left (its body out of history): peer 0
/// forgets each fire it may (`Engine::forgettable`).
fn settle(lp: &mut LocalPeer, fires: &[osis_base::CommitId]) {
    let e = &mut lp.peers[0].engine;
    let gone: Vec<_> = fires.iter().copied().filter(|c| e.forgettable(c).unwrap()).collect();
    assert_eq!(gone.len(), fires.len(), "every fire out of history may be forgotten");
    e.forget_commits(&gone).unwrap();
}

fn listed(lp: &mut LocalPeer, c: &osis_base::CommitId, inbox: Tid, a: &str) -> bool {
    lp.peers[0].engine.listed_at(c, &[(inbox, ak(a))]).unwrap()
}

// spec/commits.md §5 The setting: an open signal's fires are kept by an entry naming it only,
// never by the default: a stranger's fire on an open signal the setting does not name is out of
// history at its arrival, one on a named signal stays for its entry.
#[test]
fn only_an_entry_naming_an_open_signal_keeps_its_fires_spec_commits_5() {
    let (mut lp, inbox) = strangers(1);
    let junk = fire(&mut lp, 1, inbox, JUNK, "junk");
    let note = fire(&mut lp, 1, inbox, NOTE, "note");
    assert!(!listed(&mut lp, &junk, inbox, JUNK), "the default keeps no open fire");
    assert!(listed(&mut lp, &note, inbox, NOTE), "its entry keeps it");
    lp.advance(HOUR_MS - 1_000);
    lp.peers[0].tick().unwrap();
    assert!(listed(&mut lp, &note, inbox, NOTE), "kept for its entry");
    lp.advance(2_000);
    lp.peers[0].tick().unwrap();
    assert!(!listed(&mut lp, &note, inbox, NOTE), "out of history past its entry");
}

/// Peer 0's rows by family (`Engine::local_census`) changed from `before` to `after`.
fn changed(before: &Census, after: &Census) -> Vec<(String, Option<Rows>, Option<Rows>)> {
    let keys: std::collections::BTreeSet<&String> = before.keys().chain(after.keys()).collect();
    keys.into_iter().filter(|k| before.get(*k) != after.get(*k)).map(|k| (k.clone(), before.get(k).copied(), after.get(k).copied())).collect()
}

/// Count and bytes of one family.
type Rows = (usize, usize);

type Census = std::collections::BTreeMap<String, Rows>;

// spec/sync-inbox.md §4 A sealed fire, spec/commits.md §5 Forgetting: a stranger's fires go
// whole once out of history, and with the last of them its chain (its records, its and its
// inbox's `keys.0` commits), which nothing held needs then: N strangers each firing on a named
// and an unnamed open signal leave peer 0's rows exactly as before.
#[test]
fn strangers_fires_leave_no_row_spec_sync_inbox_4() {
    for n in [1, 3] {
        let (mut lp, inbox) = strangers(n);
        lp.peers[0].tick().unwrap();
        let before = lp.peers[0].engine.local_census().unwrap();
        let ids: std::collections::BTreeSet<_> = lp.peers[0].engine.commit_ids().into_iter().collect();
        let mut fires = Vec::new();
        for i in 1..=n {
            fires.push(fire(&mut lp, i, inbox, NOTE, "note"));
            fires.push(fire(&mut lp, i, inbox, JUNK, "junk"));
        }
        assert!(lp.peers[0].engine.local_census().unwrap() != before, "n={n}: the fires and chains arrived");
        lp.advance(HOUR_MS + 1_000);
        lp.peers[0].tick().unwrap();
        settle(&mut lp, &fires);
        let e = &mut lp.peers[0].engine;
        let new: Vec<_> = e.commit_ids().into_iter().filter(|c| !ids.contains(c)).collect();
        assert_eq!(new, vec![], "n={n}: no commit stays");
        assert_eq!(changed(&before, &e.local_census().unwrap()), vec![], "n={n}: rows by family");
    }
}

// spec/sync-inbox.md §1, spec/commits.md §5 The setting, Forgetting: one stranger flooding the
// inbox, past `DEPOSITS_WAITING` fires on its named signal and as many on open signals it names
// nothing for, each on its own AK: the unnamed are out of history at arrival and go at once, the
// named stay for their entry, then go; every row of the flood goes with its fires.
#[test]
fn a_fire_flood_leaves_no_row_past_its_setting_spec_sync_inbox_1() {
    let k = 2 * osis_base::format::DEPOSITS_WAITING;
    let (mut lp, inbox) = strangers(1);
    // the stranger's chain, learned with a first fire that has since gone
    let first = fire(&mut lp, 1, inbox, NOTE, "first");
    lp.advance(HOUR_MS + 1_000);
    lp.peers[0].tick().unwrap();
    settle(&mut lp, &[first]);
    let base = lp.peers[0].engine.local_census().unwrap();
    let junk: Vec<_> = (0..k).map(|i| fire(&mut lp, 1, inbox, &format!("x:junk{i}@~0"), "junk")).collect();
    for (i, c) in junk.iter().enumerate() {
        assert!(!listed(&mut lp, c, inbox, &format!("x:junk{i}@~0")), "an unnamed open signal keeps nothing");
    }
    settle(&mut lp, &junk);
    assert_eq!(changed(&base, &lp.peers[0].engine.local_census().unwrap()), vec![], "unnamed fires leave no row");
    let notes: Vec<_> = (0..k).map(|i| fire(&mut lp, 1, inbox, NOTE, &format!("note {i}"))).collect();
    assert!(notes.iter().all(|c| listed(&mut lp, c, inbox, NOTE)), "kept for their entry");
    lp.advance(HOUR_MS + 1_000);
    lp.peers[0].tick().unwrap();
    settle(&mut lp, &notes);
    assert_eq!(changed(&base, &lp.peers[0].engine.local_census().unwrap()), vec![], "named fires leave no row past their entry");
}
