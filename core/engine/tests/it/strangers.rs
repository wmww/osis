//! What a stranger's external fires leave on the node they reach (spec/commits.md §5 The setting,
//! spec/sync-inbox.md §2, §4): only a setting entry naming an external signal enables it and keeps
//! its fires (a stranger's fire of another is refused), and a sealed fire's records and chain go
//! at the pass end, its fires staying.

use crate::common::{ak, s, set_setting};
use crate::flows::send_carried;
use osis_base::Tid;
use osis_engine::local_peer::LocalPeer;
use osis_schema::core_types as ct;

const NOTE: &str = "x:note@~0";
const JUNK: &str = "x:junk@~0";
const HOUR_MS: u64 = 3_600_000;

/// Peer 0's account and `n` strangers, each its own account holding peer 0's public records
/// (all peer 0 made, one way) by a strong to its account: peer 0 knows none of them. Peer 0's inbox keeps `NOTE` an hour
/// beside its three signals, and every other aspect for good by default. Its inbox.
fn strangers(n: usize) -> (LocalPeer, Tid) {
    let mut lp = LocalPeer::new_apart(n + 1, 0, crate::common::T0).unwrap();
    let accounts: Vec<Tid> = lp.peers.iter_mut().map(|p| p.engine.make_account().unwrap().0.thing).collect();
    let p0 = accounts[0];
    let inbox = lp.peers[0].engine.inbox_thing(&p0).unwrap();
    let mut x = lp.peers[0].engine.get_typed(&inbox, &ct::RETENTION).unwrap().unwrap();
    x.rules.insert(ak(NOTE), ct::RetentionEntry { history: Some(osis_schema::History::Keep { until: None, after: Some(HOUR_MS) }), ..Default::default() });
    x.default = Some(ct::RetentionEntry { history: Some(osis_schema::History::FOREVER), ..Default::default() });
    set_setting(&mut lp, 0, inbox, &x);
    let ids = lp.peers[0].engine.commit_ids();
    for i in 1..=n {
        // the stranger keeps peer 0's account (and so its inbox), on which it means to fire
        lp.peers[i].know(&[p0]).unwrap();
        send_carried(&mut lp, 0, i, &ids);
        send_carried(&mut lp, 0, i, &ids);
    }
    (lp, inbox)
}

/// Stranger `i` fires `ak` on `inbox` with `v`, sealed; peer 0 opens it under the inbox's sync
/// ID. The fire's commit.
fn fire(lp: &mut LocalPeer, i: usize, inbox: Tid, ak: &str, v: &str) -> osis_base::CommitId {
    fire_value(lp, i, inbox, ak, s(v))
}

/// `fire` of value `v`.
fn fire_value(lp: &mut LocalPeer, i: usize, inbox: Tid, ak: &str, v: osis_base::Value) -> osis_base::CommitId {
    match open(lp, i, inbox, ak, v) {
        osis_engine::sync::Opened::Commit(c, _) => c,
        o => panic!("not opened: {o:?}"),
    }
}

/// Stranger `i`'s sealed fire of `ak` on `inbox` as peer 0 opens it.
fn open(lp: &mut LocalPeer, i: usize, inbox: Tid, ak: &str, v: osis_base::Value) -> osis_engine::sync::Opened {
    let e = &mut lp.peers[i].engine;
    e.fire_open(&inbox, ak, v).unwrap();
    let id = *e.fires_owed().last().expect("owed sealed");
    let out = e.sealed_fire(&id).unwrap().expect("sealed");
    e.fire_taken(&id).unwrap();
    let b = osis_blob::blob_id(&out.blob);
    lp.peers[0].engine.open_entry(&out.sync_id, &b, &[0; 57], &out.blob, u64::MAX).unwrap()
}

/// Stranger `i` fires `ak`, which `inbox`'s setting does not enable: peer 0 refuses it whole
/// (spec/permissions.md §5.2 External fires, spec/sync-inbox.md §4: none of a fire that does not
/// apply valid).
fn refused(lp: &mut LocalPeer, i: usize, inbox: Tid, ak: &str) {
    let o = open(lp, i, inbox, ak, s("junk"));
    assert!(matches!(o, osis_engine::sync::Opened::Bad), "a fire of {ak} its setting does not enable: {o:?}");
}

/// What node-sync does once no entry of a fire's blob is left (its body out of history): peer 0
/// forgets each fire it may (`Engine::forgettable`), and the pass ends (`Engine::settle_needs`).
fn settle(lp: &mut LocalPeer, fires: &[osis_base::CommitId]) {
    let e = &mut lp.peers[0].engine;
    let gone: Vec<_> = fires.iter().copied().filter(|c| e.forgettable(c).unwrap()).collect();
    assert_eq!(gone.len(), fires.len(), "every fire out of history may be forgotten");
    e.forget_commits(&gone).unwrap();
    e.settle_needs().unwrap();
}

fn listed(lp: &mut LocalPeer, c: &osis_base::CommitId, inbox: Tid, a: &str) -> bool {
    lp.peers[0].engine.listed_at(c, &[(inbox, ak(a))]).unwrap()
}

// spec/commits.md §5 The setting: an external signal is enabled and its fires kept by an entry
// naming it only, never by the default: a stranger's fire on an external signal the setting does
// not name is refused (the default keeping everything else for good), one on a named signal stays
// for its entry.
#[test]
fn only_an_entry_naming_an_external_signal_keeps_its_fires_spec_commits_5() {
    let (mut lp, inbox) = strangers(1);
    refused(&mut lp, 1, inbox, JUNK);
    let note = fire(&mut lp, 1, inbox, NOTE, "note");
    assert!(listed(&mut lp, &note, inbox, NOTE), "its entry keeps it");
    lp.advance(HOUR_MS - 1_000);
    lp.peers[0].tick().unwrap();
    assert!(listed(&mut lp, &note, inbox, NOTE), "kept for its entry");
    lp.advance(2_000);
    lp.peers[0].tick().unwrap();
    assert!(!listed(&mut lp, &note, inbox, NOTE), "out of history past its entry");
}

/// Peer 0's rows by family (`Engine::local_census`) changed from `before` to `after`, but the
/// node's one blob sequence row (`blo`: written once its first transaction notes a blob, kept for
/// the node's life, owned by no fire).
fn changed(before: &Census, after: &Census) -> Vec<(String, Option<Rows>, Option<Rows>)> {
    let keys: std::collections::BTreeSet<&String> = before.keys().chain(after.keys()).filter(|k| k.as_str() != "blo").collect();
    keys.into_iter().filter(|k| before.get(*k) != after.get(*k)).map(|k| (k.clone(), before.get(k).copied(), after.get(k).copied())).collect()
}

/// Count and bytes of one family.
type Rows = (usize, usize);

type Census = std::collections::BTreeMap<String, Rows>;

// spec/sync-inbox.md §4 A sealed fire, spec/commits.md §5 Forgetting, What a held thing needs: a
// stranger's fires go whole once out of history, and its chain (its records, its and its
// inbox's `keys.0` commits) with the pass end, which nothing held needs (a weak a fire carries
// to its account needs nothing): N strangers each firing on a named and an unnamed external signal
// leave peer 0's rows exactly as before.
#[test]
fn strangers_fires_leave_no_row_spec_sync_inbox_4() {
    for n in [1, 3] {
        let (mut lp, inbox) = strangers(n);
        lp.peers[0].tick().unwrap();
        let before = lp.peers[0].engine.local_census().unwrap();
        let ids: std::collections::BTreeSet<_> = lp.peers[0].engine.commit_ids().into_iter().collect();
        let mut fires = Vec::new();
        for i in 1..=n {
            // a fire naming its sender's account by a weak, which needs nothing
            let me = lp.peers[i].engine.me();
            fires.push(fire_value(&mut lp, i, inbox, NOTE, osis_base::Value::Weak(me)));
            refused(&mut lp, i, inbox, JUNK);
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
// inbox, past `DEPOSITS_WAITING` fires on its named signal and as many on external signals it names
// nothing for, each on its own AK: the unnamed are refused whole, the
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
    for i in 0..k {
        refused(&mut lp, 1, inbox, &format!("x:junk{i}@~0"));
    }
    settle(&mut lp, &[]);
    assert_eq!(changed(&base, &lp.peers[0].engine.local_census().unwrap()), vec![], "unnamed fires leave no row");
    let notes: Vec<_> = (0..k).map(|i| fire(&mut lp, 1, inbox, NOTE, &format!("note {i}"))).collect();
    assert!(notes.iter().all(|c| listed(&mut lp, c, inbox, NOTE)), "kept for their entry");
    lp.advance(HOUR_MS + 1_000);
    lp.peers[0].tick().unwrap();
    settle(&mut lp, &notes);
    assert_eq!(changed(&base, &lp.peers[0].engine.local_census().unwrap()), vec![], "named fires leave no row past their entry");
}

// spec/commits.md §5 What a held thing needs (another account's chain goes with the last held
// thing holding a strong to it or that it holds a role on): a stranger's fire kept in history
// keeps nothing of the stranger, whose chain goes at the pass end; the fire stays listed, across
// a restart, its blob carrying the chain any other reader verifies it by (spec/sync-inbox.md §2).
#[test]
fn a_kept_fire_keeps_nothing_of_its_sender_spec_commits_5() {
    let (mut lp, inbox) = strangers(1);
    let p1 = lp.peers[1].engine.me();
    let note = fire(&mut lp, 1, inbox, NOTE, "note");
    assert!(lp.peers[0].engine.core.created(&p1).is_some(), "its record came with the fire");
    lp.peers[0].engine.settle_needs().unwrap();
    assert!(lp.peers[0].engine.core.created(&p1).is_none(), "{}", lp.peers[0].engine.why_kept(&p1));
    assert!(listed(&mut lp, &note, inbox, NOTE));
    lp.peers[0].restart(7).unwrap();
    assert!(listed(&mut lp, &note, inbox, NOTE), "listed after a restart");
}
