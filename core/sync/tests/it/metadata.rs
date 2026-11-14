//! What a node keeping S unread learns (spec/requirements.md Data a node cannot read;
//! notes/unreadable-data.md): three nodes of three accounts on recording devices, node 1 granted
//! sync on node 0's thing, node 2 write; after values and a map key are written and synced, node
//! 1's store device and everything an attacker holding its whole device decrypts are searched for
//! every secret and identifier of the scenario, and its blob sizes checked against Padmé.

use crate::harness::history::{file, introduce};
use crate::harness::{World, fixture_with};
use osis_base::{Ak, Role, SyncId, Tid, Value};
use osis_engine::Mutation;
use osis_schema::core_types as ct;

const MARK_A: &str = "plaintext-marker-alpha-7f3a91";
pub(crate) const MARK_B: &str = "plaintext-marker-beta-c4e82d";
const MAP_KEY: &str = "map-key-marker-5b0e66";

pub(crate) fn value_ak() -> Ak {
    Ak::new("u:secretvalue.0").unwrap()
}

fn map_ak() -> Ak {
    Ak::new("u:secretmap.0").unwrap()
}

fn edge(role: Role) -> ct::Edge {
    ct::Edge { role, until: None, invite: None, tied: None, floor: None }
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
}

/// Node 0 makes thing t (a value), grants node 1's account sync and node 2's write; both accept;
/// node 2 writes another value and node 0 a map key; synced to quiet. Built once per process.
fn scenario() -> (World, Tid, SyncId) {
    let (w, t, s, _) = scenario_b();
    (w, t, s)
}

/// `scenario` and the commit of node 2's value (`MARK_B`).
pub(crate) fn scenario_b() -> (World, Tid, SyncId, osis_base::CommitId) {
    let (w, (t, s, b)) = fixture_with("metadata scenario", || {
        let mut w = World::new(0);
        w.record = true;
        w.cap = 3 * crate::harness::RULE_CAP;
        for _ in 0..3 {
            w.add_node();
        }
        introduce(&mut w);
        w.run();
        let (a0, a1, a2) = (w.node(0).account.unwrap(), w.node(1).account.unwrap(), w.node(2).account.unwrap());
        let t = w.write(0, |e| {
            let mut m = Mutation::new();
            let t = e.new_thing(&mut m, a0);
            m.set(t, &value_ak(), &Value::Str(MARK_A.into())).unwrap();
            e.commit(m).unwrap();
            t
        });
        file(&mut w, 0, vec![t], Vec::new());
        w.write(0, |e| e.grant(&t, &a1, &edge(Role::Sync))).unwrap();
        w.write(0, |e| e.grant(&t, &a2, &edge(Role::Write))).unwrap();
        w.run();
        file(&mut w, 1, Vec::new(), vec![t]);
        file(&mut w, 2, Vec::new(), vec![t]);
        w.run();
        let b = w.write(2, |e| {
            let mut m = Mutation::new();
            m.set(t, &value_ak(), &Value::Str(MARK_B.into())).unwrap();
            e.commit(m).unwrap().unwrap()
        });
        w.write(0, |e| {
            let mut m = Mutation::new();
            let mut map = osis_base::ValueMap::default();
            map.insert(Value::Str(MAP_KEY.into()), Value::Int(1));
            m.set(t, &map_ak(), &Value::Map(map)).unwrap();
            e.commit(m).unwrap();
        });
        w.run();
        w.advance(60_000);
        w.run();
        assert_eq!(w.engine(0).get(&t, &value_ak()).unwrap(), Some(Value::Str(MARK_B.into())), "node 2's write reached node 0");
        let s = w.engine(0).home_sync_id(&t).unwrap().unwrap();
        assert_eq!(w.engine(1).thing_sync(&t).unwrap(), osis_engine::sync::ThingSync::Unread(vec![s]), "node 1 keeps t unread");
        assert!(w.store(1).entries(&s).unwrap().len() >= 4, "node 1 holds the writes");
        (w, (t, s, b))
    });
    (w, t, s, b)
}

/// What node 1 must not learn: t's values, map key, content AKs and role secrets, the writers'
/// node tids and signing keys; then (named `ak ...`) the core AKs, which node 1's own things carry.
fn needles(w: &mut World, t: Tid) -> Vec<(String, Vec<u8>)> {
    let mut needles: Vec<(String, Vec<u8>)> = vec![
        ("value a".into(), MARK_A.as_bytes().to_vec()),
        ("value b".into(), MARK_B.as_bytes().to_vec()),
        ("map key".into(), MAP_KEY.as_bytes().to_vec()),
        ("value ak".into(), value_ak().as_str().as_bytes().to_vec()),
        ("map ak".into(), map_ak().as_str().as_bytes().to_vec()),
    ];
    let ep = w.engine(0).epochs(&t).unwrap();
    for r in [Role::Read, Role::Write, Role::Admin] {
        let (_, sec) = ep.role(r).newest_secret().unwrap();
        needles.push((format!("{r:?} secret of t"), sec.expose().to_vec()));
    }
    let mut clear = needles;
    for i in [0, 2] {
        let tid = w.engine(i).tid();
        clear.push((format!("node {i} tid"), tid.as_bytes().to_vec()));
        let pk = w.engine(i).identity().keys().signing.verifying_key().to_bytes();
        clear.push((format!("node {i} signing key"), pk.to_vec()));
    }
    for ak in ["roles.0", "secrets.0", "keys.0", "sync.0", "group.0", "created.0"] {
        clear.push((format!("ak {ak}"), ak.as_bytes().to_vec()));
    }
    clear
}

// spec/requirements.md Data a node cannot read (it must not learn identifiers, keys, values,
// authors, role grants, node identities), spec/sync-ids.md §2 (What a sync holder learns: of the
// thing, its tid alone): no value, map key, content AK, role secret of t, or the writers' node
// tids and signing keys reach node 1's store device, live or overwritten, in clear. Control: the
// search sees S's blobs.
#[test]
fn a_node_keeping_s_unread_stores_nothing_forbidden_spec_sync_ids_2() {
    let (mut w, t, s) = scenario();
    let clear = needles(&mut w, t);
    let (history, live, blobs) = w.recorded(1);
    assert!(history.len() > 20 && blobs.len() > 4, "the scenario stored something");
    // control: a blob node 1 holds under S is found among the blobs searched
    let held = w.store(1).entries(&s).unwrap()[0].blob;
    let held = w.store(1).bytes(&held).unwrap().unwrap();
    assert!(blobs.iter().any(|b| contains(b, &held[..32])), "the search sees S's blobs");
    for (what, needle) in &clear {
        for (k, v) in history.iter().chain(&live) {
            assert!(!contains(k, needle) && !contains(v, needle), "{what} in clear in node 1's store rows");
        }
        for b in &blobs {
            assert!(!contains(b, needle), "{what} in clear in a blob node 1 stores");
        }
    }
}

// spec/requirements.md Data a node cannot read, spec/sync-ids.md §2 (What a sync holder learns):
// as above, searched in everything an attacker holding node 1's whole device decrypts (every row
// and blob since it was made, its store keys and read secrets; notes/test-security.md), every
// needle but the core AKs. Control: the attack recovers rows naming S's sync ID.
#[test]
#[ignore = "by hand: the forensic attack on a node keeping S unread costs about 350 G instructions in debug"]
fn a_node_keeping_s_unread_yields_nothing_forbidden_to_its_devices_attacker_spec_sync_ids_2() {
    let (mut w, t, s) = scenario();
    let clear = needles(&mut w, t);
    let plain: Vec<Vec<u8>> = w.forensic(1).into_iter().map(|r| r.plain).collect();
    assert!(plain.iter().any(|p| contains(p, &s.0)), "the attack opens node 1's rows naming S");
    // node 1's own things carry the core AKs: every other needle
    for (what, needle) in clear.iter().filter(|(w, _)| !w.starts_with("ak ")) {
        assert!(!plain.iter().any(|p| contains(p, needle)), "{what} recovered from node 1's device");
    }
}

// spec/wire.md §5 (padding: Padmé), spec/requirements.md Data a node cannot read (it may
// learn padded sizes): every blob node 1 holds under S has a Padmé length of padded plaintext.
#[test]
fn blobs_kept_unread_have_padme_lengths_spec_wire_5() {
    let (w, _, s) = scenario();
    let entries = w.store(1).entries(&s).unwrap();
    assert!(entries.len() >= 4);
    for e in entries {
        let Some(b) = w.store(1).bytes(&e.blob).unwrap() else { continue };
        let p = osis_label::Prefix::parse(&b).unwrap();
        let n = b.len() - p.len() - 16;
        assert_eq!(osis_crypto::padme(n), n, "blob {:?}: {n} bytes is not a Padmé length", e.blob);
    }
}
