//! Flows between nodes of different accounts end to end through the product's sync, nothing
//! carried by hand after the contact exchange (`introduce`).

use crate::harness::World;
use osis_base::{Role, Value};
use osis_engine::Mutation;
use osis_engine::flows::Demotion;
use osis_schema::core_types as ct;

pub(crate) fn edge(role: Role) -> ct::Edge {
    ct::Edge { role, until: None, invite: None, floor: None }
}


// spec/permissions.md §3 (Re-seal: a node that may rotate re-seals a current holder without a box
// at a current epoch; Complete pass: it decides at the end of a complete pass of the actor's sync
// IDs): node 0 grants node 2 read while node 1, an admin cut off from it, removes node 3 (a
// rotation); once healed node 2 has no box at node 1's epoch, and an admin re-seals it at the end
// of the complete pass a role commit from elsewhere began, so node 2 reads a write under it.
#[test]
fn a_raced_grant_is_resealed_at_a_complete_passs_end_spec_perm_3() {
    use crate::harness::Step::*;
    use crate::harness::history::{Gives, check, world};
    let mut w = world(0, 4);
    w.cap = crate::harness::STORM_CAP;
    let _ = crate::harness::play(&mut w, &[New(0), Grant(0, 0, 1, Gives::Writes), Grant(0, 0, 3, Gives::Reads), Run], String::new());
    let t = w.history.things[0].0;
    let a1 = w.node(1).account.unwrap();
    w.write(0, |e| e.grant(&t, &a1, &edge(Role::Admin))).unwrap();
    w.run();
    let _script = crate::harness::play(&mut w, &[Partition(0, 1), Partition(1, 2), Partition(1, 3), Grant(0, 0, 2, Gives::Reads), Run, Remove(1, 0, 3), Run, Heal, Run, Write(0, 0), Run], String::new());
    check(&mut w);
}

// spec/permissions.md §3 (removal logged first): a node that removes a holder logs the removal,
// in the same sync and before anything else it logs, under every sync ID the removed party could
// read. Node 0 writes t, then removes node 2's account from t, before its sync steps: the
// removal's entry under S is logged before the write's.
#[test]
#[ignore = "issues/removal-not-logged-first.md"]
fn repro_a_removal_is_logged_before_what_was_written_before_it_spec_permissions_3() {
    use crate::harness::Step::*;
    use crate::harness::history::{Gives, value_ak, world};
    let mut w = world(0, 3);
    w.cap = 20_000;
    let _ = crate::harness::play(&mut w, &[New(0), Grant(0, 0, 1, Gives::Syncs), Grant(0, 0, 2, Gives::Reads), Run], String::new());
    let t = w.history.things[0].0;
    let s = w.engine(0).sync_id_of(&t).unwrap().unwrap();
    let a2 = w.node(2).account.unwrap();
    // both written before node 0's sync next steps: one sync logs both
    let (c, r) = w.write(0, |e| {
        let mut m = Mutation::new();
        m.set(t, &value_ak(), &Value::Str("before the removal".into())).unwrap();
        let c = e.commit(m).unwrap().unwrap();
        (c, e.demote(&t, &Demotion { holder: a2, new: None, retain: None }).unwrap().commits[0])
    });
    w.run();
    let at = |w: &mut World, x: osis_base::CommitId| {
        let es = w.store(0).entries(&s).unwrap();
        let b = es.into_iter().find(|e| w.engine(0).blob_commit(&e.blob) == Some(x)).expect("an own entry under S").blob;
        w.store(0).first_logged(&s, &b).unwrap().expect("logged")
    };
    let (pc, pr) = (at(&mut w, c), at(&mut w, r));
    assert!(pr < pc, "the removal ({pr:?}) logged before the write ({pc:?})");
}

// spec/sync-inbox.md §1, spec/permissions.md §1: a node paired to an account pairs another
// (pairing): the third node is on D's roster and joins (`paired`), reading the rotation that
// added the second by the creation device's card.
#[test]
fn a_paired_node_pairs_another_spec_sync_inbox_1() {
    let mut w = crate::harness::siblings();
    let n = w.pair(2);
    w.run();
    assert!(w.engine(n).account_root().is_some());
}

// spec/sync-inbox.md §1, spec/permissions.md §1: a node pairs another after removing the device
// that paired it: the chain names the removed device, whose card the new node reads it by.
#[test]
fn a_node_pairs_another_after_removing_its_pairer_spec_sync_inbox_1() {
    let mut w = crate::harness::siblings();
    let n1 = w.engine(1).tid();
    w.write(2, |e| e.remove_device(&n1)).unwrap();
    w.run();
    let n = w.pair(2);
    w.run();
    assert!(w.engine(n).account_root().is_some());
    // the contact's card link K included, held through D
    holds_as_sibling(&mut w, n, 2);
}

// spec/sync-judgement.md §2 (a grant naming a holder travels under the holder's sync ID; for an
// account A, its account root's sync ID stands for A's own): a node paired once the inbox's
// fires are gone holds every thing its sibling holds with its current secrets. The commits giving
// the contact's card link K its epochs are wrapped under epochs the account took only by its
// inbox's ticket fire, and D's ticket gives K's current read secret alone: without K's boxes to
// the account under D the new node opens neither K's sync secret nor its history.
#[test]
fn a_node_paired_after_the_fires_expire_holds_its_siblings_secrets_spec_sync_judgement_2() {
    let mut w = crate::harness::contacts();
    w.advance(2 * osis_base::format::INBOX_LIFETIME_MS);
    w.run();
    let n = w.pair(1);
    w.run();
    holds_as_sibling(&mut w, n, 1);
}

/// New node `n` holds every thing with a sync ID its sibling `sib` holds, with its current sync
/// and read secrets.
fn holds_as_sibling(w: &mut World, n: usize, sib: usize) {
    let has = w.engine(n).things_with_sync_ids();
    for t in w.engine(sib).things_with_sync_ids() {
        assert!(has.contains(&t), "{t:?} lacks a `sync.0` at the new node");
        let (a, b) = (w.engine(sib).epochs(&t).unwrap(), w.engine(n).epochs(&t).unwrap());
        for r in [Role::Sync, Role::Read] {
            for e in a.role(r).current() {
                assert!(b.role(r).secret(&e).is_some(), "{t:?} {r:?} {} lacks its secret at the new node", e.n());
            }
        }
    }
}
