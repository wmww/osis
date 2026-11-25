//! Flows between nodes of different accounts end to end through the product's sync, nothing
//! carried by hand after the contact exchange (`introduce`).

use crate::harness::{World, edge};
use osis_base::{Role, Tid, Value};
use osis_engine::Mutation;
use osis_engine::flows::Demotion;


// spec/permissions.md §3 (Re-seal: a node that may rotate re-seals a current holder without a box
// at a current epoch; Complete pass: it decides at the end of a complete pass of the actor's sync
// IDs): node 0 grants node 2 read while node 1, an admin cut off from it, removes node 3 (a
// rotation); once healed node 2 has no box at node 1's epoch, and an admin re-seals it at the end
// of the complete pass a role commit from elsewhere began, so node 2 reads a write under it.
#[test]
fn a_raced_grant_is_resealed_at_a_complete_passs_end_spec_perm_3() {
    use crate::harness::Step::*;
    use crate::harness::history::{Gives, check, world_of};
    let mut w = world_of(0, 4, 4);
    w.cap = crate::harness::STORM_CAP;
    let _ = crate::harness::play(&mut w, &[New(0), Grant(0, 0, 1, Gives::Writes), Grant(0, 0, 3, Gives::Reads), Run], String::new());
    let t = w.history.things[0].0;
    let a1 = w.node(1).account.unwrap();
    w.write(0, |e| e.grant(&t, &a1, &edge(Role::Admin))).unwrap();
    w.run();
    let _script = crate::harness::play(&mut w, &[Partition(0, 1), Partition(1, 2), Partition(1, 3), Grant(0, 0, 2, Gives::Reads), Run, Remove(1, 0, 3), Run, Heal, Run, Write(0, 0), Run], String::new());
    check(&mut w);
}

// spec/permissions.md §3 (removal logged in its sync),
// spec/sync-judgement.md §3 (own store: what is logged together goes in `ts` order): node 0 writes
// an aspect of t, removes node 2's account from t, and writes other aspects of t (none covering
// another), all before its sync steps: one sync logs them all under S, in the order made. Enough writes that their commit IDs
// do not sort in that order (asserted), so logging in ID order fails this.
#[test]
fn a_removal_is_logged_before_what_was_written_after_it_spec_permissions_3() {
    use crate::harness::history::{Gives, three};
    let (mut w, t, s) = three(Gives::Reads, 1);
    w.cap = 20_000;
    let a2 = w.node(2).account.unwrap();
    let made: Vec<osis_base::CommitId> = w.write(0, |e| {
        let write = |e: &mut osis_engine::Engine, i: usize| {
            let mut m = Mutation::new();
            m.set(t, &osis_base::Ak::new(format!("u:w{i}.0")).unwrap(), &Value::Str(format!("write {i}"))).unwrap();
            e.commit(m).unwrap().unwrap()
        };
        let mut made = vec![write(e, 0)];
        made.push(e.demote(&t, &Demotion { holder: a2, new: None, retain: None }).unwrap().commits[0]);
        for i in 1..6 {
            made.push(write(e, i));
        }
        made
    });
    let mut by_id = made.clone();
    by_id.sort();
    assert_ne!(by_id, made, "the commit IDs sort in the order made: this reaches nothing");
    w.run();
    let at = |w: &mut World, x: osis_base::CommitId| {
        let es = w.store(0).entries(&s).unwrap();
        let b = es.into_iter().find(|e| w.engine(0).blob_commit(&e.blob) == Some(x)).expect("an own entry under S").blob;
        w.store(0).first_logged(&s, &b).unwrap().expect("logged")
    };
    let logged: Vec<_> = made.iter().map(|c| at(&mut w, *c)).collect();
    assert!(logged.windows(2).all(|p| p[0] < p[1]), "logged in the order made: {logged:?}");
}

// spec/sync-inbox.md §1, spec/permissions.md §1: a node paired to an account pairs another
// (pairing): the third node is on D's roster and joins (`paired`), reading the rotation that
// added the second by the creating node's card.
#[test]
fn a_paired_node_pairs_another_spec_sync_inbox_1() {
    let mut w = crate::harness::siblings();
    let n = w.pair(2);
    w.run();
    assert!(w.engine(n).node_root().is_some());
}

// spec/sync-judgement.md §2 (the key part of S's actor: on an account's D's and inbox's sync IDs, the account's),
// spec/permissions.md §4 Key part: a node paired past the inbox's lifetime, every offer's fire
// gone, holds every thing its sibling holds with its current secrets, by its account's key part
// under D's sync ID: the profile and inbox its account minted, and the contact's card link K,
// which the account was granted from outside.
#[test]
fn a_node_paired_past_the_inbox_lifetime_holds_its_siblings_secrets_spec_sync_judgement_2() {
    let mut w = crate::harness::contacts();
    w.advance(2 * osis_base::format::INBOX_LIFETIME_MS);
    w.run();
    let n = w.pair(1);
    w.run();
    holds_as_sibling(&mut w, n, 1);
}

/// New node `n` holds every thing with a sync ID its sibling `sib` holds but `sib`'s own things,
/// with the current sync and read secrets `sib` holds.
fn holds_as_sibling(w: &mut World, n: usize, sib: usize) {
    let has = w.engine(n).things_with_sync_ids();
    // the sibling's node thing and the link keys it redeemed by are its own alone
    // (spec/sync-set.md §1, §2 Own things)
    let own = w.engine(sib).me();
    let link_key = |w: &mut World, t: &Tid| w.engine(sib).core.created(t).is_some_and(|r| r.link_key_of().is_some());
    let ts: Vec<Tid> = w.engine(sib).things_with_sync_ids().into_iter().collect();
    let ts: Vec<Tid> = ts.into_iter().filter(|t| *t != own && !link_key(w, t)).collect();
    for t in ts {
        assert!(has.contains(&t), "{t:?} lacks a `sync.0` at the new node");
        // a `sync.0` held as evidence alone (steps placing listed keys, spec/permissions.md §4
        // Copies) comes with no secret
        let Some(a) = w.engine(sib).epochs(&t) else { continue };
        let b = w.engine(n).epochs(&t).unwrap();
        for r in [Role::Sync, Role::Read] {
            for e in a.role(r).current().into_iter().filter(|e| a.role(r).secret(e).is_some()) {
                assert!(b.role(r).secret(&e).is_some(), "{t:?} {r:?} {} lacks its secret at the new node", e.n());
            }
        }
    }
}

// spec/crypto.md §4 (State at a cut), §5 (Passing on: floors), notes/history-less-grant.md (From
// now means current state): node 0 writes t twice, then grants node 1's account read without
// history; node 1 holds t. Through sync alone it reads t's current value, holds no body carrying
// an earlier write of it, and reads what node 0 writes next.
#[test]
fn a_from_now_grantee_reads_the_current_state_and_no_earlier_write_spec_crypto_4() {
    use crate::harness::Step::*;
    use crate::harness::history::{value_ak, world_of};
    let mut w = world_of(0, 2, 2);
    let _ = crate::harness::play(&mut w, &[New(0), Write(0, 0), Run], String::new());
    let t = w.history.things[0].0;
    let before: Vec<(String, osis_base::CommitId)> = w.history.values.clone().into_iter().collect();
    assert_eq!(before.len(), 2, "two writes before the grant");
    let now = w.engine(0).get(&t, &value_ak()).unwrap().expect("a current value");
    let a1 = w.node(1).account.unwrap();
    w.write(0, |e| e.grant_with(&t, &a1, &edge(Role::Read), osis_engine::flows::edges::History::None)).unwrap();
    w.run();
    let _ = crate::harness::play(&mut w, &[Strong(1, None, 0), Run], String::new());
    assert_eq!(w.engine(1).get(&t, &value_ak()).unwrap(), Some(now), "the current state");
    for (v, c) in &before {
        let e = w.engine(1);
        let parts = e.body(c).unwrap().map(|b| b.parts).unwrap_or_default();
        let held = e.header(c).is_some_and(|h| parts.iter().any(|ai| h.aspects.get(*ai).is_some_and(|a| a.tid == t && a.ak == value_ak())));
        assert!(!held, "node 1 holds the write of {v:?} from before its grant");
    }
    let c = w.write(0, |e| {
        let mut m = Mutation::new();
        m.set(t, &value_ak(), &Value::Str("after".into())).unwrap();
        e.commit(m)
    });
    assert!(c.unwrap().is_some());
    w.run();
    assert_eq!(w.engine(1).get(&t, &value_ak()).unwrap(), Some(Value::Str("after".into())), "what follows the grant");
}

// spec/crypto.md §4 (State at a cut: a record whose minting lies below the cut goes as a
// certificate), spec/commits.md §4 (Records: a held strong awaits its target's record): a dependent
// thing p under t (carried under t's sync ID, as a chat's messages are) written before node 1's
// grant without history on t: node 1 reads p's current value through t's sync ID, and no earlier
// write of it. Its record rides in p's minting, below the cut, so it reaches node 1 only by a
// record blob, which node 1 learns for t's strong to p. A thing q made after the cut is minted
// above it: its record goes in its minting alone.
#[test]
fn a_from_now_grantee_reads_a_dependent_thing_minted_with_it_spec_crypto_4() {
    use crate::harness::Step::*;
    use crate::harness::history::{value_ak, world_of};
    let mut w = world_of(0, 2, 2);
    let _ = crate::harness::play(&mut w, &[New(0), NewIn(0, 0), Write(0, 1), Run], String::new());
    let (t, p) = (w.history.things[0].0, w.history.things[1].0);
    assert!(w.engine(0).sync_id_of(&p).unwrap().is_none(), "p is dependent");
    let before: Vec<osis_base::CommitId> = w.history.values.values().copied().collect();
    let now = w.engine(0).get(&p, &value_ak()).unwrap().expect("a current value");
    let a1 = w.node(1).account.unwrap();
    w.write(0, |e| e.grant_with(&t, &a1, &edge(Role::Read), osis_engine::flows::edges::History::None)).unwrap();
    w.run();
    let _ = crate::harness::play(&mut w, &[Strong(1, None, 0), Run], String::new());
    assert_eq!(w.engine(1).get(&p, &value_ak()).unwrap(), Some(now), "p's current state");
    for c in &before {
        let e = w.engine(1);
        let parts = e.body(c).unwrap().map(|b| b.parts).unwrap_or_default();
        assert!(!e.header(c).is_some_and(|h| parts.iter().any(|ai| h.aspects.get(*ai).is_some_and(|a| a.ak == value_ak()))), "node 1 holds a write from before its grant");
    }
    let _ = crate::harness::play(&mut w, &[NewIn(0, 0), Run], String::new());
    let q = w.history.things[2].0;
    assert!(w.engine(1).get(&q, &value_ak()).unwrap().is_some(), "q, made after the cut");
    let s = w.engine(0).sync_id_of(&t).unwrap().unwrap();
    let records = w.engine(0).certificate_records(&s).unwrap();
    assert!(records.contains(&p) && !records.contains(&q), "p's record goes as a certificate, q's in its minting");
}


