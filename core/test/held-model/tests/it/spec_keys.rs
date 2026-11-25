//! spec/crypto.md §7 Checked keys, spec/commits.md §4 Unjudgeable: a part whose commit lists for
//! its thing a level-1 or level-3 key no held step places is unjudgeable until one does.
use crate::util::*;
use held_model::*;

/// `sync.0` (a role-class aspect).
const SYNC: Aspect = Aspect { name: 101, admin_only: false, signal: false, external: false };
/// Genesis step 100 of node 0 (minted with a key, `T`'s mint admin) bears keys 1 and 2; its child
/// 101, keys 3 and 4.
const GENESIS: StepRec = StepRec { id: 100, parent: None, delete: 1, write: 2 };
const CHILD: StepRec = StepRec { id: 101, parent: Some(100), delete: 3, write: 4 };

/// A role commit by `author` at hour `h` recording `steps` on `thing`.
fn steps(id: CommitId, author: NodeId, h: u64, thing: ThingId, steps: &[StepRec]) -> Commit {
    let p = Part { thing, aspect: SYNC, keys: Keys { listed: vec![], steps: steps.to_vec() }, ..part(SYNC, PurgeBy::Admin, vec![]) };
    Commit { kind: CommitKind::Role, ..content(id, author, h, vec![p]) }
}

/// Node 0's write of `v` on `T` at hour `h` listing step `s`'s keys.
fn listing(id: CommitId, h: u64, s: StepRec, v: i64) -> Commit {
    let mut c = reg(id, MINT_ADMIN, h, REG, PurgeBy::AuthorOrAdmin, v);
    c.parts[0].keys.listed = vec![(KeyLevel::Admin, s.delete), (KeyLevel::Writer, s.write)];
    c
}

const REG: Aspect = Aspect { name: 1, admin_only: false, signal: false, external: false };

fn judged(commits: Vec<Commit>, c: CommitId) -> (Option<bool>, Option<Value>) {
    let h = held(5, commits);
    let o = evaluate(&h);
    (o.valid.get(&(c, 0)).copied().filter(|_| o.applied.contains(&c)), o.reads.get(&(T, REG)).cloned().flatten())
}

// A write on `T` listing the keys of step 100 of node 0 (up `T`'s record chain): right once a
// valid `sync.0` write recorded before it on node 0 holds the step; with none held it applies
// nowhere and reads nothing, whatever else is held.
#[test]
fn a_listed_key_is_right_once_a_held_step_places_it_spec_crypto_7() {
    let s = steps(20, MINT_ADMIN, 1, MINT_ADMIN, &[GENESIS]);
    let w = listing(21, 2, GENESIS, 7);
    assert_eq!(judged(vec![s.clone(), w.clone()], 21), (Some(true), int(7)), "the step recorded before it places the keys");
    let (v, r) = judged(vec![w.clone()], 21);
    assert_ne!(v, Some(true));
    assert_eq!(r, None, "no held step: unjudgeable, applies nowhere");
    let o = evaluate(&held(5, vec![w.clone()]));
    assert!(!o.applied.contains(&21) && o.revisit.contains(&21), "every part unjudgeable: the commit pends, not held");
    // control: the step recorded after the write places nothing for it
    let late = steps(20, MINT_ADMIN, 3, MINT_ADMIN, &[GENESIS]);
    assert_eq!(judged(vec![late, w.clone()], 21).1, None, "a step recorded after the write");
    // control: a step recorded by a node holding no admin on node 0 is no valid write
    let forged = steps(20, 1, 1, MINT_ADMIN, &[GENESIS]);
    assert_eq!(judged(vec![forged, w], 21).1, None, "a step recorded by an invalid write");
}

// A step is placed only on a path from a genesis step every step of which is recorded: a child
// step alone places nothing.
#[test]
fn a_step_is_placed_with_its_path_from_the_genesis_spec_crypto_7() {
    let w = listing(21, 3, CHILD, 7);
    let child = steps(22, MINT_ADMIN, 2, MINT_ADMIN, &[CHILD]);
    assert_eq!(judged(vec![child.clone(), w.clone()], 21).1, None, "the child without its parent");
    let genesis = steps(20, MINT_ADMIN, 1, MINT_ADMIN, &[GENESIS]);
    assert_eq!(judged(vec![genesis, child, w], 21), (Some(true), int(7)));
}
