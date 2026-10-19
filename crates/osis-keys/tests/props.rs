#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Random membership histories of one actor (spec/crypto.md §4, spec/permissions.md §3): a
//! member departed from a role before an epoch was made opens nothing of that role at it; every
//! current member opens the newest epoch of each of its roles after every step.

mod common;
use common::*;
use osis_core::{Role, Tid};
use osis_crypto::{Epoch, Secret32};
use osis_keys::{
    ActorEpochs, MemberKeys, Opener, ROLES, Recipient, box_member, ingest, roles_up_to, rotate,
};
use osis_schema::core_types::Secrets;
use proptest::prelude::*;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug)]
enum Op {
    Grant(usize, Role),
    Remove(usize),
    Demote(usize, Role),
    Rotate(Role),
    Fork,
}

fn op() -> impl Strategy<Value = Op> {
    let role = prop_oneof![Just(Role::Read), Just(Role::Write), Just(Role::Admin)];
    prop_oneof![
        3 => (0..POOL, role.clone()).prop_map(|(i, r)| Op::Grant(i, r)),
        2 => (0..POOL).prop_map(Op::Remove),
        1 => (0..POOL, role.clone()).prop_map(|(i, r)| Op::Demote(i, r)),
        1 => role.prop_map(Op::Rotate),
        1 => Just(Op::Fork),
    ]
}

const POOL: usize = 4;

/// Roles lost, and the epochs per role known when it departed.
type Departed = (BTreeSet<Role>, BTreeMap<Role, BTreeSet<Epoch>>);

enum Kind {
    Actor(ActorEpochs),
    Key(Secret32),
}

struct Sim {
    a: Tid,
    p: Tid,
    pe: ActorEpochs,
    pool: Vec<(Tid, Kind)>,
    roster: BTreeMap<usize, Role>,
    /// Ever removed or demoted: never re-granted, so the property is about pure departures.
    departed: BTreeMap<usize, Departed>,
    view: ActorEpochs,
    s: Secrets,
    seed: u64,
}

impl Sim {
    fn new() -> Sim {
        let (a, p, pe) = (tid(1), tid(2), person(0x20));
        let pool = (0..POOL)
            .map(|i| {
                let t = tid(10 + i as u8);
                let k = if i % 2 == 0 { Kind::Actor(person(0x30 + i as u8)) } else { Kind::Key(Secret32::from_bytes([0x60 + i as u8; 32])) };
                (t, k)
            })
            .collect();
        let mut sim = Sim { a, p, pe: pe.clone(), pool, roster: BTreeMap::new(), departed: BTreeMap::new(), view: ActorEpochs::derived(&pe, &a), s: Secrets::default(), seed: 0 };
        sim.rotate(&roles_up_to(Role::Admin));
        sim
    }

    fn rcpt(&self, i: usize, role: Role) -> Recipient {
        let (t, k) = &self.pool[i];
        match k {
            Kind::Actor(e) => actor_rcpt(*t, role, e),
            Kind::Key(seed) => key_rcpt(*t, role, seed),
        }
    }

    fn members(&self) -> Vec<Recipient> {
        let mut v = vec![Recipient { member: self.p, role: Role::Admin, keys: MemberKeys::from_keys(&keys_of(&self.pe)).unwrap().with_own(&self.pe) }];
        v.extend(self.roster.iter().map(|(i, r)| self.rcpt(*i, *r)));
        v
    }

    fn next_rng(&mut self) -> osis_crypto::SeededRng {
        self.seed += 1;
        rng(self.seed)
    }

    fn rotate(&mut self, roles: &BTreeSet<Role>) {
        let mut r = self.next_rng();
        let rot = rotate(&self.a, roles, &self.view, &self.s, &self.members(), &|_, _| true, &mut r).unwrap();
        assert!(rot.unboxed.is_empty());
        rot.secrets.apply(&mut self.s);
        rot.record(&mut self.view);
    }

    fn step(&mut self, op: &Op) {
        match *op {
            Op::Grant(i, role) if !self.roster.contains_key(&i) && !self.departed.contains_key(&i) => {
                self.roster.insert(i, role);
                let mut r = self.next_rng();
                let w = box_member(&self.a, &self.view, &self.s, &self.rcpt(i, role), &roles_up_to(role), &mut r).unwrap().unwrap();
                w.apply(&mut self.s);
            }
            Op::Remove(i) | Op::Demote(i, _) if self.roster.contains_key(&i) => {
                let held = self.roster[&i];
                let new = match op {
                    Op::Demote(_, to) if *to < held => Some(*to),
                    Op::Demote(..) => return,
                    _ => None,
                };
                let lost: BTreeSet<Role> = ROLES.into_iter().filter(|r| Some(*r) > new && *r <= held).collect();
                match new {
                    Some(r) => self.roster.insert(i, r),
                    None => self.roster.remove(&i),
                };
                let known: BTreeMap<Role, BTreeSet<Epoch>> = ROLES.into_iter().map(|r| (r, self.view.role(r).epochs().map(|(e, _)| *e).collect())).collect();
                self.departed.insert(i, (lost.clone(), known));
                // The departure and its rotation are one commit (spec/permissions.md §3).
                self.rotate(&lost);
            }
            Op::Rotate(r) => self.rotate(&[r].into_iter().collect()),
            Op::Fork => {
                let base = (self.view.clone(), self.s.clone());
                let mut forks = Vec::new();
                for _ in 0..2 {
                    let mut r = self.next_rng();
                    forks.push(rotate(&self.a, &[Role::Read].into_iter().collect(), &base.0, &base.1, &self.members(), &|_, _| true, &mut r).unwrap());
                }
                for f in &forks {
                    f.secrets.apply(&mut self.s);
                    f.record(&mut self.view);
                }
            }
            _ => {}
        }
        // No re-seal: a key actor demoted below its box's key keeps its lower roles through the
        // demotion's rotation (spec/crypto.md §4).
    }

    fn opened(&self, i: usize) -> ActorEpochs {
        let (t, k) = &self.pool[i];
        let mut v = ActorEpochs::default();
        let opener = match k {
            Kind::Actor(e) => Opener::Actor { member: *t, epochs: e },
            Kind::Key(seed) => Opener::KeyActor { member: *t, seed },
        };
        let errs = ingest(&self.a, &self.s, &opener, &mut v).unwrap();
        assert!(errs.is_empty(), "{errs:?}");
        v
    }

    fn check(&self) {
        for (i, role) in &self.roster {
            let v = self.opened(*i);
            for r in ROLES.into_iter().filter(|r| r <= role) {
                let newest = self.view.role(r).newest().unwrap();
                assert!(v.role(r).secret(&newest).is_some(), "member {i} role {r:?}");
            }
            // Holding the state as a compaction snapshot, it agrees on the newest epoch.
            let mut sv = v.clone();
            osis_keys::snapshot_keyed(&self.s, &mut sv).unwrap();
            assert!(osis_keys::may_compact_secrets(&self.s, &sv).unwrap());
            for r in ROLES.into_iter().filter(|r| r <= role) {
                assert_eq!(sv.role(r).newest_held().map(|x| x.0), self.view.role(r).newest(), "member {i} role {r:?}");
            }
        }
        for (i, (lost, known)) in &self.departed {
            let v = self.opened(*i);
            for r in lost {
                for (e, _) in v.role(*r).held() {
                    assert!(known[r].contains(&e), "departed {i} opens {r:?} at {e:?}");
                }
            }
        }
    }
}

proptest! {
    // spec/crypto.md §4, spec/permissions.md §3: departed members open nothing newer; current
    // members open the newest epoch of each of their roles and, establishing from a snapshot of
    // the state, agree on it.
    #[test]
    fn departures_and_current_members(ops in prop::collection::vec(op(), 1..10)) {
        let mut sim = Sim::new();
        for o in &ops {
            sim.step(o);
            sim.check();
        }
    }
}
