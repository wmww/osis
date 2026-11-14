#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Sharing across nodes in process, commits carried by hand (notes/api.md Sharing and roles).

use osis::internals::Internals as _;
use crate::common;
use common::*;
use osis::{SetRoleOpts, Error, Role, Value};

fn s(x: &str) -> Value {
    Value::Str(x.into())
}

// spec/crypto.md §7 (a writer lists the thing's delete keys), notes/api.md Rights: a role whose
// delete keys are not here yet (no inbox hint, the thing's `keys.0` in a later batch: another node
// of the grantee's account, a group's grant learned from its certificate copy) reads as `Read`
// and a content write on it is `Permission`, until the keys come; then both say the role. An
// admin's calls are `Permission { needs: Admin }` meanwhile alike, by the same rule.
#[test]
fn role_before_delete_keys_reads_as_read_spec_crypto_7() {
    for role in [Role::Write, Role::Admin] {
        let (alice, bob, carol, dave) = (db(1), db(2), db(3), db(4));
        deliver(&bob, &alice);
        deliver(&carol, &alice);
        deliver(&dave, &bob);
        let mut w = alice.write();
        let t = w.create().unwrap();
        w.at(t, osis::DynamicAspectKey::untyped(ak("t:x.0"))).set(&s("one")).unwrap();
        w.commit().unwrap();
        // the first holder gives `t` secrets of its own: its `keys.0` goes in that commit
        alice.grant(t, carol.me(), Role::Read, Default::default()).unwrap();
        alice.grant(t, bob.me(), role, Default::default()).unwrap();
        let keys = ak("keys.0");
        let (later, now): (Vec<_>, Vec<_>) = alice.engine(|e| {
            e.commit_ids().into_iter().map(|id| (e.header(&id).unwrap().aspects.iter().any(|a| a.tid == t && a.ak == keys), e.package(&id).unwrap().unwrap())).partition(|(k, _)| *k)
        });
        assert_eq!(later.len(), 1, "one commit carries t's keys.0");
        for (_, pk) in &now {
            bob.engine(|e| e.ingest(&pk.bytes, pk.blobs.clone()).unwrap());
        }
        let write = |v: &str| {
            let mut w = bob.write();
            w.at(t, osis::DynamicAspectKey::untyped(ak("t:x.0"))).set(&s(v))?;
            w.commit().map(drop)
        };
        assert_eq!(bob.engine(|e| e.role_on(&t)), Some(role), "the grant is here");
        assert_eq!(bob.role_on(t).unwrap(), Some(Role::Read));
        assert!(matches!(write("two"), Err(Error::Permission { tid, needs: Role::Write }) if tid == t));
        let grant = || bob.grant(t, dave.me(), Role::Read, Default::default());
        if role == Role::Admin {
            let r = grant();
            assert!(matches!(r, Err(Error::Permission { tid, needs: Role::Admin }) if tid == t), "grant: {r:?}");
            let r = bob.set_role(t, carol.me(), None, SetRoleOpts::default());
            assert!(matches!(r, Err(Error::Permission { tid, needs: Role::Admin }) if tid == t), "set_role: {r:?}");
            assert_eq!(bob.grants(t).unwrap().get(&carol.me()).map(|g| g.role), Some(Role::Read), "nothing written");
        }
        for (_, pk) in &later {
            bob.engine(|e| e.ingest(&pk.bytes, pk.blobs.clone()).unwrap());
        }
        assert_eq!(bob.role_on(t).unwrap(), Some(role));
        write("two").unwrap();
        if role == Role::Admin {
            grant().unwrap();
        }
    }
}

