//! An account's nodes through the API (spec/permissions.md §5.4-§5.5; notes/engine-validity-epochs.md):
//! what the engine's `rotation::tests_signing` and `tests_account` leave untested.

use crate::common::*;
use osis::internals::Internals as _;
use osis::{Osis, Role, SetRoleOpts};

// spec/crypto.md §4 (Departs mark: a role commit's `ts`, author and `blind`), spec/wire.md §4:
// two nodes of one account changing roles in one millisecond write commits of one `ts` and one
// author; their blinds differ, so their departs marks do (a paired node draws its own).
#[test]
fn siblings_role_commits_at_one_ts_have_distinct_departs_marks_spec_crypto_4() {
    let (a, b, c) = paired();
    let (r, s) = (db(3), db(4));
    for d in [&a, &b] {
        deliver(&r, d);
        deliver(&s, d);
    }
    let t = a.commit_with(|w| w.create_held()).unwrap();
    deliver(&a, &b);
    deliver(&b, &a);
    c.advance(1000);
    a.set_role(t, r.me(), Some(Role::Read), SetRoleOpts::default()).unwrap();
    b.set_role(t, s.me(), Some(Role::Read), SetRoleOpts::default()).unwrap();
    let newest = |d: &Osis| d.engine(|e| e.commit_ids().iter().filter_map(|id| e.header(id).map(|h| (h.ts, h.author, h.blind))).max_by_key(|x| x.0).unwrap());
    let (x, y) = (newest(&a), newest(&b));
    assert_eq!((x.0, x.1), (y.0, y.1), "one ts, one author");
    assert_ne!(x.2, y.2, "distinct blinds");
}
