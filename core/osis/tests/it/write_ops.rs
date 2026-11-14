#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! The `Write` recorder: generic helpers over value keys, ranges, clashes.

use crate::common::TestWrites as _;
use crate::common::*;
use osis::{Osis, Tid, Value, p};

use crate::schemas::example;

// spec: none (notes/api.md Keys): an app's generic helper over value aspects names `osis::ValueKey` alone, with or without a value type, and takes generated keys and `osis::DynamicAspectKey`
#[test]
fn a_generic_helper_names_value_key() {
    fn set_and_read<K: osis::ValueKey + Clone>(db: &Osis, t: Tid, k: K, v: &K::T) -> osis::Result<Option<K::T>> {
        let mut w = db.write();
        w.at(t, k.clone()).set(v)?;
        w.commit()?;
        db.at(t, k).get()
    }
    fn title_of<K: osis::ValueKey<T = String>>(db: &Osis, t: Tid, k: K) -> osis::Result<String> {
        Ok(db.at(t, k).get()?.unwrap_or_default())
    }
    let db = db(0);
    let mut w = db.write();
    let t = w.create().unwrap();
    w.commit().unwrap();
    let key = db.aspect_key("app:h.0").unwrap();
    assert_eq!(set_and_read(&db, t, key, &Value::Int(1)).unwrap(), Some(Value::Int(1)));
    assert_eq!(set_and_read(&db, t, example::TITLE, &"x".to_string()).unwrap().as_deref(), Some("x"));
    assert_eq!(title_of(&db, t, example::TITLE).unwrap(), "x");
}

// spec: none (notes/api.md Writes): a backward range moves nothing and says so
#[test]
fn a_backward_move_range_is_invalid() {
    let db = db(0);
    let k = ak("app:m.0");
    let mut w = db.write();
    let t = w.create().unwrap();
    #[allow(clippy::reversed_empty_ranges)]
    let back = 2..1;
    assert!(matches!(w.at(t, osis::DynamicAspectKey::untyped(k)).path(p![]).move_range(back, 0), Err(osis::Error::Invalid(_))));
}

// spec/commits.md §6, notes/api.md Writes: what clashes is judged on what the ops ask, not on what they
// turn out to write, so the same calls clash whatever the state: a `set` of the value already there
// counts, and a key's default names itself in the error.
#[test]
fn a_clash_is_judged_on_what_is_asked() {
    let db = db(0);
    db.register_schema("rv.osis", "revision 1;\nexpires(30d) aspect app:d.0: int;\naspect app:p.0: int;").unwrap();
    let t = db.commit_with(|w| {
        let t = w.create()?;
        w.at(t, osis::DynamicAspectKey::untyped(ak("app:a.0"))).set(&Value::Int(0))?;
        Ok(t)
    })
    .unwrap();
    let (d, plain) = (db.aspect_key("app:d.0").unwrap(), db.aspect_key("app:p.0").unwrap());
    db.commit_set(t, d.clone(), &Value::Int(1)).unwrap();
    let mut w = db.write();
    w.at(t, d.clone()).set(&Value::Int(1)).unwrap();
    w.at(t, plain.clone()).set(&Value::Int(1)).unwrap();
    assert!(matches!(w.commit(), Err(osis::Error::Invalid(m)) if m.contains("app:d.0") && m.contains("app:p.0")));
    assert_eq!(db.at(t, plain).get().unwrap(), None);
}
