#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Core aspect Rust types and typed keys (spec/data-model.md §9, spec/wire.md §3). A sample of
//! each core aspect, its schema fields and round trips: the `schema/core` generator of osis-vectors.

use osis_base::{Ak, Classified, CreationRecord, ErrorClass, Role, Tid, Value};
use osis_schema::core_types::*;
use osis_schema::*;
use std::collections::BTreeMap;

fn tid(n: u8) -> Tid {
    Tid::from_bytes([n; 15])
}

#[test]
fn fixed_lengths_and_unknown_cases_spec_wire_3() {
    // A KEM key of the wrong length is malformed.
    let short = Value::Enum(1, Some(Box::new(Value::Bytes(vec![0; 10]))));
    let e = KemKey::from_value(&short).unwrap_err();
    assert_eq!(e.class(), ErrorClass::BadInput);
    // An unknown agility case is newer data: parked.
    let e = KemKey::from_value(&Value::Enum(2, Some(Box::new(Value::Bytes(vec![]))))).unwrap_err();
    assert_eq!((e.kind.clone(), e.class()), (PathErrorKind::UnknownCase(2), ErrorClass::Parked));
    // An unknown role case in a holder grant: parked, with the path.
    let mut m = ROLES.encode(&BTreeMap::from([(tid(1).into(), Grant { role: Role::Read, until: None, may_grant: false, retain: false, floor: None })]));
    if let Value::Map(mm) = &mut m {
        let e = mm.get_mut(&Value::Weak(tid(1))).unwrap();
        if let Value::Map(f) = e {
            f.insert(Value::Int(0), Value::Enum(9, None));
        }
    }
    let e = ROLES.decode(&m).unwrap_err();
    assert_eq!(e.kind, PathErrorKind::UnknownCase(9));
    assert_eq!(e.path, p![osis_schema::osis_base::Weak(tid(1)), FieldId(0)]);
    // created.0: an unknown signing key case parks; both admin and key is bad input.
    let rec = CreationRecord::with_key(osis_base::SignKey([3; 32]), [4; 32]).to_value();
    let Value::Map(mut f) = rec else { panic!() };
    f.insert(Value::Int(1), Value::Enum(7, Some(Box::new(Value::Bytes(vec![0; 40])))));
    assert_eq!(CREATED.decode(&Value::Map(f.clone())).unwrap_err().class(), ErrorClass::Parked);
    f.insert(Value::Int(1), Value::Enum(1, Some(Box::new(Value::Bytes(vec![3; 32])))));
    f.insert(Value::Int(0), Value::Weak(tid(1)));
    assert_eq!(CREATED.decode(&Value::Map(f)).unwrap_err().class(), ErrorClass::BadInput);
    // Reader defaults: an keys.0 written with only some fields reads with none for the rest.
    let k = KEYS.decode(&Value::Map(osis_base::ValueMap::new())).unwrap();
    assert_eq!(k, Keys::default());
}

#[test]
fn key_defaults_and_identity_spec_commits_5() {
    let m = ROLES.defaults();
    assert_eq!((m.purge_by, m.expires), (PurgeBy::Admin, None));
    for ak in ROLE_CLASS {
        let a = &core_schema().aspects[ak];
        assert_eq!(a.purge_by, PurgeBy::Admin, "{ak}");
        assert!(is_role_class(ak));
    }
    assert!(!is_role_class("tag.0"));
    assert_eq!(CREATED.defaults().purge_by, PurgeBy::Admin);
    assert_eq!(DIAL.defaults(), AspectDefaults::default());
    assert!(TAG.schema().is_some_and(Schema::declares_core));
    let untyped = Ak::new("x:y.0").unwrap();
    assert!(untyped.schema().is_none());
    assert_eq!(untyped.defaults(), AspectDefaults::default());
    assert_eq!(RawKey::decode(&untyped, &Value::Int(3)).unwrap(), Value::Int(3));
    assert!(core_schema().aspects["aspects.0"].flags.contains(&Flag::Synthetic));
    assert!(core_schema().aspects["created.0"].flags.contains(&Flag::Guaranteed));
}
