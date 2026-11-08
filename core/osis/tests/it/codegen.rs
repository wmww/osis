//! Codegen output compiled (build.rs, `crate::schemas`): typed keys of osis-schema's fixture
//! (core/schema/tests/example.osis) round-trip through spec/versioning.md §5 typed reads, and the
//! generated core and meta modules agree with the hand-written ones.

use crate::schemas::{core_gen, example, meta};
use osis_base::{Float, Tid, Value};
use osis_schema::*;
use std::collections::{BTreeMap, BTreeSet};

fn task() -> example::Task {
    example::Task {
        title: "t".into(),
        done: false,
        tags: BTreeSet::from(["a".to_string()]),
        priority: Some(example::Priority::Custom(7)),
        due: None,
        status: Some(example::Status::Blocked),
        weight: Float::new(2.0),
    }
}

#[test]
fn generated_types_round_trip_through_keys_spec_versioning_5() {
    let tasks = vec![task()];
    let v = example::TASKS.encode(&tasks);
    example::TASKS.validate(&v).unwrap();
    assert_eq!(example::TASKS.decode(&v).unwrap(), tasks);
    assert_eq!(example::TASKS.schema().unwrap().revision, 4);
    assert_eq!(example::LAST_OPENED.defaults().expires, Some(30 * 86_400_000));
    // Reader defaults apply through TryFrom: an old task without fields 3..8.
    let old = Value::Map(osis_base::ValueMap::from([(Value::Int(1), Value::Str("x".into())), (Value::Int(2), Value::Bool(true))]));
    let t = example::Task::try_from(&old).unwrap_err();
    assert_eq!(t.kind, PathErrorKind::MissingField(3), "tags has no default");
    let mut old = old;
    if let Value::Map(m) = &mut old {
        m.insert(Value::Int(3), Value::Set(osis_base::ValueSet::new()));
    }
    let t = example::Task::try_from(&old).unwrap();
    assert_eq!((t.priority, t.status, t.weight), (None, None, Float::new(1.0)));
    // Unknown fields are ignored on read.
    if let Value::Map(m) = &mut old {
        m.insert(Value::Int(99), Value::Int(0));
    }
    assert!(example::Task::try_from(&old).is_ok());
    // Parametric type and a signal aspect.
    let pinned = BTreeMap::from([(Tid::from_bytes([1; 15]), example::Tagged { label: "l".into(), value: 3i64 })]);
    let v = example::PINNED.encode(&pinned);
    assert_eq!(example::PINNED.decode(&v).unwrap(), pinned);
    let ty = example::Typing { who: Tid::from_bytes([2; 15]), at: 5 };
    assert_eq!(example::TYPING.decode(&example::TYPING.encode(&ty)).unwrap(), ty);
    // Field and case constants build paths.
    assert_eq!(p![0, example::task::DONE], Path(vec![Step::Index(0), Step::Field(2)]));
    assert_eq!(example::priority::CUSTOM, CaseId(3));
}

#[test]
fn generated_core_matches_hand_written_spec_data_model_9() {
    use osis_schema::core_types as hw;
    let g = core_gen::Group { items: BTreeSet::from([Tid::from_bytes([1; 15])]), subgroups: BTreeSet::new() };
    let v = core_gen::GROUP.encode(&g);
    assert_eq!(hw::GROUP.decode(&v).unwrap().items, g.items);
    let r = core_gen::Role::Admin;
    assert_eq!(Codec::to_value(&r), Codec::to_value(&osis_base::Role::Admin));
}

#[test]
fn generated_meta_reads_schema_values_spec_data_model_10() {
    // The schema of schemas, generated, reads every schema value (recursive type_expr boxed).
    let v = core_schema().to_value();
    let s = meta::Schema::try_from(&v).unwrap();
    assert_eq!(s.revision, 1);
    assert!(s.aspects.contains_key("roles.0"));
    let ty = &s.aspects["roles.0"].r#type;
    assert!(matches!(ty.as_ref(), meta::TypeExpr::Map(_)));
    assert_eq!(Codec::to_value(&s), v);
}
