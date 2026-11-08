#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Codegen (notes/base-schema.md): generated modules for the example (tests/example.osis), core and meta schemas are checked
//! in under tests/gen, compiled here, and must equal a fresh generation (regenerate:
//! OSIS_REGEN_VECTORS=1). Typed keys round-trip through spec/versioning.md §5 typed reads.

use osis_base::{Float, Tid, Value};
use osis_schema::*;
use std::collections::{BTreeMap, BTreeSet};

#[allow(dead_code, clippy::all)]
mod example {
    include!("../gen/example.rs");
}
#[allow(dead_code, clippy::all)]
mod core_gen {
    include!("../gen/core.rs");
}
#[allow(dead_code, clippy::all)]
mod meta {
    include!("../gen/meta.rs");
}

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/");

#[test]
fn generated_code_is_current() {
    for (name, path) in [("example", "tests/example.osis"), ("core", "../../schema/core.osis"), ("meta", "../../schema/meta.osis")] {
        let path = format!("{DIR}{path}");
        let g = generate_file(std::path::Path::new(&path)).unwrap();
        let out = format!("{DIR}tests/gen/{name}.rs");
        if std::env::var_os("OSIS_REGEN_VECTORS").is_some() {
            std::fs::write(&out, &g.code).unwrap();
        }
        assert_eq!(std::fs::read_to_string(&out).unwrap(), g.code, "{name}: regenerate with OSIS_REGEN_VECTORS=1");
    }
}

#[test]
fn list_struct_warning() {
    let g = generate_file(std::path::Path::new(&format!("{DIR}tests/example.osis"))).unwrap();
    assert_eq!(g.warnings.len(), 1);
    assert!(g.warnings[0].contains("note:tasks.0"), "{:?}", g.warnings);
}

// Constant names are not injective in the key: a collision is a codegen error, not a duplicate
// item in the generated module.
#[test]
fn colliding_constant_names_refused() {
    for (a, b) in [("a:b_c.0", "a_b:c.0"), ("x:y.1", "x:y_v1.0"), ("a:b_c.0", "a_b:c.0~"), (":AAAAAAAAAAAAAAAAAAAA:x:y.0", "x:y.0^"), ("t:schema.0", "t:z.0")] {
        let d = |k: &str| if k.contains(": ") { k.to_string() } else { format!("{k}: int") };
        let src = format!("version 1;\naspect {};\naspect {};\n", d(a), d(b));
        let s = parse("c.osis", &src).unwrap();
        let e = generate(&s, "c.osis", &src).unwrap_err();
        assert!(matches!(e, Error::Codegen(ref m) if m.contains("collides")), "{a} {b}: {e}");
    }
    let src = "version 1;\naspect x:y.0: int;\naspect x:y.1: int;\n";
    assert!(generate(&parse("c.osis", src).unwrap(), "c.osis", src).is_ok());
}

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
    assert_eq!(example::TASKS.schema().unwrap().version, 4);
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
    assert_eq!(s.version, 1);
    assert!(s.aspects.contains_key("roles.0"));
    let ty = &s.aspects["roles.0"].r#type;
    assert!(matches!(ty.as_ref(), meta::TypeExpr::Map(_)));
    assert_eq!(Codec::to_value(&s), v);
}
