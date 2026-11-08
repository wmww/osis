#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Hostile schemas end in errors, never in stack overflows or runaway work (notes/architecture.md
//! §3, no panics on data; spec/data-model.md §3 named and recursive types; spec/versioning.md §4).

use osis_base::Value;
use osis_base::format::CHUNK_THRESHOLD;
use osis_schema::*;
use std::collections::{BTreeMap, BTreeSet};

fn src(body: &str) -> String {
    format!("revision 1;\n{body}")
}

fn err(body: &str) -> ParseError {
    parse("t.osis", &src(body)).expect_err("should fail")
}

// spec/data-model.md §3: wrappers take int or float; a self-referential wrapper with a default
// is an error, not unbounded recursion while typing the default.
#[test]
fn wrapper_of_itself_with_default() {
    let e = err("type a = counter<a>; type s = struct { x 0: a = 1 };");
    assert!(e.msg.contains("int or float"), "{e}");
    let e = err("type a = max<a>; aspect x:y.0: a;");
    assert!(e.msg.contains("int or float"), "{e}");
}

// spec/data-model.md §3: recursive types must be regular (a recursive reference passes its
// parameters unchanged), else expansion never repeats.
#[test]
fn polymorphic_recursion_rejected() {
    let e = err("type t<T> = struct { a 0: option<t<list<T>>> }; aspect x:y.0: t<int>;");
    assert!(e.msg.contains("recursive reference"), "{e}");
    let e = err("type t<T> = struct { a 0: list<t<list<T>>> };");
    assert!(e.msg.contains("recursive reference"), "{e}");
    let e = err("type a<T> = struct { x 0: option<b<T>> }; type b<U> = struct { y 0: option<a<set<U>>> };");
    assert!(e.msg.contains("recursive reference"), "{e}");
    // Regular recursion, also mutual, is fine.
    parse("t.osis", &src("type a<T> = struct { x 0: option<b<T>>, v 1: T }; type b<U> = struct { y 0: list<a<U>> }; aspect x:y.0: a<int>;"))
        .unwrap();
}

// spec/versioning.md §4: the checker on schemas that bypass validation stops with a violation.
#[test]
fn checker_refuses_unvalidated_irregular_schemas() {
    let good = parse("t.osis", &src("aspect x:y.0: int;")).unwrap();
    let mut bad = good.clone();
    let body = Type::Struct(StructType {
        fields: BTreeMap::from([(0, Field::new("a", Type::List(Box::new(Type::Named("t".into(), vec![Type::List(Box::new(Type::Param("T".into())))])))))]),
        reserved: BTreeSet::new(),
    });
    bad.types.insert("t".into(), TypeDef { params: vec!["T".into()], body, doc: None });
    bad.revision = 2;
    let v = check(&good, &bad);
    assert_eq!(v.iter().map(|v| v.rule).collect::<Vec<_>>(), vec![Rule::Invalid]);
    // And the same schema as a value is refused by from_value.
    assert!(Schema::from_value(&bad.to_value()).is_err());
}

fn chain(n: usize) -> String {
    let mut s = String::new();
    for i in 0..n {
        s.push_str(&format!("type a{i} = list<a{}>;\n", i + 1));
    }
    s.push_str(&format!("type a{n} = int;\naspect x:y.0: a0;\n"));
    s
}

// notes/architecture.md §3: a long chain is an error (the nesting bound stops the walk).
#[test]
fn long_type_chains_error() {
    for n in [1_000, 10_000] {
        let e = err(&chain(n));
        assert!(e.msg.contains("nests too deeply"), "{e}");
    }
    // Within the limit: parses and compares.
    let s = parse("t.osis", &src(&chain(200))).unwrap();
    let mut s2 = s.clone();
    s2.revision = 2;
    assert_eq!(check(&s, &s2), vec![]);
    // Plain aliases beyond the expansion bound say so.
    let mut a = String::new();
    for i in 0..100 {
        a.push_str(&format!("type b{i} = b{};\n", i + 1));
    }
    a.push_str("type b100 = int;\naspect x:y.0: b0;");
    let e = err(&a);
    assert!(e.msg.contains("alias chain too long"), "{e}");
}

// notes/architecture.md §3: parametric types that multiply instances hit a work bound.
#[test]
fn exponential_instances_bounded() {
    let mut s = String::new();
    for i in 0..40 {
        s.push_str(&format!("type p{i}<T> = struct {{ x 0: p{n}<list<T>>, y 1: p{n}<set<T>> }};\n", n = i + 1));
    }
    s.push_str("type p40<T> = T;\naspect x:y.0: p0<int>;");
    let e = err(&s);
    assert!(e.msg.contains("too many type instances"), "{e}");
}

// spec/data-model.md §6: a negative int key in a struct-typed position is a map key, never a
// field step (field IDs are non-negative).
#[test]
fn negative_keys_are_not_fields() {
    let s = parse("t.osis", &src("aspect x:y.0: struct { b 3: blob };")).unwrap();
    let big = Value::Bytes(vec![1; CHUNK_THRESHOLD]);
    let v = Value::Map(osis_base::ValueMap::from([(Value::Int(-3), big.clone())]));
    let got = large_positions(&s, &v, &s.aspects["x:y.0"].ty);
    assert_eq!(got, vec![Large { path: Path(vec![Step::Key(Value::Int(-3))]), map_key: false }]);
}
