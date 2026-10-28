#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Hostile schemas end in errors, never in stack overflows or runaway work (notes/architecture.md
//! §3, no panics on data; spec/data-model.md §3 named and recursive types; spec/versioning.md §4).

use osis_core::Value;
use osis_core::format::CHUNK_THRESHOLD;
use osis_schema::*;
use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

fn src(body: &str) -> String {
    format!("schema 0x0102030405060708090a0b0c0d0e0f10;\nrevision 1;\n{body}")
}

fn err(body: &str) -> ParseError {
    parse("t.osis", &src(body)).expect_err("should fail")
}

// spec/data-model.md §3: wrappers take int or float; a self-referential wrapper with a default
// is an error, not unbounded recursion while typing the default.
#[test]
fn wrapper_of_itself_with_default() {
    let e = err("type a = counter<a>; type s = struct { 0 x: a = 1 };");
    assert!(e.msg.contains("int or float"), "{e}");
    let e = err("type a = max<a>; aspect /x/y: a;");
    assert!(e.msg.contains("int or float"), "{e}");
}

// spec/data-model.md §3: recursive types must be regular (a recursive reference passes its
// parameters unchanged), else expansion never repeats.
#[test]
fn polymorphic_recursion_rejected() {
    let e = err("type t<T> = struct { 0 a: option<t<list<T>>> }; aspect /x/y: t<int>;");
    assert!(e.msg.contains("recursive reference"), "{e}");
    let e = err("type t<T> = struct { 0 a: list<t<list<T>>> };");
    assert!(e.msg.contains("recursive reference"), "{e}");
    let e = err("type a<T> = struct { 0 x: option<b<T>> }; type b<U> = struct { 0 y: option<a<set<U>>> };");
    assert!(e.msg.contains("recursive reference"), "{e}");
    // Regular recursion, also mutual, is fine.
    parse("t.osis", &src("type a<T> = struct { 0 x: option<b<T>>, 1 v: T }; type b<U> = struct { 0 y: list<a<U>> }; aspect /x/y: a<int>;"))
        .unwrap();
}

// spec/versioning.md §4: the checker on schemas that bypass validation stops with a violation.
#[test]
fn checker_refuses_unvalidated_irregular_schemas() {
    let good = parse("t.osis", &src("aspect /x/y: int;")).unwrap();
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
    s.push_str(&format!("type a{n} = int;\naspect /x/y: a0;\n"));
    s
}

// notes/architecture.md §3: a long chain is an error, linear in its length.
#[test]
fn long_type_chains_error_fast() {
    let e = err(&chain(10_000));
    assert!(e.msg.contains("nests too deeply"), "{e}");
    let t = Instant::now();
    let e = err(&chain(1_000));
    assert!(e.msg.contains("nests too deeply"), "{e}");
    assert!(t.elapsed().as_secs_f64() < 0.5, "{:?}", t.elapsed());
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
    a.push_str("type b100 = int;\naspect /x/y: b0;");
    let e = err(&a);
    assert!(e.msg.contains("alias chain too long"), "{e}");
}

// notes/architecture.md §3: parametric types that multiply instances hit a work bound.
#[test]
fn exponential_instances_bounded() {
    let mut s = String::new();
    for i in 0..40 {
        s.push_str(&format!("type p{i}<T> = struct {{ 0 x: p{n}<list<T>>, 1 y: p{n}<set<T>> }};\n", n = i + 1));
    }
    s.push_str("type p40<T> = T;\naspect /x/y: p0<int>;");
    let t = Instant::now();
    let e = err(&s);
    assert!(e.msg.contains("too many type instances"), "{e}");
    assert!(t.elapsed().as_secs() < 5, "{:?}", t.elapsed());
}

// spec/data-model.md §6: a negative int key in a struct-typed position is a map key, never a
// field step (field IDs are non-negative).
#[test]
fn negative_keys_are_not_fields() {
    let s = parse("t.osis", &src("aspect /x/y: struct { 3 b: blob };")).unwrap();
    let big = Value::Bytes(vec![1; CHUNK_THRESHOLD]);
    let v = Value::Map(BTreeMap::from([(Value::Int(-3), big.clone())]));
    let got = large_positions(&s, &v, &s.aspects["/x/y"].ty);
    assert_eq!(got, vec![Large { path: Path(vec![Step::Key(Value::Int(-3))]), map_key: false }]);
}
