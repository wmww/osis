#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Typed reads, reader defaults, write validation, the View, large-value positions
//! (spec/versioning.md §5, spec/crdt.md §9, spec/data-model.md §6), version skew.

use osis_base::format::CHUNK_THRESHOLD;
use osis_base::{Limits, Tid, Value};
use osis_crdt::{Encoding, View};
use osis_schema::*;
use proptest::prelude::*;
use std::collections::{BTreeMap, BTreeSet};

fn schema(rev: u64, body: &str) -> Schema {
    parse("t.osis", &format!("version {rev};\n{body}")).unwrap()
}

fn st(fields: &[(i64, Value)]) -> Value {
    Value::Map(fields.iter().cloned().map(|(k, v)| (Value::Int(k), v)).collect())
}
fn s(x: &str) -> Value {
    Value::Str(x.into())
}
fn none() -> Value {
    Value::Enum(0, None)
}
fn some(v: Value) -> Value {
    Value::Enum(1, Some(Box::new(v)))
}

const V1: &str = "\
type status = enum { 0 todo, 1 done };
type task = struct { 1 title: string, 2 done: bool };
aspect n:tasks.0: list<task>;
aspect n:st.0: status;
";
const V2: &str = "\
type status = enum { 0 todo, 1 done, 2 blocked };
type task = struct { 1 title: string, 2 done: bool, 3 status: option<status>, 4 weight: float = 1.5 };
aspect n:tasks.0: list<task>;
aspect n:st.0: status;
";

fn tasks(s: &Schema) -> Type {
    s.aspects["n:tasks.0"].ty.clone()
}

#[test]
fn old_reads_new_open_structs_spec_versioning_5() {
    let (v1, v2) = (schema(1, V1), schema(2, V2));
    let t = st(&[(1, s("a")), (2, Value::Bool(false)), (3, some(Value::Enum(0, None))), (4, Value::float(2.0))]);
    validate_write(&v2, &Value::List(vec![t.clone()]), &tasks(&v2)).unwrap();
    // v1 ignores fields 3 and 4.
    let r = typed_read(&v1, &Value::List(vec![t]), &tasks(&v1)).unwrap();
    assert_eq!(r, Value::List(vec![st(&[(1, s("a")), (2, Value::Bool(false))])]));
}

#[test]
fn new_reads_old_with_reader_defaults_spec_versioning_5() {
    let v2 = schema(2, V2);
    let old = Value::List(vec![st(&[(1, s("a")), (2, Value::Bool(true))])]);
    let r = typed_read(&v2, &old, &tasks(&v2)).unwrap();
    let full = st(&[(1, s("a")), (2, Value::Bool(true)), (3, none()), (4, Value::float(1.5))]);
    assert_eq!(r, Value::List(vec![full]));
}

// spec/versioning.md §5 (mistyped reads absent): the decoder refuses, with the path
#[test]
fn typed_read_errors_carry_paths_spec_versioning_5() {
    let (v1, v2) = (schema(1, V1), schema(2, V2));
    let good = st(&[(1, s("a")), (2, Value::Bool(true))]);
    // Unknown enum case (newer data) deep inside: parked class, with the path.
    let newer = st(&[(1, s("b")), (2, Value::Bool(false)), (3, some(Value::Enum(2, None)))]);
    let e = typed_read(&v2, &Value::List(vec![good.clone(), newer.clone()]), &tasks(&v2));
    assert!(e.is_ok());
    let e = typed_read(&v1, &Value::Enum(2, None), &v1.aspects["n:st.0"].ty).unwrap_err();
    assert_eq!(e.kind, PathErrorKind::UnknownCase(2));
    assert_eq!(osis_base::Classified::class(&e), osis_base::ErrorClass::Parked);
    // Type mismatch at [1].2.
    let bad = st(&[(1, s("b")), (2, Value::Int(1))]);
    let e = typed_read(&v1, &Value::List(vec![good.clone(), bad]), &tasks(&v1)).unwrap_err();
    assert_eq!(e.path, p![1, FieldId(2)]);
    assert_eq!(e.kind, PathErrorKind::Mismatch { expected: "bool" });
    // Missing field without default.
    let e = typed_read(&v1, &Value::List(vec![st(&[(1, s("x"))])]), &tasks(&v1)).unwrap_err();
    assert_eq!((e.path, e.kind), (p![0], PathErrorKind::MissingField(2)));
    // Unknown tags fail typed reads only.
    let unknown = Value::Unknown(osis_base::Unknown::new(4000, osis_base::CanonicalBytes::from_value(&Value::Int(1))).unwrap());
    let e = typed_read(&v1, &unknown, &Type::String).unwrap_err();
    assert_eq!(e.kind, PathErrorKind::UnknownTag(4000));
    assert_eq!(typed_read(&v1, &unknown, &Type::Any).unwrap(), unknown);
    // Missing payload; struct with non-int keys.
    let s2 = schema(1, "type e = enum { 0 a(int) };");
    assert_eq!(typed_read(&s2, &Value::Enum(0, None), &Type::named("e")).unwrap_err().kind, PathErrorKind::MissingPayload(0));
    let m = Value::Map(BTreeMap::from([(s("k"), Value::Int(1))]));
    assert!(matches!(typed_read(&v1, &m, &Type::named("task")).unwrap_err().kind, PathErrorKind::Mismatch { .. }));
}

#[test]
fn writes_need_every_declared_field_spec_versioning_5() {
    let v2 = schema(2, V2);
    let partial = st(&[(1, s("a")), (2, Value::Bool(true))]);
    let e = validate_write(&v2, &partial, &Type::named("task")).unwrap_err();
    assert_eq!(e.kind, PathErrorKind::MissingField(3));
    let extra = st(&[(1, s("a")), (2, Value::Bool(true)), (3, none()), (4, Value::float(1.0)), (9, Value::Int(0))]);
    assert_eq!(validate_write(&v2, &extra, &Type::named("task")).unwrap_err().kind, PathErrorKind::UndeclaredField(9));
    let mut deep = Value::Int(0);
    for _ in 0..70 {
        deep = Value::List(vec![deep]);
    }
    assert_eq!(validate_write(&v2, &deep, &Type::Any).unwrap_err().kind, PathErrorKind::TooDeep);
}

#[test]
fn any_reads_back_struct_as_map_spec_data_model_3() {
    let s1 = schema(1, "aspect n:a.0: any;");
    let v = st(&[(0, s("x"))]);
    assert_eq!(typed_read(&s1, &v, &Type::Any).unwrap(), v);
    let view = s1.view("n:a.0").unwrap();
    assert_eq!(view.encoding(), None);
    assert_eq!(view.field(3).unwrap().encoding(), None);
}

#[test]
fn view_projects_onto_writer_schema_spec_crdt_9() {
    let (v1, v2) = (schema(1, V1), schema(2, V2));
    let view = v1.view("n:tasks.0").unwrap();
    assert_eq!(view.encoding(), Some(Encoding::List));
    let el = view.element().unwrap();
    assert_eq!(el.encoding(), Some(Encoding::Struct));
    // A newer element projects onto the v1 fields, so the diff matches it with a v1 item.
    let newer = st(&[(1, s("a")), (2, Value::Bool(false)), (3, some(Value::Enum(2, None)))]);
    assert_eq!(el.project(&newer).unwrap().into_owned(), st(&[(1, s("a")), (2, Value::Bool(false))]));
    // An exact v1 element projects to itself, borrowed.
    let same = st(&[(1, s("a")), (2, Value::Bool(false))]);
    assert!(matches!(el.project(&same).unwrap(), std::borrow::Cow::Borrowed(_)));
    // An element the writer cannot type is opaque.
    assert!(el.project(&st(&[(1, Value::Int(3)), (2, Value::Bool(false))])).is_none());
    assert!(v1.view("n:st.0").unwrap().project(&Value::Enum(2, None)).is_none());
    // Fields, declared defaults (never materialized), cases.
    let el2 = v2.view("n:tasks.0").unwrap().element().unwrap();
    assert_eq!(el2.field(1).unwrap().encoding(), Some(Encoding::Register));
    assert_eq!(el2.field(3).unwrap().encoding(), Some(Encoding::Enum));
    assert!(el2.field(9).is_none());
    assert_eq!(el2.field_default(4), Some(Value::float(1.5)));
    assert_eq!(el2.field_default(3), Some(none()));
    assert_eq!(el2.field_default(1), None);
    let opt = el2.field(3).unwrap();
    assert_eq!(opt.case(1).unwrap().encoding(), Some(Encoding::Enum));
    assert!(opt.case(0).is_none());
    // Projection fills defaults so an old element equals the typed new item.
    let old = st(&[(1, s("a")), (2, Value::Bool(false))]);
    let full = st(&[(1, s("a")), (2, Value::Bool(false)), (3, none()), (4, Value::float(1.5))]);
    assert_eq!(el2.project(&old).unwrap().into_owned(), full);
    // Maps, sets, bags.
    let s3 = schema(1, "aspect n:m.0: map<string, set<tid>>; aspect n:c.0: counter<int>;");
    let m = s3.view("n:m.0").unwrap();
    assert_eq!(m.key().unwrap().encoding(), Some(Encoding::Register));
    assert_eq!(m.element().unwrap().encoding(), Some(Encoding::Set));
    assert_eq!(m.element().unwrap().element().unwrap().encoding(), Some(Encoding::Register));
    let c = s3.view("n:c.0").unwrap();
    assert_eq!(c.encoding(), Some(Encoding::Counter));
    assert_eq!(c.element().unwrap().project(&Value::Int(4)).unwrap().into_owned(), Value::Int(4));
}

// spec/data-model.md §6 (chunk threshold)
#[test]
fn large_atomic_positions_spec_data_model_6() {
    let sc = schema(1, "aspect n:a.0: struct { 0 b: blob, 1 t: text, 2 s: set<string>, 3 m: map<blob, string>, 4 x: any };");
    let big = "x".repeat(CHUNK_THRESHOLD);
    let bigb = vec![7u8; CHUNK_THRESHOLD];
    let v = st(&[
        (0, Value::Bytes(bigb.clone())),
        (1, s(&big)),
        (2, Value::Set(BTreeSet::from([s(&big), s("small")]))),
        (3, Value::Map(BTreeMap::from([(Value::Bytes(bigb.clone()), s(&big))]))),
        (4, s(&big)),
    ]);
    let ty = &sc.aspects["n:a.0"].ty;
    let got = large_positions(&sc, &v, ty);
    let l = |path: Vec<Step>, map_key| Large { path: Path(path), map_key };
    let want = vec![
        l(vec![Step::Field(0)], false),
        l(vec![Step::Field(2), Step::Elem(s(&big))], false),
        l(vec![Step::Field(3), Step::Key(Value::Bytes(bigb.clone()))], true),
        l(vec![Step::Field(3), Step::Key(Value::Bytes(bigb))], false),
        l(vec![Step::Field(4)], false),
    ];
    assert_eq!(got, want, "text at field 1 never chunks");
    // At the threshold exactly: not chunked.
    let edge = "y".repeat(CHUNK_THRESHOLD - 5); // 5-byte head: 0x7a + 4-byte length
    assert_eq!(osis_base::encode(&s(&edge)).len(), CHUNK_THRESHOLD);
    assert!(large_positions(&sc, &s(&edge), &Type::String).is_empty());
    assert_eq!(large_positions(&sc, &s(&format!("{edge}y")), &Type::String).len(), 1);
}

/// Values of a type that a writer could write (every field present).
fn arb(schema: &Schema, ty: &Type, depth: u32) -> BoxedStrategy<Value> {
    let t = schema.expand(ty).unwrap().into_owned();
    let leaf = |t: &Type| -> BoxedStrategy<Value> {
        match t {
            Type::String | Type::Text => "[a-z]{0,4}".prop_map(Value::Str).boxed(),
            Type::Blob => proptest::collection::vec(any::<u8>(), 0..4).prop_map(Value::Bytes).boxed(),
            Type::Bool => any::<bool>().prop_map(Value::Bool).boxed(),
            Type::Int => any::<i64>().prop_map(Value::Int).boxed(),
            Type::Float => any::<f64>().prop_map(Value::float).boxed(),
            Type::Tid => any::<[u8; 15]>().prop_map(|b| Value::Tid(Tid::from_bytes(b))).boxed(),
            _ => any::<i64>().prop_map(Value::Int).boxed(),
        }
    };
    let n = if depth == 0 { 0..1usize } else { 0..3usize };
    match t {
        Type::Counter(i) | Type::Max(i) | Type::Min(i) => arb(schema, &i, depth),
        Type::List(e) => proptest::collection::vec(arb(schema, &e, depth.saturating_sub(1)), n).prop_map(Value::List).boxed(),
        Type::Set(e) => proptest::collection::btree_set(arb(schema, &e, depth.saturating_sub(1)), n).prop_map(Value::Set).boxed(),
        Type::Map(k, v) => proptest::collection::btree_map(arb(schema, &k, 0), arb(schema, &v, depth.saturating_sub(1)), n)
            .prop_map(Value::Map)
            .boxed(),
        Type::Struct(stt) => {
            let parts: Vec<BoxedStrategy<(Value, Value)>> = stt
                .fields
                .iter()
                .map(|(id, f)| {
                    let k = Value::Int(*id as i64);
                    arb(schema, &f.ty, depth).prop_map(move |v| (k.clone(), v)).boxed()
                })
                .collect();
            parts.prop_map(|kv| Value::Map(kv.into_iter().collect())).boxed()
        }
        Type::Enum(en) => {
            let cases: Vec<BoxedStrategy<Value>> = en
                .cases
                .iter()
                .map(|(id, c)| {
                    let id = *id;
                    match &c.payload {
                        None => Just(Value::Enum(id, None)).boxed(),
                        Some(p) => arb(schema, p, depth.saturating_sub(1)).prop_map(move |v| Value::Enum(id, Some(Box::new(v)))).boxed(),
                    }
                })
                .collect();
            proptest::strategy::Union::new(cases).boxed()
        }
        Type::Any => leaf(&Type::Int),
        other => leaf(&other),
    }
}

proptest! {
    /// spec/versioning.md §5: a value a writer writes reads back as itself through its type,
    /// also after the canonical encoding round trip.
    #[test]
    fn typed_read_of_written_is_identity(v in arb(core_schema(), &core_schema().aspects["keys.0"].ty, 2)) {
        let sc = core_schema();
        let ty = &sc.aspects["keys.0"].ty;
        validate_write(sc, &v, ty).unwrap();
        let back = osis_base::decode(&osis_base::encode(&v), &Limits::DEFAULT).unwrap();
        prop_assert_eq!(typed_read(sc, &back, ty).unwrap(), v);
    }

    #[test]
    fn typed_read_identity_app(v in arb(&schema(2, V2), &Type::named("task"), 2)) {
        let sc = schema(2, V2);
        validate_write(&sc, &v, &Type::named("task")).unwrap();
        prop_assert_eq!(typed_read(&sc, &v, &Type::named("task")).unwrap(), v);
    }

    #[test]
    fn every_core_aspect_round_trips(seed in 0usize..15) {
        let sc = core_schema();
        let (_, a) = sc.aspects.iter().nth(seed).unwrap();
        let mut runner = proptest::test_runner::TestRunner::deterministic();
        for _ in 0..4 {
            let v = arb(sc, &a.ty, 2).new_tree(&mut runner).unwrap().current();
            validate_write(sc, &v, &a.ty).unwrap();
            prop_assert_eq!(typed_read(sc, &v, &a.ty).unwrap(), v);
        }
    }
}

// spec/data-model.md §6: a link stands only where the type takes one: blob and string positions,
// and set elements and map keys (and inside them) of a type that is not small. Elsewhere it is a
// type mismatch, judged from the value and the type alone; `misplaced_link` agrees with the
// typed read and the view's projection (the receiver's check on core aspects).
#[test]
fn link_only_where_the_type_takes_one_spec_dm_6() {
    let sc = schema(
        1,
        "type role = enum { 0 read, 1 write };
type pair = struct { 0 who: tid, 1 note: string };
aspect n:a.0: struct { 0 tids: set<tid>, 1 ints: set<int>, 2 roles: set<role>, 3 strs: set<string>, 4 pairs: set<pair>, 5 by: map<tid, string>, 6 named: map<string, int>, 7 one: tid, 8 text: string };",
    );
    let ty = sc.aspects["n:a.0"].ty.clone();
    let link = Value::Link(osis_base::Link { hash: [3; 32], blob: osis_base::BlobId([4; 32]), suite: 1, key: [5; 32] });
    let set = |v: Value| Value::Set([v].into_iter().collect());
    let map = |k: Value, v: Value| Value::Map([(k, v)].into_iter().collect());
    let cases = [
        (0, set(link.clone()), false),
        (1, set(link.clone()), false),
        (2, set(link.clone()), false),
        (3, set(link.clone()), true),
        (4, set(link.clone()), true),
        (4, set(st(&[(0, link.clone()), (1, s("x"))])), false),
        (4, set(st(&[(0, Value::Tid(Tid::from_bytes([1; 15]))), (1, link.clone())])), true),
        (5, map(link.clone(), s("x")), false),
        (5, map(Value::Tid(Tid::from_bytes([1; 15])), link.clone()), true),
        (6, map(link.clone(), Value::Int(1)), true),
        (6, map(s("k"), link.clone()), false),
        (7, link.clone(), false),
        (8, link.clone(), true),
    ];
    for (i, (f, v, ok)) in cases.into_iter().enumerate() {
        let whole = st(&[(f, v.clone())]);
        assert_eq!(!misplaced_link(&sc, &whole, &ty, false), ok, "{i}");
        let probe = Schema::view(&sc, "n:a.0").unwrap().field(u64::try_from(f).unwrap()).unwrap();
        assert_eq!(probe.project(&v).is_some(), ok, "{i}: the view agrees");
        let (ft, _) = type_at(&sc, &ty, &Path(vec![Step::Field(u64::try_from(f).unwrap())])).unwrap();
        assert_eq!(typed_read(&sc, &v, &ft).is_ok(), ok, "{i}: the typed read agrees");
    }
}

// spec/crdt.md §3.3 rule 7: a core-aspect delta must fit the type (`Fragment::fits`, the
// receiver's check): each non-register fragment has the position's encoding, each value
// projects there, each enum case write names a declared case; undeclared struct fields are not
// looked into, and `any` takes every encoding.
#[test]
fn fragment_fits_its_type_spec_crdt_3_3() {
    use osis_crdt::{AnyView, Source, Writer, create};
    let sc = schema(
        1,
        "type role = enum { 0 read, 1 write(int) };
aspect n:a.0: struct { 0 tids: set<tid>, 1 r: role, 2 free: any, 3 n: counter<int> };",
    );
    let view = Schema::view(&sc, "n:a.0").unwrap();
    let ts = osis_base::Ts::make(osis_base::WallMs(1), 0).unwrap();
    let w = || Writer::new(ts, Source::commit(osis_base::CommitId([0; 32])), 1);
    let tid = Value::Tid(Tid::from_bytes([1; 15]));
    let set = |v: Value| Value::Set([v].into_iter().collect());
    let cases = [
        (st(&[(0, set(tid.clone()))]), true),
        (st(&[(0, set(Value::Int(5)))]), false),
        (st(&[(1, Value::Enum(0, None))]), true),
        (st(&[(1, Value::Enum(1, Some(Box::new(Value::Int(3)))))]), true),
        (st(&[(1, Value::Enum(1, Some(Box::new(s("x")))))]), false),
        (st(&[(1, Value::Enum(7, None))]), false),
        (st(&[(2, Value::Map([(tid.clone(), set(Value::Int(1)))].into_iter().collect()))]), true),
        (st(&[(3, Value::Int(2))]), true),
        (st(&[(9, s("unknown field"))]), true),
    ];
    for (i, (v, ok)) in cases.into_iter().enumerate() {
        assert_eq!(create(&mut w(), &view, &v).unwrap().fits(&view), ok, "{i}");
    }
    // the same values in the wrong encodings: a map where the struct is, a list where the set is
    assert!(!create(&mut w(), &AnyView, &st(&[(0, set(tid.clone()))])).unwrap().fits(&view));
    let other = schema(1, "aspect n:a.0: struct { 0 tids: list<tid>, 1 r: int };");
    let ov = Schema::view(&other, "n:a.0").unwrap();
    assert!(!create(&mut w(), &ov, &st(&[(0, Value::List(vec![tid]))])).unwrap().fits(&view), "a list where the set is");
    assert!(!create(&mut w(), &ov, &st(&[(1, Value::Int(0))])).unwrap().fits(&view), "a register int where the enum is");
}
