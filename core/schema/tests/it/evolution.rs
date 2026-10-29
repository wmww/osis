#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Schema value form (spec/data-model.md §10), lock files and the additive checker
//! (spec/versioning.md §4): each rule violated and respected.

use osis_base::{Limits, Value};
use osis_schema::*;

const BASE: &str = "\
type t = struct { 0 a: int, 1 b: string = \"x\", 2 c: option<int>, reserved 5 };
type e = enum { 0 x, 1 y(int), reserved 7 };
type tree = struct { 0 kids: list<tree>, 1 n: int };
aspect /n/a: t;
aspect /n/n: int;
aspect /n/s: string;
aspect /n/e: e;
aspect /n/tree: tree;
aspect /n/sig: int [signal];
";

fn schema(id: &str, rev: u64, body: &str) -> Schema {
    parse("t.osis", &format!("schema 0x{id};\nrevision {rev};\n{body}")).unwrap()
}

const ID: &str = "0102030405060708090a0b0c0d0e0f10";

/// Rules broken by revision 2 of BASE with `from` replaced by `to`.
fn rules(from: &str, to: &str) -> Vec<Rule> {
    assert!(BASE.contains(from), "{from}");
    let old = schema(ID, 1, BASE);
    let new = schema(ID, 2, &BASE.replacen(from, to, 1));
    let mut r: Vec<Rule> = check(&old, &new).into_iter().map(|v| v.rule).collect();
    r.dedup();
    r
}

#[test]
fn value_form_round_trips_spec_data_model_10() {
    for s in [core_schema().clone(), parse("n.osis", include_str!("../../schemas/notes.osis")).unwrap(), meta_schema().clone()] {
        let bytes = s.canonical_bytes();
        let v = osis_base::decode(&bytes, &Limits::DEFAULT).unwrap();
        assert_eq!(Schema::from_value(&v).unwrap(), s);
        assert_eq!(s.hash(), osis_base::hash::hash(&bytes));
    }
}

#[test]
fn schema_value_is_typed_by_meta_schema_spec_data_model_10() {
    // The schema of schemas describes itself.
    let m = meta_schema();
    assert!(m.types.contains_key("schema"));
    typed_read(m, &m.to_value(), &Type::named("schema")).unwrap();
    validate_write(m, &core_schema().to_value(), &Type::named("schema")).unwrap();
}

#[test]
fn from_value_rejects_bad_forms() {
    let good = schema(ID, 1, BASE).to_value();
    let Value::Map(mut m) = good.clone() else { panic!() };
    m.remove(&Value::Int(0));
    assert!(matches!(Schema::from_value(&Value::Map(m)), Err(Error::Form(_))));
    assert!(Schema::from_value(&Value::Int(1)).is_err());
    // Typed but invalid: an aspect naming an unknown type.
    let mut s = schema(ID, 1, BASE);
    s.aspects.get_mut("/n/n").unwrap().ty = Type::named("nope");
    let e = Schema::from_value(&s.to_value()).unwrap_err();
    assert!(e.to_string().contains("unknown type nope"), "{e}");
    // A short schema ID.
    let Value::Map(mut m) = good else { panic!() };
    m.insert(Value::Int(0), Value::Bytes(vec![1]));
    assert!(Schema::from_value(&Value::Map(m)).is_err());
}

#[test]
fn lock_file_round_trip_and_tamper() {
    let s = schema(ID, 1, BASE);
    let text = Lock::of(&s).to_text();
    let lock = Lock::parse(&text).unwrap();
    assert_eq!(lock.schema, s);
    assert_eq!(check_lock(&s, &lock, &[]).unwrap(), LockStatus::Published);
    let s2 = schema(ID, 2, &format!("{BASE}aspect /n/new: int;"));
    assert_eq!(check_lock(&s2, &lock, &[]).unwrap(), LockStatus::Unpublished);
    let bad = text.replacen("hash 0", "hash 1", 1).replacen("hash 1", "hash 2", 1);
    let tampered = if bad == text { text.replace("osis-lock 1\nhash ", "osis-lock 1\nhash ff") } else { bad };
    assert!(Lock::parse(&tampered).is_err());
    assert!(Lock::parse("nope").is_err());
}

#[test]
fn additive_changes_pass_spec_versioning_4() {
    for (from, to) in [
        ("reserved 5 }", "reserved 5, 3 d: int = 0, 4 o: option<string> }"),
        ("reserved 7 }", "reserved 7, 2 z(string) }"),
        ("0 a: int", "0 renamed: int"),
        ("aspect /n/n: int;", "aspect /n/n: counter<int>;"),
        ("aspect /n/n: int;", "aspect /n/n: max<int>;"),
        ("aspect /n/s: string;", "aspect /n/s: text;"),
        ("aspect /n/s: string;", "aspect /n/s: markdown;"),
        ("2 c: option<int>, reserved 5", "reserved (2, 5)"),
        ("aspect /n/n: int;", "/// Docs change freely.\naspect /n/n: int [indexed, by: admin, expires: 1d];"),
        ("aspect /n/sig: int [signal];", "aspect /n/sig: int [signal];\naspect /n/more: set<tid>;"),
        ("type t = struct", "type t2 = struct { 0 q: int };\ntype t = struct"),
    ] {
        assert_eq!(rules(from, to), vec![], "{to}");
    }
    // Aliases compare structurally.
    assert_eq!(rules("aspect /n/n: int;", "type i = int;\naspect /n/n: timestamp;"), vec![]);
    assert_eq!(check(&schema(ID, 1, BASE), &schema(ID, 1, BASE)), vec![]);
}

// spec/versioning.md §4 (additive revision)
#[test]
fn each_rule_is_enforced_spec_versioning_4() {
    use Rule::*;
    for (from, to, want) in [
        ("reserved 5 }", "5 r: int = 0 }", vec![IdReused]),
        ("reserved 7 }", "7 w }", vec![IdReused]),
        ("1 b: string = \"x\", ", "", vec![RemovedNotReserved]),
        (", reserved 5 }", " }", vec![ReservedDropped]),
        (", reserved 7 }", " }", vec![ReservedDropped]),
        ("0 x, ", "", vec![CaseRemoved]),
        ("0 x, 1 y(int), reserved 7", "1 y(int), reserved (0, 7)", vec![CaseRemoved]),
        ("0 a: int", "0 a: string", vec![TypeChanged]),
        ("aspect /n/n: int;", "aspect /n/n: string;", vec![TypeChanged]),
        ("aspect /n/s: string;", "aspect /n/s: counter<int>;", vec![TypeChanged]),
        ("aspect /n/n: int;", "aspect /n/n: counter<float>;", vec![TypeChanged]),
        ("1 y(int)", "1 y(string)", vec![TypeChanged]),
        ("0 x,", "0 x(int),", vec![TypeChanged]),
        ("1 y(int)", "1 y", vec![TypeChanged]),
        ("0 kids: list<tree>", "0 kids: set<tree>", vec![TypeChanged]),
        ("reserved 5 }", "reserved 5, 3 d: int }", vec![FieldWithoutDefault]),
        ("b: string = \"x\"", "b: string = \"y\"", vec![DefaultChanged]),
        ("b: string = \"x\"", "b: string", vec![DefaultChanged]),
        ("2 c: option<int>", "2 c: option<int> = some(1)", vec![DefaultChanged]),
        ("0 a: int", "0 a: int = 0", vec![DefaultAdded]),
        ("aspect /n/e: e;\n", "", vec![AspectRemoved]),
        ("aspect /n/sig: int [signal];\n", "", vec![AspectRemoved]),
    ] {
        assert_eq!(rules(from, to), want, "{from} -> {to}");
    }
    // Encodings only move up the embedding edge.
    let old = schema(ID, 1, "aspect /n/n: counter<int>;\naspect /n/s: text;");
    let new = schema(ID, 2, "aspect /n/n: int;\naspect /n/s: string;");
    assert_eq!(check(&old, &new).iter().map(|v| v.rule).collect::<Vec<_>>(), vec![TypeChanged, TypeChanged]);
}

#[test]
fn identity_and_revision_rules_spec_versioning_4() {
    let old = schema(ID, 3, BASE);
    let other = schema("ffffffffffffffffffffffffffffff00", 4, BASE);
    assert_eq!(check(&old, &other).iter().map(|v| v.rule).collect::<Vec<_>>(), vec![Rule::SchemaIdChanged]);
    let changed = schema(ID, 3, &format!("{BASE}aspect /n/z: int;"));
    assert_eq!(check(&old, &changed).iter().map(|v| v.rule).collect::<Vec<_>>(), vec![Rule::RevisionNotBumped]);
    let lower = schema(ID, 2, BASE);
    assert_eq!(check(&old, &lower).iter().map(|v| v.rule).collect::<Vec<_>>(), vec![Rule::RevisionNotBumped]);
    // A bump with no change is fine.
    assert_eq!(check(&old, &schema(ID, 4, BASE)), vec![]);
}

#[test]
fn default_added_passes_only_when_marked() {
    let old = schema(ID, 1, BASE);
    let new = schema(ID, 2, &BASE.replacen("0 a: int", "0 a: int = 0", 1));
    let lock = Lock::of(&old);
    let e = check_lock(&new, &lock, &[]).unwrap_err();
    let Error::Evolution(v) = &e else { panic!("{e}") };
    assert_eq!(v[0].at, "type t.0");
    assert_eq!(check_lock(&new, &lock, &["type t.0"]).unwrap(), LockStatus::Unpublished);
}

#[test]
fn parametric_types_compare_positionally() {
    let old = schema(ID, 1, "type p<A> = struct { 0 v: A };\naspect /n/p: p<int>;");
    let new = schema(ID, 2, "type p<B> = struct { 0 v: B, 1 w: option<B> };\naspect /n/p: p<int>;");
    assert_eq!(check(&old, &new), vec![]);
    let new = schema(ID, 2, "type p<B, C> = struct { 0 v: B };\naspect /n/p: p<int, int>;");
    assert_eq!(check(&old, &new).iter().map(|v| v.rule).collect::<Vec<_>>(), vec![Rule::TypeChanged]);
}
