#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Schema value form (spec/data-model.md §10) and the additive checker
//! (spec/versioning.md §4): each rule violated and respected.

use osis_base::{Limits, Value};
use osis_schema::*;

const BASE: &str = "\
type t = struct { a 0: int, b 1: string = \"x\", c 2: option<int>, reserved 5 };
type e = enum { x 0, y 1 (int), reserved 7 };
type tree = struct { kids 0: list<tree>, n 1: int };
aspect n:a.0: t;
aspect n:n.0: int;
aspect n:s.0: string;
aspect n:e.0: e;
aspect n:tree.0: tree;
ephemeral signal n:sig+~0: int;
";

fn schema(rev: u64, body: &str) -> Schema {
    parse("t.osis", &format!("revision {rev};\n{body}")).unwrap()
}

/// Rules broken by version 2 of BASE with `from` replaced by `to`.
fn rules(from: &str, to: &str) -> Vec<Rule> {
    assert!(BASE.contains(from), "{from}");
    let old = schema(1, BASE);
    let new = schema(2, &BASE.replacen(from, to, 1));
    let mut r: Vec<Rule> = check(&old, &new).into_iter().map(|v| v.rule).collect();
    r.dedup();
    r
}

#[test]
fn value_form_round_trips_spec_data_model_10() {
    for s in [core_schema().clone(), parse("example.osis", include_str!("../example.osis")).unwrap(), meta_schema().clone()] {
        let bytes = s.canonical_bytes();
        let v = osis_base::decode(&bytes, &Limits::DEFAULT).unwrap();
        assert_eq!(Schema::from_value(&v).unwrap(), s);
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
    let good = schema(1, BASE).to_value();
    let Value::Map(mut m) = good.clone() else { panic!() };
    m.remove(&Value::Int(0));
    assert!(matches!(Schema::from_value(&Value::Map(m)), Err(Error::Form(_))));
    assert!(Schema::from_value(&Value::Int(1)).is_err());
    // Typed but invalid: an aspect naming an unknown type.
    let mut s = schema(1, BASE);
    s.aspects.get_mut("n:n.0").unwrap().ty = Type::named("nope");
    let e = Schema::from_value(&s.to_value()).unwrap_err();
    assert!(e.to_string().contains("unknown type nope"), "{e}");
    // A revision that is not an int.
    let Value::Map(mut m) = good else { panic!() };
    m.insert(Value::Int(0), Value::Bytes(vec![1]));
    assert!(Schema::from_value(&Value::Map(m)).is_err());
}

#[test]
fn additive_changes_pass_spec_versioning_4() {
    for (from, to) in [
        ("reserved 5 }", "reserved 5, d 3: int = 0, o 4: option<string> }"),
        ("reserved 7 }", "reserved 7, z 2 (string) }"),
        ("a 0: int", "renamed 0: int"),
        ("aspect n:n.0: int;", "aspect n:n.0: counter<int>;"),
        ("aspect n:n.0: int;", "aspect n:n.0: max<int>;"),
        ("aspect n:s.0: string;", "aspect n:s.0: text;"),
        ("aspect n:s.0: string;", "aspect n:s.0: markdown;"),
        ("c 2: option<int>, reserved 5", "reserved (2, 5)"),
        ("aspect n:n.0: int;", "/// Docs change freely.\npurgeable_by(writer) expires(1d) aspect n:n.0: int;"),
        ("ephemeral signal n:sig+~0: int;", "ephemeral signal n:sig+~0: int;\naspect n:more.0: set<tid>;"),
        ("type t = struct", "type t2 = struct { q 0: int };\ntype t = struct"),
    ] {
        assert_eq!(rules(from, to), vec![], "{to}");
    }
    // Aliases compare structurally.
    assert_eq!(rules("aspect n:n.0: int;", "type i = int;\naspect n:n.0: timestamp;"), vec![]);
    assert_eq!(check(&schema(1, BASE), &schema(1, BASE)), vec![]);
}

// spec/versioning.md §4 (additive version)
#[test]
fn each_rule_is_enforced_spec_versioning_4() {
    use Rule::*;
    for (from, to, want) in [
        ("reserved 5 }", "r 5: int = 0 }", vec![IdReused]),
        ("reserved 7 }", "w 7 }", vec![IdReused]),
        ("b 1: string = \"x\", ", "", vec![RemovedNotReserved]),
        (", reserved 5 }", " }", vec![ReservedDropped]),
        (", reserved 7 }", " }", vec![ReservedDropped]),
        ("x 0, ", "", vec![CaseRemoved]),
        ("x 0, y 1 (int), reserved 7", "y 1 (int), reserved (0, 7)", vec![CaseRemoved]),
        ("a 0: int", "a 0: string", vec![TypeChanged]),
        ("aspect n:n.0: int;", "aspect n:n.0: string;", vec![TypeChanged]),
        ("aspect n:s.0: string;", "aspect n:s.0: counter<int>;", vec![TypeChanged]),
        ("aspect n:n.0: int;", "aspect n:n.0: counter<float>;", vec![TypeChanged]),
        ("y 1 (int)", "y 1 (string)", vec![TypeChanged]),
        ("x 0,", "x 0 (int),", vec![TypeChanged]),
        ("y 1 (int)", "y 1", vec![TypeChanged]),
        ("kids 0: list<tree>", "kids 0: set<tree>", vec![TypeChanged]),
        ("reserved 5 }", "reserved 5, d 3: int }", vec![FieldWithoutDefault]),
        ("b 1: string = \"x\"", "b 1: string = \"y\"", vec![DefaultChanged]),
        ("b 1: string = \"x\"", "b 1: string", vec![DefaultChanged]),
        ("c 2: option<int>", "c 2: option<int> = some(1)", vec![DefaultChanged]),
        ("a 0: int", "a 0: int = 0", vec![DefaultAdded]),
        ("aspect n:e.0: e;\n", "", vec![AspectRemoved]),
        ("ephemeral signal n:sig+~0: int;\n", "", vec![AspectRemoved]),
    ] {
        assert_eq!(rules(from, to), want, "{from} -> {to}");
    }
    // Encodings only move up the embedding edge.
    let old = schema(1, "aspect n:n.0: counter<int>;\naspect n:s.0: text;");
    let new = schema(2, "aspect n:n.0: int;\naspect n:s.0: string;");
    assert_eq!(check(&old, &new).iter().map(|v| v.rule).collect::<Vec<_>>(), vec![TypeChanged, TypeChanged]);
}

#[test]
fn revision_rules_spec_versioning_4() {
    let old = schema(3, BASE);
    let changed = schema(3, &format!("{BASE}aspect n:z.0: int;"));
    assert_eq!(check(&old, &changed).iter().map(|v| v.rule).collect::<Vec<_>>(), vec![Rule::RevisionNotBumped]);
    let lower = schema(2, BASE);
    assert_eq!(check(&old, &lower).iter().map(|v| v.rule).collect::<Vec<_>>(), vec![Rule::RevisionNotBumped]);
    // A bump with no change is fine.
    assert_eq!(check(&old, &schema(4, BASE)), vec![]);
}

#[test]
fn default_added_names_its_place() {
    let old = schema(1, BASE);
    let new = schema(2, &BASE.replacen("a 0: int", "a 0: int = 0", 1));
    let v = check(&old, &new);
    assert_eq!((v[0].rule, v[0].at.as_str()), (Rule::DefaultAdded, "type t.0"));
}

#[test]
fn parametric_types_compare_positionally() {
    let old = schema(1, "type p<A> = struct { v 0: A };\naspect n:p.0: p<int>;");
    let new = schema(2, "type p<B> = struct { v 0: B, w 1: option<B> };\naspect n:p.0: p<int>;");
    assert_eq!(check(&old, &new), vec![]);
    let new = schema(2, "type p<B, C> = struct { v 0: B };\naspect n:p.0: p<int, int>;");
    assert_eq!(check(&old, &new).iter().map(|v| v.rule).collect::<Vec<_>>(), vec![Rule::TypeChanged]);
}
