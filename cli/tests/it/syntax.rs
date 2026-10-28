//! The text forms and the JSON mapping (notes/cli.md Value syntax, JSON
//! mapping): every value prints one way and reads back, numbered or named.
//! spec: none (client surface).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use osis::{Schema, Tid, Value};
use osis_cli::json;
use osis_cli::text::{self, no_aliases, parse, print};
use osis_schema::osis_core::{CanonicalBytes, Unknown};
use proptest::prelude::*;
use std::collections::{BTreeMap, BTreeSet};

fn floats() -> impl Strategy<Value = Value> {
    prop_oneof![
        any::<f64>().prop_map(Value::float),
        Just(Value::float(0.0)),
        Just(Value::float(-0.0)),
        Just(Value::float(f64::NAN)),
        Just(Value::float(f64::INFINITY)),
        Just(Value::float(f64::NEG_INFINITY)),
        Just(Value::float(1e300)),
        Just(Value::float(5e-324)),
        any::<u64>().prop_map(|b| Value::float(f64::from_bits(b))),
    ]
}

/// osis-core's value generator (tests/cbor.rs) without links: the API never returns links.
fn leaf() -> impl Strategy<Value = Value> {
    prop_oneof![
        any::<i64>().prop_map(Value::Int),
        (-30i64..300).prop_map(Value::Int),
        prop_oneof![Just(i64::MIN), Just(i64::MAX), Just(-1), Just(0)].prop_map(Value::Int),
        floats(),
        any::<bool>().prop_map(Value::Bool),
        prop::collection::vec(any::<char>(), 0..6).prop_map(|c| Value::Str(c.into_iter().collect())),
        prop::collection::vec(any::<u8>(), 0..30).prop_map(Value::Bytes),
        any::<[u8; 15]>().prop_map(|b| Value::Tid(Tid::from_bytes(b))),
        prop_oneof![Just(0u64), Just(23), Just(300), Just(u64::MAX)].prop_map(|c| Value::Enum(c, None)),
    ]
}

fn value() -> impl Strategy<Value = Value> {
    leaf().prop_recursive(4, 48, 6, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..6).prop_map(Value::List),
            prop::collection::vec((inner.clone(), inner.clone()), 0..6).prop_map(|e| Value::Map(e.into_iter().collect())),
            prop::collection::vec(inner.clone(), 0..6).prop_map(|e| Value::Set(e.into_iter().collect())),
            (any::<u64>(), inner.clone()).prop_map(|(c, p)| Value::Enum(c, Some(Box::new(p)))),
            (prop_oneof![Just(0u64), Just(2), Just(259), Just(1619), Just(u64::MAX)], inner)
                .prop_map(|(t, c)| Value::Unknown(Unknown::new(t, CanonicalBytes::from_value(&c)).unwrap())),
        ]
    })
}

const SRC: &str = "schema 0x0123456789abcdef0123456789abcdef;
revision 1;
type prio = enum { 0 low, 1 high(int), 2 tagged(list<string>) };
type rec = struct { 0 title: string, 1 done: bool, 2 when: timestamp, 3 tags: set<string>, 4 prio: prio,
  5 waits: map<int, duration>, 6 score: option<float>, 7 extra: any, 8 owner: tid, 9 body: markdown,
  10 n: counter<int>, 11 at: map<timestamp, int>, 12 lens: map<duration, bool>, 13 when_set: set<timestamp> };
aspect /t/rec: rec;
";

fn schema() -> Schema {
    osis_schema::parse("t.osis", SRC).unwrap()
}

fn rec() -> impl Strategy<Value = Value> {
    let s = || prop::collection::vec(any::<char>(), 0..5).prop_map(|c| Value::Str(c.into_iter().collect()));
    let prio = prop_oneof![
        Just(Value::Enum(0, None)),
        any::<i64>().prop_map(|i| Value::Enum(1, Some(Box::new(Value::Int(i))))),
        prop::collection::vec(s(), 0..3).prop_map(|l| Value::Enum(2, Some(Box::new(Value::List(l))))),
        Just(Value::Enum(7, None)),
    ];
    let fields = (
        s(),
        any::<bool>(),
        prop_oneof![any::<i64>(), -62_000_000_000_000i64..300_000_000_000_000],
        prop::collection::btree_set(s(), 0..3),
        prio,
        prop::collection::btree_map(any::<i64>().prop_map(Value::Int), any::<i64>().prop_map(Value::Int), 0..3),
        prop_oneof![Just(Value::Enum(0, None)), floats().prop_map(|f| Value::Enum(1, Some(Box::new(f))))],
        value(),
        any::<[u8; 15]>(),
        s(),
        any::<i64>(),
    );
    let ms = || prop_oneof![any::<i64>(), -62_000_000_000_000i64..300_000_000_000_000].prop_map(Value::Int);
    let maps = (
        prop::collection::btree_map(ms(), any::<i64>().prop_map(Value::Int), 0..3),
        prop::collection::btree_map(ms(), any::<bool>().prop_map(Value::Bool), 0..3),
        prop::collection::btree_set(ms(), 0..3),
    );
    (fields, maps).prop_map(|((t, d, w, tags, p, waits, score, extra, owner, body, n), (at, lens, when_set))| {
        let f = [
            t,
            Value::Bool(d),
            Value::Int(w),
            Value::Set(tags),
            p,
            Value::Map(waits),
            score,
            extra,
            Value::Tid(Tid::from_bytes(owner)),
            body,
            Value::Int(n),
            Value::Map(at),
            Value::Map(lens),
            Value::Set(when_set),
        ];
        Value::Map(f.into_iter().enumerate().map(|(i, v)| (Value::Int(i as i64), v)).collect())
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    // notes/cli.md Value syntax Value, notes/cli.md Value syntax: numbered forms read back exactly
    // (floats incl. -0.0/NaN, tids, enums, sets, maps, unknown tags).
    #[test]
    fn numbered_round_trip(v in value()) {
        let s = print(&v, None);
        prop_assert_eq!(parse(&s, None, &no_aliases), Ok(v), "{}", s);
    }

    // notes/cli.md Value syntax: named forms (fields, cases, timestamps, durations) read back.
    #[test]
    fn named_round_trip(v in rec()) {
        let sc = schema();
        let ty = &sc.aspects["/t/rec"].ty;
        let s = print(&v, Some((&sc, ty)));
        prop_assert_eq!(parse(&s, Some((&sc, ty)), &no_aliases), Ok(v.clone()), "{}", s);
        // numbered text reads at the type too
        prop_assert_eq!(parse(&print(&v, None), Some((&sc, ty)), &no_aliases), Ok(v), "numbered at type");
    }

    // notes/cli.md: durations and timestamps print and read back.
    #[test]
    fn time_forms_round_trip(ms in prop_oneof![any::<i64>(), Just(i64::MIN), Just(i64::MAX)]) {
        prop_assert_eq!(text::parse_duration(&text::duration_text(ms)), Some(ms));
        if let Some(t) = text::rfc3339(ms) {
            prop_assert_eq!(text::parse_rfc3339(&t), Some(ms), "{}", t);
        }
    }
}

fn m(e: Vec<(Value, Value)>) -> Value {
    Value::Map(e.into_iter().collect())
}

// notes/cli.md Value syntax table: one printed form per kind.
#[test]
fn printed_forms_plan_cli_3() {
    let t = Tid::from_bytes([0; 15]);
    let v = Value::List(vec![
        Value::Str("a\"\n\u{1}é".into()),
        Value::Bytes(vec![0, 255]),
        Value::Bool(true),
        Value::Int(-3),
        Value::float(1.0),
        Value::float(2.5e-3),
        Value::float(-0.0),
        Value::float(f64::NAN),
        Value::float(f64::NEG_INFINITY),
        Value::float(1e300),
        Value::Tid(t),
        m(vec![(Value::Int(1), Value::Int(2))]),
        Value::Set(BTreeSet::from([Value::Int(1)])),
        Value::Enum(3, None),
        Value::Enum(3, Some(Box::new(Value::Int(5)))),
        Value::Unknown(Unknown::new(259, CanonicalBytes::from_value(&Value::Int(7))).unwrap()),
    ]);
    assert_eq!(
        print(&v, None),
        r#"["a\"\n\u0001é", h'00ff', true, -3, 1.0, 0.0025, -0.0, NaN, -Infinity, 1e300, osis://AAAAAAAAAAAAAAAAAAAA, {1: 2}, #{1}, #3, #3(5), tag(259, 7)]"#
    );
}

// notes/cli.md Value syntax: whitespace, trailing commas, b64 input, JSON input, aliases.
#[test]
fn input_forms_plan_cli_3() {
    let p = |s: &str| parse(s, None, &no_aliases);
    assert_eq!(p(" [ 1 ,\n 2, ] "), Ok(Value::List(vec![Value::Int(1), Value::Int(2)])));
    assert_eq!(p("b64'AP8='"), Ok(Value::Bytes(vec![0, 255])));
    assert_eq!(p("b64'AP8'"), Ok(Value::Bytes(vec![0, 255])));
    assert_eq!(p(r#"{"a": [1.5, true], "b": "😀"}"#), Ok(m(vec![(Value::Str("a".into()), Value::List(vec![Value::float(1.5), Value::Bool(true)])), (Value::Str("b".into()), Value::Str("😀".into()))])));
    assert!(p("null").is_err());
    assert!(p("01").is_err() && p("-01").is_err() && p("00.5").is_err(), "leading zeros");
    assert_eq!(p("0"), Ok(Value::Int(0)));
    assert!(p(r#""\u+041""#).is_err());
    assert!(p("{1: 1, 1: 2}").is_err());
    assert!(p("#{1, 1}").is_err());
    assert!(p("99999999999999999999").is_err());
    assert!(p("tag(258, [])").is_err(), "a known tag has its own form");
    let t = Tid::from_bytes([1; 15]);
    let al = move |w: &str| (w == "me").then_some(t);
    assert_eq!(parse("[me]", None, &al), Ok(Value::List(vec![Value::Tid(t)])));
    // with a schema, JSON objects read as the struct
    let sc = schema();
    let ty = &sc.aspects["/t/rec"].ty;
    let v = parse(r#"{"title": "x", "done": true, "when": 0}"#, Some((&sc, ty)), &no_aliases).unwrap();
    assert_eq!(v, m(vec![(Value::Int(0), Value::Str("x".into())), (Value::Int(1), Value::Bool(true)), (Value::Int(2), Value::Int(0))]));
}

// notes/cli.md Value syntax: timestamps and durations as map keys stop before the `:`;
// impossible dates and the i64 extremes are handled.
#[test]
fn time_keys_and_edges_notes_cli() {
    let sc = schema();
    let ty = &sc.aspects["/t/rec"].ty;
    let v = parse("{at: {2026-01-02T03:04:05Z: 1, 2026-01-02: 2}, lens: {1h30m: true, -5s: false}}", Some((&sc, ty)), &no_aliases).unwrap();
    assert_eq!(print(&v, Some((&sc, ty))), "{at: {2026-01-02T00:00:00Z: 2, 2026-01-02T03:04:05Z: 1}, lens: {1h30m: true, -5s: false}}");
    assert!(parse("{at: {2026-02-31T00:00:00Z: 1}}", Some((&sc, ty)), &no_aliases).is_err());
    assert_eq!(text::parse_rfc3339("2024-02-29"), Some(1_709_164_800_000));
    assert_eq!(text::parse_rfc3339("2023-02-29"), None);
    let e = parse("{when: 2026-13-01T00:00:00Z}", Some((&sc, ty)), &no_aliases).unwrap_err();
    assert!(e.ends_with("column 8"), "{e}");
    assert_eq!(text::parse_duration(&text::duration_text(i64::MIN)), Some(i64::MIN));
    assert_eq!(text::parse_duration(&text::duration_text(i64::MAX)), Some(i64::MAX));
}

// notes/cli.md Value syntax: named forms with a schema.
#[test]
fn named_forms_notes_cli() {
    let sc = schema();
    let ty = &sc.aspects["/t/rec"].ty;
    let src = r#"{title: "x", when: 2026-10-19T12:00:00.5+02:00, tags: #{"a"}, prio: #high(3), waits: {1: 1h30m}, score: #some(1.5), 99: 1}"#;
    let v = parse(src, Some((&sc, ty)), &no_aliases).unwrap();
    assert_eq!(
        print(&v, Some((&sc, ty))),
        r#"{title: "x", when: 2026-10-19T10:00:00.500Z, tags: #{"a"}, prio: #high(3), waits: {1: 1h30m}, score: #some(1.5), 99: 1}"#
    );
    assert_eq!(print(&v, None), r#"{0: "x", 2: 1792404000500, 3: #{"a"}, 4: #1(3), 5: {1: 5400000}, 6: #1(1.5), 99: 1}"#);
    assert!(parse("{nope: 1}", Some((&sc, ty)), &no_aliases).is_err());
    assert!(parse("{prio: #nope}", Some((&sc, ty)), &no_aliases).is_err());
}

// notes/cli.md JSON mapping JSON mapping.
#[test]
fn json_mapping_plan_cli_5() {
    let j = |v: &Value| json::value(v, None).text();
    assert_eq!(j(&Value::Int(3)), "3");
    assert_eq!(j(&Value::float(1.0)), "1.0");
    assert_eq!(j(&Value::float(f64::NAN)), "\"NaN\"");
    assert_eq!(j(&Value::float(f64::INFINITY)), "\"Infinity\"");
    assert_eq!(j(&Value::Tid(Tid::from_bytes([0; 15]))), "\"osis://AAAAAAAAAAAAAAAAAAAA\"");
    assert_eq!(j(&Value::Bytes(vec![0, 255])), r#"{"$blob":"AP8"}"#);
    assert_eq!(j(&Value::Set(BTreeSet::from([Value::Int(1)]))), r#"{"$set":[1]}"#);
    assert_eq!(j(&Value::Enum(2, None)), r#"{"$case":2}"#);
    assert_eq!(j(&Value::Enum(2, Some(Box::new(Value::Bool(true))))), r#"{"$case":2,"$payload":true}"#);
    assert_eq!(j(&m(vec![(Value::Bool(true), Value::Int(1))])), r#"{"$map":[[true,1]]}"#);
    assert_eq!(j(&m(vec![(Value::Str("a".into()), Value::Int(1))])), r#"{"a":1}"#);
    // notes/cli.md JSON mapping: a map whose keys are not all strings, or collide with a marker, is $map
    assert_eq!(j(&m(vec![(Value::Int(0), Value::Int(1))])), r#"{"$map":[[0,1]]}"#);
    for k in ["$set", "$blob", "$case", "$map", "$tag"] {
        assert_eq!(j(&m(vec![(Value::Str(k.into()), Value::Int(1))])), format!(r#"{{"$map":[["{k}",1]]}}"#));
    }
    assert_eq!(j(&m(vec![(Value::Str("set".into()), Value::Int(1))])), r#"{"set":1}"#);
    assert_eq!(j(&Value::Unknown(Unknown::new(259, CanonicalBytes::from_value(&Value::Int(7))).unwrap())), r#"{"$tag":259,"$bytes":"Bw"}"#);
    let sc = schema();
    let ty = &sc.aspects["/t/rec"].ty;
    let v = parse(r#"{title: "x", prio: #high(3), waits: {1: 2s}}"#, Some((&sc, ty)), &no_aliases).unwrap();
    assert_eq!(json::value(&v, Some((&sc, ty))).text(), r#"{"title":"x","prio":{"$case":"high","$payload":3},"waits":{"$map":[[1,2000]]}}"#);
    let mut m2 = BTreeMap::new();
    m2.insert(Value::Int(-1), Value::Int(1));
    assert_eq!(j(&Value::Map(m2)), r#"{"$map":[[-1,1]]}"#);
}
