#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! DSL parser, validation and the encoding mapping (spec/data-model.md §2, §3, §9;
//! spec/crdt.md §3.1).

use osis_base::format::{CORE_SCHEMA_ID, CORE_SCHEMA_REVISION, MEMBERSHIP_KEEP_MS};
use osis_base::{SchemaId, Value};
use osis_crdt::Encoding;
use osis_schema::*;

const NOTES: &str = include_str!("../../schemas/notes.osis");

fn app(body: &str) -> Result<Schema, ParseError> {
    parse("t.osis", &format!("schema 0x0102030405060708090a0b0c0d0e0f10;\nrevision 1;\n{body}"))
}

fn err(body: &str) -> ParseError {
    app(body).expect_err("should fail")
}

#[test]
fn core_schema_parses_spec_data_model_9() {
    let s = core_schema();
    assert!(core_static().error().is_none(), "{:?}", core_static().error());
    assert_eq!(s.id, CORE_SCHEMA_ID);
    assert_eq!(s.revision, CORE_SCHEMA_REVISION);
    let aks: Vec<&str> = s.aspects.keys().map(String::as_str).collect();
    for ak in [
        "/tid", "/aspects", "/created", "/members", "/keys", "/secrets", "/tenures", "/label", "/moved", "/was", "/node",
        "/reach", "/seen", "/group", "/groups", "/name", "/body", "/tag",
    ] {
        assert!(aks.contains(&ak), "{ak}");
    }
    assert_eq!(aks.len(), 18);
    let members = &s.aspects["/members"];
    assert_eq!(members.retention.by, PurgeBy::Admin);
    assert_eq!(members.retention.at_least.rel, Some(MEMBERSHIP_KEEP_MS));
    assert_eq!(s.aspects["/created"].retention.by, PurgeBy::Nobody);
    assert_eq!(s.aspects["/seen"].retention, Retention::default());
    assert!(s.aspects["/groups"].flags.contains(&Flag::Synthetic));
}

#[test]
fn notes_schema_parses_items_spec_data_model_2() {
    let s = parse("notes.osis", NOTES).unwrap();
    assert_eq!(s.revision, 4);
    assert_eq!(s.id.0[0], 0x7f);
    assert_eq!(s.doc.as_deref(), Some("Notes app schema (example; notes/data-model.md)."));
    let Type::Struct(task) = &s.types["task"].body else { panic!() };
    assert_eq!(s.types["task"].doc.as_deref(), Some("A task inside a note."));
    assert!(task.reserved.contains(&5));
    assert_eq!(task.fields[&7].succeeds.iter().copied().collect::<Vec<_>>(), vec![2]);
    assert_eq!(task.fields[&8].default, Some(Value::float(1.0)));
    assert_eq!(s.default_of(&task.fields[&4]), Some(Value::Enum(0, None)), "option defaults to none");
    assert_eq!(s.default_of(&task.fields[&1]), None);
    assert_eq!(s.aspects["/note/last_opened"].expires, Some(30 * 86_400_000));
    let pinned = &s.aspects["/note/pinned"].retention;
    assert_eq!((pinned.by, pinned.at_most.rel), (PurgeBy::Writer, Some(0)));
    assert!(s.aspects["/note/body"].flags.contains(&Flag::Indexed));
    assert_eq!(s.aspects["/note/body"].doc.as_deref(), Some("Markdown; not guaranteed valid."));
    assert!(s.aspects["/note/typing"].flags.contains(&Flag::Signal));
    assert_eq!(s.types["tagged"].params, vec!["T".to_string()]);
}

#[test]
fn encoding_per_type_spec_crdt_3_1() {
    let s = parse("notes.osis", NOTES).unwrap();
    let enc = |src: &str| {
        let s2 = app(&format!("type x = {src};")).unwrap();
        s2.encoding(&Type::named("x"))
    };
    for (t, e) in [
        ("string", Some(Encoding::Register)),
        ("blob", Some(Encoding::Register)),
        ("bool", Some(Encoding::Register)),
        ("int", Some(Encoding::Register)),
        ("float", Some(Encoding::Register)),
        ("tid", Some(Encoding::Register)),
        ("timestamp", Some(Encoding::Register)),
        ("date", Some(Encoding::Register)),
        ("localtime", Some(Encoding::Register)),
        ("text", Some(Encoding::Text)),
        ("markdown", Some(Encoding::Text)),
        ("counter<int>", Some(Encoding::Counter)),
        ("max<float>", Some(Encoding::Max)),
        ("min<int>", Some(Encoding::Min)),
        ("struct { 0 a: int }", Some(Encoding::Struct)),
        ("enum { 0 a }", Some(Encoding::Enum)),
        ("option<int>", Some(Encoding::Enum)),
        ("set<int>", Some(Encoding::Set)),
        ("map<int, int>", Some(Encoding::Map)),
        ("list<int>", Some(Encoding::List)),
        ("any", None),
    ] {
        assert_eq!(enc(t), e, "{t}");
    }
    assert_eq!(s.encoding(&s.aspects["/note/views"].ty), Some(Encoding::Counter));
}

#[test]
fn trailing_commas_docs_and_recursion() {
    let s = app(
        "/// A tree.\ntype tree = struct { 0 kids: list<tree>, 1 name: string, };\n\
         type e = enum { 0 a, 1 b(int), reserved (2, 3,), };\n\
         aspect /x/t: tree [indexed, ro,];\naspect /x/old: int;\naspect /x/new: int succeeds (/x/old,) [];",
    )
    .unwrap();
    assert!(s.aspects["/x/t"].flags.contains(&Flag::Ro));
    let Type::Enum(e) = &s.types["e"].body else { panic!() };
    assert_eq!(e.reserved.len(), 2);
    assert!(s.aspects["/x/new"].succeeds.contains("/x/old"));
}

#[test]
fn defaults_typed_by_field_type() {
    let s = app(
        "type p = enum { 0 low, 1 custom(int) };\n\
         type s = struct { 0 a: int = -3, 1 b: string = \"hi\", 2 c: p = custom(4), 3 d: list<int> = [1, 2],\n\
           4 e: map<string, bool> = { \"k\": true }, 5 f: blob = 0x00ff, 6 g: option<int> = some(2),\n\
           7 h: struct { 0 x: int, 1 y: option<int> } = { x: 1 }, 8 i: any = { 1: [2] } };",
    )
    .unwrap();
    let Type::Struct(st) = &s.types["s"].body else { panic!() };
    assert_eq!(st.fields[&0].default, Some(Value::Int(-3)));
    assert_eq!(st.fields[&2].default, Some(Value::Enum(1, Some(Box::new(Value::Int(4))))));
    assert_eq!(st.fields[&5].default, Some(Value::Bytes(vec![0, 255])));
    let Some(Value::Map(h)) = &st.fields[&7].default else { panic!() };
    assert_eq!(h[&Value::Int(1)], Value::Enum(0, None));
}

#[test]
fn errors_carry_line_and_column() {
    let e = parse("f.osis", "schema 0x0102030405060708090a0b0c0d0e0f10;\nrevision 1;\ntype x = struct { 0 a int };").unwrap_err();
    assert_eq!((e.file.as_str(), e.line, e.col), ("f.osis", 3, 23));
    assert!(e.to_string().starts_with("f.osis:3:23: expected `:`"), "{e}");
    let e = err("aspect /x/y: nope;");
    assert_eq!((e.line, e.col), (3, 1));
    assert!(e.msg.contains("unknown type nope"), "{e}");
    let e = parse("f.osis", "revision 1;").unwrap_err();
    assert!(e.msg.contains("missing `schema"), "{e}");
    let e = parse("f.osis", "schema 0x01;").unwrap_err();
    assert!(e.msg.contains("16 bytes"), "{e}");
    let e = parse("f.osis", "schema 0x0102030405060708090a0b0c0d0e0f10;\nrevision 1;\ntype x = struct { 0 a: string = \"unterminated };").unwrap_err();
    assert!(e.msg.contains("unterminated"), "{e}");
}

#[test]
fn validation_rules_spec_data_model_3() {
    for (src, needle) in [
        ("type x = set<counter<int>>;", "not allowed in set elements"),
        ("type x = map<text, int>;", "not allowed in set elements"),
        ("type x = set<struct { 0 a: max<int> }>;", "not allowed in set elements"),
        ("type x = map<markdown, int>;", "not allowed in set elements"),
        ("type x = counter<string>;", "int or float"),
        ("type x = option<int, int>;", "takes 1 type argument"),
        ("type x<T> = list<U>;", "unknown type U"),
        ("type x = x;", "does not reach a structure"),
        ("type a = b; type b = a;", "does not reach a structure"),
        ("type x = struct { 0 a: int, reserved 0 };", "both declared and reserved"),
        ("type x = struct { 0 a: int, 0 b: int };", "duplicate field ID 0"),
        ("type x = struct { 0 a: int, 1 a: int };", "duplicate field name a"),
        ("type x = struct { 0 a: int succeeds 9 };", "succeeds unknown"),
        ("type x = struct { 0 a: int = \"s\" };", "does not fit"),
        ("type x = enum { 0 a } ; type y = struct { 0 f: x = b };", "unknown case b"),
        ("type option = int;", "invalid type name"),
        ("aspect /x/a: int [keep_at_most: 1d];", "needs by: writer"),
        ("aspect /x: int;", "core AKs"),
        ("aspect /x/a: int; aspect /x/a: int;", "duplicate aspect"),
        ("aspect /x/a: int [frob];", "unknown attribute"),
        ("aspect /x/a: int [by: everyone];", "expected nobody"),
        ("type x<T> = struct { 0 a: T = 1 };", "cannot type a default"),
        ("aspect /x/a: int [ephemeral, signal];", "at most one of"),
        ("aspect /x/a: int [presence, by: admin];", "durable aspects only"),
        ("aspect /x/a: int [signal, expires: 5s];", "no value to expire"),
        ("aspect /x/a: int [presence, expires: 5s];", "no expiry"),
    ] {
        let e = err(src);
        assert!(e.msg.contains(needle), "{src}: {e}");
    }
    // lifetime flags (notes/ephemeral.md): the key's defaults carry them; the form round-trips
    let s = app("aspect /x/e: int [ephemeral, expires: 5s]; aspect /x/p: int [presence]; aspect /x/s: string [signal]; aspect /x/d: int;").unwrap();
    let life = |ak: &str| s.defaults(ak).unwrap().lifetime;
    assert_eq!([life("/x/e"), life("/x/p"), life("/x/s"), life("/x/d")], [Lifetime::Ephemeral, Lifetime::Presence, Lifetime::Signal, Lifetime::Durable]);
    assert_eq!(s.defaults("/x/e").unwrap().expires, Some(5_000));
    assert_eq!(Schema::from_value(&s.to_value()).unwrap(), s);
    // Wrappers are fine in mergeable positions, and under a parameter instantiated well.
    app("type c<T> = counter<T>; type x = struct { 0 a: c<int>, 1 b: map<string, max<float>>, 2 l: list<text> };").unwrap();
    let e = err("type c<T> = counter<T>; aspect /x/a: c<string>;");
    assert!(e.msg.contains("int or float"), "{e}");
}

#[test]
fn deep_nesting_is_an_error_not_a_crash() {
    let deep = format!("type x = {}int{};", "list<".repeat(200), ">".repeat(200));
    let e = err(&deep);
    assert!(e.msg.contains("nested too deeply"), "{e}");
}

#[test]
fn core_aspects_only_in_core_schema() {
    let e = parse("c.osis", "schema 0x00000000000000000000000000000000;\nrevision 1;\naspect /a/b: int;").unwrap_err();
    assert!(e.msg.contains("core AKs"), "{e}");
    let s = parse("c.osis", "schema 0x00000000000000000000000000000000;\nrevision 1;\naspect /a: int;").unwrap();
    assert_eq!(s.id, SchemaId([0; 16]));
}

proptest::proptest! {
    /// The parser never panics: arbitrary text, and the notes schema with a byte range replaced
    /// (errors only; fuzzing proper is test-infra's).
    #[test]
    fn parser_total_on_garbage(s in "\\PC{0,200}", cut in 0usize..1500, len in 0usize..40, junk in "[{}()<>;:,=\\[\\]/a-z0-9 \"-]{0,12}") {
        let _ = parse("g.osis", &s);
        let mut src = NOTES.to_string();
        let a = cut.min(src.len());
        let b = (a + len).min(src.len());
        if src.is_char_boundary(a) && src.is_char_boundary(b) {
            src.replace_range(a..b, &junk);
            let _ = parse("g.osis", &src);
        }
    }
}
