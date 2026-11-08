#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! DSL parser, validation and the encoding mapping (spec/data-model.md §2, §3, §9;
//! spec/crdt.md §3.1).

use osis_base::Value;
use osis_crdt::Encoding;
use osis_schema::*;

const EXAMPLE: &str = include_str!("../example.osis");

fn app(body: &str) -> Result<Schema, ParseError> {
    parse("t.osis", &format!("revision 1;\n{body}"))
}

fn err(body: &str) -> ParseError {
    app(body).expect_err("should fail")
}

#[test]
fn core_schema_parses_spec_data_model_9() {
    let s = core_schema();
    assert!(core_static().error().is_none(), "{:?}", core_static().error());
    assert!(s.declares_core());
    let aks: Vec<&str> = s.aspects.keys().map(String::as_str).collect();
    for ak in [
        "tid.0", "aspects.0", "created.0", "roles.0", "keys.0", "secrets.0", "label.0", "node.0",
        "reach.0", "seen.0", "host^.0", "clients^.0", "group.0", "groups.0", "name.0", "body.0", "tag.0", "addenda.0",
    ] {
        assert!(aks.contains(&ak), "{ak}");
    }
    assert_eq!(aks.len(), 20);
    let holders = &s.aspects["roles.0"];
    assert_eq!(holders.retention.by, PurgeBy::Admin);
    assert_eq!(holders.retention.history, None);
    assert_eq!(s.aspects["created.0"].retention.by, PurgeBy::Nobody);
    assert_eq!(s.aspects["seen.0"].retention, Retention::default());
    assert!(s.aspects["groups.0"].flags.contains(&Flag::Synthetic));
}

#[test]
fn example_schema_parses_items_spec_data_model_2() {
    let s = parse("example.osis", EXAMPLE).unwrap();
    assert_eq!(s.revision, 4);
    assert_eq!(s.doc.as_deref(), Some("Test fixture, not a real schema: covers the DSL's features for osis-schema's own tests."));
    let Type::Struct(task) = &s.types["task"].body else { panic!() };
    assert_eq!(s.types["task"].doc.as_deref(), Some("A task inside a note."));
    assert!(task.reserved.contains(&5));
    assert_eq!(task.fields[&7].succeeds.iter().copied().collect::<Vec<_>>(), vec![2]);
    assert_eq!(task.fields[&8].default, Some(Value::float(1.0)));
    assert_eq!(s.default_of(&task.fields[&4]), Some(Value::Enum(0, None)), "option defaults to none");
    assert_eq!(s.default_of(&task.fields[&1]), None);
    assert_eq!(s.aspects["note:last_opened.0"].expires, Some(30 * 86_400_000));
    let pinned = &s.aspects["note:pinned.0"].retention;
    assert_eq!((pinned.by, pinned.history), (PurgeBy::Writer, Some(History::PurgeOnReplace)));
    assert!(s.aspects["note:body.0"].flags.is_empty());
    assert_eq!(s.aspects["note:body.0"].doc.as_deref(), Some("Markdown; not guaranteed valid."));
    assert!(s.aspects["note:typing+~0"].flags.is_empty());
    assert_eq!(s.aspects["note:aliases.0"].retention, Retention { by: PurgeBy::AuthorOrAdmin, history: Some(History::Keep { until: None, after: Some(7 * 86_400_000) }) });
    assert_eq!(s.aspects["note:cursor+^.0"].expires, Some(30_000));
    assert!(s.aspects["note:title.1"].succeeds.is_empty(), "a higher version succeeds the lower implicitly");
    assert_eq!(s.types["tagged"].params, vec!["T".to_string()]);
}

#[test]
fn encoding_per_type_spec_crdt_3_1() {
    let s = parse("example.osis", EXAMPLE).unwrap();
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
        ("struct { a 0: int }", Some(Encoding::Struct)),
        ("enum { a 0 }", Some(Encoding::Enum)),
        ("option<int>", Some(Encoding::Enum)),
        ("set<int>", Some(Encoding::Set)),
        ("map<int, int>", Some(Encoding::Map)),
        ("list<int>", Some(Encoding::List)),
        ("any", None),
    ] {
        assert_eq!(enc(t), e, "{t}");
    }
    assert_eq!(s.encoding(&s.aspects["note:views.0"].ty), Some(Encoding::Counter));
}

#[test]
fn trailing_commas_docs_and_recursion() {
    let s = app(
        "/// A tree.\ntype tree = struct { kids 0: list<tree>, name 1: string, };\n\
         type e = enum { a 0, b 1 (int), reserved (2, 3,), };\n\
         synthetic guaranteed aspect x:t.0: tree;\naspect x:old.0: int;\naspect x:new.0: int succeeds (x:old.0,);",
    )
    .unwrap();
    assert!(s.aspects["x:t.0"].flags.contains(&Flag::Guaranteed));
    let Type::Enum(e) = &s.types["e"].body else { panic!() };
    assert_eq!(e.reserved.len(), 2);
    assert!(s.aspects["x:new.0"].succeeds.contains("x:old.0"));
}

#[test]
fn defaults_typed_by_field_type() {
    let s = app(
        "type p = enum { low 0, custom 1 (int) };\n\
         type s = struct { a 0: int = -3, b 1: string = \"hi\", c 2: p = custom(4), d 3: list<int> = [1, 2],\n\
           e 4: map<string, bool> = { \"k\": true }, f 5: blob = 0x00ff, g 6: option<int> = some(2),\n\
           h 7: struct { x 0: int, y 1: option<int> } = { x: 1 }, i 8: any = { 1: [2] } };",
    )
    .unwrap();
    let Type::Struct(st) = &s.types["s"].body else { panic!() };
    assert_eq!(st.fields[&0].default, Some(Value::Int(-3)));
    assert_eq!(st.fields[&2].default, Some(Value::Enum(1, Some(Box::new(Value::Int(4))))));
    assert_eq!(st.fields[&5].default, Some(Value::Bytes(vec![0, 255])));
    let Some(Value::Map(h)) = &st.fields[&7].default else { panic!() };
    assert_eq!(h.get(&Value::Int(1)), Some(&Value::Enum(0, None)));
}

#[test]
fn errors_carry_line_and_column() {
    let e = parse("f.osis", "revision 1;\ntype x = struct { a 0 int };").unwrap_err();
    assert_eq!((e.file.as_str(), e.line, e.col), ("f.osis", 2, 23));
    assert!(e.to_string().starts_with("f.osis:2:23: expected `:`"), "{e}");
    let e = err("aspect x:y.0: nope;");
    assert_eq!((e.line, e.col), (2, 1));
    assert!(e.msg.contains("unknown type nope"), "{e}");
    // no schema ID item: a schema is not identified on the wire (spec/versioning.md §3)
    let e = parse("f.osis", "revision 1; schema 0x01;").unwrap_err();
    assert!(e.msg.contains("expected `aspect` or `signal`"), "{e}");
    let e = parse("f.osis", "revision 1;\ntype x = struct { a 0: string = \"unterminated };").unwrap_err();
    assert!(e.msg.contains("unterminated"), "{e}");
    // the revision comes first, once
    assert!(parse("f.osis", "type x = int;").unwrap_err().msg.contains("`revision <n>;` first"));
    assert!(parse("f.osis", "version 1;").unwrap_err().msg.contains("`revision <n>;` first"));
    assert!(err("revision 2;").msg.contains("duplicate revision"));
}

#[test]
fn validation_rules_spec_data_model_3() {
    for (src, needle) in [
        ("type x = set<counter<int>>;", "not allowed in set elements"),
        ("type x = map<text, int>;", "not allowed in set elements"),
        ("type x = set<struct { a 0: max<int> }>;", "not allowed in set elements"),
        ("type x = map<markdown, int>;", "not allowed in set elements"),
        ("type x = counter<string>;", "int or float"),
        ("type x = option<int, int>;", "takes 1 type argument"),
        ("type x<T> = list<U>;", "unknown type U"),
        ("type x = x;", "does not reach a structure"),
        ("type a = b; type b = a;", "does not reach a structure"),
        ("type x = struct { a 0: int, reserved 0 };", "both declared and reserved"),
        ("type x = struct { a 0: int, b 0: int };", "duplicate field ID 0"),
        ("type x = struct { a 0: int, a 1: int };", "duplicate field name a"),
        ("type x = struct { a 0: int succeeds 9 };", "succeeds unknown"),
        ("type x = struct { a 0: int = \"s\" };", "does not fit"),
        ("type x = enum { a 0 } ; type y = struct { f 0: x = b };", "unknown case b"),
        ("type option = int;", "invalid type name"),
        ("purge_on_replace aspect x:a.0: int;", "needs purgeable by writer"),
        ("purgeable_by(nobody) aspect x:a.0: int;", "needs history kept forever"),
        ("purgeable_by(nobody) keep_history(1d) aspect x:a.0: int;", "needs history kept forever"),
        ("aspect x.0: int; aspect x:a.0: int;", "core AKs"),
        ("aspect x:a.0: int; aspect x:a.0: int;", "duplicate aspect"),
        ("type x<T> = struct { a 0: T = 1 };", "cannot type a default"),
        ("purgeable_by(admin) ephemeral aspect x:a+.0: int;", "durable aspects only"),
        ("keep_history(forever) ephemeral signal x:a+~0: int;", "durable aspects only"),
        ("expires(5s) ephemeral signal x:a+~0: int;", "no value to expire"),
        ("signal x:a~0: int;", "durable signals are not supported yet"),
        ("ephemeral aspect x+.0: int;", "core aspects are durable"),
        ("aspect x:a.01: int;", "invalid AK"),
        ("admin aspect x:a^.0^: int;", "invalid AK"),
        ("aspect :AAAAAAAAAAAAAAAAAAA:a.0: int;", "invalid AK"),
        ("aspect x:a: int;", "expected an AK"),
        ("aspect /x/a: int;", "unexpected character '/'"),
    ] {
        let e = err(src);
        assert!(e.msg.contains(needle), "{src}: {e}");
    }
    // a tid-prefixed app key, its successor version, a marker run (spec/data-model.md §2)
    let s = app("aspect :AAAAAAAAAAAAAAAAAAAA:a.0: int; ephemeral admin aspect :AAAAAAAAAAAAAAAAAAAA:a+^.1: text succeeds (x:b.0, y:c.0);").unwrap();
    assert_eq!(s.aspects[":AAAAAAAAAAAAAAAAAAAA:a+^.1"].succeeds.len(), 2);
    // the lifetime is the key's marker (spec/data-model.md §2), no flag; the form round-trips
    let s = app("expires(5s) ephemeral aspect x:e+.0: int; ephemeral signal x:s+~0: string; aspect x:d.0: int;").unwrap();
    assert_eq!(s.defaults("x:e+.0").unwrap().expires, Some(5_000));
    assert_eq!(Schema::from_value(&s.to_value()).unwrap(), s);
    // history: unnamed by default, kept for good, for a while after replaced, or purged on replace
    let s = app("aspect x:n.0: int; purgeable_by(nobody) keep_history(forever) aspect x:f.0: int; keep_history(1d) aspect x:k.0: int; purgeable_by(writer) purge_on_replace aspect x:p.0: int;").unwrap();
    let h = |ak: &str| s.aspects[ak].retention.history;
    assert_eq!(h("x:n.0"), None);
    assert_eq!(h("x:f.0"), Some(History::FOREVER));
    assert_eq!(h("x:k.0"), Some(History::Keep { until: None, after: Some(86_400_000) }));
    assert_eq!(h("x:p.0"), Some(History::PurgeOnReplace));
    assert_eq!(Schema::from_value(&s.to_value()).unwrap(), s);
    // a fixed date is no schema default, whether parsed or built
    let mut bad = s.clone();
    bad.aspects.get_mut("x:k.0").unwrap().retention.history = Some(History::Keep { until: Some(5), after: None });
    assert!(bad.validate().iter().any(|i| i.msg.contains("keep_history(forever), keep_history(<duration>) or purge_on_replace")));
    // Wrappers are fine in mergeable positions, and under a parameter instantiated well.
    app("type c<T> = counter<T>; type x = struct { a 0: c<int>, b 1: map<string, max<float>>, l 2: list<text> };").unwrap();
    let e = err("type c<T> = counter<T>; aspect x:a.0: c<string>;");
    assert!(e.msg.contains("int or float"), "{e}");
}

// The keywords before `aspect`/`signal` agree with the key's markers; a mismatch shows the key
// the keywords need (spec/data-model.md §2).
#[test]
fn keywords_match_markers() {
    for (src, want) in [
        ("aspect x:a+.0: int;", "`aspect` needs `x:a.0`"),
        ("aspect x:a^.0: int;", "`aspect` needs `x:a.0`"),
        ("ephemeral aspect x:a.0: int;", "`ephemeral aspect` needs `x:a+.0`"),
        ("admin aspect x:a.3: int;", "`admin aspect` needs `x:a^.3`"),
        ("ephemeral admin aspect osis_app:open.0: int;", "`ephemeral admin aspect` needs `osis_app:open+^.0`"),
        ("ephemeral aspect x:a+~0: int;", "`ephemeral aspect` needs `x:a+.0`"),
        ("ephemeral signal x:a+.0: int;", "`ephemeral signal` needs `x:a+~0`"),
        ("signal x:a+~0: int;", "`signal` needs `x:a~0`"),
        ("ephemeral admin signal :AAAAAAAAAAAAAAAAAAAA:a.1: int;", "`ephemeral admin signal` needs `:AAAAAAAAAAAAAAAAAAAA:a+^~1`"),
    ] {
        let e = err(src);
        assert!(e.msg.contains(want), "{src}: {e}");
    }
    // keyword order is fixed: modifiers, ephemeral, admin, aspect/signal
    assert!(err("admin ephemeral aspect x:a+^.0: int;").msg.contains("expected `aspect` or `signal`"));
    assert!(err("ephemeral expires(5s) aspect x:a+.0: int;").msg.contains("expected `aspect` or `signal`"));
    // marker order in the key is fixed too
    assert!(err("ephemeral admin aspect x:a^+.0: int;").msg.contains("invalid AK"));
    assert!(err("aspect x:a.0^: int;").msg.contains("invalid AK"));
    for ok in ["ephemeral aspect x:a+.0: int;", "admin aspect x:a^.0: int;", "ephemeral admin aspect x:a+^.0: int;", "ephemeral signal x:a+~0: int;", "ephemeral admin signal x:a+^~0: int;"] {
        app(ok).unwrap_or_else(|e| panic!("{ok}: {e}"));
    }
}

// Versions of one name ascend in file order; a higher one succeeds the lower implicitly, so
// `succeeds` names other names only (spec/data-model.md §2).
#[test]
fn versions_ascend_and_succeed_implicitly() {
    let s = app("aspect x:a.0: int; aspect x:b.0: int; aspect x:a.2: text; ephemeral aspect x:a+.3: int; aspect x:c.0: int succeeds x:a.0;").unwrap();
    assert!(s.aspects["x:a.2"].succeeds.is_empty());
    assert!(osis_base::Ak::new("x:a+.3").unwrap().successor_of(&osis_base::Ak::new("x:a.2").unwrap()));
    let e = err("aspect x:a.2: int; aspect x:b.0: int; aspect x:a.1: int;");
    assert!(e.msg.contains("x:a.1 after x:a.2: versions of one name are declared in ascending order"), "{e}");
    assert!(err("ephemeral aspect x:a+.2: int; aspect x:a.1: int;").msg.contains("ascending order"));
    let e = err("aspect x:a.0: int; aspect x:a.1: int succeeds x:a.0;");
    assert!(e.msg.contains("succeeds the lower ones already"), "{e}");
    // markers change only with a new version
    assert!(err("aspect x:a.0: int; ephemeral aspect x:a+.0: int;").msg.contains("only in markers"));
}

// Modifiers come before the keywords, in any order, each at most once; the `[...]` list and
// `until` dates are gone.
#[test]
fn prefix_modifiers() {
    let a = |src: &str| {
        let s = app(src).unwrap_or_else(|e| panic!("{src}: {e}"));
        s.aspects.into_values().next().unwrap()
    };
    assert_eq!(a("synthetic aspect x:a.0: int;").flags, [Flag::Synthetic].into());
    assert_eq!(a("guaranteed synthetic aspect x:a.0: int;").flags, [Flag::Synthetic, Flag::Guaranteed].into());
    assert_eq!(a("purgeable_by(writer) purge_on_replace aspect x:a.0: int;").retention, Retention { by: PurgeBy::Writer, history: Some(History::PurgeOnReplace) });
    assert_eq!(a("purge_on_replace purgeable_by(writer) aspect x:a.0: int;").retention.history, Some(History::PurgeOnReplace));
    for (by, want) in [("nobody", PurgeBy::Nobody), ("admin", PurgeBy::Admin), ("author", PurgeBy::Author), ("writer", PurgeBy::Writer), ("author, admin", PurgeBy::AuthorOrAdmin), ("admin, author", PurgeBy::AuthorOrAdmin)] {
        assert_eq!(a(&format!("purgeable_by({by}) keep_history(forever) aspect x:a.0: int;")).retention.by, want, "{by}");
    }
    assert_eq!(a("keep_history(forever) aspect x:a.0: int;").retention.history, Some(History::FOREVER));
    assert_eq!(a("keep_history(12h) aspect x:a.0: int;").retention.history, Some(History::Keep { until: None, after: Some(12 * 3_600_000) }));
    assert_eq!(a("expires(250ms) aspect x:a.0: int;").expires, Some(250));
    // whitespace-insensitive: a long list on its own line
    assert_eq!(a("/// doc\npurgeable_by(author)\n  keep_history(30d) expires(1d)\naspect x:a.0: int;").doc.as_deref(), Some("doc"));
    for (src, needle) in [
        ("aspect x:a.0: int [synthetic];", "expected `;`"),
        ("aspect x:a.0: int [by: writer, purge_on_replace];", "expected `;`"),
        ("keep_history(until 5) aspect x:a.0: int;", "keep_history takes forever or a duration"),
        ("keep_history(1d until 5) aspect x:a.0: int;", "expected `)`"),
        ("keep_history(soon) aspect x:a.0: int;", "keep_history takes forever or a duration"),
        ("keep_history(1d) keep_history(2d) aspect x:a.0: int;", "duplicate keep_history"),
        ("purgeable_by(writer) purge_on_replace keep_history(1d) aspect x:a.0: int;", "exclude each other"),
        ("synthetic synthetic aspect x:a.0: int;", "duplicate synthetic"),
        ("purgeable_by(everyone) aspect x:a.0: int;", "purgeable_by takes"),
        ("purgeable_by(author_or_admin) aspect x:a.0: int;", "purgeable_by takes"),
        ("purgeable_by(author, writer) aspect x:a.0: int;", "purgeable_by takes"),
        ("purgeable_by(author) purge_on_replace aspect x:a.0: int;", "needs purgeable by writer"),
        ("purgeable_by(author, admin) purge_on_replace aspect x:a.0: int;", "needs purgeable by writer"),
        ("expires(5) aspect x:a.0: int;", "expected a duration"),
        ("expires(5s aspect x:a.0: int;", "expected `)`"),
        ("frob aspect x:a.0: int;", "expected `aspect` or `signal`"),
        ("by(writer) aspect x:a.0: int;", "expected `aspect` or `signal`"),
    ] {
        let e = err(src);
        assert!(e.msg.contains(needle), "{src}: {e}");
    }
}

// Fields are `name N: type`, cases `name N` or `name N (type)`; numbers explicit, in any order.
#[test]
fn field_and_case_syntax() {
    let s = app("type e = enum { b 2, a 0 (int), c 1 (struct { y 1: int, x 0: string }), reserved 7 };\n\
                 type s = struct { z 3: int = 4, reserved 1: string, a 0: e = a(5), reserved (4, 5) };").unwrap();
    let Type::Enum(en) = &s.types["e"].body else { panic!() };
    assert_eq!(en.cases.iter().map(|(id, c)| (*id, c.name.as_str(), c.payload.is_some())).collect::<Vec<_>>(), [(0, "a", true), (1, "c", true), (2, "b", false)]);
    assert!(en.reserved.contains(&7));
    let Type::Struct(st) = &s.types["s"].body else { panic!() };
    assert_eq!(st.fields.iter().map(|(id, f)| (*id, f.name.as_str())).collect::<Vec<_>>(), [(0, "a"), (1, "reserved"), (3, "z")], "a field may be named reserved");
    assert_eq!(st.reserved, [4, 5].into());
    assert_eq!(st.fields[&0].default, Some(Value::Enum(0, Some(Box::new(Value::Int(5))))));
    for (src, needle) in [
        ("type x = struct { 0 a: int };", "expected a field name or `reserved`"),
        ("type x = struct { a: int };", "expected the field's number"),
        ("type x = struct { a @0: int };", "unexpected character '@'"),
        ("type x = enum { 0 a };", "expected a case name or `reserved`"),
        ("type x = enum { a };", "expected the case's number"),
        ("type x = enum { a(int) 0 };", "expected the case's number"),
        ("type x = struct { a 0: int, b 0: int };", "duplicate field ID 0"),
        ("type x = struct { a 0: int, a 1: int };", "duplicate field name a"),
        ("type x = struct { a 0: int, reserved 0 };", "both declared and reserved"),
    ] {
        let e = err(src);
        assert!(e.msg.contains(needle), "{src}: {e}");
    }
}

#[test]
fn markers_not_part_of_name_spec_data_model_2() {
    for (a, b) in [("x:a.0", "x:a+.0"), ("x:a.0", "x:a^.0"), ("x:a+.0", "x:a+~0"), ("x:a^.0", "x:a+^.0"), (":AAAAAAAAAAAAAAAAAAAA:a.0", ":AAAAAAAAAAAAAAAAAAAA:a+~0")] {
        let kw = |k: &str| {
            let (_, l) = osis_base::Ak::markers_of(k);
            let admin = osis_base::Ak::markers_of(k).0;
            format!("{}{}{}", if l == Lifetime::Durable { "" } else { "ephemeral " }, if admin { "admin " } else { "" }, if l == Lifetime::Signal { "signal" } else { "aspect" })
        };
        let e = err(&format!("{} {a}: int; {} {b}: int;", kw(a), kw(b)));
        assert!(e.msg.contains("only in markers"), "{a} {b}: {e}");
    }
    app("aspect x:a.0: int; ephemeral aspect x:a+.1: int; admin aspect x:b^.0: int; ephemeral aspect :AAAAAAAAAAAAAAAAAAAA:a+.0: int;").unwrap();
    let e = parse("c.osis", "revision 1;\naspect x.0: int;\nadmin aspect x^.0: int;").unwrap_err();
    assert!(e.msg.contains("only in markers"), "{e}");
}

#[test]
fn deep_nesting_is_an_error_not_a_crash() {
    let deep = format!("type x = {}int{};", "list<".repeat(200), ">".repeat(200));
    let e = err(&deep);
    assert!(e.msg.contains("nested too deeply"), "{e}");
}

#[test]
fn core_aspects_only_in_core_schema() {
    let e = parse("c.osis", "revision 1;\naspect a.0: int;\naspect a:b.0: int;").unwrap_err();
    assert!(e.msg.contains("core AKs"), "{e}");
    assert!(parse("c.osis", "revision 1;\naspect a.0: int;").unwrap().declares_core());
    assert!(!parse("c.osis", "revision 1;\naspect a:b.0: int;").unwrap().declares_core());
}

proptest::proptest! {
    /// The parser never panics: arbitrary text, and the example schema with a byte range replaced
    /// (errors only; fuzzing proper is test-infra's).
    #[test]
    fn parser_total_on_garbage(s in "\\PC{0,200}", cut in 0usize..1500, len in 0usize..40, junk in "[{}()<>;:,=\\[\\]/a-z0-9 \"-]{0,12}") {
        let _ = parse("g.osis", &s);
        let mut src = EXAMPLE.to_string();
        let a = cut.min(src.len());
        let b = (a + len).min(src.len());
        if src.is_char_boundary(a) && src.is_char_boundary(b) {
            src.replace_range(a..b, &junk);
            let _ = parse("g.osis", &src);
        }
    }
}

// spec/commits.md §5, spec/wire.md §1: every purge class has its syntax and code; the meta form
// round trips them; the default is `author_or_admin`.
#[test]
fn purge_classes_spec_commits_5() {
    for by in PurgeBy::ALL {
        let keep = if by == PurgeBy::Nobody { " keep_history(forever)" } else { "" };
        let who = if by == PurgeBy::AuthorOrAdmin { "author, admin" } else { by.name() };
        let src = format!("revision 1; purgeable_by({who}){keep} aspect x:a.0: int;");
        let s = parse("t.osis", &src).unwrap();
        assert_eq!(s.aspects["x:a.0"].retention.by, by);
        assert_eq!(PurgeBy::from_id(by as u64), Some(by));
        assert_eq!(Schema::from_value(&s.to_value()).unwrap(), s);
    }
    assert_eq!(parse("t.osis", "revision 1; aspect x:a.0: int;").unwrap().aspects["x:a.0"].retention.by, PurgeBy::AuthorOrAdmin);
}
