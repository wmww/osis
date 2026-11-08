#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Codegen (notes/base-schema.md) checks that need no compiled output. The generated modules are
//! compiled and exercised by osis's integration tests (core/osis/build.rs, tests/it/codegen.rs).

use osis_schema::*;

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/");

// spec: none (codegen warns on a `list<struct>`, notes/api.md).
#[test]
fn list_struct_warning() {
    let g = generate_file(std::path::Path::new(&format!("{DIR}tests/example.osis"))).unwrap();
    assert_eq!(g.warnings.len(), 1);
    assert!(g.warnings[0].contains("note:tasks.0"), "{:?}", g.warnings);
}

// spec: none (codegen, notes/data-model.md): constant names are not injective in the key: a
// collision is a codegen error, not a duplicate item in the generated module.
#[test]
fn colliding_constant_names_refused() {
    for (a, b) in [("a:b_c.0", "a_b:c.0"), ("x:y.1", "x:y_v1.0"), ("a:b_c.0", "a_b:c+.0"), (":AAAAAAAAAAAAAAAAAAAA:x:y.0", "x:y^.0"), ("t:schema.0", "t:z.0")] {
        let d = |k: &str| format!("{}aspect {k}: int", if k.contains('+') { "ephemeral " } else if k.contains('^') { "admin " } else { "" });
        let src = format!("revision 1;\n{};\n{};\n", d(a), d(b));
        let s = parse("c.osis", &src).unwrap();
        let e = generate(&s, "c.osis", &src).unwrap_err();
        assert!(matches!(e, Error::Codegen(ref m) if m.contains("collides")), "{a} {b}: {e}");
    }
    let src = "revision 1;\naspect x:y.0: int;\naspect x:y.1: int;\n";
    assert!(generate(&parse("c.osis", src).unwrap(), "c.osis", src).is_ok());
}
