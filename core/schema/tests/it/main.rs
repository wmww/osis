//! osis-schema integration tests: one binary, one module per area (notes/testing.md, When tests run).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

mod codegen;
mod core_types;
mod evolution;
mod parse;
mod robustness;
mod typed;

use osis_schema::{ParseError, Schema, parse};

/// `body` as revision `rev` of a schema file.
fn schema(rev: u64, body: &str) -> Schema {
    parse("t.osis", &format!("revision {rev};\n{body}")).unwrap()
}

/// `body` as revision 1 of a schema file, parsed.
fn app(body: &str) -> Result<Schema, ParseError> {
    parse("t.osis", &format!("revision 1;\n{body}"))
}

fn err(body: &str) -> ParseError {
    app(body).expect_err("should fail")
}
