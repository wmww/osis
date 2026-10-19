//! Schemas embedded as source and parsed on first use (the core schema, generated code).

use crate::error::ParseError;
use crate::parse::parse;
use crate::schema::Schema;
use osis_core::SchemaId;
use std::sync::OnceLock;

/// A schema source compiled into the binary. The source was checked when it was embedded
/// (tests, codegen), so parsing cannot fail; if it does anyway (a bug), `get` returns a schema
/// that declares nothing, so every typed write through it fails validation loudly.
pub struct StaticSchema {
    file: &'static str,
    src: &'static str,
    cell: OnceLock<Result<Schema, ParseError>>,
}

static BROKEN: OnceLock<Schema> = OnceLock::new();

impl StaticSchema {
    pub const fn new(file: &'static str, src: &'static str) -> StaticSchema {
        StaticSchema { file, src, cell: OnceLock::new() }
    }
    fn parsed(&self) -> &Result<Schema, ParseError> {
        self.cell.get_or_init(|| parse(self.file, self.src))
    }
    pub fn get(&self) -> &Schema {
        match self.parsed() {
            Ok(s) => s,
            Err(_) => BROKEN.get_or_init(|| Schema::new(SchemaId([0xff; 16]), 0)),
        }
    }
    /// The parse error, if the embedded source is broken.
    pub fn error(&self) -> Option<&ParseError> {
        self.parsed().as_ref().err()
    }
    pub fn source(&self) -> &'static str {
        self.src
    }
}

/// Source of the core schema (spec/data-model.md §9).
pub const CORE_SRC: &str = include_str!("../schemas/core.osis");
static CORE: StaticSchema = StaticSchema::new("core.osis", CORE_SRC);

/// The core schema (spec/data-model.md §9): ID 16 zero bytes, revision 1.
pub fn core_schema() -> &'static Schema {
    CORE.get()
}

/// The core schema as a `StaticSchema` (for typed keys).
pub fn core_static() -> &'static StaticSchema {
    &CORE
}
