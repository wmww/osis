//! Schemas embedded as source and parsed on first use (the core schema, generated code).

use crate::parse::parse;
use crate::schema::Schema;
use std::sync::OnceLock;

/// A schema source compiled into the binary. The source was checked when it was embedded
/// (tests, codegen), so parsing cannot fail; if it does anyway (a bug), `get` returns a schema
/// that declares nothing, so every typed write through it fails validation loudly.
pub struct StaticSchema {
    file: &'static str,
    src: &'static str,
    cell: OnceLock<Schema>,
}

impl StaticSchema {
    pub const fn new(file: &'static str, src: &'static str) -> StaticSchema {
        StaticSchema { file, src, cell: OnceLock::new() }
    }
    pub fn get(&self) -> &Schema {
        self.cell.get_or_init(|| parse(self.file, self.src).unwrap_or_else(|_| Schema::new(0)))
    }
    pub fn file(&self) -> &'static str {
        self.file
    }
    pub fn source(&self) -> &'static str {
        self.src
    }
}

/// Source of the core schema (spec/data-model.md §9).
pub const CORE_SRC: &str = include_str!("../../../schema/core.osis");
pub static CORE: StaticSchema = StaticSchema::new("core.osis", CORE_SRC);

/// The core schema (spec/data-model.md §9).
pub fn core_schema() -> &'static Schema {
    CORE.get()
}
