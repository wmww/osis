//! osis-schema: the type system, the `*.osis` DSL (hand-written parser), schema identity and the
//! additive evolution checker, typed reads and write validation, the `View` for the structural
//! diff, the core schema and its Rust types, typed aspect keys, codegen (spec/data-model.md §2–§5,
//! §9, §10; spec/versioning.md).
//! Layer 2 (notes/architecture.md). Notes: notes/architecture.md §8, notes/versioning.md.
#![forbid(unsafe_code)]

/// Re-exported for generated code.
pub use osis_base;

mod check;
pub mod codec;
mod codegen;
pub mod core_types;
mod error;
mod form;
mod keys;
mod lex;
mod lock;
mod parse;
mod path;
mod schema;
mod statics;
mod typed;
mod types;
mod view;

pub use check::{Rule, Violation, check};
pub use codec::{Chunked, Codec};
pub use codegen::{Generated, generate, generate_file};
pub use error::{Error, ParseError};
pub use form::{META_SRC, meta_schema, read_type, type_value};
pub use keys::{Aspect, AspectKey, Signal, SignalKey};
pub use lock::{Lock, LockStatus, check_lock};
pub use parse::parse;
pub use path::{CaseId, FieldId, Path, PathError, PathErrorKind, Step};
pub use schema::{AspectDef, AspectDefaults, Bound, Flag, Invalid, PurgeBy, Retention, Schema, SignalDef, TypeDef};
pub use statics::{CORE_SRC, StaticSchema, core_schema, core_static};
pub use typed::{read_path, type_at, typed_read, validate_write, value_at};
pub use view::{Large, SchemaView, large_positions, link_positions};
pub use types::{Case, EnumType, Field, STANDARD, StructType, Type, is_reserved_name};
