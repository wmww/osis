//! Paths into values (notes/api.md Reads) and typed-read errors that carry them
//! (spec/versioning.md §5).

use osis_core::{Classified, ErrorClass, Tid, Value};
use std::fmt;

/// One step into a value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Step {
    /// Struct field ID.
    Field(u64),
    /// Payload of enum case ID.
    Case(u64),
    /// Map entry by key.
    Key(Value),
    /// List element by index.
    Index(usize),
    /// Set element by value.
    Elem(Value),
}

/// A struct field ID, as generated field constants hold it (`task::DONE`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FieldId(pub u64);

/// An enum case ID, as generated case constants hold it (`priority::HIGH`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CaseId(pub u64);

impl From<usize> for Step {
    fn from(i: usize) -> Step {
        Step::Index(i)
    }
}
impl From<FieldId> for Step {
    fn from(f: FieldId) -> Step {
        Step::Field(f.0)
    }
}
impl From<CaseId> for Step {
    fn from(c: CaseId) -> Step {
        Step::Case(c.0)
    }
}
impl From<&str> for Step {
    fn from(k: &str) -> Step {
        Step::Key(Value::Str(k.into()))
    }
}
impl From<Tid> for Step {
    fn from(k: Tid) -> Step {
        Step::Key(Value::Tid(k))
    }
}
impl From<Value> for Step {
    fn from(k: Value) -> Step {
        Step::Key(k)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Path(pub Vec<Step>);

impl Path {
    pub fn root() -> Path {
        Path(Vec::new())
    }
    pub fn steps(&self) -> &[Step] {
        &self.0
    }
    pub fn push(mut self, s: impl Into<Step>) -> Path {
        self.0.push(s.into());
        self
    }
}

/// Builds a `Path` from steps: list indices (`usize` literals), field and case constants, keys
/// (`&str`, `Tid`, `Value`). `p![2, task::DONE]`.
#[macro_export]
macro_rules! p {
    ($($s:expr),* $(,)?) => { $crate::Path(vec![$($crate::Step::from($s)),*]) };
}

impl fmt::Display for Path {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.is_empty() {
            return f.write_str("(root)");
        }
        for s in &self.0 {
            match s {
                Step::Field(id) => write!(f, ".{id}")?,
                Step::Case(id) => write!(f, "#{id}")?,
                Step::Key(k) => write!(f, "[{k:?}]")?,
                Step::Index(i) => write!(f, "[{i}]")?,
                Step::Elem(e) => write!(f, "{{{e:?}}}")?,
            }
        }
        Ok(())
    }
}

/// Why a typed read or a write validation failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PathErrorKind {
    /// The value's kind does not match the type.
    Mismatch { expected: &'static str },
    /// An enum case the schema does not declare (newer data). Parked.
    UnknownCase(u64),
    /// A CBOR tag this build does not know. Parked.
    UnknownTag(u64),
    /// A declared field without default is absent (or, on write, any declared field).
    MissingField(u64),
    /// The case has a payload type but no payload.
    MissingPayload(u64),
    /// The case has no payload type but carries one.
    UnexpectedPayload(u64),
    /// A write carries a field the writer's schema does not declare.
    UndeclaredField(u64),
    /// The path leads nowhere in the value or the type.
    NotFound,
    /// A write nests deeper than `MAX_VALUE_DEPTH`.
    TooDeep,
    /// The schema cannot type the position (unknown name; only for unvalidated schemas).
    Schema(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathError {
    pub path: Path,
    pub kind: PathErrorKind,
}

impl PathError {
    pub fn new(path: Path, kind: PathErrorKind) -> PathError {
        PathError { path, kind }
    }
    /// Prefixes the path with a step (for nested codecs).
    pub fn within(mut self, s: impl Into<Step>) -> PathError {
        self.path.0.insert(0, s.into());
        self
    }
}

impl fmt::Display for PathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let p = &self.path;
        match &self.kind {
            PathErrorKind::Mismatch { expected } => write!(f, "at {p}: expected {expected}"),
            PathErrorKind::UnknownCase(c) => write!(f, "at {p}: unknown enum case {c}"),
            PathErrorKind::UnknownTag(t) => write!(f, "at {p}: unknown tag {t}"),
            PathErrorKind::MissingField(id) => write!(f, "at {p}: missing field {id}"),
            PathErrorKind::MissingPayload(c) => write!(f, "at {p}: case {c} lacks its payload"),
            PathErrorKind::UnexpectedPayload(c) => write!(f, "at {p}: case {c} has no payload type"),
            PathErrorKind::UndeclaredField(id) => write!(f, "at {p}: field {id} is not declared"),
            PathErrorKind::NotFound => write!(f, "at {p}: not found"),
            PathErrorKind::TooDeep => write!(f, "at {p}: value too deep"),
            PathErrorKind::Schema(m) => write!(f, "at {p}: {m}"),
        }
    }
}

impl std::error::Error for PathError {}

impl Classified for PathError {
    /// Unknown cases and tags are newer data (parked); everything else is a malformed value.
    fn class(&self) -> ErrorClass {
        match self.kind {
            PathErrorKind::UnknownCase(_) | PathErrorKind::UnknownTag(_) => ErrorClass::Parked,
            PathErrorKind::Schema(_) => ErrorClass::Local,
            _ => ErrorClass::BadInput,
        }
    }
}
