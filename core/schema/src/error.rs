//! Errors (notes/architecture.md §3).

use crate::path::PathError;
use osis_base::{Classified, ErrorClass};

/// A schema source error at file, line, column.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParseError {
    pub file: String,
    pub line: u32,
    pub col: u32,
    pub msg: String,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}:{}: {}", self.file, self.line, self.col, self.msg)
    }
}

impl std::error::Error for ParseError {}

#[derive(Debug)]
pub enum Error {
    /// A schema source does not parse or validate. Local.
    Parse(ParseError),
    /// A schema value (spec/data-model.md §10) is malformed or invalid. BadInput.
    Form(String),
    /// A lock file is malformed. Local.
    Lock(String),
    /// A revision breaks the evolution rules against its lock (spec/versioning.md §4). Local.
    Evolution(Vec<crate::check::Violation>),
    /// A typed read or write validation failed; class per kind.
    Path(PathError),
    /// Code generation cannot express the schema. Local.
    Codegen(String),
    /// Reading or writing a file (codegen tool). Local.
    Io(String),
}

osis_base::impl_error!(Error {
    Parse(e) => ("{e}"),
    Form(m) => ("schema value: {m}"),
    Lock(m) => ("lock file: {m}"),
    Evolution(v) => ("evolution rules broken: {}", v.iter().map(ToString::to_string).collect::<Vec<_>>().join("; ")),
    Path(e) => ("{e}"),
    Codegen(m) => ("codegen: {m}"),
    Io(m) => ("io: {m}"),
});

impl Classified for Error {
    fn class(&self) -> ErrorClass {
        match self {
            Error::Form(_) => ErrorClass::BadInput,
            Error::Path(e) => e.class(),
            Error::Parse(_) | Error::Lock(_) | Error::Evolution(_) | Error::Codegen(_) | Error::Io(_) => ErrorClass::Local,
        }
    }
}

impl From<ParseError> for Error {
    fn from(e: ParseError) -> Error {
        Error::Parse(e)
    }
}

impl From<PathError> for Error {
    fn from(e: PathError) -> Error {
        Error::Path(e)
    }
}
