//! Lock files (`<name>.osis.lock`): the last published revision, so the checker can compare a
//! source file against it. Text: a header line, the canonical-form hash, then the canonical
//! bytes in hex, 64 digits per line. `provisional` (notes/versioning.md, Open details).

use crate::check::{Rule, Violation, check};
use crate::error::Error;
use crate::schema::Schema;
use osis_core::Limits;

const HEADER: &str = "osis-lock 1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lock {
    pub schema: Schema,
}

/// A source file against its lock.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LockStatus {
    /// The file is the published revision.
    Published,
    /// The file is an additive successor; publishing it rewrites the lock.
    Unpublished,
}

use osis_core::hex::{decode as unhex, encode as hex};

impl Lock {
    pub fn of(schema: &Schema) -> Lock {
        Lock { schema: schema.clone() }
    }

    pub fn to_text(&self) -> String {
        let bytes = hex(&self.schema.canonical_bytes());
        let mut out = format!("{HEADER}\nhash {}\n", hex(&self.schema.hash()));
        for i in (0..bytes.len()).step_by(64) {
            out.push_str(bytes.get(i..(i + 64).min(bytes.len())).unwrap_or(""));
            out.push('\n');
        }
        out
    }

    pub fn parse(text: &str) -> Result<Lock, Error> {
        let bad = |m: &str| Error::Lock(m.into());
        let mut lines = text.lines();
        if lines.next() != Some(HEADER) {
            return Err(bad("unknown header"));
        }
        let hash = lines.next().and_then(|l| l.strip_prefix("hash ")).and_then(unhex).ok_or_else(|| bad("missing hash"))?;
        let body: String = lines.map(str::trim).collect();
        let bytes = unhex(&body).ok_or_else(|| bad("bad hex"))?;
        if osis_core::hash::hash(&bytes).as_slice() != hash.as_slice() {
            return Err(bad("hash does not match"));
        }
        let v = osis_core::decode(&bytes, &Limits::DEFAULT).map_err(|e| Error::Lock(e.to_string()))?;
        Ok(Lock { schema: Schema::from_value(&v)? })
    }
}

/// Checks a source file against its lock. `allow` lists the `at` locations whose
/// `DefaultAdded` violation is explicitly marked as intended (spec/versioning.md §4).
pub fn check_lock(file: &Schema, lock: &Lock, allow: &[&str]) -> Result<LockStatus, Error> {
    if *file == lock.schema {
        return Ok(LockStatus::Published);
    }
    let v: Vec<Violation> =
        check(&lock.schema, file).into_iter().filter(|v| !(v.rule == Rule::DefaultAdded && allow.contains(&v.at.as_str()))).collect();
    if v.is_empty() { Ok(LockStatus::Unpublished) } else { Err(Error::Evolution(v)) }
}
