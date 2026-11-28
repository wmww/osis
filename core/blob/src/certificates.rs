//! Certificate copies with their creation records (spec/wire.md §11.2: a Stranded report's holder
//! keys, a Prove's evidence).

use crate::Error;
use crate::cbor::{records_from, records_value};
use osis_base::{CreationRecord, Value};

/// Certificate copies (`CommitBlobPlaintext` values, spec/wire.md §4) and the raw creation records
/// they need, ascending by tid, distinct: a Stranded report's holder keys (the holder's current
/// `keys.0` commits, each projected to that delta, with their evidence), or a Prove's copies (grant
/// writes on its proofs' key hops and claimed paths, with their evidence).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Certificates {
    pub commits: Vec<Value>,
    pub records: Vec<CreationRecord>,
}

impl Certificates {
    pub fn to_values(&self) -> [Value; 2] {
        [Value::List(self.commits.clone()), records_value(&self.records)]
    }

    /// From the two lists; at most `max` commits.
    pub fn from_values(commits: &Value, records: &Value, max: usize) -> Result<Certificates, Error> {
        let (Value::List(commits), Value::List(records)) = (commits, records) else { return Err(Error::Malformed("certificates")) };
        if commits.len() > max || !commits.iter().all(|c| matches!(c, Value::List(_))) {
            return Err(Error::Malformed("certificate commits"));
        }
        Ok(Certificates { commits: commits.clone(), records: records_from(records)? })
    }

    pub fn is_empty(&self) -> bool {
        self.commits.is_empty() && self.records.is_empty()
    }
}
