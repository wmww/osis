//! A stranded report's holder keys (spec/wire.md §11.2 Stranded).

use crate::Error;
use crate::cbor::{records_from, records_value};
use osis_base::{CreationRecord, Value};

/// A stranded report's holder keys (spec/wire.md §11.2 Stranded): the holder's current `keys.0` commits, each
/// projected to that delta, with their evidence, as certificate copies (`CommitBlobPlaintext`
/// values), and that evidence's raw creation records, ascending by tid, distinct. A reader of the sync ID's actor that is gone from the
/// holder seals it at its keyset and deposits under its inbox from these alone.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HolderKeys {
    pub commits: Vec<Value>,
    pub records: Vec<CreationRecord>,
}

impl HolderKeys {
    pub fn to_values(&self) -> [Value; 2] {
        [Value::List(self.commits.clone()), records_value(&self.records)]
    }

    pub fn from_values(commits: &Value, records: &Value) -> Result<HolderKeys, Error> {
        let (Value::List(commits), Value::List(records)) = (commits, records) else { return Err(Error::Malformed("holder keys")) };
        if !commits.iter().all(|c| matches!(c, Value::List(_))) {
            return Err(Error::Malformed("holder keys commits"));
        }
        Ok(HolderKeys { commits: commits.clone(), records: records_from(records)? })
    }
}
