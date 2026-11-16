//! A stranded report's holder keys (spec/wire.md §11.2 Stranded).

use crate::Error;
use osis_base::{CreationRecord, Value};

/// A stranded report's holder keys (spec/wire.md §11.2 Stranded): the holder's current `keys.0` commits, each
/// projected to that delta, with their authors' chain certificates for them, as
/// `CommitBlobPlaintext` values projected to their chain deltas, and the raw creation records of
/// that chain, ascending by tid, distinct. A reader of the sync ID's actor that is gone from the
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

/// Creation records ascending by tid, distinct.
fn records_value(records: &[CreationRecord]) -> Value {
    let mut records: Vec<&CreationRecord> = records.iter().collect();
    records.sort_by_key(|r| r.tid());
    records.dedup_by_key(|r| r.tid());
    Value::List(records.into_iter().map(CreationRecord::to_value).collect())
}

/// Creation records, which must be ascending by tid and distinct.
fn records_from(records: &[Value]) -> Result<Vec<CreationRecord>, Error> {
    let records = records.iter().map(|r| CreationRecord::from_value(r).ok_or(Error::Malformed("creation record"))).collect::<Result<Vec<_>, _>>()?;
    if !records.windows(2).all(|w| matches!(w, [x, y] if x.tid() < y.tid())) {
        return Err(Error::Malformed("creation records not sorted by tid"));
    }
    Ok(records)
}
