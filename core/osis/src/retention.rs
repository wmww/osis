//! How long a write's history is held and who may purge it, in the API's time types; the engine's
//! `osis_schema::Retention` counts in plain milliseconds.

use osis_base::{Time, Value};
use osis_schema::{Codec, PathError, PurgeBy};
use std::time::Duration;

fn ms(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

/// A limit on how long a replaced write's body is held: until a time, for a while after the write
/// was replaced, or both. Empty: no limit.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Bound {
    /// Until this time.
    pub until: Option<Time>,
    /// For this long after the write was replaced. Zero: gone once replaced.
    pub after_replaced: Option<Duration>,
}

impl Bound {
    /// For good, as a keep-at-least: the write's body and its proof of authorship stay until a purge.
    pub const FOREVER: Bound = Bound { until: Some(Time(osis_commit::FOREVER)), after_replaced: None };
}

impl From<osis_schema::Bound> for Bound {
    fn from(b: osis_schema::Bound) -> Bound {
        Bound { until: b.abs.map(Time), after_replaced: b.rel.map(Duration::from_millis) }
    }
}

impl From<Bound> for osis_schema::Bound {
    fn from(b: Bound) -> osis_schema::Bound {
        osis_schema::Bound { abs: b.until.map(|t| t.0), rel: b.after_replaced.map(ms) }
    }
}

/// Who may purge a write, and how long its history is held once something replaces it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Retention {
    /// Who may purge it.
    pub by: PurgeBy,
    /// Held at least this long, leaving earlier only by a purge. Who wrote a change, and when, is
    /// reported only while the change itself is held: `Bound::FOREVER` keeps that provable.
    pub at_least: Bound,
    /// Held at most this long.
    pub at_most: Bound,
}

impl From<osis_schema::Retention> for Retention {
    fn from(r: osis_schema::Retention) -> Retention {
        Retention { by: r.by, at_least: r.at_least.into(), at_most: r.at_most.into() }
    }
}

impl From<Retention> for osis_schema::Retention {
    fn from(r: Retention) -> osis_schema::Retention {
        osis_schema::Retention { by: r.by, at_least: r.at_least.into(), at_most: r.at_most.into() }
    }
}

/// The retention and expiry every write under one aspect name prefix must carry (`RequiredRules`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Required {
    /// The retention such a write must carry.
    pub retention: Retention,
    /// How long after it is written such a write must expire; none: it must not.
    pub expires: Option<Duration>,
}

/// What every write to a thing must keep to, and what a removal from it leaves behind: the value of
/// `core::REQUIRED`, written and read like any aspect by an admin of the thing.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RequiredRules {
    /// The rule for each aspect name prefix (`chat:msgs:`; empty for every aspect).
    pub rules: std::collections::BTreeMap<String, Required>,
    /// A holder removed from the thing retains a read-only copy, unless its remover says otherwise
    /// (`SetRoleOpts::retain_copy`).
    pub retain_copies: bool,
}

impl Codec for RequiredRules {
    fn to_value(&self) -> Value {
        let rules = self.rules.iter().map(|(p, r)| (p.clone(), osis_schema::core_types::Required::new(r.retention.into(), r.expires.map(ms)))).collect();
        osis_schema::core_types::RequiredRules { rules, keep: self.retain_copies }.to_value()
    }
    fn from_value(v: &Value) -> Result<RequiredRules, PathError> {
        let r = osis_schema::core_types::RequiredRules::from_value(v)?;
        let rules = r.rules.iter().map(|(p, x)| (p.clone(), Required { retention: x.retention().into(), expires: x.expires.map(Duration::from_millis) })).collect();
        Ok(RequiredRules { rules, retain_copies: r.keep })
    }
}
