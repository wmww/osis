//! How long a write's history is held and who may purge it, in the API's time types; the engine's
//! `osis_schema::Retention` counts in plain milliseconds.

use osis_base::{Ak, Time, Value};
use osis_schema::{Codec, PathError, PurgeBy};
use std::time::Duration;

fn ms(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

/// What happens to a write's history once something replaces it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum History {
    /// Kept, and shown by `Osis::history`, until `until` and for `after_replaced` after something
    /// replaces the write, whichever is later; earlier it goes only by a purge or its expiry. A
    /// zero or a past bound keeps nothing: with both, this is no promise, written as `None`.
    Keep {
        /// Until this time.
        until: Time,
        /// For this long after the write is replaced.
        after_replaced: Duration,
    },
    /// Gone from every node once something replaces the write: the old value cannot be read back
    /// or undone. Needs `PurgeBy::Writer`. Every change to such a write costs more than under the
    /// other choices; rarely the right choice.
    PurgeOnReplace,
}

impl History {
    /// Kept for good: who wrote each change, and when, stays provable until a purge.
    pub const FOREVER: History = History::Keep { until: Time(osis_commit::FOREVER), after_replaced: Duration::ZERO };
}

fn history_from(h: osis_schema::History) -> History {
    match h {
        osis_schema::History::Keep { until, after } => History::Keep { until: Time(until.unwrap_or(0)), after_replaced: Duration::from_millis(after.unwrap_or(0)) },
        osis_schema::History::PurgeOnReplace => History::PurgeOnReplace,
    }
}

fn history_into(h: History) -> osis_schema::History {
    match h {
        History::Keep { until, after_replaced } => osis_schema::History::Keep { until: Some(until.0).filter(|t| *t > 0), after: Some(ms(after_replaced)).filter(|d| *d > 0) },
        History::PurgeOnReplace => osis_schema::History::PurgeOnReplace,
    }
}

/// Who may purge a write, and what happens to its history once something replaces it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Retention {
    /// Who may purge it.
    pub by: PurgeBy,
    /// `None`, the default: no history is promised or shown; a replaced write is held only while
    /// convenient. `PurgeBy::Nobody` needs `History::FOREVER` (`Invalid` otherwise, at commit).
    pub history: Option<History>,
}

impl From<osis_schema::Retention> for Retention {
    fn from(r: osis_schema::Retention) -> Retention {
        Retention { by: r.by, history: r.history.map(history_from) }
    }
}

/// Canonical: a `Keep` with both bounds zero is `None`.
impl From<Retention> for osis_schema::Retention {
    fn from(r: Retention) -> osis_schema::Retention {
        osis_schema::Retention { by: r.by, history: r.history.map(history_into) }.canonical()
    }
}

/// The retention and expiry every write of one aspect must carry (`RequiredRules`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Required {
    /// The retention such a write must carry.
    pub retention: Retention,
    /// How long after it is written such a write must expire; none: it must not.
    pub expires: Option<Duration>,
}

impl From<Required> for osis_schema::core_types::Required {
    fn from(r: Required) -> osis_schema::core_types::Required {
        osis_schema::core_types::Required::new(r.retention.into(), r.expires.map(ms))
    }
}

impl From<&osis_schema::core_types::Required> for Required {
    fn from(r: &osis_schema::core_types::Required) -> Required {
        Required { retention: r.retention().into(), expires: r.expires.map(Duration::from_millis) }
    }
}

/// What every write to a thing must keep to, and what a removal from it leaves behind: the value of
/// `core::REQUIRED`, written and read like any aspect by an admin of the thing.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RequiredRules {
    /// The rule for each aspect named.
    pub rules: std::collections::BTreeMap<Ak, Required>,
    /// The rule for every aspect not in `rules`; none: those require nothing.
    pub default: Option<Required>,
    /// A holder removed from the thing retains a read-only copy, unless its remover says otherwise
    /// (`SetRoleOpts::retain_copy`).
    pub retain_copies: bool,
}

impl Codec for RequiredRules {
    fn to_value(&self) -> Value {
        let rules = self.rules.iter().map(|(k, r)| (k.clone(), (*r).into())).collect();
        osis_schema::core_types::RequiredRules { rules, retain: self.retain_copies, default: self.default.map(Into::into) }.to_value()
    }
    fn from_value(v: &Value) -> Result<RequiredRules, PathError> {
        let r = osis_schema::core_types::RequiredRules::from_value(v)?;
        let rules = r.rules.iter().map(|(k, x)| (k.clone(), x.into())).collect();
        Ok(RequiredRules { rules, default: r.default.as_ref().map(Into::into), retain_copies: r.retain })
    }
}
