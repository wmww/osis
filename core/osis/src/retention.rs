//! What a thing keeps of replaced content (its setting), in the API's time types; the engine's
//! counts in plain milliseconds.

use osis_base::{Ak, Time, Value};
use osis_schema::{Codec, PathError};
use std::time::Duration;

fn ms(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

/// What a thing keeps of a write once something replaces it (`RetentionEntry::history`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum History {
    /// Kept, and listed (`AspectRef::writes`), until `until` and for `after_replaced` after something
    /// replaces the write, whichever is later; earlier it goes only by a purge or its expiry. A
    /// zero or a past bound keeps nothing: with both, this is no promise, written as `None`.
    Keep {
        /// Until this time.
        until: Time,
        /// For this long after the write is replaced.
        after_replaced: Duration,
    },
    /// Gone from every node once something replaces the write: the old value cannot be read back
    /// or undone. Every change to such a write costs more than under the other choices; rarely
    /// the right choice. Once set for an aspect of a thing, a later `Keep` there keeps nothing.
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

/// Canonical: a `Keep` with both bounds zero is `None`.
fn history_into(h: History) -> Option<osis_schema::History> {
    match h {
        History::Keep { until, after_replaced } => {
            let (until, after) = (Some(until.0).filter(|t| *t > 0), Some(ms(after_replaced)).filter(|d| *d > 0));
            (until.is_some() || after.is_some()).then_some(osis_schema::History::Keep { until, after })
        }
        History::PurgeOnReplace => Some(osis_schema::History::PurgeOnReplace),
    }
}

/// A write says only who may purge it (its purge-by), checked at compile time: its thing's setting
/// says what history keeps.
/// ```
/// let _ = osis::PurgeBy::Writer;
/// let _ = osis::core::RETENTION;
/// ```
/// Nothing beside the setting rules a thing's writes.
/// ```compile_fail,E0425
/// let _ = osis::core::REQUIRED;
/// ```
/// The author alone is no purge set: admins always may.
/// ```compile_fail,E0599
/// let _ = osis::PurgeBy::Author;
/// ```
#[cfg(doctest)]
pub struct RemovedChecks;

/// What a thing keeps of one aspect's replaced content, and the expiry its writes get
/// (`RetentionSetting`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RetentionEntry {
    /// What history keeps of a replaced write: `None`, the default, promises nothing; a replaced
    /// write is held only while convenient and is not listed.
    pub history: Option<History>,
    /// How long after it is written a write expires unless it says otherwise; none: the schema's
    /// default. Only the writer reads it: a write keeps the expiry it was written with.
    pub expires: Option<Duration>,
    /// A writer refuses to replace a fire here (`replace` is `Invalid`). Only the writer reads
    /// it: an edit written anyway is honored.
    pub refuse_replace: bool,
}

impl From<RetentionEntry> for osis_schema::core_types::RetentionEntry {
    fn from(r: RetentionEntry) -> osis_schema::core_types::RetentionEntry {
        let history = r.history.and_then(history_into);
        osis_schema::core_types::RetentionEntry { history, expires: r.expires.map(ms), r#final: r.refuse_replace, purge_before: None }
    }
}

impl From<&osis_schema::core_types::RetentionEntry> for RetentionEntry {
    fn from(r: &osis_schema::core_types::RetentionEntry) -> RetentionEntry {
        RetentionEntry { history: r.history.map(history_from), expires: r.expires.map(Duration::from_millis), refuse_replace: r.r#final }
    }
}

/// What a thing keeps of replaced content and what a removal from it leaves behind: the value of
/// `core::RETENTION`, written whole and read like any aspect by an admin of the thing. The newest
/// decides what history keeps of every replaced write a node still holds, so a longer one may
/// bring back what a node has not dropped; what was written under purge on replace never comes
/// back.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RetentionSetting {
    /// The entry for each aspect named. An entry naming an external signal (an `@` key) also
    /// opens it to everyone: anyone holding the thing's public key may fire it, not only its
    /// writers. Without one, a fire of it by an actor holding no write is refused
    /// (`Error::NotEnabled`) and counts nowhere. The newest setting decides, also for fires made
    /// before it: dropping the entry withdraws the fires of non-writers not yet taken.
    pub rules: std::collections::BTreeMap<Ak, RetentionEntry>,
    /// The entry for every aspect not in `rules` but an external (`@`) signal, which only its own entry
    /// keeps; none: nothing is kept there.
    pub default: Option<RetentionEntry>,
    /// A holder removed from the thing retains a read-only copy, unless its remover says otherwise
    /// (`SetRoleOpts::retain_copy`).
    pub retain_copies: bool,
    /// A strong reference in a version this thing still holds in its history keeps its target
    /// held, as one in a current value does, so restoring the version finds what it names. Its
    /// writers can keep a target held for as long as the history keeps the version.
    pub history_holds_targets: bool,
}

impl RetentionSetting {
    /// Enables the external signals a thing takes as its own inbox, as an account's inbox has them:
    /// a ticket from a grant to it, the notice of its removal from a thing, and a reader's call
    /// for the keys it cannot read, each from parties that cannot write it, kept for as long as an
    /// account's inbox keeps them. An entry already here stays as it is. A thing others will read,
    /// or that will be granted roles on other things, needs them to learn of these without one of
    /// its writers connected.
    pub fn enable_inbox_signals(&mut self) {
        let mut x = osis_schema::core_types::RetentionSetting::default();
        x.take_inbox_signals();
        for (k, e) in &x.rules {
            self.rules.entry(k.clone()).or_insert(e.into());
        }
    }
}

impl Codec for RetentionSetting {
    fn to_value(&self) -> Value {
        let rules = self.rules.iter().map(|(k, r)| (k.clone(), (*r).into())).collect();
        osis_schema::core_types::RetentionSetting { rules, retain: self.retain_copies, default: self.default.map(Into::into), history_holds_targets: self.history_holds_targets }.to_value()
    }
    fn from_value(v: &Value) -> Result<RetentionSetting, PathError> {
        let r = osis_schema::core_types::RetentionSetting::from_value(v)?;
        let rules = r.rules.iter().map(|(k, x)| (k.clone(), x.into())).collect();
        Ok(RetentionSetting { rules, default: r.default.as_ref().map(Into::into), retain_copies: r.retain, history_holds_targets: r.history_holds_targets })
    }
}
