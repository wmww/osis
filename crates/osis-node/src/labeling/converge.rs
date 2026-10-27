//! The convergence rule (spec/sync.md §6, §7): per body held under a label, must-hold, may-hold
//! or must-not-hold, "must-not" winning every overlap; and the carrier rule for deletions.

/// What a node knows of one body under one label.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Facts {
    /// In the label's required set (closure, certificate, grantee copy, unexpired inbox blob).
    pub required: bool,
    /// A closure body (the rest are placed from outside the closure).
    pub closure: bool,
    /// Holds a delta that was purged, expired or dropped past keep-at-most.
    pub dropped: bool,
    /// Its prefix expiry has passed.
    pub expired: bool,
    /// Its delta set is a strict subset of another blob of the commit under the label.
    pub strict_subset: bool,
    /// Another blob of the commit with the same delta set and a lower blob ID is under the label.
    pub duplicate_higher: bool,
    /// Before its keep-at-least bound.
    pub before_at_least: bool,
    /// Covered by a held snapshot under the label: `None` when not established (parked, pages
    /// not fetched).
    pub covered: Option<bool>,
    /// A certificate blob whose author has no other blob under the label.
    pub sole_certificate: bool,
}

/// Why a body must not be held.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Why {
    Dropped,
    Expired,
    Outside,
    StrictSubset,
    Duplicate,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hold {
    Must,
    May,
    MustNot(Why),
}

/// The convergence rule (spec/sync.md §6).
pub fn classify(f: &Facts) -> Hold {
    let not = if f.dropped {
        Some(Why::Dropped)
    } else if f.expired {
        Some(Why::Expired)
    } else if !f.required {
        Some(Why::Outside)
    } else if f.strict_subset {
        Some(Why::StrictSubset)
    } else if f.duplicate_higher {
        Some(Why::Duplicate)
    } else {
        None
    };
    if let Some(w) = not {
        return Hold::MustNot(w);
    }
    if !f.closure {
        return if f.sole_certificate { Hold::May } else { Hold::Must };
    }
    if f.before_at_least || f.covered == Some(false) { Hold::Must } else { Hold::May }
}

/// Whether a must-not-hold body may go now (spec/sync.md §7): an expired one at once; one with
/// live writes only while other entries under the label carry them.
pub fn may_delete(why: Why, live_writes: bool, carried: bool) -> bool {
    why == Why::Expired || !live_writes || carried
}

#[cfg(test)]
mod tests {
    use super::*;

    fn closure() -> Facts {
        Facts { required: true, closure: true, ..Facts::default() }
    }

    // spec/sync.md §6: must-hold, may-hold and must-not-hold per body; a body meeting a
    // must-not-hold condition is must-not-hold whatever else holds of it.
    #[test]
    fn convergence_table_spec_sync_6() {
        let c = closure();
        let cases: Vec<(&str, Facts, Hold)> = vec![
            ("closure before keep-at-least", Facts { before_at_least: true, ..c }, Hold::Must),
            ("closure established uncovered", Facts { covered: Some(false), ..c }, Hold::Must),
            ("closure covered between bounds", Facts { covered: Some(true), ..c }, Hold::May),
            ("closure covered before keep-at-least", Facts { covered: Some(true), before_at_least: true, ..c }, Hold::Must),
            ("parked or pages unfetched", Facts { covered: None, ..c }, Hold::May),
            ("purged while uncovered", Facts { dropped: true, covered: Some(false), ..c }, Hold::MustNot(Why::Dropped)),
            ("purged before keep-at-least", Facts { dropped: true, before_at_least: true, ..c }, Hold::MustNot(Why::Dropped)),
            ("expired", Facts { expired: true, before_at_least: true, ..c }, Hold::MustNot(Why::Expired)),
            ("outside the required set", Facts { required: false, before_at_least: true, ..c }, Hold::MustNot(Why::Outside)),
            ("strict subset projection", Facts { strict_subset: true, covered: Some(false), ..c }, Hold::MustNot(Why::StrictSubset)),
            ("duplicate with the higher blob ID", Facts { duplicate_higher: true, before_at_least: true, ..c }, Hold::MustNot(Why::Duplicate)),
            ("certificate", Facts { required: true, ..Facts::default() }, Hold::Must),
            ("sole certificate", Facts { required: true, sole_certificate: true, ..Facts::default() }, Hold::May),
            ("certificate no longer placed", Facts::default(), Hold::MustNot(Why::Outside)),
            ("expired inbox blob", Facts { required: true, expired: true, ..Facts::default() }, Hold::MustNot(Why::Expired)),
        ];
        for (name, f, want) in cases {
            assert_eq!(classify(&f), want, "{name}");
        }
    }

    // spec/sync.md §7: a body with live writes leaves a label only while another entry carries
    // them; dead content goes at once.
    #[test]
    fn carrier_rule_spec_sync_7() {
        assert!(may_delete(Why::Expired, true, false));
        assert!(may_delete(Why::Dropped, false, false));
        assert!(!may_delete(Why::Dropped, true, false));
        assert!(may_delete(Why::Dropped, true, true));
        assert!(!may_delete(Why::StrictSubset, true, false));
        assert!(may_delete(Why::Duplicate, true, true));
        assert!(!may_delete(Why::Outside, true, false));
        assert!(may_delete(Why::Outside, false, false));
    }
}
