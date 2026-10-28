//! Transition conventions above the core (notes/versioning.md): which form to read when a new
//! form `succeeds` an old one, and which form(s) a write fills. The core never interprets these;
//! the `succeeds` links are data in the schema (fields, cases, aspects).

use osis_base::Ts;

/// Which form a read uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Form {
    New,
    Old,
}

/// Tie-break: the new form, unless the old one carries a newer timestamp (an old app wrote
/// since), then f(old). A form's timestamp is the greatest commit `ts` over its leaf registers
/// and resets; `None` when it holds nothing (a new form equal to its default). Equal: new.
pub fn pick_form(new_ts: Option<Ts>, old_ts: Option<Ts>) -> Form {
    match (new_ts, old_ts) {
        (Some(n), Some(o)) if o > n => Form::Old,
        (None, Some(_)) => Form::Old,
        _ => Form::New,
    }
}

/// How well the write conversion g (new to old) expresses a value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Conversion {
    Exact,
    Approximate,
    Impossible,
}

/// Which form(s) a write into a form with a transition fills.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteForm {
    /// g(new) into the old form only: old apps stay fully functional.
    OldOnly,
    /// The new form only (optionally resetting the old one in the same commit).
    NewOnly,
    /// The new form plus a lossy g(new) in the old one.
    NewPlusLossyOld,
}

/// Local inputs of the per-write policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolicyInput {
    /// g for this value.
    pub conversion: Conversion,
    /// The maintainer declared g's approximation acceptable.
    pub approximation_ok: bool,
    /// The group moved on: every recent writer is at or above the transition's revision, or an
    /// explicit setting says so.
    pub moved_on: bool,
}

/// The policy hook; apps may substitute their own.
pub type Policy = fn(&PolicyInput) -> WriteForm;

/// Default rule (notes/versioning.md, Which form is written).
pub fn default_policy(p: &PolicyInput) -> WriteForm {
    match (p.conversion, p.moved_on) {
        (Conversion::Impossible, _) | (_, true) => WriteForm::NewOnly,
        (Conversion::Exact, false) => WriteForm::OldOnly,
        (Conversion::Approximate, false) if p.approximation_ok => WriteForm::OldOnly,
        (Conversion::Approximate, false) => WriteForm::NewPlusLossyOld,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // spec: none (codegen convention, notes/versioning.md Transitions: tie-break by form timestamp).
    #[test]
    fn tie_break() {
        let t = |n| Ts::from_u64(n);
        assert_eq!(pick_form(t(5), t(4)), Form::New);
        assert_eq!(pick_form(t(5), t(5)), Form::New);
        assert_eq!(pick_form(t(5), t(6)), Form::Old);
        assert_eq!(pick_form(None, t(1)), Form::Old);
        assert_eq!(pick_form(t(1), None), Form::New);
        assert_eq!(pick_form(None, None), Form::New);
    }

    // spec: none (codegen convention, notes/versioning.md Which form is written).
    #[test]
    fn default_rule() {
        let p = |conversion, approximation_ok, moved_on| default_policy(&PolicyInput { conversion, approximation_ok, moved_on });
        assert_eq!(p(Conversion::Exact, false, false), WriteForm::OldOnly);
        assert_eq!(p(Conversion::Approximate, true, false), WriteForm::OldOnly);
        assert_eq!(p(Conversion::Approximate, false, false), WriteForm::NewPlusLossyOld);
        assert_eq!(p(Conversion::Impossible, true, false), WriteForm::NewOnly);
        assert_eq!(p(Conversion::Exact, false, true), WriteForm::NewOnly);
    }
}
