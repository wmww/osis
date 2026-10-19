//! Sequences (spec/crdt.md §5.7, §6): differential join/read against models/crdt, linearization.

use crate::tests_join::lockstep;
use crdt_model::r#gen::kitchen_sink;
use crdt_model::ops::Ty;
use proptest::prelude::*;

fn inner() -> Ty {
    Ty::Struct([(1, Ty::Register), (2, Ty::Set(Box::new(Ty::Register)))].into_iter().collect())
}

proptest! {
    /// §5.7, §6: text join and read equal the model's under random delivery and duplication.
    #[test]
    fn text_join_matches_model_spec_5_7(seed in any::<u64>()) {
        lockstep(seed, &[Ty::Text], 3, 8);
    }

    /// §5.7: list join (element resets, nested fragments) equals the model's.
    #[test]
    fn list_join_matches_model_spec_5_7(seed in any::<u64>()) {
        lockstep(seed, &[Ty::List(Box::new(inner()))], 3, 6);
    }

    /// §5.7 nested in every other encoding.
    #[test]
    fn kitchen_sink_matches_model_spec_5_7(seed in any::<u64>()) {
        lockstep(seed, &[kitchen_sink()], 3, 5);
    }

    /// §7: register and text at one position (embedded characters, Derived anchors).
    #[test]
    fn text_slots_match_model_spec_7(seed in any::<u64>()) {
        lockstep(seed, &[Ty::Register, Ty::Text, Ty::List(Box::new(Ty::Register))], 3, 6);
    }
}
