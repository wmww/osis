# notes-rewrite
> Summary: Mishaps met rewriting the notes after the A1 switch.

- Removing a section other files cite by a bold lead ("Interim in code", "The switch") breaks citations in code comments and other notes that a remnant grep over the notes alone misses: run tools/policy.py after each section cut, before committing.
- Code still carrying the old walk's words, out of this job's scope: engine test `validity::a_stated_index_acts_no_wider_than_the_acting_check_*`, `invite` in engine flows, links, rotation and test names (`flows::invite_power_spec_perm_2`, `tests_validity::invite_grant_*`), held-model `f15_..._an_inviters_grants_...`, an `Event::DisputesUnexamined` no code emits and `osis_perm::DETECT_MAX` it cites, gone; tools/policy.py's dispute lists name gone calls (`disputes_up_to`, `evaluate_with`, `trusted_active`, `take_detected`, `Trust`, `Detected`, `DETECT_MAX`).
