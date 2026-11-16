# keel-review-sync
- origin/main's osis-sync default tests fail `destruction::a_destroyed_things_sync_id_empties_but_its_request_past_its_window_spec_sync_judgement_5` (since before 8eb31aebe); an issue named it but nothing marked it KNOWN or ignored it, so every worker's `cargo test -p osis-sync` showed a red it had to recognise.
- A bisect assumed its good end without testing it and blamed the commit right after it; check the good end first.
- D's tickets are written outside the commit that enters a thing (a later follow), so a test of them calls `write_account_ticket` itself.
