# full-ends
- The `--test it` filter takes several names only after `--` (`cargo test -p osis-sync --test it -- a:: b::`); two bare names fail at argument parsing.
- A listing's own refusals land before its message applies (bodies settle first), so a trigger judged at apply time fires on the very first listing; judge listing starts as the reply arrives.
- sync-rebuild 9f28aade3 (main merged in) fails three osis-sync tests on its own: destruction::{no_request_ends_a_standing_in_minting_alone, a_remint_expiring_earlier_keeps_the_lower_copy, a_remint_wider_to_purge_keeps_the_lower_copy}_spec_commits_5, panicking in the engine's index-rebuild check (engine/mod.rs:3843).
