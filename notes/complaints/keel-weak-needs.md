# keel-weak-needs
> Summary: Mishaps met while making weaks need nothing.

- `cargo test ... 2>&1 > log` (wrong redirect order) sent the test output to the task file, not the log; write `> log 2>&1`.
- The task wants the contact as a strong to the profile, but test harnesses call `know` before the other account's chain arrives, so the profile tid is unknown then; a strong to the account itself is the minimal holding there.
- main (4e970ecfb, write only what you hold) left osis-chat `chat::since_goes_by_arrival` failing: bob posted to a chat he never held. Fixed here by holding it first; that commit's worker had not run `-p osis-chat`.
