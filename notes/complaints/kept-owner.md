# kept-owner
- e054900fc (cherry-picked) did not apply cleanly onto sync-rebuild: facade.rs conflict at the end of the file (both sides appended tests); kept both.
- e054900fc's `the_driver_rotates_past_a_stale_box_below_spec_crypto_4` is a stray anchor for spec_map (cites "encrypting under: ..." which names no rule in spec/crypto.md §4).
- A TLA module's LET/`\A` scope runs to the end of an unbulleted `/\` list: `Quiet == a /\ b` followed by aligned `/\ \A n ...` lines nested every later conjunct under the first quantifier (SANY "multiply-defined symbol"). Use a bulleted list.
- Adding a second thing to NetTrust with separate Tie and Confirm actions blew U_all up past 7M states at one worker; one `Borne` action (tie and record in one write, as `record_borne` does) and the forger's own thing in its own smaller cfgs kept the module at 150 s.
- The kept^.0 type lives twice: schema/core.osis and `ct::Kept`; changing only the Rust struct makes every write of it decode to nothing (records silently empty).
