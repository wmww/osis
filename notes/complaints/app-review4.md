# app-review4
> Summary: Mishaps met reviewing app-proto's revocation, nesting, form-save and event-time commits.

- The app's two-person tests deliver plaintext commits, so whether a revoked tag still decrypts new content cannot be checked there (a reader lost the role but still read the new name). A confidentiality check needs core's sync path.
- No harness drives the app's UI (`ui::`): focus-loss saving, the async revocation runner and the retry backoff could only be reviewed by reading.
- Re-review: no test exercised `revoke`'s grant after its demotion (an await that cannot be interleaved in a test), so it shipped although it always fails; `deliver_since` (share.rs) emulates partial sync by commit ids, but steps inside one app call need hand-split emulation.
- `PAIRED= cargo test` (empty) still reads as set via `env::var(..).is_ok()`: a probe compared a case with itself.
