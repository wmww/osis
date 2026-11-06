# write-ready
- The "stuck" direct redeem was a 60 s `peer_retry_ms` redial against the tests' 30 s guard: a probe that kept waiting past the guard showed it in one run. Worth trying first when a wait "never" finishes under load.
- The reexamine debug assertion names only commit and actor; a temporary dump of the wait (reason, openers, records), the actor's record chain and before/after epochs found the cause in one run. Worth keeping such a dump behind the assertion.
- I ran `cargo build -p osis` once (not a listed form); `cargo test -p osis --test it --no-run` is the one to use.
- Reviewer: the branch's fast sharer redial applied to every followed link forever (the follow stays after redemption), not only while redeeming; a "since when does this apply" question is worth asking of any pace change keyed on persisted state.
