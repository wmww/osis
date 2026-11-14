# one-parking
> Summary: workflow notes from moving sync's waits onto one parking rule.

- I copied a file to the scratchpad root by mistake (`follow.rs` there); the brief forbids `rm` in the scratchpad, so the reviewer removed it. A `scratch` helper that makes the task dir would avoid the slip.
- `tools/dead_pub_allow.txt` fails policy as soon as a test first uses an allowed hook (`rotate_boxing_only`); the message says what to do, but it is easy to miss under clippy output.
- A settle helper with "keep the key due on failure" had been copied into five modules plus inline in two more; `Effects::try_settle` replaces them.
- (review) No test fails when the store's start pass (parking S's entries when S becomes read) is removed: in every two-node flow tried, a peer sending the entry again or a flag change re-feeds it after a restart, so the feed parks it anyway. A restart test needs a node holding an entry no peer will send again.
