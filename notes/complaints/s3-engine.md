# s3-engine complaints
> Summary: Workflow mishaps met building S3's engine vouches.

- Many engine and flows tests stamp a removal and deliver at the same millisecond (or let peers' clocks drift), so with vouches every node receiving a removed party's write "by R's `ts`" vouches for it: nine tests needed the clock moved past the removal before delivery (or vouches off where clock drift is the point). A harness default advancing the clock a tick per delivery would make "received after" the default.
- A full `cargo test -p osis-engine` run started before further edits compiled a mix of states; wip commits before each long run would have kept results attributable.
- Captured test output hides `eprintln!` probes in passing tests: `--nocapture` is needed, easy to forget when counting probe lines.
