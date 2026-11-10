# net-reconnect
> Summary: Workflow notes from shared-set step 7a (reconnect: S restore, digest, base generations).

- The hand-dialer tests (tests/it/shared.rs `resumed`) bind a real record, so any change to what a connection with a record sends first (here the Digest) breaks them all at once; the helper now agrees an empty S.
- `kind 45 is unknown` was hard-coded in proto `msg::tests::heads`: adding a kind fails a test far from the change.
- Checking a test's teeth by a temporary env toggle in the source (removed after) was quicker than `tools/bin-at` for a one-line disable.
