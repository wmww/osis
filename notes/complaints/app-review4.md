# app-review4
> Summary: Mishaps met reviewing app-proto's revocation, nesting, form-save and event-time commits.

- The app's two-person tests deliver plaintext commits, so whether a revoked tag still decrypts new content cannot be checked there (a reader lost the role but still read the new name). A confidentiality check needs core's sync path.
- No harness drives the app's UI (`ui::`): focus-loss saving, the async revocation runner and the retry backoff could only be reviewed by reading.
