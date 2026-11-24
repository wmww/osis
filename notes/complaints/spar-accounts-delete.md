# spar-accounts-delete
- The brief's delete list named engine `sync/signing.rs`, but it holds `signers` and `step_needs` (what sync stamps entries with, what a step waits on): ordinary sync, not accounts. Deleting it cost a rebuild loop before the mistake showed. A delete list should be checked against each file's module doc before it is written down.
- `tools/policy.py` reports a removed test env var (`OSIS_CUSTODY_START` in core/base/testenv-known.txt) only as a free-form line, not by file:line like its other findings, so it is easy to miss in a long run.
