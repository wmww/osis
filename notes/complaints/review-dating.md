# review-dating
> Summary: slow spots met reviewing and gating dating-redesign.

- `tools/mutate.py` over `-p osis-engine` runs both engine binaries whole per mutant (about 4 minutes each on a quiet box): seven engine mutants are most of a review's wall time. A filter narrows it but then a "none" row is no longer "no test catches it".
- Two rollback mutants (`Core::rollback_to` clearing `index_settled`, cutting `died`) read as uncaught but are equivalent: `end_settle` clears both on every path before a failed transaction rolls back. Check that before writing a test for a "none" row.
