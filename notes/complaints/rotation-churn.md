# rotation-churn
- `wt claim rotation-churn` failed: the branch already sat in wt10 (clean, at main); worked there.
- No switch traces `rotation_due`'s clauses or Seal's choice; `OSIS_TRACE_UPLOADS` shows uploads only, and a new `OSIS_*` name fails the testenv check, so temporary eprintlns had to hide behind it.
- Changing what a removal's `Done` holds breaks ~25 tests across engine and node that read it as one commit or step it apart from its cascade: hard to tell rule changes from test-shape changes.
- A node test's coverage (`reregistration_waits_and_sends_once_spec_sync_5`: a refusal re-sent under a new head) rested on the churn this task removed.
