# rotation-churn
- `wt claim rotation-churn` failed: the branch already sat in wt10 (clean, at main); worked there.
- No switch traces `rotation_due`'s clauses or Seal's choice; `OSIS_TRACE_UPLOADS` shows uploads only, and a new `OSIS_*` name fails the testenv check, so temporary eprintlns had to hide behind it.
- Changing what a removal's `Done` holds breaks ~25 tests across engine and node that read it as one commit or step it apart from its cascade: hard to tell rule changes from test-shape changes.
- A node test's coverage (`reregistration_waits_and_sends_once_spec_sync_5`: a refusal re-sent under a new head) rested on the churn this task removed.
- Review: LocalPeer syncs every commit to every peer, so engine tests cannot show a label-placement cut-off (a sealer that never learns a holder's next keyset); it took an osis World test to see the Seal skip cut a team off.
- Gate: Seal's stale check decoded a new holder account's `secrets.0` per grant (sim `scale::add_judges_nothing_per_message`); engine tests count no decodes, only the sim scale test did.
- Stacking on stranded-keys: a test both branches changed (`inside_member_departure_leaves_holder_out`) merged with no textual conflict but with rotation-churn's expectation, which the order rule had already made wrong; each branch's gate passed alone. A stack of two rule branches needs its node tests run before the second reviewer signs off.
