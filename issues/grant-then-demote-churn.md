# Re-registration re-uploads role commits on every pass while its step waits to settle
> Summary: `SyncEngine::reregister` (core/node/src/sync/pass/register.rs) uploads the keys actor's role commits the host lacks before it checks `step_settled`, and with no in-flight check, so while another admin's rotation is under `SETTLE_MS` every pass sends the same role commits again; two admins of one group ping-pong passes and uploads until it settles.
> Priority: low
> Tags: node, sync

Seen in osis-node `ending::a_grant_holder_ends_and_a_stale_copy_ends_again_spec_permissions_6`: `Net::grant(a, t, c, Admin)` followed before any pass by a hand-built demotion of c on g (no rotation, so g's rotation stays due), then `net.run()`. a and c (c still an admin until it takes the demotion) both hold an epoch of g newer than the label head, so `step_due` holds at both. Totals over the whole test: 68 Upload messages, 17 deletes, 45-65 passes per node; with a `net.run()` between grant and demotion, 15 uploads, no deletes, 18-24 passes.

Traced with probes on each upload site: the re-registration upload (register.rs, before `Command::Upload`) runs 44 times against 2, almost every time followed by `step_settled` returning false; the uploaded blob IDs repeat (the same entries several times in one step, before the host's reply marks them present). Unlike `Pass::send`, `reregister` skips neither blobs in flight (`super::in_flight` on `req.sent`) nor the whole upload while the step cannot go out. Each upload's Added push wakes the other admin's pass, which does the same. c's uploads under the stale head also come back `NOT_HEAD` (code 9) and are sent again. Deletes rise too (delete.rs Delete: 25 against 8), not traced.

Fix direction: decide `step_settled` (and the back-off) before uploading, and skip entries already in flight, as `send` does. A test: the counts above stay near the with-a-pass case.

Repro: in that test print `net.sent_kinds` (10 = upload, 14 = delete) and `pass_stats().passes` per node after the `net.run()` that follows `demote(...)`.
