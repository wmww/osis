# A re-grant pending past a day loses its boxes to forgetting
> Summary: when a removed node drops actor A while an admin's re-grant on A is still pending (its `ts` more than `PENDING_GRANT_WAIT_MS` old, e.g. the node was offline a week), `retention::forget` shreds the pending commit's `/secrets` part on A (not a KEPT aspect). The grant then applies without its boxes: the node has the role but no secrets, stranded until a re-seal or a re-download of the grant.
> Tags: engine, sync

Severity: low (availability; recovers through the stranded heartbeat and re-seal, or the inbox copy if it is fetched again).

Where: core/engine/src/rotation/mod.rs `lost_among` (drops past the window), core/engine/src/retention/forget.rs pending loop (rewrites pending commits without the lost aspects' parts). Checked by a probe: `admins_pending_grant_keeps_lost_secrets_for_a_while` with the clock past the window leaves 0 parts on the thing in the pending store.

Unverified: whether the node re-downloads the grant's inbox blob (its blob record is forgotten with the part; the blob lives `INBOX_LIFETIME`), which would re-join the part and make this moot.

Fix direction: keep the `/secrets` part of a pending commit `rotation::authentic` by an author who may grant on the thing (boxes only, no content; costs: a never-applying admin grant leaves its sealed box held), or confirm the inbox re-download in a sim scenario.
