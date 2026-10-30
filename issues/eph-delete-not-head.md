# An ephemeral delete refused 9 is never sent again
> Summary: `eph_delete_status` drops every status of a lane delete, so a plain delete of an absorbed or expired own entry sent under head keys the server rotated past (the node had not read the rotation yet) is refused 9 and never retried: the entry stays at that server, charged to its ephemeral cap, until it expires or the server restarts.
> Tags: sync, ephemeral

Where: core/node/src/sync/ephemeral.rs `eph_delete_status` (codes ignored), `eph_delete_now` (signs under the connection's keys at send, `eph_resign`). Carried deletes (replacements of a cover) are fine: a refused cover puts them back in `waiting` and its re-upload under the next key signs them again.

Fix direction: keep the item (and the covers it waited on) per in-flight delete; on 9 put it back in `waiting` (or a per-connection restamp set like `Lane::restamp`) and send it again once the connection's keys change. Repro idea: `ephemeral::cover_across_unread_rotation_lands_spec_sync_9` with the cover reaching the server first through another path, or an expired entry deleted while `held_to` holds the rotation from the node.
