# A covered body is not carried to a label its thing joins
> Summary: A body covered by any valid snapshot is may-hold, so when its thing joins another label no holder uploads it there, whoever's snapshot it is. `nobody` bodies and bodies before keep-at-least are must-hold and do go. If the thing then leaves its first label, hosts carry no copy of that history; holders keep theirs.
> Tags: node-sync, spec

Pinned by `deletion::second_label_gets_kept_bodies_spec_sync_6` (`author` covered by an admin's snapshot stays off the new label).

Not fixed by making a snapshot without the right count for nothing in must-hold: tried, and `net::coverer_revoked` stops converging. A right holder drops a part under its own snapshot, another writer's snapshot supersedes that one, and a holder without the right then finds the whole body must-hold, uploads it, and the right holder deletes it, over and over. The fix needs a must-hold rule that knows the body's part was rightly dropped by someone, or an upload of only the parts no right holder dropped.
