# A covered body is not carried to a new label or host
> Summary: A body covered by any valid snapshot is may-hold, so no holder uploads it to a label its thing joins or to a host that lost it, whoever's snapshot it is. `nobody` bodies and bodies before keep-at-least are must-hold and do go. Hosts can end with no copy of a body its setting keeps; holders keep theirs, and reads stay alike through the snapshot.
> Tags: node-sync, spec

Pinned by `deletion::second_label_gets_kept_bodies_spec_sync_6` (`author` covered by an admin's snapshot stays off the new label). Same after `wipe_host`: measured with an `author` body under an admin's snapshot, 0 copies at the host, its author still holds it. A device coming after that gets the snapshot, not the history.

Not worse than before the snapshot right: main's right holders dropped such a body outright. What is new is that the setting now reads as a promise this gap does not meet at hosts.

Not fixed by making a snapshot without the right count for nothing in must-hold: tried, and `net::coverer_revoked` stops converging. A right holder drops a part under its own snapshot, another writer's snapshot supersedes that one, and a holder without the right then finds the whole body must-hold, uploads it, and the right holder deletes it, over and over. The fix needs a must-hold rule that knows the body's part was rightly dropped by someone, or an upload of only the parts no right holder dropped.
