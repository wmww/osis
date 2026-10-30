# A server that never holds covers grows `Lane::waiting` without bound
> Summary: a delete of an absorbed entry waits per server until a cover is held there, kept until restart. A hostile server that takes plain uploads but refuses covers with a code other than 12, or deletes them, makes the waiting set grow with every own commit absorbed. `eph_flush` walks the whole set at every step, so step cost grows over time. Low.
> Tags: security, node, ephemeral

Mechanism: `eph_forget` → `eph_delete_after` (core/node/src/sync/ephemeral.rs:407) puts the delete in `waiting` keyed by (label, blob, server) until `eph_covers_held_at` holds. A cover refused with code 1 or 4 only gets a diagnostic (`eph_status`, :867). It is never retried on that connection, and the server never marks it present. A pushed deletion of the cover (`eph_deleted`, :1074) also clears it. `waiting` is not cleared when the connection is lost (`eph_lost`), and every step's `eph_flush` (:370) runs `eph_covers` and `eph_covers_held_at` for each item. Continuous typing or cursor work adds about one absorbed commit per round trip, which is tens of thousands an hour.

The same code-4 path also hits an honest server whose delete rate is used up (the replacements count against it, core/server/src/store.rs:1360): that cover never lands there until the next cover or a reconnect.

Fix direction: bound `waiting` per server, for example by dropping the oldest items, since the server keeps the entry only until its own cap or the author's next cover. Retry a cover refused with code 4 at the periodic pass, as code 12 is. Index `waiting` by the cover it waits for, so `eph_flush` touches only the items whose cover just became held.
