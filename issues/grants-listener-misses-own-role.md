# A grants listener misses this node's own role change through another thing
> Summary: `grants(thing)` shows a roster only to a reader of the thing (`ReadOnly::shows_roster`), but its listener (`Filter::Grants`) wakes only on that thing's roster events, so a node gaining or losing read on the thing through another thing's edge keeps the last answer until the thing's roster next changes.
> Priority: low
> Tags: osis, api

`holders` listens on every roster change (`Watch::Roles`); `grants` could too, at O(grants listeners) per role change, or listen on this node's role on the thing as `role_on` does.
