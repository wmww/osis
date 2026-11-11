# A writer's delete keys arriving is no purge-on-replace trigger
> Summary: `retention::settle_none` covers a replaced purge-on-replace body only at a node that may write (role and the delete keys a write lists, spec/crypto.md §7), judged when the body, its replacement, a validity flip or a role change arrives. A node whose role was here first and whose delete keys of the thing come later (a first-holder grant's `keys.0` commit after its edge) becomes a writer without any trigger, so it keeps the body until another writer's cover or the next trigger on the aspect. The replacer always covers (it could write, so it held the keys), so the body goes once that cover arrives; only a replacer whose cover never syncs leaves it held where a just-ready writer could have covered it.
> Priority: low
> Tags: retention, engine

## Direction
Mark `none_due` for the held purge-on-replace aspects whose delete base gained keys (held epochs of a level, its `keys.0`, a promoted hint), the way `timelines_changed` marks those under a moved role; without scanning every `none_held` entry per rotation (index by delete base, or state why the scan is bounded). Or state in spec/commits.md §5 that keys arriving is not a trigger, if the replacer's cover is judged enough.
