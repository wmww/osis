# Purging a keep-forever write should leave a lasting tombstone
> Summary: Owner: if an aspect preserves history forever but allows purge, a purge should maybe leave a tombstone visible forever. Today a purged delta's header-only blob is may-hold, so new devices never see it, and header forgetting (issues/session-sources.md) removes it from old devices.
> Tags: spec, sync, engine, node-sync

Candidate rule with no new field: a purged delta whose retention has keep at least forever stays must-hold as its header-only blob, and its header is never forgotten. It keeps author, time and aspect, about 300 B each; whether to show it is the app's choice. Other retention gives no lasting tombstone. Check: must-hold and `covered` for a header-only blob, session-sources step for forgetting, purge of a commit with other live parts, an expired write (no rule change?), what a host learns. Used by notes/chat-designs/e.md.
