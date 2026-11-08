# A delete leaving a thing in an unwritable group may loop at hosts
> Summary: Unconfirmed. When a delete leaves the thing in a group the deleter cannot write, the deleter treats the thing's dropped `+` entries as `MemoryDrop::Gone` and may delete them at hosts while other holders upload them again. Whether it loops depends on the deleter holding that label's delete keys. Test it once drop-drafts is on main.
> Priority: normal
> Tags: node, ephemeral
