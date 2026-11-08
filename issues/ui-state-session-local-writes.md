# Text sessions do not follow local writes to their path
> Summary: `edit_text` watches only remote and derived changes, so a local remove of a map entry (clearing a sent draft) is invisible to an open session: the app must close the session first, then remove, then reopen. A session that follows local writes (or a clear operation on the session) would remove the dance.
> Priority: low
> Tags: core-ask, app
