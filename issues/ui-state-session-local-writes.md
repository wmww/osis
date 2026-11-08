# Text sessions do not follow local writes to their path
> Summary: `edit_text` watches only remote and derived changes, so a local remove of a map entry (clearing a sent draft) is invisible to an open session: the app must close the session first, then remove, then reopen. Two sessions on one field of one node lose text the same way. A session that follows local writes (or a clear operation on the session) would remove the dance and the sharing.
> Priority: low
> Tags: core-ask, app

Observed: two `TextSession`s on one `body.0` of one node (a thing shown twice), each typed and dropped in turn: the second commit replaced the first's text (test `two_editors_on_one_field` before kit shared a session per field). Kit now keeps one session per field and tracks what each widget shows.
