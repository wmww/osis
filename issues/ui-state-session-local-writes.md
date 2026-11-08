# Text sessions do not follow local writes to their path
> Summary: `edit_text` watches only remote and derived changes, so a local remove of a map entry (clearing a sent draft) is invisible to an open session: the app must close the session first, then remove, then reopen. Two sessions on one field of one node lose text the same way. A session that follows local writes (or a clear operation on the session) would remove the dance and the sharing.
> Priority: normal
> Tags: core-ask, app

Design: notes/listener-design.md (proposal): a session follows its field's value whoever writes it (compares with its last committed or merged text, so its own echoes do nothing); no option to exclude local writes from listeners, with the use cases checked; `on_remote` becomes `on_merge` (build steps 3 and 4).

Observed: two `TextSession`s on one `body.0` of one node (a thing shown twice), each typed and dropped in turn: the second commit replaced the first's text (test `two_editors_on_one_field` before kit shared a session per field). Kit now keeps one session per field and tracks what each widget shows.

Note from tess: osis should absolutely be usable as a local state system, so this is very much worth fixing. I'm not sure if having a way to exclude local changes from a listener is worthwhile or not, but worth considering the tradeoffs and possible usecases. 
