# A node that learns an ended actor raw reads it as a live thing
> Summary: A node granted after actor t ended learns t's record from a record blob and its frozen edges from copies, but never t's ending (no creation of t reaches it), so `Core::exists(t)` holds there: it knows t and reads t's roster, while every node that saw the ending reads t as absent (spec/commits.md §5: an ended thing reads as absent to every read). Reads of t differ by arrival.
> Priority: normal
> Tags: engine, node-sync, permissions

- Seen: in `ending::authority_through_an_ended_granted_admin_stands_spec_commits_5`, node d (granted g afterwards) has `knows(&t)` true and `roster(&t)` with t's two frozen admins; a, b, c have `knows(&t)` false and an empty roster. Writes are refused at d alike (`Core::writable` needs a held creation), so only reads differ.
- Cause: "a thing is known by its record" (so an invitee reads a group's `label.0` before its creation) cannot tell a live thing known raw from an ended one.
- Worse, read not run: a node that ended t keeping nothing, then learns t's record again from a dependent's record blob, holds no creation of t, so t is not ended there (`Core::ended` needs a held creation) and a late copy of a content part on t is judged and taken (`takes_late` takes what the ending dropped): t's content can read again at that node alone.
- Directions: (a) the label carries the ending with the history: for an expiry ending the creation commit's header with its T (every copy carries T), for a purge the request's `purge.0` part beside the value-less creation, so a late node ends t too and keeps it for the dependent; (b) a thing known by its record alone reads as existing only where something names it to read (a grant's label), never through an ended actor's history copies.
