# Notes disagree on whether a creating commit can expire
> Summary: notes/api.md (Writes, a thing's record) and notes/whole-commits.md (Expiry per commit) say `created.0` never expires, so expiring content takes two commits; notes/expiry-creation-design.md says a disappearing message is one commit, `Write::expires` lists no creation among what cannot expire, and node tests speak of "the creation's expiry".
> Priority: low
> Tags: notes

Check the engine (`Write::expires`, `apply` of an expiring commit carrying `created.0`) and rewrite whichever notes are wrong; the app's `create` then expiring-write pattern (osis `api::a_reaction_outlives_a_disappearing_message_spec_crdt_4_7`) may then simplify.
