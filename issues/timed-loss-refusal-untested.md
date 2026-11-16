# No test needs a refusal to end a timed loss's wait
> Summary: with refusals ignored entirely in `Opens::waited_unrefused`, or walk stops left out of `Opens::refusers`, every sync test passes: the refusal exit of a loss by an `until` alone (spec/permissions.md §2) is untested end to end.
> Priority: normal
> Tags: sync, tests

Tried (`life::`, `opens::`, `leave::`, `stranded::`): an owner finalizing with its clock ahead does not end node 1's wait by refusing; node 1 drops through the sourced branch (the owner keeps S open, takes the write), with or without a partition first. A test needs a node with no source left whose every waited peer (one whose kept record holds S) refuses: a ByRole refused, and separately a walk stopped there (a store keeping S under a later step). `opens::a_byrole_refused_by_a_reader_is_a_refusal_spec_permissions_2` covers only the index.
