# A kept copy of a thing read through a kept holder reads nothing
> Summary: Alice reads T0 only through T1's keyed grant on it; Bob removes her from T1 saying retain: she keeps copies of T1 and T0 (both listed kept, T0's mark on T1's copy), T1's copy reads, T0's reads no value.
> Priority: normal
> Tags: engine, retention, accounts

Ignored on it: osis-sync `holding::a_keyed_live_grant_from_a_kept_holder_keeps_a_copy_spec_permissions_3` (spec/permissions.md §3 Retain: a way alive with key access keeps). `kept_copies()` is `[T0, T1]` and `why_role` says "kept copy: yes, of T0 (a held path reads it: false); kept marks: T0 on T1"; `get` of T0's value is `None` while T1's reads. Not probed further: whether the copy of T0 lost its content when the walk stopped entering T0 (no strong reaches it once T1 is a copy; spec/sync-set.md §2 First entry) or holds it and the read refuses it.
