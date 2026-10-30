# `inside_member_revokes` takes `via[1]` as the leaver
> Summary: certs `inside_member_revokes` uses a departure's `via[1]` as the actor that left; for departures nested two or more levels deep that is a current member, not the departed one, so it likely finds no write or the wrong one. Pre-existing; spec/permissions.md §4 is ambiguous on which write is meant — make the spec precise, then fix and test with a 3-level nesting.
> Tags: security, keys, permissions
