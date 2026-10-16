# Confirm membership timeline and roster snapshot details
> Summary: The demoter-frontier timeline and some roster-snapshot details were the agent's calls; the owner may revisit their semantic consequences.
> Tags: permissions, owner-call

- Demoter-frontier rule (spec/permissions.md §5.1): membership writes seen by other admins but not by the demoter are dropped. Sync-then-revoke narrows this to writes in transit and to offline or backdated demotions. Findings: notes/permissions.md, Membership timeline.
- An un-applied epoch start leaves a compacted node with an empty roster until a fresh snapshot (spec/permissions.md §6).
- The revoker's attestation is a separate commit from the revoke.
