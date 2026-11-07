# Spec contradictions left from the carve-out audit
> Summary: The audit's three areas are decided and owned elsewhere (retention: issues/retention-modes.md; keys: notes/crypto.md, rotating needs only the right to rotate; ephemeral: notes/ephemeral.md). This lists the spec contradictions it found that are not yet fixed on main, each with its owner; delete each line as its fix lands.
> Priority: normal
> Tags: spec

1. commits §5 keeps waiting parts' bodies and purged values "for good" vs requirements "purge is prompt", "peer input never causes unbounded storage": issues/pending-unbounded.md and issues/retention-modes.md.
2. commits §5 death dates depend on arrival order vs requirements Deterministic: goes with death dating (issues/retention-modes.md step 3).
3. sync §5 a co-reader serving a hostless label drops a body with live writes without a carrier vs "live state is never lost": goes with keep-bound drops (issues/retention-modes.md step 2).
4. permissions §5.1 cuts purge requests from an oversized frontier vs requirements Cost "such a removal fails": issues/unbounded-frontier.md (on hold for Tess's revocation text, issues/revocation-without-arbiter.md).
