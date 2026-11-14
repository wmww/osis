# A receiving node checks each commit's signature about five times
> Summary: Counted in the node sync tests (notes/sync-test-harness.md, measured costs): each commit's signature is verified about 5 times per receiving node (13.6 checks per write with two receivers), at about 0.43 M instructions per verify. Structural waste in ingest: a commit's signature should be checked once per node, its result memoized with the commit.
> Priority: normal
> Tags: engine, performance

Find every verify call reached from ingest, judgement and re-judgement for one commit (count with a counter in a debug test, at n and 10n commits) and make the verified state part of the commit's memoized record (Tess: structural efficiency, one memoization system, no ad-hoc caches). A re-check that guards against a different input (e.g. a changed key set) must say so; if none does, the checks collapse to one.
