# keel-refgraph-spec
- Rebasing the 19-commit branch conflicted at its first commit and would have conflicted again per commit on the same spec lines; a squash (`git diff base branch | git apply -3`) gave 7 conflicted files once. Spec branches that sit long behind main are cheaper squashed.
- Landing a spec ahead of its code leaves policy.py and spec_map.py red (about 170 code and note anchors to removed spec text) until the demolition lands; nothing marks that as expected.
