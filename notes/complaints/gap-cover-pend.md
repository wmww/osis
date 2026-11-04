# gap-cover-pend
`LocalPeer::packages` hands over bare headers of commits with no body left, which no label carries (spec/commits.md §5). A harness treating it as "what a node holds at its label" tests more than the spec promises: that is what this seed was. `sessions::pruned_sessions_check` still delivers them that way on purpose.
`Engine::body_not_dropped` is false for a commit not applied: a "dead, so gone" assert passes on a pending one (`waits::dead_part_with_earlier_killer`, a false premise that fed the issue). Pair it with `commit_ids().contains`.
