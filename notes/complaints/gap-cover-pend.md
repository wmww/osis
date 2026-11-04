# gap-cover-pend
`LocalPeer::packages` hands over bare headers of commits with no body left, which no label carries (spec/commits.md §5). A harness treating it as "what a node holds at its label" tests more than the spec promises: that is what this seed was. `sessions::pruned_sessions_check` still delivers them that way on purpose.
