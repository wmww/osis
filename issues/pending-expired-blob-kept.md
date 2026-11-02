# A part pending past its expiry leaves the pending copy but not the node
> Summary: `retention::pending_expiry` strips a part past T from the stored pending copy, but node-sync keeps the entry's blob and key (`state.blobs`) until the commit applies and the drop reaches `forget_dropped`. A commit that never applies keeps them for good; spec/commits.md §5 says the part goes from the node at T.
> Tags: security, node-sync, retention

Seen with a real node: `parts_relay::redelivery_leaves_a_part_past_its_expiry_spec_commits_5`, `engine.has_blob` true past T, false once the record came. Nothing reads the bytes (`Engine::settled_slots` keeps `redeliver` off them), so this is erasure at rest, not a wrong read.

`forget_dropped` asks `Meta.dropped`, and an unapplied commit has no meta. A fix needs it to read the pending copy's header for a commit not applied, and the blob's other parts must not go with it while a junk copy holds their slots: a blob with parts of two expiries is the case to test.
