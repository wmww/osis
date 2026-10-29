# No way to list the groups a thing is a subgroup of
> Summary: `groups_of(t)` follows membership, not `/group.subgroups` edges, so finding a tag's parent tags or removing a deleted tag's subgroup edges means scanning every group. A deleted tag left in a subgroup list comes back as an empty unnamed thing.
> Tags: core-ask, api

Repro: app/src/data.rs `tags_of` (scans all tags for a tag) and `delete` (scans every shown group for subgroup edges to remove).
Ask: `subgroup_parents(t)` (or an index of subgroup edges), and/or `delete` of a group removing the edges pointing at it where the deleter may write them.
