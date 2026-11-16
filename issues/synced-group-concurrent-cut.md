# Two concurrent writes can cut a synced group from home
> Summary: each node refuses a local write cutting a node's synced group G from D (spec/sync-set.md §1 Home stays under it), but two concurrent writes each cutting one of two paths merge into a cut; that node then follows no change of G until it is paired again.
> Priority: low
> Tags: facade

Accepted for now. Possible fix: any own node seeing a node's G not under home after a merge adds D back to G's subgroups (an add-wins set: concurrent repairs converge); no designated node.
