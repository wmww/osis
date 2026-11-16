# keel-app-refgraph
> Summary: Mishaps while bringing kit, app and chat onto the reference graph.

- `git checkout <file>` to undo one probe line reverted every edit in that file; redo cost a few minutes. Undo a probe by editing it back.
- No public way to reach the account root: the app could not make home under it until `Osis::account_root` existed (added here).
- `BacklinkQuery` has no aspect filter, so "which tags hold t" (`held_by`, backlinks in `holds.0`) wakes on any reference to t changing, such as a window opening another thing; kit's `view_costs` rows test sets the window home first to keep its "unrelated write runs nothing" strict.
