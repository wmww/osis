# net-deposits
- Reverting a debug edit with `git checkout -- <file>` also threw away two uncommitted fixes in the same file; commit (wip) before any probe edit you mean to revert by checkout.
- `peers_review::complete_pass_counts_peers_spec_permissions_3` asserts a complete pass with no clock advance; it depends on which node delivers a role change first, so a delivery that newly lands (a removal notice) shifts it past the next host pass. Hard to read from the failure: took a role-commit trace per node to see why.
- Review: the complete-pass failure needed per-node probes of `role_change` and `passes` (no accessor shows which source a complete pass waits on); `tools/bin-at --patch` with the probe diff gave the old order side by side in one build.
