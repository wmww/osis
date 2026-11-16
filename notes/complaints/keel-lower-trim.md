# keel-lower-trim
- The `#[deprecated]` probe has no tool: I wrote a marker script and an aggregator by hand (skip `#[cfg(test)] mod`, match the warning's last path segment). A `tools/deprecated_probe.py <crate dirs>` would save each cleanup that work.
- policy.py red on main: checking "no new violations" needs main's output beside the branch's; I ran it in a throwaway `git worktree` of origin/main. A `--baseline <ref>` mode would avoid the extra checkout.
- dead_pub_allow "deferred: unused since the sync rebuild" entries kept a test-only fake transport mode (`run_on_tokio`, LAN loss, dial give-up) alive with nothing to use it; deferrals need an owner or a deletion date-free rule (delete unless a test uses it by the next cleanup).
