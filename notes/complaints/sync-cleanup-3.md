# sync-cleanup-3
> Summary: Complaints from a cleanup pass over core/sync/src.

- `tools/deprecated_probe.py --dead osis-sync` took about 6 minutes and locks the tree meanwhile; reading a `git archive HEAD core/sync/src` copy in scratch let reading go on during it.
- The probes found almost nothing in osis-sync (two dead `idle`s, already issues/node-idle-unexposed.md): earlier cleanups took the easy volume. What is left is trait ports (`Live`, `Links`, `NetView`) forwarding one line per method, a cost of the fake-testable design rather than of cruft.
