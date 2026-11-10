# rotation-seed
- The issue named "on main" was only on origin/main: the local main checkout was behind, so the issue file looked missing until a fetch.
- The rotation property's failure log records `made` epochs only for actors without holder actors, so a cycle seed's history shows no rotations; finding the mechanism took a temporary per-epoch dump (established, supersedes, keyset lists) at the failing assertion. Worth a standing dump on that assertion.
