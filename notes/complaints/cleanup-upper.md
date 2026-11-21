# cleanup-upper complaints
> Summary: Footguns and slow spots met by the cleanup of osis-schema, -cli, -proto, -commit and -blob.

- `deprecated_probe.py --dead` on five crates took about 3 minutes and found two dead methods in all of them; reading the sources (via `git show HEAD:path` while the probe edits the tree) found the rest. The probe is worth one run per session, not per crate.
- `tools/dup_windows.py` hits in these crates were almost all test fixtures; the product-code hits were short encoder pairs not worth a helper.
- The brief named `issues/last-admin-rule-in-perm-engine.md`, which is not on main yet: the last-admin rule and the header's `adminless` flag are still in spec/permissions.md, so they were left alone.
