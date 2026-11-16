# keel-needed-stopgap
> Summary: Mishaps while trying to remove the needed-rule interim roots.

- The brief counted only engine lib tests (~60); `cargo test -p osis-engine --test it` adds 73 more failures without the root, most from a harness that writes bare edges on plain things under the maker's account root (no receiver can ever open them). Count both binaries before scoping a harness job.
- A strong from the receiver holds nothing unless it can open the thing: raw `roles.0` writes give no boxes, so the hold helper only works with flow grants.
- `cargo test -p X --lib a b` takes only one filter; use `-- a b`.
