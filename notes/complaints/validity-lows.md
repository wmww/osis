# validity-lows
> Summary: footguns met on the validity-lows branch.

- Delivering packages in a chosen order: `LocalPeer::packages(i)` includes everything peer i received, so a "deliver X first" test must filter those out too (got `Duplicate` and a vacuous order).
- Constructing hostile imports needs a creator without rights: `move_thing` refuses even under `skip_writer_rules` when the node cannot create under the owner; grant then revoke instead.
