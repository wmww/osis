# Rename: host, label, placed
> Summary: After the concepts are unified (issues/net-one-peer.md, issues/net-role-sync.md), rewrite the spec in the new words, then rename code a crate at a time: about 5,000 uses each of host and label. Words: issues/net-rework.md; registry: issues/deprecated-terms.md. Part of issues/net-rework.md.
> Priority: low
> Tags: naming, spec

- Spec first, in the new words, where the concept changes land: spec/overview.md Conventions; spec/sync.md §2, §4-§6, §10; spec/wire.md §10; spec/permissions.md §3, §7; spec/data-model.md §9 `host.0^`; requirements' "a hiding host", "a host's word", an inbox's budget "at a host".
- Then code, mechanically: host and label across core, cli, app, libs; placed (`Placed`, `place`, `placed_with`, `untie_unplaced`, test names); the harness (`World::add_host`, `NetHost`, `Opening.hosts`); osis-proto session names (issues/net-one-peer.md).
- Each row of issues/deprecated-terms.md this covers goes when its last use does.

Unsure (implementor): one branch per crate to keep merges small, or one sweep while nothing else is in flight.
