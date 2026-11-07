# Role and sync paired
> Summary: Decided (Tess), strong form: every thing with role secrets of its own has exactly one live sync ID, given in the same commit as the secrets, so every holder of a role can sync it. `NoRoute` goes; a group's sync ID, an actor's home and its inbox are one thing. Open: per-sync-ID cost, key actors, replacement. Part of issues/net-rework.md.
> Priority: normal
> Tags: sync, spec, api, engine

## Today
A group syncs under a label (sync ID), whose keys derive from the group's own secrets; syncing a group first gives it secrets of its own, which makes it an actor. The first holder of a plain thing besides its first admin also gives it secrets of its own. An actor's home label is the actor synced as a group of itself; its inbox is one of its labels. A grant records the permission and nothing else (spec/sync.md §2 "a grant makes none"; notes/api.md `grant`), so a holder can have a role and nothing to sync it through (`SyncState::NoRoute`), and loses its only route when a group membership goes.

## Decided
- Every thing with role secrets of its own has exactly one live sync ID, given in the commit that gives it the secrets: a grant to a plain thing, `sync`, `make_link`.
- Weak form rejected (a sync ID only when a holder has no other route): the other route goes when a membership does, which strands the holder again.
- Every holder of a role on a thing can sync it. Membership and rights are independent both ways. `NoRoute` goes.
- A group's sync ID, an actor's home and its inbox are one thing: the actor's sync ID. Inbox naming and the sender's record-chain fallback go. `make_link`'s special case becomes the rule.
- What travels under a sync ID is as today: the closure by membership and entitlement (spec/sync.md §3). Plain things in a shared group get no sync ID of their own. A thing shared directly and in a shared group syncs under both, one blob per commit.
- Sharing a local-only thing also syncs it among the sharer's own nodes; granting is an explicit act, so "nothing syncs by being created under an actor" holds.
- A sync ID stays once made. `unsync` becomes a node's local choice to stop syncing it; `sync(group)` gives it secrets and a sync ID with no new holder.

## Spec and API to change
spec/sync.md §2 ("a grant makes none", Route, Home label, Inbox), §3 (inbox placement), notes/api.md `grant`, `make_link`, `sync`, `unsync`, `SyncState::NoRoute`.

## Unsure
- (design) Cost: a sync ID per directly shared thing means registration steps, node cards, heartbeats and a pass per sync ID (issues/idle-pass-per-label.md). Needs per-sync-ID cost flat and small; measure first. Sharing sets through one actor (notes/permissions.md Patterns) keeps counts low.
- (design) Key actors (nodes, link keys, recovery keys) have no role secrets and so no sync ID; today they reach labels by cards, links and static entries. Check that this still covers them.
- (design) **Replacement (index > 0).** Its reason is a removed admin registering a label first at a host with keys only it knows (notes/label-access.md, Replacement labels). Any peer that cannot read keeps registration state, so the race exists without hosts too. Unclear whether it is worth its cost (an index, retiring, `register_path`, hints naming an index). Decide with issues/net-one-peer.md.
- (design) Whether to land before or inside issues/net-one-peer.md.
