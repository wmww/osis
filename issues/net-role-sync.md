# Role and sync paired
> Summary: Decided (Tess), strong form: a commit that gives a thing role secrets of its own also makes its one sync ID, so every holder of a role can sync it. Routes, `NotCarried`, first-label delivery and the inbox fallback go; an actor's sync ID is its home and its inbox. Proposed: replacement (index > 0) goes, `unsync` goes. Open: per-sync-ID cost. Part of issues/net-rework.md.
> Priority: normal
> Tags: sync, spec, api, engine, tess-call

## Today
- A grant records the permission only (spec/sync.md §2 "a grant makes none"; notes/api.md `grant`). A holder with no live label carrying the thing reads nothing: `SyncState::NotCarried` (`Engine::unrouted`), `wait_synced` waiting while `route_arriving` (share.rs), and a thing's first `label.0` sent by inbox to its roster (spec/sync.md §3, inbox blob case 5). A holder reading only through a group loses it when the membership goes.
- `sync` gives the group secrets of its own, then a label: two commits (share.rs `make_label`: `give_own_secrets`, `create_label`). `make_link` syncs its target when it has none. Other labels are infrastructure: an account's home, a contact profile, K's, a replacement.
- An actor's inbox is the label its `keys.0` names: its home label, else its first admin's up the record chain (spec/sync.md §2 Inbox). Grant copies go only when the inbox is the home label (notes/inbox.md).
- `unsync(group)` marks every live label replaced: the group stops syncing for all its holders.

## Decided (Tess)
- **The rule**: a commit that gives a thing role secrets of its own makes its sync ID in that commit (one rule in `give_own_secrets`, not a list of callers). Today's callers: a grant to a plain thing's first holder besides its first admin, `sync`, `make_link` (K, and the target when plain), account creation, the contact profile.
- Weak form rejected (a sync ID only when a holder has no other route): the other route goes when a membership does, stranding the holder again.
- Every holder of a role on a thing can sync it. Membership and rights stay independent both ways.
- An actor's sync ID is its home and its inbox. `keys.0` names it with the deposit seed; the first-admin fallback goes.
- What travels under a sync ID is unchanged: the closure by membership and entitlement (spec/sync.md §3). Plain things in a shared group get none. A thing shared directly and in a group syncs under both, one blob per commit.
- A sync ID stays for the thing's life.
- Sharing a local-only thing syncs it among the sharer's own nodes too. Granting is an explicit act, so things still never sync just by being created under an actor (spec/requirements.md: "add to synced groups" becomes "add to synced groups or share them", approved by Tess; changed when this job lands).

## Goes
`NotCarried`, `not_carried_to`, `Engine::unrouted`, `route_arriving` and `wait_synced`'s "route may still arrive"; spec/sync.md §2 Route and "a grant makes none"; inbox blob case 5 and its copy rule (first `label.0` to the roster); the inbox fallback and grant copies' "only when the inbox is home" test; `make_link`'s special case; `make_label`'s two commits.

## Spec and API to change
spec/sync.md §2 (Labels, Route, Home label, Inbox, Replacement), §3 (inbox blob cases, grant copy); spec/crypto.md §3 (`keys.0` inbox); spec/data-model.md (`inbox`, `label` types); spec/requirements.md (above); notes/api.md `grant`, `make_link`, `sync`, `unsync`, `wait_synced`, `NotCarried`; notes/inbox.md, notes/label-access.md.

## Unsure
- **`unsync` goes** (Tess). Stopping a share is removing its holders; a node that does not want a group's content uses `set_sync_options` (`LogOnly`, or a new mode holding nothing). `sync(group)` stays as "give it its own sync ID with no new holder" (to sync it among own nodes alone).
- **Replacement (index > 0) goes** (Tess: fine). Its one cause: a removed admin still holding the delete key registers a child with keys only it knows at a server before the honest step gets there, locking holders out there (notes/label-access.md, Replacement labels). After issues/net-one-peer.md:
  - A serving node that reads the group needs no first-come registration: its path is the steps recorded in `label.0` writes it holds valid, so a removed admin's step never counts there.
  - Only a peer that cannot read is exposed, and by default those are the user's own nodes (decided). There the remedy is local: the honest own nodes, admins of that peer's node thing, have it drop the sync ID's registration and register the recorded path again; or the group's readers drop that peer from the group's peer list.
  - Then going: the index in key derivation, `replaced`, `replace_label`, retiring, `register_path` for replaced labels, index in hints and payloads, "one live" in place of "one", issues/replaced-inbox-resend.md. Stays: re-registering a recorded path at a peer that lost its data.
  - Check first that no other cause of a lost sync ID exists.
- (design) **Cost.** More sync IDs: one per directly shared thing and per link (K, plus a plain target). Each costs a registration path (claim set padded to a power of two, entry boxes), node cards and heartbeats, an inbox budget at each server, a pass (issues/idle-pass-per-label.md: 3.5 µs per sync ID and node a minute idle, 0.4 ms a pass at 1000), shared-set beacons each connection (issues/net-shared-set.md) and reconnect work (issues/net-reconnect.md). Measure first; sharing sets through one actor (notes/permissions.md Patterns) keeps counts low.
- (design) **Key actors** (nodes, link keys, recovery keys) have no role secrets of their own, so no sync ID: they hold roles and sync others' sync IDs. A link key starts from its link text, a recovery key from its card (both by static entry, spec/sync.md §5 Claim), a node through its account's secrets or by pairing. The open part is how shared-set matches the first two (by static entry: issues/net-first-contact.md).
- (design) Land before issues/net-one-peer.md (recommended: it is engine and spec work, and one-peer's admission and replacement answer build on it) or inside it.
