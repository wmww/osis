# Honest status and waits
> Summary: Status, `wait_synced`, `set_role`'s catching up and history `complete` judge passes at saved peers only, so with peers only they report wrong things (audit rows 13, 15-18). Judge every sync ID over one set, the nodes connected now with it open whoever dialed, and let the served side judge too (a pass of its own over the same connection). Synced needs at least one such node. Two steps: the API and the one set first; the served side's own judgment with issues/net-reconnect.md's pull. Part of issues/net-rework.md.
> Priority: normal
> Tags: api, node, sync

## Today
- `label_state` (core/osis/src/share.rs): a label with no hosts (`LabelStatus::hosts == 0`) is `Connected` or `NoPeers`, whatever its passes; with hosts it judges host connections only (`open`, `idle`). core/node/src/sync/status.rs `label_status` counts dialed co-readers in `peers_open`/`peers_idle` and served sessions only in `peers_connected`.
- `synced` (`wait_synced`): `Thing` fails `Unsynced` at once on `NoPeers`/`Connected` (row 16); `AllWithSavedPeers` leaves those groups out (row 15).
- `caught_up` (`set_role`, `revoke_link`): hosts until `Synced`, dialed co-readers as connected at each look, served sessions not judged, nobody reachable: done at once (row 13; notes/api.md Demotion and catching up).
- `fetched` (history `complete`): `NoPeers` and `Connected` count as complete (row 18).
- No wait has a deadline: the caller's timeout drops the future (crate docs, Sharing). `Unsynced` comes only from a check sure never to finish (stranded, nothing holding the thing).
- Two nodes that know each other usually both dial, and each judges its own dialed connection. A connection only one side dialed (one side behind NAT, a link redeemer the sharer does not know) is judged by nobody on the served side: that side runs no pass and cannot tell when the dialer's ended.

## Design
- **Sources** of a sync ID: nodes with a connection to this one up now on which it is open, whoever dialed, readers or not. Nodes known but not connected (group data, hints, `label.0`, LAN) are not sources: they decide whom to dial, not what is true now. The same set issues/net-shared-set.md produces, so this holds whichever way nodes are found.
- A source is **caught up** when this node's own pass with it ended with nothing outstanding and nothing changed on either side since (today's `idle`). At a peer that cannot read, this node's pass is the judge, as at a hub today.
- **Both sides judge**: with issues/net-reconnect.md each side of a connection pulls from the other's node log, whoever dialed, so every source is judged by this node's own pull and a pair needs one connection, not two.
- **States** per sync ID, a group the worst of its own (as today):
  - `Synced`: at least one source, each caught up.
  - `Syncing`: at least one source, some not caught up.
  - `NotConnected`: no source. Replaces `NoPeers`, `Connected` and `Unreachable`: one state, whether or not a node is known for it (Tess).
  - `Refused`: no source, and a connected node this node judged a holder of it (issues/net-shared-set.md: an Offer this node sent by its own J, or a Hit on a credential it holds) answered 14, `refused_by` naming them. Code 14 is one code for "departed in my view" and "I do not hold it", so the state means: a node I believe holds this will not serve it to me; my view and its differ. A 14 from a node this node did not judge a holder is no refusal.
  - `Stranded`, `LogOnly` as today. `NotCarried` goes with `NoRoute` (issues/net-role-sync.md).
  - `last_sync`: when it was last `Synced`. `leaving`: until a source has the removal.
- **`wait_synced`** resolves once every sync ID in scope is `Synced` and the deliveries in scope were taken; otherwise it waits, nobody connected included (Tess). It fails only on a known-never (`Stranded`). Scopes: `All` (every synced group, every delivery; replaces `AllWithSavedPeers`) and `Thing(t)` (the groups holding `t`). The guess whether a route to `t` may still arrive (`route_arriving`) goes once every holder has a sync ID (issues/net-role-sync.md).
- **Catching up** goes: `set_role` writes at once (addenda, spec/permissions.md §5.2; Tess); an app that wants a removal judged against what it can fetch first calls `wait_synced(Thing)` before it, and the docs recommend that. The pre-sync is that same check.
- **History `complete`**: false while a pass with a source is unfinished on a sync ID carrying the thing, or before this node first finished a pass there (a sync ID it made counts as finished). Otherwise true, and like `Synced` it says nothing of nodes not connected. Unlike `Synced` it stays true offline: no gap is known.
- Public API changes (`SyncState`, `SyncScope`) pass notes/api-design.md; notes/api.md Sync configuration and status and Demotion and catching up are rewritten to match.
- Tests: the repro tests of rows 9 (an undelivered grant) and 15-18 (issues/net-tests.md), plus a served-only connection reaching `Synced` on both sides and a node connected only to a peer that cannot read.

## Steps
1. **One set and the API**: `sources(L)` (issues/net-sync-structure.md) over the connections up with L open, whoever dialed; the states, scopes and waits above; catching up goes; history `complete`. A served-only connection is a source judged by the dialer's pass alone, so at the served side it is `Syncing`: honest, and stated as the gap this step ships with (a NAT'd node's partner is never `Synced` until step 2).
2. **Both sides judge**, with issues/net-reconnect.md's pull (jobs 5-6 of issues/net-rework.md): each side's own pass over its own pull; the gap closes.

Unsure:
- (design) `complete` per sync ID of a node's own making: whether "counts as finished" holds when another node wrote under it first (a sync ID made from a group it was granted).
