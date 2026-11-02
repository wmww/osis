# Evidence for E spaces
> Summary: Citations and traces for notes/chat-designs/e-spaces.md: inheritance by nesting, the removal cascade and its cost, node cards under the members actor's label, the no-deny rule, mod bundles, hidden listings, sync per label, and what is estimated.

"Traced" = read in spec or notes. "Estimated" = arithmetic from cited sizes. "Unverified" = inferred.

## Shape
- Listing grants nothing (spec/data-model.md §8; spec/permissions.md §1). Role on an actor covers everything it owns and, through its grants, the minimum along each path; effective role is the maximum over paths (spec/permissions.md §1). So EV write on C gives a writer of EV write on C; admin on C through a role actor needs admin on that actor. Traced.
- Admins of an actor are equal and may remove each other (§1). So admin-holders of MODS manage MODS. Traced.
- Ownerless actors: issues/ownerless-things.md (no roster snapshots), so `roles.0` edge writes stay forever (notes/growth.md "roles.0 edge writes with no roster snapshot"): the audit log. Traced.
- EV must have a home label: an actor "MUST have one when ... it receives grants" (spec/sync.md §2) and every grant to a holder actor is delivered to its inbox (spec/permissions.md §2). Members hold roles on EV, so they read its label (boxes to them are in EV's `secrets.0`). Traced.

## Removal
- §3: a departure of M from EV "requires rotating every role secret M could open through A: on A the roles M left; on every thing with secrets of its own that A's roles open ... transitively". The removal and EV's rotation are one role commit; "Every other rotation is required of whoever may make it, when it next encrypts under the secret" (lazy, by writers: "a node with effective role write or above on an actor may rotate its roles at or below that role"). Traced.
- Boxes: about 1.2 KB per holder per role (notes/permissions.md Nesting cost); 2707 B per holder measured for read plus write (notes/chat.md Costs). Channel rotation sealed to EV, MODS, direct holders: about 3 holders × 2.4 KB plus `keys.0`: about 7 KB. 100 channels about 0.7 MB. Estimated.
- Registration admin-only: "only an admin registers" (spec/sync.md §2); a writer's rotation leaves the old step (notes/sync.md Limits). Traced.
- Frontier scope "every aspect of the things the demoted authority gave write on" (§5.1); pre-sync of every such label (§5.3), receipts-only reads for labels the kicker does not hold (notes/sync.md). Heads per (aspect, device) for permanent deltas: notes/frontier-study.md §5 (about 60 B each), unbuilt. Traced.
- Nesting: "Direct rosters hold thousands of holders; larger ones nest" (spec/requirements.md Scale). Tiers as holder actors of EV: a removal from a tier rotates the tier, then EV (holders: tiers), then channels (§3 transitively). Traced; sizes estimated.
- Node cards: "When a node first places anything under a label ... it places its chain certificates and node card" (spec/permissions.md §4; a reader by deposit); notes/permissions.md Concepts: "the node card under every label a node tracks shows ... which nodes sync L (a read-only node's card arrives by deposit)". Card size about 1.3 KB (a 1216-byte KEM key in `keys.0`, notes/chat.md Costs) plus `node.0` and `reach.0`. 100,000 members × 1.5 devices × 1.5 KB ≈ 225 MB. Estimated; whether a pure reader always deposits its card, or only once it places something, is unverified from the text ("first places anything").
- Join: 2.7 KB grant; 11.5 KB chain certificates per label the joiner writes to (notes/permissions.md Certificates). Traced.

## Permissions
- No deny: maximum over paths (§1); `until` is per edge (§2). Traced.
- Admin bundle: "Admin = write + change role grants + purge + write admin-only aspects" (§1). Traced.
- Purge by admins: `author` includes the thing's admins (§8). Traced.
- Reactions need write on the chat (E; e-review §8). Sister chat: a second ownerless actor granted EV write. Traced by rule.
- Hidden listing: entitlement puts a blob under a label only if the group's actor may read it (spec/sync.md §3); a sub-list group with secrets of its own, read by the private role only, keeps its `group.0` under its own label. Traced.
- Acting as EV: writers may act as the actor (notes/permissions.md Concepts "A role on an actor covers both editing the actor thing and acting as it"); the display rule of e.md plus "actor is an account" (its creation record names a key actor as owner, spec/data-model.md §1; an ownerless actor names none). Traced by rule.
- Invites: `invite` on edges, links (§2, §9). Traced.

## Sync
- Sync is per chosen group (`db.sync`, notes/api.md Sync configuration); "Nothing syncs by being owned: apps place things into synced groups explicitly" (spec/requirements.md Offline). Traced.
- Unread counts: cursor sync returns log events after the cursor (spec/sync.md §6); counting without bodies needs issues/partial-history-fetch.md. Mentions need bodies (content encrypted). Wake relay: notes/networking.md proposal. Traced.

## Composability and moderation
- A thing in many groups is stored once (spec/requirements.md Cost); listing in two spaces and granting two EV actors. Moving a thing is a copy only when ownership changes (§7); here nothing is owned. Traced.
- Space in space: S1's EV granted write on S2's EV; roles nest by the minimum rule (§1). Rotations cascade through holder actors (§3). Traced.
- Purge request may name many deltas; purge by author: issues/purge-by-author.md (unbuilt). Rate limits: hosts limit per label and connection (spec/sync.md §5), nothing per member. Traced.

## Matrix comparison
- From general knowledge of Matrix spaces (m.space.child, per-room power levels, restricted join rules), not from this repository. Unverified against Matrix's current spec.
