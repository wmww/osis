# Review of chat design E spaces
> Summary: Independent review: the shape holds (lists do not double-store, channels do not carry whole rosters), but cutting off a kicked member at hosts needs an admin step per channel per host, devices sync all channels by default, the worst cost is certificates and heartbeats under the members' label, and ordinary device churn drives the bill. Fits about 1000 to a few thousand members today's way.


Read spec/, core/ and the notes; nothing was run. Sizes are arithmetic from cited measurements. Issues in issues/ are assumed fixed unless noted.

## 1. Removal

**What must rotate: CONFIRMED.** Per §3: EV read and write in the removal commit, then read and write of each channel EV opens, transitively (sub-spaces' EVs too). Any writer may rotate these (§3 Who rotates).

**M's secret: CONFIRMED indirect.** C's box is keyed to EV, not to M. M opened it with EV's secret and holds C's old epochs that way. The new box is sealed to EV's new keyset, so M cannot open it.

**First post under the new key: CONFIRMED.** A node "MUST NOT encrypt under" an uncovered epoch, so it rotates first (crypto §4) and the message follows under the new key. Only the rotation commit stays under the old wrap, showing M the holder tids but no secret. The hole is a poster who has not heard of the kick. That poster's message is readable by M (accepted limit, notes/permissions.md). Who learns: anyone syncing EV. A channel-only poster learns only once someone places the removal under C.

**"A channel nobody posts in never rotates": REFUTED by code.** `pass` -> `usable_keys` -> `uncovered` -> `ensure_rotated` (core/node/src/sync/pass/mod.rs:555, sync/mod.rs:1219) rotates on any sync pass by any writer holding the label, not on post. Two consequences:
- Quiet channels rotate as soon as a member's device passes them. Spec allows it ("MAY rotate eagerly").
- There is no settle delay on this path (`SETTLE_MS` guards only certificates and steps). When the kicker does not sync C, every online writer may rotate at once and fork. That is up to about 11 KB per online device per channel. Magnitude UNVERIFIED, path traced.

To get the design's laziness, the pass must stop rotating. Then writers must also stop stamping and placing under C until something forces the rotation.

**"With no kicker work and no half-done state": REFUTED. This is the crux.** A writer's rotation changes no label key at a host. Only an admin registers (§3, sync §5). Until an admin syncs that channel at that host, M keeps:
- the old sync key (ciphertext, counts, timing);
- the old **write key**, so a modified client can still upload stamped junk;
- the old deposit key (only an admin's read rotation refreshes the seed, crypto §3).

The design says "ciphertext only", which is wrong: M can still post into hosts. Those posts are invalid for readers holding the kick, but no must-not-hold rule covers invalid bodies, so they stay in the required set (sync §6), are stored and are downloaded. So a kick really has three states per channel: not rotated, rotated, stepped.

**Cost of the admin part: channels x hosts in messages, little in bytes.** The claim set counts holder actors, not members, so a step is about 323 B plus about 128 B, plus a `label.0` write. At 100 channels and 3 hosts that is 300 registers, about 150 KB. It does not change the byte totals.

The real costs are authority and reach:
- `step_due` needs admin on that label, and receipts-only reads refuse to register (§5.3, `register_path` fails). So a mod must fully sync every channel, or be a bot that does.
- Steps never leave the host path, and a member offline through n steps walks n round trips per channel (sync §5). At 100,000 members, with about 100 departures a day, that is about 700 round trips per channel after a week away.

**Channel rotation "about 7 KB": undercount.** Measured figures give 2.7 KB per holder plus 2.6 KB `keys.0`, about 11 KB at 3 holders. Worse, it holds only if issues/keyset-names-placement-rosters.md is fixed, and that issue has no chosen fix. Today a rotation names every departure below C, and ownerless EV has no epoch start, so every EV removal ever plus every member's device removals appear, and each named commit is placed under C. At 75 B per name x 2 roles: about 0.3 MB per rotation at 1000 members, about 30 MB at 100,000.

## 2. Frontier scope

**One commit, scope across channels: CONFIRMED.** A demotion on EV below write audits "every aspect of the things the demoted authority gave write on", so all channels EV writes (§5.1). One edge write means one frontier.

**Size: CONFIRMED with a condition.** 60 B x (aspect, device): 100 channels x 2 aspects x 2 devices x years is 24 KB per year of aspects, about 120 KB after 5 years. Fine and by link. Holds only for all-permanent aspects. A disappearing channel lists commit IDs for its window (32 B each).

**Pre-sync "reads 100 labels' headers": undercount.** Headers are inside the ciphertext. `read_receipts` fetches every commit blob it can open (notes/sync.md), and each read lists the label cursor-less. A mod device without the channels pays the whole history once, then a log listing per kick. That is O(history), which the frontier study removes from the commit but not from the pre-sync.

**Which label: CONFIRMED.** The commit is under EV's label. A copy goes under every label the kicker tracks that M could read (§3). Other nodes place it only where it changes a verdict (§4). A channel-only reader gets it when M posts after the kick, or from the kicker. M's old posts stay valid without it.

**"Every channel carries everyone's whole roster": REFUTED.** Certificates are path-projected (§4; `cert_parts`): only the author's own edge (P, EV), edge (EV, C), and the writers' chains, 11.5 KB per person per label. A channel-only member verifies a poster with no EV roster. Exceptions:
- A removed inviter's demotion, with its frontier, sits in each invitee's chain, one copy per label.
- The names issue above does carry departure history to every channel.

**Not raised: "read-only mode, one commit each" is a demotion of EV on C.** Its frontier covers every node below EV: about 90 KB per aspect at 1500 devices, about 9 MB at 150,000. Its write rotation is lazy too. Moving a channel out of a space costs the same. Still one commit, but not small, and re-granting revives gap posts.

## 3. Node cards and join

**Real, and placed by readers too: CONFIRMED by code.** `certificates` runs on each pass for a node with write or deposit keys (pass/mod.rs:300), not only after it first places something. This settles the unverified note in the evidence file.

**"That is the worst cost": REFUTED.** Per pass the node places chain certificates and card together. Chain is 11.5 KB per person, card about 1.5 KB per device. The design charges chain "per channel posted in" and only the card per label read. Actual cost is both, per label synced.

| Under EV's label | 1000 members | 100,000 members |
|---|---|---|
| Chains and cards, once | about 13 MB | about 1.4 GB (design: 200 MB) |
| Heartbeats per day, all online (on by default, 4 a day, 0.4 KB) | 2.4 MB | 240 MB |
| Per-channel chains and cards, for each channel synced by all | about 13 MB | about 1.4 GB |

Nesting does not help: a member must read EV's label to get EV's secrets, so everyone's chain lands there. The names cost (item 1), if unfixed, is the worst of all. A card opt-out alone does not solve this. It must also skip chains and heartbeats for pure readers.

**Join cost: undercount.** The joiner uploads about 13 KB per label it syncs. First sync of EV at 1000 is about 20 MB (roster about 1 MB, current boxes 2.7 MB, certificates 13 MB). No roster snapshot ever compacts EV. Memory for the role walk is a further worry: the bench at 10^4 edge writes held about 3 GB per held set (issues/perm-eval-cost.md), UNVERIFIED for a member's node.

## 4. Sync

**List without bodies: CONFIRMED, with a trap.** Entitlement filters closure by `may_read(group's actor, thing)` (sync §3, labeling/actors.rs). S with secrets of its own and no role on channels gets only its own aspects, no duplicates, whether channels are items or subgroups.

The trap: the list must never be EV, or a role actor, or a plain thing they own, because its actor could then read the channels and every body lands under its label too. Same for the private sub-list. The design's shape is right but does not state this rule.

**"A node syncs the labels it chooses; holding EV forces nothing": REFUTED.** `compute_labels` syncs **every** labeled group whose read secret the node holds, unless marked receipts-only (sync/mod.rs:1123). A grant to EV lands under EV's home label with C's box and `label.0` (sync §3), so a device syncing EV syncs every channel by default. `db.sync` is the admin's act of creating a label, not a device's choice.

The opt-out exists (`GroupPolicy::receipts_only`), but it is per device, per channel, and set after discovery, so a new channel starts syncing before the app can mark it. Core needs a default-off policy for this. That is a core change the design says it does not need.

**`sync_closure`:** marks closure things `syncing` though their labels are not synced. Effect: a commit that both creates C and lists it in S holds whole at devices not syncing C, because `created.0` of C never comes (commits §4). Rule: list a channel in a commit of its own. `wait_synced` is unaffected.

## 5. Hidden channels

**Mostly CONFIRMED.** Roster, chain certificates, inbox (ROLE's own) and rotation names stay within readers of C. No tied edges in this design. Leaks:
- If the sub-list is a subgroup of S, S's `group.0` shows its tid to every member. Fix: do not list it in S; list it in ROLE's own label via a sub-list.
- After the frontier study, a device removal's frontier names `(tid, ak, ...)` for every aspect the device wrote, private channels included, and that certificate copy goes under public channels. Today's frontier is opaque IDs. The study's head format adds this leak. Fix candidate: name the head by commit ID.
- One purge commit across channels shows all their tids in its header, so private channels need a separate commit.

## 6. Not expressible

**No deny: CONFIRMED.** Roles take the maximum over paths, and no layout subtracts.

**Admin bundle on C: CONFIRMED.** Admin forces roster, settings, keys and purge together.

**"Delete but not lock is not expressible": REFUTED.** Put messages on a thing Y owned by C, and give delete-mods read on C and an admin edge on Y (§1 "An admin edge on a plain thing grants changing its role grants and purge on that thing"). Purge is judged per thing (§8). They cannot touch C's roster, settings or lock, and cannot remove C's writers, since an owner edge is not removable. Costs: Y needs its own secrets, so one more rotation per channel per kick, and a Y admin can add writers to Y. E already lists this layout as clean for another app.

**Hide-and-purge: partly works, and it is a mute, not a ban.** Hiding needs honest clients; purge needs a retention that admins can purge. The banned member keeps reading and keeps posting, each post costing about 1.2 KB and leaving a 300 B tombstone for good. Only removal from EV stops it.

**"Timeouts: `until` on the EV grant": REFUTED.** `until` ends an edge at a time. There is no start time and nothing restores it. A timeout is a kick plus a later re-grant by an online mod, and the re-grant makes the modified client's gap posts valid (§5.2). A real timeout must be client-honored: a time in the muted set.

## 7. Composition and senders

- **Space in space: CONFIRMED** with limits. A kick from S1 also requires rotating S2's EV (2.7 MB at 1000, by a writer) and S2's channels. S1's mods cannot step S2's labels. S2's channels join the frontier scope and pre-sync.
- **Same chat in two spaces, moving: CONFIRMED** by rule. No copy, but moving out is the demotion cost of item 2.
- **Second path: CONFIRMED.** Validity falls only if the effective class falls (§5.1, §5.2). The secret still rotates, though M reads on through its other path.
- **Sender rule through two levels: CONFIRMED.** Effective role is the path minimum, so D -> P -> EV -> C passes with actor P. The device signs, header `actor` is P. Acting as EV also passes the rule and is hidden by "account".
- **"Actor is an account" too narrow: correction.** Thin-client actors and any actor owned by a person name no key actor as owner (spec/data-model.md §9 `clients.0^`), so bots and nested personas show as no sender. Hide ownerless actors instead.
- **No admin left: CONFIRMED,** and labels freeze: no steps at all, so every later kick leaves stale keys for good.
- **Ban under a flood: REFUTED as sufficient.** Purge-by-author alone leaves M uploading through the stale write key. The stopping action is an admin step per channel per host, first. Hosts may rate-limit the many deletes.

## 8. Unread and notifications

**Unread counts: mostly REFUTED as useful.** A metadata Sync (`inline_limit` 0) gives entries without bodies, so counting works. But the log event carries no kind (sync §4): certificates, reactions and 4 heartbeats per device per day all count. In a 1000-member channel heartbeats alone are about 4000 entries a day, drowning any real count. An exact count needs fetching and opening the small entries. A separate per-channel latest-time register on S would be cheaper.

**Mentions: CONFIRMED need bodies.** Waking per label means fetching new bodies, which is a tail sync, so "mute by not syncing" and "tell me when mentioned" conflict. Needs tail fetch (partial fetch) or a new mention blob boxed to the target; inbox payloads are only role commits today (crypto §5).

**Hosts see:** per-label opens, entry counts and timing; labels shared on one connection linked together; wake relay adds a device-to-label map.

## 9. Other failures

1. **Device churn and leaves count as kicks, unpriced.** A lost device or a self-removal is a departure inside EV (§3, crypto §4). The next writer pays EV's whole rotation before posting: 2.7 MB from a phone at 1000 members, plus tier, EV and channel at 100,000. Self-removal carries no rotation, so a random poster pays. At 100,000 with 100+ departures a day, EV's label alone gets about 27 MB a day, more with concurrent forks.
2. **Removing a mod is the worst kick, unpriced.** All three roles rotate on MODS, EV, S, tiers and every channel, by admins only. Until each label is stepped the ex-mod keeps the delete key: it can delete entries at hosts and race re-registration, whose remedy is a replacement label, O(entries). Hostile admins are out of scope, but this shape makes demoting one routine.
3. **Sidebar needs names.** The list holds tids only. Names live on C, under C's label. A directory needs `name` per channel on S itself. Easy, but not in the design.
4. **Read-only channels fill the deposit budget.** Budget is `64 + 4 x claim slots` (host policy default), and slots count actors, so about 80 entries at 2-4 holders. Every reader device deposits chain and card. An announcement channel fills at about 20 devices until a mod's device promotes them. Heartbeats back off when tight, but a stranded report or revoke can be refused.
5. **Host admission.** `admit own` never admits labels of ownerless things (spec/data-model.md §9). A host must be told each channel, tier, role actor and sub-list explicitly, or run `open`. Each new channel is a host-configuration step for self-hosters.

## Corrections for e-spaces.md

- Replace "no kicker work" with: confidentiality needs no kicker work; cutting M's sync and write keys needs an admin step per channel per host.
- Replace "ciphertext only" with: M keeps stamping uploads and depositing until stepped.
- Replace node cards as worst cost with: chains, cards and heartbeats per label, about 1.4 GB once plus 240 MB a day on EV at 100,000.
- Replace "holding EV forces nothing" with: default syncs all; needs a default-off policy.
- Add the list rule (actor holds no role on channels), the separate listing commit, and channel names on S.
- Remove `until` timeouts; move delete-only mods to expressible by layout (Y); call the channel ban a mute.
- Fix the sender rule to hide ownerless actors. Price device churn, leaves and mod removal. List the names issue as a blocker for every number.

## Verdict

The shape is right. A list, role actors, nesting and path-based roles do give Discord's structure with few new concepts, and two things I expected to break do not: lists do not double-store bodies, and channels do not carry whole rosters. But "mostly simple" and "nothing blocks this" oversell it. A kick is simple only for confidentiality; cutting a kicked member off at hosts needs an admin's step per channel per host, and until then that member can still upload. Rotation today is eager on sync, not lazy on post; devices sync every channel by default; the worst cost is several times the stated one and recurs daily. Ordinary churn, not kicks, drives the bill. Assuming the listed issues are fixed, it fits about 1000 to a few thousand members comfortably, and about 10,000 on desktops at the outside (about 130 MB of certificates plus 24 MB a day of heartbeats on EV, per device). The limit is per-device certificates and heartbeats under EV's label, then rotation per departure. 100,000 needs a core change so pure readers place nothing under EV, plus cheaper rotation. If the names issue stays unfixed the limit is near 1000.
