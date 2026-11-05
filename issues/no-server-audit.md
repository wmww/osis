# No-server audit
> Summary: What each feature does with no hosts, relays or internet, only nodes that sometimes reach each other (spec/requirements.md, Offline and network). Data sync between nodes that already know each other works; getting to know each other, grants, revocation, recovery and sync status mostly don't, and no shipped build has P2P at all.
> Tags: node, sync, api

Probes: throwaway tests in `core/osis/tests/it`, two or three hostless `Osis` on `Runtime::Tokio`, not committed (`pNN`/`qN` below). `(tier 2)`: real iroh on localhost under `cargo test-net`. All others ran over `Transport::InProcess`, whose `peer://` finds any listener by key (core/transport/src/multi.rs:39). That is **kinder than reality**: a `works` from it says the sync logic holds, not that nodes find each other.

## Findings
Severity: **fails** (error or never happens), **silent** (claims success or does nothing, no error), **degraded**, ok.

| # | Feature | No hosts, no internet | Evidence | Severity |
|---|---|---|---|---|
| 1 | P2P at all, today's builds | App, Android and CLI are `Transport::Quic` without `iroh`, so peers are turned off; a direct link is `Invalid` | net.rs:239,257; p01 `Quic iroh=false` | fails |
| 2 | Create account | Works, but no recovery card and the key is discarded | handle.rs:436; p01 | degraded |
| 3 | CLI on a hostless store | `Runtime::None`, never syncs; links always `direct: false` | cli/src/lib.rs:318, cmd.rs:582 (read) | fails |
| 4 | Pair a second device | Works both ways: the app carries the texts, the reply brings the sharer's `reach.0`, so the new device dials it and hears its LAN tag | p02. Over a real LAN only in pieces: p02, `driver_lan_loop` (tier 2) | ok in-process; not run end to end |
| 5 | `make_link` | Not direct: `Invalid`. Direct: fine, with a runtime and iroh. `Runtime::None`: `Invalid`, though a bundle could carry it | share.rs:958,961; p01 | degraded |
| 6 | **Redeem a direct link on a LAN** | **Cannot find the sharer.** The link holds key and relays only; iroh refuses a key with no address (`No addressing information available`, 2 ms, same dial with a socket hint works in 6 ms); LAN tags match only co-readers' lan secrets, which the redeemer lacks | wire.md §10; iroh.rs:125; peers.rs:531; p20, p21 `Network("timed out")` at 40 s with the LAN loop on (tier 2); p09 `matched=false` for a joiner and a stranger | fails |
| 7 | Redeem, in-process | Works, also read role, also a joiner's `leave` of K | p04, p05 | ok in-process |
| 8 | Contact card | `contact_card` and `profile` are `Invalid` (a card's link is never direct), so no `import_contact` and no names | share.rs:1227,1259; p01; app/src/chat.rs:61,77 | fails |
| 9 | **Grant to a known account** | `Ok`, then never arrives: the inbox has no hosts, the deposit loop runs zero times, the delivery is marked sent. `wait_synced(AllWithSavedPeers)` `Ok`, nothing pending, no invite, status `NoPeers`, `unrouted` empty; after 100 s Bob has no role and doesn't know the thing. Also removal notices and re-seals by inbox (read) | local.rs:466-469,340-345; status.rs:71; p03, q4 | silent |
| 10 | **A grant cuts the grantee off** | Granting a joiner a role on a group whose label holds `reach.0` rotates Alice's key; so does a second direct link to such a group, ending a direct link, or `rotate_reach`. Joiners hold only the key from the link text and never learn the new one, so sync with them stops both ways, for good | peers.rs:179, share.rs:1183, peers.rs:407; q5, p14, q3 (100 s, past every retry) | silent |
| 11 | `add_with_grant` into a shared group | Works, when nothing rotated | q1 | ok |
| 12 | Chat | `create` works (read). `link` always `direct: false`, so `Invalid`; `add` is row 9; names are row 8. Android's home screen asks for a host first | libs/chat/src/lib.rs:182; app/src/ui/chat.rs:118; p01 for the same call | fails |
| 13 | `set_role`, `revoke_link` default (`Required`) | **Never succeeds**: a hostless label is `NoPeers`, which fails `Unsynced` in under 1 ms of the timeout, peers connected or not | share.rs:368,520; p04 | fails |
| 14 | `SyncFirst::Try` | Doesn't try: goes ahead after 24-54 ms of a 6 s timeout, so a connected holder's unseen work is undone (by `SyncFirst`'s doc, not measured). Only `Skip` and `Backdate` are honest here | share.rs:758; p04 | silent |
| 15 | `wait_synced(AllWithSavedPeers)` | Skips groups with no saved peer: `Ok` in microseconds with a write nobody received. The name and the doc say so, and the CLI's `sync` and `wait` print those groups; an app's own call still gets `Ok` | share.rs; p04 | visible |
| 16 | `wait_synced(Thing)` | `Unsynced` at once, always, even fully caught up with a connected peer | share.rs:520; p04 | fails |
| 17 | Status | Fixed in wording: `NoPeers` only with nobody connected on the group; with co-readers having it open, dialed or served, `Connected`; `connected` counts sync connections both ways, no client's. `Connected` claims nothing of what they hold, and waits treat it as `NoPeers` (rows 13, 16, 18) | share.rs, status.rs; `runtime::status_says_connected_with_a_direct_peer` | degraded |
| 18 | History `complete` | True whenever `NoPeers` or `Connected`, though a peer may hold more; the doc says so | share.rs:464, history.rs:146 (read) | silent |
| 19 | Restore, recover | No card without hosts, `Card` requires `address+`. With a card and the host gone, a live device doesn't help: only the card's hosts are followed, and it needs state `Synced`, which a hostless label never reaches | wire.md §10; person.rs:207,209; p01, p13 `Network` | fails |
| 20 | Data between nodes that know each other | Works: writes both ways, a 3 MB value, reader deposits | p02, p05, p12; `driver_p2p_iroh`, LAN loop (tier 2) | ok |
| 21 | Bundles | Work between co-readers, also hostless and with `Runtime::None`. **Not** for first contact: redeem by bundle alone times out (cause not traced; the link key's entry box comes from an open reply) | p01, p11 | degraded |
| 22 | **Peers of a link-shared group** | Default `reach.0` policy excludes it, so nobody knows anyone: a star on the sharer. Sharer gone: B to C never arrives. `Reach::Always` set by hand on every node fixes it | peers.rs:641-651; p07 | fails |
| 23 | LAN after joining | Same cause: a joiner never hears the sharer's LAN announcement | p09 | fails |
| 24 | Multi-hop, B reads | A to C through B works (A, C partitioned, B an admin who made C's link). **C to A doesn't**: Alice has the commit, pending `MissingChain` for 100 s, and never sees C as a holder (cause not traced: C's chain certificates aren't relayed) | p06, q2 | degraded |
| 25 | Multi-hop, B can't read | Works **only** if an admin names B as a host from the start, B is `Admit::Open`, and B has a fixed `quic://` address: A to B to C, B's role `None`. Nothing suggests or finds a carrier | p08 | degraded |
| 26 | Adding a carrier later | `sync(g, [b])` on a hostless group is `Invalid`. `add_peer` moves all of an account's own groups at once; nothing does it per group, nor for a group someone else owns | share.rs:1527,1759; p08 | degraded |
| 27 | Carrier on a dynamic address | `peer://` in a label's hosts is never dialed, so a host can't be reached by key: needs a stable IP and port. Link and card text fix hosts for good | conn.rs:226; spec/sync.md §10; share.rs:1416 | fails |
| 28 | Who gets dialed | Only: config hosts, labels' non-`peer://` hosts, hints, queued deposits' hosts, receipts groups, co-readers with `reach.0`, a link's sharer. No dynamic discovery; the LAN only confirms known co-readers | conn.rs:222-254 (read) | fails |
| 29 | `Admit::Own` default | A friend's device refuses: `Refused`, clear and not silent. No choice between own groups and any stranger's (`Open`) | host.rs:113; p08 | degraded |
| 30 | LAN source check | Valid announcements from 100.64/10, global IPv4, global IPv6, Yggdrasil's 200::/7 are dropped; the same one from 10/8, fc00::/7, fe80::/10 matches | lan.rs:394, peers.rs:517; p09 (with a control) | fails |
| 31 | LAN reach on a mesh | 255.255.255.255 and ff02::1 stop at one hop; no way to add targets (`LanConfig` not in `Config`) | lan.rs, net.rs:252 (read) | fails |
| 32 | LAN loop on one machine | Second node's `bind(47380)` fails: only logged, no LAN for it, no status | driver.rs:625-630 (read) | silent |
| 33 | Lost announcement | Next one is 30 s away; `driver_lan_loop_localhost` failed 1 run in 5 here, within its 30 s guard (not traced, likely this) | tier 2 | degraded |
| 34 | LAN tag vs clock | Tags tolerate 10-20 min of skew, `MAX_DRIFT` allows 60. Past it nodes never match, and a connection is what would correct the clock | peers.rs:525; p10 window | fails |
| 35 | Clock pulled by a peer | The offset is the median over all connections, peers included, with no cap: one peer can set it. Alice 120 min behind: Bob's `redeem` fails `own commit not applicable`. +120, ±30, -5 fine. Against "a wrong local clock harms only that node's own writes" | conn.rs:386; apply/mod.rs:817; p10 | fails |
| 36 | Co-reader cap | At most 8 per label, chosen by newest `seen.0`, and LAN tags come from that same list: an unreachable 8 hide a reachable 9th | peers.rs:303-315,524 (read) | degraded |
| 37 | Link expiry, hostless K | Only the device that made the link finalizes it (`h.here`) | deliver.rs:485 (read) | degraded |

## Builds (`iroh`, `lan` on by default)
- **Build**: `cargo test-net --tests --no-run` passes here, 4 min with iroh's tree. `osis` goes from 87 to 263 crates (`cargo tree`). Tier 2 passes but for row 33's flake. `clippy-net` not run.
- **Rust**: iroh and netwatch say `rust-version = 1.91`; root and libs/kit manifests say 1.88. Raise both. Toolchain here is 1.99 (read; not tried on 1.88).
- **Unification**: a default on `osis` alone breaks the gate's `unification_check`, since `-p osis-transport` then resolves differently (notes/build.md). Make `iroh` and `lan` non-optional in osis-transport, osis-node and osis, as QUIC is; keep only `relay` as a test feature. Every crate above osis-transport then pays for it (read).
- **deny**: root `cargo deny check` passes (`all-features` already covers iroh), but the `skip-tree` reason "off by default" goes stale. libs/kit: `Cargo.lock` has no iroh and `deny.toml` has no licence exceptions (CDLA-Permissive-2.0, Unlicense), so it needs both, and `--locked` fails until then (read).
- **Android**: not built, no SDK at ~/android. For that target `cargo tree` adds jni, ndk-context, netdev, netlink (277 crates). The manifest has only `INTERNET`. Likely lacks `ACCESS_NETWORK_STATE`, `ACCESS_WIFI_STATE`, `CHANGE_WIFI_MULTICAST_STATE`, plus a held multicast lock for broadcast reception, and netlink is restricted on newer APIs. All unverified, from general Android knowledge; needs a real phone. The app has no Java (`hasCode="false"`), so the lock goes over JNI as the clipboard does.
- **Browser**: no transport yet; iroh there is relay-only (notes/networking.md). No LAN, no direct. Not looked at further.

## Fixes: few mechanisms, many rows
1. **Tests that can fail** (all rows): `World` drops every dial that isn't a hub (core/test/sim/src/world.rs:424), so the sim and its sweeps never run peers; `InProcess` dials any key. Give `World` peer connections, and make `InProcess` honour `peer://` hints: no hint, no route, as iroh. Most of what's above then shows up in tier 1.
2. **P2P on** (1, 3, 5, 12): Builds above; hostless CLI and app get a runtime.
3. **`reach.0` to everyone who shares a group, by default** (10, 22, 23, 24 partly; issues/node-host-unify.md item 2): each side knows the other's key and lan secret, so joiners mesh, a rotated key spreads through the label, and either side can dial. Rotate only when someone is really removed. A joiner stops depending on the key in the link text. Open: public and bearer-read audiences.
4. **One idea of a label's sources** (13-18, 19's wait): hosts plus co-readers. `Synced` means a finished pass with each source reachable in the timeout, `Unsynced` only at the timeout, served sessions count as connected, `NoPeers` stops being a fault (a state "nobody else known" is enough). To decide: what `Required` promises when no single place holds all writes; proposed: a pass with the holder's own node if reachable, else any co-reader, else `Unsynced` at timeout.
5. **First contact without an address** (6, 8, 12, 21): a LAN tag and sealed signature derived from the link's seed, announced while the link is open, so holding the link is what recognises the sharer; plus current socket hints in link text (spec/sync.md §10 "published forms list relays only" must change: a link is a bearer secret handed over out of band, and hints are what work on a routed mesh). `contact_card` becomes a direct link when there are no hosts. A bundle may carry the K label's entry box.
6. **Inbox over any connection** (9, 8): an inbox's hosts may name `peer://`, dialed like any peer; the recipient's own node serves its inbox label already. Until delivered it stays pending and shows, so never silent. Minimum now: a grant to an inbox with no route reports it.
7. **Carrier: hosting by key** (25-29): `peer://` hosts are dialed (conn.rs:226 and spec/sync.md §10 change), an `Admit` for contacts and co-readers. How holders learn carriers on a dynamic mesh (gossip in `label.0`? a tag per label?) is Tess's design call, as is whether that is one mechanism with row 28. Row 24's chain bug is a small fix of its own.
8. **LAN rules** (30-34, 36): drop the source check (tag and signature already decide), tag windows as wide as `MAX_DRIFT`, `SO_REUSEADDR` or a local status for a failed bind, LAN tags over every known co-reader with the cap only on dials, extra announcement targets for routed meshes, faster re-announce on a join.
9. **Clock** (35, 34): a peer's offset is bounded or needs agreement from more than one source, and never fails a node's own commit.
10. **Recovery** (2, 19): always keep a key; `Card` with hosts optional and peers; restore through peers and the LAN. Goes with the rework in issues/node-host-unify.md item 3.

**First**: 1, then 2 and 3 (small, and they unblock the rest), then 4 (fixes the worst silent lies: rows 13-17). Then 5 and 6, which make a real first contact and grant work on a LAN.

## Verified or only read
- **By probe**: rows marked with `p`/`q`, tier 2 tests. In-process results say nothing about finding a peer: only p20, p21 and the tier-2 tests ran iroh, and all on localhost, never between machines.
- **By reading only**: 3, 18, 28, 31, 32, 36, 37, the "works, read" part of 12; 9's removal notices and re-seals; causes in 21, 24, 33; deny for libs/kit; everything on Android.
- **Not checked**: real devices, Wi-Fi client isolation, ephemeral values and signals over peers beyond existing tests, thin clients with no hosts, disk-backed restart of link peers.
- notes/networking.md is out of date where it says a contact card may carry a dialable key, and names `sync_policy` (now `set_sync_options`).
