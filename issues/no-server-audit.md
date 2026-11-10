# Audit: no saved peers, relays or internet
> Summary: What each feature does with no saved peers (nodes serving at a fixed address), relays or internet, only nodes that sometimes reach each other (spec/requirements.md, Offline and network). Data sync between nodes that already know each other works; getting to know each other, grants, revocation, recovery and sync status mostly don't, and no shipped build has P2P at all.
> Priority: normal
> Tags: node, sync, api

Evidence: `pNN`/`qN` are throwaway probes over `Transport::InProcess`, whose `peer://` finds any listener by key (**kinder than reality**: a `works` from it says the sync logic holds, not that nodes find each other). `(by hand)`: real sockets on localhost (the networking check, notes/testing.md By hand). `no_server` tests: core/test/sim/tests/it/no_server.rs, on `World` over the reachability model, model time; each open row's `repro_row<N>_*` (`#[ignore]` names the job, which renames it) asserts the right outcome. Also cli/tests/it/cli.rs `repro_row3_row12_*`.

## Findings
Row 35's likely cause, read only: the own-commit drift exemption skips only commits this node signs, not those signed by a key actor it holds (issues/clock-peer-offset.md).

Severity: **fails** (error or never happens), **silent** (claims success or does nothing, no error), **degraded**, ok.

| # | Feature | No saved peers, no internet | Evidence | Severity |
|---|---|---|---|---|
| 1 | P2P at all | P2P and the LAN loop run in every build; with no relay configured, nodes off one LAN reach each other only when one has a global address (listed in `reach.0`; issues/p2p-own.md) | net.rs `spawn_driver` | degraded |
| 2 | Create account | Works | handle.rs:436; p01 | degraded |
| 3 | CLI on a store with no saved peers | Commands that sync run a runtime with or without saved peers; local commands and `init` without `--peer` have none. Links are always `direct: false`, so `link make` is `Invalid` here (row 5) | cli/src/cmd.rs `network`, `Cmd::Link` (read) | degraded |
| 4 | Pair a second device | Works both ways: the app carries the texts, the reply brings the sharer's `reach.0`, so the new device dials it and hears its LAN tag | p02. Over a real LAN only in pieces: p02, `driver_lan_loop` (by hand) | ok in-process; not run end to end |
| 5 | `make_link` | Not direct: `Invalid`. Direct: fine, with a runtime. `Runtime::None`: `Invalid`, though a bundle could carry it | share.rs:958,961; p01 | degraded |
| 6 | **Redeem a direct link on a LAN** | **Cannot find the sharer.** The link holds key and relays only; with no relay a `peer://` URL lists nothing to dial (`Unreachable` at once); LAN tags match only co-readers' lan secrets, which the redeemer lacks | wire.md §10; p2p.rs `dial_inner`; peers.rs:531; p20, p21 `Network("timed out")` at 40 s with the LAN loop on (by hand); p09 `matched=false` for a joiner and a stranger | fails |
| 7 | Redeem, in-process | Works, also read role, also a joiner's `leave` of K | p04, p05 | ok in-process |
| 8 | Contact card | `contact_card` and `profile` are `Invalid` (a card's link is never direct), so no `import_contact` and no names | share.rs:1227,1259; p01; app/src/chat.rs:61,77 | fails |
| 9 | **Grant to a known account** | `Ok`, then never arrives: the inbox has no saved peers, the deposit loop runs zero times, the delivery is marked sent. `wait_synced(AllWithSavedPeers)` `Ok`, nothing pending, no invite, status `NoPeers`, `unrouted` empty; after 100 s Bob has no role and doesn't know the thing. Also removal notices and re-seals by inbox (read) | local.rs:466-469,340-345; status.rs:71; p03, q4 | silent Status: `wait_synced` keeps a delivery whose inbox lists no node pending (not "sent"); arrival is issues/net-first-contact.md. |
| 10 | Key changes and a joiner | A connected joiner keeps syncing through a grant, a second direct link, ending one and `rotate_peer_address`; a joiner away while a direct link ends finds the same key when back (nothing rotates by itself). A joiner away during a `rotate_peer_address` who can only dial out (NAT, no relay) is cut off for good: it knows only the old key and hears the new one from nobody (issues/net-connect.md, The listening key) | `no_server`: `key_changes_keep_a_connected_joiner`, `a_link_ending_while_away_does_not_strand_a_joiner` | silent (by hand only) |
| 11 | `add_with_grant` into a shared group | Works, when nothing rotated | q1 | ok |
| 12 | Chat | `create` works (read). The CLI's `chat link` is always `direct: false`, so `Invalid`; `add` is row 9; names are row 8 | cli/src/chat.rs; `repro_row3_row12_*` | fails |
| 13 | `set_role`, `revoke_link` | Write at once; other writers' addenda keep what they received, and a caller may `wait_synced` first (notes/api.md Demotion and addenda) | share.rs | ok |
| 14 | `SyncFirst::Try` | Gone: nothing waits before a removal | share.rs | ok |
| 15 | `wait_synced(All)` | Waits with nobody connected on any group in scope: nothing reports `Ok` over a group no node has open | share.rs | ok |
| 16 | `wait_synced(Thing)` | Ends `Ok` once caught up with every connected node; fails only on `Stranded` or no group holding it | share.rs | ok |
| 17 | Status | `Synced` needs at least one connected node with it open, each caught up (`NotConnected` for none); served-only connections read `Syncing` at the served side (issues/net-honest-status.md step 2) | share.rs, status.rs | ok |
| 18 | History `complete` | False while a pass with a connected node is unfinished or about to run, or before a first pass; true offline after | share.rs | ok |
| 19 | Restore, recover | Gone from the API until a design exists (issues/recovery-redesign.md) | - | n/a |
| 20 | Data between nodes that know each other | Works: writes both ways, a 3 MB value, reader deposits | p02, p05, p12; `driver_p2p_localhost`, LAN loop (by hand) | ok |
| 21 | Bundles | Work between co-readers, also with no saved peers and with `Runtime::None`. **Not** for first contact: redeem by bundle alone times out (cause not traced; the link key's entry box comes from an open reply) | p01, p11 | degraded |
| 22 | Peers of a link-shared group | Joiners find each other: `reach.0` goes under every synced label. Sharer and relay gone, B to C arrives | `no_server`: `joiners_of_a_link_reach_each_other` | ok |
| 23 | LAN after joining | A joiner hears its sharer's LAN announcement | `no_server`: `a_joiner_finds_its_sharer_on_the_lan` | ok |
| 24 | Multi-hop, B reads | Both ways through B (A, C apart, B an admin who made C's link). One order trips a debug assertion: issues/inbox-copied-stale.md | `no_server`: `writes_cross_a_reader_both_ways` | ok |
| 25 | Multi-hop, B can't read | Works **only** if an admin names B as a saved peer from the start, B is `Admit::Open`, and B has a fixed `quic://` address: A to B to C, B's role `None`. Nothing suggests or finds such a peer | p08 | degraded |
| 26 | Adding a non-reading peer later | `sync(g, [b])` on a group already synced with no saved peer is `Invalid`. `add_peer` moves all of an account's own groups at once; nothing does it per group, nor for a group under someone else's account | share.rs:1527,1759; p08 | degraded |
| 27 | Non-reading peer on a dynamic address | `peer://` among a label's saved peers is never dialed, so a saved peer can't be reached by key: needs a stable IP and port. Link and card text fix their addresses for good | conn.rs:226; spec/sync.md §10; share.rs:1416 | fails |
| 28 | Who gets dialed | Only: config peers, labels' non-`peer://` saved peers, hints, queued deposits' peers, co-readers with `reach.0`, a link's sharer. No dynamic discovery; the LAN only confirms known co-readers | conn.rs:222-254 (read) | fails |
| 29 | `Admit::Own` default | A friend's node refuses: `Refused`, clear and not silent. No choice between own groups and any stranger's (`Open`) | host.rs:113; p08 | degraded |
| 30 | LAN source check | Valid announcements from 100.64/10, global IPv4, global IPv6, Yggdrasil's 200::/7 are dropped; the same one from 10/8, fc00::/7, fe80::/10 matches | lan.rs:394, peers.rs:517; p09 (with a control) | fails |
| 31 | LAN reach on a mesh | 255.255.255.255 and ff02::1 stop at one hop; `Lan::On { also_announce_to }` adds targets by hand, and a source outside the private ranges is still dropped (row 30). No discovery across hops (issues/net-mesh-discovery.md) | lan.rs, net.rs (read); `lan_announces_to_configured_targets_across_segments` | degraded |
| 32 | LAN loop on one machine | Nodes share port 47380 on Linux (`SO_REUSEADDR`) and all hear broadcasts; a bind that still fails is logged and leaves the node working | `two_nodes_share_the_port` (by hand), `driver_lan_failed_bind_leaves_the_node_working` | ok |
| 33 | Lost announcement | A join announces 3 times in its first 2 s; a later loss waits for the next 30 s repeat | `driver_lan_join_repeats_its_announcement` | ok |
| 34 | LAN tag vs clock | Tags tolerate 10-20 min of skew, `MAX_DRIFT` allows 60. Past it nodes never match, and a connection is what would correct the clock | peers.rs:525; p10 window | fails |
| 35 | Clock pulled by a peer | The offset is the median over all connections, peers included, with no cap: one peer can set it. Alice 120 min behind: Bob's `redeem` fails `own commit not applicable`. +120, ±30, -5 fine. Against "a wrong local clock harms only that node's own writes" | conn.rs:386; apply/mod.rs:817; p10 | fails |
| 36 | Co-reader cap | At most 8 per label, chosen by node tid, and LAN tags come from that same list: an unreachable 8 hide a reachable 9th | peers.rs:303-315,524 (read) | degraded |
| 37 | Link expiry, K with no saved peer | Only the node that made the link finalizes it (`h.here`) | deliver.rs:485 (read) | degraded |

## Builds (`lan` on by default)
P2P is in every build; `lan` (socket2 only) is the one networking feature left.
- **Unification**: a default on `osis` alone breaks the gate's `unification_check`, since `-p osis-transport` then resolves differently (notes/build.md). Make `lan` non-optional in osis-transport, osis-node and osis, as QUIC and P2P are (read).
- **Android**: not built, no SDK at ~/android. The manifest has only `INTERNET`. Likely lacks `ACCESS_NETWORK_STATE`, `ACCESS_WIFI_STATE`, `CHANGE_WIFI_MULTICAST_STATE`, plus a held multicast lock for broadcast reception, and `/proc/net/if_inet6` (the IPv6 interface list) may be unreadable on newer APIs (then announcements go out the default interface only). All unverified, from general Android knowledge; needs a real phone. The app has no Java (`hasCode="false"`), so the lock goes over JNI as the clipboard does.
- **Browser**: no transport yet; relay-only there (notes/networking.md). No LAN, no direct. Not looked at further.

## Fixes
The fixes, their order and what is open: issues/net-rework.md and its job issues (`net-*`, rows cited in each).

## Verified or only read
- **By probe**: rows marked with `p`/`q`, by-hand tests. In-process results say nothing about finding a peer: only p20, p21 and the by-hand tests ran real sockets, and all on localhost, never between machines.
- **By reading only**: 3's "never syncs" (`Runtime::None` under the CLI needs real sockets to see), 31, 32, the "works, read" part of 12; 9's removal notices and re-seals; causes in 21, 24, 33; deny for libs/kit; everything on Android.
- **Not checked**: real devices, Wi-Fi client isolation, ephemeral values and ephemeral signals over peers beyond existing tests, thin clients with no saved peers, disk-backed restart of link peers.
- notes/networking.md is out of date where it says a contact card may carry a dialable key, and names `sync_policy`, which does not exist.
