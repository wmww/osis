# P2P: what works and what is left
> Summary: Co-readers sync labels with no server (in process and over iroh on localhost); the iroh transport and LAN announcement codec/socket exist. Left: LAN loop in a driver, one driver carrying servers and peers, the member-node rule without an open, `/reach` exclusion per label, a relay test, peer coverage in `complete_pass`, LAN key binding.
> Tags: sync, networking

Repro: not built yet, no failing test.

Works (notes/networking.md, Implementation; tests: osis-node tests/peers.rs, tests/driver.rs `driver_p2p_*`, osis-transport `iroh.rs`/`lan.rs`): `/reach` publish and rotation, co-reader selection and dialing at `peer://`, member-peer serving over the node's own entries, LAN tags and matching (`lan_seen`), `Iroh` (dial by key, direct and relay hints, `dial_as`), `run_serving` with listeners.

Left, roughly in order:
1. **One driver for servers and peers.** The node driver is generic over one `Transport`; servers need `Quic`, peers `Iroh`. A scheme-dispatching transport (`quic://` -> Quic, `peer://` -> Iroh, `mem://` -> InProcess) in osis-transport, then the API's driver uses it with the dialable-key listener.
2. **LAN loop.** Per network join: a fresh `StaticSecret`, an `Iroh` listener with it (`run_serving` takes it), announce `Announce { tag: lan_tag_now(), key, port }` to the broadcast address every window and on join; feed received announcements to `SyncEngine::lan_seen` (via `Control::Call`). Needs network-change detection (iroh's netwatch, or the app) and a way to add listeners to a running driver.
3. **Member node without an open** (spec/sync.md §5 last bullet): `accept`'s peer key matched to a `/reach` dialable of a node that currently reads the label opens it on that session (a `ServerConnection` hook to pre-open labels, osis-proto). Needed for first contact (a redeemer without keys yet, spec/permissions.md §9); peers that dial with `dial_as(dialable secret)` then.
4. **`/reach` per label**: apps exclude it under open-audience labels (spec/permissions.md §4); the node card places it everywhere today.
5. **Relay test**: two nodes through a self-hosted `iroh-relay` on localhost (iroh-relay's `server` feature, tier 2 only), and the relay setup recorded in notes/networking.md.
6. **Complete pass over peers**: `complete_pass` counts servers only; spec/permissions.md §3 also names peers it received from and can reach.
7. **LAN key binding** (owner decision: do it with the LAN loop, item 2): spec/sync.md §10 should bind the per-network LAN transport key to the node after connecting (e.g. the served side signs the session under its dialable key, or the announcement is MACed under the lan secret with the transport key), so a matching tag alone cannot divert a co-reader's route. Until then the node keeps the conservative rule (written in §10 with the provisional datagram): a LAN address is a candidate until a session through it opens a label; a failed one is backed off, never the peer.
8. **Costs**: `PeerStore::live` reads each blob for its size; `peers()` reads every `/reach` and `/seen` per call (called per `handle`); budget accounting scans charges and presence per served message; both want an index if peers become common.
