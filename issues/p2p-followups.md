# P2P follow-ups
> Summary: Direct device-to-device sync works (LAN, relays, no server); left: a new contact cannot yet reach the sharer directly from a share link, devices already talking through a relay keep doing so after meeting on one LAN, a `/reach` placed under a label stays after the group's policy excludes it, and a new dialable key needs a restart to be listened on.
> Tags: sync, networking

Repro: none failing; gaps found while finishing the P2P work (notes/networking.md, Implementation (node peers)).

1. **First contact by link** (spec/wire.md §10, spec/sync.md §5): a link's `peers` field (the sharer's dialable key and relays) is decoded but never dialed. A redeemer sharing no server with the sharer should dial it (`peer://` + relays) and open K's label there; the served side already opens it for a static-entry proof.
2. **LAN over a running relay route**: a LAN candidate never displaces a running connection (spec/sync.md §10), so a peer reached through a relay stays on the relay after both join one LAN until that connection ends. Wanted: dial the candidate beside the running connection and switch once it is up.
3. **Retracting `/reach`**: when a group's policy turns to excluded (or a contact stops being one), the node card's `/reach` already placed under its labels stays; deleting it needs the pass to delete this node's own certificate entry (`sync/pass.rs`).
4. **`rotate_reach`**: gives a new dialable secret, but the driver keeps listening with the old one until `Control::Reach` is sent again (the osis handle sends it only at start).
5. **Network change**: the LAN loop polls the route's local IP every 5 s (`lan::route_ip`); a change that keeps the IP (another Wi-Fi with the same addressing) is missed. iroh's netwatch could replace the poll. IPv4 only (the listener binds `0.0.0.0`, announcements go to the IPv4 broadcast address).
