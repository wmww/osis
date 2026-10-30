# One hub thread: what is left of the stall bounds
> Summary: the server runs every connection's input on one hub thread. Per-input work is now bounded and close to honest work (notes/sync.md, Hub stall bounds). Left: sources a transport cannot tell apart (iroh, many addresses), no node-wide relay rate with a shared replay memory, and everything still serial on one thread. Low.
> Tags: security, server

Done (branch hub-stall): claim keys indexed as rows (an Open is a lookup); after one bogus signature a message's later ones try the head key only; Sync entries capped at 1024; one fsync per input; relays only to subscribers; full connection slots shared fairly by source (hub sessions and listener connections); a connection pipelining replies past `SEND_QUEUE` is closed mid-input; per-label maps pruned when an open ends.

Left:
- **Sources**: fairness keys on `Connection::source` (IP, IPv6 /64). iroh connections have none and count as one source together, so an iroh flood shares slots with every iroh client; an attacker holding many addresses (a botnet, many /64s) still gets a share per address.
- **Relays**: rates are per label (`RelayLimits`), so an attacker with many labels relays without a node-wide bound (fan-out now only to subscribers, each limited by its send queue). The node-wide `MAX_RELAY_SEEN` set is shared, so such a flood evicts honest labels' replay memory (a replay is then pushed again: minor).
- **Serial work**: decode, signature checks and store access all run on the hub thread; connections interleave per 64 KiB read chunk. Moving decode and verification to per-connection tasks (store access serial) would let a slow input no longer delay others at all.
