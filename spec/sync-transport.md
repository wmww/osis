# Sync transport
> Summary: The transports sync runs over: byte streams and addresses, node keys and `reach.0`, QUIC, `peer://` with relays and hole punching, LAN discovery, the one listening key, bounds on served connections, the unix socket and client sessions.

**Principle:** sync needs only an ordered, confidential byte stream with an authenticated peer key; nothing above this layer assumes a peer is directly reachable, on IP, or found by broadcast.

## 1. Streams and addresses
- Sync runs over any ordered, bidirectional byte stream with confidentiality and an authenticated peer key.
- A transport handshake has no deadline of its own beyond the transport's idle timeout; a node MAY close a connection whose peer sends no Hello (spec/wire.md §11.1) within a local policy bound.
- A node **address** is a transport URL plus the node's static public key; a client MUST check the node's key against it.
- **Route rank**: each connection the transport hands up carries a rank, the same at both ends, lower better: 0 a direct connection whose session protocol is `osis-lan` (a LAN listener's, §3, §4), 1 any other direct connection, 2 a relayed one (§3); a transport added later names its own. It is all sync learns of how a peer is reached (spec/sync-opens.md §1 One connection per pair). **Discovery** (§4) hands up the keys and routes it finds as dial candidates.
- **Keys and reach**: clients connect to nodes with an ephemeral transport key per connection. A node's dialable P2P key is separate from its signing key and published only in `reach.0`, together with its global addresses, its relays and the account it says it belongs to (for dialing only, never proof); `reach.0` goes under its account's D's home sync ID only, so only its own account's nodes read it. Other nodes learn a dialable key and addresses from a link, a configured address, a connection, or the dial list of a contact's profile (`dial.0`, spec/sync-set.md §1; for dialing only). Other addresses are never published; nodes exchange them on a connection (hole punching), or LAN discovery finds them.
- **Node keys**: a node's dialable key and its LAN transport keys are Ed25519 public keys (RFC 8032), each with a 32-byte seed as its transport secret. A node dials other nodes with an ephemeral transport key and proves the actors it acts for inside the session (spec/sync-opens.md §2).

## 2. QUIC
- **`quic://host[:port]`** addresses (port 4040 when absent, an IPv6 address in brackets):
  - QUIC v1 (RFC 9000, RFC 9001) with TLS 1.3 only, ALPN `osis`, 0-RTT MUST NOT be used.
  - Both sides MUST authenticate (client authentication is mandatory) with RFC 7250 raw public keys: an RFC 8410 Ed25519 SubjectPublicKeyInfo, signature scheme `ed25519` only, no certificates.
  - The listener's key is the address key; a client's is fresh per connection.
  - SNI is ignored.
  - Each sync session (spec/wire.md §11.1) runs on a bidirectional stream the client opens; the dialer closes the connection.

## 3. `peer://` and relays
- **P2P transports**: a node dials another node by dialable key over a P2P transport, each named by its own address scheme; only `peer://` is defined.
- **`peer://`** nodes are dialed by dialable or LAN transport key:
  - The URL is `peer://` then items separated by single spaces, each a socket address of the node (`ip:port`, an IPv6 address in brackets) or a relay, written `<key>@<socket address>` with the relay node's dialable key as 64 lowercase hex digits. Other items are skipped, and items past the 16th; none means LAN only. No address lookup service or default relay is used.
  - `reach.0` lists the node's dialable listener at each global socket address it is bound to, then its relays. An unspecified bound address stands for the local address of each route out (IPv4, IPv6) of a family the listener serves (an unspecified IPv6 address serves both) as of when it starts listening; global means none of unspecified, multicast, IPv4 broadcast, loopback, private (10/8, 172.16/12, 192.168/16), link-local, IPv4 shared (100.64/10) and IPv6 unique-local (fc00::/7).
  - Links list relays only.
  - A node listens on one UDP socket with QUIC as `quic://` (TLS 1.3, raw Ed25519 keys both ways, no 0-RTT, no session tickets), its key the dialable or LAN transport key. A LAN listener serves ALPN `osis-lan` only; any other serves `osis` for sessions and, when it relays, `osis-relay`. A direct dial for a session offers `osis` and `osis-lan`, so the protocol chosen is the listener's kind at both ends.
  - A dialer binds a fresh UDP socket per dial and address family its items use, and does each item's work from the socket of its family. It dials each socket address of the URL, and through each relay, at once; the first connection to complete serves the dial.
- **Relay wire**: a client connects to the relay's socket address with ALPN `osis-relay`, pinning the relay's key, and makes each request on a bidirectional stream it opens. `addr` is 18 bytes: the 16-byte IPv6 address (IPv4 as IPv4-mapped) then the be16 port of the UDP source as the relay sees it.
  - **Register**: the client sends `0x01`; the key registered is its TLS key. The relay answers `0x00 ‖ addr` (the client's) and the key stays registered while the stream and connection stay open, a later registration of the key replacing it; or it answers `0x01` (refused) and finishes the stream.
  - **Dial**: the client sends `0x02 ‖ key (32)`. The relay opens a stream on the key's registration connection that starts with a 16-byte tag of the dialer's source, and answers `0x00 ‖ addr` (the dialer's); or, with no registration of the key it allows, answers `0x02`; or, when it cannot open that stream at once, answers `0x03` (busy). It never waits for room on a registration connection. After `0x02` or `0x03` it finishes the stream. A tag is the same for every dial from one source through that relay, differs between sources, and reveals nothing of the address to one without the relay's secret; the target counts it as the connection's source. The relay never sends a side the other's address.
  - From then on the relay forwards each side's bytes, and its finish, to the other unchanged. A stream starting with any other byte is dropped.
- **Relayed connection**: TLS 1.3 runs over the forwarded bytes as on a direct connection (the dialer is the client and pins the target's key, ALPN `osis`, raw keys, no session tickets, no early data), records exactly as RFC 8446 frames them. The plaintext starts with an `addr` from each side, which each sends before reading the other's: its own address as the relay saw it (the dialer's from its Dial answer, the target's from its Register answer). Then the plaintext is one session; a relayed connection carries no other. Its end is the TLS close_notify; forwarded bytes ending without one end it abnormally.
- **Registration streams**: a registering client lets the relay open 2048 streams at once on the registration connection, with a connection receive window at least 2048 times its stream receive window, so forwarded streams it has not read never hold back another. It holds at most 1024 forwarded streams not yet serving an accepted connection (handshaking or queued), ending the oldest past that.
- **Hole punching**: on a relayed connection the target sends one UDP datagram, the single byte `0x00` (no QUIC packet: QUIC endpoints drop it unanswered), from its listening socket to the dialer's address, and the dialer dials the target's address from the socket it reached the relay from, as a direct connection. Each side uses the address the other sent only if it is unicast (not unspecified, multicast or IPv4 broadcast) with a nonzero port, and global (as `reach.0` defines it) unless the relay's address it reached is not global; otherwise it neither punches nor dials, and the connection stays relayed.
- **IP consent**: any positive action toward a node (sharing a group with it, making, sending or following a link, accepting an invite, choosing a relay) is consent to show it this node's IP address. So a node exchanges addresses with every peer of a relayed connection.
- **Switching**: when a direct connection completes after a dialer began using a relayed one, it closes the relayed one and its next dial of that key uses the direct one.
- **Relaying** is a node's choice. A relay accepts registrations only of the keys it allows, and bounds per source (an IPv4 address, an IPv6 /64) the bytes per second it forwards and its share of relay connections. It sees addresses, volume and the keys dialed, never the data.

## 4. LAN discovery
LAN discovery announces nothing stable across networks or meaningful to strangers: a transport key fresh per network join, never the dialable key.
- **Joining**: a node joins anew (a fresh transport key and listener, announced at once and a few more times in its first seconds) whenever its network may have changed.
- **Announcement**: a UDP datagram to port 47380 on each address family the node has, as an IPv4 broadcast (255.255.255.255) and an IPv6 multicast to the link-local all-nodes group ff02::1 on each up interface with a link-local address, and to any further addresses configured, of exactly 44 bytes:

  | offset | size | field |
  |---|---|---|
  | 0 | 10 | `"osis lan 2"` (ASCII) |
  | 10 | 32 | transport key (this join's) |
  | 42 | 2 | listening port, big-endian: the listener's port on the datagram's family |

- **A receiver ignores**:
  - any other datagram;
  - one from a source address that cannot be on its LAN (only IPv4 loopback 127/8, private 10/8, 172.16/12, 192.168/16 and link-local 169.254/16, and IPv6 loopback, unique-local fc00::/7 and link-local fe80::/10 count; shared address space 100.64/10 does not);
  - one announcing its own transport key.
- **Dialing**: it dials every announcer, paced (local policy), at the datagram's source address (an IPv6 link-local one on the interface it arrived on) and the announced port. It need not dial a key again that it dialed earlier in its own join and still remembers; what it remembers is bounded (local policy). The address is a route to the node only once a connection through it is up (the transport authenticated the announced key). What the connection then shares is decided above this layer (spec/sync-opens.md).

## 5. One key and served connections
- **One key**: a node listens under one transport key, its dialable key, at every listener but its LAN ones (a fresh key per join) and its unix socket (a key by uid): the URLs its operator chose, its `peer://` listener. Every listener serves everything the node serves: node-to-node sync, whatever the node holds of each sync ID read or kept unread, and the client port (spec/wire.md §11.2 kinds 24-29), as does every connection the node dialed. A connection's `Hello` static key is the key of the listener that took it.
- **Key change**: the key changes only by hand (`rotate_peer_address`), and every listener moves to the new one. The node then writes its `reach.0` and its `dial.0` entry (spec/sync-set.md §1) for the new key, keeps no listener on the old key and sends no notice: peers find it by those records. `rotate_peer_address` returns once every listener listens under the new key; a listener that cannot is an error it returns, never an `Ok`.
- **Served connections**: a node serves any number of connections at once and closes none for their count or for sharing nothing. Limit: the transport's buffers per connection are not bounded in total, so many connections can take a node's memory. A node bounds the rest of the memory it holds for the connections it serves (local policy): in each direction over all of them, bytes of frames received and not yet run or answered, partial ones included (past it the connection holding the most is closed) and bytes written and not taken by the transport. The latter, with the reply allowances of requests it is answering, is never passed: a connection's reply, push or own request goes only within its share of the bound and the bound's room, else the request waits, in order, and the node reads no more of that connection meanwhile; one holding nothing may take one reply past its share, in turn with others waiting for the bound's room. While one waits so, the node closes connections whose bytes the transport takes none of, the one holding the most first, and, once it has waited half the requester's stall time (spec/sync-streams.md §1), the connections holding the most whatever they take, until it fits.

## 6. Local and client sessions
- **`unix:///path`**: a path socket (never an abstract one), no TLS.
  - Each side reads the other's uid from the kernel (`SO_PEERCRED`) and accepts only its own uid.
  - A side's key for the address is BLAKE3(`"osis v1 unix peer"` ‖ be32(uid)).
  - Only a local client dials one; a node never dials a `unix://` address taken from synced data.
  - A session on it is a **main session**, acting as the node's main actor (Auth without secret); a session on any other transport never is, whatever key it presents.
- **Client-actor session**: a session on a keyed transport, whose dialer pinned the node's key, that sent a current bearer secret in Auth (spec/wire.md §11.2).
  - The node acts as its client actor: it signs the session's commits as its account, with that actor in the header's actor field, and holds them to that actor's rights itself, since receivers judge only the author account's (spec/permissions.md §5).
  - A client's secret is never sent on another transport.
  - A client whose connection ended dials again with its session id unchanged, sends Auth, and resends each write that had no answer, marking it (spec/wire.md §11.2). A node that no longer remembers it answers that its outcome is unknown.
- **Group source**: a group read and written through a node one is a client of: spec/sync-set.md §5.
