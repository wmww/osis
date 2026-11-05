# One kind of node
> Summary: There is no fundamental distinction between nodes by how much of their data they can read (Tess). Words are fixed by spec/requirements.md Terms; this lists what still separates them in code and notes, and what to decide about each. The same binary already runs every case; the remaining question is three serving paths, two stores and three keys on one node.
> Tags: node, host, api

A normal device may keep data it cannot read for others, and a backup machine may read some of what it holds (its settings, a website's data). Same binary, run the same way, any mix.

What already holds: hosting runs inside a node, from its `host.0^` (notes/sync.md, Hosting in the node), and there is no separate host program. So a laptop can already host, and a mostly encrypted machine already has an account and data of its own.

## Keep
The code that serves data a node may not read cannot decrypt anything (`osis-host` has no engine or keys, `tools/policy.py` `host_blind`). That is a security boundary inside every node, not a kind of node. Describe it that way.

## Still separated: decide each
1. **Two stores.** A node hosting a group it also reads keeps it twice: plaintext state in `db.redb`, blobs in `host.redb`.
2. **Three ways to serve a label.** The hub for hosting (`osis-host`), a peer that reads the label serving it (spec/sync.md §5, "serves it as its own host"), and hosts replicating to each other. Can a peer's serving and the hub be one path, differing only in what proof opens a label?
3. **Three listening keys.** Host address, dialable key and client listener key, each with its own rules, and the client port is never served on the host address (notes/client-port.md §5). Some of this is privacy (transport keys unlinkable from node keys), so keep what that needs and no more.
4. **Hosting is opt-in by `Hosting` config.** Fine as a default. Check nothing assumes a host is always on or has a public address (Tess's laptop case), and that `Admit` isn't phrased around servers.
5. **`osis-proto` session names.** `ClientSession` means the dialing side of a connection, unrelated to a client of the API. `ServingSession::port_only` and friends likewise.

## No server assumed (Tess)
Requirements: spec/requirements.md, Decentralization. Known departures, in order:
1. **P2P is off in every build.** No manifest for the app, Android or CLI enables `iroh` or `lan`; only `cargo test-net` does. Turn both on by default, raising the Rust minimum to 1.91, and test real devices, Android included.
2. **Direct sync between users is off by default.** `reach.0` goes out only where every reader is this account or a contact, so a chat joined by link has none. Default to on. An open audience (public, bearer read) is the case to think about, as is what a user can do about address exposure without losing P2P.
3. **Recovery** is tied to having hosts (no card without them, key discarded), and is being reworked anyway: an explicit step, with `create` returning only the database.
4. **Every feature with no hosts:** see the audit below.

## Clients
A **client** is anything using the client protocol; a node may be one too (a phone syncing its private data and using a server's node for bigger, less sensitive data). A **thin client** is a client that is not a node. Neither says what actor it acts as, and the model doesn't couple machine, transport and actor: there are many threat models, and which fits is a node's policy.

Default policy (Tess):
- **Unix socket**: open without authentication to the current user, as the node's main actor. There is no security boundary there anyway.
- **Localhost or network listener**: a client may act only as actors it has cryptographically authenticated for.

To build: a credential names the actor it acts as, the main one included if the node's owner chooses. Today the transport decides (socket: main actor; secret: an actor minted for it), and notes/client-port.md Rejected ("Thin devices") argues from a threat model it shouldn't impose: reword it as a default. Today's credential is a bearer secret inside TLS; decide whether "cryptographically authenticated" needs a signature by the actor's key instead. Also: acting as several actors in process, issues/grant-rename-multi-actor.md (public `act_as`).

## Words to sweep
"Blind node", "untrusted node" as a kind, "Owner" session, "device" as a term of the model. notes/networking.md "Blind always-on nodes are the backbone", notes/client-port.md §0 "Two kinds of process", notes/sync.md, notes/convergence-study.md, notes/overview.md. API part: issues/api-refactor.md, Names.
