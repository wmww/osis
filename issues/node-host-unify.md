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

## Clients
A **client** is a program using a node out of process, local or remote; a **remote client** is one whose node is on another machine. Which actor it acts as is a separate matter. Today the two are tied:
- Unix socket: same uid, acts as the node's account (`attach`, "Owner").
- Secret over a keyed transport: acts as an actor minted for it (`add_client`).

To decide: a credential names the actor it acts as, so transport and actor are independent. The hard part is a remote client acting as the account: a bearer secret would then carry the account's full power, and notes/client-port.md Rejected ("Thin devices") argued against that. Grants to its own actor may remain the recommended way even if the shape allows both.

In-process acting as several actors is issues/grant-rename-multi-actor.md (public `act_as`).

## Words to sweep
"Blind node", "untrusted node" as a kind, "thin client", "Owner" session, "device" as a term of the model. notes/networking.md "Blind always-on nodes are the backbone", notes/client-port.md §0 "Two kinds of process", notes/sync.md, notes/convergence-study.md, notes/overview.md. API part: issues/api-refactor.md, Names.
