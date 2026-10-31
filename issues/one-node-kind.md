# One kind of node: blind per group, no separate server program
> Summary: owner direction: "server" gets no special meaning in osis (it is just osis running on a server, for whatever reason); a node is blind to some groups and not others, "blind node" is shorthand for a mostly blind node, not a technical term; any node can sync encrypted data it cannot read (structurally, not by default); no distinct server project: serving is part of the node, started from the CLI, configured through osis data. Terminology and code refactor; design first.
> Tags: design, spec, server, node, api

## Owner direction (round 13)
- **"Server" is not a role.** Many server applications want to process data, not just sync it. Within osis "server" means only that osis runs on a server machine. The spec and code today use "server" for "blind node used as a store" (spec/overview.md §terms, spec/sync.md throughout): rename the role (e.g. a node *hosting* a label, a label's *hosts*), keep "server" for deployment talk only.
- **Blindness is per group, not per node.** A node may read some groups and host others blind; "blind node" is informal shorthand for a node that is fully or mostly blind. Nothing in the code design should force a node to be one or the other. Example (not to build now): a sync service whose settings (accounts, rate limits) are osis data its admin writes; the service reads its configuration group and is blind to everything it hosts, in one osis instance.
- **Any node can host encrypted data it cannot read**, structurally, even if not by default (a normal node relaying or storing a friend's group).
- **No separate server project.** Hosting is part of the node; a CLI command starts a node that hosts (`osis serve` or similar); configuration may live in the osis database.

## Today
- `core/server` (~3k lines: blind store over osis-store backends, the hub, flow control and caps, replication, the driver) is a separate crate and binary with no actor keys; `core/node` syncs readable groups and serves them to member peers (`ServerConnection` over its own entries, notes/networking.md).
- spec/overview.md defines "Blind node: a node holding no read secret of a label it stores; 'server' is a blind node used as one", so the spec is already per label; the split is in code and wording.

## Design questions (for the design pass)
- Isolation: today the blind store cannot touch keys because it is another program. In one node the hosting path must still never decrypt or depend on key state for what it hosts; keep that a module boundary that tests can check (the hosting module takes no engine or key types).
- Store: one store with hosted labels beside the node's own data, or the existing blind store as a module the node owns; host caps and accounting per label.
- Which groups a node hosts, and how that is configured (osis data in a config group the node reads, CLI flags, both), and how clients find hosts (`/label` server lists become host lists).
- A node hosting a group it can also read: serve its readable entries and the blind entries alike, or one path.
- Terminology pass across spec, notes, code, API and CLI together with issues/rename-roles-members.md (do both renames in one sweep).
