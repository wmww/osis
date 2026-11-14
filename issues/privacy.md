# Privacy
> Summary: Low priority (Tess): where every privacy concern of networking and sharing goes, so sync does not design for it yet. Who learns this node's IP (settings: strangers only through relays, one chosen relay for everything), open audiences learning IPs. Today any positive action counts as IP consent (spec/sync-opens.md §4). Don't spend effort here until asked.
> Priority: low
> Tags: transport, security

- **IP settings**: who learns this node's IP, e.g. strangers only through relays, or tunnel everything through one chosen relay.
- **Open audiences**: with `reach.0` under every synced group (issues/account-signing.md steps 7-8), everyone holding a public or bearer-read link learns the node's IP; so do holders of a link, card or profile with dial hints.
- LAN discovery announces a transport key fresh per network join, never the dialable key (spec/sync-transport.md §4).
- **A node serving data it cannot read** shows every connection how many sync IDs it holds (its filter's size, spec/sync-opens.md §5) and "I keep this one" to anyone holding a credential of it. On the one listening key (spec/sync-transport.md §5) this ties what a node keeps unread to the key its contacts know it by.
- **A node keeping data unread learns who keeps what** (accepted, Tess): a node holding a group sync-only learns the granting account and which accounts' nodes open the group there (notes/unreadable-data.md), and that two groups it holds share a blob. Guarantees that a node learns nothing about the nodes it syncs encrypted groups with may be more than is reasonable to provide.
