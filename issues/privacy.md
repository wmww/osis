# Privacy
> Summary: Low priority (Tess): where every privacy concern of networking and sharing goes, so the rework (issues/net-rework.md) does not design for it. Who learns this node's IP (settings: strangers only through relays, one chosen relay for everything), open audiences learning IPs. Today any positive action counts as IP consent (spec/sync.md §10). Don't spend effort here until asked.
> Priority: low
> Tags: transport, security

- **IP settings**: who learns this node's IP, e.g. strangers only through relays, or tunnel everything through one chosen relay.
- **Open audiences**: with `reach.0` under every synced group, everyone holding a public or bearer-read link learns the node's IP; so do holders of a link or card with connect hints (issues/net-first-contact.md).
- Identity on the LAN is a requirement, not a setting: issues/net-connect.md.
- **A node serving data it cannot read** shows every connection how many heads it serves (its beacon filter's size) and "I serve this one" to anyone holding that group's `label.0`, roster or `keys.0` (issues/net-shared-set.md, Peers that cannot read); a host answering Open and Deposit shows the same today.
