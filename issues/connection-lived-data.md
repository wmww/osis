# Data that lives while its keepers are connected
> Summary: Tess's model for ephemeral data, replacing keep-alive and the "Superseded commits" rule: a commit may name a set of keeper accounts (default its author's); its writes live at a node only while that node is connected, directly or indirectly, to at least one node of a keeper account. No periodic writes: a keeper leaving drops the data at once; a reconnecting keeper's node re-sends what it holds by ordinary sync. After issues/net-rework.md (connections) and issues/account-signing.md (accounts as the identity).
> Priority: normal
> Tags: sync, ephemeral, net, spec

- Connected set: each node holds the accounts it reaches through current connections. Indirect reach is learned from neighbours with the path (path-vector), event-driven (sent on change only), so a loop cannot keep a departed account alive; the connection layer's idle timeout bounds detection of an abrupt drop.
- Nodes may briefly disagree on who is connected during partitions; such data then shows at some nodes and not others until it settles (stated).
- What it applies to: per commit, as expiry is; a schema may default an aspect or thing to it. A thing created in such a commit follows whatever the general expiry rule decides for things created in an expiring commit (issues/expiry-knocks-out-commit.md; today a creation needs a commit with no expiry, so the same would hold here).
- Listing other accounts as keepers only keeps one's own data alive longer while they are online; it grants nothing.
