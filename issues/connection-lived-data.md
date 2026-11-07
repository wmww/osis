# Data that lives while its keepers are connected
> Summary: Tess's model for ephemeral data, replacing keep-alive and the "Superseded commits" rule: a thing may carry an aspect naming its keeper accounts (default its creator's); a node holds the thing (creation and all its content) only while it is connected, directly or indirectly, to at least one node of a keeper account, and drops it locally otherwise. Thing-level, not per commit: no wire change, one rule, and ephemeral state on a durable thing lives on a separate keeper-held thing. No periodic writes: a keeper leaving drops the data at once; a reconnecting keeper's node re-sends what it holds by ordinary sync. After issues/net-rework.md (connections) and issues/account-signing.md (accounts as the identity).
> Priority: normal
> Tags: sync, ephemeral, net, spec

- Connected set: each node holds the accounts it reaches through current connections. Indirect reach is learned from neighbours with the path (path-vector), event-driven (sent on change only), so a loop cannot keep a departed account alive; the connection layer's idle timeout bounds detection of an abrupt drop.
- Nodes may briefly disagree on who is connected during partitions; such data then shows at some nodes and not others until it settles (stated).
- Granularity: a whole thing (chosen over per commit: no wire field, the drop is a local held-set rule like any other, and a reconnecting keeper re-sends the thing by ordinary sync). Per-session churn of such things relies on issues/creation-record-ordinary.md (no kept creation record).
- Listing other accounts as keepers only keeps one's own data alive longer while they are online; it grants nothing.
